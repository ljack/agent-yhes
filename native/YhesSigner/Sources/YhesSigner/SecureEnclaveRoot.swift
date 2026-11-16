import CryptoKit
import Foundation
import LocalAuthentication
import Security
import YhesSignerCore

/// No arbitrary-data method is exported by the app. This backend is internal and
/// reachable only after native review. Wrapped enclave handles stay in Keychain.
// UI serializes load/create/sign; cancel alone is concurrent and lock protected.
final class SecureEnclaveRoot: @unchecked Sendable {
    private static let service = "com.agent-yhes.YhesSigner.root.v1"
    private struct Record: Codable {
        let version: Int
        let author: String
        let project: String
        let publicKey: Data
        let wrappedEnclaveKey: Data
    }
    private var record: Record?
    private var activeContext: LAContext?
    private var activeAttempt: UUID?
    private var reviewPermit: OneUseSigningPermit?
    private var setupIdentity: (author: String, project: String)?
    private let lock = NSLock()

    func cancel() { finish(nil) }
    private func finish(_ expected: UUID?) {
        lock.lock()
        if let expected, activeAttempt != expected { lock.unlock(); return }
        let context = activeContext
        activeContext = nil; activeAttempt = nil; reviewPermit = nil; setupIdentity = nil
        lock.unlock()
        context?.invalidate()
    }
    func prepareReview(_ document: ReviewedDocument, identity: SigningIdentity) throws -> UUID {
        let plan = try FixedSigningPlan(document: document, identity: identity, now: Int64(Date().timeIntervalSince1970))
        guard let record, record.author == identity.author, record.project == identity.project,
              record.publicKey == identity.publicKey else { throw SignerError.invalid("Load this device identity before signing.") }
        let attempt = try freshContext(reason: document.authenticationReason)
        lock.lock(); reviewPermit = OneUseSigningPermit(plan); lock.unlock()
        return attempt
    }
    func prepareKeySetup(author: String, project: String) throws -> UUID {
        guard ValidatedEvent.validID(author), ValidatedEvent.validID(project) else { throw SignerError.invalid("Invalid setup author or project.") }
        let attempt = try freshContext(reason: "Create a new device signing key for \(author), project \(project)")
        lock.lock(); setupIdentity = (author, project); lock.unlock()
        return attempt
    }
    private func freshContext(reason: String) throws -> UUID {
        try TrustedApplication.requireProtectedIdentity()
        guard SecureEnclave.isAvailable else { throw SignerError.invalid("Secure Enclave is unavailable.") }
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Cancel signing"
        context.localizedReason = reason
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error), context.biometryType == .touchID else {
            context.invalidate()
            throw SignerError.invalid("Touch ID is unavailable or locked. Signing was refused.")
        }
        let attempt = UUID()
        lock.lock()
        activeContext?.invalidate(); activeContext = context; activeAttempt = attempt
        reviewPermit = nil; setupIdentity = nil
        lock.unlock()
        return attempt
    }
    private func claimSetup(_ attempt: UUID, author: String, project: String) throws -> LAContext {
        lock.lock(); defer { lock.unlock() }
        guard activeAttempt == attempt, let context = activeContext,
              setupIdentity?.author == author, setupIdentity?.project == project else {
            throw SignerError.invalid("Key setup was cancelled or already consumed.")
        }
        setupIdentity = nil
        return context
    }
    private func claimReview(_ attempt: UUID) throws -> (LAContext, FixedSigningPlan) {
        lock.lock(); defer { lock.unlock() }
        guard activeAttempt == attempt, let context = activeContext, var permit = reviewPermit else {
            throw SignerError.invalid("Signing attempt was cancelled or already consumed.")
        }
        reviewPermit = nil
        return (context, try permit.take())
    }
    private func requireCurrent(_ context: LAContext) throws {
        lock.lock(); defer { lock.unlock() }
        guard activeContext === context else { throw SignerError.invalid("Signing attempt was cancelled.") }
    }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: Self.service,
         kSecAttrAccount as String: "root-device",
         kSecAttrAccessGroup as String: TrustedApplication.keychainGroup,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: false]
    }
    func load() throws -> SigningIdentity {
        record = nil
        try TrustedApplication.requireProtectedIdentity()
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let readContext = LAContext(); readContext.interactionNotAllowed = true
        defer { readContext.invalidate() }
        request[kSecUseAuthenticationContext as String] = readContext
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { throw SignerProtocolError.identityMissing }
        guard status == errSecSuccess, let data = result as? Data else { throw SignerProtocolError.identityUnavailable }
        let record = try PropertyListDecoder().decode(Record.self, from: data)
        guard record.version == 1 else { throw SignerError.invalid("Unsupported stored identity.") }
        let identity = try SigningIdentity(author: record.author, project: record.project, publicKey: record.publicKey)
        self.record = record
        return identity
    }
    /// Only called by the native setup confirmation. This is local key setup,
    /// not enterprise enrollment; registry approval is a separate required step.
    func create(author: String, project: String, attempt: UUID) throws -> SigningIdentity {
        guard ValidatedEvent.validID(author), ValidatedEvent.validID(project) else { throw SignerError.invalid("Use valid account and project identifiers.") }
        let context = try claimSetup(attempt, author: author, project: project)
        defer { finish(attempt) }
        var existing: CFTypeRef?
        let readContext = LAContext(); readContext.interactionNotAllowed = true
        defer { readContext.invalidate() }
        var lookup = query; lookup[kSecUseAuthenticationContext as String] = readContext
        let status = SecItemCopyMatching(lookup as CFDictionary, &existing)
        guard status == errSecItemNotFound else { throw SignerError.invalid("A device key already exists, or its status could not be established. No key was replaced.") }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error) else { throw SignerError.invalid("Cannot create biometric key policy.") }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false,
                                                         accessControl: access, authenticationContext: context)
        // A possession challenge forces private-key use and the biometric policy
        // before persistence. This is not a yhes event and is never exported.
        var challenge = Data("agent-yhes/local-key-setup/v1\0".utf8)
        challenge.append(Data(UUID().uuidString.utf8))
        _ = try key.signature(for: challenge)
        try requireCurrent(context)
        let publicKey = key.publicKey.x963Representation
        let identity = try SigningIdentity(author: author, project: project, publicKey: publicKey)
        let record = Record(version: 1, author: author, project: project,
                            publicKey: publicKey, wrappedEnclaveKey: key.dataRepresentation)
        var request = query
        request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        request[kSecValueData as String] = try PropertyListEncoder().encode(record)
        // Linearize cancellation against the add-only persistence step. A
        // cancelled setup cannot begin a later Keychain write.
        lock.lock()
        guard activeContext === context else { lock.unlock(); throw SignerError.invalid("Key setup was cancelled.") }
        let saved = SecItemAdd(request as CFDictionary, nil)
        if saved == errSecSuccess { self.record = record }
        lock.unlock()
        guard saved == errSecSuccess else { throw SignerError.invalid("Cannot save the device key in its protected Keychain group.") }
        return identity
    }
    /// No payload parameter: all bytes and domains were frozen before Touch ID.
    func sign(attempt: UUID) throws -> SignedReview {
        let (context, plan) = try claimReview(attempt)
        defer { finish(attempt) }
        let identity = plan.identity
        guard let record, record.author == identity.author, record.project == identity.project,
              record.publicKey == identity.publicKey else { throw SignerError.invalid("Device identity changed after review.") }
        try requireCurrent(context)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: record.wrappedEnclaveKey,
                                                         authenticationContext: context)
        guard key.publicKey.x963Representation == identity.publicKey else { throw SignerError.invalid("Stored device key does not match its enclave key.") }
        // Exactly this fixed plan uses the same context. The OS may request
        // additional prompts; never loosen ACL/reuse settings to force one prompt.
        return try plan.sign(using: EnclaveFixedSigner(key: key), now: { Int64(Date().timeIntervalSince1970) },
                             checkCancellation: { try self.requireCurrent(context) })
    }
    // Used serially within one claimed attempt; never shared with other callers.
    private struct EnclaveFixedSigner: EventSigning, @unchecked Sendable {
        let key: SecureEnclave.P256.Signing.PrivateKey
        func signPAE(_ bytes: Data) throws -> Data { try key.signature(for: bytes).rawRepresentation }
    }
}
