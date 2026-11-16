import Foundation
import Security
import YhesSignerCore

/// Local pilot identity is pinned in source and protected by the signed artifact.
/// A mutable plist, environment variable, CLI flag, or caller value is not a trust root.
enum TrustedApplication {
    static let teamID = "25C9H9N953"
    static let engineID = "com.agent-yhes.engine"
    static let bundleID = "com.agent-yhes.YhesSigner"
    static var keychainGroup: String { teamID + "." + bundleID }

    static func requireProtectedIdentity() throws {
        guard teamID.count == 10, teamID.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
              Bundle.main.bundleIdentifier == bundleID,
              Bundle.main.bundleURL.pathExtension == "app" else {
            throw SignerError.invalid("Open the signed Yhes Signer app. Build and provision its dedicated app identity first.")
        }
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { throw SignerError.invalid("Cannot inspect signer identity.") }
        try requireCode(code, identifier: bundleID)
    }

    static func requireEnginePeer(socket: Int32) throws {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(socket, &uid, &gid) == 0, uid == getuid() else { throw SignerProtocolError.unauthorized }
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(socket, 0, 6, &token, &length) == 0,
              length == MemoryLayout<audit_token_t>.size else { throw SignerProtocolError.unauthorized }
        let audit = withUnsafeBytes(of: token) { Data($0) }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit as String: audit] as CFDictionary, [], &code) == errSecSuccess,
              let code else { throw SignerProtocolError.unauthorized }
        do { try requireCode(code, identifier: engineID) } catch { throw SignerProtocolError.unauthorized }
    }

    private static func requireCode(_ code: SecCode, identifier: String) throws {
        let expectedApplication = teamID + "." + identifier
        let expectedGroup = expectedApplication + (identifier == engineID ? ".vault" : "")
        var requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
        guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw SignerError.invalid("Signer application signature is not trusted.")
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { throw SignerError.invalid("Missing static code identity.") }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? UInt32,
              flags & 0x10000 != 0, // CS_RUNTIME (hardened runtime)
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              entitlements["com.apple.application-identifier"] as? String == expectedApplication,
              entitlements["keychain-access-groups"] as? [String] == [expectedGroup] else {
            throw SignerError.invalid("Signer requires hardened runtime and its exclusive Keychain access group.")
        }
        let forbidden = ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation",
                         "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory",
                         "com.apple.security.cs.allow-jit"]
        guard forbidden.allSatisfy({ (entitlements[$0] as? Bool) != true }) else {
            throw SignerError.invalid("Signer has unsafe development entitlements.")
        }
    }
}
