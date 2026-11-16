import Foundation

public struct ValidatedEvent: Sendable, Equatable {
    public let payload: Data
    public let id: String
    public let project: String
    public let kind: String
    public let author: String
    public let keyID: String
    public let issuedAt: Int64
    public let expiresAt: Int64
    public let audience: [String]
    public let fields: [String: JSONValue]
    public var digest: String { DSSE.digest(payload) }
    public var exactText: String { String(decoding: payload, as: UTF8.self) }

    public static func validID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !value.contains("..") && (1...128).contains(bytes.count) && bytes.first.map { asciiAlphanumeric($0) } == true &&
            bytes.allSatisfy { asciiAlphanumeric($0) || [45, 46, 95].contains($0) }
    }
    private static func asciiAlphanumeric(_ b: UInt8) -> Bool {
        (48...57).contains(b) || (65...90).contains(b) || (97...122).contains(b)
    }
    public static func validDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public static func parse(_ payload: Data) throws -> Self {
        guard let fields = try StrictJSON.parse(payload).object else { throw SignerError.invalid("Event must be an object.") }
        try exactKeys(fields, ["version", "id", "project", "kind", "author", "key_id", "session", "issued_at", "expires_at", "audience", "group", "epoch", "previous", "body"])
        guard fields["version"] == .integer(1) else { throw SignerError.invalid("Unsupported event version.") }
        let id = try identifier(fields, "id"), project = try identifier(fields, "project"), author = try identifier(fields, "author")
        let kind = try text(fields, "kind"), keyID = try text(fields, "key_id")
        guard keyID.hasPrefix("k_"), validDigest(String(keyID.dropFirst(2))) else { throw SignerError.invalid("Invalid signing key ID.") }
        guard let issued = fields["issued_at"]?.integer, let expires = fields["expires_at"]?.integer,
              issued >= 0, expires > issued, expires <= 253_402_300_799 else { throw SignerError.invalid("Invalid event validity period.") }
        let audience = try identifiers(fields, "audience")
        // This first native profile only signs root-device actions. Session keys and
        // session grants are deliberately not provisioned or accepted.
        guard fields["session"] == .null else { throw SignerError.invalid("Human signing sessions are not enabled.") }
        if fields["group"] != .null { _ = try identifier(fields, "group") }
        if fields["epoch"] != .null {
            guard let epoch = fields["epoch"]?.integer, epoch >= 0 else { throw SignerError.invalid("Invalid epoch.") }
        }
        let groupWideDelegation = kind == "agent.delegation" && fields["group"] != .null && fields["epoch"] == .null
        guard groupWideDelegation || (fields["group"] == .null) == (fields["epoch"] == .null) else { throw SignerError.invalid("Group and epoch must be bound together, except an explicit group-wide agent delegation.") }
        if fields["previous"] != .null {
            guard validDigest(try text(fields, "previous")) else { throw SignerError.invalid("Invalid previous digest.") }
        }
        guard let body = fields["body"]?.object else { throw SignerError.invalid("Event body must be a typed object.") }
        try validateBody(kind: kind, body: body)
        return Self(payload: payload, id: id, project: project, kind: kind, author: author,
                    keyID: keyID, issuedAt: issued, expiresAt: expires, audience: audience, fields: fields)
    }
    private static func validateBody(kind: String, body: [String: JSONValue]) throws {
        switch kind {
        case "human.statement":
            try exactKeys(body, ["text"])
            let value = try text(body, "text")
            guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw SignerError.invalid("Statement is empty.") }
        case "agent.delegation":
            try exactKeys(body, ["agent", "agent_key_id", "purposes"])
            _ = try identifier(body, "agent")
            let target = try text(body, "agent_key_id")
            guard target.hasPrefix("k_"), validDigest(String(target.dropFirst(2))) else { throw SignerError.invalid("Invalid delegated key ID.") }
            guard let items = body["purposes"]?.array, !items.isEmpty else { throw SignerError.invalid("Delegation needs explicit purposes.") }
            let purposes = try items.map { value -> String in
                guard let purpose = value.string, ["agent.message", "agent.relay", "action.execute", "ticket.action"].contains(purpose) else {
                    throw SignerError.invalid("Delegation cannot grant human authority.")
                }
                return purpose
            }
            guard purposes == purposes.sorted(), Set(purposes).count == purposes.count else { throw SignerError.invalid("Delegation purposes must be sorted and unique.") }
        case "action.authorization":
            try exactKeys(body, ["action", "request_digest", "performer"])
            let action = try identifier(body, "action")
            guard ["group.create", "group.add", "group.remove", "ticket.recover"].contains(action),
                  validDigest(try text(body, "request_digest")) else { throw SignerError.invalid("Unsupported action or invalid request digest.") }
            _ = try identifier(body, "performer")
        default:
            throw SignerError.invalid("This native profile does not support this event kind.")
        }
    }
    static func exactKeys(_ object: [String: JSONValue], _ keys: Set<String>) throws {
        guard Set(object.keys) == keys else { throw SignerError.invalid("Unknown or missing JSON fields.") }
    }
    static func text(_ object: [String: JSONValue], _ key: String) throws -> String {
        guard let value = object[key]?.string else { throw SignerError.invalid("Expected string: \(key).") }
        return value
    }
    static func identifier(_ object: [String: JSONValue], _ key: String) throws -> String {
        let value = try text(object, key)
        guard validID(value) else { throw SignerError.invalid("Invalid identifier: \(key).") }
        return value
    }
    static func identifiers(_ object: [String: JSONValue], _ key: String) throws -> [String] {
        guard let items = object[key]?.array, (1...128).contains(items.count) else { throw SignerError.invalid("Expected bounded nonempty audience.") }
        let values = try items.map { item -> String in
            guard let value = item.string, validID(value) else { throw SignerError.invalid("Invalid audience identifier.") }
            return value
        }
        guard values == values.sorted(), Set(values).count == values.count else { throw SignerError.invalid("Audience must be sorted and unique.") }
        return values
    }
}

public struct SigningIdentity: Sendable, Equatable {
    public let author: String
    public let project: String
    public let publicKey: Data
    public var keyID: String { get throws { try DSSE.keyID(publicKey: publicKey) } }
    public init(author: String, project: String, publicKey: Data) throws {
        guard ValidatedEvent.validID(author), ValidatedEvent.validID(project) else { throw SignerError.invalid("Invalid identity or project.") }
        _ = try DSSE.keyID(publicKey: publicKey)
        self.author = author; self.project = project; self.publicKey = publicKey
    }
}

public enum SigningPolicy {
    public static func validate(_ event: ValidatedEvent, identity: SigningIdentity, now: Int64, request: ActionRequest? = nil) throws {
        guard event.author == identity.author, event.project == identity.project,
              event.keyID == (try identity.keyID) else { throw SignerError.invalid("Draft does not match this device identity and project.") }
        // An agent delegation is an explicitly reviewed capability for a separate
        // agent key, not a reusable human-signing session. Match the wire cap.
        let maximumLifetime: Int64 = switch event.kind {
        case "action.authorization": 300
        case "agent.delegation": 7 * 86_400
        default: 1_800
        }
        guard now >= event.issuedAt, now < event.expiresAt,
              event.expiresAt - event.issuedAt <= maximumLifetime else { throw SignerError.invalid("Draft is not current or exceeds this action's validity limit.") }
        if event.kind == "action.authorization" {
            guard let request else { throw SignerError.invalid("Open the exact action request before approving. Hash-only approval is forbidden.") }
            try request.validateBinding(to: event)
        } else if request != nil { throw SignerError.invalid("Unexpected action request for this event kind.") }
    }
}

/// Pure state machine; a revision identifies the immutable draft shown by the UI.
/// A revision is NOT proof of human consent. Only the native caller can collect it.
public struct ApprovalState: Sendable {
    public private(set) var event: ValidatedEvent?
    public private(set) var revision: UInt64 = 0
    public private(set) var request: ActionRequest?
    public init() {}
    public mutating func replace(with event: ValidatedEvent) { revision &+= 1; self.event = event; request = nil }
    public mutating func invalidate() { revision &+= 1; event = nil; request = nil }
    public mutating func attach(_ request: ActionRequest) throws {
        // Clear any previous details even when replacement validation fails.
        revision &+= 1; self.request = nil
        guard let event else { throw SignerError.invalid("Open an authorization draft first.") }
        try request.validateBinding(to: event)
        self.request = request
    }
    public mutating func clearRequest() { revision &+= 1; request = nil }
    public func checked(revision expected: UInt64, identity: SigningIdentity, now: Int64) throws -> ValidatedEvent {
        guard expected == revision, let event else { throw SignerError.invalid("Approval expired. Open and review the draft again.") }
        try SigningPolicy.validate(event, identity: identity, now: now, request: request)
        return event
    }
}

/// Injection seam for tests. The executable only constructs SecureEnclaveRoot;
/// it never selects this dependency using input, environment, or a runtime flag.
public protocol EventSigning: Sendable {
    func signPAE(_ bytes: Data) throws -> Data
}
public enum EnvelopeSigning {
    public static func sign(_ event: ValidatedEvent, identity: SigningIdentity, now: Int64, request: ActionRequest? = nil,
                            using signer: some EventSigning) throws -> Data {
        try SigningPolicy.validate(event, identity: identity, now: now, request: request)
        let signature = try signer.signPAE(DSSE.pae(payload: event.payload))
        return try DSSE.envelope(payload: event.payload, signature: signature, publicKey: identity.publicKey)
    }
}
