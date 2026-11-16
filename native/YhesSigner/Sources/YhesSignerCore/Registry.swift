import CryptoKit
import Foundation

public struct RegistryParticipant: Sendable, Equatable {
    public let id: String
    public let kind: String
    public let controller: String?
    public let ghesInstance: String?
    public let ghesUserID: Int64?
}
public struct RegistryPublicKey: Sendable, Equatable {
    public let keyID: String
    public let participant: String
    public let algorithm: String
    public let publicKey: Data
    public let notBefore: Int64
    public let notAfter: Int64
}

/// Strict native subset of yhes-wire's registry schema. This is an UNTRUSTED
/// draft; parsing does not authenticate GHES accounts or enroll an authority.
public struct ValidatedRegistry: Sendable, Equatable {
    public let payload: Data
    public let project: String
    public let generation: Int64
    public let previous: String?
    public let issuedAt: Int64
    public let expiresAt: Int64
    public let participants: [RegistryParticipant]
    public let keys: [RegistryPublicKey]
    public let revokedKeyIDs: [String]
    public var digest: String { DSSE.digest(payload) }
    public var exactText: String { String(decoding: payload, as: UTF8.self) }

    public static func parse(_ payload: Data) throws -> Self {
        guard let fields = try StrictJSON.parse(payload).object else { throw SignerError.invalid("Registry must be an object.") }
        try ValidatedEvent.exactKeys(fields, ["version", "project", "generation", "previous", "issued_at", "expires_at", "participants", "keys", "revocations"])
        guard fields["version"] == .integer(1), let generation = fields["generation"]?.integer,
              generation >= 1, generation < Int64.max else { throw SignerError.invalid("Invalid registry version or generation.") }
        let project = try ValidatedEvent.identifier(fields, "project")
        let previous: String?
        if fields["previous"] == .null { previous = nil }
        else {
            let value = try ValidatedEvent.text(fields, "previous")
            guard ValidatedEvent.validDigest(value) else { throw SignerError.invalid("Invalid registry predecessor digest.") }
            previous = value
        }
        guard (generation == 1) == (previous == nil) else { throw SignerError.invalid("Registry predecessor does not match generation.") }
        let issued = try timestamp(fields, "issued_at"), expires = try timestamp(fields, "expires_at")
        guard expires > issued else { throw SignerError.invalid("Registry validity must have positive duration.") }
        let participantItems = try boundedArray(fields, "participants", maximum: 128)
        var participants: [RegistryParticipant] = []
        var accounts = Set<String>()
        for item in participantItems {
            let p = try object(item)
            try ValidatedEvent.exactKeys(p, ["id", "kind", "controller", "ghes"])
            let id = try ValidatedEvent.identifier(p, "id"), kind = try ValidatedEvent.text(p, "kind")
            guard ["human", "agent", "service"].contains(kind), participants.last.map({ $0.id < id }) ?? true else {
                throw SignerError.invalid("Registry participants must have known kinds and sorted unique IDs.")
            }
            let controller = p["controller"] == .null ? nil : try ValidatedEvent.identifier(p, "controller")
            var host: String?, userID: Int64?
            if p["ghes"] != .null {
                let ghes = try object(p["ghes"]!)
                try ValidatedEvent.exactKeys(ghes, ["instance", "user_id"])
                let instance = try ValidatedEvent.text(ghes, "instance")
                guard validHost(instance), let value = ghes["user_id"]?.integer, value > 0,
                      accounts.insert("\(instance):\(value)").inserted else {
                    throw SignerError.invalid("Invalid or duplicate GHES account binding.")
                }
                host = instance; userID = value
            }
            participants.append(RegistryParticipant(id: id, kind: kind, controller: controller,
                                                    ghesInstance: host, ghesUserID: userID))
        }
        let people = Dictionary(uniqueKeysWithValues: participants.map { ($0.id, $0) })
        for participant in participants {
            switch participant.kind {
            case "human":
                guard participant.controller == nil else { throw SignerError.invalid("A human cannot have a controller.") }
                // A local pilot human has no GHES claim. Optional GHES linkage
                // remains structurally checked and must be verified separately.
            case "agent":
                guard let controller = participant.controller, people[controller]?.kind == "human",
                      participant.ghesInstance == nil else { throw SignerError.invalid("An agent needs a human controller and no GHES account.") }
            default:
                if let controller = participant.controller, people[controller]?.kind != "human" {
                    throw SignerError.invalid("A service controller must be a human.")
                }
            }
        }
        var keys: [RegistryPublicKey] = []
        for item in try boundedArray(fields, "keys", maximum: 256) {
            let k = try object(item)
            try ValidatedEvent.exactKeys(k, ["key_id", "participant", "algorithm", "public_key", "not_before", "not_after"])
            let id = try keyID(k, "key_id"), participant = try ValidatedEvent.identifier(k, "participant")
            let algorithm = try ValidatedEvent.text(k, "algorithm")
            let encoded = try ValidatedEvent.text(k, "public_key")
            guard let raw = Data(base64Encoded: encoded), raw.base64EncodedString() == encoded,
                  people[participant] != nil, keys.last.map({ $0.keyID < id }) ?? true else {
                throw SignerError.invalid("Invalid registry public-key encoding, owner or ordering.")
            }
            let derived = try registryKeyID(algorithm: algorithm, raw: raw)
            guard derived == id else { throw SignerError.invalid("Registry key ID does not match its public key.") }
            let before = try timestamp(k, "not_before"), after = try timestamp(k, "not_after")
            guard after >= before else { throw SignerError.invalid("Invalid registry key validity.") }
            keys.append(RegistryPublicKey(keyID: id, participant: participant, algorithm: algorithm,
                                          publicKey: raw, notBefore: before, notAfter: after))
        }
        var revoked: [String] = []
        for item in try boundedArray(fields, "revocations", maximum: 256) {
            let r = try object(item)
            try ValidatedEvent.exactKeys(r, ["key_id", "revoked_at"])
            let id = try keyID(r, "key_id"); _ = try timestamp(r, "revoked_at")
            guard revoked.last.map({ $0 < id }) ?? true else { throw SignerError.invalid("Revocations must be sorted and unique.") }
            revoked.append(id)
        }
        return Self(payload: payload, project: project, generation: generation, previous: previous,
                    issuedAt: issued, expiresAt: expires, participants: participants, keys: keys, revokedKeyIDs: revoked)
    }
    private static func registryKeyID(algorithm: String, raw: Data) throws -> String {
        try RegistryKeyValidation.keyID(algorithm: algorithm, raw: raw)
    }
    private static func object(_ value: JSONValue) throws -> [String: JSONValue] {
        guard let object = value.object else { throw SignerError.invalid("Expected typed registry object.") }
        return object
    }
    private static func boundedArray(_ fields: [String: JSONValue], _ key: String, maximum: Int) throws -> [JSONValue] {
        guard let items = fields[key]?.array, items.count <= maximum else { throw SignerError.invalid("Invalid or oversized registry list.") }
        return items
    }
    private static func timestamp(_ fields: [String: JSONValue], _ key: String) throws -> Int64 {
        guard let value = fields[key]?.integer, value >= 0, value <= 253_402_300_799 else { throw SignerError.invalid("Invalid registry timestamp.") }
        return value
    }
    private static func keyID(_ fields: [String: JSONValue], _ key: String) throws -> String {
        let value = try ValidatedEvent.text(fields, key)
        guard value.hasPrefix("k_"), ValidatedEvent.validDigest(String(value.dropFirst(2))) else { throw SignerError.invalid("Invalid registry key ID.") }
        return value
    }
    private static func validHost(_ host: String) -> Bool {
        guard (1...253).contains(host.utf8.count) else { return false }
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            let bytes = Array(label.utf8)
            return (1...63).contains(bytes.count) && bytes.first != 45 && bytes.last != 45 &&
                bytes.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }
    public func validate(identity: SigningIdentity, now: Int64) throws {
        guard project == identity.project, issuedAt <= now, now < expiresAt, expiresAt - issuedAt <= 604_800 else {
            throw SignerError.invalid("Registry must match this device's project, be current and have at most seven days validity.")
        }
    }
}
