import Foundation

/// Exact request sidecar from SECURE-TEAM-CONTRACT. Hash-only consent is refused.
public struct ActionRequest: Sendable, Equatable {
    public let payload: Data
    public let project: String
    public let action: String
    public let performer: String
    public let group: String
    public let epoch: Int64
    public let audience: [String]
    public let parameters: [String: JSONValue]
    public var digest: String { DSSE.digest(payload) }
    public var exactText: String { String(decoding: payload, as: UTF8.self) }

    public static func parse(_ payload: Data) throws -> Self {
        guard let fields = try StrictJSON.parse(payload).object else { throw SignerError.invalid("Action request must be an object.") }
        try ValidatedEvent.exactKeys(fields, ["version", "project", "action", "performer", "group", "epoch", "audience", "parameters"])
        guard fields["version"] == .integer(1), let epoch = fields["epoch"]?.integer, epoch >= 0,
              let parameters = fields["parameters"]?.object else { throw SignerError.invalid("Invalid action version, epoch or parameters.") }
        let project = try ValidatedEvent.identifier(fields, "project")
        let action = try ValidatedEvent.identifier(fields, "action")
        let performer = try ValidatedEvent.identifier(fields, "performer")
        let group = try ValidatedEvent.identifier(fields, "group")
        let audience = try ValidatedEvent.identifiers(fields, "audience")
        switch action {
        case "group.create":
            try ValidatedEvent.exactKeys(parameters, [])
            guard epoch == 0, audience == [performer] else { throw SignerError.invalid("Initial group audience must be its performer at epoch zero.") }
        case "group.add":
            try ValidatedEvent.exactKeys(parameters, ["member", "key_id", "key_package_digest"])
            _ = try ValidatedEvent.identifier(parameters, "member")
            let keyID = try ValidatedEvent.text(parameters, "key_id")
            guard keyID.hasPrefix("k_"), ValidatedEvent.validDigest(String(keyID.dropFirst(2))),
                  ValidatedEvent.validDigest(try ValidatedEvent.text(parameters, "key_package_digest")) else { throw SignerError.invalid("Invalid member key or key-package digest.") }
        case "group.remove":
            try ValidatedEvent.exactKeys(parameters, ["member"])
            _ = try ValidatedEvent.identifier(parameters, "member")
        case "ticket.recover":
            try ValidatedEvent.exactKeys(parameters, ["ticket", "expected_revision", "stop_evidence"])
            _ = try ValidatedEvent.identifier(parameters, "ticket")
            guard let revision = parameters["expected_revision"]?.integer, revision >= 0 else { throw SignerError.invalid("Invalid expected ticket revision.") }
            let evidence = try ValidatedEvent.text(parameters, "stop_evidence")
            guard !evidence.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw SignerError.invalid("Ticket recovery requires explicit stop evidence.") }
        default:
            throw SignerError.invalid("Unsupported privileged action. Shell and deployment requests are not supported.")
        }
        return Self(payload: payload, project: project, action: action, performer: performer,
                    group: group, epoch: epoch, audience: audience, parameters: parameters)
    }
    public func validateBinding(to event: ValidatedEvent) throws {
        guard event.kind == "action.authorization", let body = event.fields["body"]?.object,
              body["action"] == .string(action), body["performer"] == .string(performer),
              body["request_digest"] == .string(digest), event.project == project,
              event.fields["group"] == .string(group), event.fields["epoch"] == .integer(epoch),
              event.audience == audience else {
            throw SignerError.invalid("Action details do not match the exact request digest, action, performer, project, group, epoch and audience in this authorization.")
        }
    }
}
