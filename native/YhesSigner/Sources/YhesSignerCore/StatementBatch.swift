import Foundation

/// A closed list, not a grant for future statements. There is no append API.
public struct StatementBatch: Equatable, Sendable {
    public static let maxCount = 16
    public static let maxBytes = 262_144
    public let events: [ValidatedEvent]
    public let digest: String

    public init(payloads: [Data]) throws {
        guard (1...Self.maxCount).contains(payloads.count),
              payloads.reduce(0, { $0 + $1.count }) <= Self.maxBytes else {
            throw SignerError.invalid("Select 1–16 statements totaling at most 256 KiB.")
        }
        let events = try payloads.map(ValidatedEvent.parse)
        let first = events[0]
        var ids = Set<String>()
        for event in events {
            guard event.kind == "human.statement", ids.insert(event.id).inserted,
                  event.project == first.project, event.author == first.author,
                  event.keyID == first.keyID, event.audience == first.audience,
                  event.fields["group"] == first.fields["group"],
                  event.fields["epoch"] == first.fields["epoch"] else {
                throw SignerError.invalid("A batch requires unique human statements with the same author, key, project, audience, group and epoch.")
            }
        }
        var manifest = Data("agent-yhes/reviewed-statement-batch/v1\0\(events.count) ".utf8)
        for event in events {
            manifest.append(Data("\(event.payload.count) ".utf8)); manifest.append(event.payload)
        }
        self.events = events; digest = DSSE.digest(manifest)
    }
    public func validate(identity: SigningIdentity, now: Int64) throws {
        for event in events { try SigningPolicy.validate(event, identity: identity, now: now) }
    }
}
