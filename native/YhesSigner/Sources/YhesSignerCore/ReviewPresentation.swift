import Foundation

/// Display and navigation only. Never a substitute for a verified request or key.
public enum SetupStage: Int, CaseIterable, Sendable {
    case identity, team, permissions, channel
    public var title: String { ["Identity", "Team", "Permissions", "Channel"][rawValue] }
}

public struct SetupContext: Codable, Equatable, Sendable {
    public let folder: String
    public let human: String
    public let project: String
    public init(folder: String, human: String, project: String) throws {
        guard folder.hasPrefix("/"), !folder.utf8.contains(0),
              ValidatedEvent.validID(human), ValidatedEvent.validID(project),
              !["codex", "claude"].contains(human) else {
            throw SignerError.invalid("Choose an existing folder and use IDs made of letters, numbers, '.', '_' or '-'. The human ID must differ from codex and claude.")
        }
        self.folder = folder; self.human = human; self.project = project
    }
    public var arguments: [String] { ["pilot", "--project", folder, "--human", human, "--project-id", project] }
    public static func suggestedID(_ name: String) -> String {
        let mapped = name.utf8.map { byte -> UInt8 in
            (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) || [45, 46, 95].contains(byte) ? byte : 45
        }
        var value = String(decoding: mapped.prefix(128), as: UTF8.self)
        while let first = value.utf8.first, !((48...57).contains(first) || (65...90).contains(first) || (97...122).contains(first)) { value.removeFirst() }
        while value.contains("..") { value = value.replacingOccurrences(of: "..", with: "-") }
        return ValidatedEvent.validID(value) ? value : ""
    }
}

/// Bounded helper diagnostics are untrusted display data, never approval input.
public struct SetupOutput: Sendable {
    public static let limit = 32_768
    public private(set) var bytes = Data()
    public private(set) var truncated = false
    public init() {}
    public mutating func append(_ data: Data) {
        if bytes.count + data.count > Self.limit { truncated = true }
        bytes.append(data.suffix(Self.limit))
        if bytes.count > Self.limit { bytes.removeFirst(bytes.count - Self.limit) }
    }
    public var text: String { String(decoding: bytes, as: UTF8.self) }
    public var progressStage: SetupStage? {
        for line in text.split(separator: "\n").reversed() {
            if line.contains("step 7/7") || line.contains("step 6/7") || line.contains("step 5/7") { return .channel }
            if line.contains("step 4/7") { return .permissions }
            if line.contains("step 3/7") || line.contains("step 2/7") { return .team }
            if line.contains("step 1/7") { return .identity }
        }
        return nil
    }
    public func result(exitCode: Int32) -> (succeeded: Bool, message: String) {
        guard !truncated, let value = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
            return (false, "Setup stopped without a complete result. Resume to check the saved progress.")
        }
        if exitCode == 0, value["ok"] as? Bool == true, value["ready"] as? Bool == true, value["command"] as? String == "pilot" {
            return (true, "Your local team is ready. Codex and Claude can use the channel with the permissions you approved.")
        }
        let error = value["error"] as? [String: Any]
        let message = error?["message"] as? String ?? "Setup did not complete."
        return (false, String(message.prefix(600)) + " Resume to check what is saved and continue.")
    }
}

/// Modal dialogs run a nested event loop. Their result belongs only to the
/// manual review revision that opened them, never an arriving CLI request.
public struct ManualReviewGate: Sendable {
    private var modalRevision: UInt64?
    public var modalOpen: Bool { modalRevision != nil }
    public init() {}
    public mutating func beginModal(revision: UInt64, hasRequest: Bool, hasConnection: Bool, busy: Bool) -> Bool {
        guard !modalOpen, !hasRequest, !hasConnection, !busy else { return false }
        modalRevision = revision; return true
    }
    public mutating func endModal(revision: UInt64, hasRequest: Bool, hasConnection: Bool, busy: Bool) -> Bool {
        defer { modalRevision = nil }
        return modalRevision == revision && !hasRequest && !hasConnection && !busy
    }
    public func canReceive(hasReview: Bool, hasRequest: Bool, hasConnection: Bool, busy: Bool) -> Bool {
        !modalOpen && !hasReview && !hasRequest && !hasConnection && !busy
    }
    public static func ownsDocument(_ document: ReviewedDocument, requestDocument: ReviewedDocument?, hasRequest: Bool) -> Bool {
        !hasRequest || requestDocument == document
    }
}

extension ReviewedDocument {
    public var approvalAction: String {
        switch self {
        case .registry: return "Approve team with Touch ID…"
        case .statementBatch(let batch): return "Sign \(batch.events.count) statements with Touch ID…"
        case .event(let event, let action):
            switch event.kind {
            case "human.statement": return "Sign statement with Touch ID…"
            case "agent.delegation": return "Allow permissions with Touch ID…"
            default:
                switch action?.action {
                case "group.create": return "Create channel with Touch ID…"
                case "group.add": return "Add member with Touch ID…"
                case "group.remove": return "Remove member with Touch ID…"
                case "ticket.recover": return "Recover ticket with Touch ID…"
                default: return "Approve action with Touch ID…"
                }
            }
        }
    }
    public var setupStage: SetupStage? {
        switch self {
        case .registry: return .team
        case .event(let event, _):
            if event.kind == "agent.delegation" { return .permissions }
            if event.kind == "action.authorization" { return .channel }
            return nil
        case .statementBatch: return nil
        }
    }
    public var reviewHeading: String {
        switch self {
        case .event(let event, _):
            switch event.kind {
            case "human.statement": return "Review your statement"
            case "agent.delegation": return "Review agent permissions"
            default: return "Review a channel change"
            }
        case .statementBatch: return "Review these statements"
        case .registry: return "Review team identities"
        }
    }
    public var reviewText: String {
        switch self {
        case .event(let event, let action):
            let body = event.fields["body"]?.object ?? [:]
            let explanation: String
            switch event.kind {
            case "human.statement": explanation = "Your exact words\n\n" + (body["text"]?.string ?? "")
            case "agent.delegation":
                let names = ["agent.message": "Send messages as this agent", "agent.relay": "Relay signed human messages without changing the original",
                             "action.execute": "Carry out actions that have separate human approval",
                             "ticket.action": "Create, claim, release, update, complete and cancel tickets without another human approval"]
                let capabilities = body["purposes"]?.array?.compactMap(\.string).map { "• " + (names[$0] ?? $0) }.joined(separator: "\n") ?? ""
                explanation = "Allow \(body["agent"]?.string ?? "") to:\n\n\(capabilities)\n\nOnly within the project, recipients, channel and validity shown below. This does not let the agent sign as you.\nAgent key reference: \(Self.keyReference(body["agent_key_id"]?.string ?? ""))"
            default:
                if let action {
                    let member = action.parameters["member"]?.string ?? ""
                    switch action.action {
                    case "group.create": explanation = "Let \(action.performer) create the channel “\(action.group)”.\n\nThe initial channel contains only \(action.performer)."
                    case "group.add": explanation = "Let \(action.performer) add \(member) to the channel “\(action.group)”.\n\nMember: \(member)\nMember key reference: \(Self.keyReference(action.parameters["key_id"]?.string ?? ""))\nThe exact member key and invitation digest are in Details."
                    case "group.remove": explanation = "Let \(action.performer) remove \(member) from the channel “\(action.group)”.\n\nRemoved member: \(member)"
                    case "ticket.recover": explanation = "Let \(action.performer) recover ticket \(action.parameters["ticket"]?.string ?? "").\n\nExpected ticket revision: \(action.parameters["expected_revision"]?.integer.map(String.init) ?? "")\nStop evidence:\n\(action.parameters["stop_evidence"]?.string ?? "")"
                    default: explanation = "Review the complete action details before approving."
                    }
                } else { explanation = "Action details are missing. Open the matching action details in Advanced before approving." }
            }
            return explanation + "\n\n" + Self.scope(event)
        case .statementBatch(let batch):
            return batch.events.enumerated().map { "Statement \($0.offset + 1) of \(batch.events.count)\n\n\($0.element.fields["body"]?.object?["text"]?.string ?? "")" }.joined(separator: "\n\n") + "\n\n" + Self.scope(batch.events[0]) + "\n\nOnly these exact statements are approved. Future statements need a new review."
        case .registry(let registry):
            var text = "Trust these identities and their listed keys in project \(registry.project).\n\nTeam"
            for participant in registry.participants {
                text += "\n\n\(participant.id) — \(participant.kind == "human" ? "person" : "agent")"
                if let controller = participant.controller { text += ", controlled by \(controller)" }
                if let host = participant.ghesInstance, let user = participant.ghesUserID { text += "\nEnterprise account claim: \(host), user \(user). Verify independently." }
                else if participant.kind == "human" { text += "\nUses a local identity; no verified enterprise account is claimed." }
            }
            text += "\n\nKey bindings"
            for key in registry.keys {
                text += "\n\n\(key.participant): \(key.algorithm == "p256-sha256" ? "P-256 signing key" : "Ed25519 signing key")\nReference: \(Self.keyReference(key.keyID))\nValid from \(Self.date(key.notBefore))\nuntil \(Self.date(key.notAfter))"
            }
            text += "\n\nRevoked keys: " + (registry.revokedKeyIDs.isEmpty ? "none" : registry.revokedKeyIDs.joined(separator: "\n"))
            text += "\n\nRegistry version: \(registry.generation)\n" + (registry.previous == nil ? "First registry; no predecessor." : "Replaces a previous registry. Verify its full digest in Details.")
            return text + "\nValid from \(Self.date(registry.issuedAt))\nuntil \(Self.date(registry.expiresAt))\n\nDetails contains every complete key, digest and exact JSON field."
        }
    }
    public var reviewDetails: String {
        switch self {
        case .event(let event, let action):
            var text: String
            let body = event.fields["body"]?.object ?? [:]
            switch event.kind {
            case "human.statement": text = "Your exact words\n\n" + (body["text"]?.string ?? "")
            case "agent.delegation":
                text = "Give \(body["agent"]?.string ?? "") these permissions:\n" + (body["purposes"]?.array?.compactMap(\.string).joined(separator: ", ") ?? "") + "\nAgent key: \(body["agent_key_id"]?.string ?? "")"
            default:
                text = "Action: \(action?.action ?? "Missing details")\nPerformer: \(action?.performer ?? "")"
                if let action {
                    let labels = ["member": "Member", "key_id": "Member key", "key_package_digest": "Key package digest", "ticket": "Ticket", "expected_revision": "Expected revision", "stop_evidence": "Stop evidence"]
                    for key in action.parameters.keys.sorted() {
                        let value = action.parameters[key]!
                        text += "\n\(labels[key] ?? key): \(value.string ?? value.integer.map(String.init) ?? "Invalid")"
                    }
                }
            }
            return text + "\n\n" + Self.scope(event) + "\nEvent: \(event.id)\nSHA-256: \(event.digest)"
        case .statementBatch(let batch):
            return batch.events.enumerated().map { "Statement \($0.offset + 1) of \(batch.events.count)\n\n\($0.element.fields["body"]?.object?["text"]?.string ?? "")" }.joined(separator: "\n\n") + "\n\n" + Self.scope(batch.events[0]) + "\nBatch SHA-256: \(batch.digest)\nThis grants no permission for future statements."
        case .registry(let registry):
            var text = "Project: \(registry.project)\nGeneration: \(registry.generation)\nPrevious: \(registry.previous ?? "none — first registry")\nValidity (Unix time): \(registry.issuedAt) to \(registry.expiresAt)\n\nParticipants"
            for participant in registry.participants {
                text += "\n\n\(participant.id) · \(participant.kind)"
                if let controller = participant.controller { text += "\nControlled by: \(controller)" }
                if let host = participant.ghesInstance, let user = participant.ghesUserID {
                    text += "\nGHES claim: \(host), user \(user) · verify independently"
                } else if participant.kind == "human" { text += "\nlocal identity · no enterprise account claim" }
            }
            text += "\n\nPublic keys"
            for key in registry.keys {
                text += "\n\n\(key.participant) · \(key.algorithm)\nKey: \(key.keyID)\nPublic key: \(key.publicKey.base64EncodedString())\nValid (Unix time): \(key.notBefore) to \(key.notAfter)"
            }
            text += "\n\nRevoked keys: " + (registry.revokedKeyIDs.isEmpty ? "none" : registry.revokedKeyIDs.joined(separator: "\n"))
            return text + "\n\nSHA-256: \(registry.digest)\nVerify identity claims and the predecessor independently."
        }
    }
    private static func scope(_ event: ValidatedEvent) -> String {
        var result = "Author: \(event.author)\nProject: \(event.project)\nRecipients (\(event.audience.count)): \(event.audience.joined(separator: ", "))"
        if let group = event.fields["group"]?.string { result += "\nGroup: \(group) · Epoch: \(event.fields["epoch"]?.integer.map(String.init) ?? "all epochs (group-wide delegation)")" }
        result += "\nValid from \(date(event.issuedAt))\nuntil \(date(event.expiresAt))"
        return result
    }
    private static func keyReference(_ value: String) -> String { String(value.prefix(14)) + "…" + String(value.suffix(8)) }
    private static func date(_ seconds: Int64) -> String {
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "d MMM yyyy, HH:mm:ss 'UTC'"
        return formatter.string(from: Date(timeIntervalSince1970: Double(seconds)))
    }
}
