import Foundation

public enum SignerProtocolError: String, Error, Sendable {
    case invalidRequest = "invalid_request", invalidDocument = "invalid_document"
    case identityMissing = "identity_missing", identityMismatch = "identity_mismatch"
    case identityUnavailable = "identity_unavailable", identityExists = "identity_exists"
    case busy, unauthorized, timeout, cancelled, unavailable
    case approvalFailed = "approval_failed"
}

/// This layer accepts only typed work. Decoding never grants consent.
public struct SignerRequest: Sendable {
    public static let maxFrameBytes = 1_048_576
    public enum Operation: String, Sendable { case identity, enroll, review }
    public let id: String
    public let operation: Operation
    public let author: String
    public let project: String
    public let document: ReviewedDocument?

    public static func parse(_ bytes: Data) throws -> SignerRequest {
        do {
            guard let f = try StrictJSON.parseSocketFrame(bytes).object else { throw SignerProtocolError.invalidRequest }
            try ValidatedEvent.exactKeys(f, ["version", "id", "operation", "author", "project", "mode", "payloads", "request"])
            guard f["version"] == .integer(1), let id = f["id"]?.string,
                  id.utf8.count == 36, UUID(uuidString: id) != nil,
                  let op = f["operation"]?.string, let operation = Operation(rawValue: op),
                  let payloads = f["payloads"]?.array else { throw SignerProtocolError.invalidRequest }
            let author = try ValidatedEvent.identifier(f, "author"), project = try ValidatedEvent.identifier(f, "project")
            if operation != .review {
                guard f["mode"] == .null, payloads.isEmpty, f["request"] == .null else { throw SignerProtocolError.invalidRequest }
                return SignerRequest(id: id, operation: operation, author: author, project: project, document: nil)
            }
            guard (1...StatementBatch.maxCount).contains(payloads.count) else { throw SignerProtocolError.invalidRequest }
            let decoded = try payloads.map(decode)
            let document: ReviewedDocument
            do {
                switch f["mode"]?.string {
                case "event":
                    guard decoded.count == 1 else { throw SignerProtocolError.invalidRequest }
                    let event = try ValidatedEvent.parse(decoded[0])
                    let request = f["request"] == .null ? nil : try ActionRequest.parse(decode(f["request"]!))
                    guard (event.kind == "action.authorization") == (request != nil) else { throw SignerProtocolError.invalidDocument }
                    if let request { try request.validateBinding(to: event) }
                    guard event.author == author, event.project == project else { throw SignerProtocolError.identityMismatch }
                    document = .event(event, request)
                case "registry":
                    guard decoded.count == 1, f["request"] == .null else { throw SignerProtocolError.invalidRequest }
                    let registry = try ValidatedRegistry.parse(decoded[0])
                    guard registry.project == project else { throw SignerProtocolError.identityMismatch }
                    document = .registry(registry)
                case "batch":
                    guard f["request"] == .null else { throw SignerProtocolError.invalidRequest }
                    let batch = try StatementBatch(payloads: decoded)
                    guard batch.events[0].author == author, batch.events[0].project == project else { throw SignerProtocolError.identityMismatch }
                    document = .statementBatch(batch)
                default: throw SignerProtocolError.invalidRequest
                }
            } catch let e as SignerProtocolError { throw e }
            catch { throw SignerProtocolError.invalidDocument }
            return SignerRequest(id: id, operation: operation, author: author, project: project, document: document)
        } catch let e as SignerProtocolError { throw e }
        catch { throw SignerProtocolError.invalidRequest }
    }
    private static func decode(_ value: JSONValue) throws -> Data {
        guard let text = value.string, let bytes = Data(base64Encoded: text),
              bytes.base64EncodedString() == text, !bytes.isEmpty, bytes.count <= StrictJSON.maxBytes,
              String(data: bytes, encoding: .utf8) != nil else { throw SignerProtocolError.invalidRequest }
        return bytes
    }
    public func requireIdentity(_ identity: SigningIdentity) throws {
        guard identity.author == author, identity.project == project else { throw SignerProtocolError.identityMismatch }
    }
}

public enum SignerResponse {
    public static let invalidID = "00000000-0000-0000-0000-000000000000"
    public static func success(id: String, result: Data) throws -> Data {
        try encode(id: id, status: "ok", result: result.base64EncodedString(), error: nil)
    }
    public static func failure(id: String, code: SignerProtocolError) -> Data {
        // All fields are bounded constants or validated UUIDs; serialization cannot fail.
        try! encode(id: id, status: code == .cancelled ? "cancelled" : "error", result: nil, error: code.rawValue)
    }
    private static func encode(id: String, status: String, result: String?, error: String?) throws -> Data {
        var data = try JSONSerialization.data(withJSONObject: ["version": 1, "id": id, "status": status,
            "result": result as Any? ?? NSNull(), "error": error as Any? ?? NSNull()], options: [.sortedKeys])
        guard data.count <= SignerRequest.maxFrameBytes else { throw SignerProtocolError.invalidDocument }
        data.append(10)
        return data
    }
}

/// One request can own native consent. Disconnect and expiry consume that claim.
/// The connection token is unique even if a caller reuses a protocol UUID.
public struct PendingReview: Sendable {
    public private(set) var token: UUID?
    private var deadline: TimeInterval = 0
    public init() {}
    public mutating func begin(token: UUID, now: TimeInterval) throws {
        guard self.token == nil else { throw SignerProtocolError.busy }
        self.token = token; deadline = now + 300
    }
    public func isCurrent(_ token: UUID, now: TimeInterval) -> Bool { self.token == token && now < deadline }
    public mutating func finish(_ token: UUID) -> Bool {
        guard self.token == token else { return false }
        self.token = nil; deadline = 0; return true
    }
}
