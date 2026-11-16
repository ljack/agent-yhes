import Foundation

public enum ReviewedDocument: Sendable, Equatable {
    case event(ValidatedEvent, ActionRequest?)
    case statementBatch(StatementBatch)
    case registry(ValidatedRegistry)

    public func validate(identity: SigningIdentity, now: Int64) throws {
        switch self {
        case .event(let event, let request): try SigningPolicy.validate(event, identity: identity, now: now, request: request)
        case .statementBatch(let batch): try batch.validate(identity: identity, now: now)
        case .registry(let registry): try registry.validate(identity: identity, now: now)
        }
    }
    public var digest: String {
        switch self {
        case .event(let event, _): return event.digest
        case .statementBatch(let batch): return batch.digest
        case .registry(let registry): return registry.digest
        }
    }
    public var authenticationReason: String {
        switch self {
        case .event(let event, _): return "Approve \(event.kind), project \(event.project), event \(event.id), digest \(digest.prefix(12))"
        case .statementBatch(let batch): return "Approve exactly \(batch.events.count) reviewed statements in \(batch.events[0].project), batch \(digest.prefix(12)). No future statements."
        case .registry(let registry): return "Approve full trust registry for \(registry.project), generation \(registry.generation), digest \(digest.prefix(12))"
        }
    }
    public var suggestedFilename: String {
        switch self {
        case .event(let event, _): return "approved-\(event.id).json"
        case .statementBatch: return "approved-batch-\(digest.prefix(12)).json"
        case .registry(let registry): return "approved-registry-\(registry.project)-\(registry.generation).json"
        }
    }
}

/// Revision is local review state, never proof of human action. All modes are
/// mutually exclusive; changing mode, bytes or sidecar invalidates old approval.
public struct ReviewState: Sendable {
    public private(set) var document: ReviewedDocument?
    public private(set) var revision: UInt64 = 0
    public init() {}
    public mutating func replace(with document: ReviewedDocument) { revision &+= 1; self.document = document }
    public mutating func invalidate() { revision &+= 1; document = nil }
    public func checked(revision expected: UInt64, identity: SigningIdentity, now: Int64) throws -> ReviewedDocument {
        guard revision == expected, let document else { throw SignerError.invalid("Review changed or expired. Review every document again.") }
        try document.validate(identity: identity, now: now)
        return document
    }
}

/// Immutable exact work list built BEFORE authentication. The backend accepts
/// only a one-use handle to this plan, never replacement bytes after Touch ID.
public struct FixedSigningPlan: Sendable, Equatable {
    public let document: ReviewedDocument
    public let identity: SigningIdentity
    public init(document: ReviewedDocument, identity: SigningIdentity, now: Int64) throws {
        try document.validate(identity: identity, now: now)
        self.document = document; self.identity = identity
    }
    public func sign(using signer: some EventSigning, now: () -> Int64,
                     checkCancellation: () throws -> Void = {}) throws -> SignedReview {
        try checkCancellation()
        try document.validate(identity: identity, now: now())
        let payloads: [(Data, DSSEPayloadKind)]
        switch document {
        case .event(let event, _): payloads = [(event.payload, .event)]
        case .statementBatch(let batch): payloads = batch.events.map { ($0.payload, .event) }
        case .registry(let registry): payloads = [(registry.payload, .registry)]
        }
        var envelopes: [Data] = []
        for (payload, kind) in payloads {
            try checkCancellation()
            try document.validate(identity: identity, now: now())
            let signature = try signer.signPAE(DSSE.pae(payload: payload, kind: kind))
            try checkCancellation()
            try document.validate(identity: identity, now: now())
            envelopes.append(try DSSE.envelope(payload: payload, signature: signature,
                                               publicKey: identity.publicKey, kind: kind))
        }
        // No partially signed batch is returned on any error or cancellation.
        try checkCancellation()
        try document.validate(identity: identity, now: now())
        return SignedReview(document: document, envelopes: envelopes)
    }
}

/// Consumed atomically under the backend lock. Not an authentication substitute.
public struct OneUseSigningPermit: Sendable {
    private var plan: FixedSigningPlan?
    public init(_ plan: FixedSigningPlan) { self.plan = plan }
    public mutating func take() throws -> FixedSigningPlan {
        guard let plan else { throw SignerError.invalid("Signing attempt was consumed or cancelled.") }
        self.plan = nil
        return plan
    }
    public mutating func invalidate() { plan = nil }
}

public struct SignedReview: Sendable {
    public let document: ReviewedDocument
    public let envelopes: [Data]
    fileprivate init(document: ReviewedDocument, envelopes: [Data]) { self.document = document; self.envelopes = envelopes }
    public func exportData() throws -> Data {
        guard case .statementBatch(let batch) = document else { return envelopes[0] }
        // This container is not a new wire event, signature or remote approval
        // attestation. Each inner DSSE envelope must be verified independently.
        let values = try envelopes.map { try JSONSerialization.jsonObject(with: $0) }
        return try JSONSerialization.data(withJSONObject: ["format": "yhes.reviewed-batch.v1",
            "batch_digest": batch.digest, "envelopes": values], options: [.sortedKeys])
    }
}
