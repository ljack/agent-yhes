import Foundation

/// UI focus is not an authentication result. Once an explicit action has frozen
/// its one-use plan, macOS may give the Touch ID sheet focus. Security/liveness
/// interruptions still invalidate that exact attempt immediately.
public enum ApprovalInterruption: Sendable, CaseIterable {
    case focusChanged
    case screenLocked
    case sessionInactive
    case requestEnded
    case userCancelled
    case appClosed
    case documentChanged
    case identityChanged
}

public enum ApprovalActivityDecision: Sendable, Equatable {
    case refresh
    case keepFrozenAttempt
    case cancel
}

public enum ApprovalActivity {
    public static func decision(for reason: ApprovalInterruption,
                                hasFrozenAttempt: Bool) -> ApprovalActivityDecision {
        switch reason {
        case .focusChanged:
            return hasFrozenAttempt ? .keepFrozenAttempt : .refresh
        case .screenLocked, .sessionInactive, .requestEnded, .userCancelled,
             .appClosed, .documentChanged, .identityChanged:
            return .cancel
        }
    }
}

/// The main-actor continuation belongs to one frozen attempt, not to whatever
/// request happens to be displayed when a worker eventually returns.
public struct ApprovalAttemptBinding: Sendable, Equatable {
    public let attempt: UUID
    public let connection: UUID?
    public let requestID: String?
    public let revision: UInt64
    public let identity: SigningIdentity?
    public init(attempt: UUID, connection: UUID?, requestID: String?,
                revision: UInt64, identity: SigningIdentity?) {
        self.attempt = attempt; self.connection = connection; self.requestID = requestID
        self.revision = revision; self.identity = identity
    }
}

public struct ApprovalAttempts: Sendable {
    public private(set) var active: ApprovalAttemptBinding?
    public init() {}
    public mutating func begin(_ binding: ApprovalAttemptBinding) { active = binding }
    public func isCurrent(_ binding: ApprovalAttemptBinding, revision: UInt64,
                          identity: SigningIdentity?, connection: UUID?, requestID: String?) -> Bool {
        active == binding && binding.revision == revision && binding.identity == identity &&
        binding.connection == connection && binding.requestID == requestID
    }
    @discardableResult public mutating func finish(_ binding: ApprovalAttemptBinding) -> Bool {
        guard active == binding else { return false }
        active = nil; return true
    }
    public mutating func cancel() { active = nil }
}

/// Prevent an input already in flight from approving newly presented content.
/// This is only a UI guard. The explicit action, fresh biometric authentication,
/// exact plan and liveness checks remain necessary.
public struct ApprovalActionArming: Sendable {
    public static let dwell: TimeInterval = 1
    private var revision: UInt64?
    private var since: TimeInterval?
    public init() {}
    public mutating func update(revision: UInt64, activeAndKey: Bool, now: TimeInterval) {
        if self.revision != revision { self.revision = revision; since = nil }
        guard activeAndKey else { since = nil; return }
        if since == nil { since = now }
    }
    public func isArmed(revision: UInt64, activeAndKey: Bool, now: TimeInterval) -> Bool {
        guard activeAndKey, self.revision == revision, let since, now >= since else { return false }
        return now - since >= Self.dwell
    }
    public mutating func reset() { revision = nil; since = nil }
}
