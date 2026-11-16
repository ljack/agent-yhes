import XCTest
@testable import YhesSignerCore

final class ApprovalActivityTests: XCTestCase {
    func testSystemFocusTransferDoesNotWithdrawAnAlreadyFrozenAttempt() {
        XCTAssertEqual(ApprovalActivity.decision(for: .focusChanged, hasFrozenAttempt: true), .keepFrozenAttempt)
        XCTAssertEqual(ApprovalActivity.decision(for: .focusChanged, hasFrozenAttempt: false), .refresh)
    }

    func testHardInterruptionsCancelBeforeAndDuringAuthentication() {
        for reason in ApprovalInterruption.allCases where reason != .focusChanged {
            XCTAssertEqual(ApprovalActivity.decision(for: reason, hasFrozenAttempt: false), .cancel)
            XCTAssertEqual(ApprovalActivity.decision(for: reason, hasFrozenAttempt: true), .cancel)
        }
    }

    func testFocusDoesNotConvertAHardInterruptionIntoAnApprovedState() {
        // A caller must still clear its permit on lock/disconnect. The later
        // focus event only refreshes UI; it cannot create a frozen permit.
        XCTAssertEqual(ApprovalActivity.decision(for: .screenLocked, hasFrozenAttempt: true), .cancel)
        XCTAssertEqual(ApprovalActivity.decision(for: .focusChanged, hasFrozenAttempt: false), .refresh)
        var pending = PendingReview()
        let token = UUID()
        XCTAssertNoThrow(try pending.begin(token: token, now: 1))
        XCTAssertTrue(pending.finish(token))
        XCTAssertFalse(pending.isCurrent(token, now: 2))
    }
}

final class ApprovalAttemptTests: XCTestCase {
    private func identity(_ author: String) throws -> SigningIdentity {
        let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        let data = Data(stride(from: 0, to: hex.count, by: 2).map { offset in
            UInt8(hex.dropFirst(offset).prefix(2), radix: 16)!
        })
        return try SigningIdentity(author: author, project: "demo", publicKey: data)
    }
    func testLateCompletionCannotFinishOrReplaceTheNewRequest() throws {
        let alice = try identity("alice")
        let a = ApprovalAttemptBinding(attempt: UUID(), connection: UUID(), requestID: "a", revision: 1, identity: alice)
        let b = ApprovalAttemptBinding(attempt: UUID(), connection: UUID(), requestID: "b", revision: 2, identity: alice)
        var state = ApprovalAttempts(); state.begin(a); state.cancel(); state.begin(b)
        XCTAssertFalse(state.isCurrent(a, revision: 2, identity: alice, connection: b.connection, requestID: b.requestID))
        XCTAssertFalse(state.finish(a))
        XCTAssertEqual(state.active, b)
        XCTAssertTrue(state.isCurrent(b, revision: 2, identity: alice, connection: b.connection, requestID: b.requestID))
    }
    func testRetryOfSameDocumentStillHasADistinctAttempt() throws {
        let alice = try identity("alice"), token = UUID()
        let a = ApprovalAttemptBinding(attempt: UUID(), connection: token, requestID: "same", revision: 1, identity: alice)
        let b = ApprovalAttemptBinding(attempt: UUID(), connection: token, requestID: "same", revision: 1, identity: alice)
        var state = ApprovalAttempts(); state.begin(a); XCTAssertTrue(state.finish(a)); state.begin(b)
        XCTAssertFalse(state.isCurrent(a, revision: 1, identity: alice, connection: token, requestID: "same"))
        XCTAssertFalse(state.finish(a)); XCTAssertEqual(state.active, b)
    }
    func testManualReviewCannotDeliverIntoANewConnectionOrIdentity() throws {
        let alice = try identity("alice"), bob = try identity("bob")
        let manual = ApprovalAttemptBinding(attempt: UUID(), connection: nil, requestID: nil, revision: 9, identity: alice)
        var state = ApprovalAttempts(); state.begin(manual)
        XCTAssertTrue(state.isCurrent(manual, revision: 9, identity: alice, connection: nil, requestID: nil))
        XCTAssertFalse(state.isCurrent(manual, revision: 10, identity: alice, connection: nil, requestID: nil))
        XCTAssertFalse(state.isCurrent(manual, revision: 9, identity: bob, connection: nil, requestID: nil))
        XCTAssertFalse(state.isCurrent(manual, revision: 9, identity: alice, connection: UUID(), requestID: "new"))
    }
    func testArmingRequiresAContinuouslyVisibleUnchangedRequest() {
        var gate = ApprovalActionArming()
        gate.update(revision: 1, activeAndKey: false, now: 0)
        XCTAssertFalse(gate.isArmed(revision: 1, activeAndKey: false, now: 10))
        gate.update(revision: 1, activeAndKey: true, now: 10)
        XCTAssertFalse(gate.isArmed(revision: 1, activeAndKey: true, now: 10.9))
        XCTAssertTrue(gate.isArmed(revision: 1, activeAndKey: true, now: 11))
        gate.update(revision: 1, activeAndKey: false, now: 12)
        gate.update(revision: 1, activeAndKey: true, now: 13)
        XCTAssertFalse(gate.isArmed(revision: 1, activeAndKey: true, now: 13))
        gate.update(revision: 2, activeAndKey: true, now: 14)
        XCTAssertFalse(gate.isArmed(revision: 2, activeAndKey: true, now: 14.5))
        XCTAssertTrue(gate.isArmed(revision: 2, activeAndKey: true, now: 15))
        gate.reset(); XCTAssertFalse(gate.isArmed(revision: 2, activeAndKey: true, now: 20))
    }
}
