import Foundation
import XCTest
@testable import YhesSignerCore

final class PresentationTests: XCTestCase {
    func testSetupArgumentsKeepChosenPathAsOneLiteralArgument() throws {
        let path = "/tmp/project with ' quotes $(touch nope); --override"
        let context = try SetupContext(folder: path, human: "jarkko", project: "agent-yhes")
        XCTAssertEqual(context.arguments, ["pilot", "--project", path, "--human", "jarkko", "--project-id", "agent-yhes"])
    }
    func testNavigationRejectsInvalidOrReservedIDsAndNulPaths() {
        for human in ["", "../root", "--human", "codex", "claude", "a b", String(repeating: "a", count: 129)] {
            XCTAssertThrowsError(try SetupContext(folder: "/tmp/existing", human: human, project: "team"))
        }
        XCTAssertThrowsError(try SetupContext(folder: "relative", human: "alice", project: "team"))
        XCTAssertThrowsError(try SetupContext(folder: "/tmp/a\0b", human: "alice", project: "team"))
        XCTAssertThrowsError(try SetupContext(folder: "/tmp/existing", human: "alice", project: "../other"))
    }
    func testSuggestedIdentifiersAreBoundedAndNotTrustedAsAuthority() {
        XCTAssertEqual(SetupContext.suggestedID("My Project"), "My-Project")
        XCTAssertEqual(SetupContext.suggestedID("..project"), "project")
        XCTAssertEqual(SetupContext.suggestedID("a..b"), "a-b")
        XCTAssertEqual(SetupContext.suggestedID("--"), "")
        XCTAssertEqual(SetupContext.suggestedID(String(repeating: "a", count: 200)).count, 128)
    }
    func testOutputIsBoundedAcrossManyChunksAndOneOversizeChunk() {
        var output = SetupOutput()
        for _ in 0..<200 { output.append(Data(repeating: 120, count: 1_000)) }
        XCTAssertEqual(output.bytes.count, SetupOutput.limit)
        XCTAssertTrue(output.truncated)
        output.append(Data(repeating: 121, count: SetupOutput.limit * 3))
        XCTAssertEqual(output.bytes, Data(repeating: 121, count: SetupOutput.limit))
    }
    func testProgressTracksLatestStageWithoutGrantingCompletion() {
        var output = SetupOutput()
        output.append(Data("step 1/7 identity: pending\nstep 3/7 registry: pending\n".utf8))
        XCTAssertEqual(output.progressStage, .team)
        output.append(Data("step 4/7 delegation: pending\n".utf8))
        XCTAssertEqual(output.progressStage, .permissions)
        output.append(Data("step 6/7 group: pending\n".utf8))
        XCTAssertEqual(output.progressStage, .channel)
        XCTAssertFalse(output.result(exitCode: 0).succeeded)
    }
    func testOnlyCompleteSuccessfulPilotResultShowsReady() {
        var output = SetupOutput(); output.append(Data(#"{"ok":true,"ready":true,"command":"pilot","project_id":"demo"}"#.utf8))
        XCTAssertTrue(output.result(exitCode: 0).succeeded)
        XCTAssertFalse(output.result(exitCode: 1).succeeded)
        var wrong = SetupOutput(); wrong.append(Data(#"{"ok":true,"command":"send"}"#.utf8))
        XCTAssertFalse(wrong.result(exitCode: 0).succeeded)
        var truncated = SetupOutput(); truncated.append(Data(repeating: 32, count: SetupOutput.limit + 1)); truncated.append(output.bytes)
        XCTAssertFalse(truncated.result(exitCode: 0).succeeded)
        for payload in [#"{"ok":true,"command":"pilot"}"#, #"{"ok":true,"ready":false,"command":"pilot"}"#,
                        #"{"ok":false,"ready":true,"command":"pilot"}"#] {
            var incomplete = SetupOutput(); incomplete.append(Data(payload.utf8))
            XCTAssertFalse(incomplete.result(exitCode: 0).succeeded)
        }
    }
    func testFailedSetupOffersResumeAndBoundsErrorCopy() {
        var output = SetupOutput()
        output.append(try! JSONSerialization.data(withJSONObject: ["ok": false, "error": ["message": String(repeating: "x", count: 10_000)]]))
        let result = output.result(exitCode: 1)
        XCTAssertFalse(result.succeeded)
        XCTAssertTrue(result.message.contains("Resume"))
        XCTAssertLessThan(result.message.count, 700)
    }
    private func event(kind: String, body: [String: Any], audience: [String] = ["alice", "claude", "codex"]) throws -> ValidatedEvent {
        try ValidatedEvent.parse(JSONSerialization.data(withJSONObject: [
            "version": 1, "id": "test-event", "project": "demo", "kind": kind,
            "author": "alice", "key_id": "k_" + String(repeating: "a", count: 64), "session": NSNull(),
            "issued_at": 2_000_000_000, "expires_at": 2_000_000_300, "audience": audience,
            "group": "team", "epoch": 1, "previous": NSNull(), "body": body]))
    }
    func testStatementShowsExactWordsAndEveryRecipient() throws {
        let recipients = (0..<128).map { String(format: "recipient-%03d", $0) }
        let words = "First line.\n\n  Preserve my exact words.\nLast line."
        let document = ReviewedDocument.event(try event(kind: "human.statement", body: ["text": words], audience: recipients), nil)
        XCTAssertTrue(document.reviewText.contains(words))
        for recipient in recipients { XCTAssertTrue(document.reviewText.contains(recipient)) }
        XCTAssertTrue(document.reviewText.contains("Recipients (128)"))
        XCTAssertTrue(document.reviewText.contains("Project: demo"))
        XCTAssertTrue(document.reviewText.contains("Group: team · Epoch: 1"))
        XCTAssertEqual(document.approvalAction, "Sign statement with Touch ID…")
        XCTAssertNil(document.setupStage)
    }
    func testPermissionsNameAgentKeyAndEveryPurpose() throws {
        let key = "k_" + String(repeating: "b", count: 64)
        let purposes = ["action.execute", "agent.message", "agent.relay", "ticket.action"]
        let document = ReviewedDocument.event(try event(kind: "agent.delegation", body: ["agent": "codex", "agent_key_id": key, "purposes": purposes]), nil)
        for text in ["Send messages", "Relay signed human messages", "separate human approval", "tickets without another human approval", "codex", "alice", "claude"] { XCTAssertTrue(document.reviewText.contains(text)) }
        for text in purposes + [key] { XCTAssertTrue(document.reviewDetails.contains(text)); XCTAssertFalse(document.reviewText.contains(text)) }
        XCTAssertTrue(document.reviewText.contains("May 2033")); XCTAssertFalse(document.reviewText.contains("2000000000"))
        XCTAssertEqual(document.setupStage, .permissions)
        XCTAssertEqual(document.approvalAction, "Allow permissions with Touch ID…")
    }
    func testRegistryPresentationRetainsAllParticipantsKeysAndRevocations() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "p256-registry-payload", withExtension: "json", subdirectory: "Fixtures"))
        let registry = try ValidatedRegistry.parse(Data(contentsOf: url))
        let document = ReviewedDocument.registry(registry)
        for participant in registry.participants { XCTAssertTrue(document.reviewText.contains(participant.id)) }
        for key in registry.keys {
            XCTAssertTrue(document.reviewText.contains(key.participant))
            XCTAssertFalse(document.reviewText.contains(key.publicKey.base64EncodedString()))
            XCTAssertTrue(document.reviewDetails.contains(key.keyID)); XCTAssertTrue(document.reviewDetails.contains(key.publicKey.base64EncodedString()))
        }
        for key in registry.revokedKeyIDs { XCTAssertTrue(document.reviewText.contains(key)) }
        XCTAssertEqual(document.setupStage, .team)
        XCTAssertEqual(document.approvalAction, "Approve team with Touch ID…")
    }
    func testModalBlocksIncomingRequestsUntilItsOwnResultReturns() {
        var gate = ManualReviewGate()
        XCTAssertTrue(gate.canReceive(hasReview: false, hasRequest: false, hasConnection: false, busy: false))
        XCTAssertTrue(gate.beginModal(revision: 4, hasRequest: false, hasConnection: false, busy: false))
        XCTAssertFalse(gate.canReceive(hasReview: false, hasRequest: false, hasConnection: false, busy: false))
        XCTAssertFalse(gate.beginModal(revision: 4, hasRequest: false, hasConnection: false, busy: false))
        XCTAssertTrue(gate.endModal(revision: 4, hasRequest: false, hasConnection: false, busy: false))
        XCTAssertTrue(gate.canReceive(hasReview: false, hasRequest: false, hasConnection: false, busy: false))
    }
    func testModalRejectsChangedRevisionOrHijackedOwnership() {
        for (revision, request, connection, busy) in [(5, false, false, false), (4, true, false, false), (4, false, true, false), (4, false, false, true)] {
            var gate = ManualReviewGate()
            XCTAssertTrue(gate.beginModal(revision: 4, hasRequest: false, hasConnection: false, busy: false))
            XCTAssertFalse(gate.endModal(revision: UInt64(revision), hasRequest: request, hasConnection: connection, busy: busy))
            XCTAssertFalse(gate.modalOpen)
        }
    }
    func testManualDialogsCannotOpenWhileARequestOrWorkerOwnsTheReview() {
        for (request, connection, busy) in [(true, false, false), (false, true, false), (false, false, true)] {
            var gate = ManualReviewGate()
            XCTAssertFalse(gate.beginModal(revision: 1, hasRequest: request, hasConnection: connection, busy: busy))
            XCTAssertFalse(gate.canReceive(hasReview: false, hasRequest: request, hasConnection: connection, busy: busy))
            XCTAssertFalse(gate.modalOpen)
        }
        XCTAssertFalse(ManualReviewGate().canReceive(hasReview: true, hasRequest: false, hasConnection: false, busy: false))
    }
    func testSigningCannotRouteAManualDocumentToAnotherRequest() throws {
        let displayed = ReviewedDocument.event(try event(kind: "human.statement", body: ["text": "Displayed words"]), nil)
        let incoming = ReviewedDocument.event(try event(kind: "human.statement", body: ["text": "Different request words"]), nil)
        XCTAssertTrue(ManualReviewGate.ownsDocument(displayed, requestDocument: displayed, hasRequest: true))
        XCTAssertFalse(ManualReviewGate.ownsDocument(displayed, requestDocument: incoming, hasRequest: true))
        XCTAssertFalse(ManualReviewGate.ownsDocument(displayed, requestDocument: nil, hasRequest: true))
        XCTAssertTrue(ManualReviewGate.ownsDocument(displayed, requestDocument: nil, hasRequest: false))
    }
    func testMemberChangeNamesPerformerMemberChannelAndEveryRecipient() throws {
        let key = "k_" + String(repeating: "b", count: 64), digest = String(repeating: "c", count: 64)
        let action = try ActionRequest.parse(JSONSerialization.data(withJSONObject: ["version": 1, "project": "demo", "action": "group.add", "performer": "codex", "group": "team", "epoch": 1,
            "audience": ["alice", "claude", "codex"], "parameters": ["member": "claude", "key_id": key, "key_package_digest": digest]]))
        let value = try event(kind: "action.authorization", body: ["action": "group.add", "performer": "codex", "request_digest": action.digest])
        try action.validateBinding(to: value)
        let document = ReviewedDocument.event(value, action)
        XCTAssertTrue(document.reviewText.contains("Let codex add claude to the channel “team”"))
        for recipient in action.audience { XCTAssertTrue(document.reviewText.contains(recipient)) }
        XCTAssertTrue(document.reviewText.contains("Epoch: 1")); XCTAssertTrue(document.reviewText.contains("May 2033"))
        XCTAssertTrue(document.reviewDetails.contains(key)); XCTAssertTrue(document.reviewDetails.contains(digest))
    }
}
