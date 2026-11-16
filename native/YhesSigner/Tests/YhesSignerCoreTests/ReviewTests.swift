import CryptoKit
import Foundation
import XCTest
@testable import YhesSignerCore

private final class ReviewTestSigner: EventSigning, @unchecked Sendable {
    let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([1]))
    var signed: [Data] = []
    var failAt: Int?
    var afterSignature: (() -> Void)?
    func signPAE(_ bytes: Data) throws -> Data {
        signed.append(bytes)
        if signed.count == failAt { throw SignerError.invalid("Test authentication refusal") }
        let signature = try key.signature(for: bytes).rawRepresentation
        afterSignature?()
        return signature
    }
    var identity: SigningIdentity { try! SigningIdentity(author: "alice", project: "demo", publicKey: key.publicKey.x963Representation) }
}

final class ReviewTests: XCTestCase {
    private let now: Int64 = 2_000_000_000
    private func encode(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func statement(_ id: String, _ overrides: [String: Any] = [:]) throws -> Data {
        let signer = ReviewTestSigner()
        var object: [String: Any] = ["version": 1, "id": id, "project": "demo", "kind": "human.statement",
            "author": "alice", "key_id": try signer.identity.keyID, "session": NSNull(),
            "issued_at": now, "expires_at": now + 300, "audience": ["alice", "alice-agent"],
            "group": NSNull(), "epoch": NSNull(), "previous": NSNull(), "body": ["text": "Exact statement \(id)"]]
        object.merge(overrides) { _, value in value }
        return try encode(object)
    }
    private func registryObject() throws -> [String: Any] {
        let signer = ReviewTestSigner()
        return ["version": 1, "project": "demo", "generation": 1, "previous": NSNull(),
            "issued_at": now, "expires_at": now + 600,
            "participants": [
                ["id": "alice", "kind": "human", "controller": NSNull(), "ghes": ["instance": "ghes.example.com", "user_id": 1001]],
                ["id": "alice-agent", "kind": "agent", "controller": "alice", "ghes": NSNull()]],
            "keys": [["key_id": try signer.identity.keyID, "participant": "alice", "algorithm": "p256-sha256",
                      "public_key": signer.identity.publicKey.base64EncodedString(), "not_before": now, "not_after": now + 3600]],
            "revocations": []]
    }
    private func registry(_ overrides: [String: Any] = [:]) throws -> ValidatedRegistry {
        var object = try registryObject(); object.merge(overrides) { _, value in value }
        return try ValidatedRegistry.parse(encode(object))
    }
    private func batch() throws -> StatementBatch { try StatementBatch(payloads: [statement("one"), statement("two")]) }
    private func plan(_ document: ReviewedDocument) throws -> FixedSigningPlan {
        try FixedSigningPlan(document: document, identity: ReviewTestSigner().identity, now: now)
    }
    func testBatchHasExactImmutableBytesAndOrderedDigest() throws {
        var payloads = try [statement("one"), statement("two") + Data([10])]
        let batch = try StatementBatch(payloads: payloads)
        XCTAssertEqual(batch.events.map(\.payload), payloads)
        let original = payloads[0]
        payloads[0].append(32)
        XCTAssertEqual(batch.events[0].payload, original)
        XCTAssertNotEqual(batch.digest, try StatementBatch(payloads: payloads).digest)
        XCTAssertNotEqual(batch.digest, try StatementBatch(payloads: payloads.reversed()).digest)
    }
    func testBatchRejectsEmptyOversizeAndTooManyItems() throws {
        XCTAssertThrowsError(try StatementBatch(payloads: []))
        XCTAssertThrowsError(try StatementBatch(payloads: (0...16).map { try statement("item-\($0)") }))
        XCTAssertThrowsError(try StatementBatch(payloads: [Data(repeating: 32, count: StatementBatch.maxBytes + 1)]))
        XCTAssertNoThrow(try StatementBatch(payloads: (0..<16).map { try statement("item-\($0)") }))
    }
    func testBatchRejectsDuplicateIDsAndMixedScope() throws {
        let first = try statement("one")
        XCTAssertThrowsError(try StatementBatch(payloads: [first, first]))
        let changes: [[String: Any]] = [["project": "other"], ["author": "bob"],
            ["key_id": "k_" + String(repeating: "b", count: 64)], ["audience": ["alice"]],
            ["group": "group-1", "epoch": 0]]
        for change in changes {
            XCTAssertThrowsError(try StatementBatch(payloads: [first, statement("two", change)]))
        }
    }
    func testBatchRejectsMajorActionsAndSessions() throws {
        let delegation = try statement("delegation", ["kind": "agent.delegation", "body": [
            "agent": "alice-agent", "agent_key_id": "k_" + String(repeating: "b", count: 64), "purposes": ["agent.message"]]])
        XCTAssertThrowsError(try StatementBatch(payloads: [statement("one"), delegation]))
        XCTAssertThrowsError(try StatementBatch(payloads: [statement("one", ["session": String(repeating: "a", count: 64)])]))
    }
    func testBatchPlanSignsOnlyExactReviewedListAndExportsIndividualEnvelopes() throws {
        let batch = try batch(), signer = ReviewTestSigner()
        let result = try plan(.statementBatch(batch)).sign(using: signer, now: { self.now })
        XCTAssertEqual(signer.signed, batch.events.map { DSSE.pae(payload: $0.payload) })
        XCTAssertEqual(result.envelopes.count, 2)
        let export = try XCTUnwrap(try JSONSerialization.jsonObject(with: result.exportData()) as? [String: Any])
        XCTAssertEqual(export["format"] as? String, "yhes.reviewed-batch.v1")
        XCTAssertEqual(export["batch_digest"] as? String, batch.digest)
        let envelopes = try XCTUnwrap(export["envelopes"] as? [[String: Any]])
        for (index, envelope) in envelopes.enumerated() {
            XCTAssertEqual(envelope["payload_type"] as? String, DSSE.payloadType)
            XCTAssertEqual(Data(base64Encoded: try XCTUnwrap(envelope["payload"] as? String)), batch.events[index].payload)
        }
    }
    func testAttemptCannotBeUsedTwiceOrAfterCancellation() throws {
        let plan = try plan(.statementBatch(batch()))
        var permit = OneUseSigningPermit(plan)
        XCTAssertEqual(try permit.take(), plan)
        XCTAssertThrowsError(try permit.take())
        var cancelled = OneUseSigningPermit(plan); cancelled.invalidate()
        XCTAssertThrowsError(try cancelled.take())
    }
    func testFailureInBatchReturnsNoPartialResultAndAttemptStaysConsumed() throws {
        var permit = try OneUseSigningPermit(plan(.statementBatch(batch())))
        let signer = ReviewTestSigner(); signer.failAt = 2
        let frozen = try permit.take()
        XCTAssertThrowsError(try frozen.sign(using: signer, now: { self.now }))
        XCTAssertEqual(signer.signed.count, 2)
        XCTAssertThrowsError(try permit.take())
    }
    func testBatchExpiryDuringSigningDiscardsEntireBatch() throws {
        let signer = ReviewTestSigner(); var clock = now
        signer.afterSignature = { clock += 300 }
        XCTAssertThrowsError(try plan(.statementBatch(batch())).sign(using: signer, now: { clock }))
        XCTAssertEqual(signer.signed.count, 1)
    }
    func testBatchCancellationDuringSigningDiscardsEntireBatch() throws {
        let signer = ReviewTestSigner(); var cancelled = false
        signer.afterSignature = { cancelled = true }
        XCTAssertThrowsError(try plan(.statementBatch(batch())).sign(using: signer, now: { self.now }, checkCancellation: {
            if cancelled { throw SignerError.invalid("Cancelled") }
        }))
        XCTAssertEqual(signer.signed.count, 1)
    }
    func testExpiredBatchFailsBeforeAnySigning() throws {
        let signer = ReviewTestSigner()
        let fixed = try plan(.statementBatch(batch()))
        XCTAssertThrowsError(try fixed.sign(using: signer, now: { self.now + 300 }))
        XCTAssertTrue(signer.signed.isEmpty)
    }
    func testChangingModeOrDocumentsInvalidatesReview() throws {
        let signer = ReviewTestSigner(); var state = ReviewState()
        state.replace(with: .statementBatch(try batch())); let revision = state.revision
        state.replace(with: .registry(try registry()))
        XCTAssertThrowsError(try state.checked(revision: revision, identity: signer.identity, now: now))
        let registryRevision = state.revision; state.invalidate()
        XCTAssertThrowsError(try state.checked(revision: registryRevision, identity: signer.identity, now: now))
    }
    func testRegistryExactBytesAndSeparateSignatureDomain() throws {
        let original = try encode(registryObject()) + Data([10])
        let registry = try ValidatedRegistry.parse(original), signer = ReviewTestSigner()
        let result = try plan(.registry(registry)).sign(using: signer, now: { self.now })
        XCTAssertEqual(signer.signed, [DSSE.pae(payload: original, kind: .registry)])
        XCTAssertTrue(signer.signed[0].starts(with: Data("DSSEv1 43 application/vnd.agent-yhes.registry.v1+json ".utf8)))
        let env = try XCTUnwrap(try StrictJSON.parse(result.exportData()).object)
        XCTAssertEqual(env["payload_type"], .string(DSSEPayloadKind.registry.rawValue))
        XCTAssertEqual(Data(base64Encoded: try XCTUnwrap(env["payload"]?.string)), original)
        let eventDomainSignature = try signer.signPAE(DSSE.pae(payload: original))
        XCTAssertThrowsError(try DSSE.envelope(payload: original, signature: eventDomainSignature,
            publicKey: signer.identity.publicKey, kind: .registry))
    }
    func testIndependentRegistryVectorAndPayloadPreservation() throws {
        let payload = try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: "p256-registry-payload", withExtension: "json", subdirectory: "Fixtures")))
        let bytes = try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: "p256-registry-envelope", withExtension: "json", subdirectory: "Fixtures")))
        let envelope = try XCTUnwrap(try StrictJSON.parse(bytes).object)
        let entry = try XCTUnwrap(envelope["signatures"]?.array?.first?.object)
        let raw = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(entry["signature"]?.string)))
        XCTAssertEqual(Data(base64Encoded: try XCTUnwrap(envelope["payload"]?.string)), payload)
        XCTAssertEqual(try ValidatedRegistry.parse(payload).generation, 1)
        XCTAssertNoThrow(try DSSE.envelope(payload: payload, signature: raw, publicKey: ReviewTestSigner().identity.publicKey, kind: .registry))
        XCTAssertThrowsError(try DSSE.envelope(payload: payload + Data([32]), signature: raw, publicKey: ReviewTestSigner().identity.publicKey, kind: .registry))
    }
    func testRegistryAuthorityDoesNotSelfEnrollFromPayload() throws {
        // Registry signing authority is externally pinned; it need not be a
        // participant key. No authority/pin field in a draft is accepted.
        let registry = try registry(["keys": []])
        XCTAssertNoThrow(try plan(.registry(registry)).sign(using: ReviewTestSigner(), now: { self.now }))
        XCTAssertThrowsError(try self.registry(["authority": "alice"]))
        XCTAssertThrowsError(try self.registry(["trusted": true]))
    }
    func testEventAndRegistryCannotMasqueradeAsEachOther() throws {
        XCTAssertThrowsError(try ValidatedRegistry.parse(statement("one")))
        XCTAssertThrowsError(try ValidatedEvent.parse(encode(registryObject())))
    }
    func testRegistryGenerationAndPreviousRules() throws {
        for fields: [String: Any] in [["generation": 0], ["generation": -1], ["generation": true], ["generation": 2],
            ["previous": String(repeating: "a", count: 64)], ["generation": 2, "previous": "bad"]] {
            XCTAssertThrowsError(try registry(fields))
        }
        XCTAssertNoThrow(try registry(["generation": 2, "previous": String(repeating: "a", count: 64)]))
    }
    func testRegistryUnknownMissingDuplicateKeysRejected() throws {
        XCTAssertThrowsError(try registry(["version": 2]))
        XCTAssertThrowsError(try registry(["extra": []]))
        var object = try registryObject(); object.removeValue(forKey: "revocations")
        XCTAssertThrowsError(try ValidatedRegistry.parse(encode(object)))
        let json = String(decoding: try encode(registryObject()), as: UTF8.self)
        let duplicate = json.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1")
        XCTAssertThrowsError(try ValidatedRegistry.parse(Data(duplicate.utf8)))
    }
    func testRegistryParticipantSortKindsAndControllers() throws {
        let human: [String: Any] = ["id": "alice", "kind": "human", "controller": NSNull(), "ghes": ["instance": "ghes.example.com", "user_id": 1001]]
        let agent: [String: Any] = ["id": "alice-agent", "kind": "agent", "controller": "alice", "ghes": NSNull()]
        XCTAssertThrowsError(try registry(["participants": [agent, human]]))
        XCTAssertThrowsError(try registry(["participants": [human, human]]))
        for fields: [String: Any] in [["kind": "Human"], ["controller": "alice-agent"], ["extra": true]] {
            var changed = human; changed.merge(fields) { _, value in value }
            XCTAssertThrowsError(try registry(["participants": [changed, agent]]))
        }
        for fields: [String: Any] in [["controller": "unknown"], ["controller": NSNull()], ["ghes": ["instance": "ghes.example.com", "user_id": 1002]]] {
            var changed = agent; changed.merge(fields) { _, value in value }
            XCTAssertThrowsError(try registry(["participants": [human, changed]]))
        }
    }
    func testRegistryRejectsGHESAmbiguityAndDuplicateAccounts() throws {
        for account: [String: Any] in [["instance": "https://ghes.example.com", "user_id": 1],
            ["instance": "GHES.example.com", "user_id": 1], ["instance": "ghes..example.com", "user_id": 1],
            ["instance": "ghes.example.com", "user_id": 0], ["instance": "ghes.example.com", "user_id": true],
            ["instance": "ghes.example.com", "user_id": 1, "name": "alice"]] {
            XCTAssertThrowsError(try registry(["participants": [["id": "alice", "kind": "human", "controller": NSNull(), "ghes": account]]]))
        }
        let account: [String: Any] = ["instance": "ghes.example.com", "user_id": 1]
        XCTAssertThrowsError(try registry(["participants": [
            ["id": "alice", "kind": "human", "controller": NSNull(), "ghes": account],
            ["id": "service", "kind": "service", "controller": NSNull(), "ghes": account]]]))
    }
    func testRegistryKeysRejectMismatchInvalidPointsUnknownOwnersAndDuplicates() throws {
        let original = try XCTUnwrap(try registryObject()["keys"] as? [[String: Any]])[0]
        for fields: [String: Any] in [["key_id": "k_" + String(repeating: "b", count: 64)],
            ["participant": "unknown"], ["algorithm": "rsa"], ["public_key": Data(repeating: 0, count: 65).base64EncodedString()],
            ["not_before": now + 3601], ["extra": true]] {
            var key = original; key.merge(fields) { _, value in value }
            XCTAssertThrowsError(try registry(["keys": [key]]))
        }
        XCTAssertThrowsError(try registry(["keys": [original, original]]))
    }
    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
    }
    func testRustBridgeAcceptsRFC8032AndRejectsWeakAndOffCurveEd25519Keys() throws {
        let key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        XCTAssertEqual(try RegistryKeyValidation.keyID(algorithm: "ed25519", raw: key),
            "k_62f86f298e70d2c824f181a96d85c24d59ff01a028f2476b22c87e9e4eecfa8f")
        let invalid = [Data(), Data(repeating: 0, count: 31), Data(repeating: 0, count: 32),
            Data([1]) + Data(repeating: 0, count: 31),
            Data([2]) + Data(repeating: 0, count: 31),
            hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
        for bytes in invalid { XCTAssertThrowsError(try RegistryKeyValidation.keyID(algorithm: "ed25519", raw: bytes)) }
        XCTAssertThrowsError(try RegistryKeyValidation.keyID(algorithm: "Ed25519", raw: key))
    }
    func testRustBridgeP256MatchesCryptoKitAndRejectsInvalidPoints() throws {
        let raw = ReviewTestSigner().identity.publicKey
        XCTAssertEqual(try RegistryKeyValidation.keyID(algorithm: "p256-sha256", raw: raw), try DSSE.keyID(publicKey: raw))
        for bytes in [Data(), Data(repeating: 4, count: 65), Data(repeating: 0, count: 65), Data(repeating: 3, count: 33)] {
            XCTAssertThrowsError(try RegistryKeyValidation.keyID(algorithm: "p256-sha256", raw: bytes))
        }
    }
    func testRegistryAcceptsEd25519AgentWithVerifierValidatedKey() throws {
        let raw = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let key: [String: Any] = ["key_id": try RegistryKeyValidation.keyID(algorithm: "ed25519", raw: raw),
            "participant": "alice-agent", "algorithm": "ed25519", "public_key": raw.base64EncodedString(),
            "not_before": now, "not_after": now + 3600]
        let registry = try registry(["keys": [key]])
        XCTAssertEqual(registry.keys.first?.algorithm, "ed25519")
        XCTAssertNoThrow(try plan(.registry(registry)).sign(using: ReviewTestSigner(), now: { self.now }))
        var bad = key
        let offCurve = Data([2]) + Data(repeating: 0, count: 31)
        bad["public_key"] = offCurve.base64EncodedString()
        bad["key_id"] = "k_" + DSSE.digest(Data("agent-yhes/key/v1\0ed25519\0".utf8) + offCurve)
        XCTAssertThrowsError(try self.registry(["keys": [bad]]))
    }
    func testRegistryRejectsNoncanonicalBase64() throws {
        var key = try XCTUnwrap(try registryObject()["keys"] as? [[String: Any]])[0]
        key["public_key"] = try XCTUnwrap(key["public_key"] as? String) + "\n"
        XCTAssertThrowsError(try registry(["keys": [key]]))
    }
    func testRegistryRevocationSchemaOrderingAndTimestamps() throws {
        let id = "k_" + String(repeating: "b", count: 64)
        let r: [String: Any] = ["key_id": id, "revoked_at": now]
        XCTAssertNoThrow(try registry(["revocations": [r]]))
        XCTAssertThrowsError(try registry(["revocations": [r, r]]))
        for fields: [String: Any] in [["key_id": "bad"], ["revoked_at": -1], ["revoked_at": true], ["extra": true]] {
            var changed = r; changed.merge(fields) { _, value in value }
            XCTAssertThrowsError(try registry(["revocations": [changed]]))
        }
    }
    func testRegistrySigningPolicyBindsProjectAndCurrentBoundedValidity() throws {
        let identity = ReviewTestSigner().identity
        for fields: [String: Any] in [["project": "other"], ["issued_at": now + 1], ["expires_at": now + 604801]] {
            XCTAssertThrowsError(try registry(fields).validate(identity: identity, now: now))
        }
        XCTAssertThrowsError(try registry().validate(identity: identity, now: now + 600))
        XCTAssertThrowsError(try registry(["expires_at": now]))
    }
}
