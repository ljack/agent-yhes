import CryptoKit
import Foundation
import XCTest
@testable import YhesSignerCore

private struct TestOnlySigner: EventSigning {
    // Publicly known test scalar. Never linked into the executable target.
    let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([1]))
    func signPAE(_ bytes: Data) throws -> Data { try key.signature(for: bytes).rawRepresentation }
    var identity: SigningIdentity { try! SigningIdentity(author: "alice", project: "demo", publicKey: key.publicKey.x963Representation) }
}
private struct RefusingSigner: EventSigning {
    func signPAE(_ bytes: Data) throws -> Data { throw SignerError.invalid("Authentication denied") }
}
private struct BrokenSigner: EventSigning {
    func signPAE(_ bytes: Data) throws -> Data { Data(repeating: 0, count: 64) }
}

final class SignerTests: XCTestCase {
    private let signer = TestOnlySigner()
    private let now: Int64 = 2_000_000_000
    private func draft(_ overrides: [String: Any] = [:]) throws -> Data {
        var object: [String: Any] = [
            "version": 1, "id": "event-1", "project": "demo", "kind": "human.statement",
            "author": "alice", "key_id": try signer.identity.keyID, "session": NSNull(),
            "issued_at": now, "expires_at": now + 300, "audience": ["alice", "bob"],
            "group": NSNull(), "epoch": NSNull(), "previous": NSNull(), "body": ["text": "Hyväksyn tämän täsmällisen viestin."]
        ]
        object.merge(overrides) { _, value in value }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func event(_ overrides: [String: Any] = [:]) throws -> ValidatedEvent { try ValidatedEvent.parse(draft(overrides)) }
    private func reject(_ overrides: [String: Any]) { XCTAssertThrowsError(try event(overrides)) }

    func testExactUTF8BytesAndPAE() throws {
        let payload = try draft() + Data([32, 10])
        let parsed = try ValidatedEvent.parse(payload)
        XCTAssertEqual(parsed.payload, payload)
        let prefix = "DSSEv1 40 application/vnd.agent-yhes.event.v1+json \(payload.count) "
        // Type length computed independently below, to make a changed type visible.
        XCTAssertEqual(DSSE.payloadType.utf8.count, 40)
        XCTAssertEqual(DSSE.pae(payload: payload), Data(prefix.utf8) + payload)
        XCTAssertGreaterThan(payload.count, String(decoding: payload, as: UTF8.self).count)
    }
    func testIndependentPythonFixturesIncludingHighS() throws {
        let payload = try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: "p256-statement-payload", withExtension: "json", subdirectory: "Fixtures")))
        for name in ["p256-statement-envelope", "p256-high-s-envelope"] {
            let bytes = try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures")))
            let env = try XCTUnwrap(try StrictJSON.parse(bytes).object)
            XCTAssertEqual(Data(base64Encoded: try XCTUnwrap(env["payload"]?.string)), payload)
            let sig = try XCTUnwrap(env["signatures"]?.array?.first?.object)
            XCTAssertEqual(sig["key_id"]?.string, try signer.identity.keyID)
            let raw = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(sig["signature"]?.string)))
            XCTAssertNoThrow(try DSSE.envelope(payload: payload, signature: raw, publicKey: signer.identity.publicKey))
        }
    }
    func testKnownKeyIDVector() throws {
        XCTAssertEqual(signer.key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined(),
                       "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        let input = Data("agent-yhes/key/v1\0p256-sha256\0".utf8) + signer.key.publicKey.x963Representation
        XCTAssertEqual(try signer.identity.keyID, "k_" + DSSE.digest(input))
    }
    func testEnvelopeRoundTripAndRawSignature() throws {
        let payload = Data([32, 10]) + (try draft()) + Data([10])
        let parsed = try ValidatedEvent.parse(payload)
        let encoded = try EnvelopeSigning.sign(parsed, identity: signer.identity, now: now, using: signer)
        let envelope = try XCTUnwrap(try StrictJSON.parse(encoded).object)
        XCTAssertEqual(Set(envelope.keys), ["payload_type", "payload", "signatures"])
        XCTAssertEqual(envelope["payload_type"], .string(DSSE.payloadType))
        XCTAssertEqual(Data(base64Encoded: try XCTUnwrap(envelope["payload"]?.string)), payload)
        let entry = try XCTUnwrap(envelope["signatures"]?.array?.first?.object)
        XCTAssertEqual(entry["key_id"], .string(try signer.identity.keyID))
        XCTAssertEqual(entry["algorithm"], .string("p256-sha256"))
        let raw = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(entry["signature"]?.string)))
        XCTAssertEqual(raw.count, 64)
        XCTAssertTrue(signer.key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: DSSE.pae(payload: payload)))
    }
    func testPayloadReserializationInvalidatesSignature() throws {
        let payload = try draft()
        let signature = try signer.signPAE(DSSE.pae(payload: payload))
        XCTAssertThrowsError(try DSSE.envelope(payload: payload + Data([32]), signature: signature, publicKey: signer.identity.publicKey))
    }
    func testNoSignatureAfterAuthenticationFailure() throws {
        XCTAssertThrowsError(try EnvelopeSigning.sign(event(), identity: signer.identity, now: now, using: RefusingSigner()))
    }
    func testFaultySignerRejected() throws {
        XCTAssertThrowsError(try EnvelopeSigning.sign(event(), identity: signer.identity, now: now, using: BrokenSigner()))
    }
    func testWrongSignatureDomainRejected() throws {
        let payload = try draft()
        let signature = try signer.signPAE(payload)
        XCTAssertThrowsError(try DSSE.envelope(payload: payload, signature: signature, publicKey: signer.identity.publicKey))
    }
    func testInvalidPublicKeysRejected() {
        for key in [Data(), Data(repeating: 0, count: 65), Data(repeating: 4, count: 65), Data(repeating: 3, count: 33)] {
            XCTAssertThrowsError(try DSSE.keyID(publicKey: key))
        }
    }
    func testDuplicateAndEscapedDuplicateKeysRejected() {
        for json in [#"{"a":1,"a":2}"#, #"{"a":1,"\u0061":2}"#, #"{"outer":{"text":"one","text":"two"}}"#] {
            XCTAssertThrowsError(try StrictJSON.parse(Data(json.utf8)))
        }
    }
    func testDuplicateEventKeyRejected() throws {
        let json = String(decoding: try draft(), as: UTF8.self)
        XCTAssertThrowsError(try ValidatedEvent.parse(Data(json.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1").utf8)))
    }
    func testUnknownOrMissingFieldsRejected() throws {
        reject(["display_author": "human"])
        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: draft()) as? [String: Any])
        object.removeValue(forKey: "previous")
        XCTAssertThrowsError(try ValidatedEvent.parse(JSONSerialization.data(withJSONObject: object)))
    }
    func testUnknownBodyFieldsRejected() { reject(["body": ["text": "ok", "approved": true]]) }
    func testAmbiguousKindRejected() {
        for kind in ["human", "Human.Statement", "human.statement ", "agent.message", "action.execute", "session.grant", "registry.update"] { reject(["kind": kind]) }
    }
    func testSessionsRejected() { reject(["session": String(repeating: "a", count: 64)]) }
    func testIntegerOnlyAndBoundedJSON() {
        for json in ["1.0", "1e2", "01", "-0", "9223372036854775808", "true false", "{}x", "[1,]", "{\"a\":1,}"] {
            XCTAssertThrowsError(try StrictJSON.parse(Data(json.utf8)), json)
        }
        XCTAssertThrowsError(try StrictJSON.parse(Data(repeating: 32, count: StrictJSON.maxBytes + 1)))
        XCTAssertThrowsError(try StrictJSON.parse(Data((String(repeating: "[", count: 18) + "0" + String(repeating: "]", count: 18)).utf8)))
    }
    func testInvalidStringsAndUTF8Rejected() {
        for json in [#""\uD800""#, #""\uDC00""#, #""\uD800x""#, #""\x00""#, #""\u202e""#, #""\u0000""#, #""\u200b""#, #""\uffff""#] {
            XCTAssertThrowsError(try StrictJSON.parse(Data(json.utf8)), json)
        }
        XCTAssertThrowsError(try StrictJSON.parse(Data([34, 0xFF, 34])))
        XCTAssertThrowsError(try StrictJSON.parse(Data([0xEF, 0xBB, 0xBF, 123, 125])))
        XCTAssertEqual(try StrictJSON.parse(Data(#""\uD83D\uDE00""#.utf8)), .string("😀"))
    }
    func testAudienceMustBeSortedUniqueAndBounded() {
        for audience in [[], ["bob", "alice"], ["alice", "alice"], ["../bob"], (0...128).map { String(format: "u%03d", $0) }] {
            reject(["audience": audience])
        }
    }
    func testUnsafeIdentifiersRejected() {
        for value in ["../alice", "alice..bob", "/alice", "alice/bob", "_alice", "álîce", "a b", String(repeating: "a", count: 129)] {
            reject(["author": value])
        }
    }
    func testGroupEpochMustBePaired() {
        reject(["group": "g"]); reject(["epoch": 1]); reject(["group": "g", "epoch": -1])
        XCTAssertNoThrow(try event(["group": "g", "epoch": 0]))
    }
    func testVersionsAndScalarTypesRejected() {
        reject(["version": true]); reject(["version": 2]); reject(["issued_at": "2000000000"])
        reject(["issued_at": -1]); reject(["expires_at": now]); reject(["body": "text"])
    }
    func testInvalidDigestsRejected() {
        reject(["key_id": "k_" + String(repeating: "A", count: 64)])
        reject(["previous": String(repeating: "A", count: 64)])
        reject(["previous": "../digest"])
    }
    func testEmptyStatementRejected() { reject(["body": ["text": " \n\t"]]) }
    func testPolicyIdentityProjectAndKeyBinding() throws {
        for changes: [String: Any] in [["author": "mallory"], ["project": "other"], ["key_id": "k_" + String(repeating: "0", count: 64)]] {
            XCTAssertThrowsError(try SigningPolicy.validate(event(changes), identity: signer.identity, now: now))
        }
    }
    func testValidityAndMaximumLifetime() throws {
        for clock in [now - 1, now + 300, now + 301] {
            XCTAssertThrowsError(try SigningPolicy.validate(event(), identity: signer.identity, now: clock))
        }
        XCTAssertNoThrow(try SigningPolicy.validate(event(["expires_at": now + 1800]), identity: signer.identity, now: now))
        XCTAssertThrowsError(try SigningPolicy.validate(event(["expires_at": now + 1801]), identity: signer.identity, now: now))
    }
    func testStaleApprovalAfterReplacementAndLock() throws {
        var state = ApprovalState()
        state.replace(with: try event())
        let revision = state.revision
        XCTAssertNoThrow(try state.checked(revision: revision, identity: signer.identity, now: now))
        state.replace(with: try event(["id": "event-2"]))
        XCTAssertThrowsError(try state.checked(revision: revision, identity: signer.identity, now: now))
        let next = state.revision
        state.invalidate()
        XCTAssertThrowsError(try state.checked(revision: next, identity: signer.identity, now: now))
        XCTAssertNil(state.event)
    }
    func testApprovalRechecksTimeAfterTouchID() throws {
        var state = ApprovalState(); state.replace(with: try event())
        XCTAssertThrowsError(try state.checked(revision: state.revision, identity: signer.identity, now: now + 300))
    }
    func testDelegationHasExactNarrowPurposes() throws {
        let body: [String: Any] = ["agent": "alice-agent", "agent_key_id": "k_" + String(repeating: "a", count: 64), "purposes": ["agent.message", "agent.relay"]]
        XCTAssertNoThrow(try event(["kind": "agent.delegation", "body": body]))
        for purposes in [["human.statement"], ["session.grant"], [], ["agent.relay", "agent.message"], ["agent.message", "agent.message"]] {
            var changed = body; changed["purposes"] = purposes
            reject(["kind": "agent.delegation", "body": changed])
        }
    }
    func testReviewedAgentDelegationCanOutlastHumanSigningWindow() throws {
        let body: [String: Any] = ["agent": "alice-agent", "agent_key_id": "k_" + String(repeating: "a", count: 64), "purposes": ["agent.message"]]
        let draft = try event(["kind": "agent.delegation", "body": body, "expires_at": now + 7 * 86_400])
        XCTAssertNoThrow(try SigningPolicy.validate(draft, identity: signer.identity, now: now))
        XCTAssertThrowsError(try SigningPolicy.validate(event(["kind": "agent.delegation", "body": body, "expires_at": now + 7 * 86_400 + 1]), identity: signer.identity, now: now))
        XCTAssertThrowsError(try SigningPolicy.validate(draft, identity: signer.identity, now: now + 7 * 86_400))
    }
    private func requestData(action: String = "group.add", parameters: [String: Any]? = nil,
                             overrides: [String: Any] = [:]) throws -> Data {
        var object: [String: Any] = ["version": 1, "project": "demo", "action": action,
            "performer": "alice-agent", "group": "group-1", "epoch": 2,
            "audience": ["alice", "bob"], "parameters": parameters ?? [
                "member": "carol", "key_id": "k_" + String(repeating: "b", count: 64),
                "key_package_digest": String(repeating: "c", count: 64)]]
        object.merge(overrides) { _, value in value }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
    private func authorization(_ request: ActionRequest, overrides: [String: Any] = [:]) throws -> ValidatedEvent {
        var fields: [String: Any] = ["kind": "action.authorization", "group": request.group, "epoch": request.epoch,
            "audience": request.audience, "body": ["action": request.action,
            "request_digest": request.digest, "performer": request.performer]]
        fields.merge(overrides) { _, value in value }
        return try event(fields)
    }
    func testSupportedActionSidecars() throws {
        let add = try ActionRequest.parse(requestData())
        let remove = try ActionRequest.parse(requestData(action: "group.remove", parameters: ["member": "bob"]))
        let create = try ActionRequest.parse(requestData(action: "group.create", parameters: [:],
            overrides: ["epoch": 0, "audience": ["alice-agent"]]))
        let recover = try ActionRequest.parse(requestData(action: "ticket.recover", parameters: [
            "ticket": "ticket-1", "expected_revision": 4, "stop_evidence": "Previous worker exited; operation reconciled."]))
        for request in [add, remove, create, recover] {
            let event = try authorization(request)
            XCTAssertNoThrow(try EnvelopeSigning.sign(event, identity: signer.identity, now: now, request: request, using: signer))
        }
    }
    func testHashOnlyAuthorizationCannotSign() throws {
        let request = try ActionRequest.parse(requestData())
        XCTAssertThrowsError(try EnvelopeSigning.sign(authorization(request), identity: signer.identity, now: now, using: signer))
        XCTAssertThrowsError(try EnvelopeSigning.sign(event(), identity: signer.identity, now: now, request: request, using: signer))
    }
    func testActionBindingChecksEveryScopeDimension() throws {
        let request = try ActionRequest.parse(requestData())
        let variants: [[String: Any]] = [
            ["project": "other"], ["group": "other"], ["epoch": 3], ["audience": ["alice", "bob", "carol"]],
            ["body": ["action": "group.remove", "request_digest": request.digest, "performer": request.performer]],
            ["body": ["action": request.action, "request_digest": request.digest, "performer": "other-agent"]],
            ["body": ["action": request.action, "request_digest": String(repeating: "d", count: 64), "performer": request.performer]]
        ]
        for fields in variants {
            XCTAssertThrowsError(try request.validateBinding(to: authorization(request, overrides: fields)))
        }
    }
    func testActionRequestExactBytesBoundIncludingWhitespace() throws {
        let bytes = try requestData()
        let original = try ActionRequest.parse(bytes)
        let changed = try ActionRequest.parse(bytes + Data([10]))
        XCTAssertEqual(changed.payload, bytes + Data([10]))
        XCTAssertNotEqual(original.digest, changed.digest)
        XCTAssertThrowsError(try changed.validateBinding(to: authorization(original)))
    }
    func testActionRequestUnknownAndDuplicateFieldsRejected() throws {
        XCTAssertThrowsError(try ActionRequest.parse(requestData(overrides: ["approved": true])))
        let text = String(decoding: try requestData(), as: UTF8.self)
        let duplicate = text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1")
        XCTAssertThrowsError(try ActionRequest.parse(Data(duplicate.utf8)))
        XCTAssertThrowsError(try ActionRequest.parse(requestData(parameters: ["member": "carol", "shell": "do-stuff"])))
    }
    func testActionRequestUnknownActionAndTypesRejected() throws {
        for action in ["shell", "deploy", "trust.change", "group.Add", "group.add "] {
            XCTAssertThrowsError(try ActionRequest.parse(requestData(action: action)))
        }
        for fields: [String: Any] in [["version": 2], ["epoch": true], ["epoch": -1], ["audience": ["bob", "alice"]], ["group": NSNull()]] {
            XCTAssertThrowsError(try ActionRequest.parse(requestData(overrides: fields)))
        }
    }
    func testGroupCreationIsSinglePerformerAtEpochZero() throws {
        XCTAssertThrowsError(try ActionRequest.parse(requestData(action: "group.create", parameters: [:])))
        XCTAssertThrowsError(try ActionRequest.parse(requestData(action: "group.create", parameters: [:], overrides: ["epoch": 0])))
    }
    func testRecoveryNeedsRevisionAndNonemptyStopEvidence() throws {
        for evidence: Any in ["", " \n", true, ["stopped": true]] {
            XCTAssertThrowsError(try ActionRequest.parse(requestData(action: "ticket.recover", parameters: [
                "ticket": "ticket-1", "expected_revision": 4, "stop_evidence": evidence])))
        }
        XCTAssertThrowsError(try ActionRequest.parse(requestData(action: "ticket.recover", parameters: [
            "ticket": "ticket-1", "expected_revision": -1, "stop_evidence": "process exited"])))
    }
    func testActionAuthorizationHasFiveMinuteValidityLimit() throws {
        let request = try ActionRequest.parse(requestData())
        XCTAssertThrowsError(try SigningPolicy.validate(authorization(request, overrides: ["expires_at": now + 301]),
            identity: signer.identity, now: now, request: request))
    }
    func testReplacingActionDetailsRevokesOldReviewAndInvalidDetailsClearIt() throws {
        let request = try ActionRequest.parse(requestData())
        var state = ApprovalState(); state.replace(with: try authorization(request)); try state.attach(request)
        let revision = state.revision
        XCTAssertNoThrow(try state.checked(revision: revision, identity: signer.identity, now: now))
        try state.attach(request)
        XCTAssertThrowsError(try state.checked(revision: revision, identity: signer.identity, now: now))
        let altered = try ActionRequest.parse(requestData() + Data([10]))
        XCTAssertThrowsError(try state.attach(altered))
        XCTAssertNil(state.request)
        XCTAssertThrowsError(try state.checked(revision: state.revision, identity: signer.identity, now: now))
    }
    func testEnvironmentDoesNotBypassPolicy() throws {
        // Production has no environment lookup. Even if an embedding caller sets
        // a suggestive flag, an invalid event stays rejected by the pure policy.
        setenv("YHES_SKIP_AUTH", "1", 1); defer { unsetenv("YHES_SKIP_AUTH") }
        XCTAssertThrowsError(try EnvelopeSigning.sign(event(["author": "mallory"]), identity: signer.identity, now: now, using: signer))
        XCTAssertThrowsError(try EnvelopeSigning.sign(event(), identity: signer.identity, now: now, using: RefusingSigner()))
    }
}
