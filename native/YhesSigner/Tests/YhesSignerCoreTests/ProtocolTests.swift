import Foundation
import XCTest
@testable import YhesSignerCore

final class ProtocolTests: XCTestCase {
    private let id = "eebd9b80-c260-4736-99d6-9091af5f13e2"
    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures")!)
    }
    private func frame(_ changes: [String: Any] = [:]) throws -> Data {
        var f: [String: Any] = ["version": 1, "id": id, "operation": "identity", "author": "alice", "project": "demo",
            "mode": NSNull(), "payloads": [], "request": NSNull()]
        f.merge(changes) { _, v in v }
        return try JSONSerialization.data(withJSONObject: f, options: [.sortedKeys])
    }
    private func review(_ changes: [String: Any] = [:]) throws -> Data {
        var f: [String: Any] = ["operation": "review", "mode": "event", "payloads": [try fixture("p256-statement-payload").base64EncodedString()]]
        f.merge(changes) { _, v in v }
        return try frame(f)
    }
    func testIdentityAndEnrollmentNeverContainSigningWork() throws {
        for operation in ["identity", "enroll"] {
            let req = try SignerRequest.parse(frame(["operation": operation]))
            XCTAssertNil(req.document)
            for change: [String: Any] in [["mode": "event"], ["payloads": ["e30="]], ["request": "e30="]] {
                var f = change; f["operation"] = operation
                XCTAssertThrowsError(try SignerRequest.parse(frame(f)))
            }
        }
    }
    func testUnknownDuplicateAndEscapedDuplicateFieldsFail() throws {
        XCTAssertThrowsError(try SignerRequest.parse(frame(["consent": true])))
        let source = String(decoding: try frame(), as: UTF8.self)
        for key in ["version", "\\u0076ersion"] {
            XCTAssertThrowsError(try SignerRequest.parse(Data(("{\"\(key)\":1," + source.dropFirst()).utf8)))
        }
    }
    func testUnknownVersionOperationMalformedIDAndMissingFieldsFail() throws {
        for change: [String: Any] in [["version": 2], ["version": true], ["id": "alice"], ["operation": "sign"], ["author": "../alice"], ["project": ""], ["mode": 0]] {
            XCTAssertThrowsError(try SignerRequest.parse(frame(change)))
        }
        var f = try JSONSerialization.jsonObject(with: frame()) as! [String: Any]
        f.removeValue(forKey: "request")
        XCTAssertThrowsError(try SignerRequest.parse(JSONSerialization.data(withJSONObject: f)))
    }
    func testExactStatementBytesAndReadableTextArePreserved() throws {
        let payload = try fixture("p256-statement-payload") + Data([32, 10])
        let request = try SignerRequest.parse(review(["payloads": [payload.base64EncodedString()]]))
        guard case .event(let event, nil) = request.document else { return XCTFail("Wrong document") }
        XCTAssertEqual(event.payload, payload)
        XCTAssertTrue(request.document!.reviewText.contains("Hyväksyn tämän täsmällisen viestin. 😀"))
        XCTAssertTrue(request.document!.reviewText.contains("Recipients (2): alice, bob"))
        XCTAssertEqual(request.document!.reviewHeading, "Review your statement")
    }
    func testOuterIdentityMustMatchStatementAndRegistryProject() throws {
        XCTAssertThrowsError(try SignerRequest.parse(review(["author": "bob"])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["project": "other"])))
        let payload = try fixture("p256-registry-payload").base64EncodedString()
        XCTAssertNoThrow(try SignerRequest.parse(review(["mode": "registry", "payloads": [payload]])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["mode": "registry", "payloads": [payload], "project": "other"])))
    }
    func testBase64MustBeCanonicalAndPayloadMustBeUTF8() throws {
        for payload in ["e30", "e30=\n", "!!!!", "/w==", ""] {
            XCTAssertThrowsError(try SignerRequest.parse(review(["payloads": [payload]])))
        }
    }
    func testPerDocumentBoundSurvivesTransportDecoding() throws {
        let payload = Data(repeating: 32, count: 65_537).base64EncodedString()
        XCTAssertThrowsError(try SignerRequest.parse(review(["payloads": [payload]])))
        XCTAssertThrowsError(try SignerRequest.parse(Data(repeating: 32, count: SignerRequest.maxFrameBytes + 1)))
        XCTAssertThrowsError(try SignerRequest.parse(Data([0xff])))
    }
    func testTransportAllowsLargeValidBase64WithoutLooseningDocumentStringLimit() throws {
        var event = try JSONSerialization.jsonObject(with: fixture("p256-statement-payload")) as! [String: Any]
        event["body"] = ["text": String(repeating: "a", count: 30_000)]
        let data = try JSONSerialization.data(withJSONObject: event)
        XCTAssertGreaterThan(data.base64EncodedString().count, 32_768)
        XCTAssertNoThrow(try SignerRequest.parse(review(["payloads": [data.base64EncodedString()]])))
        event["body"] = ["text": String(repeating: "a", count: 32_769)]
        let invalid = try JSONSerialization.data(withJSONObject: event)
        XCTAssertThrowsError(try SignerRequest.parse(review(["payloads": [invalid.base64EncodedString()]])))
    }
    func testSidecarForbiddenForStatementsAndRegistries() throws {
        XCTAssertThrowsError(try SignerRequest.parse(review(["request": "e30="])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["mode": "registry", "payloads": [fixture("p256-registry-payload").base64EncodedString()], "request": "e30="])))
    }
    func testBatchIsFixedAndRejectsDuplicateEvents() throws {
        let payload = try fixture("p256-statement-payload").base64EncodedString()
        XCTAssertNoThrow(try SignerRequest.parse(review(["mode": "batch", "payloads": [payload]])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["mode": "batch", "payloads": [payload, payload]])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["mode": "batch", "payloads": Array(repeating: payload, count: 17)])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["payloads": [payload, payload]])))
        XCTAssertThrowsError(try SignerRequest.parse(review(["payloads": []])))
    }
    func testLocalHumanRegistryWithoutFabricatedGHESClaim() throws {
        var registry = try JSONSerialization.jsonObject(with: fixture("p256-registry-payload")) as! [String: Any]
        var participants = registry["participants"] as! [[String: Any]]
        participants[0]["ghes"] = NSNull()
        registry["participants"] = participants
        let bytes = try JSONSerialization.data(withJSONObject: registry)
        let request = try SignerRequest.parse(review(["mode": "registry", "payloads": [bytes.base64EncodedString()]]))
        guard case .registry(let value) = request.document else { return XCTFail("Wrong mode") }
        XCTAssertNil(value.participants[0].ghesInstance)
        XCTAssertTrue(request.document!.reviewText.contains("local identity"))
    }
    func testOnlyDelegationCanBeGroupWideWithoutEpoch() throws {
        var event = try JSONSerialization.jsonObject(with: fixture("p256-statement-payload")) as! [String: Any]
        event["kind"] = "agent.delegation"; event["group"] = "team"; event["epoch"] = NSNull()
        event["body"] = ["agent": "codex", "agent_key_id": event["key_id"]!, "purposes": ["agent.message", "agent.relay"]]
        let data = try JSONSerialization.data(withJSONObject: event)
        let request = try SignerRequest.parse(review(["payloads": [data.base64EncodedString()]]))
        XCTAssertTrue(request.document!.reviewText.contains("all epochs"))
        event["kind"] = "human.statement"; event["body"] = ["text": "Exact statement"]
        let statement = try JSONSerialization.data(withJSONObject: event)
        XCTAssertThrowsError(try SignerRequest.parse(review(["payloads": [statement.base64EncodedString()]])))
    }
    func testResponseHasOnlyProtocolFieldsAndExactResult() throws {
        let data = try fixture("p256-statement-envelope")
        let wire = try SignerResponse.success(id: id, result: data)
        XCTAssertEqual(wire.last, 10)
        let json = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
        XCTAssertEqual(Set(json.keys), ["version", "id", "status", "result", "error"])
        XCTAssertEqual(json["status"] as? String, "ok")
        XCTAssertEqual(Data(base64Encoded: json["result"] as! String), data)
        XCTAssertTrue(json["error"] is NSNull)
    }
    func testCancellationAndFailureNeverContainResult() throws {
        for code in [SignerProtocolError.cancelled, .identityMissing, .unauthorized, .busy, .timeout, .approvalFailed] {
            let json = try JSONSerialization.jsonObject(with: SignerResponse.failure(id: id, code: code)) as! [String: Any]
            XCTAssertEqual(json["status"] as? String, code == .cancelled ? "cancelled" : "error")
            XCTAssertTrue(json["result"] is NSNull)
            XCTAssertEqual(json["error"] as? String, code.rawValue)
        }
    }
    func testOnePendingRequestAndTimeout() throws {
        var pending = PendingReview()
        let first = UUID(), second = UUID()
        try pending.begin(token: first, now: 10)
        XCTAssertThrowsError(try pending.begin(token: second, now: 11))
        XCTAssertTrue(pending.isCurrent(first, now: 309))
        XCTAssertFalse(pending.isCurrent(first, now: 310))
        XCTAssertFalse(pending.isCurrent(second, now: 20))
    }
    func testDisconnectInvalidatesAndLateCompletionCannotConsumeNewRequest() throws {
        var pending = PendingReview()
        let first = UUID(), second = UUID()
        try pending.begin(token: first, now: 1)
        XCTAssertTrue(pending.finish(first))
        XCTAssertFalse(pending.isCurrent(first, now: 2))
        try pending.begin(token: second, now: 2)
        XCTAssertFalse(pending.finish(first))
        XCTAssertTrue(pending.isCurrent(second, now: 3))
        XCTAssertTrue(pending.finish(second))
        XCTAssertFalse(pending.finish(second))
    }
}
