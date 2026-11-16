import CryptoKit
import Foundation

public enum DSSEPayloadKind: String, Sendable {
    case event = "application/vnd.agent-yhes.event.v1+json"
    case registry = "application/vnd.agent-yhes.registry.v1+json"
}

public enum DSSE {
    public static let payloadType = "application/vnd.agent-yhes.event.v1+json"
    public static let algorithm = "p256-sha256"
    public static func pae(payload: Data, kind: DSSEPayloadKind = .event) -> Data {
        let payloadType = kind.rawValue
        var data = Data("DSSEv1 \(payloadType.utf8.count) \(payloadType) \(payload.count) ".utf8)
        data.append(payload)
        return data
    }
    public static func digest(_ payload: Data) -> String {
        SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
    }
    public static func keyID(publicKey: Data) throws -> String {
        guard publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil else {
            throw SignerError.invalid("Expected valid uncompressed P-256 public key.")
        }
        var bytes = Data("agent-yhes/key/v1\0p256-sha256\0".utf8)
        bytes.append(publicKey)
        return "k_" + digest(bytes)
    }
    /// Also verifies the returned signature; faulty injected signers cannot produce envelopes.
    public static func envelope(payload: Data, signature: Data, publicKey: Data, kind: DSSEPayloadKind = .event) throws -> Data {
        let keyID = try keyID(publicKey: publicKey)
        switch kind {
        case .event:
            guard try ValidatedEvent.parse(payload).keyID == keyID else { throw SignerError.invalid("Event signing key mismatch.") }
        case .registry:
            _ = try ValidatedRegistry.parse(payload)
        }
        guard signature.count == 64 else { throw SignerError.invalid("Signing key or signature mismatch.") }
        let key = try P256.Signing.PublicKey(x963Representation: publicKey)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        guard key.isValidSignature(sig, for: pae(payload: payload, kind: kind)) else { throw SignerError.invalid("Returned signature did not verify.") }
        return try JSONEncoder().encode(Envelope(payload_type: kind.rawValue,
            payload: payload.base64EncodedString(), signatures: [Signature(key_id: keyID,
                algorithm: algorithm, signature: signature.base64EncodedString())]))
    }
    private struct Envelope: Encodable { let payload_type: String; let payload: String; let signatures: [Signature] }
    private struct Signature: Encodable { let key_id: String; let algorithm: String; let signature: String }
}
