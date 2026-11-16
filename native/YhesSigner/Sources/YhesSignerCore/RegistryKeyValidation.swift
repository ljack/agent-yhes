import CYhesWire
import Foundation

/// Uses yhes-wire's public-key decoder through a statically linked C ABI.
/// No alternate validator/fallback is selected by input or environment.
public enum RegistryKeyValidation {
    public static func keyID(algorithm: String, raw: Data) throws -> String {
        let code: UInt32
        switch algorithm {
        case "ed25519": code = 1
        case "p256-sha256": code = 2
        default: throw SignerError.invalid("Unsupported registry key algorithm.")
        }
        let valid = raw.withUnsafeBytes { bytes in
            yhes_signer_public_key_is_valid(code, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count) == 1
        }
        guard valid else { throw SignerError.invalid("Registry public key failed verifier curve/weak-key validation.") }
        var material = Data("agent-yhes/key/v1\0\(algorithm)\0".utf8)
        material.append(raw)
        return "k_" + DSSE.digest(material)
    }
}
