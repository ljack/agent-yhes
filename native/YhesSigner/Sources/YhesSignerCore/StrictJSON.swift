import Foundation

public enum SignerError: Error, Equatable, LocalizedError, Sendable {
    case invalid(String)
    public var errorDescription: String? {
        switch self { case .invalid(let reason): return reason }
    }
}

public indirect enum JSONValue: Equatable, Sendable {
    case object([String: JSONValue]), array([JSONValue]), string(String), integer(Int64), bool(Bool), null
    public var object: [String: JSONValue]? { if case .object(let v) = self { return v }; return nil }
    public var string: String? { if case .string(let v) = self { return v }; return nil }
    public var integer: Int64? { if case .integer(let v) = self { return v }; return nil }
    public var array: [JSONValue]? { if case .array(let v) = self { return v }; return nil }
}

/// Deliberately small JSON dialect: integer numbers only, duplicate keys rejected
/// after escape decoding, strict UTF-8, bounded size/depth, no permissive decoder.
public struct StrictJSON {
    public static let maxBytes = 65_536
    public static func parse(_ data: Data) throws -> JSONValue {
        try parse(data, limit: maxBytes, stringLimit: 32_768)
    }
    // Transport encoding needs larger base64 strings; document parsing remains strict.
    static func parseSocketFrame(_ data: Data) throws -> JSONValue {
        try parse(data, limit: 1_048_576, stringLimit: 87_384)
    }
    private static func parse(_ data: Data, limit: Int, stringLimit: Int) throws -> JSONValue {
        guard !data.isEmpty, data.count <= limit,
              String(data: data, encoding: .utf8) != nil else {
            throw SignerError.invalid("Draft must be UTF-8 JSON of at most 65,536 bytes.")
        }
        var parser = Parser(bytes: Array(data), stringLimit: stringLimit)
        let value = try parser.value(depth: 0)
        parser.space()
        guard parser.offset == parser.bytes.count else { throw SignerError.invalid("Trailing JSON content.") }
        return value
    }
    private struct Parser {
        let bytes: [UInt8]
        let stringLimit: Int
        var offset = 0
        mutating func space() { while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
        mutating func take(_ byte: UInt8) -> Bool {
            if offset < bytes.count && bytes[offset] == byte { offset += 1; return true }
            return false
        }
        mutating func require(_ byte: UInt8) throws { guard take(byte) else { throw SignerError.invalid("Invalid JSON punctuation.") } }
        mutating func value(depth: Int) throws -> JSONValue {
            guard depth <= 8 else { throw SignerError.invalid("JSON exceeds 8 levels.") }
            space()
            guard offset < bytes.count else { throw SignerError.invalid("Truncated JSON.") }
            switch bytes[offset] {
            case 123:
                offset += 1; space()
                var fields: [String: JSONValue] = [:]
                if take(125) { return .object(fields) }
                repeat {
                    space(); let key = try string(); space(); try require(58)
                    guard fields[key] == nil else { throw SignerError.invalid("Duplicate JSON key.") }
                    fields[key] = try value(depth: depth + 1); space()
                    if take(125) { return .object(fields) }
                    try require(44)
                } while true
            case 91:
                offset += 1; space(); var items: [JSONValue] = []
                if take(93) { return .array(items) }
                repeat {
                    items.append(try value(depth: depth + 1)); space()
                    if take(93) { return .array(items) }
                    try require(44)
                } while true
            case 34: return .string(try string())
            case 116: try literal("true"); return .bool(true)
            case 102: try literal("false"); return .bool(false)
            case 110: try literal("null"); return .null
            default:
                let start = offset
                let negative = take(45)
                guard offset < bytes.count, (48...57).contains(bytes[offset]) else { throw SignerError.invalid("Expected JSON value.") }
                if take(48) {
                    guard !negative else { throw SignerError.invalid("Negative zero is not allowed.") }
                } else {
                    while offset < bytes.count && (48...57).contains(bytes[offset]) { offset += 1 }
                }
                guard let number = Int64(String(decoding: bytes[start..<offset], as: UTF8.self)) else {
                    throw SignerError.invalid("Integer out of range.")
                }
                return .integer(number)
            }
        }
        mutating func literal(_ text: String) throws {
            for byte in text.utf8 { try require(byte) }
        }
        mutating func string() throws -> String {
            let start = offset
            try require(34)
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 34 {
                    let token = Data(bytes[start..<offset])
                    guard let decoded = try? JSONDecoder().decode(String.self, from: token),
                          decoded.utf8.count <= stringLimit else { throw SignerError.invalid("Invalid JSON string.") }
                    // Reject invisible direction controls, zero-width formatting, and
                    // noncharacters: neither summaries nor exact-payload review may spoof order.
                    guard decoded.unicodeScalars.allSatisfy({ scalar in
                        let v = scalar.value
                        return !(scalar.properties.generalCategory == .format ||
                                 (scalar.properties.generalCategory == .control && ![9, 10, 13].contains(v)) ||
                                 (0xFDD0...0xFDEF).contains(v) || v & 0xFFFF == 0xFFFE || v & 0xFFFF == 0xFFFF)
                    }) else { throw SignerError.invalid("Unsafe invisible characters in draft.") }
                    return decoded
                }
                guard byte >= 32 else { throw SignerError.invalid("Unescaped control character.") }
                if byte == 92 {
                    guard offset < bytes.count else { throw SignerError.invalid("Truncated escape.") }
                    // JSONDecoder checks escape and surrogate syntax after this boundary scan.
                    offset += 1
                }
            }
            throw SignerError.invalid("Unterminated JSON string.")
        }
    }
}
