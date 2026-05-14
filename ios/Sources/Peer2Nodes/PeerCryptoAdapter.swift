import Foundation

// MARK: - PeerCryptoAdapterError

public enum PeerCryptoAdapterError: Error, LocalizedError {
    case invalidFormat(String)

    public var errorDescription: String? {
        if case .invalidFormat(let msg) = self { return msg }
        return nil
    }
}

// MARK: - PeerCryptoAdapter
//
// Pure format-conversion utilities for P-256 public keys and ECDSA signatures.
// Enables interoperability between platforms using different serialisation conventions:
//
//   Platform        | Public key format           | Signature format
//   ----------------|-----------------------------|------------------------------
//   Node.js         | DER/SPKI  (91 bytes)        | DER ECDSA  (70–72 bytes)
//   Android (JCE)   | DER/SPKI  (91 bytes)        | DER ECDSA  (70–72 bytes)
//   iOS (CryptoKit) | x9.63 uncompressed (65 B)   | P1363 raw R‖S (64 bytes)
//
// All methods accept and return Data.

public enum PeerCryptoAdapter {

    // Fixed 26-byte DER/SPKI header for all P-256 (secp256r1) public keys.
    // Encodes: SEQUENCE { AlgorithmIdentifier { ecPublicKey OID, P-256 OID }, BIT STRING }
    private static let p256SpkiHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ])

    // MARK: - Public key conversions

    /// Converts an x9.63 uncompressed P-256 point (65 bytes, 0x04 prefix) to DER/SPKI (91 bytes).
    public static func x963ToDerSpki(_ x963Data: Data) throws -> Data {
        guard x963Data.count == 65, x963Data[0] == 0x04 else {
            throw PeerCryptoAdapterError.invalidFormat(
                "x963ToDerSpki: expected 65-byte x9.63 uncompressed point, got \(x963Data.count) bytes"
            )
        }
        return p256SpkiHeader + x963Data
    }

    /// Extracts the x9.63 uncompressed point (65 bytes) from a DER/SPKI key (91 bytes).
    public static func derSpkiToX963(_ derData: Data) throws -> Data {
        guard derData.count == 91 else {
            throw PeerCryptoAdapterError.invalidFormat(
                "derSpkiToX963: expected 91-byte DER/SPKI, got \(derData.count) bytes"
            )
        }
        guard derData.prefix(26) == p256SpkiHeader else {
            throw PeerCryptoAdapterError.invalidFormat(
                "derSpkiToX963: DER/SPKI header does not match P-256 curve"
            )
        }
        return derData.dropFirst(26)
    }

    // MARK: - Signature conversions

    /// Converts a P1363 signature (64-byte R‖S, CryptoKit native) to DER-encoded ECDSA.
    public static func p1363ToDer(_ p1363Data: Data) throws -> Data {
        guard p1363Data.count == 64 else {
            throw PeerCryptoAdapterError.invalidFormat(
                "p1363ToDer: expected 64-byte P1363 signature, got \(p1363Data.count) bytes"
            )
        }
        let r      = derEncodeInteger(p1363Data.prefix(32))
        let s      = derEncodeInteger(p1363Data.suffix(32))
        let seq    = r + s
        return Data([0x30, UInt8(seq.count)]) + seq
    }

    /// Converts a DER-encoded ECDSA signature to P1363 format (64-byte R‖S).
    public static func derToP1363(_ derData: Data) throws -> Data {
        guard derData.first == 0x30 else {
            throw PeerCryptoAdapterError.invalidFormat("derToP1363: expected DER SEQUENCE tag 0x30")
        }
        var pos = 2   // skip 0x30 and sequence-length byte
        let (r, rAdv) = try decodeDerInteger(derData, at: pos); pos += rAdv
        let (s, _)    = try decodeDerInteger(derData, at: pos)
        return padTo32(r) + padTo32(s)
    }

    // MARK: - Auto-detecting normalisation

    /// Normalises a P-256 public key to DER/SPKI format.
    /// Accepts DER/SPKI (91 bytes) or x9.63 uncompressed (65 bytes, 0x04 prefix).
    public static func normalizePublicKey(_ data: Data) throws -> Data {
        if data.count == 91 && data[0] == 0x30 { return data }
        if data.count == 65 && data[0] == 0x04 { return try x963ToDerSpki(data) }
        throw PeerCryptoAdapterError.invalidFormat(
            "normalizePublicKey: unrecognized P-256 key format (\(data.count) bytes)"
        )
    }

    /// Normalises a P-256 ECDSA signature to DER format.
    /// Accepts DER (starts with 0x30) or P1363 (exactly 64 bytes).
    public static func normalizeSignature(_ data: Data) throws -> Data {
        if data.first == 0x30     { return data }
        if data.count == 64       { return try p1363ToDer(data) }
        throw PeerCryptoAdapterError.invalidFormat(
            "normalizeSignature: unrecognized ECDSA signature format (\(data.count) bytes)"
        )
    }

    // MARK: - Private helpers

    /// DER INTEGER encoding: strip leading zero bytes, add 0x00 prefix if MSB is set.
    private static func derEncodeInteger(_ bytes: Data) -> Data {
        var arr = Array(bytes)
        while arr.count > 1 && arr.first == 0x00 { arr.removeFirst() }
        if arr.first! & 0x80 != 0 { arr.insert(0x00, at: 0) }
        return Data([0x02, UInt8(arr.count)]) + Data(arr)
    }

    /// Reads a DER INTEGER at `data[pos]`. Returns (value, bytesConsumed).
    private static func decodeDerInteger(_ data: Data, at pos: Int) throws -> (Data, Int) {
        guard pos < data.count, data[pos] == 0x02 else {
            throw PeerCryptoAdapterError.invalidFormat(
                "decodeDerInteger: expected INTEGER tag 0x02 at offset \(pos)"
            )
        }
        let len = Int(data[pos + 1])
        let val = data[(pos + 2)..<(pos + 2 + len)]
        return (val, 2 + len)
    }

    /// Strips leading 0x00 bytes and zero-pads on the left to exactly 32 bytes.
    private static func padTo32(_ data: Data) -> Data {
        var stripped = data
        while stripped.first == 0x00 { stripped = stripped.dropFirst() }
        guard stripped.count <= 32 else {
            return Data(stripped.suffix(32)) // should not happen for valid P-256 values
        }
        let padding = Data(repeating: 0, count: 32 - stripped.count)
        return padding + stripped
    }
}
