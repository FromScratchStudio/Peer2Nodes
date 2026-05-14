package com.fromscratchstudio.peer2nodes

import java.util.Base64

/**
 * PeerCryptoAdapter — pure format-conversion utilities for P-256 public keys and
 * ECDSA signatures. Enables interoperability between platforms using different
 * serialisation conventions:
 *
 *   Platform        | Public key format           | Signature format
 *   ----------------|-----------------------------|------------------------------
 *   Node.js         | DER/SPKI  (91 bytes)        | DER ECDSA  (70–72 bytes)
 *   Android (JCE)   | DER/SPKI  (91 bytes)        | DER ECDSA  (70–72 bytes)
 *   iOS (CryptoKit) | x9.63 uncompressed (65 B)   | P1363 raw R‖S (64 bytes)
 *
 * Android (JCE) already uses canonical DER format natively. This adapter is provided
 * for completeness and for incoming messages from iOS peers.
 */
object PeerCryptoAdapter {

    // Fixed 26-byte DER/SPKI header for P-256 (secp256r1) public keys.
    private val P256_SPKI_HEADER = byteArrayOf(
        0x30.toByte(), 0x59.toByte(), 0x30.toByte(), 0x13.toByte(),
        0x06.toByte(), 0x07.toByte(), 0x2a.toByte(), 0x86.toByte(),
        0x48.toByte(), 0xce.toByte(), 0x3d.toByte(), 0x02.toByte(),
        0x01.toByte(), 0x06.toByte(), 0x08.toByte(), 0x2a.toByte(),
        0x86.toByte(), 0x48.toByte(), 0xce.toByte(), 0x3d.toByte(),
        0x03.toByte(), 0x01.toByte(), 0x07.toByte(), 0x03.toByte(),
        0x42.toByte(), 0x00.toByte()
    )

    // ── Public key conversions ────────────────────────────────────────────────

    /**
     * Converts an x9.63 uncompressed P-256 point (65 bytes, 0x04 prefix) to
     * DER/SPKI format (91 bytes).
     */
    fun x963ToDerSpki(x963Bytes: ByteArray): ByteArray {
        require(x963Bytes.size == 65 && x963Bytes[0] == 0x04.toByte()) {
            "x963ToDerSpki: expected 65-byte x9.63 uncompressed point, got ${x963Bytes.size} bytes"
        }
        return P256_SPKI_HEADER + x963Bytes
    }

    /**
     * Extracts the x9.63 uncompressed point (65 bytes) from a P-256 DER/SPKI key (91 bytes).
     */
    fun derSpkiToX963(derBytes: ByteArray): ByteArray {
        require(derBytes.size == 91) {
            "derSpkiToX963: expected 91-byte DER/SPKI, got ${derBytes.size} bytes"
        }
        require(derBytes.take(26).toByteArray().contentEquals(P256_SPKI_HEADER)) {
            "derSpkiToX963: DER/SPKI header does not match P-256 curve"
        }
        return derBytes.copyOfRange(26, 91)
    }

    // ── Signature conversions ─────────────────────────────────────────────────

    /**
     * Converts a P1363 signature (64-byte R‖S, CryptoKit native format) to
     * DER-encoded ECDSA (JCE / OpenSSL / Web Crypto format).
     */
    fun p1363ToDer(p1363Bytes: ByteArray): ByteArray {
        require(p1363Bytes.size == 64) {
            "p1363ToDer: expected 64-byte P1363 signature, got ${p1363Bytes.size} bytes"
        }
        val r    = derEncodeInteger(p1363Bytes.copyOfRange(0, 32))
        val s    = derEncodeInteger(p1363Bytes.copyOfRange(32, 64))
        val seq  = r + s
        return byteArrayOf(0x30.toByte(), seq.size.toByte()) + seq
    }

    /**
     * Converts a DER-encoded ECDSA signature to P1363 format (64-byte R‖S).
     */
    fun derToP1363(derBytes: ByteArray): ByteArray {
        require(derBytes.isNotEmpty() && derBytes[0] == 0x30.toByte()) {
            "derToP1363: expected DER SEQUENCE tag 0x30"
        }
        var pos = 2  // skip 0x30 and sequence-length byte
        val (r, rAdv) = decodeDerInteger(derBytes, pos); pos += rAdv
        val (s, _)    = decodeDerInteger(derBytes, pos)
        return padTo32(r) + padTo32(s)
    }

    // ── Auto-detecting normalisation ──────────────────────────────────────────

    /**
     * Normalises a base64-encoded P-256 public key to DER/SPKI format.
     * Accepts DER/SPKI (91 bytes) or x9.63 uncompressed (65 bytes, 0x04 prefix).
     * Returns base64-encoded DER/SPKI.
     */
    fun normalizePublicKey(base64Key: String): String {
        val bytes = Base64.getDecoder().decode(base64Key)
        if (bytes.size == 91 && bytes[0] == 0x30.toByte()) return base64Key
        if (bytes.size == 65 && bytes[0] == 0x04.toByte()) {
            return Base64.getEncoder().encodeToString(x963ToDerSpki(bytes))
        }
        error("normalizePublicKey: unrecognized P-256 key format (${bytes.size} bytes)")
    }

    /**
     * Normalises a base64-encoded P-256 ECDSA signature to DER format.
     * Accepts DER (starts with 0x30) or P1363 (exactly 64 bytes).
     * Returns base64-encoded DER signature.
     */
    fun normalizeSignature(base64Sig: String): String {
        val bytes = Base64.getDecoder().decode(base64Sig)
        if (bytes.isNotEmpty() && bytes[0] == 0x30.toByte()) return base64Sig
        if (bytes.size == 64) {
            return Base64.getEncoder().encodeToString(p1363ToDer(bytes))
        }
        error("normalizeSignature: unrecognized ECDSA signature format (${bytes.size} bytes)")
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /** DER INTEGER encoding: strip leading zeros, add 0x00 prefix if MSB is set. */
    private fun derEncodeInteger(bytes: ByteArray): ByteArray {
        var arr = bytes.toMutableList()
        while (arr.size > 1 && arr.first() == 0x00.toByte()) arr.removeFirst()
        if (arr.first().toInt() and 0x80 != 0) arr.add(0, 0x00.toByte())
        return byteArrayOf(0x02.toByte(), arr.size.toByte()) + arr.toByteArray()
    }

    /** Reads a DER INTEGER at bytes[pos]. Returns Pair(value, bytesConsumed). */
    private fun decodeDerInteger(bytes: ByteArray, pos: Int): Pair<ByteArray, Int> {
        require(pos < bytes.size && bytes[pos] == 0x02.toByte()) {
            "decodeDerInteger: expected INTEGER tag 0x02 at offset $pos"
        }
        val len = bytes[pos + 1].toInt() and 0xff
        return bytes.copyOfRange(pos + 2, pos + 2 + len) to (2 + len)
    }

    /** Strips leading 0x00 bytes and zero-pads on the left to exactly 32 bytes. */
    private fun padTo32(bytes: ByteArray): ByteArray {
        var arr = bytes.toMutableList()
        while (arr.size > 1 && arr.first() == 0x00.toByte()) arr.removeFirst()
        check(arr.size <= 32) { "padTo32: integer too long (${arr.size} bytes) for P-256" }
        while (arr.size < 32) arr.add(0, 0x00.toByte())
        return arr.toByteArray()
    }
}
