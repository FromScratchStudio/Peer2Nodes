'use strict';

// Fixed 26-byte DER/SPKI header for P-256 public keys (constant for all secp256r1 keys).
// Structure: SEQUENCE { AlgorithmIdentifier { ecPublicKey OID, P-256 OID }, BIT STRING }
const P256_SPKI_HEADER = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'
);

/**
 * PeerCryptoAdapter — pure format-conversion utilities for P-256 public keys and
 * ECDSA signatures. Enables interoperability between platforms that use different
 * native serialisation conventions:
 *
 *   Platform      | Public key format       | Signature format
 *   --------------|-------------------------|------------------
 *   Node.js       | DER/SPKI  (91 bytes)    | DER ECDSA  (70–72 bytes)
 *   Android (JCE) | DER/SPKI  (91 bytes)    | DER ECDSA  (70–72 bytes)
 *   iOS (CryptoKit)| x9.63 uncompressed (65 bytes) | P1363 raw R‖S (64 bytes)
 *
 * All methods work with base64-encoded strings or raw Buffers.
 */
const PeerCryptoAdapter = {

  // ── Public key conversions ────────────────────────────────────────────────

  /**
   * Converts a P-256 x9.63 uncompressed public key (65 bytes, starts with 0x04)
   * to DER/SPKI format (91 bytes).
   */
  x963ToDerSpki(input) {
    const buf = toBuffer(input);
    if (buf.length !== 65 || buf[0] !== 0x04) {
      throw new Error(`x963ToDerSpki: expected 65-byte x9.63 point (0x04 prefix), got ${buf.length} bytes`);
    }
    return toOutput(input, Buffer.concat([P256_SPKI_HEADER, buf]));
  },

  /**
   * Extracts the x9.63 uncompressed point (65 bytes) from a P-256 DER/SPKI key (91 bytes).
   */
  derSpkiToX963(input) {
    const buf = toBuffer(input);
    if (buf.length !== 91) {
      throw new Error(`derSpkiToX963: expected 91-byte DER/SPKI, got ${buf.length} bytes`);
    }
    if (!buf.subarray(0, 26).equals(P256_SPKI_HEADER)) {
      throw new Error('derSpkiToX963: DER/SPKI header does not match P-256 curve');
    }
    return toOutput(input, buf.subarray(26));
  },

  // ── Signature conversions ─────────────────────────────────────────────────

  /**
   * Converts a P1363 signature (64-byte R‖S, as produced by CryptoKit) to
   * DER-encoded ECDSA (as produced by OpenSSL / JCE / Web Crypto).
   */
  p1363ToDer(input) {
    const buf = toBuffer(input);
    if (buf.length !== 64) {
      throw new Error(`p1363ToDer: expected 64-byte P1363 signature, got ${buf.length} bytes`);
    }
    const rDer = encodeInteger(buf.subarray(0, 32));
    const sDer = encodeInteger(buf.subarray(32, 64));
    const seq  = Buffer.concat([rDer, sDer]);
    return toOutput(input, Buffer.concat([Buffer.from([0x30, seq.length]), seq]));
  },

  /**
   * Converts a DER-encoded ECDSA signature to P1363 format (64-byte R‖S).
   */
  derToP1363(input) {
    const buf = toBuffer(input);
    if (buf[0] !== 0x30) throw new Error('derToP1363: expected DER SEQUENCE tag 0x30');
    let pos = 2; // skip 0x30 and sequence length byte
    const [r, rAdv] = decodeInteger(buf, pos); pos += rAdv;
    const [s]       = decodeInteger(buf, pos);
    return toOutput(input, Buffer.concat([padTo32(r), padTo32(s)]));
  },

  // ── Auto-detecting normalisation ─────────────────────────────────────────

  /**
   * Normalises a P-256 public key to DER/SPKI format.
   * Accepts DER/SPKI (91 bytes) or x9.63 uncompressed (65 bytes, 0x04 prefix).
   * Returns the same type as the input (Buffer or base64 string).
   */
  normalizePublicKey(input) {
    const buf = toBuffer(input);
    if (buf.length === 91 && buf[0] === 0x30) return input;             // already DER/SPKI
    if (buf.length === 65 && buf[0] === 0x04) return PeerCryptoAdapter.x963ToDerSpki(input);
    throw new Error(`normalizePublicKey: unrecognized P-256 key format (${buf.length} bytes)`);
  },

  /**
   * Normalises a P-256 ECDSA signature to DER format.
   * Accepts DER (starts with 0x30) or P1363 (exactly 64 bytes).
   * Returns the same type as the input (Buffer or base64 string).
   */
  normalizeSignature(input) {
    const buf = toBuffer(input);
    if (buf[0] === 0x30) return input;                                   // already DER
    if (buf.length === 64) return PeerCryptoAdapter.p1363ToDer(input);
    throw new Error(`normalizeSignature: unrecognized ECDSA signature format (${buf.length} bytes)`);
  },
};

// ── Private helpers ─────────────────────────────────────────────────────────

function toBuffer(input) {
  return typeof input === 'string' ? Buffer.from(input, 'base64') : input;
}

function toOutput(original, result) {
  return typeof original === 'string' ? result.toString('base64') : result;
}

/** DER INTEGER encoding: strip leading zeros, add 0x00 if MSB set. */
function encodeInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const stripped = bytes.subarray(start);
  const needsPad = stripped[0] & 0x80;
  const content  = needsPad
    ? Buffer.concat([Buffer.from([0x00]), stripped])
    : stripped;
  return Buffer.concat([Buffer.from([0x02, content.length]), content]);
}

/** Reads a DER INTEGER at buf[pos]. Returns [value, bytesConsumed]. */
function decodeInteger(buf, pos) {
  if (buf[pos] !== 0x02) throw new Error(`decodeInteger: expected tag 0x02 at offset ${pos}, got 0x${buf[pos].toString(16)}`);
  const len = buf[pos + 1];
  return [buf.subarray(pos + 2, pos + 2 + len), 2 + len];
}

/** Strips leading 0x00 bytes and zero-pads on the left to exactly 32 bytes. */
function padTo32(buf) {
  let start = 0;
  while (start < buf.length - 1 && buf[start] === 0) start++;
  const stripped = buf.subarray(start);
  if (stripped.length > 32) throw new Error(`padTo32: integer too long (${stripped.length} bytes) for P-256`);
  if (stripped.length === 32) return stripped;
  const out = Buffer.alloc(32, 0);
  stripped.copy(out, 32 - stripped.length);
  return out;
}

module.exports = { PeerCryptoAdapter };
