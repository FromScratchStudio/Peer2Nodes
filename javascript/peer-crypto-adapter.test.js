'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { PeerCryptoAdapter } = require('./peer-crypto-adapter.js');

(async () => {

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`      ${err.message}`);
    if (process.env.VERBOSE) console.error(err.stack);
    failed++;
  }
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

// Generate a real P-256 keypair (DER/SPKI from Node.js)
const { privateKey: sigPriv, publicKey: sigPub } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const realDerSpki   = sigPub.export({ type: 'spki', format: 'der' });           // Buffer, 91 bytes
const realX963      = realDerSpki.subarray(26);                                 // Buffer, 65 bytes (0x04…)
const realDerSig    = crypto.sign('SHA256', Buffer.from('hello'), sigPriv);     // DER ECDSA
// Simulated P1363 sig: take raw R and S from the DER sig
const realP1363     = simulatedP1363FromDer(realDerSig);                        // Buffer, 64 bytes

// ── x9.63 ↔ DER/SPKI ─────────────────────────────────────────────────────────

console.log('x963 ↔ DER/SPKI conversions');

test('x963ToDerSpki produces 91-byte DER/SPKI', () => {
  const result = PeerCryptoAdapter.x963ToDerSpki(realX963);
  assert.equal(result.length, 91);
  assert.equal(result[0], 0x30);
});

test('x963ToDerSpki round-trips back to original DER/SPKI', () => {
  const converted = PeerCryptoAdapter.x963ToDerSpki(realX963);
  assert.ok(converted.equals(realDerSpki));
});

test('derSpkiToX963 extracts 65-byte x9.63 point', () => {
  const result = PeerCryptoAdapter.derSpkiToX963(realDerSpki);
  assert.equal(result.length, 65);
  assert.equal(result[0], 0x04);
});

test('derSpkiToX963 round-trips back to original x9.63', () => {
  const converted = PeerCryptoAdapter.derSpkiToX963(realDerSpki);
  assert.ok(converted.equals(realX963));
});

test('x9.63 → DER/SPKI → importable by crypto.createPublicKey', () => {
  const converted = PeerCryptoAdapter.x963ToDerSpki(realX963);
  const imported  = crypto.createPublicKey({ key: converted, format: 'der', type: 'spki' });
  assert.equal(imported.asymmetricKeyType, 'ec');
});

test('x9.63 → DER/SPKI: imported key verifies a signature', () => {
  const converted = PeerCryptoAdapter.x963ToDerSpki(realX963);
  const imported  = crypto.createPublicKey({ key: converted, format: 'der', type: 'spki' });
  const ok = crypto.verify('SHA256', Buffer.from('hello'), imported, realDerSig);
  assert.ok(ok, 'signature should verify with imported key');
});

test('x963ToDerSpki throws on wrong-size input', () => {
  assert.throws(() => PeerCryptoAdapter.x963ToDerSpki(Buffer.alloc(64)), /65-byte/);
});

test('derSpkiToX963 throws on wrong-size input', () => {
  assert.throws(() => PeerCryptoAdapter.derSpkiToX963(Buffer.alloc(90)), /91-byte/);
});

test('derSpkiToX963 throws on wrong header', () => {
  const bad = Buffer.from(realDerSpki);
  bad[2] = 0xff;  // corrupt AlgorithmIdentifier
  assert.throws(() => PeerCryptoAdapter.derSpkiToX963(bad), /header/);
});

// ── P1363 ↔ DER ECDSA ────────────────────────────────────────────────────────

console.log('\nP1363 ↔ DER ECDSA conversions');

test('p1363ToDer produces DER SEQUENCE (starts with 0x30)', () => {
  const result = PeerCryptoAdapter.p1363ToDer(realP1363);
  assert.equal(result[0], 0x30);
  assert.ok(result.length >= 70 && result.length <= 72, `unexpected DER sig length: ${result.length}`);
});

test('derToP1363 produces 64-byte P1363', () => {
  const result = PeerCryptoAdapter.derToP1363(realDerSig);
  assert.equal(result.length, 64);
});

test('DER → P1363 → DER round-trip: re-encoded sig still verifies', () => {
  const p1363      = PeerCryptoAdapter.derToP1363(realDerSig);
  const backToDer  = PeerCryptoAdapter.p1363ToDer(p1363);
  const ok = crypto.verify('SHA256', Buffer.from('hello'), sigPub, backToDer);
  assert.ok(ok, 'round-tripped signature should verify');
});

test('P1363 → DER: converted sig verifies with original public key', () => {
  const converted = PeerCryptoAdapter.p1363ToDer(realP1363);
  const ok = crypto.verify('SHA256', Buffer.from('hello'), sigPub, converted);
  assert.ok(ok, 'P1363→DER converted sig should verify');
});

test('p1363ToDer throws on wrong-size input', () => {
  assert.throws(() => PeerCryptoAdapter.p1363ToDer(Buffer.alloc(63)), /64-byte/);
});

test('derToP1363 throws on non-SEQUENCE input', () => {
  assert.throws(() => PeerCryptoAdapter.derToP1363(Buffer.from([0x02, 0x01, 0x00])), /0x30/);
});

// ── Edge cases: R or S with leading zeros / MSB set ──────────────────────────

console.log('\nEdge cases: integer boundary conditions');

test('p1363ToDer handles R with high bit set (MSB = 1)', () => {
  // Construct a P1363 where R[0] = 0x80 (high bit set → needs 0x00 prefix in DER)
  const p1363 = Buffer.alloc(64, 0x01);
  p1363[0] = 0x80;
  const der = PeerCryptoAdapter.p1363ToDer(p1363);
  // DER layout: [0x30][seq_len][0x02][R_len][0x00][0x80]...
  //              [0]   [1]      [2]   [3]    [4]   [5]
  assert.equal(der[2], 0x02, 'R INTEGER tag');
  assert.equal(der[3], 0x21, 'R should be 33 bytes (0x21) due to 0x00 prefix');
  assert.equal(der[4], 0x00, 'R should have 0x00 prefix');
  assert.equal(der[5], 0x80, 'R first value byte');
});

test('p1363ToDer handles R with leading zeros', () => {
  // Construct a P1363 where R starts with two 0x00 bytes (stripped in DER)
  const p1363 = Buffer.alloc(64, 0x01);
  p1363[0] = 0x00;
  p1363[1] = 0x00;
  p1363[2] = 0x7f; // first significant byte (< 0x80, no 0x00 prefix needed)
  const der = PeerCryptoAdapter.p1363ToDer(p1363);
  // DER layout: [0x30][seq_len][0x02][R_len=30][0x7f][0x01]...
  //              [0]   [1]      [2]   [3]       [4]
  assert.equal(der[2], 0x02, 'INTEGER tag');
  assert.equal(der[3], 30,   `R length should be 30 (32 − 2 leading zeros), got ${der[3]}`);
  assert.equal(der[4], 0x7f, 'R first value byte');
});

test('derToP1363 + padTo32 handles R shorter than 32 bytes (leading zeros in original)', () => {
  // Build a DER sig where R is only 30 bytes (two leading zeros stripped)
  const shortR = Buffer.alloc(30, 0x01);
  shortR[0] = 0x01; // no high bit
  const fullS  = Buffer.alloc(32, 0x02);
  const rDer   = Buffer.concat([Buffer.from([0x02, 30]), shortR]);
  const sDer   = Buffer.concat([Buffer.from([0x02, 32]), fullS]);
  const seq    = Buffer.concat([rDer, sDer]);
  const der    = Buffer.concat([Buffer.from([0x30, seq.length]), seq]);

  const p1363 = PeerCryptoAdapter.derToP1363(der);
  assert.equal(p1363.length, 64);
  // First 2 bytes of R in P1363 should be 0x00 (zero-padded)
  assert.equal(p1363[0], 0x00);
  assert.equal(p1363[1], 0x00);
  assert.equal(p1363[2], 0x01); // actual value starts here
});

// ── Auto-detection (normalise*) ───────────────────────────────────────────────

console.log('\nnormalizePublicKey / normalizeSignature');

test('normalizePublicKey is a no-op for DER/SPKI input (Buffer)', () => {
  const result = PeerCryptoAdapter.normalizePublicKey(realDerSpki);
  assert.ok(result === realDerSpki);  // same reference — no copy
});

test('normalizePublicKey is a no-op for DER/SPKI input (base64 string)', () => {
  const b64    = realDerSpki.toString('base64');
  const result = PeerCryptoAdapter.normalizePublicKey(b64);
  assert.equal(result, b64);
});

test('normalizePublicKey converts x9.63 Buffer to DER/SPKI Buffer', () => {
  const result = PeerCryptoAdapter.normalizePublicKey(realX963);
  assert.equal(result.length, 91);
  assert.ok(result.equals(realDerSpki));
});

test('normalizePublicKey converts x9.63 base64 to DER/SPKI base64', () => {
  const x963b64    = realX963.toString('base64');
  const derSpkiB64 = realDerSpki.toString('base64');
  assert.equal(PeerCryptoAdapter.normalizePublicKey(x963b64), derSpkiB64);
});

test('normalizeSignature is a no-op for DER input (Buffer)', () => {
  const result = PeerCryptoAdapter.normalizeSignature(realDerSig);
  assert.ok(result === realDerSig);
});

test('normalizeSignature converts P1363 Buffer to DER Buffer', () => {
  const result = PeerCryptoAdapter.normalizeSignature(realP1363);
  assert.equal(result[0], 0x30);
  const ok = crypto.verify('SHA256', Buffer.from('hello'), sigPub, result);
  assert.ok(ok);
});

test('normalizePublicKey throws on unrecognized format', () => {
  assert.throws(() => PeerCryptoAdapter.normalizePublicKey(Buffer.alloc(33)), /unrecognized/);
});

test('normalizeSignature throws on unrecognized format', () => {
  assert.throws(() => PeerCryptoAdapter.normalizeSignature(Buffer.alloc(33)), /unrecognized/);
});

// ── End-to-end cross-format scenario ─────────────────────────────────────────
// Simulates: iOS sends x9.63 public key and P1363 signature → Node.js receives and verifies.

console.log('\nEnd-to-end cross-format scenario');

test('iOS→Node.js: x9.63 key + P1363 signature verifiable after normalization', () => {
  // "iOS" side: key is in x9.63, signature is P1363
  const iosPublicKeyB64  = realX963.toString('base64');    // as iOS would transmit
  const iosSignatureB64  = realP1363.toString('base64');   // as iOS would transmit
  const message          = Buffer.from('cross-platform message');

  // "Node.js" side: normalize both
  const normalizedKey = PeerCryptoAdapter.normalizePublicKey(iosPublicKeyB64);
  const normalizedSig = PeerCryptoAdapter.normalizeSignature(iosSignatureB64);

  const importedKey = crypto.createPublicKey({
    key:    Buffer.from(normalizedKey, 'base64'),
    format: 'der',
    type:   'spki',
  });

  // Reuse the known-good DER sig (our P1363 fixture was derived from it)
  // normalizedSig should match the original DER
  const ok = crypto.verify('SHA256', Buffer.from('hello'), importedKey,
                            Buffer.from(normalizedSig, 'base64'));
  assert.ok(ok, 'cross-format signature should verify');
});

test('Node.js→iOS: DER key + DER signature convertible to x9.63 + P1363', () => {
  // "Node.js" emits DER; "iOS" needs x9.63 and P1363
  const nodeKeyB64 = realDerSpki.toString('base64');
  const nodeSigB64 = realDerSig.toString('base64');

  const x963B64  = PeerCryptoAdapter.derSpkiToX963(nodeKeyB64);
  const p1363B64 = PeerCryptoAdapter.derToP1363(nodeSigB64);

  // Verify that the round-tripped key is importable and verifies the signature
  const importedKeyDer = PeerCryptoAdapter.x963ToDerSpki(Buffer.from(x963B64, 'base64'));
  const importedKey    = crypto.createPublicKey({ key: importedKeyDer, format: 'der', type: 'spki' });
  const reEncodedSig   = PeerCryptoAdapter.p1363ToDer(Buffer.from(p1363B64, 'base64'));
  const ok = crypto.verify('SHA256', Buffer.from('hello'), importedKey, reEncodedSig);
  assert.ok(ok, 'reverse cross-format should also verify');
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests — ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

// ── Helpers ───────────────────────────────────────────────────────────────────

// Builds a P1363 fixture from a real DER signature (for testing).
function simulatedP1363FromDer(derSig) {
  const p1363 = PeerCryptoAdapter.derToP1363(derSig);
  return p1363;
}

})().catch(err => { console.error(err); process.exit(1); });
