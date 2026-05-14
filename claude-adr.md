# Architecture Decision Record — PeerChannelManager

**Date:** 2026-05-13  
**Author:** Claude Sonnet 4.6 (AI-assisted implementation)  
**Branch:** `copilot/add-peer-to-peer-communication`  
**Status:** Implemented

---

## 1. Context

The existing `PeerNodeClient` (JavaScript, Swift, Kotlin) provides a protocol-compliant session
layer (HELLO / HELLO_ACK / DATA / HEARTBEAT / GOODBYE) with a pluggable transport. It does **not**
provide:

- Peer identity authentication (any node can claim any `sourceNodeId`)
- Payload confidentiality (DATA messages are sent in the clear)
- Delivery guarantees (no acknowledgement tracking or retry)

`PeerChannelManager` is a higher-level component that wraps `PeerNodeClient` and adds all three.

---

## 2. Decisions

### 2.1 Layer above, not a fork

`PeerChannelManager` wraps an existing `PeerNodeClient` instance rather than replacing it. This
preserves backwards-compatibility: any app already using `PeerNodeClient` can migrate
incrementally by wrapping its client.

### 2.2 Mutual challenge-response authentication over the existing DATA channel

Auth messages are sent as **plain DATA frames** with reserved `contentType` values:

| contentType | Direction | Purpose |
|---|---|---|
| `application/vnd.peer2nodes.key-exchange+json` | Initiator → Responder | Ephemeral pub key + identity pub key + challenge nonce |
| `application/vnd.peer2nodes.auth-response+json` | Responder → Initiator | Ephemeral pub key + identity pub key + challenge nonce + `sig(A_challenge)` |
| `application/vnd.peer2nodes.auth-confirm+json` | Initiator → Responder | `sig(B_challenge)` |
| `application/vnd.peer2nodes.ack+json` | Receiver → Sender | ACK for a DATA message |
| `application/vnd.peer2nodes.app+json` | Either direction | Encrypted application payload |

This approach avoids schema changes to `peer2nodes-message.schema.json` — all auth frames are
valid `DATA` messages.

**Why not add new `messageType` values?**  
The schema is versioned. Adding new enum values is a protocol change that must be coordinated
across all clients. Piggybacking on DATA + contentType is already how HTTP multipart, gRPC, and
many other protocols carry sub-types over a single channel.

### 2.3 Ephemeral ECDH + HKDF for session key agreement (perfect forward secrecy)

Each channel open generates a fresh P-256 ephemeral keypair. The shared secret is derived via
ECDH and immediately expanded to a 256-bit AES-GCM key using HKDF-SHA256.

```
sharedSecret = ECDH(ephPrivA, ephPubB)  =  ECDH(ephPrivB, ephPubA)
sessionKey   = HKDF-SHA256(sharedSecret, salt=0x00…, info="peer2nodes-v1", len=32)
```

Discarding the ephemeral private key after derivation ensures past sessions cannot be decrypted
even if the long-term identity key is later compromised.

### 2.4 P-256 (secp256r1) for all asymmetric operations

| Algorithm | Usage |
|---|---|
| P-256 ECDH | Ephemeral key agreement |
| ECDSA / SHA-256 with P-256 | Identity challenge-response signatures |
| AES-256-GCM | Symmetric payload encryption (12-byte random nonce) |
| HKDF-SHA256 | Key derivation |

**Why P-256 over Curve25519/Ed25519?**  
P-256 is available natively on all three target platforms without extra dependencies:
- iOS: `CryptoKit.P256` (iOS 13+)
- Android: JCE `EC/secp256r1` + `ECDH` (API 26+)
- Node.js: `crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })`

Curve25519 would require an additional dependency on Android (API 31+ for `XDH`) and the
`rawRepresentation` export is non-standard on JCE. P-256 is a pragmatic choice for maximum
platform coverage without bridging libraries.

### 2.5 AES-256-GCM for payload encryption

AES-GCM provides authenticated encryption (confidentiality + integrity + authenticity) in a
single pass. A fresh 96-bit nonce is generated per message (`SecureRandom` / `kSecRandomDefault`
/ `crypto.randomBytes`). The GCM authentication tag (128 bits) is appended to the ciphertext
before base64-encoding, making tampering detectable.

**Replay attack mitigation:** AES-GCM alone does not prevent message replay. The existing
`sequence` counter in `PeerEnvelope` can be checked by the application layer to reject
out-of-order or replayed envelopes; this is documented as a caller responsibility (see §6).

### 2.6 ACK queue with configurable retry / expiry

`OutboundMessageQueue` stores the `sendFn` closure for each unacknowledged message and
periodically re-invokes it until an ACK is received or `maxRetries` is exhausted.

Default tuning: **3 retries, 5-second interval**. These are overridable per-manager to suit
different transport latency profiles (BLE requires larger values than WebRTC).

The Promise / callback returned by `sendMessage` lets callers do exactly-once delivery
confirmation without polling.

---

## 3. Security Analysis

### 3.1 Threat model

| Threat | Mitigation |
|---|---|
| Passive eavesdropping | AES-256-GCM encryption of all app payloads |
| Active MITM during handshake | Mutual challenge-response: both nodes sign the other's nonce with their long-term identity key |
| Identity spoofing | Identity keys must be pre-shared (pinned) via an out-of-band channel (QR code, invite link, etc.) |
| Replay of old messages | Per-message random GCM nonce (probabilistic); sequence counter monotonicity check (caller responsibility) |
| Tampering with ciphertext | AES-GCM authentication tag — any modification causes `AEADBadTagException` / `CryptoKitError.authenticationFailure` |
| Past-session decryption | Ephemeral ECDH keys are discarded after `deriveSessionKey` — perfect forward secrecy |
| Brute-force on session key | 256-bit AES key; infeasible with current hardware |

### 3.2 Known limitations

1. **No PKI / certificate authority.** Identity keys are long-lived public keys that must be
   trusted via an out-of-band mechanism. Without key pinning the system is vulnerable to TOFU
   (Trust On First Use) attacks. Future work: integrate a lightweight certificate or capability
   token system.

2. **No sequence-number window check in `PeerChannelManager`.** The `sequence` field in
   `PeerEnvelope` is available but not validated against a sliding window. Applications that
   require strict anti-replay should check monotonicity in their `onMessageReceived` handler.

3. **Session keys are held in process memory.** No key escrow or hardware-backed keystore
   integration. On iOS, migrating `SymmetricKey` to `CryptoKit`'s `SecureEnclave` support
   would further harden against process-memory attacks.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Application Layer                   │
└───────────────┬───────────────────────┬─────────────┘
                │ openChannel           │ sendMessage / onMessageReceived
┌───────────────▼───────────────────────▼─────────────┐
│              PeerChannelManager                      │
│  ┌─────────────────────┐  ┌──────────────────────┐  │
│  │  PeerCryptoService  │  │ OutboundMessageQueue  │  │
│  │  (ECDH + ECDSA +    │  │  (retry / ACK track) │  │
│  │   AES-256-GCM)      │  └──────────────────────┘  │
│  └─────────────────────┘                            │
│                    ↕  DATA envelopes                 │
│              PeerNodeClient                          │
│   (HELLO / HELLO_ACK / DATA / HEARTBEAT / GOODBYE)  │
└───────────────────────────────────────────────────┬──┘
                                                    │
┌───────────────────────────────────────────────────▼──┐
│           PeerTransport (pluggable)                   │
│  LoopbackPeerTransport │ WebRTC │ Wi-Fi Direct │ BLE  │
└──────────────────────────────────────────────────────┘
```

---

## 5. Cross-platform wire format

All platforms now emit and accept a single canonical wire format:

| Field | Canonical format |
|---|---|
| Public keys | DER/SPKI (91 bytes), base64 |
| ECDSA signatures | DER-encoded ECDSA (70–72 bytes), base64 |

### Platform native vs. wire format

| Platform | Native key format | Native sig format | Conversion |
|---|---|---|---|
| **Node.js** | DER/SPKI | DER ECDSA | None (already canonical) |
| **Android (JCE)** | DER/SPKI | DER ECDSA | None (already canonical) |
| **iOS (CryptoKit)** | x9.63 uncompressed (65 B) | P1363 R‖S (64 B) | `PeerCryptoAdapter` (transparent in `PeerCryptoService`) |

### PeerCryptoAdapter

`PeerCryptoAdapter` is a stateless utility available on all three platforms. It provides:

- `x963ToDerSpki` / `derSpkiToX963` — P-256 public key format conversion
- `p1363ToDer` / `derToP1363` — ECDSA signature format conversion
- `normalizePublicKey` / `normalizeSignature` — auto-detect format and normalise to canonical

The iOS `PeerCryptoService` uses the adapter transparently: it internally converts CryptoKit's
native formats to/from the canonical DER wire format. Callers and `PeerChannelManager` see only
the canonical base64 strings.

**Result:** iOS ↔ Android ↔ Node.js sessions are fully interoperable at the
`PeerChannelManager` level without any caller changes.

---

## 6. File Index

| File | Description |
|---|---|
| `javascript/peer-channel.js` | JS `PeerCryptoService`, `OutboundMessageQueue`, `PeerChannelManager` |
| `javascript/peer-channel.test.js` | 21 JS channel tests (`node javascript/peer-channel.test.js`) |
| `javascript/peer-crypto-adapter.js` | JS `PeerCryptoAdapter` format-conversion utilities |
| `javascript/peer-crypto-adapter.test.js` | 28 JS adapter tests (`node javascript/peer-crypto-adapter.test.js`) |
| `ios/Sources/Peer2Nodes/PeerChannelManager.swift` | Swift `PeerCryptoService` (DER canonical), `OutboundMessageQueue`, `PeerChannelManager` |
| `ios/Sources/Peer2Nodes/PeerCryptoAdapter.swift` | Swift `PeerCryptoAdapter` (x9.63 ↔ DER/SPKI, P1363 ↔ DER) |
| `ios/Tests/Peer2NodesTests/PeerChannelManagerTests.swift` | XCTest suite (12 tests) |
| `android/src/main/java/…/PeerChannelManager.kt` | Kotlin `PeerCryptoService`, `OutboundMessageQueue`, `PeerChannelManager` |
| `android/src/main/java/…/PeerCryptoAdapter.kt` | Kotlin `PeerCryptoAdapter` format-conversion utilities |
| `android/src/test/java/…/PeerChannelManagerTest.kt` | JUnit4 channel test suite (11 tests) |
| `android/src/test/java/…/PeerCryptoAdapterTest.kt` | JUnit4 adapter test suite (18 tests) |

---

## 7. Future Work

- Sliding-window sequence counter check in `PeerChannelManager` for anti-replay
- Identity key persistence (Keychain on iOS, Android Keystore) for across-launch identity stability
- Rate-limiting on handshake messages to mitigate handshake-flooding DoS
- Session rekeying (periodic key rotation without re-authentication)
