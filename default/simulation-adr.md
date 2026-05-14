# Architecture Decision Record — Peer2Nodes Simulation App

**Date:** 2026-05-14
**Author:** Claude Sonnet 4.6 (AI-assisted implementation)
**Directory:** `simulation/`
**Status:** Implemented

---

## 1. Context

The simulation app provides a visual, in-browser sandbox for exercising the full
`PeerChannelManager` lifecycle — instance creation, mutual authentication, encrypted
messaging, and ACK tracking — without needing a native runtime (Node.js, iOS, Android).

All existing runtime implementations (`javascript/peer-channel.js`,
`ios/…/PeerChannelManager.swift`, `android/…/PeerChannelManager.kt`) depend on
platform-native crypto APIs that are not available in a browser context. The simulation
therefore required browser-compatible ports of both the protocol layer and the crypto layer.

---

## 2. Decisions

### 2.1 Zero-dependency, zero-build — ES modules served directly

The simulation is four plain files loadable by any modern browser with no bundler,
no npm install, and no local server (file:// works for Chromium; Firefox/Safari
require a server due to CORS on ES module imports).

**Why no bundler?**
The goal is an exploratory tool, not a shipped product. Keeping it dependency-free
means the simulation stays always runnable with a double-click in Chrome, which is the
correct trade-off for a developer simulation.

**Structure:**

| File | Role |
|---|---|
| `index.html` | HTML shell + inline CSS |
| `peer2nodes-browser.js` | ES-module port of `javascript/peer2nodes.js` |
| `peer-channel-browser.js` | ES-module port of `javascript/peer-channel.js` |
| `app.js` | UI orchestration |

### 2.2 Web Crypto API (crypto.subtle) for all cryptographic operations

The Node.js `peer-channel.js` uses `require('node:crypto')` which is not available in
browsers. The browser port rewrites `PeerCryptoService` entirely using `crypto.subtle`.

| Operation | Node.js | Browser (crypto.subtle) |
|---|---|---|
| P-256 ECDSA key generation | `generateKeyPairSync('ec', …)` | `subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, …)` |
| P-256 ECDH key generation | `generateKeyPairSync('ec', …)` | `subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, …)` |
| ECDH shared secret | `crypto.diffieHellman(…)` | `subtle.deriveBits({ name: 'ECDH', public: … }, …)` |
| HKDF-SHA256 | `crypto.hkdfSync(…)` | `subtle.importKey('raw', …, 'HKDF') + subtle.deriveKey(…)` |
| AES-256-GCM encrypt | `createCipheriv('aes-256-gcm', …)` | `subtle.encrypt({ name: 'AES-GCM', iv: … }, …)` |
| AES-256-GCM decrypt | `createDecipheriv(…)` | `subtle.decrypt({ name: 'AES-GCM', iv: … }, …)` |
| ECDSA sign | `crypto.sign('SHA256', …)` | `subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, …)` |
| ECDSA verify | `crypto.verify(…)` | `subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, …)` |
| Random bytes | `crypto.randomBytes(n)` | `crypto.getRandomValues(new Uint8Array(n))` |
| UUID | `crypto.randomUUID()` | `crypto.randomUUID()` (same global API) |

`PeerCryptoService.create()` is a static async factory because key generation is now
async. All downstream methods that invoke crypto are likewise async; the calling code
in `PeerChannelManager` is unchanged in structure, just with `await` added to crypto
calls.

**Signature format note:** `crypto.subtle.sign` with ECDSA returns raw P1363 (64-byte
R‖S), not DER. Since both nodes in the simulation run in the same browser and use the
same Web Crypto API, the format is consistent end-to-end. No `PeerCryptoAdapter`
conversion is required within the simulation. Cross-platform interoperability (browser ↔
Node.js ↔ iOS ↔ Android) is out of scope for the simulation.

### 2.3 SimulationBus — shared message bus replaces point-to-point MemoryPeerTransport

`javascript/peer2nodes.js` provides `MemoryPeerTransport`, which links two transports
in a point-to-point pair (`transportA.connect(transportB)`). This works for a fixed
two-node test but does not scale to N instances each capable of talking to any other.

The simulation introduces `SimulationBus`, a simple registry:

```
SimulationBus
  #handlers: Map<nodeId, messageHandler>
  register(nodeId, handler)
  unregister(nodeId)
  deliver(envelope)        // routes envelope to handler at envelope.targetNodeId
```

`BusPeerTransport` wraps the bus and implements the `PeerNodeClient` transport
interface. When `PeerNodeClient.start()` calls `transport.setMessageHandler(fn)`, the
transport registers `fn` on the bus under its `nodeId`.

**Result:** any number of instances can coexist and communicate with any other instance
by specifying `targetNodeId`. No explicit pairing step is needed — connecting two
instances in the UI simply means choosing which two to call `openChannel()` on.

### 2.4 Inline async handshake chain — no polling, no events between turns

`BusPeerTransport.send()` does `await bus.deliver(envelope)`, which calls the
recipient's handler and awaits it. This means the entire HELLO → HELLO_ACK →
KEY-EXCHANGE → AUTH-RESPONSE → AUTH-CONFIRM chain executes as a single contiguous
chain of awaited Promises, completing before `openChannel()` returns.

This is the same guarantee as the `MemoryPeerTransport` in the Node.js tests. It means:

- `await manager.openChannel(targetNodeId)` resolves with a READY, authenticated sessionId.
- No polling or `onChannelReady` callback is needed by the caller — the returned
  sessionId is immediately usable.
- Both nodes' `onChannelReady` callbacks fire during this chain (before `openChannel`
  resolves), so UI logs appear in the correct causal order.

### 2.5 Channel registry in app.js — dual-side ownership model

`PeerChannelManager` tracks channels internally per instance. `app.js` maintains its
own `channels` Map (sessionId → metadata) for UI rendering purposes.

Both the initiator and responder fire `onChannelReady(sessionId, remoteNodeId)`. The
app.js callbacks populate the channel entry collaboratively:

1. **Responder** fires first (during `await sendData(AUTH_CONFIRM)` on the initiator):
   creates `{ peerIds: [responderId, null], peerNodeIds: [respNodeId, initNodeId] }`.
2. **Initiator** fires next: fills `peerIds[1] = initiatorId`.
3. `openChannel()` resolves: ensures both peerIds are set; creates entry if callbacks
   somehow did not (defensive).

Since all three steps occur within a single async chain before the browser event loop
yields, no partial state is ever visible to the user.

### 2.6 Message history per channel — in-memory, non-persistent

Each channel entry in `channels` carries a `messages: []` array. Outbound messages are
pushed before `sendMessage()` resolves; inbound messages are pushed in `onMessageReceived`.
`onMessageAcknowledged` marks the corresponding outbound message as `acked: true`.

Messages are rendered inside the channel card as a compact history (scrollable, capped
by CSS `max-height`). This is intentionally ephemeral — no localStorage persistence,
because the simulation's purpose is live interactive testing, not record-keeping.

### 2.7 Global event log — structured audit trail

A `appendLog(instanceName, color, event, detail)` function appends timestamped rows to
the `#log` panel at the bottom. Every significant event is logged:

- Instance created
- Channel opening initiated
- Handshake complete (READY)
- Message sent / received
- ACK received
- Error
- Channel closed

Each instance has a stable color (cycled from an 8-color palette) so log rows are
visually attributable at a glance. The log auto-scrolls to the bottom on each append.

---

## 3. Security scope

The simulation is a **developer tool, not a production component**. Security properties
are preserved from the real `PeerChannelManager` (mutual auth, AES-GCM encryption,
perfect forward secrecy) but the following points apply:

- Session keys live in browser JavaScript heap — no `SubtleCrypto` non-extractable
  enforcement beyond what Web Crypto provides by default (keys are `extractable: false`).
- Identity keys are ephemeral per page load — there is no persistence.
- The `SimulationBus` is an in-process router; "network" isolation does not apply.
  All instances share the same JavaScript origin and memory space.

---

## 4. Browser compatibility

| Feature | Minimum version |
|---|---|
| `crypto.subtle` (ECDH, ECDSA, AES-GCM, HKDF) | Chrome 67 / Firefox 57 / Safari 11 |
| `crypto.randomUUID()` | Chrome 92 / Firefox 95 / Safari 15.4 |
| ES modules (`type="module"`) | Chrome 61 / Firefox 60 / Safari 10.1 |
| Private class fields (`#field`) | Chrome 74 / Firefox 90 / Safari 14.1 |

**Effective minimum:** Chrome 92, Firefox 95, Safari 15.4 (driven by `randomUUID`).

---

## 5. File index

| File | Description |
|---|---|
| `simulation/index.html` | HTML shell + dark terminal CSS |
| `simulation/peer2nodes-browser.js` | `SimulationBus`, `BusPeerTransport`, `PeerNodeClient` (ES module) |
| `simulation/peer-channel-browser.js` | `PeerCryptoService` (Web Crypto), `OutboundMessageQueue`, `PeerChannelManager` (ES module) |
| `simulation/connection-info-share-browser.js` | Connection-info share encoding/decoding for URI, NFC payload, and QR payload |
| `simulation/app.js` | Instance management, channel orchestration, message send/receive, event log |
| `simulation/simulation-adr.md` | This document |
| `simulation/simulation-readme.md` | Usage guide and run instructions |
