# ADR — WebRTC peer-to-peer transport (Option B)

**Date:** 2026-05-14  
**Status:** Implemented (runtime building blocks)

## 1. Context

The existing simulation transport is in-memory and local to a single page/process.  
It cannot connect two browsers running on two different machines.

To support real cross-device communication, we need:

1. a true P2P transport (WebRTC DataChannel) for application envelopes,
2. a signaling path to exchange `offer` / `answer` / `candidate` during negotiation.

## 2. Decision

Implement Option B as a transport-layer extension across JavaScript, iOS, and Kotlin:

- keep `PeerNodeClient` and protocol semantics unchanged,
- introduce WebRTC as another `PeerTransport` implementation,
- isolate signaling and engine responsibilities behind clean interfaces.

## 3. What was added

### 3.1 JavaScript

Files:

- `javascript/webrtc-p2p.js`
- `javascript/signaling-server.js`

Key elements:

- `WebRTCPeerTransport`: `PeerTransport` over `RTCPeerConnection` + `RTCDataChannel`.
- `HttpPollingSignaling`: signaling client (publish + long-poll receive).
- `SignalType`: `offer`, `answer`, `candidate`.
- Minimal signaling relay server (Node `http`, no external dependency).

After DataChannel setup, `PeerEnvelope` messages flow peer-to-peer and do not traverse the signaling server.

### 3.2 iOS (Swift)

File:

- `ios/Sources/Peer2Nodes/WebRTCPeerTransport.swift`

Key elements:

- `WebRTCSignalType`, `WebRTCSignal`
- `WebRTCSignalingClient` (signaling abstraction)
- `WebRTCEngine` (native WebRTC engine abstraction)
- `WebRTCPeerTransport` (implements `PeerTransport`)

This keeps app-specific WebRTC framework choices outside core transport logic.

### 3.3 Android/Kotlin

File:

- `android/src/main/java/com/fromscratchstudio/peer2nodes/WebRTCPeerTransport.kt`

Key elements:

- `WebRTCSignalType`, `WebRTCSignal`
- `WebRTCSignalingClient`, `WebRTCEngine`, `PeerEnvelopeCodec`
- `WebRTCPeerTransport` (implements `PeerTransport`)

The same separation of concerns is applied: orchestration in transport, platform specifics in adapters.

## 4. Clean code principles applied

- **Single Responsibility**: transport, signaling, and WebRTC engine are separated.
- **Dependency Inversion**: iOS/Kotlin depend on interfaces, not concrete SDK bindings.
- **Open/Closed**: signaling backend can be replaced without changing protocol logic.
- **Consistency**: naming and flow are aligned across JS/Swift/Kotlin implementations.

## 5. Runtime flow

1. Peer A sends to B via `WebRTCPeerTransport`.
2. If no channel exists, A creates and signals an offer.
3. B receives offer, creates answer, signals back.
4. ICE candidates are exchanged through signaling.
5. Once DataChannel opens, `PeerEnvelope` traffic is direct P2P.

## 6. Operational notes

- The provided signaling server is intentionally minimal and in-memory.
- Production deployments should add:
  - authentication and authorization,
  - room/session controls,
  - monitoring/metrics,
  - lifecycle cleanup and persistence strategy (if needed).

## 7. Compatibility

Existing transports (`MemoryPeerTransport`, `LoopbackPeerTransport`, simulation bus) remain valid.  
WebRTC is introduced as an additional transport option behind the same protocol contract.
