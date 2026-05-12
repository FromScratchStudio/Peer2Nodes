# Peer2Nodes

Peer-to-peer communication component for mobile devices and desktop that allows direct connection between nodes.

## Goal

Provide a universal, app-embeddable peer communication layer that can connect one app instance directly to another app instance across iOS, Android, and desktop environments.

## Compatibility Model

- **Transport-agnostic core**: app code targets one protocol and can plug in platform transports.
- **Modern mobile-first transports**:
  - WebRTC DataChannel (preferred when available)
  - Wi-Fi Direct / Wi-Fi Aware capable adapters
  - BLE local-link adapters for constrained networks
- **Cross-platform protocol contract**: all peers exchange the same versioned message envelope.

## Protocol

The repository now includes a universal JSON Schema for peer messages:

- `protocol/peer2nodes-message.schema.json`

This schema defines:

- Identity and capability handshake messages
- Session negotiation messages
- Reliable app payload messages
- Heartbeat / disconnect control messages
- Required metadata for interoperability, versioning, and security signaling

## Runtime Implementations

The repository now includes reference runtime code for three environments:

- iOS: `ios/Sources/Peer2Nodes/Peer2Nodes.swift`
- Android/JVM: `android/src/main/java/com/fromscratchstudio/peer2nodes/Peer2Nodes.kt`
- JavaScript runtimes (desktop/server/web tooling): `javascript/peer2nodes.js`

Each runtime includes:

- The shared Peer2Nodes message model
- Session lifecycle handling for `HELLO`, `HELLO_ACK`, `DATA`, `HEARTBEAT`, and `GOODBYE`
- A transport abstraction that can be backed by WebRTC, local wireless discovery, or another direct transport
- A loopback/in-memory transport implementation for integration and smoke testing
