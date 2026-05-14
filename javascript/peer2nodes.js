'use strict';

const crypto = require('node:crypto');

const MessageType = Object.freeze({
  HELLO: 'HELLO',
  HELLO_ACK: 'HELLO_ACK',
  OFFER: 'OFFER',
  ANSWER: 'ANSWER',
  CANDIDATE: 'CANDIDATE',
  DATA: 'DATA',
  HEARTBEAT: 'HEARTBEAT',
  GOODBYE: 'GOODBYE',
  ERROR: 'ERROR'
});

const Capability = Object.freeze({
  WEBRTC_DATA_CHANNEL: 'webrtc-data-channel',
  WIFI_DIRECT: 'wifi-direct',
  WIFI_AWARE: 'wifi-aware',
  BLE_GATT: 'ble-gatt',
  END_TO_END_ENCRYPTION: 'end-to-end-encryption',
  FILE_TRANSFER: 'file-transfer',
  STREAMING: 'streaming'
});

const TransportKind = Object.freeze({
  WEBRTC: 'webrtc',
  WIFI_DIRECT: 'wifi-direct',
  WIFI_AWARE: 'wifi-aware',
  BLE: 'ble'
});

const PayloadEncoding = Object.freeze({
  JSON: 'json',
  UTF8: 'utf8',
  BASE64: 'base64',
  BINARY: 'binary'
});

const EncryptionMode = Object.freeze({
  NONE: 'none',
  DTLS: 'dtls',
  NOISE_XK: 'noise-xk',
  TLS: 'tls'
});

function stripNullish(value) {
  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    return value.map(stripNullish);
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, nestedValue]) => nestedValue !== null && nestedValue !== undefined)
        .map(([key, nestedValue]) => [key, stripNullish(nestedValue)])
    );
  }

  return value;
}

class MemoryPeerTransport {
  #handler = null;
  #remote = null;

  connect(remoteTransport) {
    this.#remote = remoteTransport;
  }

  setMessageHandler(handler) {
    this.#handler = handler;
  }

  async start() {}

  async stop() {}

  async send(envelope) {
    if (this.#remote?.#handler) {
      await this.#remote.#handler(envelope);
    }
  }
}

class PeerNodeClient {
  constructor({
    nodeId = crypto.randomUUID(),
    protocolVersion = '1.0.0',
    capabilities,
    transport,
    now = () => new Date()
  }) {
    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      throw new Error('capabilities must be a non-empty array');
    }
    if (!transport) {
      throw new Error('transport is required');
    }

    this.nodeId = nodeId;
    this.protocolVersion = protocolVersion;
    this.capabilities = capabilities;
    this.transport = transport;
    this.now = now;
    this.sessions = new Map();

    this.onSessionOpened = null;
    this.onData = null;
    this.onFailure = null;
    this.onSessionClosed = null;
  }

  async start() {
    this.transport.setMessageHandler(async (envelope) => {
      await this.#handleIncoming(envelope);
    });
    await this.transport.start();
  }

  async stop() {
    await this.transport.stop();
    this.sessions.clear();
  }

  async openSession(targetNodeId = null) {
    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, {
      targetNodeId,
      lastReceivedAt: this.now(),
      nextSequence: 1,
      connected: false
    });

    await this.transport.send(this.#buildEnvelope({
      messageType: MessageType.HELLO,
      sessionId,
      targetNodeId,
      capabilities: this.capabilities
    }));

    return sessionId;
  }

  async sendData({
    sessionId,
    body,
    targetNodeId = null,
    contentType = 'text/plain',
    encoding = PayloadEncoding.UTF8
  }) {
    await this.transport.send(this.#buildEnvelope({
      messageType: MessageType.DATA,
      sessionId,
      targetNodeId: targetNodeId ?? this.sessions.get(sessionId)?.targetNodeId ?? null,
      payload: { contentType, encoding, body }
    }));
  }

  async sendHeartbeat(sessionId, targetNodeId = null) {
    await this.transport.send(this.#buildEnvelope({
      messageType: MessageType.HEARTBEAT,
      sessionId,
      targetNodeId: targetNodeId ?? this.sessions.get(sessionId)?.targetNodeId ?? null
    }));
  }

  async disconnect(sessionId, targetNodeId = null) {
    await this.transport.send(this.#buildEnvelope({
      messageType: MessageType.GOODBYE,
      sessionId,
      targetNodeId: targetNodeId ?? this.sessions.get(sessionId)?.targetNodeId ?? null
    }));
    this.sessions.delete(sessionId);
    if (this.onSessionClosed) {
      this.onSessionClosed(sessionId);
    }
  }

  encode(envelope) {
    return JSON.stringify(stripNullish(envelope));
  }

  decode(json) {
    const parsed = JSON.parse(json);
    return {
      ...parsed,
      timestamp: new Date(parsed.timestamp)
    };
  }

  async #handleIncoming(envelope) {
    if (!this.sessions.has(envelope.sessionId)) {
      this.sessions.set(envelope.sessionId, {
        targetNodeId: envelope.sourceNodeId,
        lastReceivedAt: envelope.timestamp,
        nextSequence: envelope.sequence + 1,
        connected: false
      });
    }

    const state = this.sessions.get(envelope.sessionId);
    state.targetNodeId = envelope.sourceNodeId;
    state.lastReceivedAt = envelope.timestamp;

    switch (envelope.messageType) {
      case MessageType.HELLO:
        state.connected = true;
        if (this.onSessionOpened) {
          this.onSessionOpened(envelope.sessionId, envelope.sourceNodeId);
        }
        await this.transport.send(this.#buildEnvelope({
          messageType: MessageType.HELLO_ACK,
          sessionId: envelope.sessionId,
          targetNodeId: envelope.sourceNodeId,
          capabilities: this.capabilities
        }));
        break;
      case MessageType.HELLO_ACK:
        state.connected = true;
        if (this.onSessionOpened) {
          this.onSessionOpened(envelope.sessionId, envelope.sourceNodeId);
        }
        break;
      case MessageType.DATA:
        if (this.onData) {
          this.onData(envelope);
        }
        break;
      case MessageType.ERROR:
        if (this.onFailure) {
          this.onFailure(envelope);
        }
        break;
      case MessageType.GOODBYE:
        this.sessions.delete(envelope.sessionId);
        if (this.onSessionClosed) {
          this.onSessionClosed(envelope.sessionId);
        }
        break;
      case MessageType.HEARTBEAT:
      case MessageType.OFFER:
      case MessageType.ANSWER:
      case MessageType.CANDIDATE:
        break;
      default:
        throw new Error(`Unhandled message type: ${envelope.messageType}`);
    }
  }

  #buildEnvelope({
    messageType,
    sessionId,
    targetNodeId = null,
    capabilities = null,
    negotiation = null,
    payload = null,
    security = null,
    error = null
  }) {
    return {
      protocolVersion: this.protocolVersion,
      messageType,
      sessionId,
      sourceNodeId: this.nodeId,
      targetNodeId,
      timestamp: this.now(),
      sequence: this.#nextSequence(sessionId),
      capabilities,
      negotiation,
      payload,
      security,
      error
    };
  }

  #nextSequence(sessionId) {
    const state = this.sessions.get(sessionId) ?? {
      targetNodeId: null,
      lastReceivedAt: this.now(),
      nextSequence: 1,
      connected: false
    };
    const sequence = state.nextSequence;
    state.nextSequence += 1;
    this.sessions.set(sessionId, state);
    return sequence;
  }
}

module.exports = {
  Capability,
  EncryptionMode,
  MemoryPeerTransport,
  MessageType,
  PayloadEncoding,
  PeerNodeClient,
  TransportKind
};
