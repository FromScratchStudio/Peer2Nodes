// Browser ES-module port of peer2nodes.js — no Node.js dependencies.

const MessageType = Object.freeze({
  HELLO: 'HELLO', HELLO_ACK: 'HELLO_ACK', OFFER: 'OFFER', ANSWER: 'ANSWER',
  CANDIDATE: 'CANDIDATE', DATA: 'DATA', HEARTBEAT: 'HEARTBEAT',
  GOODBYE: 'GOODBYE', ERROR: 'ERROR',
});

const Capability = Object.freeze({
  WEBRTC_DATA_CHANNEL: 'webrtc-data-channel',
  END_TO_END_ENCRYPTION: 'end-to-end-encryption',
});

const PayloadEncoding = Object.freeze({
  JSON: 'json', UTF8: 'utf8', BASE64: 'base64', BINARY: 'binary',
});

// ---------------------------------------------------------------------------
// SimulationBus — routes envelopes to registered node handlers by targetNodeId.
// Replaces the point-to-point MemoryPeerTransport for multi-instance simulations.
// ---------------------------------------------------------------------------
class SimulationBus {
  #handlers = new Map(); // nodeId -> handler fn

  register(nodeId, handler) { this.#handlers.set(nodeId, handler); }
  unregister(nodeId) { this.#handlers.delete(nodeId); }

  async deliver(envelope) {
    if (!envelope.targetNodeId) return;
    const handler = this.#handlers.get(envelope.targetNodeId);
    if (handler) await handler(envelope);
  }
}

// ---------------------------------------------------------------------------
// BusPeerTransport — PeerNodeClient transport that sends via SimulationBus.
// ---------------------------------------------------------------------------
class BusPeerTransport {
  #bus;
  #nodeId;
  #handler = null;

  constructor(bus, nodeId) {
    this.#bus = bus;
    this.#nodeId = nodeId;
  }

  setMessageHandler(handler) {
    this.#handler = handler;
    this.#bus.register(this.#nodeId, handler);
  }

  async start() {}

  async stop() { this.#bus.unregister(this.#nodeId); }

  async send(envelope) { await this.#bus.deliver(envelope); }
}

// ---------------------------------------------------------------------------
// PeerNodeClient — protocol session layer (HELLO / DATA / GOODBYE …).
// Identical logic to the Node.js version; uses browser crypto.randomUUID().
// ---------------------------------------------------------------------------
function stripNullish(v) {
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map(stripNullish);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.entries(v)
        .filter(([, val]) => val !== null && val !== undefined)
        .map(([k, val]) => [k, stripNullish(val)])
    );
  }
  return v;
}

class PeerNodeClient {
  constructor({ nodeId = crypto.randomUUID(), protocolVersion = '1.0.0', capabilities, transport, now = () => new Date() }) {
    if (!Array.isArray(capabilities) || capabilities.length === 0) throw new Error('capabilities required');
    if (!transport) throw new Error('transport is required');
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
    this.transport.setMessageHandler(async (env) => this.#handleIncoming(env));
    await this.transport.start();
  }

  async stop() { await this.transport.stop(); this.sessions.clear(); }

  async openSession(targetNodeId = null) {
    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, { targetNodeId, lastReceivedAt: this.now(), nextSequence: 1, connected: false });
    await this.transport.send(this.#buildEnvelope({ messageType: MessageType.HELLO, sessionId, targetNodeId, capabilities: this.capabilities }));
    return sessionId;
  }

  async sendData({ sessionId, body, targetNodeId = null, contentType = 'text/plain', encoding = PayloadEncoding.UTF8 }) {
    await this.transport.send(this.#buildEnvelope({
      messageType: MessageType.DATA, sessionId,
      targetNodeId: targetNodeId ?? this.sessions.get(sessionId)?.targetNodeId ?? null,
      payload: { contentType, encoding, body },
    }));
  }

  async disconnect(sessionId, targetNodeId = null) {
    await this.transport.send(this.#buildEnvelope({
      messageType: MessageType.GOODBYE, sessionId,
      targetNodeId: targetNodeId ?? this.sessions.get(sessionId)?.targetNodeId ?? null,
    }));
    this.sessions.delete(sessionId);
    this.onSessionClosed?.(sessionId);
  }

  async #handleIncoming(envelope) {
    if (!this.sessions.has(envelope.sessionId)) {
      this.sessions.set(envelope.sessionId, {
        targetNodeId: envelope.sourceNodeId,
        lastReceivedAt: envelope.timestamp,
        nextSequence: (envelope.sequence ?? 0) + 1,
        connected: false,
      });
    }
    const state = this.sessions.get(envelope.sessionId);
    state.targetNodeId = envelope.sourceNodeId;
    state.lastReceivedAt = envelope.timestamp;

    switch (envelope.messageType) {
      case MessageType.HELLO:
        state.connected = true;
        this.onSessionOpened?.(envelope.sessionId, envelope.sourceNodeId);
        await this.transport.send(this.#buildEnvelope({
          messageType: MessageType.HELLO_ACK, sessionId: envelope.sessionId,
          targetNodeId: envelope.sourceNodeId, capabilities: this.capabilities,
        }));
        break;
      case MessageType.HELLO_ACK:
        state.connected = true;
        this.onSessionOpened?.(envelope.sessionId, envelope.sourceNodeId);
        break;
      case MessageType.DATA:    this.onData?.(envelope); break;
      case MessageType.ERROR:   this.onFailure?.(envelope); break;
      case MessageType.GOODBYE:
        this.sessions.delete(envelope.sessionId);
        this.onSessionClosed?.(envelope.sessionId);
        break;
      default: break;
    }
  }

  #buildEnvelope({ messageType, sessionId, targetNodeId = null, capabilities = null, payload = null }) {
    return stripNullish({
      protocolVersion: this.protocolVersion,
      messageType, sessionId,
      sourceNodeId: this.nodeId,
      targetNodeId, timestamp: this.now(),
      sequence: this.#nextSeq(sessionId),
      capabilities, payload,
    });
  }

  #nextSeq(sessionId) {
    const s = this.sessions.get(sessionId) ?? { nextSequence: 1 };
    const seq = s.nextSequence;
    s.nextSequence = (s.nextSequence ?? 1) + 1;
    this.sessions.set(sessionId, s);
    return seq;
  }
}

export { SimulationBus, BusPeerTransport, PeerNodeClient, MessageType, PayloadEncoding, Capability };
