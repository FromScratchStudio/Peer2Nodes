// Browser ES-module port of peer-channel.js.
// Uses Web Crypto API (crypto.subtle) instead of Node.js crypto.
// Web Crypto ECDSA returns P1363 (raw R‖S) signatures; since both nodes run in
// the same browser context they are mutually compatible without format conversion.

import { PayloadEncoding } from './peer2nodes-browser.js';

const CT_KEY_EXCHANGE  = 'application/vnd.peer2nodes.key-exchange+json';
const CT_AUTH_RESPONSE = 'application/vnd.peer2nodes.auth-response+json';
const CT_AUTH_CONFIRM  = 'application/vnd.peer2nodes.auth-confirm+json';
const CT_ACK           = 'application/vnd.peer2nodes.ack+json';
const CT_APP           = 'application/vnd.peer2nodes.app+json';

export const ChannelStatus = Object.freeze({
  AUTHENTICATING: 'AUTHENTICATING',
  READY:          'READY',
  CLOSING:        'CLOSING',
  CLOSED:         'CLOSED',
  ERROR:          'ERROR',
});

// ── Binary / base64 helpers ──────────────────────────────────────────────────

function bufToBase64(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBuf(b64) {
  const s = atob(b64);
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b.buffer;
}

function randomBase64(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return bufToBase64(arr);
}

// ── PeerCryptoService ────────────────────────────────────────────────────────

export class PeerCryptoService {
  #identityKeyPair;
  #identityPublicKeyBase64;
  #sessions = new Map(); // sessionId → { sharedKey, remoteIdentityKeyBase64 }

  constructor(kp, pubB64) {
    this.#identityKeyPair = kp;
    this.#identityPublicKeyBase64 = pubB64;
  }

  static async create() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
    return new PeerCryptoService(kp, bufToBase64(spki));
  }

  get identityPublicKeyBase64() { return this.#identityPublicKeyBase64; }

  async generateEphemeralKeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
    return { publicKeyBase64: bufToBase64(spki), privateKey: kp.privateKey };
  }

  async deriveSessionKey(sessionId, localPrivKey, remotePubBase64) {
    const remotePub = await crypto.subtle.importKey(
      'spki', base64ToBuf(remotePubBase64),
      { name: 'ECDH', namedCurve: 'P-256' },
      false, []
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: remotePub }, localPrivKey, 256
    );
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const sessionKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF', hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('peer2nodes-v1'),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
    const entry = this.#sessions.get(sessionId) ?? { sharedKey: null, remoteIdentityKeyBase64: null };
    entry.sharedKey = sessionKey;
    this.#sessions.set(sessionId, entry);
  }

  registerRemoteIdentityKey(sessionId, base64Key) {
    const entry = this.#sessions.get(sessionId) ?? { sharedKey: null, remoteIdentityKeyBase64: null };
    entry.remoteIdentityKeyBase64 = base64Key;
    this.#sessions.set(sessionId, entry);
  }

  async signChallenge(challengeBase64) {
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.#identityKeyPair.privateKey,
      base64ToBuf(challengeBase64)
    );
    return bufToBase64(sig);
  }

  async verifyChallengeSignature(sessionId, challengeBase64, sigBase64) {
    const entry = this.#sessions.get(sessionId);
    if (!entry?.remoteIdentityKeyBase64) return false;
    try {
      const remoteKey = await crypto.subtle.importKey(
        'spki', base64ToBuf(entry.remoteIdentityKeyBase64),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, ['verify']
      );
      return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        remoteKey,
        base64ToBuf(sigBase64),
        base64ToBuf(challengeBase64)
      );
    } catch { return false; }
  }

  async encrypt(sessionId, plaintext) {
    const entry = this.#sessions.get(sessionId);
    if (!entry?.sharedKey) throw new Error(`No session key for ${sessionId}`);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      entry.sharedKey,
      new TextEncoder().encode(plaintext)
    );
    return { ciphertext: bufToBase64(ct), nonce: bufToBase64(nonce) };
  }

  async decrypt(sessionId, ciphertextBase64, nonceBase64) {
    const entry = this.#sessions.get(sessionId);
    if (!entry?.sharedKey) throw new Error(`No session key for ${sessionId}`);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(nonceBase64)) },
      entry.sharedKey,
      base64ToBuf(ciphertextBase64)
    );
    return new TextDecoder().decode(plain);
  }

  clearSession(sessionId) { this.#sessions.delete(sessionId); }
}

// ── OutboundMessageQueue ─────────────────────────────────────────────────────

export class OutboundMessageQueue {
  #pending = new Map();
  #maxRetries;
  #retryIntervalMs;
  #onRetry;
  #onExpired;
  #timer = null;

  constructor({ maxRetries = 3, retryIntervalMs = 5000, onRetry = null, onExpired = null } = {}) {
    this.#maxRetries = maxRetries;
    this.#retryIntervalMs = retryIntervalMs;
    this.#onRetry = onRetry;
    this.#onExpired = onExpired;
  }

  enqueue(messageId, sendFn) {
    return new Promise((resolve, reject) => {
      this.#pending.set(messageId, { sendFn, retries: 0, resolve, reject });
      if (!this.#timer) this.#timer = setInterval(() => this.#tick(), this.#retryIntervalMs);
    });
  }

  acknowledge(messageId) {
    const e = this.#pending.get(messageId);
    if (!e) return;
    e.resolve(messageId);
    this.#pending.delete(messageId);
    if (!this.#pending.size) this.#clearTimer();
  }

  get pendingCount() { return this.#pending.size; }

  stop() {
    this.#clearTimer();
    for (const [id, e] of this.#pending) e.reject(new Error(`Queue stopped before ${id} acked`));
    this.#pending.clear();
  }

  #tick() {
    for (const [id, e] of [...this.#pending]) {
      if (e.retries >= this.#maxRetries) {
        e.reject(new Error(`${id} not acked after ${this.#maxRetries} retries`));
        this.#pending.delete(id);
        this.#onExpired?.(id);
      } else {
        e.retries++;
        e.sendFn().catch(() => {});
        this.#onRetry?.(id, e.retries);
      }
    }
    if (!this.#pending.size) this.#clearTimer();
  }

  #clearTimer() { if (this.#timer) { clearInterval(this.#timer); this.#timer = null; } }
}

// ── PeerChannelManager ───────────────────────────────────────────────────────

export class PeerChannelManager {
  #client;
  #crypto;
  #queue;
  #channels = new Map(); // sessionId → { status, remoteNodeId }
  #pending  = new Map(); // sessionId → handshake state

  onChannelReady        = null; // (sessionId, remoteNodeId) => void
  onMessageReceived     = null; // (sessionId, messageId, plaintext) => void
  onMessageAcknowledged = null; // (sessionId, messageId) => void
  onChannelError        = null; // (reason) => void
  onChannelClosed       = null; // (sessionId) => void

  constructor({ client, cryptoService, queueOptions } = {}) {
    if (!client) throw new Error('client is required');
    if (!cryptoService) throw new Error('cryptoService is required');
    this.#client = client;
    this.#crypto = cryptoService;
    this.#queue  = new OutboundMessageQueue({
      ...queueOptions,
      onExpired: (id) => this.onChannelError?.(`ack_timeout:${id}`),
    });
    this.#client.onSessionOpened = (sid, rid)  => this.#onSessionOpened(sid, rid);
    this.#client.onData          = (env)        => this.#onData(env);
    this.#client.onFailure       = (env)        => this.onChannelError?.(env.error?.message ?? 'transport_error');
    this.#client.onSessionClosed = (sid)        => this.#onSessionClosed(sid);
  }

  get nodeId() { return this.#client.nodeId; }

  async start() { await this.#client.start(); }

  async stop() {
    this.#queue.stop();
    await this.#client.stop();
    this.#channels.clear();
    this.#pending.clear();
  }

  async openChannel(targetNodeId = null) {
    const { publicKeyBase64: ephemeralPub, privateKey: ephemeralPriv } =
      await this.#crypto.generateEphemeralKeyPair();
    const challenge = randomBase64(32);

    // Pre-create settle functions before sendData triggers the inline delivery chain.
    let resolve, reject;
    const channelReady = new Promise((res, rej) => { resolve = res; reject = rej; });

    const sessionId = await this.#client.openSession(targetNodeId);
    this.#channels.set(sessionId, { status: ChannelStatus.AUTHENTICATING, remoteNodeId: targetNodeId });
    this.#pending.set(sessionId, { ephemeralPriv, challenge, resolve, reject, isInitiator: true });

    await this.#client.sendData({
      sessionId,
      body: JSON.stringify({ ephemeralPubKey: ephemeralPub, identityKey: this.#crypto.identityPublicKeyBase64, challenge }),
      contentType: CT_KEY_EXCHANGE,
      encoding: PayloadEncoding.JSON,
    });

    return channelReady;
  }

  async sendMessage(sessionId, plaintext, { requireAck = true } = {}) {
    const ch = this.#channels.get(sessionId);
    if (!ch || ch.status !== ChannelStatus.READY)
      throw new Error(`Channel ${sessionId} not ready (status: ${ch?.status ?? 'none'})`);

    const messageId = crypto.randomUUID();
    const { ciphertext, nonce } = await this.#crypto.encrypt(sessionId, plaintext);

    const sendFn = async () => this.#client.sendData({
      sessionId,
      body: JSON.stringify({ messageId, ciphertext, nonce, requireAck }),
      contentType: CT_APP,
      encoding: PayloadEncoding.JSON,
    });

    await sendFn();
    return requireAck ? this.#queue.enqueue(messageId, sendFn) : messageId;
  }

  async closeChannel(sessionId) {
    const ch = this.#channels.get(sessionId);
    if (!ch) return;
    ch.status = ChannelStatus.CLOSING;
    await this.#client.disconnect(sessionId);
  }

  getChannelStatus(sessionId) { return this.#channels.get(sessionId)?.status ?? null; }

  // ── Internal handlers ──────────────────────────────────────────────────────

  #onSessionOpened(sessionId, remoteNodeId) {
    if (!this.#channels.has(sessionId))
      this.#channels.set(sessionId, { status: ChannelStatus.AUTHENTICATING, remoteNodeId });
  }

  async #onData(envelope) {
    const sid = envelope.sessionId;
    if (!this.#channels.has(sid)) return;
    switch (envelope.payload?.contentType) {
      case CT_KEY_EXCHANGE:  return this.#handleKeyExchange(sid, envelope);
      case CT_AUTH_RESPONSE: return this.#handleAuthResponse(sid, envelope);
      case CT_AUTH_CONFIRM:  return this.#handleAuthConfirm(sid, envelope);
      case CT_ACK:           return this.#handleAck(sid, envelope);
      case CT_APP:           return this.#handleAppMessage(sid, envelope);
    }
  }

  async #handleKeyExchange(sid, envelope) {
    const body = JSON.parse(envelope.payload.body);
    this.#crypto.registerRemoteIdentityKey(sid, body.identityKey);

    const { publicKeyBase64: respPub, privateKey: respPriv } = await this.#crypto.generateEphemeralKeyPair();
    await this.#crypto.deriveSessionKey(sid, respPriv, body.ephemeralPubKey);

    const respChallenge = randomBase64(32);
    const sig = await this.#crypto.signChallenge(body.challenge);

    this.#pending.set(sid, { isInitiator: false, responderChallenge: respChallenge });

    await this.#client.sendData({
      sessionId: sid,
      body: JSON.stringify({
        ephemeralPubKey: respPub,
        identityKey: this.#crypto.identityPublicKeyBase64,
        challenge: respChallenge,
        challengeResponse: sig,
      }),
      contentType: CT_AUTH_RESPONSE,
      encoding: PayloadEncoding.JSON,
    });
  }

  async #handleAuthResponse(sid, envelope) {
    const body    = JSON.parse(envelope.payload.body);
    const pending = this.#pending.get(sid);
    if (!pending?.isInitiator) return;

    this.#crypto.registerRemoteIdentityKey(sid, body.identityKey);

    if (!await this.#crypto.verifyChallengeSignature(sid, pending.challenge, body.challengeResponse)) {
      this.#failChannel(sid, 'auth_failed:invalid_challenge_response');
      return;
    }

    await this.#crypto.deriveSessionKey(sid, pending.ephemeralPriv, body.ephemeralPubKey);

    const confirmSig = await this.#crypto.signChallenge(body.challenge);
    await this.#client.sendData({
      sessionId: sid,
      body: JSON.stringify({ challengeResponse: confirmSig }),
      contentType: CT_AUTH_CONFIRM,
      encoding: PayloadEncoding.JSON,
    });

    this.#setChannelReady(sid);
    pending.resolve(sid);
    this.#pending.delete(sid);
  }

  async #handleAuthConfirm(sid, envelope) {
    const body    = JSON.parse(envelope.payload.body);
    const pending = this.#pending.get(sid);
    if (!pending || pending.isInitiator) return;

    if (!await this.#crypto.verifyChallengeSignature(sid, pending.responderChallenge, body.challengeResponse)) {
      this.#failChannel(sid, 'auth_failed:invalid_auth_confirm');
      return;
    }

    this.#setChannelReady(sid);
    this.#pending.delete(sid);
  }

  async #handleAppMessage(sid, envelope) {
    if (this.#channels.get(sid)?.status !== ChannelStatus.READY) return;
    const body = JSON.parse(envelope.payload.body);
    let plaintext;
    try {
      plaintext = await this.#crypto.decrypt(sid, body.ciphertext, body.nonce);
    } catch {
      this.onChannelError?.(`decrypt_failed:${sid}`);
      return;
    }
    if (body.requireAck) {
      await this.#client.sendData({
        sessionId: sid,
        body: JSON.stringify({ messageId: body.messageId }),
        contentType: CT_ACK,
        encoding: PayloadEncoding.JSON,
      });
    }
    this.onMessageReceived?.(sid, body.messageId, plaintext);
  }

  #handleAck(sid, envelope) {
    const { messageId } = JSON.parse(envelope.payload?.body ?? '{}');
    if (messageId) {
      this.#queue.acknowledge(messageId);
      this.onMessageAcknowledged?.(sid, messageId);
    }
  }

  #setChannelReady(sid) {
    const ch = this.#channels.get(sid);
    if (ch) { ch.status = ChannelStatus.READY; this.onChannelReady?.(sid, ch.remoteNodeId); }
  }

  #failChannel(sid, reason) {
    const ch = this.#channels.get(sid);
    if (ch) ch.status = ChannelStatus.ERROR;
    const pending = this.#pending.get(sid);
    pending?.reject?.(new Error(`Channel auth failed: ${reason}`));
    this.#pending.delete(sid);
    this.#crypto.clearSession(sid);
    this.onChannelError?.(reason);
  }

  #onSessionClosed(sid) {
    const ch = this.#channels.get(sid);
    if (ch) ch.status = ChannelStatus.CLOSED;
    this.#crypto.clearSession(sid);
    this.#pending.delete(sid);
    this.onChannelClosed?.(sid);
  }
}
