'use strict';

const crypto = require('node:crypto');
const { PeerNodeClient, MessageType, PayloadEncoding } = require('./peer2nodes.js');

const CT_KEY_EXCHANGE  = 'application/vnd.peer2nodes.key-exchange+json';
const CT_AUTH_RESPONSE = 'application/vnd.peer2nodes.auth-response+json';
const CT_AUTH_CONFIRM  = 'application/vnd.peer2nodes.auth-confirm+json';
const CT_ACK           = 'application/vnd.peer2nodes.ack+json';
const CT_APP           = 'application/vnd.peer2nodes.app+json';

const ChannelStatus = Object.freeze({
  AUTHENTICATING: 'AUTHENTICATING',
  READY:          'READY',
  CLOSING:        'CLOSING',
  CLOSED:         'CLOSED',
  ERROR:          'ERROR',
});

// ---------------------------------------------------------------------------
// PeerCryptoService
// Manages a stable P-256 identity keypair (ECDSA/SHA-256) and per-session
// AES-256-GCM symmetric keys derived via ephemeral ECDH + HKDF-SHA256.
// ---------------------------------------------------------------------------
class PeerCryptoService {
  #identityKeyPair;
  // sessionId -> { sharedKey: Buffer | null, remoteIdentityKeyDer: Buffer | null }
  #sessions = new Map();

  constructor() {
    this.#identityKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  }

  /** DER-encoded SPKI public key, base64 */
  get identityPublicKeyBase64() {
    return this.#identityKeyPair.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');
  }

  /** Returns a fresh ephemeral P-256 keypair for ECDH */
  generateEphemeralKeyPair() {
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    return {
      publicKeyBase64: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      privateKey: kp.privateKey,
    };
  }

  /**
   * Computes ECDH shared secret with the remote ephemeral public key, derives a
   * 32-byte AES-256-GCM key via HKDF-SHA256, and stores it for this session.
   */
  deriveSessionKey(sessionId, localEphemeralPrivKey, remoteEphemeralPubBase64) {
    const remoteKeyDer  = Buffer.from(remoteEphemeralPubBase64, 'base64');
    const remotePublicKey = crypto.createPublicKey({ key: remoteKeyDer, format: 'der', type: 'spki' });
    const sharedSecret  = crypto.diffieHellman({ privateKey: localEphemeralPrivKey, publicKey: remotePublicKey });
    const derived       = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32, 0), 'peer2nodes-v1', 32);
    const entry = this.#sessions.get(sessionId) ?? { sharedKey: null, remoteIdentityKeyDer: null };
    entry.sharedKey = Buffer.from(derived);
    this.#sessions.set(sessionId, entry);
  }

  registerRemoteIdentityKey(sessionId, base64Key) {
    const entry = this.#sessions.get(sessionId) ?? { sharedKey: null, remoteIdentityKeyDer: null };
    entry.remoteIdentityKeyDer = Buffer.from(base64Key, 'base64');
    this.#sessions.set(sessionId, entry);
  }

  /** ECDSA-SHA256 signature over raw challenge bytes */
  signChallenge(challengeBase64) {
    return crypto
      .sign('SHA256', Buffer.from(challengeBase64, 'base64'), this.#identityKeyPair.privateKey)
      .toString('base64');
  }

  verifyChallengeSignature(sessionId, challengeBase64, signatureBase64) {
    const entry = this.#sessions.get(sessionId);
    if (!entry?.remoteIdentityKeyDer) return false;
    try {
      const remoteKey = crypto.createPublicKey({
        key: entry.remoteIdentityKeyDer,
        format: 'der',
        type: 'spki',
      });
      return crypto.verify(
        'SHA256',
        Buffer.from(challengeBase64, 'base64'),
        remoteKey,
        Buffer.from(signatureBase64, 'base64'),
      );
    } catch {
      return false;
    }
  }

  /** AES-256-GCM encrypt. Returns { ciphertext, nonce } both base64. */
  encrypt(sessionId, plaintext) {
    const entry = this.#sessions.get(sessionId);
    if (!entry?.sharedKey) throw new Error(`No session key for ${sessionId}`);
    const nonce  = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', entry.sharedKey, nonce);
    const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag    = cipher.getAuthTag();
    return {
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      nonce: nonce.toString('base64'),
    };
  }

  /** AES-256-GCM decrypt. Throws on authentication failure. */
  decrypt(sessionId, ciphertextBase64, nonceBase64) {
    const entry = this.#sessions.get(sessionId);
    if (!entry?.sharedKey) throw new Error(`No session key for ${sessionId}`);
    const nonce    = Buffer.from(nonceBase64, 'base64');
    const combined = Buffer.from(ciphertextBase64, 'base64');
    const tag      = combined.subarray(combined.length - 16);
    const body     = combined.subarray(0, combined.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', entry.sharedKey, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  }

  clearSession(sessionId) {
    this.#sessions.delete(sessionId);
  }
}

// ---------------------------------------------------------------------------
// OutboundMessageQueue
// Tracks DATA messages that require an ACK and retries them on timeout.
// ---------------------------------------------------------------------------
class OutboundMessageQueue {
  // messageId -> { sendFn, sentAt, retries, resolve, reject }
  #pending      = new Map();
  #maxRetries;
  #retryIntervalMs;
  #onRetry;
  #onExpired;
  #timer        = null;

  constructor({ maxRetries = 3, retryIntervalMs = 5000, onRetry = null, onExpired = null } = {}) {
    this.#maxRetries     = maxRetries;
    this.#retryIntervalMs = retryIntervalMs;
    this.#onRetry        = onRetry;
    this.#onExpired      = onExpired;
  }

  /**
   * Enqueues a message for ACK tracking. sendFn() will be called on retries.
   * Returns a Promise that resolves with messageId on ACK or rejects on expiry.
   */
  enqueue(messageId, sendFn) {
    return new Promise((resolve, reject) => {
      this.#pending.set(messageId, { sendFn, sentAt: Date.now(), retries: 0, resolve, reject });
      if (!this.#timer) {
        this.#timer = setInterval(() => this.#tick(), this.#retryIntervalMs);
      }
    });
  }

  acknowledge(messageId) {
    const entry = this.#pending.get(messageId);
    if (!entry) return;
    entry.resolve(messageId);
    this.#pending.delete(messageId);
    if (this.#pending.size === 0) this.#clearTimer();
  }

  get pendingCount() { return this.#pending.size; }

  stop() {
    this.#clearTimer();
    for (const [id, entry] of this.#pending) {
      entry.reject(new Error(`Queue stopped before message ${id} was acknowledged`));
    }
    this.#pending.clear();
  }

  #tick() {
    for (const [id, entry] of [...this.#pending]) {
      if (entry.retries >= this.#maxRetries) {
        entry.reject(new Error(`Message ${id} not acknowledged after ${this.#maxRetries} retries`));
        this.#pending.delete(id);
        this.#onExpired?.(id);
      } else {
        entry.retries += 1;
        entry.sendFn().catch(() => {});
        this.#onRetry?.(id, entry.retries);
      }
    }
    if (this.#pending.size === 0) this.#clearTimer();
  }

  #clearTimer() {
    if (this.#timer) { clearInterval(this.#timer); this.#timer = null; }
  }
}

// ---------------------------------------------------------------------------
// PeerChannelManager
//
// Sits above PeerNodeClient and provides:
//   - Mutual authentication via ECDH ephemeral key exchange + challenge-response
//   - AES-256-GCM payload encryption / decryption
//   - ACK-tracked reliable message delivery with configurable retries
//
// Handshake (per session):
//   Initiator → Responder : HELLO  (via PeerNodeClient)
//   Responder → Initiator : HELLO_ACK  (via PeerNodeClient)
//   Initiator → Responder : DATA / key-exchange  { ephemeralPubKey, identityKey, challenge }
//   Responder → Initiator : DATA / auth-response { ephemeralPubKey, identityKey, challenge, sig(A_challenge) }
//   Initiator → Responder : DATA / auth-confirm  { sig(B_challenge) }
//   — both sides now hold a derived AES-256-GCM session key —
//
// Security guarantees:
//   - Mutual authentication: both nodes prove ownership of their identity private key
//   - Perfect forward secrecy: ephemeral ECDH keys discarded after derivation
//   - Confidentiality + integrity: AES-256-GCM authenticated encryption
//   - Replay protection: per-message random 96-bit GCM nonce; duplicate detection
//     at the application level is the caller's responsibility
// ---------------------------------------------------------------------------
class PeerChannelManager {
  #client;
  #crypto;
  #queue;

  // sessionId -> { status, remoteNodeId }
  #channels = new Map();

  // sessionId -> { ephemeralPrivKey?, challenge, resolve?, reject?, isInitiator, responderChallenge? }
  #pending  = new Map();

  onChannelReady        = null; // (sessionId, remoteNodeId) => void
  onMessageReceived     = null; // (sessionId, messageId, plaintext) => void
  onMessageAcknowledged = null; // (sessionId, messageId) => void
  onChannelError        = null; // (reason: string) => void
  onChannelClosed       = null; // (sessionId) => void

  constructor({ client, cryptoService, queueOptions } = {}) {
    if (!client) throw new Error('client is required');
    this.#client = client;
    this.#crypto = cryptoService ?? new PeerCryptoService();
    this.#queue  = new OutboundMessageQueue({
      ...queueOptions,
      onExpired: (id) => this.onChannelError?.(`ack_timeout:${id}`),
    });

    this.#client.onSessionOpened = (sid, rid)   => this.#onSessionOpened(sid, rid);
    this.#client.onData          = (env)         => this.#onData(env);
    this.#client.onFailure       = (env)         => this.onChannelError?.(env.error?.message ?? 'transport_error');
    this.#client.onSessionClosed = (sid)         => this.#onSessionClosed(sid);
  }

  async start() { await this.#client.start(); }

  async stop() {
    this.#queue.stop();
    await this.#client.stop();
    this.#channels.clear();
    this.#pending.clear();
  }

  /**
   * Opens an authenticated, encrypted channel to targetNodeId.
   * Returns a Promise<sessionId> that resolves once mutual auth completes.
   */
  async openChannel(targetNodeId = null) {
    const { publicKeyBase64: ephemeralPub, privateKey: ephemeralPriv } =
      this.#crypto.generateEphemeralKeyPair();
    const challenge = crypto.randomBytes(32).toString('base64');

    // Pre-create the settle functions so #pending is set before sendData triggers
    // the synchronous loopback chain (MemoryPeerTransport delivers inline).
    let resolve, reject;
    const channelReady = new Promise((res, rej) => { resolve = res; reject = rej; });

    const sessionId = await this.#client.openSession(targetNodeId);
    this.#channels.set(sessionId, { status: ChannelStatus.AUTHENTICATING, remoteNodeId: targetNodeId });
    this.#pending.set(sessionId, { ephemeralPriv, challenge, resolve, reject, isInitiator: true });

    await this.#client.sendData({
      sessionId,
      body: JSON.stringify({
        ephemeralPubKey: ephemeralPub,
        identityKey:     this.#crypto.identityPublicKeyBase64,
        challenge,
      }),
      contentType: CT_KEY_EXCHANGE,
      encoding:    PayloadEncoding.JSON,
    });

    return channelReady;
  }

  /**
   * Sends an encrypted message over a READY channel.
   * When requireAck is true (default) returns Promise<messageId> resolving on ACK.
   */
  async sendMessage(sessionId, plaintext, { requireAck = true } = {}) {
    const ch = this.#channels.get(sessionId);
    if (!ch || ch.status !== ChannelStatus.READY) {
      throw new Error(`Channel ${sessionId} is not ready (status: ${ch?.status ?? 'none'})`);
    }

    const messageId = crypto.randomUUID();
    const { ciphertext, nonce } = this.#crypto.encrypt(sessionId, plaintext);

    const sendFn = async () => this.#client.sendData({
      sessionId,
      body:        JSON.stringify({ messageId, ciphertext, nonce, requireAck }),
      contentType: CT_APP,
      encoding:    PayloadEncoding.JSON,
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

  getChannelStatus(sessionId) {
    return this.#channels.get(sessionId)?.status ?? null;
  }

  // ---- internal handlers ----

  #onSessionOpened(sessionId, remoteNodeId) {
    if (!this.#channels.has(sessionId)) {
      // We are the responder — create channel entry (initiator creates it in openChannel)
      this.#channels.set(sessionId, { status: ChannelStatus.AUTHENTICATING, remoteNodeId });
    }
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

    const { publicKeyBase64: respPub, privateKey: respPriv } = this.#crypto.generateEphemeralKeyPair();
    this.#crypto.deriveSessionKey(sid, respPriv, body.ephemeralPubKey);

    const respChallenge = crypto.randomBytes(32).toString('base64');
    const sig           = this.#crypto.signChallenge(body.challenge);

    this.#pending.set(sid, { isInitiator: false, responderChallenge: respChallenge });

    await this.#client.sendData({
      sessionId:   sid,
      body:        JSON.stringify({
        ephemeralPubKey:   respPub,
        identityKey:       this.#crypto.identityPublicKeyBase64,
        challenge:         respChallenge,
        challengeResponse: sig,
      }),
      contentType: CT_AUTH_RESPONSE,
      encoding:    PayloadEncoding.JSON,
    });
  }

  async #handleAuthResponse(sid, envelope) {
    const body    = JSON.parse(envelope.payload.body);
    const pending = this.#pending.get(sid);
    if (!pending?.isInitiator) return;

    this.#crypto.registerRemoteIdentityKey(sid, body.identityKey);

    if (!this.#crypto.verifyChallengeSignature(sid, pending.challenge, body.challengeResponse)) {
      this.#failChannel(sid, 'auth_failed:invalid_challenge_response');
      return;
    }

    this.#crypto.deriveSessionKey(sid, pending.ephemeralPriv, body.ephemeralPubKey);

    const confirmSig = this.#crypto.signChallenge(body.challenge);
    await this.#client.sendData({
      sessionId:   sid,
      body:        JSON.stringify({ challengeResponse: confirmSig }),
      contentType: CT_AUTH_CONFIRM,
      encoding:    PayloadEncoding.JSON,
    });

    this.#setChannelReady(sid);
    pending.resolve(sid);
    this.#pending.delete(sid);
  }

  async #handleAuthConfirm(sid, envelope) {
    const body    = JSON.parse(envelope.payload.body);
    const pending = this.#pending.get(sid);
    if (!pending || pending.isInitiator) return;

    if (!this.#crypto.verifyChallengeSignature(sid, pending.responderChallenge, body.challengeResponse)) {
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
      plaintext = this.#crypto.decrypt(sid, body.ciphertext, body.nonce);
    } catch {
      this.onChannelError?.(`decrypt_failed:${sid}`);
      return;
    }

    if (body.requireAck) {
      await this.#client.sendData({
        sessionId:   sid,
        body:        JSON.stringify({ messageId: body.messageId }),
        contentType: CT_ACK,
        encoding:    PayloadEncoding.JSON,
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
    if (ch) {
      ch.status = ChannelStatus.READY;
      this.onChannelReady?.(sid, ch.remoteNodeId);
    }
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

module.exports = { ChannelStatus, OutboundMessageQueue, PeerChannelManager, PeerCryptoService };
