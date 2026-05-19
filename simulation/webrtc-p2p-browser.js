// Browser ES-module port of javascript/webrtc-p2p.js
// Uses browser globals: fetch (global), RTCPeerConnection (global).
// Additional: connectionTimeoutMs option on WebRTCPeerTransport (default 30 s).

const SignalType = Object.freeze({
  OFFER: 'offer',
  ANSWER: 'answer',
  CANDIDATE: 'candidate'
});

const DEFAULT_POLL_TIMEOUT_MS = 20_000;
const MIN_POLL_TIMEOUT_MS = 1_000;
const MAX_POLL_TIMEOUT_MS = 120_000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 30_000;
const SLASH_CHAR_CODE = 47;

function assertFunction(value, name) {
  if (typeof value !== 'function') {
    throw new Error(`${name} must be a function`);
  }
}

function trimTrailingSlashes(value) {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === SLASH_CHAR_CODE) end -= 1;
  return value.slice(0, end);
}

function normalizeTimeoutMs(value, fallbackMs = DEFAULT_POLL_TIMEOUT_MS) {
  const parsed = Number(value);
  const timeoutMs = Number.isFinite(parsed) ? parsed : fallbackMs;
  return Math.max(MIN_POLL_TIMEOUT_MS, Math.min(timeoutMs, MAX_POLL_TIMEOUT_MS));
}

function isAbortError(error) {
  return error?.name === 'AbortError';
}

class HttpPollingSignaling {
  #baseUrl;
  #roomId;
  #nodeId;
  #pollTimeoutMs;
  #stopped = true;
  #onSignal = null;
  #onError = null;
  #pollPromise = null;
  #pollAbortController = null;

  constructor({
    baseUrl,
    roomId,
    nodeId,
    pollTimeoutMs = DEFAULT_POLL_TIMEOUT_MS,
    onError = null
  }) {
    if (!baseUrl || typeof baseUrl !== 'string') throw new Error('baseUrl is required');
    if (!roomId || typeof roomId !== 'string') throw new Error('roomId is required');
    if (!nodeId || typeof nodeId !== 'string') throw new Error('nodeId is required');
    this.#baseUrl = trimTrailingSlashes(baseUrl);
    this.#roomId = roomId;
    this.#nodeId = nodeId;
    this.#pollTimeoutMs = normalizeTimeoutMs(pollTimeoutMs);
    this.#onError = typeof onError === 'function' ? onError : null;
  }

  async start(onSignal) {
    assertFunction(onSignal, 'onSignal');
    if (this.#pollPromise) return;
    this.#onSignal = onSignal;
    this.#stopped = false;
    this.#pollPromise = this.#pollLoop()
      .catch((error) => {
        this.#onError?.(error);
      })
      .finally(() => {
        this.#pollPromise = null;
        this.#pollAbortController = null;
        this.#stopped = true;
      });
  }

  async stop() {
    this.#stopped = true;
    this.#pollAbortController?.abort();
    await this.#pollPromise;
  }

  async sendSignal(signal) {
    if (!signal || typeof signal !== 'object') throw new Error('signal is required');
    if (!signal.targetNodeId) throw new Error('signal.targetNodeId is required');
    if (!Object.values(SignalType).includes(signal.type)) {
      throw new Error(`Unsupported signal type: ${signal.type}`);
    }

    await this.#request('/signals/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        roomId: this.#roomId,
        sourceNodeId: this.#nodeId,
        targetNodeId: signal.targetNodeId,
        sessionId: signal.sessionId ?? null,
        type: signal.type,
        sdp: signal.sdp ?? null,
        candidate: signal.candidate ?? null
      })
    });
  }

  async #pollLoop() {
    while (!this.#stopped) {
      this.#pollAbortController = new AbortController();
      try {
        const query = new URLSearchParams({
          roomId: this.#roomId,
          nodeId: this.#nodeId,
          timeoutMs: String(this.#pollTimeoutMs)
        });
        const response = await this.#request(`/signals/poll?${query.toString()}`, {
          method: 'GET',
          signal: this.#pollAbortController.signal
        });
        const signals = Array.isArray(response?.signals) ? response.signals : [];
        for (const signal of signals) {
          if (this.#stopped) break;
          await this.#onSignal?.(signal);
        }
      } catch (error) {
        if (this.#stopped && isAbortError(error)) break;
        this.#onError?.(error);
        await new Promise((resolve) => setTimeout(resolve, 800));
      }
    }
  }

  async #request(path, init) {
    const response = await fetch(`${this.#baseUrl}${path}`, init);
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`Signaling request failed (${response.status}): ${text}`);
    }
    if (response.status === 204) return null;
    return response.json();
  }
}

class WebRTCPeerTransport {
  #nodeId;
  #signaling;
  #rtcConfig;
  #connectionTimeoutMs;
  #onTransportError;
  #handler = null;
  #sessionTargets = new Map();
  #peerStates = new Map();

  kind = 'webrtc';

  constructor({
    nodeId,
    signaling,
    rtcConfig = undefined,
    connectionTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS,
    onTransportError = null
  }) {
    if (!nodeId || typeof nodeId !== 'string') throw new Error('nodeId is required');
    if (!signaling || typeof signaling.start !== 'function' || typeof signaling.sendSignal !== 'function') {
      throw new Error('signaling adapter is required');
    }
    this.#nodeId = nodeId;
    this.#signaling = signaling;
    this.#rtcConfig = rtcConfig;
    this.#connectionTimeoutMs = Number.isFinite(connectionTimeoutMs) && connectionTimeoutMs > 0
      ? connectionTimeoutMs
      : DEFAULT_CONNECTION_TIMEOUT_MS;
    this.#onTransportError = typeof onTransportError === 'function' ? onTransportError : null;
  }

  setMessageHandler(handler) {
    this.#handler = handler;
  }

  async start() {
    await this.#signaling.start(async (signal) => {
      await this.#handleSignal(signal);
    });
  }

  async stop() {
    for (const state of this.#peerStates.values()) {
      clearTimeout(state.timeoutId);
      state.dataChannel?.close();
      state.pc.close();
    }
    this.#peerStates.clear();
    await this.#signaling.stop?.();
  }

  async send(envelope) {
    const targetNodeId = envelope?.targetNodeId ?? this.#sessionTargets.get(envelope?.sessionId);
    if (!targetNodeId) throw new Error('targetNodeId is required to send over WebRTC');
    if (envelope?.sessionId) this.#sessionTargets.set(envelope.sessionId, targetNodeId);
    const state = await this.#ensurePeer(targetNodeId, { initiator: true });
    const payload = JSON.stringify(envelope);

    if (state.ready) {
      state.dataChannel.send(payload);
      return;
    }

    state.pendingMessages.push(payload);
    await state.readyPromise;
  }

  async #handleSignal(signal) {
    if (!signal || signal.targetNodeId !== this.#nodeId || !signal.sourceNodeId) return;
    if (!Object.values(SignalType).includes(signal.type)) return;
    if (signal.sessionId && !this.#sessionTargets.has(signal.sessionId)) {
      this.#sessionTargets.set(signal.sessionId, signal.sourceNodeId);
    }

    const state = await this.#ensurePeer(signal.sourceNodeId, { initiator: false });
    const pc = state.pc;

    if (signal.type === SignalType.OFFER) {
      await pc.setRemoteDescription({ type: 'offer', sdp: signal.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await this.#signaling.sendSignal({
        type: SignalType.ANSWER,
        targetNodeId: signal.sourceNodeId,
        sessionId: signal.sessionId,
        sdp: answer.sdp
      });
      return;
    }

    if (signal.type === SignalType.ANSWER) {
      await pc.setRemoteDescription({ type: 'answer', sdp: signal.sdp });
      return;
    }

    if (signal.type === SignalType.CANDIDATE && signal.candidate) {
      await pc.addIceCandidate(signal.candidate);
    }
  }

  async #ensurePeer(remoteNodeId, { initiator }) {
    if (this.#peerStates.has(remoteNodeId)) return this.#peerStates.get(remoteNodeId);

    const pc = new RTCPeerConnection(this.#rtcConfig);
    const state = {
      pc,
      dataChannel: null,
      ready: false,
      pendingMessages: [],
      readyPromise: null,
      readyResolve: null,
      timeoutId: null
    };

    // Build the ready promise, racing against a connection timeout.
    const innerPromise = new Promise((resolve) => { state.readyResolve = resolve; });
    state.readyPromise = new Promise((resolve, reject) => {
      state.timeoutId = setTimeout(() => {
        this.#peerStates.delete(remoteNodeId);
        pc.close();
        const shortRemote = remoteNodeId.length > 8 ? `${remoteNodeId.slice(0, 8)}…` : remoteNodeId;
        reject(new Error(`WebRTC connection to ${shortRemote} timed out`));
      }, this.#connectionTimeoutMs);
      innerPromise.then(() => {
        clearTimeout(state.timeoutId);
        resolve();
      }).catch(reject);
    });

    this.#peerStates.set(remoteNodeId, state);

    // ICE candidate callback must NOT be async — unhandled rejections escape event callbacks.
    pc.onicecandidate = (event) => {
      if (!event.candidate) return;
      this.#signaling.sendSignal({
        type: SignalType.CANDIDATE,
        targetNodeId: remoteNodeId,
        candidate: event.candidate
      }).catch((error) => this.#onTransportError?.(error));
    };

    pc.ondatachannel = (event) => {
      this.#attachDataChannel(remoteNodeId, state, event.channel);
    };

    if (initiator) {
      const channel = pc.createDataChannel('peer2nodes');
      this.#attachDataChannel(remoteNodeId, state, channel);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await this.#signaling.sendSignal({
        type: SignalType.OFFER,
        targetNodeId: remoteNodeId,
        sdp: offer.sdp
      });
    }

    return state;
  }

  #attachDataChannel(remoteNodeId, state, channel) {
    state.dataChannel = channel;

    channel.onopen = () => {
      state.ready = true;
      state.readyResolve();
      while (state.pendingMessages.length) {
        const payload = state.pendingMessages.shift();
        channel.send(payload);
      }
    };

    // onmessage must NOT be async — unhandled rejections escape event callbacks.
    channel.onmessage = (event) => {
      if (!this.#handler || typeof event?.data !== 'string') return;
      let envelope;
      try {
        envelope = JSON.parse(event.data);
      } catch {
        return;
      }
      if (envelope?.sessionId && envelope?.sourceNodeId) {
        this.#sessionTargets.set(envelope.sessionId, envelope.sourceNodeId);
      }
      Promise.resolve(this.#handler(envelope)).catch((error) => this.#onTransportError?.(error));
    };

    channel.onclose = () => {
      state.ready = false;
      clearTimeout(state.timeoutId);
      this.#peerStates.delete(remoteNodeId);
    };
  }
}

export { HttpPollingSignaling, SignalType, WebRTCPeerTransport };
