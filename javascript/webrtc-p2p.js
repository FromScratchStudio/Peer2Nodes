'use strict';

const SignalType = Object.freeze({
  OFFER: 'offer',
  ANSWER: 'answer',
  CANDIDATE: 'candidate'
});

function assertFunction(value, name) {
  if (typeof value !== 'function') {
    throw new Error(`${name} must be a function`);
  }
}

function getFetch(fetchImpl) {
  if (fetchImpl) return fetchImpl;
  if (typeof fetch === 'function') return fetch;
  throw new Error('fetch is required (provide fetchImpl in non-browser environments)');
}

class HttpPollingSignaling {
  #fetch;
  #baseUrl;
  #roomId;
  #nodeId;
  #pollTimeoutMs;
  #stopped = true;
  #onSignal = null;

  constructor({
    baseUrl,
    roomId,
    nodeId,
    pollTimeoutMs = 20_000,
    fetchImpl
  }) {
    if (!baseUrl || typeof baseUrl !== 'string') throw new Error('baseUrl is required');
    if (!roomId || typeof roomId !== 'string') throw new Error('roomId is required');
    if (!nodeId || typeof nodeId !== 'string') throw new Error('nodeId is required');
    this.#baseUrl = baseUrl.replace(/\/+$/, '');
    this.#roomId = roomId;
    this.#nodeId = nodeId;
    this.#pollTimeoutMs = pollTimeoutMs;
    this.#fetch = getFetch(fetchImpl);
  }

  async start(onSignal) {
    assertFunction(onSignal, 'onSignal');
    this.#onSignal = onSignal;
    this.#stopped = false;
    this.#pollLoop().catch(() => {});
  }

  async stop() {
    this.#stopped = true;
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
      try {
        const query = new URLSearchParams({
          roomId: this.#roomId,
          nodeId: this.#nodeId,
          timeoutMs: String(this.#pollTimeoutMs)
        });
        const response = await this.#request(`/signals/poll?${query.toString()}`, { method: 'GET' });
        const signals = Array.isArray(response?.signals) ? response.signals : [];
        for (const signal of signals) {
          if (this.#stopped) break;
          await this.#onSignal?.(signal);
        }
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 800));
      }
    }
  }

  async #request(path, init) {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, init);
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`Signaling request failed (${response.status}): ${text}`);
    }
    if (response.status === 204) return null;
    return response.json();
  }
}

function createPeerConnectionFactory(rtcConfig) {
  if (typeof RTCPeerConnection !== 'function') {
    throw new Error('RTCPeerConnection is unavailable in this environment');
  }
  return () => new RTCPeerConnection(rtcConfig);
}

class WebRTCPeerTransport {
  #nodeId;
  #signaling;
  #createPeerConnection;
  #handler = null;
  #sessionTargets = new Map();
  #peerStates = new Map();

  kind = 'webrtc';

  constructor({
    nodeId,
    signaling,
    rtcConfig = undefined,
    createPeerConnection
  }) {
    if (!nodeId || typeof nodeId !== 'string') throw new Error('nodeId is required');
    if (!signaling || typeof signaling.start !== 'function' || typeof signaling.sendSignal !== 'function') {
      throw new Error('signaling adapter is required');
    }
    this.#nodeId = nodeId;
    this.#signaling = signaling;
    this.#createPeerConnection = createPeerConnection ?? createPeerConnectionFactory(rtcConfig);
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

    const pc = this.#createPeerConnection();
    const state = {
      pc,
      dataChannel: null,
      ready: false,
      pendingMessages: [],
      readyPromise: null,
      readyResolve: null
    };
    state.readyPromise = new Promise((resolve) => { state.readyResolve = resolve; });
    this.#peerStates.set(remoteNodeId, state);

    pc.onicecandidate = async (event) => {
      if (!event.candidate) return;
      await this.#signaling.sendSignal({
        type: SignalType.CANDIDATE,
        targetNodeId: remoteNodeId,
        candidate: event.candidate
      });
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

    channel.onmessage = async (event) => {
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
      await this.#handler(envelope);
    };

    channel.onclose = () => {
      state.ready = false;
      this.#peerStates.delete(remoteNodeId);
    };
  }
}

module.exports = {
  HttpPollingSignaling,
  SignalType,
  WebRTCPeerTransport
};
