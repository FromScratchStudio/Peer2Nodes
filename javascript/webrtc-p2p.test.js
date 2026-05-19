'use strict';

const assert = require('node:assert/strict');
const { HttpPollingSignaling, SignalType, WebRTCPeerTransport } = require('./webrtc-p2p');

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return body; },
    async text() { return JSON.stringify(body); }
  };
}

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (error) {
    console.error(`  ✗ ${name}`);
    console.error(`      ${error.message}`);
    if (process.env.VERBOSE) console.error(error.stack);
    failed++;
  }
}

(async () => {
  console.log('WebRTC P2P');

  await test('HttpPollingSignaling start is idempotent and stop aborts poll loop', async () => {
    let pollCalls = 0;
    let abortSeen = false;
    const errors = [];
    const fetchImpl = async (_url, init = {}) => {
      pollCalls += 1;
      return new Promise((resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          abortSeen = true;
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        }, { once: true });
        setTimeout(() => resolve(jsonResponse({ signals: [] })), 200);
      });
    };

    const signaling = new HttpPollingSignaling({
      baseUrl: 'http://relay.local',
      roomId: 'room-a',
      nodeId: 'node-a',
      fetchImpl,
      onError: (error) => errors.push(error)
    });

    await signaling.start(async () => {});
    await signaling.start(async () => {});
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(pollCalls, 1);
    await signaling.stop();
    assert.equal(abortSeen, true);
    assert.equal(errors.length, 0);
  });

  await test('HttpPollingSignaling sendSignal publishes expected payload', async () => {
    const calls = [];
    const fetchImpl = async (url, init = {}) => {
      calls.push({ url, init });
      return jsonResponse({ accepted: true }, 202);
    };

    const signaling = new HttpPollingSignaling({
      baseUrl: 'http://relay.local/',
      roomId: 'room-b',
      nodeId: 'node-b',
      fetchImpl
    });

    await signaling.sendSignal({
      type: SignalType.OFFER,
      targetNodeId: 'node-c',
      sessionId: 'session-1',
      sdp: 'offer-sdp'
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'http://relay.local/signals/publish');
    const body = JSON.parse(calls[0].init.body);
    assert.equal(body.roomId, 'room-b');
    assert.equal(body.sourceNodeId, 'node-b');
    assert.equal(body.targetNodeId, 'node-c');
    assert.equal(body.type, SignalType.OFFER);
  });

  await test('HttpPollingSignaling poll loop forwards signals to handler', async () => {
    let pollCount = 0;
    const delivered = [];

    const fetchImpl = async (_url, init = {}) => {
      pollCount += 1;
      if (pollCount === 1) {
        return jsonResponse({
          signals: [{ sourceNodeId: 'node-x', targetNodeId: 'node-y', type: SignalType.ANSWER, sdp: 'answer-sdp' }]
        });
      }
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        }, { once: true });
      });
    };

    const signaling = new HttpPollingSignaling({
      baseUrl: 'http://relay.local',
      roomId: 'room-c',
      nodeId: 'node-y',
      fetchImpl
    });

    await signaling.start(async (signal) => delivered.push(signal));
    await new Promise((resolve) => setTimeout(resolve, 20));
    await signaling.stop();

    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].type, SignalType.ANSWER);
  });

  // ── WebRTCPeerTransport tests ─────────────────────────────────────────────

  // Minimal fake DataChannel supporting onopen/onmessage/onclose callbacks.
  function makeFakeChannel() {
    const channel = {
      sent: [],
      onopen: null,
      onmessage: null,
      onclose: null,
      send(payload) { this.sent.push(payload); },
      close() { this.onclose?.(); }
    };
    return channel;
  }

  // Minimal fake RTCPeerConnection.
  function makeFakePc(channel) {
    let iceCandidateHandler = null;
    const pc = {
      localDescription: null,
      onicecandidate: null,
      ondatachannel: null,
      async createOffer() { return { type: 'offer', sdp: 'sdp-offer' }; },
      async setLocalDescription(desc) { pc.localDescription = desc; },
      async setRemoteDescription() {},
      async createAnswer() { return { type: 'answer', sdp: 'sdp-answer' }; },
      async addIceCandidate() {},
      createDataChannel() { return channel; },
      close() {},
      // Helper to fire a fake ICE candidate
      _fireIceCandidate(candidate) { pc.onicecandidate?.({ candidate }); },
      // Helper to simulate remote data channel (responder side)
      _fireDataChannel(ch) { pc.ondatachannel?.({ channel: ch }); }
    };
    return pc;
  }

  // Minimal fake signaling adapter.
  function makeFakeSignaling() {
    const sig = {
      signals: [],
      handler: null,
      async start(onSignal) { this.handler = onSignal; },
      async stop() {},
      async sendSignal(s) { this.signals.push(s); }
    };
    return sig;
  }

  await test('WebRTCPeerTransport initiator creates offer and queues messages until channel opens', async () => {
    const fakeChannel = makeFakeChannel();
    const fakePc = makeFakePc(fakeChannel);
    const signaling = makeFakeSignaling();

    const transport = new WebRTCPeerTransport({
      nodeId: 'node-initiator',
      signaling,
      createPeerConnection: () => fakePc,
      connectionTimeoutMs: 5000
    });

    const received = [];
    transport.setMessageHandler(async (env) => { received.push(env); });
    await transport.start();

    // Kick off send (doesn't resolve until channel opens)
    const sendPromise = transport.send({
      targetNodeId: 'node-responder',
      sessionId: 'sess-1',
      sourceNodeId: 'node-initiator',
      type: 'HELLO'
    });

    // Drain the microtask queue so #ensurePeer (createOffer + sendSignal) completes.
    await new Promise((r) => setTimeout(r, 0));

    // Offer should have been published
    const offerSignal = signaling.signals.find(s => s.type === SignalType.OFFER);
    assert.ok(offerSignal, 'offer should be sent');
    assert.equal(offerSignal.targetNodeId, 'node-responder');

    // Simulate channel opening → pending message should drain
    fakeChannel.onopen?.();
    await sendPromise;

    assert.equal(fakeChannel.sent.length, 1);
    const sent = JSON.parse(fakeChannel.sent[0]);
    assert.equal(sent.type, 'HELLO');
    assert.equal(sent.sessionId, 'sess-1');

    await transport.stop();
  });

  await test('WebRTCPeerTransport responder receives offer and sends answer', async () => {
    const fakeChannel = makeFakeChannel();
    const fakePc = makeFakePc(fakeChannel);
    const signaling = makeFakeSignaling();

    const transport = new WebRTCPeerTransport({
      nodeId: 'node-responder',
      signaling,
      createPeerConnection: () => fakePc,
      connectionTimeoutMs: 5000
    });
    await transport.start();

    // Simulate incoming OFFER from initiator
    await signaling.handler({
      type: SignalType.OFFER,
      sourceNodeId: 'node-initiator',
      targetNodeId: 'node-responder',
      sessionId: 'sess-2',
      sdp: 'sdp-offer'
    });

    const answerSignal = signaling.signals.find(s => s.type === SignalType.ANSWER);
    assert.ok(answerSignal, 'answer should be sent');
    assert.equal(answerSignal.targetNodeId, 'node-initiator');
    assert.equal(answerSignal.sdp, 'sdp-answer');

    await transport.stop();
  });

  await test('WebRTCPeerTransport forwards ICE candidates via signaling', async () => {
    const fakeChannel = makeFakeChannel();
    const fakePc = makeFakePc(fakeChannel);
    const signaling = makeFakeSignaling();

    const transport = new WebRTCPeerTransport({
      nodeId: 'node-a',
      signaling,
      createPeerConnection: () => fakePc,
      connectionTimeoutMs: 5000
    });
    await transport.start();

    // Start connection (creates PC + sets up onicecandidate)
    const sendPromise = transport.send({
      targetNodeId: 'node-b',
      sessionId: 'sess-3',
      sourceNodeId: 'node-a',
      type: 'HELLO'
    });

    // Fire a fake ICE candidate
    fakePc._fireIceCandidate({ candidate: 'ice-candidate-data' });
    await new Promise((r) => setTimeout(r, 0)); // let microtask settle

    const candidateSignal = signaling.signals.find(s => s.type === SignalType.CANDIDATE);
    assert.ok(candidateSignal, 'candidate signal should be sent');
    assert.equal(candidateSignal.targetNodeId, 'node-b');

    fakeChannel.onopen?.();
    await sendPromise;
    await transport.stop();
  });

  await test('WebRTCPeerTransport receives messages and invokes handler', async () => {
    const fakeChannel = makeFakeChannel();
    const fakePc = makeFakePc(fakeChannel);
    const signaling = makeFakeSignaling();

    const received = [];
    const transport = new WebRTCPeerTransport({
      nodeId: 'node-recv',
      signaling,
      createPeerConnection: () => fakePc,
      connectionTimeoutMs: 5000
    });
    transport.setMessageHandler(async (env) => { received.push(env); });
    await transport.start();

    // Simulate responder path: incoming offer triggers ondatachannel indirectly;
    // here we manually attach a channel via the ondatachannel event.
    await signaling.handler({
      type: SignalType.OFFER,
      sourceNodeId: 'node-sender',
      targetNodeId: 'node-recv',
      sessionId: 'sess-4',
      sdp: 'sdp-offer'
    });
    fakePc._fireDataChannel(fakeChannel);
    fakeChannel.onopen?.();

    const msg = JSON.stringify({ sessionId: 'sess-4', sourceNodeId: 'node-sender', type: 'DATA' });
    fakeChannel.onmessage?.({ data: msg });
    await new Promise((r) => setTimeout(r, 0));

    assert.equal(received.length, 1);
    assert.equal(received[0].sessionId, 'sess-4');

    await transport.stop();
  });

  await test('WebRTCPeerTransport connection timeout rejects send', async () => {
    const fakeChannel = makeFakeChannel(); // onopen never called
    const fakePc = makeFakePc(fakeChannel);
    const signaling = makeFakeSignaling();

    const transport = new WebRTCPeerTransport({
      nodeId: 'node-timeout',
      signaling,
      createPeerConnection: () => fakePc,
      connectionTimeoutMs: 50 // very short for test
    });
    await transport.start();

    await assert.rejects(
      () => transport.send({ targetNodeId: 'node-far', sessionId: 'sess-5', sourceNodeId: 'node-timeout', type: 'HELLO' }),
      /timed out/
    );
    await transport.stop();
  });

  await test('WebRTCPeerTransport message handler error is routed to onTransportError', async () => {
    const fakeChannel = makeFakeChannel();
    const fakePc = makeFakePc(fakeChannel);
    const signaling = makeFakeSignaling();
    const transportErrors = [];

    const transport = new WebRTCPeerTransport({
      nodeId: 'node-err',
      signaling,
      createPeerConnection: () => fakePc,
      connectionTimeoutMs: 5000,
      onTransportError: (e) => transportErrors.push(e)
    });
    transport.setMessageHandler(async () => { throw new Error('handler failure'); });
    await transport.start();

    // Establish a responder-side channel
    await signaling.handler({
      type: SignalType.OFFER,
      sourceNodeId: 'node-other',
      targetNodeId: 'node-err',
      sessionId: 'sess-6',
      sdp: 'sdp-offer'
    });
    fakePc._fireDataChannel(fakeChannel);
    fakeChannel.onopen?.();

    const msg = JSON.stringify({ sessionId: 'sess-6', sourceNodeId: 'node-other', type: 'DATA' });
    fakeChannel.onmessage?.({ data: msg });
    await new Promise((r) => setTimeout(r, 10));

    assert.equal(transportErrors.length, 1);
    assert.equal(transportErrors[0].message, 'handler failure');

    await transport.stop();
  });

  console.log(`\n${passed + failed} tests — ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
