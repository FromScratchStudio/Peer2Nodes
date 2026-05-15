'use strict';

const assert = require('node:assert/strict');
const { HttpPollingSignaling, SignalType } = require('./webrtc-p2p');

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

  console.log(`\n${passed + failed} tests — ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
