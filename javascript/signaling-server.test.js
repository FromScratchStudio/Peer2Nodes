'use strict';

const assert = require('node:assert/strict');
const { createSignalingServer } = require('./signaling-server');

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

async function withServer(options, fn) {
  const server = createSignalingServer(options);
  const { host, port } = await server.start();
  const baseUrl = `http://${host}:${port}`;
  try {
    await fn(baseUrl);
  } finally {
    await server.stop();
  }
}

(async () => {
  console.log('SignalingServer');

  await test('supports CORS preflight for allowed origin', async () => {
    await withServer(
      { host: '127.0.0.1', port: 0, corsAllowedOrigins: ['http://example.com'] },
      async (baseUrl) => {
        const response = await fetch(`${baseUrl}/signals/publish`, {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://example.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type'
          }
        });

        assert.equal(response.status, 204);
        assert.equal(response.headers.get('access-control-allow-origin'), 'http://example.com');
      }
    );
  });

  await test('rejects disallowed CORS origin', async () => {
    await withServer(
      { host: '127.0.0.1', port: 0, corsAllowedOrigins: ['http://allowed.example'] },
      async (baseUrl) => {
        const response = await fetch(`${baseUrl}/signals/poll?roomId=r1&nodeId=n1`, {
          headers: { Origin: 'http://blocked.example' }
        });
        assert.equal(response.status, 403);
      }
    );
  });

  await test('rejects payloads larger than configured max body size', async () => {
    await withServer(
      { host: '127.0.0.1', port: 0, maxBodyBytes: 64 },
      async (baseUrl) => {
        const response = await fetch(`${baseUrl}/signals/publish`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            roomId: 'r2',
            sourceNodeId: 'a',
            targetNodeId: 'b',
            type: 'offer',
            sdp: 'x'.repeat(512)
          })
        });
        assert.equal(response.status, 413);
      }
    );
  });

  await test('publish and poll deliver queued signal', async () => {
    await withServer(
      { host: '127.0.0.1', port: 0, pollTimeoutMs: 2_000 },
      async (baseUrl) => {
        const pollPromise = fetch(`${baseUrl}/signals/poll?roomId=r3&nodeId=receiver`).then((response) => response.json());

        await new Promise((resolve) => setTimeout(resolve, 50));

        const publishResponse = await fetch(`${baseUrl}/signals/publish`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            roomId: 'r3',
            sourceNodeId: 'sender',
            targetNodeId: 'receiver',
            type: 'offer',
            sessionId: 's-1',
            sdp: 'dummy-offer'
          })
        });
        assert.equal(publishResponse.status, 202);

        const pollData = await pollPromise;
        assert.equal(Array.isArray(pollData.signals), true);
        assert.equal(pollData.signals.length, 1);
        assert.equal(pollData.signals[0].sourceNodeId, 'sender');
      }
    );
  });

  console.log(`\n${passed + failed} tests — ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
