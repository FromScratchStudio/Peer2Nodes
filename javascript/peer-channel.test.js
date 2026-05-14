'use strict';

const assert     = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { PeerNodeClient, MemoryPeerTransport, Capability, PayloadEncoding } = require('./peer2nodes.js');
const { ChannelStatus, OutboundMessageQueue, PeerChannelManager, PeerCryptoService } = require('./peer-channel.js');

(async () => {

// ---- helpers ---------------------------------------------------------------

let passed = 0;
let failed = 0;

async function test(suite, name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${suite} — ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${suite} — ${name}`);
    console.error(`      ${err.message}`);
    if (process.env.VERBOSE) console.error(err.stack);
    failed++;
  }
}

/** Lets the async message chain settle in MemoryPeerTransport. */
function settle(n = 20) {
  return new Promise(res => {
    let i = 0;
    const tick = () => (++i >= n ? res() : setImmediate(tick));
    setImmediate(tick);
  });
}

function makePair(caps = [Capability.END_TO_END_ENCRYPTION]) {
  const tA = new MemoryPeerTransport();
  const tB = new MemoryPeerTransport();
  tA.connect(tB);
  tB.connect(tA);

  const clientA = new PeerNodeClient({ capabilities: caps, transport: tA });
  const clientB = new PeerNodeClient({ capabilities: caps, transport: tB });
  const managerA = new PeerChannelManager({ client: clientA });
  const managerB = new PeerChannelManager({ client: clientB });

  return { managerA, managerB, clientA, clientB, tA, tB };
}

// ---- PeerCryptoService -----------------------------------------------------

await test('PeerCryptoService', 'identity key is stable across calls', () => {
  const svc = new PeerCryptoService();
  assert.equal(svc.identityPublicKeyBase64, svc.identityPublicKeyBase64);
  assert.ok(Buffer.from(svc.identityPublicKeyBase64, 'base64').length > 50);
});

await test('PeerCryptoService', 'ephemeral keypairs are distinct', () => {
  const svc = new PeerCryptoService();
  const a   = svc.generateEphemeralKeyPair();
  const b   = svc.generateEphemeralKeyPair();
  assert.notEqual(a.publicKeyBase64, b.publicKeyBase64);
});

await test('PeerCryptoService', 'two services derive the same session key (encrypt/decrypt round-trip)', () => {
  const svcA = new PeerCryptoService();
  const svcB = new PeerCryptoService();
  const kpA  = svcA.generateEphemeralKeyPair();
  const kpB  = svcB.generateEphemeralKeyPair();
  svcA.deriveSessionKey('s1', kpA.privateKey, kpB.publicKeyBase64);
  svcB.deriveSessionKey('s1', kpB.privateKey, kpA.publicKeyBase64);

  const { ciphertext, nonce } = svcA.encrypt('s1', 'hello cross-key');
  assert.equal(svcB.decrypt('s1', ciphertext, nonce), 'hello cross-key');
});

await test('PeerCryptoService', 'GCM tag mismatch throws on decrypt', () => {
  const svcA = new PeerCryptoService();
  const svcB = new PeerCryptoService();
  const kpA  = svcA.generateEphemeralKeyPair();
  const kpB  = svcB.generateEphemeralKeyPair();
  svcA.deriveSessionKey('s1', kpA.privateKey, kpB.publicKeyBase64);
  svcB.deriveSessionKey('s1', kpB.privateKey, kpA.publicKeyBase64);

  const { ciphertext, nonce } = svcA.encrypt('s1', 'secret');
  const tampered = Buffer.from(ciphertext, 'base64');
  tampered[0] ^= 0xff; // flip first byte
  assert.throws(() => svcB.decrypt('s1', tampered.toString('base64'), nonce));
});

await test('PeerCryptoService', 'sign + verify round-trip succeeds', () => {
  const svcA = new PeerCryptoService();
  const svcB = new PeerCryptoService();
  const challenge = nodeCrypto.randomBytes(32).toString('base64');
  const sig       = svcA.signChallenge(challenge);

  svcB.registerRemoteIdentityKey('s1', svcA.identityPublicKeyBase64);
  assert.ok(svcB.verifyChallengeSignature('s1', challenge, sig));
});

await test('PeerCryptoService', 'verify fails with wrong identity key (impersonation)', () => {
  const svcA = new PeerCryptoService();
  const svcB = new PeerCryptoService();
  const svcC = new PeerCryptoService(); // attacker
  const challenge = nodeCrypto.randomBytes(32).toString('base64');
  const sig       = svcA.signChallenge(challenge);

  svcB.registerRemoteIdentityKey('s1', svcC.identityPublicKeyBase64); // wrong key
  assert.ok(!svcB.verifyChallengeSignature('s1', challenge, sig));
});

await test('PeerCryptoService', 'clearSession removes key — decrypt throws', () => {
  const svc = new PeerCryptoService();
  const kp  = svc.generateEphemeralKeyPair();
  const svc2 = new PeerCryptoService();
  const kp2  = svc2.generateEphemeralKeyPair();
  svc.deriveSessionKey('s1', kp.privateKey, kp2.publicKeyBase64);
  const { ciphertext, nonce } = svc.encrypt('s1', 'data');
  svc.clearSession('s1');
  assert.throws(() => svc.decrypt('s1', ciphertext, nonce), /No session key/);
});

// ---- OutboundMessageQueue --------------------------------------------------

await test('OutboundMessageQueue', 'resolves on acknowledge', async () => {
  const q = new OutboundMessageQueue({ retryIntervalMs: 60_000 });
  const p = q.enqueue('m1', async () => {});
  q.acknowledge('m1');
  assert.equal(await p, 'm1');
  q.stop();
});

await test('OutboundMessageQueue', 'stop rejects all pending entries', async () => {
  const q = new OutboundMessageQueue({ retryIntervalMs: 60_000 });
  const p = q.enqueue('m2', async () => {});
  q.stop();
  await assert.rejects(p, /stopped/);
});

await test('OutboundMessageQueue', 'pendingCount tracks entries', async () => {
  const q = new OutboundMessageQueue({ retryIntervalMs: 60_000 });
  q.enqueue('m3', async () => {}).catch(() => {});
  q.enqueue('m4', async () => {}).catch(() => {});
  assert.equal(q.pendingCount, 2);
  q.acknowledge('m3');
  assert.equal(q.pendingCount, 1);
  q.stop();
});

await test('OutboundMessageQueue', 'rejects after maxRetries', async () => {
  let calls = 0;
  const q = new OutboundMessageQueue({ maxRetries: 2, retryIntervalMs: 10 });
  const p = q.enqueue('m5', async () => { calls++; });
  await assert.rejects(p, /not acknowledged/);
  assert.ok(calls >= 2);
  q.stop();
});

// ---- PeerChannelManager — channel establishment ----------------------------

await test('PeerChannelManager', 'openChannel resolves with sessionId once READY', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  const sidA = await managerA.openChannel();
  await settle();

  assert.ok(typeof sidA === 'string' && sidA.length > 0);
  assert.equal(managerA.getChannelStatus(sidA), ChannelStatus.READY);

  await managerA.stop();
  await managerB.stop();
});

await test('PeerChannelManager', 'responder side fires onChannelReady', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  let bSid = null;
  managerB.onChannelReady = (sid) => { bSid = sid; };

  const aSid = await managerA.openChannel();
  await settle();

  assert.ok(bSid !== null, 'B should have fired onChannelReady');
  assert.equal(bSid, aSid, 'both sides share the same sessionId');

  await managerA.stop();
  await managerB.stop();
});

// ---- PeerChannelManager — messaging ----------------------------------------

await test('PeerChannelManager', 'encrypted message received as plaintext', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  const sid     = await managerA.openChannel();
  await settle();

  let received = null;
  managerB.onMessageReceived = (_sid, _mid, text) => { received = text; };

  await managerA.sendMessage(sid, 'hello B', { requireAck: false });
  await settle();

  assert.equal(received, 'hello B');

  await managerA.stop();
  await managerB.stop();
});

await test('PeerChannelManager', 'ACK-tracked message resolves on acknowledgement', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  const sid = await managerA.openChannel();
  await settle();
  managerB.onMessageReceived = () => {};

  const ackPromise = managerA.sendMessage(sid, 'ack me', { requireAck: true });
  await settle();
  const ackedId = await ackPromise;

  assert.ok(typeof ackedId === 'string');

  await managerA.stop();
  await managerB.stop();
});

await test('PeerChannelManager', 'onMessageAcknowledged fires on sender side', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  const sid = await managerA.openChannel();
  await settle();
  managerB.onMessageReceived = () => {};

  let ackedId = null;
  managerA.onMessageAcknowledged = (_sid, mid) => { ackedId = mid; };

  const p = managerA.sendMessage(sid, 'check ack event', { requireAck: true });
  await settle();
  await p;

  assert.ok(ackedId !== null);

  await managerA.stop();
  await managerB.stop();
});

await test('PeerChannelManager', 'bidirectional messaging works', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  let bSid  = null;
  let bRecv = null;
  let aRecv = null;
  managerB.onChannelReady    = (sid) => { bSid  = sid; };
  managerB.onMessageReceived = (_s, _m, t) => { bRecv = t; };
  managerA.onMessageReceived = (_s, _m, t) => { aRecv = t; };

  const aSid = await managerA.openChannel();
  await settle();

  await managerA.sendMessage(aSid, 'A→B', { requireAck: false });
  await settle();
  await managerB.sendMessage(bSid, 'B→A', { requireAck: false });
  await settle();

  assert.equal(bRecv, 'A→B');
  assert.equal(aRecv, 'B→A');

  await managerA.stop();
  await managerB.stop();
});

// ---- PeerChannelManager — security -----------------------------------------

await test('PeerChannelManager', 'sendMessage throws on non-ready channel', async () => {
  const { managerA } = makePair();
  await managerA.start();
  await assert.rejects(() => managerA.sendMessage('ghost', 'hi'), /not ready/);
  await managerA.stop();
});

await test('PeerChannelManager', 'tampered auth-response triggers onChannelError', async () => {
  const { managerA, managerB, clientB } = makePair();
  await managerA.start();
  await managerB.start();

  // Intercept B's outgoing sendData and corrupt the challenge signature
  const orig = clientB.sendData.bind(clientB);
  clientB.sendData = async (opts) => {
    if (opts.contentType === 'application/vnd.peer2nodes.auth-response+json') {
      const parsed = JSON.parse(opts.body);
      parsed.challengeResponse = nodeCrypto.randomBytes(64).toString('base64'); // garbage sig
      return orig({ ...opts, body: JSON.stringify(parsed) });
    }
    return orig(opts);
  };

  let errorReason = null;
  managerA.onChannelError = (r) => { errorReason = r; };

  let channelAuthFailed = false;
  try {
    await managerA.openChannel();
  } catch (e) {
    channelAuthFailed = e.message.includes('auth_failed');
  }
  await settle();

  assert.ok(channelAuthFailed || (errorReason && errorReason.includes('auth_failed')),
    `expected auth failure, got: ${errorReason}`);

  await managerA.stop();
  await managerB.stop();
});

await test('PeerChannelManager', 'channel status transitions to CLOSED after closeChannel', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  const sid = await managerA.openChannel();
  await settle();

  await managerA.closeChannel(sid);
  await settle();

  assert.equal(managerA.getChannelStatus(sid), ChannelStatus.CLOSED);

  await managerA.stop();
  await managerB.stop();
});

await test('PeerChannelManager', 'onChannelClosed fires on both sides after closeChannel', async () => {
  const { managerA, managerB } = makePair();
  await managerA.start();
  await managerB.start();

  let closedA = false;
  let closedB = false;
  managerA.onChannelClosed = () => { closedA = true; };
  managerB.onChannelClosed = () => { closedB = true; };

  let bSid = null;
  managerB.onChannelReady = (sid) => { bSid = sid; };

  const aSid = await managerA.openChannel();
  await settle();

  await managerA.closeChannel(aSid);
  await settle();

  assert.ok(closedA, 'A should fire onChannelClosed');
  assert.ok(closedB, 'B should fire onChannelClosed');

  await managerA.stop();
  await managerB.stop();
});

// ---- summary ---------------------------------------------------------------

console.log(`\n${passed + failed} tests — ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

})().catch(err => { console.error(err); process.exit(1); });
