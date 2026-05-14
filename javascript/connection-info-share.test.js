'use strict';

const assert = require('node:assert/strict');
const { ConnectionInfoShare } = require('./connection-info-share');

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
  } catch (error) {
    console.error(`  ✗ ${name}`);
    throw error;
  }
}

console.log('ConnectionInfoShare');

test('builds + parses a share URI', () => {
  const info = ConnectionInfoShare.createConnectionInfo({
    nodeId: 'node-123',
    displayName: 'Alice',
    capabilities: ['end-to-end-encryption']
  });

  const uri = ConnectionInfoShare.toShareUri(info);
  const parsed = ConnectionInfoShare.fromShareUri(uri);

  assert.equal(parsed.nodeId, 'node-123');
  assert.equal(parsed.displayName, 'Alice');
  assert.deepEqual(parsed.capabilities, ['end-to-end-encryption']);
  assert.equal(parsed.version, 1);
});

test('supports NFC and QR payload helpers', () => {
  const info = ConnectionInfoShare.createConnectionInfo({ nodeId: 'node-456' });
  const nfcPayload = ConnectionInfoShare.toNfcTextPayload(info);
  const qrPayload = ConnectionInfoShare.toQrPayload(info);

  assert.equal(ConnectionInfoShare.fromNfcTextPayload(nfcPayload).nodeId, 'node-456');
  assert.equal(ConnectionInfoShare.fromQrPayload(qrPayload).nodeId, 'node-456');
});

test('throws for invalid URIs', () => {
  assert.throws(() => ConnectionInfoShare.fromShareUri('not-peer2nodes'));
});

console.log('\n3 tests — 3 passed, 0 failed');
