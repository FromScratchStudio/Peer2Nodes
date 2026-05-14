'use strict';

const SCHEME = 'peer2nodes://connect?c=';
const VERSION = 1;

function toUrlSafeBase64(input) {
  return Buffer.from(input, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromUrlSafeBase64(input) {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  const normalized = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized, 'base64').toString('utf8');
}

class ConnectionInfoShare {
  static createConnectionInfo({ nodeId, displayName = null, capabilities = [] }) {
    if (!nodeId || typeof nodeId !== 'string') {
      throw new Error('nodeId is required');
    }

    return {
      version: VERSION,
      nodeId,
      displayName,
      capabilities: Array.isArray(capabilities) ? [...capabilities] : [],
      createdAt: new Date().toISOString()
    };
  }

  static toShareUri(connectionInfo) {
    const json = JSON.stringify(connectionInfo);
    return SCHEME + toUrlSafeBase64(json);
  }

  static fromShareUri(value) {
    if (typeof value !== 'string' || !value.startsWith(SCHEME)) {
      throw new Error('Invalid connection share URI');
    }

    const encoded = value.slice(SCHEME.length).trim();
    if (!encoded) {
      throw new Error('Connection share URI is empty');
    }

    let parsed;
    try {
      parsed = JSON.parse(fromUrlSafeBase64(encoded));
    } catch (err) {
      throw new Error(`Failed to parse connection info: ${err.message}`);
    }

    if (!parsed || typeof parsed !== 'object' || typeof parsed.nodeId !== 'string' || parsed.nodeId.length === 0) {
      throw new Error('Connection info is missing nodeId');
    }

    return parsed;
  }

  static toNfcTextPayload(connectionInfo) {
    return this.toShareUri(connectionInfo);
  }

  static fromNfcTextPayload(payload) {
    return this.fromShareUri(payload);
  }

  static toQrPayload(connectionInfo) {
    return this.toShareUri(connectionInfo);
  }

  static fromQrPayload(payload) {
    return this.fromShareUri(payload);
  }
}

module.exports = {
  ConnectionInfoShare
};
