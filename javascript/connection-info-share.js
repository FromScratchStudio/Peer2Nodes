'use strict';

const SCHEME = 'peer2nodes://connect?c=';
const VERSION = 1;

function toUrlSafeBase64(input) {
  const base64 = Buffer.from(input, 'utf8').toString('base64');
  const noPadding = stripTrailingEquals(base64);
  return noPadding.split('+').join('-').split('/').join('_');
}

function stripTrailingEquals(value) {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 61) end -= 1; // '='
  return value.slice(0, end);
}

function fromUrlSafeBase64(input) {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  const normalized = padded.split('-').join('+').split('_').join('/');
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

    return normalizeConnectionInfo(parsed);
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

function normalizeConnectionInfo(parsed) {
  if (!parsed || typeof parsed !== 'object' || typeof parsed.nodeId !== 'string' || parsed.nodeId.length === 0) {
    throw new Error('Connection info is missing nodeId');
  }

  if (parsed.version !== VERSION) {
    throw new Error(`Unsupported connection info version: ${parsed.version}`);
  }

  const displayName = typeof parsed.displayName === 'string' ? parsed.displayName : null;
  const capabilities = Array.isArray(parsed.capabilities)
    ? parsed.capabilities.filter((cap) => typeof cap === 'string')
    : [];

  return {
    version: VERSION,
    nodeId: parsed.nodeId,
    displayName,
    capabilities,
    createdAt: normalizeCreatedAt(parsed.createdAt),
  };
}

function normalizeCreatedAt(value) {
  if (typeof value !== 'string') return null;
  return Number.isNaN(Date.parse(value)) ? null : value;
}

module.exports = {
  ConnectionInfoShare
};
