const SCHEME = 'peer2nodes://connect?c=';
const VERSION = 1;

function toBase64UrlUtf8(text) {
  const bytes = new TextEncoder().encode(text);
  const chars = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) chars[i] = String.fromCharCode(bytes[i]);
  const binary = chars.join('');
  const noPadding = stripTrailingEquals(btoa(binary));
  return noPadding.split('+').join('-').split('/').join('_');
}

function stripTrailingEquals(value) {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 61) end -= 1; // '='
  return value.slice(0, end);
}

function fromBase64UrlUtf8(input) {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  const b64 = padded.split('-').join('+').split('_').join('/');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

class ConnectionInfoShare {
  static createConnectionInfo({ nodeId, displayName = null, capabilities = [] }) {
    if (!nodeId || typeof nodeId !== 'string') throw new Error('nodeId is required');
    return {
      version: VERSION,
      nodeId,
      displayName,
      capabilities: Array.isArray(capabilities) ? [...capabilities] : [],
      createdAt: new Date().toISOString(),
    };
  }

  static toShareUri(connectionInfo) {
    return SCHEME + toBase64UrlUtf8(JSON.stringify(connectionInfo));
  }

  static fromShareUri(value) {
    if (typeof value !== 'string' || !value.startsWith(SCHEME)) throw new Error('Invalid connection share URI');
    const encoded = value.slice(SCHEME.length).trim();
    if (!encoded) throw new Error('Connection share URI is empty');

    let parsed;
    try {
      parsed = JSON.parse(fromBase64UrlUtf8(encoded));
    } catch (error) {
      throw new Error(`Failed to parse connection info: ${error.message}`);
    }
    return normalizeConnectionInfo(parsed);
  }

  static toNfcTextPayload(connectionInfo) { return this.toShareUri(connectionInfo); }
  static fromNfcTextPayload(payload) { return this.fromShareUri(payload); }
  static toQrPayload(connectionInfo) { return this.toShareUri(connectionInfo); }
  static fromQrPayload(payload) { return this.fromShareUri(payload); }
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
    createdAt: parsed.createdAt,
  };
}

export { ConnectionInfoShare };
