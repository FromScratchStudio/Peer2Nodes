const SCHEME = 'peer2nodes://connect?c=';
const VERSION = 1;

function toBase64UrlUtf8(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64UrlUtf8(input) {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
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
    if (!parsed?.nodeId || typeof parsed.nodeId !== 'string') throw new Error('Connection info is missing nodeId');
    return parsed;
  }

  static toNfcTextPayload(connectionInfo) { return this.toShareUri(connectionInfo); }
  static fromNfcTextPayload(payload) { return this.fromShareUri(payload); }
  static toQrPayload(connectionInfo) { return this.toShareUri(connectionInfo); }
  static fromQrPayload(payload) { return this.fromShareUri(payload); }
}

export { ConnectionInfoShare };
