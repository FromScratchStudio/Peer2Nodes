'use strict';

const http = require('node:http');
const { EventEmitter } = require('node:events');
const { normalizeTimeoutMs, DEFAULT_POLL_TIMEOUT_MS } = require('./webrtc-p2p');

const DEFAULT_PORT = 8787;
const DEFAULT_HOST = '0.0.0.0';
const DEFAULT_MAX_BODY_BYTES = 16 * 1024;
const DEFAULT_CORS_ALLOWED_ORIGINS = ['*'];
const DEFAULT_MAX_POLL_LISTENERS = 256;

function parseJsonBody(req, maxBodyBytes) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    let tooLarge = false;
    const chunks = [];
    req.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBodyBytes) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) {
        const error = new Error('payload_too_large');
        error.statusCode = 413;
        reject(error);
        return;
      }
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch (error) {
        const parseError = new Error(`invalid_json:${error.message}`);
        parseError.statusCode = 400;
        reject(parseError);
      }
    });
    req.on('error', reject);
  });
}

function createCorsHeaders(origin, corsAllowedOrigins) {
  const allowAll = corsAllowedOrigins.includes('*');
  const allowedOrigin = allowAll || corsAllowedOrigins.includes(origin) ? (allowAll ? '*' : origin) : null;
  if (!allowedOrigin) return null;

  const headers = {
    'access-control-allow-origin': allowedOrigin,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '600'
  };
  if (!allowAll) headers.vary = 'origin';
  return headers;
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

function badRequest(res, message, headers) {
  sendJson(res, 400, { error: message }, headers);
}

function queueKey(roomId, nodeId) {
  return `${roomId}::${nodeId}`;
}

function getRoomQueue(queuesByRoom, roomId) {
  if (!queuesByRoom.has(roomId)) queuesByRoom.set(roomId, new Map());
  return queuesByRoom.get(roomId);
}

function enqueueSignal(queuesByRoom, queueEvents, signal) {
  const roomQueue = getRoomQueue(queuesByRoom, signal.roomId);
  const nodeQueue = roomQueue.get(signal.targetNodeId) ?? [];
  nodeQueue.push(signal);
  roomQueue.set(signal.targetNodeId, nodeQueue);
  queueEvents.emit(queueKey(signal.roomId, signal.targetNodeId));
}

function drainSignals(queuesByRoom, roomId, nodeId) {
  const roomQueue = getRoomQueue(queuesByRoom, roomId);
  const nodeQueue = roomQueue.get(nodeId) ?? [];
  roomQueue.set(nodeId, []);
  return nodeQueue;
}

function validateNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function createSignalingServer({
  port = DEFAULT_PORT,
  host = DEFAULT_HOST,
  pollTimeoutMs = DEFAULT_POLL_TIMEOUT_MS,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  corsAllowedOrigins = DEFAULT_CORS_ALLOWED_ORIGINS,
  maxPollListeners = DEFAULT_MAX_POLL_LISTENERS
} = {}) {
  const queuesByRoom = new Map(); // roomId => Map<targetNodeId, signal[]>
  const queueEvents = new EventEmitter();
  queueEvents.setMaxListeners(Math.max(16, Number(maxPollListeners) || DEFAULT_MAX_POLL_LISTENERS));

  const effectivePollTimeoutMs = normalizeTimeoutMs(pollTimeoutMs);
  const effectiveMaxBodyBytes = Math.max(1, Number(maxBodyBytes) || DEFAULT_MAX_BODY_BYTES);
  const effectiveCorsAllowedOrigins = Array.isArray(corsAllowedOrigins) && corsAllowedOrigins.length > 0
    ? corsAllowedOrigins
    : DEFAULT_CORS_ALLOWED_ORIGINS;

  const server = http.createServer(async (req, res) => {
    if (!req.url) return badRequest(res, 'missing_url');
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const origin = req.headers.origin;
    const corsHeaders = createCorsHeaders(origin, effectiveCorsAllowedOrigins);

    if (origin && !corsHeaders) {
      return sendJson(res, 403, { error: 'origin_not_allowed' });
    }

    if (req.method === 'OPTIONS') {
      if (!corsHeaders) return sendJson(res, 403, { error: 'origin_not_allowed' });
      res.writeHead(204, {
        ...corsHeaders,
        'content-length': '0'
      });
      res.end();
      return;
    }

    if (req.method === 'POST' && url.pathname === '/signals/publish') {
      const contentLength = Number(req.headers['content-length']);
      if (Number.isFinite(contentLength) && contentLength > effectiveMaxBodyBytes) {
        return sendJson(res, 413, { error: 'payload_too_large' }, corsHeaders ?? {});
      }

      let payload;
      try {
        payload = await parseJsonBody(req, effectiveMaxBodyBytes);
      } catch (error) {
        const statusCode = error?.statusCode ?? 400;
        return sendJson(res, statusCode, { error: error.message }, corsHeaders ?? {});
      }

      const requiredFields = ['roomId', 'sourceNodeId', 'targetNodeId', 'type'];
      for (const field of requiredFields) {
        if (!validateNonEmptyString(payload[field])) {
          return badRequest(res, `missing_field:${field}`, corsHeaders ?? {});
        }
      }

      enqueueSignal(queuesByRoom, queueEvents, {
        roomId: payload.roomId,
        sourceNodeId: payload.sourceNodeId,
        targetNodeId: payload.targetNodeId,
        type: payload.type,
        sessionId: validateNonEmptyString(payload.sessionId) ? payload.sessionId : null,
        sdp: validateNonEmptyString(payload.sdp) ? payload.sdp : null,
        candidate: payload.candidate ?? null,
        createdAt: new Date().toISOString()
      });

      return sendJson(res, 202, { accepted: true }, corsHeaders ?? {});
    }

    if (req.method === 'GET' && url.pathname === '/signals/poll') {
      const roomId = url.searchParams.get('roomId');
      const nodeId = url.searchParams.get('nodeId');
      if (!validateNonEmptyString(roomId)) return badRequest(res, 'missing_query:roomId', corsHeaders ?? {});
      if (!validateNonEmptyString(nodeId)) return badRequest(res, 'missing_query:nodeId', corsHeaders ?? {});

      const immediateSignals = drainSignals(queuesByRoom, roomId, nodeId);
      if (immediateSignals.length > 0) return sendJson(res, 200, { signals: immediateSignals }, corsHeaders ?? {});

      await new Promise((resolve) => {
        const eventName = queueKey(roomId, nodeId);
        const onSignal = () => {
          clearTimeout(timeoutHandle);
          queueEvents.off(eventName, onSignal);
          resolve();
        };
        const timeoutHandle = setTimeout(() => {
          queueEvents.off(eventName, onSignal);
          resolve();
        }, effectivePollTimeoutMs);
        queueEvents.on(eventName, onSignal);
      });

      const delayedSignals = drainSignals(queuesByRoom, roomId, nodeId);
      if (delayedSignals.length > 0) return sendJson(res, 200, { signals: delayedSignals }, corsHeaders ?? {});
      return sendJson(res, 200, { signals: [] }, corsHeaders ?? {});
    }

    sendJson(res, 404, { error: 'not_found' }, corsHeaders ?? {});
  });

  return {
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.removeListener('error', reject);
          const address = server.address();
          const boundPort = address && typeof address === 'object' ? address.port : port;
          resolve({ host, port: boundPort });
        });
      });
    },
    stop() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  };
}

if (require.main === module) {
  const port = Number(process.env.PEER2NODES_SIGNALING_PORT) || DEFAULT_PORT;
  const host = process.env.PEER2NODES_SIGNALING_HOST || DEFAULT_HOST;
  const signaling = createSignalingServer({ port, host });
  signaling.start()
    .then(({ host: boundHost, port: boundPort }) => {
      // eslint-disable-next-line no-console
      console.log(`Peer2Nodes signaling server listening on http://${boundHost}:${boundPort}`);
    })
    .catch((error) => {
      // eslint-disable-next-line no-console
      console.error(`Failed to start signaling server: ${error.message}`);
      process.exit(1);
    });
}

module.exports = {
  createSignalingServer
};
