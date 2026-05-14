'use strict';

const http = require('node:http');
const { EventEmitter } = require('node:events');

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch (error) {
        reject(new Error(`invalid_json:${error.message}`));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store'
  });
  res.end(body);
}

function badRequest(res, message) {
  sendJson(res, 400, { error: message });
}

const queuesByRoom = new Map(); // roomId => Map<targetNodeId, signal[]>
const queueEvents = new EventEmitter();

function queueKey(roomId, nodeId) {
  return `${roomId}::${nodeId}`;
}

function getRoomQueue(roomId) {
  if (!queuesByRoom.has(roomId)) queuesByRoom.set(roomId, new Map());
  return queuesByRoom.get(roomId);
}

function enqueueSignal(signal) {
  const roomQueue = getRoomQueue(signal.roomId);
  const nodeQueue = roomQueue.get(signal.targetNodeId) ?? [];
  nodeQueue.push(signal);
  roomQueue.set(signal.targetNodeId, nodeQueue);
  queueEvents.emit(queueKey(signal.roomId, signal.targetNodeId));
}

function drainSignals(roomId, nodeId) {
  const roomQueue = getRoomQueue(roomId);
  const nodeQueue = roomQueue.get(nodeId) ?? [];
  roomQueue.set(nodeId, []);
  return nodeQueue;
}

function validateNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function createSignalingServer({ port = 8787, host = '0.0.0.0', pollTimeoutMs = 20_000 } = {}) {
  const effectivePollTimeoutMs = Math.max(1_000, Math.min(Number(pollTimeoutMs) || 20_000, 120_000));
  const server = http.createServer(async (req, res) => {
    if (!req.url) return badRequest(res, 'missing_url');
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'POST' && url.pathname === '/signals/publish') {
      let payload;
      try {
        payload = await parseJsonBody(req);
      } catch (error) {
        return badRequest(res, error.message);
      }

      const requiredFields = ['roomId', 'sourceNodeId', 'targetNodeId', 'type'];
      for (const field of requiredFields) {
        if (!validateNonEmptyString(payload[field])) {
          return badRequest(res, `missing_field:${field}`);
        }
      }

      enqueueSignal({
        roomId: payload.roomId,
        sourceNodeId: payload.sourceNodeId,
        targetNodeId: payload.targetNodeId,
        type: payload.type,
        sessionId: validateNonEmptyString(payload.sessionId) ? payload.sessionId : null,
        sdp: validateNonEmptyString(payload.sdp) ? payload.sdp : null,
        candidate: payload.candidate ?? null,
        createdAt: new Date().toISOString()
      });

      return sendJson(res, 202, { accepted: true });
    }

    if (req.method === 'GET' && url.pathname === '/signals/poll') {
      const roomId = url.searchParams.get('roomId');
      const nodeId = url.searchParams.get('nodeId');
      if (!validateNonEmptyString(roomId)) return badRequest(res, 'missing_query:roomId');
      if (!validateNonEmptyString(nodeId)) return badRequest(res, 'missing_query:nodeId');

      const immediateSignals = drainSignals(roomId, nodeId);
      if (immediateSignals.length > 0) return sendJson(res, 200, { signals: immediateSignals });

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

      const delayedSignals = drainSignals(roomId, nodeId);
      if (delayedSignals.length > 0) return sendJson(res, 200, { signals: delayedSignals });
      return sendJson(res, 200, { signals: [] });
    }

    sendJson(res, 404, { error: 'not_found' });
  });

  return {
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.removeListener('error', reject);
          resolve({ host, port });
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
  const port = Number(process.env.PEER2NODES_SIGNALING_PORT) || 8787;
  const host = process.env.PEER2NODES_SIGNALING_HOST || '0.0.0.0';
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
