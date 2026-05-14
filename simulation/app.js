import { SimulationBus, BusPeerTransport, PeerNodeClient, Capability } from './peer2nodes-browser.js';
import { PeerCryptoService, PeerChannelManager, ChannelStatus } from './peer-channel-browser.js';
import { ConnectionInfoShare } from './connection-info-share-browser.js';

// ── Shared bus — all instances route messages through it ─────────────────────
const bus = new SimulationBus();

// instances: id → { id, name, nodeId, manager, color }
const instances = new Map();
// channels: sessionId → { sessionId, peerIds: [id?, id?], peerNodeIds: [nodeId, nodeId], status, messages: [] }
const channels  = new Map();
const collapsedChannels = new Set();

let nextNum = 1;
const COLORS = ['#58a6ff', '#3fb950', '#f78166', '#d2a8ff', '#ffa657', '#79c0ff', '#ff7b72', '#56d364'];

// ── DOM helpers ───────────────────────────────────────────────────────────────
const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function appendLog(instanceName, color, event, detail = '') {
  const el = $('#log');
  const row = document.createElement('div');
  row.className = 'log-row';
  row.innerHTML =
    `<span class="lt">${timestamp()}</span>` +
    `<span class="li" style="color:${color}">[${escHtml(instanceName)}]</span> ` +
    `<span class="le">${escHtml(event)}</span>` +
    (detail ? ` <span class="ld">${escHtml(detail)}</span>` : '');
  el.appendChild(row);
  el.scrollTop = el.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function shortId(id) { return id ? id.slice(0, 8) : '?'; }

function instanceByNodeId(nodeId) {
  for (const inst of instances.values()) if (inst.nodeId === nodeId) return inst;
  return null;
}

// ── Render instances ──────────────────────────────────────────────────────────
function renderInstances() {
  const list = $('#instances-list');
  list.innerHTML = '';
  for (const inst of instances.values()) {
    const div = document.createElement('div');
    div.className = 'inst-card';
    div.innerHTML =
      `<span class="inst-dot" style="background:${inst.color}"></span>` +
      `<span class="inst-name">${escHtml(inst.name)}</span>` +
      `<span class="inst-id">${shortId(inst.nodeId)}</span>`;
    list.appendChild(div);
  }
  refreshSelects();
}

function refreshSelects() {
  const opts = [...instances.values()]
    .map(i => `<option value="${i.id}">${escHtml(i.name)}</option>`)
    .join('');

  $$('.inst-select')
    .filter((sel) => sel.id !== 'sel-share-instance')
    .forEach((sel) => {
    const prev = sel.value;
    sel.innerHTML = '<option value="">— select —</option>' + opts;
    if (prev && instances.has(prev)) sel.value = prev;
  });

  const shareSel = $('#sel-share-instance');
  if (shareSel) {
    const prev = shareSel.value;
    shareSel.innerHTML = opts;
    if (prev && instances.has(prev)) shareSel.value = prev;
    if (!shareSel.value && instances.size) shareSel.value = [...instances.keys()][0];
  }
}

// ── Render channels ───────────────────────────────────────────────────────────
function renderChannels() {
  const list = $('#channels-list');
  list.innerHTML = '';

  for (const [sid, ch] of channels) {
    if (ch.status === ChannelStatus.CLOSED) continue;

    const [idA, idB] = ch.peerIds;
    const instA = idA ? instances.get(idA) : instanceByNodeId(ch.peerNodeIds[0]);
    const instB = idB ? instances.get(idB) : instanceByNodeId(ch.peerNodeIds[1]);

    const statusClass =
      ch.status === ChannelStatus.READY         ? 'st-ready' :
      ch.status === ChannelStatus.ERROR         ? 'st-error' :
      ch.status === ChannelStatus.AUTHENTICATING ? 'st-auth' : 'st-other';

    const nameA = instA?.name ?? shortId(ch.peerNodeIds[0]);
    const nameB = instB?.name ?? shortId(ch.peerNodeIds[1]);
    const colorA = instA?.color ?? '#c9d1d9';
    const colorB = instB?.color ?? '#c9d1d9';
    const isCollapsed = collapsedChannels.has(sid);

    const card = document.createElement('div');
    card.className = `ch-card${isCollapsed ? ' ch-collapsed' : ''}`;
    card.dataset.sid = sid;

    const msgHistory = ch.messages.map(m =>
      `<div class="msg-row msg-${m.dir}">` +
      `<span class="msg-who" style="color:${m.dir === 'out' ? colorA : colorB}">${escHtml(m.sender)}</span>` +
      `<span class="msg-text">${escHtml(m.text)} [${m.dir}]</span>` +
      `<span class="msg-ack">${m.acked ? '✓✓' : m.dir === 'out' ? '✓' : ''}</span>` +
      `</div>`
    ).join('');

    card.innerHTML =
      `<div class="ch-header">` +
        `<span class="ch-peers">` +
          `<span style="color:${colorA}">${escHtml(nameA)}</span>` +
          `<span class="ch-arrow"> ⟷ </span>` +
          `<span style="color:${colorB}">${escHtml(nameB)}</span>` +
        `</span>` +
        `<button class="btn-toggle-ch" data-sid="${sid}" title="${isCollapsed ? 'Expand channel' : 'Collapse channel'}" aria-label="${isCollapsed ? 'Expand channel' : 'Collapse channel'}">${isCollapsed ? '▸' : '▾'}</button>` +
        `<span class="ch-badge ${statusClass}">${ch.status}</span>` +
        `<button class="btn-close-ch" data-sid="${sid}" title="Close channel">✕</button>` +
      `</div>` +
      `<div class="ch-body">` +
        (ch.messages.length ? `<div class="msg-history">${msgHistory}</div>` : '') +
        (ch.status === ChannelStatus.READY
          ? `<div class="ch-compose">` +
              `<select class="sender-sel" data-sid="${sid}">` +
                `<option value="${idA ?? ''}">${escHtml(nameA)}</option>` +
                `<option value="${idB ?? ''}">${escHtml(nameB)}</option>` +
              `</select>` +
              `<input class="msg-input" data-sid="${sid}" type="text" placeholder="Type a message…" />` +
              `<button class="btn-send" data-sid="${sid}">Send</button>` +
            `</div>`
          : '') +
      `</div>`;

    list.appendChild(card);
  }

  $$('.btn-send').forEach(btn => btn.addEventListener('click', () => handleSend(btn.dataset.sid)));
  $$('.msg-input').forEach(inp => inp.addEventListener('keydown', e => { if (e.key === 'Enter') handleSend(inp.dataset.sid); }));
  $$('.btn-toggle-ch').forEach(btn => btn.addEventListener('click', () => handleToggleChannelCard(btn.dataset.sid)));
  $$('.btn-close-ch').forEach(btn => btn.addEventListener('click', () => handleCloseChannel(btn.dataset.sid)));
}

// ── Create instance ───────────────────────────────────────────────────────────
async function createInstance() {
  const nameInput = $('#inp-name');
  const name  = nameInput.value.trim() || `Node-${nextNum}`;
  nameInput.value = '';
  nextNum++;

  const color      = COLORS[(instances.size) % COLORS.length];
  const nodeId     = crypto.randomUUID();
  const transport  = new BusPeerTransport(bus, nodeId);
  const cryptoSvc  = await PeerCryptoService.create();
  const client     = new PeerNodeClient({ nodeId, capabilities: [Capability.END_TO_END_ENCRYPTION], transport });
  const manager    = new PeerChannelManager({ client, cryptoService: cryptoSvc });
  const instanceId = crypto.randomUUID();

  // Wire callbacks
  manager.onChannelReady = (sid, remoteNodeId) => {
    let ch = channels.get(sid);
    if (!ch) {
      ch = { sessionId: sid, peerIds: [instanceId, null], peerNodeIds: [nodeId, remoteNodeId], status: ChannelStatus.READY, messages: [] };
      channels.set(sid, ch);
    } else {
      // Second party registering — fill in second slot
      if (!ch.peerIds.includes(instanceId)) {
        ch.peerIds[1] = instanceId;
        ch.peerNodeIds[1] = nodeId;
      }
      ch.status = ChannelStatus.READY;
    }
    const remote = instanceByNodeId(remoteNodeId);
    appendLog(name, color, 'channel READY', `↔ ${remote?.name ?? shortId(remoteNodeId)}`);
    renderChannels();
  };

  manager.onMessageReceived = (sid, _msgId, plaintext) => {
    const ch = channels.get(sid);
    if (ch) {
      ch.messages.push({ dir: 'in', sender: name, text: plaintext, acked: false });
    }
    appendLog(name, color, 'received', `"${plaintext}"`);
    renderChannels();
  };

  manager.onMessageAcknowledged = (sid, msgId) => {
    appendLog(name, color, 'ACK', shortId(msgId));
    // Mark last unacked outbound message as acked
    const ch = channels.get(sid);
    if (ch) {
      const m = [...ch.messages].reverse().find(x => x.dir === 'out' && !x.acked);
      if (m) m.acked = true;
      renderChannels();
    }
  };

  manager.onChannelError = (reason) => {
    appendLog(name, color, 'error', reason);
    renderChannels();
  };

  manager.onChannelClosed = (sid) => {
    const ch = channels.get(sid);
    if (ch) ch.status = ChannelStatus.CLOSED;
    collapsedChannels.delete(sid);
    appendLog(name, color, 'channel closed');
    renderChannels();
  };

  await manager.start();

  instances.set(instanceId, { id: instanceId, name, nodeId, manager, color });
  appendLog(name, color, 'instance created', shortId(nodeId));
  renderInstances();
}

// ── Open channel ──────────────────────────────────────────────────────────────
async function openChannel() {
  const initId = $('#sel-initiator').value;
  const respId = $('#sel-responder').value;

  if (!initId || !respId) { appendLog('system', '#d29922', 'select two instances'); return; }
  if (initId === respId)  { appendLog('system', '#d29922', 'initiator ≠ responder'); return; }

  const initiator = instances.get(initId);
  const responder = instances.get(respId);
  if (!initiator || !responder) return;

  appendLog(initiator.name, initiator.color, 'opening channel →', responder.name);
  appendLog(responder.name, responder.color, 'awaiting handshake', `← ${initiator.name}`);

  // Pre-register a placeholder so onChannelReady can find the channel by sid
  try {
    const sessionId = await initiator.manager.openChannel(responder.nodeId);
    // If onChannelReady didn't create the entry yet, create it now
    if (!channels.has(sessionId)) {
      channels.set(sessionId, {
        sessionId,
        peerIds:     [initId, respId],
        peerNodeIds: [initiator.nodeId, responder.nodeId],
        status:      ChannelStatus.READY,
        messages:    [],
      });
    } else {
      // Ensure both peerIds are filled from the initiator side
      const ch = channels.get(sessionId);
      if (!ch.peerIds.includes(initId)) ch.peerIds[0] = initId;
      if (!ch.peerIds.includes(respId)) ch.peerIds[1] = respId;
    }
    appendLog(initiator.name, initiator.color, 'handshake complete', shortId(sessionId));
    renderChannels();
  } catch (err) {
    appendLog(initiator.name, '#f85149', 'channel failed', err.message);
  }
}

// ── Send message ──────────────────────────────────────────────────────────────
async function handleSend(sid) {
  const input     = $(`.msg-input[data-sid="${sid}"]`);
  const senderSel = $(`.sender-sel[data-sid="${sid}"]`);
  const text = input?.value.trim();
  if (!text) return;

  const senderId = senderSel?.value;
  const sender   = instances.get(senderId);
  if (!sender) return;
  input.value = '';

  const ch = channels.get(sid);
  if (ch) ch.messages.push({ dir: 'out', sender: sender.name, text, acked: false });

  try {
    await sender.manager.sendMessage(sid, text);
    appendLog(sender.name, sender.color, 'sent', `"${text}"`);
  } catch (err) {
    appendLog(sender.name, '#f85149', 'send failed', err.message);
    if (ch) ch.messages.pop();
  }
  renderChannels();
}

// ── Close channel ─────────────────────────────────────────────────────────────
async function handleCloseChannel(sid) {
  const ch = channels.get(sid);
  if (!ch) return;
  const inst = ch.peerIds[0] ? instances.get(ch.peerIds[0]) : null;
  if (inst) await inst.manager.closeChannel(sid);
}

function handleToggleChannelCard(sid) {
  if (!channels.has(sid)) return;
  if (collapsedChannels.has(sid)) collapsedChannels.delete(sid);
  else collapsedChannels.add(sid);
  renderChannels();
}

// ── Clear log ─────────────────────────────────────────────────────────────────
function clearLog() { $('#log').innerHTML = ''; }

function selectedShareInstance() {
  const id = $('#sel-share-instance').value;
  return instances.get(id) ?? null;
}

function buildConnectionInfo(instance) {
  return ConnectionInfoShare.createConnectionInfo({
    nodeId: instance.nodeId,
    displayName: instance.name,
    capabilities: [Capability.END_TO_END_ENCRYPTION],
  });
}

function renderQrPreview(payload) {
  const img = $('#qr-preview');
  if (!payload) {
    img.removeAttribute('src');
    img.alt = 'No QR code generated';
    return;
  }
  const encoded = encodeURIComponent(payload);
  img.src = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encoded}`;
  img.alt = 'Connection QR code';
}

function generateSharePayload() {
  const instance = selectedShareInstance();
  if (!instance) {
    appendLog('system', '#d29922', 'select instance to share');
    return;
  }

  const shareUri = ConnectionInfoShare.toShareUri(buildConnectionInfo(instance));
  $('#share-uri').value = shareUri;
  renderQrPreview('');
  appendLog(instance.name, instance.color, 'share info generated', shortId(instance.nodeId));
}

function renderRemoteQrPreview() {
  const value = $('#share-uri').value.trim();
  if (!value) {
    appendLog('system', '#d29922', 'generate share info first');
    return;
  }
  renderQrPreview(value);
  appendLog('system', '#d29922', 'remote QR rendered', 'shares payload with api.qrserver.com');
}

async function copyShareUri() {
  const value = $('#share-uri').value.trim();
  if (!value) {
    appendLog('system', '#d29922', 'generate share info first');
    return;
  }
  if (!navigator.clipboard?.writeText) {
    appendLog('system', '#d29922', 'clipboard API unavailable');
    return;
  }
  await navigator.clipboard.writeText(value);
  appendLog('system', '#58a6ff', 'share URI copied');
}

async function nativeShareUri() {
  const value = $('#share-uri').value.trim();
  if (!value) {
    appendLog('system', '#d29922', 'generate share info first');
    return;
  }
  if (!navigator.share) {
    appendLog('system', '#d29922', 'native share API unavailable');
    return;
  }
  await navigator.share({ title: 'Peer2Nodes connection', text: value });
  appendLog('system', '#58a6ff', 'share sheet opened');
}

async function connectFromSharedUri() {
  const uri = $('#share-uri').value.trim();
  if (!uri) {
    appendLog('system', '#d29922', 'paste a shared URI first');
    return;
  }

  let info;
  try {
    info = ConnectionInfoShare.fromShareUri(uri);
  } catch (error) {
    appendLog('system', '#f85149', 'invalid shared URI', error.message);
    return;
  }

  const responder = instanceByNodeId(info.nodeId);
  if (!responder) {
    appendLog('system', '#f85149', 'shared target not found in simulation', shortId(info.nodeId));
    return;
  }

  const candidates = [...instances.values()].filter(i => i.id !== responder.id);
  const initiator = candidates[0];
  if (!initiator) {
    appendLog('system', '#d29922', 'need at least two instances');
    return;
  }

  $('#sel-initiator').value = initiator.id;
  $('#sel-responder').value = responder.id;
  appendLog('system', '#58a6ff', 'connecting from shared info', `${initiator.name} → ${responder.name}`);
  await openChannel();
}

async function nfcWriteShareUri() {
  const value = $('#share-uri').value.trim();
  if (!value) {
    appendLog('system', '#d29922', 'generate share info first');
    return;
  }
  if (!('NDEFReader' in window)) {
    appendLog('system', '#d29922', 'Web NFC unavailable');
    return;
  }

  try {
    const ndef = new NDEFReader();
    await ndef.write({ records: [{ recordType: 'url', data: value }] });
    appendLog('system', '#58a6ff', 'NFC write complete');
  } catch (error) {
    appendLog('system', '#f85149', 'NFC write failed', error.message);
  }
}

async function nfcReadAndConnect() {
  if (!('NDEFReader' in window)) {
    appendLog('system', '#d29922', 'Web NFC unavailable');
    return;
  }

  try {
    const ndef = new NDEFReader();
    await ndef.scan();
    appendLog('system', '#58a6ff', 'NFC scan active', 'tap a tag');

    ndef.addEventListener('reading', async (event) => {
      for (const record of event.message.records) {
        if (record.recordType !== 'url' && record.recordType !== 'text') continue;
        const data = new TextDecoder('utf-8').decode(record.data);
        $('#share-uri').value = data;
        renderQrPreview('');
        appendLog('system', '#58a6ff', 'NFC tag read');
        await connectFromSharedUri();
        return;
      }
      appendLog('system', '#d29922', 'NFC tag has no compatible record');
    }, { once: true });
  } catch (error) {
    appendLog('system', '#f85149', 'NFC scan failed', error.message);
  }
}

function bindAsyncClick(selector, action, errorMessagePrefix) {
  $(selector).addEventListener('click', async () => {
    try {
      await action();
    } catch (err) {
      appendLog('system', '#f85149', `${errorMessagePrefix} (${selector})`, err.message);
    }
  });
}

// ── Wire up static controls ───────────────────────────────────────────────────
$('#btn-create').addEventListener('click', createInstance);
$('#inp-name').addEventListener('keydown', e => { if (e.key === 'Enter') createInstance(); });
$('#btn-open-channel').addEventListener('click', openChannel);
$('#btn-clear-log').addEventListener('click', clearLog);
$('#btn-generate-share').addEventListener('click', generateSharePayload);
$('#btn-render-remote-qr').addEventListener('click', renderRemoteQrPreview);
bindAsyncClick('#btn-copy-share', copyShareUri, 'copy failed');
bindAsyncClick('#btn-share-native', nativeShareUri, 'share failed');
bindAsyncClick('#btn-connect-from-share', connectFromSharedUri, 'connect failed');
bindAsyncClick('#btn-nfc-write', nfcWriteShareUri, 'NFC write failed');
bindAsyncClick('#btn-nfc-read', nfcReadAndConnect, 'NFC read failed');
$('#share-uri').addEventListener('keydown', e => { if (e.key === 'Enter') connectFromSharedUri(); });

// Auto-create two instances so the UI isn't empty on load
createInstance().then(() => createInstance());
