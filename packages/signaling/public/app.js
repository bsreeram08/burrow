'use strict';
const $ = id => document.getElementById(id);
const status = message => { $('status').textContent = message; $('status').classList?.remove('idle'); };
let roomId = null, token = null, validInvite = false;
let socket, stream, pc, config, sessionId, polite = false, ready = false, makingOffer = false;
let ignoreOffer = false, settingAnswer = false, candidates = [], generation = 0, lifecycle = 0;
let active = false, joining = false, connecting = false, sessionPrepared = false, reconnectTimer, restartTimer, handshakeTimer, reconnectSince = 0, reconnectAttempt = 0, iceRestarts = 0;
let messages = Promise.resolve(), verifyTimer, verified = false;
let dataChannel = null, flushTimer, requestChatFlush = null, chatBusy = false, historyRevision = 0, selectedHistory = '', transcriptSignature = '';
let burnAck = null, peerBurned = false;
// Account conversations keep one stable ChatStore id per contact pair across rooms; guest links use the room id.
let conversationId = null, peerName = 'the other participant', accountChat = false, peerKey = null;
const encoder = new TextEncoder();
const messageIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const chatStatus = text => { $('chat-status').textContent = text; };
// Body data attributes drive layout: lobby, call or chat, plus the open sheet/panel.
const view = (key, value) => { $('app').dataset[key] = value; };
const setJoinable = on => {
  for (const id of ['join', 'join-audio', 'join-chat']) $(id).disabled = !on;
  $('audio-only').disabled = !on || $('chat-only').checked; $('chat-only').disabled = !on;
};
const clock = time => new Date(time).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

function parseInvitation(value) {
  const url = new URL(value);
  if (url.origin !== location.origin || url.pathname !== '/' || url.search || url.username || url.password) throw new Error('Use a personal invitation from this server.');
  const parts = new URLSearchParams(url.hash.slice(1));
  if (parts.getAll('roomId').length !== 1 || parts.getAll('token').length !== 1 || [...parts.keys()].some(key => !['roomId', 'token'].includes(key))) throw new Error('This invitation is incomplete.');
  const id = parts.get('roomId'), credential = parts.get('token');
  if (!/^[A-Za-z0-9_-]{43}$/.test(id || '') || !/^[A-Za-z0-9_-]{43}$/.test(credential || '')) throw new Error('This invitation is incomplete.');
  return { id, credential };
}
function openInvitation(value) {
  if (active || joining || chatBusy) throw new Error('Finish this conversation or message before opening another invitation.');
  const next = parseInvitation(value);
  lifecycle++; roomId = next.id; token = next.credential; validInvite = true; conversationId = selectedHistory = roomId; peerBurned = false; accountChat = false; peerName = 'the other participant';
  $('invitation-input').value = ''; $('invitation-panel').open = false;
  setJoinable(true); window.Theme?.use(conversationId);
  status('Invitation ready. Choose how to join.');
  refreshHistory();
}
function updateComposer() {
  const canCompose = (validInvite || accountChat) && selectedHistory === conversationId && Boolean(window.ChatStore);
  // Never disable the text box while a send is in flight: that drops keyboard focus mid-conversation.
  $('chat-input').disabled = !canCompose;
  $('chat-send').disabled = !canCompose || chatBusy;
  $('burn').disabled = $('conv-burn').disabled = !(validInvite || accountChat) || chatBusy;
  // Attachments, voice, reactions, edits and link previews need an account (blobs and receipts go end to end through it).
  view('rich', accountChat && canCompose ? 'yes' : 'no');
  $('attach').disabled = $('voice-record').disabled = !canCompose || !accountChat;
}
// The transcript is keyed by message id: new rows are appended, statuses change in place and
// removed rows go, so a 5-second poll touches almost nothing and only real changes animate.
// Day separators and uploads still in progress are rows too (keys `day:…` and `pending:…`).
const SVG = 'http://www.w3.org/2000/svg';
let rendered = { conversation: null, rows: new Map() }, tickTemplate = null, shown = new Map(), unseenBelow = 0;
const QUICK_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🙏'], GROUP_GAP = 300000;
const ATTACHMENT_LABEL = { image: '📷 Photo', video: '🎬 Video', audio: '🎵 Audio', voice: '🎤 Voice message', file: '📎 File' };
function svgNode(tag, attributes) { const node = document.createElementNS(SVG, tag); for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value); return node; }
function tickIcon() {
  // Two checks that draw in with stroke-dashoffset, and a small clock for queued messages.
  const svg = svgNode('svg', { class: 'ticks', viewBox: '0 0 18 12', 'aria-hidden': 'true' });
  svg.append(svgNode('path', { class: 'tick-one', d: 'M1.5 6.5l3 3 6-7', pathLength: '1' }), svgNode('path', { class: 'tick-two', d: 'M7.5 9.5l6-7', pathLength: '1' }),
    svgNode('circle', { class: 'tick-clock', cx: '9', cy: '6', r: '4.2' }), svgNode('path', { class: 'tick-clock tick-hand', d: 'M9 3.6V6l1.6 1' }));
  return svg;
}
const element = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
const preference = key => { try { return localStorage.getItem(key) !== 'off'; } catch { return true; } };
const readReceiptsOn = () => preference('read-receipts-v1');
const linkPreviewsOn = () => preference('link-previews-v1');
const shownText = record => record.editedText ?? record.text;
const peerLabel = () => peerName === 'the other participant' ? 'They' : peerName;
const who = record => record.direction === 'outgoing' ? 'You' : peerLabel();
/** Shortens to at most `max` UTF-16 units without splitting a character. */
function clip(text, max) { let out = ''; for (const character of text) { if (out.length + character.length > max) break; out += character; } return out; }
/** One line for a message: quotes, the chat list and the find bar. */
function preview(record) {
  const text = (window.Markdown ? window.Markdown.plainText(shownText(record)) : shownText(record)).replace(/\s+/g, ' ').trim();
  if (text) return text;
  const file = record.attachment;
  return file ? file.kind === 'file' ? `📎 ${file.name || 'File'}` : ATTACHMENT_LABEL[file.kind] : '';
}
function describe(record, flagged) {
  if (record.direction === 'system') return `${record.text} · ${new Date(record.createdAt).toLocaleString()}`;
  const status = record.status === 'read' && !readReceiptsOn() ? 'delivered' : record.status;
  const delivery = { queued: 'Queued on this device', sent: 'Sent · delivery unconfirmed', delivered: 'Delivered to device', read: 'Read', uncertain: 'Restored · delivery unconfirmed' }[status];
  const detail = `${record.direction === 'outgoing' ? 'You' : peerName === 'the other participant' ? 'Other participant' : peerName} · ${new Date(record.createdAt).toLocaleString()} · ${delivery}${record.editedAt ? ` · Edited ${new Date(record.editedAt).toLocaleString()}` : ''}${record.expiresAt ? ' · Disappears ' + new Date(record.expiresAt).toLocaleString() : ''}`;
  return flagged ? `${detail} · Sent under a new security code` : detail;
}
/** Markdown subset with custom emoji in its plain runs; DOM nodes only. */
function renderText(container, text) {
  const runs = run => { if (!window.Emoji) return [document.createTextNode(run)]; const fragment = document.createDocumentFragment(); window.Emoji.render(fragment, run); return [...fragment.childNodes]; };
  if (window.Markdown) window.Markdown.render(container, text, runs); else container.replaceChildren(...runs(text));
}
/** A poll: the question, then one button per option with its tally; your choice is marked and can be changed. */
function paintPoll(container, record) {
  const votes = record.votes || {}, total = Object.values(votes).filter(value => value !== null).length;
  const question = document.createElement('strong'); question.className = 'poll-question'; question.textContent = record.poll.question;
  const options = document.createElement('div'); options.className = 'poll-options'; options.setAttribute('role', 'group'); options.setAttribute('aria-label', `Poll: ${record.poll.question}`);
  record.poll.options.forEach((label, index) => {
    const count = Object.values(votes).filter(value => value === index).length, mine = votes.me === index;
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'poll-option'; button.dataset.poll = record.id; button.dataset.option = String(index);
    button.setAttribute('aria-pressed', String(mine));
    const text = document.createElement('span'); text.className = 'poll-label'; text.textContent = label;
    const tally = document.createElement('span'); tally.className = 'poll-count'; tally.textContent = `${mine ? '✓ ' : ''}${count}`;
    const bar = document.createElement('span'); bar.className = 'poll-bar'; bar.dataset.share = String(total ? Math.round(count / total * 4) : 0);
    button.append(bar, text, tally); options.append(button);
  });
  const note = document.createElement('small'); note.className = 'poll-note'; note.textContent = `${total} of 2 voted · tap to vote or change`;
  container.replaceChildren(question, options, note);
}
function paintQuote(quote, record) {
  const original = shown.get(record.replyTo.id), text = record.replyTo.text || 'Message';
  quote.replaceChildren(...(original ? [element('strong', 'reply-author', who(original))] : []), element('span', 'reply-text', text));
  quote.setAttribute('aria-label', `In reply to ${original ? who(original) : 'a message'}: ${text}.${original ? ' Show the original.' : ''}`);
  quote.disabled = !original;
}
function paintReactions(container, record) {
  const people = new Map();
  for (const person of ['me', 'peer']) for (const emoji of record.reactions?.[person] || []) people.set(emoji, [...people.get(emoji) || [], person]);
  container.replaceChildren(...[...people].map(([emoji, list]) => {
    const button = element('button', 'reaction'), mine = list.includes('me'), names = list.map(person => person === 'me' ? 'You' : peerLabel()).join(' and ');
    button.type = 'button'; button.dataset.emoji = emoji; button.setAttribute('aria-pressed', String(mine));
    button.title = `${names} reacted with ${emoji}`;
    button.setAttribute('aria-label', `${emoji} ${list.length}: ${names}. ${mine ? 'Remove your reaction' : 'React with this too'}`);
    const glyph = element('span', 'reaction-emoji');
    if (window.Emoji) window.Emoji.render(glyph, emoji); else glyph.textContent = emoji;
    button.append(glyph, element('span', 'reaction-count', String(list.length)));
    return button;
  }));
  container.hidden = people.size === 0;
}
function paintRow(row, record) {
  // Messages that arrived under a changed security code stay marked until the code is reviewed.
  const flagged = Boolean(window.App?.flagged?.(record)), status = record.status === 'read' && !readReceiptsOn() ? 'delivered' : record.status;
  const quoted = record.replyTo ? shown.get(record.replyTo.id)?.direction || '-' : '';
  const key = `${status}|${flagged}|${record.createdAt}|${shownText(record)}|${record.editedAt || ''}|${JSON.stringify(record.votes || null)}|${JSON.stringify(record.reactions || null)}|${quoted}|${peerName}|${window.Emoji?.revision || 0}`;
  if (row.dataset.paint === key) return;
  row.dataset.paint = key; row.dataset.status = status; row.classList.toggle('flagged', flagged);
  const body = row.querySelector('.message-text'), text = shownText(record);
  delete row.dataset.emoji;
  if (record.kind === 'poll') paintPoll(body, record);
  // An action reads as a sentence on both sides ("alice waves"); a guest's own line, with no username, reads "You: waves".
  else if (record.kind === 'action') body.textContent = record.direction === 'outgoing' ? `${window.App?.myName || 'You:'} ${text}` : `${who(record)} ${text}`;
  else if (record.direction !== 'system') {
    if (text) renderText(body, text); else body.replaceChildren(); // An attachment alone: no text block.
    const size = window.Emoji && !record.attachment ? window.Emoji.size(text) : '';
    if (size) row.dataset.emoji = size;
    // A `:name:` this device does not know yet may be a custom emoji someone just added: refresh the pack.
    if (/:[a-z0-9_+-]{2,32}:/.test(text) && window.Emoji && !body.querySelector('.custom-emoji')) window.App?.onUnknownEmoji?.();
  }
  else body.textContent = text; // System lines can be updated in place.
  const head = row.querySelector('.msg-head'); if (head) head.textContent = peerLabel();
  const quote = row.querySelector('.reply-quote'); if (quote) paintQuote(quote, record);
  const reactions = row.querySelector('.reactions'); if (reactions) paintReactions(reactions, record);
  const label = describe(record, flagged); row.title = label;
  const meta = row.querySelector('.message-meta'); meta.setAttribute('aria-label', label);
  meta.querySelector('.meta-text').textContent = `${flagged ? '⚠ ' : ''}${record.expiresAt ? '⏱ ' : ''}${record.editedAt ? 'edited · ' : ''}${clock(record.createdAt)}${record.direction === 'outgoing' && record.status === 'uncertain' ? ' ?' : ''}`;
}
function buildRow(record, animate) {
  const row = document.createElement('li'); row.className = record.direction;
  if (record.kind) row.classList.add(`kind-${record.kind}`);
  if (record.attachment) row.classList.add('has-attachment', `attachment-${record.attachment.kind}`);
  if (animate) row.classList.add('enter');
  row.dataset.messageId = record.id;
  if (record.direction === 'incoming') { const head = element('span', 'msg-head'); head.dataset.name = String(window.Theme?.nameIndex?.(peerKey || peerName) ?? 0); row.append(head); }
  if (record.replyTo) { const quote = element('button', 'reply-quote'); quote.type = 'button'; quote.dataset.target = record.replyTo.id; row.append(quote); }
  if (record.attachment) row.append(attachmentNode(record));
  const text = document.createElement('div'); text.className = 'message-text';
  row.append(text);
  if (record.link) row.append(linkCard(record.link));
  const meta = document.createElement('small'); meta.className = 'message-meta';
  const metaText = document.createElement('span'); metaText.className = 'meta-text'; meta.append(metaText);
  if (record.direction === 'outgoing') meta.append((tickTemplate ||= tickIcon()).cloneNode(true));
  row.append(meta);
  if (record.direction !== 'system') { const reactions = element('div', 'reactions'); reactions.hidden = true; reactions.setAttribute('role', 'group'); reactions.setAttribute('aria-label', 'Reactions'); row.append(reactions); }
  paintRow(row, record);
  return row;
}
const dayKey = time => { const date = new Date(time); return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`; };
function dayLabel(time) {
  const date = new Date(time), today = new Date(); today.setHours(0, 0, 0, 0);
  const start = new Date(date); start.setHours(0, 0, 0, 0);
  const days = Math.round((today - start) / 86400000);
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days > 1 && days < 7) return date.toLocaleDateString([], { weekday: 'long' });
  return date.toLocaleDateString([], { weekday: 'short', month: 'long', day: 'numeric', year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
}
/** Consecutive messages from the same sender within 5 minutes share one header; only the last has the tail. */
const sameGroup = (a, b) => Boolean(a && b) && a.direction === b.direction && a.direction !== 'system' && b.createdAt - a.createdAt < GROUP_GAP && dayKey(a.createdAt) === dayKey(b.createdAt);
function renderTranscript(visible) {
  const log = $('chat-log'), wasNearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
  // A different conversation (or a forced refresh) is a fresh, motionless render.
  const fresh = rendered.conversation !== selectedHistory || transcriptSignature === '';
  if (fresh) {
    log.replaceChildren(); rendered = { conversation: selectedHistory, rows: new Map() }; transcriptSignature = 'live'; unseenBelow = 0;
    // Placeholder images belong to the rows just removed: release their blob: URLs (the composer's preview keeps its own).
    for (const [data, url] of thumbUrls) if (data !== linkDraft?.link?.thumb) { URL.revokeObjectURL(url); thumbUrls.delete(data); }
  }
  shown = new Map(visible.map(record => [record.id, record]));
  const keep = new Set();
  let previous = null, added = 0;
  const place = (key, row) => {
    keep.add(key);
    // Keep document order equal to message order with the fewest moves (normally none).
    if ((previous ? previous.nextSibling : log.firstChild) !== row) log.insertBefore(row, previous ? previous.nextSibling : log.firstChild);
    previous = row;
  };
  visible.forEach((record, index) => {
    const before = visible[index - 1];
    if (!before || dayKey(before.createdAt) !== dayKey(record.createdAt)) {
      const key = `day:${dayKey(record.createdAt)}`;
      let separator = rendered.rows.get(key);
      if (!separator) { separator = element('li', 'day'); separator.setAttribute('role', 'separator'); rendered.rows.set(key, separator); }
      const label = dayLabel(record.createdAt); if (separator.textContent !== label) separator.textContent = label;
      place(key, separator);
    }
    let row = rendered.rows.get(record.id);
    if (!row) { row = buildRow(record, !fresh); rendered.rows.set(record.id, row); if (!fresh && record.direction === 'incoming') added++; }
    else paintRow(row, record);
    row.classList.toggle('cont', sameGroup(before, record));
    row.classList.toggle('tail', !sameGroup(record, visible[index + 1]));
    place(record.id, row);
  });
  for (const item of uploads.values()) {
    if (item.conversation !== selectedHistory) continue;
    const key = `pending:${item.id}`;
    let row = rendered.rows.get(key);
    if (!row) { row = pendingRow(item); rendered.rows.set(key, row); }
    paintPending(row, item); place(key, row);
  }
  for (const [id, row] of rendered.rows) if (!keep.has(id)) { row.remove(); rendered.rows.delete(id); }
  if (fresh || wasNearBottom) log.scrollTop = log.scrollHeight;
  else unseenBelow += added;
  updateJump();
  if (!$('find-bar').hidden) runFind(false);
  window.App?.onDisplayed?.();
}
async function refreshHistory() {
  const revision = ++historyRevision;
  try {
    if (!window.ChatStore) throw new Error('Local message storage is unavailable.');
    const records = await window.ChatStore.list();
    if (revision !== historyRevision) return;
    const ids = [...new Set(records.map(record => record.conversationId))].reverse(), lastAt = new Map();
    for (const record of records) lastAt.set(record.conversationId, Math.max(lastAt.get(record.conversationId) || 0, record.createdAt));
    if (conversationId && !ids.includes(conversationId)) ids.unshift(conversationId);
    if (!selectedHistory || !ids.includes(selectedHistory)) selectedHistory = conversationId || ids[0] || '';
    const selector = $('history-select'); selector.replaceChildren();
    if (!ids.length) selector.add(new Option('No conversations yet', ''));
    for (const id of ids) selector.add(new Option(id === conversationId ? 'This conversation' : `Earlier conversation — ${new Date(lastAt.get(id)).toLocaleDateString([], { month: 'short', day: 'numeric' })}, ${clock(lastAt.get(id))}`, id));
    view('history', ids.length ? 'yes' : 'no');
    selector.value = selectedHistory;
    renderTranscript(records.filter(record => record.conversationId === selectedHistory).slice(-2000));
    updateComposer();
  } catch (error) { chatStatus(error.message || 'Could not read local history.'); $('chat-input').disabled = true; $('chat-send').disabled = true; }
}
function detachChat() {
  clearTimeout(flushTimer); flushTimer = undefined;
  requestChatFlush = null;
  const previous = dataChannel; dataChannel = null;
  if (previous) { previous.onclose = null; previous.close(); }
  chatStatus(accountChat ? '' : 'Messages stay on this device. Queued messages need both participants connected with a valid invitation.');
}
function attachChat(peer, channel) {
  if (pc !== peer || !active || channel.label !== 'chat-v1' || !channel.ordered || channel.maxRetransmits !== null || channel.maxPacketLifeTime !== null || dataChannel) { channel.close(); return; }
  dataChannel = channel;
  const current = generation, conversation = conversationId, sent = new Set(), pendingAcks = new Set();
  let queue = Promise.resolve(), queued = 0, windowStart = Date.now(), count = 0, flushing = false, pendingWake = false;
  const isCurrent = () => active && pc === peer && dataChannel === channel && generation === current;
  const fail = text => { if (isCurrent()) { channel.close(); chatStatus(text); } };
  const transmit = packet => {
    if (!isCurrent() || channel.readyState !== 'open' || channel.bufferedAmount > 65536) return false;
    channel.send(JSON.stringify(packet)); return true;
  };
  function scheduleFlush(delay = 0) {
    if (!isCurrent() || channel.readyState !== 'open') return;
    pendingWake = true;
    if (!flushing && !flushTimer) flushTimer = setTimeout(flush, delay);
  }
  requestChatFlush = scheduleFlush;
  async function flush() {
    flushTimer = undefined;
    if (!isCurrent() || channel.readyState !== 'open') return;
    flushing = true; pendingWake = false;
    let more = false;
    try {
      // A stored incoming message must not lose its acknowledgment merely because
      // the channel is temporarily full. Drain bounded priority batches first.
      more = pendingAcks.size > 0;
      for (const id of [...pendingAcks].slice(0, 16)) {
        if (!transmit({ v: 1, type: 'ack', id })) return;
        pendingAcks.delete(id);
      }
      more = pendingAcks.size > 0;
      if (more) return;
      const records = await window.ChatStore.list();
      if (!isCurrent()) return;
      if (pendingAcks.size) { more = true; return; }
      const pending = records.filter(record => record.conversationId === conversation && record.direction === 'outgoing' && ['queued', 'sent'].includes(record.status) && !sent.has(record.id));
      const next = pending[0];
      more = Boolean(next); // Keep bounded retries while channel backpressure prevents sending.
      if (next && transmit(messagePayload(next))) {
        sent.add(next.id);
        more = pending.length > 1;
        await window.ChatStore.setStatus(conversation, next.id, 'sent');
        refreshHistory();
      }
    } catch (error) { if (isCurrent()) chatStatus(error.message || 'Could not send a saved message.'); }
    finally {
      flushing = false;
      // An enqueue during either storage await must not lose its wake-up.
      if (isCurrent() && (more || pendingWake)) scheduleFlush(100);
    }
  }
  channel.bufferedAmountLowThreshold = 32768;
  channel.onbufferedamountlow = () => { if (isCurrent()) scheduleFlush(); };
  channel.onopen = () => { if (isCurrent()) { chatStatus('Encrypted device-to-device chat connected.'); scheduleFlush(); } };
  channel.onclose = () => { if (isCurrent()) { dataChannel = null; requestChatFlush = null; clearTimeout(flushTimer); flushTimer = undefined; chatStatus('Chat disconnected. New messages will wait on this device.'); } };
  channel.onerror = () => { if (isCurrent()) chatStatus('Chat connection interrupted. Messages remain on this device.'); };
  channel.onmessage = event => {
    if (!isCurrent()) return;
    if (Date.now() - windowStart >= 10000) { windowStart = Date.now(); count = 0; }
    if (++count > 240 || queued >= 128 || typeof event.data !== 'string' || encoder.encode(event.data).length > 32768) { fail('Chat closed because the peer exceeded message limits.'); return; }
    queued++;
    queue = queue.then(async () => {
      if (!isCurrent()) return;
      const packet = JSON.parse(event.data);
      if (packet?.v === 1 && Object.keys(packet).length === 2 && packet.type === 'burned') { burnAck?.(); return; }
      if (packet?.type === 'vote') {
        let type; try { type = window.ChatStore.checkPayload(packet); } catch { type = null; }
        if (type !== 'vote') throw new Error('Invalid chat packet');
        await window.ChatStore.vote(conversation, packet.poll, 'peer', packet.option); refreshHistory(); return;
      }
      if (packet?.v === 1 && Object.keys(packet).length === 2 && packet.type === 'burn') {
        // The other participant burned the conversation: delete our copy and confirm.
        peerBurned = true;
        await window.ChatStore.removeConversation(conversation);
        if (isCurrent()) transmit({ v: 1, type: 'burned' });
        status('The other person burned this conversation. It was deleted on this device.');
        refreshHistory(); return;
      }
      if (!packet || packet.v !== 1 || !messageIdPattern.test(packet.id || '') || !['message', 'ack'].includes(packet.type)) throw new Error('Invalid chat packet');
      const records = await window.ChatStore.list();
      if (!isCurrent()) return;
      const existing = records.find(record => record.id === packet.id && record.conversationId === conversation);
      if (packet.type === 'ack') {
        if (existing?.direction === 'outgoing' && sent.has(packet.id)) { await window.ChatStore.setStatus(conversation, existing.id, 'delivered'); refreshHistory(); }
        return;
      }
      if (typeof packet.text !== 'string' || !packet.text.trim() || encoder.encode(packet.text).length > 4096 || !Number.isSafeInteger(packet.createdAt) || packet.createdAt < 0 || packet.createdAt > Date.now() + 300000 || !(packet.expiresAt === null || Number.isSafeInteger(packet.expiresAt) && packet.expiresAt > packet.createdAt && packet.expiresAt <= packet.createdAt + 2592000000)) throw new Error('Invalid chat message');
      if (packet.expiresAt !== null && packet.expiresAt <= Date.now()) return;
      let shape; try { shape = window.ChatStore.checkPayload(packet); } catch { shape = null; }
      if (shape !== 'message') throw new Error('Invalid chat message');
      const rich = packet.kind === 'poll' ? { kind: 'poll', poll: packet.poll } : packet.kind ? { kind: packet.kind } : {};
      if (packet.replyTo !== undefined) rich.replyTo = packet.replyTo;
      if (packet.attachment !== undefined || packet.link !== undefined) throw new Error('Invalid chat message'); // Account chats only.
      const record = { id: packet.id, conversationId: conversation, direction: 'incoming', text: packet.text, createdAt: packet.createdAt, status: 'delivered', expiresAt: packet.expiresAt, ...rich };
      if (existing && (existing.direction !== 'incoming' || existing.text !== record.text || existing.createdAt !== record.createdAt || existing.expiresAt !== record.expiresAt || existing.kind !== record.kind)) throw new Error('Conflicting message identifier');
      try { await window.ChatStore.put(record); } catch (error) { throw existing ? error : new Error('Invalid chat message'); }
      if (!isCurrent()) return;
      // The acknowledgment means durable receiver storage, never merely arrival.
      // Deduplicate and bound the queue; ordinary channel backpressure is retried.
      if (!pendingAcks.has(packet.id) && pendingAcks.size >= 128) throw new Error('Too many pending chat acknowledgments');
      pendingAcks.add(packet.id); scheduleFlush();
      refreshHistory();
    }).catch(error => fail(error.message === 'Invalid chat packet' || error.message === 'Invalid chat message' || error.message === 'Conflicting message identifier' ? 'Chat closed because a message was invalid.' : 'Chat could not save a message. Check local storage capacity.')).finally(() => { queued--; });
  };
  if (channel.readyState === 'open') channel.onopen();
}

/**
 * The wire form of a stored outgoing message: plain, a /me action or a poll, with its reply, attachment and link
 * preview (votes and reactions stay local). A message edited before it ever left this device goes out edited.
 */
function messagePayload(record) {
  const text = record.status === 'queued' && record.editedText !== undefined ? record.editedText : record.text;
  const payload = { v: 1, type: 'message', id: record.id, text, createdAt: record.createdAt, expiresAt: record.expiresAt };
  if (record.kind) payload.kind = record.kind;
  if (record.kind === 'poll') payload.poll = record.poll;
  if (record.replyTo) payload.replyTo = record.replyTo;
  if (record.attachment) payload.attachment = record.attachment;
  if (record.link && text.includes(record.link.url)) payload.link = record.link;
  return payload;
}
function send(message) {
  if (socket?.readyState !== WebSocket.OPEN) return false;
  if (message.type === 'description' || message.type === 'candidate') {
    if (!sessionId) return false;
    message = { ...message, sessionId };
  }
  socket.send(JSON.stringify(message));
  return true;
}
function closePeer() {
  generation++;
  detachChat();
  clearTimeout(restartTimer); restartTimer = undefined;
  if (pc) { pc.onconnectionstatechange = null; pc.close(); }
  pc = null; sessionId = null; ready = false; candidates = [];
  makingOffer = false; ignoreOffer = false; settingAnswer = false; iceRestarts = 0;
  $('remote').srcObject = null; updateMediaView();
  clearTimeout(verifyTimer); verifyTimer = undefined;
  $('verify-code').hidden = true; $('verify-digits').textContent = ''; $('verify-label').textContent = '';
}
/** Layout follows the live video on each side: a camera that is off (or never captured) shows an avatar instead of black video. */
function updateMediaView() {
  const local = Boolean(stream?.getVideoTracks().some(track => track.readyState === 'live' && track.enabled));
  const remote = Boolean($('remote').srcObject?.getVideoTracks?.().some(track => track.readyState === 'live' && !track.muted));
  view('local', local ? 'on' : 'off'); view('remote', remote ? 'on' : 'off');
  view('media', local || remote ? 'video' : 'audio');
}
function cleanup(message) {
  active = false; sessionPrepared = false; lifecycle++;
  clearTimeout(reconnectTimer); reconnectTimer = undefined;
  clearTimeout(handshakeTimer); handshakeTimer = undefined;
  closePeer();
  stream?.getTracks().forEach(track => track.stop()); stream = null;
  $('local').srcObject = null;
  const previous = socket; socket = null; previous?.close();
  for (const id of ['mute', 'camera', 'hangup']) $(id).disabled = true;
  $('play').hidden = true; joining = false; connecting = false; reconnectSince = 0; reconnectAttempt = 0;
  $('invitation-load').disabled = false; $('invitation-input').disabled = false;
  view('state', 'lobby'); view('sheet', ''); view('panel', ''); $('chat-toggle').setAttribute('aria-expanded', 'false');
  status(message);
  window.App?.onEnd?.();
}
function matchesGeneration(peer, candidate) {
  return !candidate?.usernameFragment || peer.remoteDescription?.sdp.split('\r\n')
    .some(line => line === 'a=ice-ufrag:' + candidate.usernameFragment);
}
function recoverIce(peer, immediate = false) {
  if (pc !== peer || !active || !ready || socket?.readyState !== WebSocket.OPEN || restartTimer) return;
  const current = generation;
  restartTimer = setTimeout(() => {
    restartTimer = undefined;
    if (current !== generation || !active || socket?.readyState !== WebSocket.OPEN) return;
    const broken = ['failed', 'disconnected'].includes(peer.connectionState);
    if (!immediate && !broken) return;
    if (broken && iceRestarts >= 3) { cleanup('The connection could not recover. Reopen your invitation to try again.'); return; }
    // A healthy connection can renegotiate without emitting another connected
    // event. Do not charge these refreshes against the failed-recovery budget.
    iceRestarts = broken ? iceRestarts + 1 : 0;
    if (broken) status('Connection interrupted. Reconnecting your call…');
    peer.restartIce();
  }, immediate ? 0 : polite ? 6000 : 3000);
}
function createPeer() {
  const peer = new RTCPeerConnection(config); pc = peer;
  for (const track of stream?.getTracks() || []) peer.addTrack(track, stream);
  peer.ondatachannel = ({ channel }) => {
    // Contact chats travel through the end-to-end encrypted mailbox, not the call's data channel.
    if (pc !== peer || !polite || accountChat) { channel.close(); return; }
    attachChat(peer, channel);
  };
  peer.onicecandidate = ({ candidate }) => { if (pc === peer) send({ type: 'candidate', candidate }); };
  peer.ontrack = ({ track, streams }) => {
    if (pc !== peer) return;
    const remote = streams[0] || $('remote').srcObject || new MediaStream();
    if (!remote.getTracks().includes(track)) remote.addTrack(track);
    $('remote').srcObject = remote;
    // A peer that answers audio only, or turns its camera on later, flips the layout without renegotiating UI.
    track.onmute = track.onunmute = track.onended = () => { if (pc === peer) updateMediaView(); };
    updateMediaView();
    $('remote').play().catch(() => { if (pc === peer) $('play').hidden = false; });
  };
  peer.onconnectionstatechange = () => {
    if (pc !== peer) return;
    if (peer.connectionState === 'connected') {
      clearTimeout(restartTimer); restartTimer = undefined; iceRestarts = 0;
      status(stream ? 'Connected — your call is live.' : 'Connected — chat is end-to-end encrypted.');
      if (!verified && !verifyTimer) verifyTimer = setTimeout(() => { verifyTimer = undefined; if (pc === peer && !verified) showVerification('warn', 'Could not verify — treat this call as untrusted and end it.'); }, 15000);
    } else if (['disconnected', 'failed'].includes(peer.connectionState)) {
      status('Connection interrupted. Reconnecting your call…');
      recoverIce(peer);
    }
  };
  peer.onnegotiationneeded = async () => {
    if (!ready || pc !== peer || socket?.readyState !== WebSocket.OPEN) return;
    if (polite && !peer.remoteDescription) return;
    try {
      makingOffer = true;
      await peer.setLocalDescription();
      if (pc === peer) send({ type: 'description', description: peer.localDescription });
    } catch { if (pc === peer) cleanup('Could not negotiate this call. Reopen your invitation to try again.'); }
    finally { if (pc === peer) makingOffer = false; }
  };
  if (!polite && !accountChat) attachChat(peer, peer.createDataChannel('chat-v1', { ordered: true }));
  // Fail closed: no code (missing script, blocked channel, timeout) is shown as an untrusted call.
  const showVerification = (kind, label, code = '') => {
    if (pc !== peer) return;
    const badge = $('verify-code'); badge.hidden = false; badge.dataset.kind = kind;
    $('verify-digits').textContent = code; $('verify-label').textContent = label;
    badge.title = code ? `Verification code ${code}. Read it aloud with the other person. If it doesn't match, end the call: someone is in the middle.` : label;
  };
  verified = false;
  if (!window.Verify) showVerification('warn', 'Verification unavailable — treat this call as untrusted.');
  else {
    showVerification('pending', 'Verifying this call…');
    window.Verify.attach(peer, peer.createDataChannel('verify-v1', { negotiated: true, id: 1000, ordered: true }), result => {
      if (pc !== peer) return;
      verified = Boolean(result.code); clearTimeout(verifyTimer); verifyTimer = undefined;
      if (result.code) showVerification('ok', 'Same code on their screen? No one is listening in.', result.code);
      else showVerification('warn', result.error);
    });
  }
  return peer;
}
async function receive(message) {
  if (message.type === 'welcome') {
    // The server retires the invitation on every accepted connection; keep only the fresh credential.
    if (typeof message.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(message.token)) throw new Error('Invalid welcome');
    token = message.token; polite = message.polite; reconnectSince = 0; reconnectAttempt = 0; return;
  }
  if (message.type === 'ready') {
    closePeer(); sessionId = message.sessionId; ready = true; createPeer(); window.App?.onPeerJoined?.();
    status(`Connecting to ${peerName}…`); return;
  }
  if (message.type === 'peer-left') { closePeer(); status(`${peerName[0].toUpperCase() + peerName.slice(1)} disconnected. Waiting for them to return…`); return; }
  if (message.type === 'error') {
    // These refer to a retired pairing; its messages must not affect the new one.
    if (message.error !== 'Stale session') status(`Waiting for ${peerName} to reconnect…`);
    return;
  }
  const peer = pc, current = generation;
  if (!peer || !ready || message.sessionId !== sessionId) return;
  if (message.type === 'description') {
    const description = message.description;
    const offerCollision = description.type === 'offer' && (makingOffer || !(peer.signalingState === 'stable' || settingAnswer));
    ignoreOffer = !polite && offerCollision;
    if (ignoreOffer) { candidates = []; return; }
    settingAnswer = description.type === 'answer';
    try { await peer.setRemoteDescription(description); }
    finally { if (current === generation) settingAnswer = false; }
    if (current !== generation) return;
    for (const candidate of candidates.splice(0)) {
      if (matchesGeneration(peer, candidate)) await peer.addIceCandidate(candidate);
      if (current !== generation) return;
    }
    if (description.type === 'offer') {
      await peer.setLocalDescription();
      if (current === generation) send({ type: 'description', description: peer.localDescription });
    }
  } else if (message.type === 'candidate' && !ignoreOffer) {
    if (!peer.remoteDescription || !matchesGeneration(peer, message.candidate)) {
      // A new ICE generation can arrive before its SDP; keep a bounded queue.
      if (candidates.length >= 128) throw new Error('Too many pending candidates');
      candidates.push(message.candidate);
    } else await peer.addIceCandidate(message.candidate);
  }
}
function scheduleReconnect() {
  if (!active || reconnectTimer) return;
  reconnectSince ||= Date.now();
  if (Date.now() - reconnectSince >= 90000) {
    cleanup('Unable to reconnect. Reopen your invitation when your connection returns.'); return;
  }
  status(stream ? 'Call connection lost. Reconnecting… Your camera and microphone remain on locally.' : 'Chat connection lost. Reconnecting… Messages remain on this device.');
  const current = lifecycle;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = undefined;
    if (active && current === lifecycle) connectSocket(current);
  }, Math.min(500 * 2 ** Math.min(reconnectAttempt++, 4), 8000));
}
async function loadIce(current, attempt = 0) {
  const response = await fetch(`/rooms/${roomId}/ice`, {
    headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: AbortSignal.timeout(10000),
  });
  if (!active || current !== lifecycle) return false;
  // Devices sharing one address (home Wi-Fi) can briefly hit the per-source limit; retry a few times.
  if (response.status === 429 && attempt < 3) { await new Promise(resolve => setTimeout(resolve, 700 * (attempt + 1))); return loadIce(current, attempt + 1); }
  if (response.status === 401) { validInvite = false; token = null; updateComposer(); cleanup('Call ended or invitation expired. Request a new invitation to call again.'); return false; }
  if (!response.ok) throw new Error(`Call server unavailable (HTTP ${response.status})`);
  const next = await response.json();
  if (!active || current !== lifecycle) return false;
  config = next;
  return true;
}
async function connectSocket(current) {
  if (!active || !sessionPrepared || current !== lifecycle || connecting || socket && socket.readyState < WebSocket.CLOSING) return;
  connecting = true;
  try {
    if (!await loadIce(current)) return;
    const connection = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/rooms/${roomId}/socket`, ['webrtc', token]);
    socket = connection;
    handshakeTimer = setTimeout(() => {
      if (!active || socket !== connection || connection.readyState !== WebSocket.CONNECTING) return;
      handshakeTimer = undefined; socket = null;
      connection.close(); scheduleReconnect();
    }, 10000);
    connection.onopen = () => {
      if (socket !== connection) return;
      clearTimeout(handshakeTimer); handshakeTimer = undefined;
      status(accountChat && stream ? `Calling ${peerName}…` : `Waiting for ${peerName}…`);
    };
    connection.onmessage = event => {
      messages = messages.then(() => { if (active && socket === connection) return receive(JSON.parse(event.data)); }).catch(() => {
        if (active && socket === connection) cleanup('Call negotiation failed. Reopen your invitation to try again.');
      });
    };
    connection.onclose = event => {
      if (!active || socket !== connection) return;
      clearTimeout(handshakeTimer); handshakeTimer = undefined;
      socket = null; closePeer();
      if ([1000, 1008, 4001, 4002].includes(event.code)) {
        // 4001: the pair's room was replaced by a newer call; 4002: the call was declined.
        validInvite = false; token = null; updateComposer();
        cleanup(peerBurned ? 'The other person burned this conversation. It was deleted on this device.' : event.code === 4002 ? `${peerName[0].toUpperCase() + peerName.slice(1)} declined the call.` : event.code === 4001 ? 'Switched to a new call.' : accountChat ? 'Conversation ended.' : 'Call ended or invitation expired. Request a new invitation to call again.');
      }
      else scheduleReconnect();
    };
    // The close event carries the reconnect decision; errors must not race it.
    connection.onerror = () => {};
  } catch {
    if (active && current === lifecycle) scheduleReconnect();
  } finally { if (current === lifecycle) connecting = false; }
}
$('join-form').addEventListener('submit', event => { event.preventDefault(); return join(event.submitter?.value); });
async function join(choice) {
  if (joining || !validInvite) return;
  if (choice) { $('chat-only').checked = choice === 'chat'; $('audio-only').checked = choice === 'audio'; }
  joining = true; active = true; sessionPrepared = false; const current = ++lifecycle;
  setJoinable(false); $('hangup').disabled = false;
  view('state', $('chat-only').checked ? 'chat' : 'call'); view('media', $('audio-only').checked ? 'audio' : 'video');
  $('invitation-load').disabled = true; $('invitation-input').disabled = true;
  status($('chat-only').checked ? 'Preparing your chat connection…' : 'Preparing your microphone and call connection…');
  try {
    if (!await loadIce(current)) return;
    if (!$('chat-only').checked) {
      const acquired = await navigator.mediaDevices.getUserMedia({ audio: true, video: !$('audio-only').checked });
      if (!active || current !== lifecycle) { acquired.getTracks().forEach(track => track.stop()); return; }
      stream = acquired; $('local').srcObject = stream;
    }
    updateMediaView();
    if (!active || current !== lifecycle) return;
    sessionPrepared = true;
    // The camera button stays usable on audio-only calls: it can capture and add video later.
    $('mute').disabled = !stream; $('camera').disabled = !stream;
    $('mute').setAttribute('aria-pressed', 'false'); $('mute').setAttribute('aria-label', 'Mute microphone'); $('mute-cap').textContent = 'Mute';
    setCameraButton(!stream?.getVideoTracks().length);
    await connectSocket(current);
  } catch (error) {
    if (current !== lifecycle) return;
    cleanup(error.name === 'NotAllowedError' ? 'Microphone or camera permission denied. Allow access, then try again.' : error.name === 'NotFoundError' ? 'No microphone or camera found. Connect a device or try audio only.' : 'Unable to join. Check your invitation, connection, and media permissions.');
    setJoinable(!accountChat);
  }
}
$('mute').onclick = () => {
  const muted = $('mute').getAttribute('aria-pressed') !== 'true';
  stream?.getAudioTracks().forEach(track => { track.enabled = !muted; });
  $('mute').setAttribute('aria-pressed', String(muted)); $('mute').setAttribute('aria-label', muted ? 'Unmute microphone' : 'Mute microphone'); $('mute-cap').textContent = muted ? 'Unmute' : 'Mute';
};
function setCameraButton(off) {
  $('camera').setAttribute('aria-pressed', String(off)); $('camera').setAttribute('aria-label', off ? 'Turn camera on' : 'Turn camera off'); $('camera-cap').textContent = off ? 'Camera on' : 'Camera';
}
$('camera').onclick = async () => {
  if (!stream) return;
  if (!stream.getVideoTracks().length) {
    // Joined audio only: capture the camera now (this tap is the consent) and renegotiate to send it.
    const current = lifecycle; $('camera').disabled = true;
    try {
      const track = (await navigator.mediaDevices.getUserMedia({ video: true })).getVideoTracks()[0];
      if (!active || current !== lifecycle || !stream) { track.stop(); return; }
      stream.addTrack(track); $('local').srcObject = null; $('local').srcObject = stream;
      if (pc) pc.addTrack(track, stream);
      setCameraButton(false);
    } catch { status('Camera unavailable. Check the camera permission and try again.'); }
    finally { if (current === lifecycle) $('camera').disabled = false; updateMediaView(); }
    return;
  }
  const off = $('camera').getAttribute('aria-pressed') !== 'true';
  stream.getVideoTracks().forEach(track => { track.enabled = !off; });
  setCameraButton(off); updateMediaView();
};
$('play').onclick = () => $('remote').play().then(() => { $('play').hidden = true; }).catch(() => status('Use your browser’s audio controls to allow playback.'));
async function endRoom(ended) {
  // Stop capture immediately, including when signaling or a permission prompt is pending.
  const endingRoom = roomId, endingToken = token;
  cleanup('Call stopped. Ending the room…');
  const stoppedLifecycle = lifecycle;
  validInvite = false; token = null; updateComposer();
  try {
    const response = await fetch(`/rooms/${endingRoom}`, { method: 'DELETE', headers: { Authorization: `Bearer ${endingToken}` }, signal: AbortSignal.timeout(5000) });
    if (stoppedLifecycle === lifecycle) status(response.ok || response.status === 401 ? ended : 'Call stopped locally. Could not confirm the room ended.');
  } catch { if (stoppedLifecycle === lifecycle) status('Call stopped locally. Could not end the room while offline.'); }
}
$('hangup').onclick = () => endRoom('Call ended.');
$('burn').onclick = () => { $('menu').open = false; $('burn-confirm').hidden = false; };
$('settings-open').onclick = () => { $('menu').open = false; $('settings').open = true; view('panel', 'settings'); };
$('settings-close').onclick = () => view('panel', '');
// Collapsing Settings (e.g. from the chat list) must also drop its sheet, or it stays over the next chat.
$('settings').addEventListener('toggle', () => { if (!$('settings').open) view('panel', ''); });
const toggleChat = open => {
  view('sheet', open ? 'open' : ''); $('chat-toggle').setAttribute('aria-expanded', String(open));
  if (open) { const log = $('chat-log'); log.scrollTop = log.scrollHeight; }
};
$('chat-toggle').onclick = () => toggleChat($('app').dataset.sheet !== 'open');
$('chat-close').onclick = () => toggleChat(false);
$('burn-cancel').onclick = () => { $('burn-confirm').hidden = true; };
$('burn-confirm-yes').onclick = async () => {
  $('burn-confirm').hidden = true;
  if (accountChat && window.App?.onBurn && !chatBusy) {
    chatBusy = true; updateComposer();
    try { await window.App.onBurn(); }
    catch (error) { chatStatus(error.message || 'Could not burn this conversation.'); }
    finally { chatBusy = false; updateComposer(); refreshHistory(); }
    return;
  }
  if (!validInvite || chatBusy) return;
  chatBusy = true; updateComposer();
  const conversation = conversationId;
  let confirmed = false;
  try {
    if (dataChannel?.readyState === 'open') {
      // Wait briefly for the other device to confirm deletion before the room closes the channel.
      dataChannel.send(JSON.stringify({ v: 1, type: 'burn' }));
      confirmed = await new Promise(resolve => { burnAck = () => resolve(true); setTimeout(() => resolve(false), 2000); });
      burnAck = null;
    }
    await endRoom(confirmed ? 'Conversation burned on both devices. The room is closed.' : 'Conversation burned on this device. The other device did not confirm. The room is closed.');
    await window.ChatStore.removeConversation(conversation);
  } catch (error) { status(error.message || 'Could not burn this conversation.'); }
  finally { chatBusy = false; updateComposer(); refreshHistory(); }
};
window.addEventListener('online', () => {
  if (!active || !sessionPrepared) return;
  if (socket?.readyState !== WebSocket.OPEN) {
    clearTimeout(reconnectTimer); reconnectTimer = undefined; scheduleReconnect();
  } else if (pc) recoverIce(pc, true);
});
window.addEventListener('pagehide', () => cleanup('Call closed.'));
$('invitation-form').addEventListener('submit', event => {
  event.preventDefault();
  try { openInvitation($('invitation-input').value.trim()); }
  catch (error) { status(error.message); }
});
window.addEventListener('hashchange', () => {
  const incoming = location.href; history.replaceState(null, '', location.pathname);
  const invite = new URLSearchParams(new URL(incoming).hash.slice(1)).get('invite');
  if (invite) { window.pendingAccountInvite = invite; window.App?.onInvite?.(invite); return; }
  try { openInvitation(incoming); } catch (error) { status(error.message); }
});
$('history-select').onchange = () => { selectedHistory = $('history-select').value; refreshHistory(); };
/** Saves an outgoing message (plain, /me action, poll or attachment) and hands it to the right transport. */
async function queueMessage({ text, kind, poll, replyTo, attachment, link }) {
  if (!kind && window.Emoji) text = window.Emoji.expand(text); // ":smile:" becomes 😄 on send; custom ones stay as :name:.
  if (!text.trim() && !attachment || encoder.encode(text).length > 4096) throw new Error('Enter a message up to 4096 UTF-8 bytes.');
  const createdAt = Date.now(), duration = Number($('disappear').value) || 0;
  const rich = kind === 'poll' ? { kind, poll } : kind ? { kind } : {};
  if (replyTo) rich.replyTo = replyTo;
  if (attachment) rich.attachment = attachment;
  if (link && text.includes(link.url)) rich.link = link;
  await window.ChatStore.put({ id: crypto.randomUUID(), conversationId, direction: 'outgoing', text, createdAt, status: 'queued', expiresAt: duration ? createdAt + duration : null, ...rich });
  if (accountChat) window.App?.onQueued?.(); // Encrypted and posted to the mailbox by account.js.
  else if (requestChatFlush?.(), dataChannel?.readyState === 'open') chatStatus('');
  else chatStatus('Queued on this device. Both participants need a valid invitation and a connection to exchange it.');
  await refreshHistory();
}
$('chat-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (chatBusy || !(validInvite || accountChat) || selectedHistory !== conversationId) return;
  let text = $('chat-input').value;
  window.Commands?.close();
  if (editing) { await submitEdit(text); return; } // An edit is text, never a command.
  // "/command …" runs here and is never sent; "//text" sends text that starts with a slash.
  if (window.Commands?.parse(text)) {
    chatBusy = true; updateComposer();
    try {
      const result = await window.Commands.run(text.trim(), commandContext());
      if (result.ok) { if ($('chat-input').value === text) { $('chat-input').value = ''; resizeComposer(); composerChanged(); } }
      else chatStatus(result.error);
    } finally { chatBusy = false; updateComposer(); $('chat-input').focus?.(); }
    return;
  }
  if (text.startsWith('//')) text = text.slice(1);
  if (!text.trim() || encoder.encode(text).length > 4096) { chatStatus('Enter a message up to 4096 UTF-8 bytes.'); return; }
  const replyTo = replyReference(), link = takeLink(text);
  if (replyTo) { replying = null; paintContext(); }
  window.App?.onTyping?.(false);
  chatBusy = true; updateComposer();
  const send = $('chat-send'); if (send.classList) { const fly = send.classList.contains('fly-a') ? 'fly-b' : 'fly-a'; send.classList.remove('fly-a', 'fly-b'); send.classList.add(fly); }
  // Clear at once so typing can continue; restore the text only if saving fails and nothing new was typed.
  const typed = $('chat-input').value;
  $('chat-input').value = ''; resizeComposer(); $('chat-form').dataset.empty = 'true'; $('chat-input').focus?.();
  try { await queueMessage({ text, replyTo, link }); }
  catch (error) {
    chatStatus(error.message || 'Could not save this message.');
    if (!$('chat-input').value) { $('chat-input').value = typed; resizeComposer(); composerChanged(); }
  }
  finally { chatBusy = false; updateComposer(); $('chat-input').focus?.(); }
});
/** Saves an edit of your own message here and sends it end to end; the original text stays for deduplication. */
async function submitEdit(text) {
  const target = editing;
  if (window.Emoji) text = window.Emoji.expand(text);
  if (!text.trim() || encoder.encode(text).length > 4096) { chatStatus('An edited message needs some text, up to 4096 UTF-8 bytes.'); return; }
  if (text === shownText(target)) { cancelContext(); return; }
  chatBusy = true; updateComposer();
  try {
    await window.App.onEdit(target, text);
    editing = null; $('chat-input').value = ''; resizeComposer(); composerChanged(); paintContext();
    await refreshHistory();
  } catch (error) { chatStatus(error.code === 'identity-blocked' ? `${peerName}'s security code changed. Review it to keep sending.` : `Couldn't save your edit: ${error.message || 'try again.'}`); }
  finally { chatBusy = false; updateComposer(); $('chat-input').focus?.(); }
}
// ---------- Slash commands ----------
// Commands act only through this context: the same buttons and storage the visible UI uses.
let commandConfirm = null;
function confirmDialog(title, text, yes) {
  $('cmd-confirm-title').textContent = title; $('cmd-confirm-text').textContent = text; $('cmd-confirm-yes').textContent = yes;
  $('cmd-confirm').hidden = false; $('cmd-confirm-yes').focus?.();
  return new Promise(resolve => { commandConfirm = resolve; });
}
const answerConfirm = value => { $('cmd-confirm').hidden = true; commandConfirm?.(value); commandConfirm = null; };
$('cmd-confirm-yes').onclick = () => answerConfirm(true);
$('cmd-confirm-cancel').onclick = () => answerConfirm(false);
const reminderKey = () => `reminders-v1:${window.App?.accountId || 'guest'}`;
const readReminders = () => { try { const list = JSON.parse(localStorage.getItem(reminderKey()) || '[]'); return Array.isArray(list) ? list.slice(-100) : []; } catch { return []; } };
const writeReminders = list => { try { localStorage.setItem(reminderKey(), JSON.stringify(list.slice(-100))); } catch {} };
const reminderTimers = new Map();
/** Local reminders fire on this device only: a notification if allowed, and a line in that chat. */
function scheduleReminders() {
  for (const timer of reminderTimers.values()) clearTimeout(timer);
  reminderTimers.clear();
  for (const reminder of readReminders()) {
    if (!reminder || typeof reminder.id !== 'string' || !Number.isSafeInteger(reminder.at) || typeof reminder.text !== 'string' || typeof reminder.conversationId !== 'string') continue;
    reminderTimers.set(reminder.id, setTimeout(async () => {
      writeReminders(readReminders().filter(value => value.id !== reminder.id)); reminderTimers.delete(reminder.id);
      try { await window.ChatStore.note(reminder.conversationId, reminder.id, `⏰ Reminder: ${reminder.text}`); } catch {}
      chatStatus(`⏰ Reminder: ${reminder.text}`);
      try {
        if (globalThis.Notification?.permission === 'granted') {
          const registration = await navigator.serviceWorker?.getRegistration?.();
          if (registration) await registration.showNotification('Reminder', { body: reminder.text, tag: reminder.id });
          else new Notification('Reminder', { body: reminder.text });
        }
      } catch {}
      refreshHistory();
    }, Math.max(0, Math.min(reminder.at - Date.now(), 2147483000))));
  }
}
function commandContext() {
  const where = accountChat ? 'account' : validInvite ? 'guest' : 'none';
  const context = {
    where, active,
    send: message => queueMessage(message),
    /** Presses an existing control, so a command can do exactly what its button does and nothing more. */
    press(id, disabledHint) { const control = $(id); if (!control || control.disabled) return { error: disabledHint || 'Not available right now.' }; control.click(); },
    setTimer(value) { $('disappear').value = value; $('disappear').dispatchEvent(new Event('change')); },
    setTheme: name => Boolean(window.Theme?.setChatPreset?.(name)),
    notice: text => chatStatus(text),
    confirm: confirmDialog,
    async clearChat() { await window.ChatStore.removeConversation(conversationId); transcriptSignature = ''; await refreshHistory(); chatStatus('Chat history cleared on this device.'); },
    remind(at, text) { writeReminders([...readReminders(), { id: crypto.randomUUID(), at, text: text.slice(0, 500), conversationId }]); scheduleReminders(); },
    showHelp: () => window.Commands.showHelp(context),
    compose(text) { const input = $('chat-input'); input.value = text; input.focus?.(); input.setSelectionRange?.(text.length, text.length); input.dispatchEvent(new Event('input')); },
  };
  return context;
}
// A tap on a poll option votes (or changes the vote); account chats send it end to end, guest rooms over the live channel.
$('chat-log').addEventListener('click', async event => {
  const button = event.target.closest?.('.poll-option');
  if (!button || selectedHistory !== conversationId) return;
  const option = Number(button.dataset.option), poll = button.dataset.poll;
  try {
    if (accountChat) await window.App.onVote(poll, option);
    else {
      if (dataChannel?.readyState !== 'open') { chatStatus('Connect to the other person to vote.'); return; }
      dataChannel.send(JSON.stringify({ v: 1, type: 'vote', id: crypto.randomUUID(), poll, option }));
    }
    await window.ChatStore.vote(conversationId, poll, 'me', option);
    refreshHistory();
  } catch (error) { chatStatus(error.message || 'Could not send your vote.'); }
});
// Single-row composer that grows with its text; Enter sends on devices with a keyboard.
function resizeComposer() { const input = $('chat-input'); if (!input.style) return; input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 160)}px`; }
$('chat-input').oninput = resizeComposer;
$('chat-input').onkeydown = event => {
  if (window.Commands?.keydown(event)) return;
  // ↑ in an empty composer edits your last message; Escape leaves editing or replying.
  if (event.key === 'ArrowUp' && !$('chat-input').value && !event.shiftKey && !event.altKey && !event.metaKey && !event.ctrlKey) { const last = lastEditable(); if (last) { event.preventDefault(); startEdit(last); } return; }
  if (event.key === 'Escape' && (editing || replying)) { event.preventDefault(); cancelContext(); return; }
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && matchMedia('(pointer: fine)').matches) { event.preventDefault(); $('chat-form').requestSubmit(); }
};
const disappearingPreferenceKey = 'private-chat-disappearing-v1';
try { const preference = localStorage.getItem(disappearingPreferenceKey); if (['off', '3600000', '86400000', '604800000'].includes(preference)) $('disappear').value = preference; } catch {}
$('disappear').onchange = () => { try { localStorage.setItem(disappearingPreferenceKey, $('disappear').value); } catch {} };
async function backupAction(action) {
  $('backup-export').disabled = true; $('backup-import').disabled = true;
  $('backup-status').textContent = 'Working on your device…';
  try { await action(); }
  catch (error) { $('backup-status').textContent = error.message || 'Backup operation failed.'; }
  finally { $('backup-password').value = ''; $('backup-export').disabled = false; $('backup-import').disabled = false; }
}
$('backup-export').onclick = () => backupAction(async () => {
  const blob = await window.ChatStore.exportBackup($('backup-password').value);
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = `private-conversations-${new Date().toISOString().slice(0, 10)}.json`; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  $('backup-status').textContent = 'Encrypted backup downloaded. Save this file to Google Drive if you want to move it to another phone.';
});
$('backup-import').onclick = () => backupAction(async () => {
  const file = $('backup-file').files[0];
  if (!file) throw new Error('Choose an encrypted backup file.');
  const count = await window.ChatStore.importBackup(file, $('backup-password').value);
  $('backup-file').value = ''; await refreshHistory();
  $('backup-status').textContent = `Restored ${count} messages. Original expiry times are preserved. Restored history does not reopen conversations or resend messages.`;
});
$('history-clear').onclick = () => { $('clear-confirm').hidden = false; };
$('history-clear-cancel').onclick = () => { $('clear-confirm').hidden = true; };
$('history-clear-confirm').onclick = async () => {
  try { await window.ChatStore.clear(); await refreshHistory(); $('clear-confirm').hidden = true; $('backup-status').textContent = 'Local history deleted. Other devices and backup files are unchanged.'; }
  catch (error) { $('backup-status').textContent = error.message || 'Could not delete local history.'; }
};
setInterval(() => { refreshHistory(); }, 5000);
if (!window.isSecureContext || !window.RTCPeerConnection) status('Conversations require a supported browser over HTTPS (or localhost for development).');
else {
  const incoming = location.href; history.replaceState(null, '', location.pathname);
  const hash = new URLSearchParams(new URL(incoming).hash.slice(1));
  // Account invitations (#invite=…) belong to the sign-up screen, not the call flow.
  if (hash.has('invite')) { window.pendingAccountInvite = hash.get('invite'); status('Create your account with this invitation.'); }
  // Notification taps open a contact's conversation (#open=username); account.js picks it up after sign-in.
  // It only selects a conversation: nothing in a URL may start or answer a call or capture media.
  else if (hash.has('open')) window.pendingOpen = { user: hash.get('open'), call: hash.has('call') };
  else if (new URL(incoming).hash) { try { openInvitation(incoming); } catch (error) { status(error.message); $('invitation-panel').open = true; } }
  else { status('Open your invitation link to connect. Saved messages stay below.'); $('status').classList?.add('idle'); $('invitation-panel').open = true; }
}
// ---------- Attachments: bubbles, uploads, viewer ----------
// Files are encrypted before upload (files.js); account chats only, since blobs need a signed-in account.
const uploads = new Map(); // id → { id, conversation, file, override, info, local, progress, error, replyTo }
const thumbUrls = new Map();
const thumbUrl = data => { if (!data || !window.Files) return ''; if (!thumbUrls.has(data)) thumbUrls.set(data, window.Files.dataUrlToObjectUrl(data)); return thumbUrls.get(data); };
const reducedMotion = () => Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches);
function icon(paths, className = 'icon') {
  const svg = svgNode('svg', { class: className, viewBox: '0 0 24 24', 'aria-hidden': 'true' });
  for (const d of paths) svg.append(svgNode('path', { d }));
  return svg;
}
const PLAY = 'M7 4.5v15l12-7.5z', PAUSE = 'M7 4h3.5v16H7zM13.5 4H17v16h-3.5z';
function frameSize(node, file) {
  if (!file.width || !file.height) return;
  // Shown at their aspect ratio, at most 320 px wide (CSSOM properties are allowed by the page's CSP).
  node.style.setProperty('--ratio', `${file.width} / ${file.height}`);
  node.style.setProperty('--media-width', `${Math.min(320, file.width, Math.round(320 * Math.min(1, file.width / file.height * 1.25)))}px`);
}
function attachmentNode(record) {
  const file = record.attachment, box = element('div', `attachment attachment-${file.kind}`);
  box.dataset.state = 'idle';
  if (file.kind === 'image' || file.kind === 'video') {
    const frame = element('button', 'media-frame'); frame.type = 'button'; frameSize(frame, file);
    frame.setAttribute('aria-label', file.kind === 'image' ? `Photo${file.name ? ` ${file.name}` : ''}. Open full size.` : `Video, ${window.Files?.duration(file.duration) || ''}. Play.`);
    if (file.thumb) { const placeholder = element('img', 'media-thumb'); placeholder.alt = ''; placeholder.src = thumbUrl(file.thumb); frame.append(placeholder); }
    if (file.kind === 'video') { const play = element('span', 'media-play'); play.append(icon([PLAY])); frame.append(play); if (file.duration) frame.append(element('span', 'media-badge', window.Files?.duration(file.duration))); }
    box.append(frame);
    if (file.kind === 'image' && window.Files?.eager(file)) loadMedia(box, record);
  } else if (file.kind === 'voice') box.append(voicePlayer(record));
  else box.append(fileCard(record));
  return box;
}
function showLoadError(box, record, error) {
  box.dataset.state = 'error';
  box.querySelector('.media-error')?.remove();
  const note = element('div', 'media-error'), integrity = error?.code === 'integrity';
  note.append(element('span', '', integrity ? 'That file couldn’t be read.' : error?.code === 'missing' ? error.message : 'Couldn’t load.'));
  if (!integrity && error?.code !== 'missing') { const retry = element('button', 'link media-retry', 'Retry'); retry.type = 'button'; retry.dataset.retry = record.id; note.append(retry); }
  box.append(note);
}
async function loadMedia(box, record, then) {
  const file = record.attachment;
  if (box.dataset.state === 'loading') return;
  box.dataset.state = 'loading'; box.querySelector('.media-error')?.remove();
  try {
    const { url } = await window.Files.open(file);
    if (file.kind === 'image') {
      const frame = box.querySelector('.media-frame');
      let image = frame.querySelector('.media-full');
      if (!image) { image = element('img', 'media-full'); image.alt = file.name || 'Photo'; image.decoding = 'async'; frame.append(image); }
      await new Promise(resolve => { image.onload = image.onerror = resolve; image.src = url; });
      box.dataset.state = 'ready';
    } else if (file.kind === 'video') {
      const video = element('video', 'media-video'); frameSize(video, file);
      video.controls = true; video.playsInline = true; video.preload = 'metadata'; video.src = url;
      if (file.thumb) video.poster = thumbUrl(file.thumb);
      box.replaceChildren(video); box.dataset.state = 'ready';
      if (then === 'play') video.play().catch(() => {});
    } else box.dataset.state = 'ready';
    return url;
  } catch (error) { showLoadError(box, record, error); return null; }
}
function fileCard(record) {
  const file = record.attachment, card = element('div', 'file-card');
  // The name is shown left to right with its real extension in the icon, so no character can disguise the type.
  const name = window.Files ? window.Files.cleanName(file.name) : file.name || 'file';
  const extension = /\.([a-z0-9]{1,5})$/i.exec(name)?.[1]?.toUpperCase() || (file.kind === 'audio' ? '♪' : 'FILE');
  const text = element('span', 'file-text'), label = element('strong', 'file-name', name);
  label.dir = 'ltr'; label.title = name;
  text.append(label, element('small', 'file-size', `${window.Files?.size(file.size) || ''}${file.duration ? ` · ${window.Files?.duration(file.duration)}` : ''}`));
  const action = element('button', 'file-action', file.kind === 'audio' ? 'Play' : 'Download'); action.type = 'button';
  action.setAttribute('aria-label', `${file.kind === 'audio' ? 'Play' : 'Download'} ${file.name || 'file'}`);
  card.append(element('span', 'file-icon', extension), text, action);
  return card;
}
async function openFile(box, record) {
  const file = record.attachment, url = await loadMedia(box, record);
  if (!url) return;
  if (file.kind === 'audio') {
    const audio = element('audio', 'file-audio'); audio.controls = true; audio.src = url;
    box.querySelector('.file-action')?.remove(); box.append(audio); audio.play().catch(() => {});
    return;
  }
  const link = document.createElement('a'); link.href = url; link.download = file.name || 'file'; document.body.append(link); link.click(); link.remove();
}
// Voice messages: play/pause, a waveform you can tap or drag to seek, the time, and 1× / 1.5× / 2×.
function voicePlayer(record) {
  const file = record.attachment, player = element('div', 'voice');
  const play = element('button', 'voice-play'); play.type = 'button'; play.setAttribute('aria-label', 'Play voice message'); play.append(icon([PLAY]));
  const wave = element('div', 'voice-wave'); wave.tabIndex = 0; wave.setAttribute('role', 'slider'); wave.setAttribute('aria-label', 'Position in voice message');
  wave.setAttribute('aria-valuemin', '0'); wave.setAttribute('aria-valuemax', String(Math.round(file.duration || 0))); wave.setAttribute('aria-valuenow', '0');
  const levels = file.waveform?.length ? file.waveform : Array(40).fill(8);
  for (const level of levels) { const bar = element('i'); bar.style.setProperty('--level', String(Math.max(3, level))); wave.append(bar); }
  const speed = element('button', 'voice-speed', '1×'); speed.type = 'button'; speed.setAttribute('aria-label', 'Playback speed 1×');
  player.append(play, wave, element('span', 'voice-time', window.Files?.duration(file.duration) || '0:00'), speed);
  if (window.Files?.eager(file)) queueMicrotask(() => voiceAudio(player, record).catch(() => {}));
  return player;
}
async function voiceAudio(player, record) {
  if (player.audio) return player.audio;
  const box = player.closest('.attachment') || player, url = await loadMedia(box, record);
  if (!url) throw new Error('unavailable');
  if (player.audio) return player.audio;
  const audio = element('audio'); audio.preload = 'auto'; audio.src = url; audio.playbackRate = Number(player.dataset.rate || 1);
  const bars = [...player.querySelectorAll('.voice-wave i')], time = player.querySelector('.voice-time'), button = player.querySelector('.voice-play'), wave = player.querySelector('.voice-wave');
  const total = () => Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : record.attachment.duration || 0;
  const paint = () => {
    const fraction = total() ? audio.currentTime / total() : 0, played = Math.round(fraction * bars.length);
    bars.forEach((bar, index) => bar.classList.toggle('played', index < played));
    time.textContent = window.Files.duration(audio.paused && !audio.currentTime ? total() : audio.currentTime);
    wave.setAttribute('aria-valuenow', String(Math.round(audio.currentTime))); wave.setAttribute('aria-valuetext', `${window.Files.duration(audio.currentTime)} of ${window.Files.duration(total())}`);
  };
  const state = playing => { button.replaceChildren(icon([playing ? PAUSE : PLAY])); button.setAttribute('aria-label', playing ? 'Pause voice message' : 'Play voice message'); player.classList.toggle('playing', playing); };
  audio.ontimeupdate = paint; audio.onplay = () => state(true); audio.onpause = () => { state(false); paint(); };
  audio.onended = () => { audio.currentTime = 0; state(false); paint(); };
  player.audio = audio; player.append(audio);
  return audio;
}
async function toggleVoice(player, record) {
  try {
    const audio = await voiceAudio(player, record);
    if (audio.paused) { for (const other of document.querySelectorAll('#chat-log audio')) if (other !== audio) other.pause(); await audio.play(); }
    else audio.pause();
  } catch { /* The load error is already shown in the bubble. */ }
}
async function seekVoice(player, record, fraction) {
  try { const audio = await voiceAudio(player, record), total = Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : record.attachment.duration || 0; audio.currentTime = Math.max(0, Math.min(total, fraction * total)); audio.ontimeupdate(); } catch {}
}
function linkCard(link) {
  const card = element('a', 'link-card'); card.href = link.url; card.target = '_blank'; card.rel = 'noopener noreferrer nofollow';
  if (link.thumb) { const image = element('img', 'link-thumb'); image.alt = ''; image.src = thumbUrl(link.thumb); card.append(image); }
  const text = element('span', 'link-text');
  let host = ''; try { host = new URL(link.url).hostname.replace(/^www\./, ''); } catch {}
  if (link.title) text.append(element('strong', 'link-title', link.title));
  if (link.description) text.append(element('small', 'link-description', link.description));
  text.append(element('small', 'link-site', link.site || host));
  card.append(text);
  return card;
}
function pendingRow(item) {
  const row = element('li', 'outgoing pending tail'); row.dataset.pending = item.id;
  const box = element('div', 'attachment pending-box');
  const ring = svgNode('svg', { class: 'progress-ring', viewBox: '0 0 36 36', 'aria-hidden': 'true' });
  ring.append(svgNode('circle', { class: 'ring-track', cx: '18', cy: '18', r: '15' }), svgNode('circle', { class: 'ring-value', cx: '18', cy: '18', r: '15', pathLength: '100' }));
  const cancel = element('button', 'pending-cancel'); cancel.type = 'button'; cancel.dataset.cancelUpload = item.id; cancel.setAttribute('aria-label', `Cancel sending ${item.file.name || 'file'}`); cancel.append(ring, icon(['M18 6L6 18M6 6l12 12'], 'icon pending-x'));
  const status = element('div', 'pending-status'); status.setAttribute('role', 'status');
  box.append(element('div', 'pending-preview'), cancel, status);
  row.append(box);
  return row;
}
function paintPending(row, item) {
  const preview = row.querySelector('.pending-preview'), info = item.info;
  if (info && !preview.dataset.ready) {
    preview.dataset.ready = 'yes';
    if (info.kind === 'image' && item.local) { const image = element('img', 'media-full'); image.alt = ''; image.src = item.local; frameSize(preview, info); preview.append(image); }
    else if (info.kind === 'video' && info.thumb) { const image = element('img', 'media-thumb'); image.alt = ''; image.src = thumbUrl(info.thumb); frameSize(preview, info); preview.append(image); }
    else preview.append(element('span', 'file-icon', info.kind === 'voice' ? '🎤' : /\.([a-z0-9]{1,5})$/i.exec(info.name || '')?.[1]?.toUpperCase() || 'FILE'), element('span', 'file-name', info.kind === 'voice' ? `Voice message · ${window.Files.duration(info.duration)}` : info.name));
  }
  row.querySelector('.ring-value').style.setProperty('--progress', String(Math.round((item.progress || 0) * 100)));
  row.dataset.state = item.error ? 'error' : 'uploading';
  const status = row.querySelector('.pending-status');
  if (item.error) {
    if (status.dataset.error !== item.error) {
      status.dataset.error = item.error;
      const retry = element('button', 'link', 'Retry'); retry.type = 'button'; retry.dataset.retryUpload = item.id;
      const remove = element('button', 'link', 'Remove'); remove.type = 'button'; remove.dataset.cancelUpload = item.id;
      status.replaceChildren(element('span', '', item.error), retry, remove);
    }
  } else { delete status.dataset.error; status.textContent = item.progress >= 1 ? 'Sending…' : `Encrypting and uploading · ${Math.round((item.progress || 0) * 100)}%`; }
}
function paintUploads() {
  for (const item of uploads.values()) { const row = rendered.rows.get(`pending:${item.id}`); if (row) paintPending(row, item); }
}
/** Encrypts and uploads files one by one; each becomes its own message (with the reply, if one is open). */
async function sendFiles(list) {
  const files = [...list || []];
  if (!files.length) return;
  if (!accountChat || selectedHistory !== conversationId || !window.Files) { chatStatus('Open a conversation with a contact to send files.'); return; }
  for (const file of files) await sendAttachment(file);
}
async function sendAttachment(file, override = {}) {
  if (file.size > window.Files.MAX_SIZE) { chatStatus(`${file.name || 'That file'} is larger than 25 MB. Send something smaller, or share a link to it.`); return; }
  if (!file.size) { chatStatus(`${file.name || 'That file'} is empty, so there's nothing to send.`); return; }
  const item = { id: crypto.randomUUID(), conversation: conversationId, file, override, progress: 0, error: null, replyTo: replyReference() };
  if (item.replyTo) cancelContext();
  uploads.set(item.id, item); chatStatus('');
  await refreshHistory();
  await runUpload(item);
}
async function runUpload(item) {
  item.error = null; item.progress = 0; item.controller = new AbortController(); paintUploads();
  try {
    if (!item.info) {
      const { info, local } = await window.Files.describe(item.file);
      item.info = { ...info, ...item.override }; item.local = local;
      if (uploads.has(item.id)) await refreshHistory();
    }
    const { ciphertext, key, sha256 } = await window.Files.encrypt(new Uint8Array(await item.file.arrayBuffer()));
    if (!uploads.has(item.id)) return;
    const blob = await window.Files.upload(ciphertext, progress => { item.progress = progress; paintUploads(); }, item.controller.signal);
    const attachment = Object.fromEntries(Object.entries({ ...item.info, blob, key, sha256 }).filter(([, value]) => value !== undefined));
    window.Files.remember?.(attachment, item.file, item.local); // Our own copy shows at once, without downloading it back.
    uploads.delete(item.id);
    await queueMessage({ text: '', attachment, replyTo: item.replyTo });
  } catch (error) {
    if (!uploads.has(item.id)) return;
    item.error = error.code === 'aborted' ? 'Upload cancelled.' : error.message || 'Couldn’t upload.';
    paintUploads();
  }
}
// The viewer: full window, click to zoom in at that point, wheel or pinch to zoom, Escape closes.
let lightboxOpener = null, lightboxScale = 1;
function openLightbox(url, name) {
  lightboxOpener = document.activeElement; lightboxScale = 1;
  const image = $('lightbox-img'); image.src = url; image.alt = name || 'Photo'; image.style.setProperty('--zoom', '1');
  $('lightbox').dataset.zoom = 'no';
  $('lightbox-name').textContent = name || 'Photo'; $('lightbox-save').href = url; $('lightbox-save').download = name || 'photo';
  $('lightbox').hidden = false; $('lightbox-close').focus();
}
function closeLightbox() { $('lightbox').hidden = true; $('lightbox-img').removeAttribute('src'); lightboxOpener?.focus?.(); lightboxOpener = null; }
function zoomTo(scale, event) {
  const image = $('lightbox-img'); lightboxScale = Math.max(1, Math.min(5, scale));
  if (event) { const box = image.getBoundingClientRect(); image.style.setProperty('--origin', `${((event.clientX - box.left) / box.width * 100).toFixed(1)}% ${((event.clientY - box.top) / box.height * 100).toFixed(1)}%`); }
  image.style.setProperty('--zoom', String(lightboxScale)); $('lightbox').dataset.zoom = lightboxScale > 1 ? 'yes' : 'no';
}
$('lightbox-close').onclick = closeLightbox;
$('lightbox-img').onclick = event => zoomTo(lightboxScale > 1 ? 1 : 2.5, event);
$('lightbox-stage').addEventListener('wheel', event => { event.preventDefault(); zoomTo(lightboxScale * (event.deltaY < 0 ? 1.15 : 1 / 1.15), event); }, { passive: false });
document.addEventListener('keydown', event => {
  if ($('lightbox').hidden) return;
  if (event.key === 'Escape') { event.preventDefault(); event.stopImmediatePropagation(); closeLightbox(); }
  // Keep keyboard focus inside the viewer while it is open.
  else if (event.key === 'Tab') { const stops = [$('lightbox-save'), $('lightbox-close')]; const at = stops.indexOf(document.activeElement); event.preventDefault(); stops[(at + (event.shiftKey ? -1 : 1) + stops.length) % stops.length].focus(); }
}, true);
$('lightbox-stage').addEventListener('click', event => { if (event.target === $('lightbox-stage')) closeLightbox(); });

// ---------- Message actions: react, reply, edit, copy ----------
const canReact = record => accountChat && record && record.direction !== 'system' && selectedHistory === conversationId;
const canEdit = record => accountChat && record?.direction === 'outgoing' && !record.kind && !record.attachment && selectedHistory === conversationId;
const canReply = record => record && record.direction !== 'system' && selectedHistory === conversationId && (accountChat || validInvite);
let actionTarget = null;
function buildActions() {
  const bar = $('msg-actions');
  const button = (label, content, data) => { const node = element('button', 'action'); node.type = 'button'; node.setAttribute('aria-label', label); node.title = label; Object.assign(node.dataset, data); if (typeof content === 'string') node.textContent = content; else node.append(content); return node; };
  bar.replaceChildren(
    ...QUICK_REACTIONS.map(emoji => button(`React with ${emoji}`, emoji, { react: emoji })),
    button('More reactions', icon(['M12 5v14M5 12h14']), { action: 'more' }),
    button('Reply', icon(['M9 17l-5-5 5-5', 'M4 12h11a5 5 0 0 1 5 5v2']), { action: 'reply' }),
    button('Edit', icon(['M12 20h9', 'M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z']), { action: 'edit' }),
    button('Copy text', icon(['M8 8h12v12H8z', 'M4 16V4h12']), { action: 'copy' }));
}
buildActions();
function showActions(row) {
  const record = row && shown.get(row.dataset.messageId), bar = $('msg-actions');
  if (!record || !canReply(record) || !$('emoji-picker').hidden) { if (!record) hideActions(); return; }
  actionTarget = record.id;
  for (const node of bar.querySelectorAll('[data-react], [data-action="more"]')) node.hidden = !canReact(record);
  bar.querySelector('[data-action="edit"]').hidden = !canEdit(record);
  bar.querySelector('[data-action="copy"]').hidden = !shownText(record).trim() || !navigator.clipboard;
  for (const node of bar.querySelectorAll('[data-react]')) node.setAttribute('aria-pressed', String((record.reactions?.me || []).includes(node.dataset.react)));
  bar.hidden = false;
  const section = $('chat-log').closest('.chat-section').getBoundingClientRect(), box = row.getBoundingClientRect();
  // Above the message, or below it when there is no room, so the bar never covers what it acts on.
  const above = box.top - section.top - bar.offsetHeight + 4, top = above >= 4 ? above : Math.min(box.bottom - section.top - 4, section.height - bar.offsetHeight - 4);
  bar.style.setProperty('--top', `${Math.round(top)}px`);
  bar.dataset.side = record.direction === 'outgoing' ? 'end' : 'start';
  bar.style.setProperty('--edge', `${Math.round(record.direction === 'outgoing' ? section.right - box.right : box.left - section.left)}px`);
}
function hideActions() { $('msg-actions').hidden = true; actionTarget = null; }
async function react(id, emoji, on) {
  const record = shown.get(id);
  if (!canReact(record)) return;
  if (on === undefined) on = !(record.reactions?.me || []).includes(emoji);
  const distinct = new Set([...record.reactions?.me || [], ...record.reactions?.peer || []]);
  if (on && !distinct.has(emoji) && distinct.size >= (window.ChatStore.MAX_REACTIONS || 20)) { chatStatus('This message already has as many different reactions as it can hold.'); return; }
  try {
    await window.App.onReact(id, emoji, on);
    await window.ChatStore.react(conversationId, id, 'me', emoji, on);
    await refreshHistory();
    if (on && !reducedMotion()) { const row = rendered.rows.get(id); row?.classList.remove('burst'); requestAnimationFrame(() => row?.classList.add('burst')); }
  } catch (error) { chatStatus(error.code === 'identity-blocked' ? `${peerName}'s security code changed. Review it to keep sending.` : `Couldn't send your reaction: ${error.message || 'try again.'}`); }
}
let replying = null, editing = null;
const replyReference = () => replying ? { id: replying.id, text: clip(preview(replying), 140) } : undefined;
function paintContext() {
  const target = editing || replying;
  $('compose-quote').hidden = !target;
  if (target) {
    $('compose-label').textContent = editing ? 'Editing' : `Replying to ${who(target)}`;
    $('compose-preview').textContent = preview(target);
    $('compose-cancel').setAttribute('aria-label', editing ? 'Cancel editing' : 'Cancel reply');
  }
  $('compose-context').hidden = $('compose-quote').hidden && $('compose-link').hidden;
  $('chat-form').dataset.editing = String(Boolean(editing));
}
function startReply(record) {
  if (!canReply(record)) return;
  if (editing) { editing = null; $('chat-input').value = ''; resizeComposer(); }
  replying = record; paintContext(); hideActions(); $('chat-input').focus();
}
function startEdit(record) {
  if (!canEdit(record)) return;
  replying = null; editing = record;
  const input = $('chat-input'); input.value = shownText(record); resizeComposer(); composerChanged();
  paintContext(); hideActions(); input.focus(); input.setSelectionRange?.(input.value.length, input.value.length);
}
function cancelContext() {
  if (editing) { $('chat-input').value = ''; resizeComposer(); composerChanged(); }
  editing = null; replying = null; paintContext();
}
$('compose-cancel').onclick = () => { cancelContext(); $('chat-input').focus(); };
/** The newest message of yours that can still be edited ("Edit Last Message"). */
const lastEditable = () => [...shown.values()].reverse().find(canEdit);
function flash(id) {
  const row = rendered.rows.get(id);
  if (!row) { chatStatus('That message is no longer on this device.'); return; }
  row.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
  row.classList.remove('flash'); requestAnimationFrame(() => row.classList.add('flash'));
  setTimeout(() => row.classList.remove('flash'), 1600);
}

// ---------- Emoji picker (the "more" reaction) ----------
let pickerChoice = null, pickerList = null;
async function openEmojiPicker(onPick) {
  pickerChoice = onPick; hideActions();
  $('emoji-picker').hidden = false; $('emoji-search').value = ''; $('emoji-search').focus();
  if (!pickerList && window.Emoji) {
    const table = await window.Emoji.load(), seen = new Map();
    for (const [name, emoji] of Object.entries(table || {})) if (!seen.has(emoji)) seen.set(emoji, [name]); else seen.get(emoji).push(name);
    pickerList = [...seen].map(([emoji, names]) => ({ emoji, names: names.join(' ') }));
  }
  paintEmojiPicker();
}
function paintEmojiPicker() {
  const query = $('emoji-search').value.trim().toLowerCase().replace(/^:|:$/g, '');
  const custom = window.Emoji ? [...window.Emoji.custom.keys()].filter(name => !query || name.includes(query)).map(name => ({ emoji: `:${name}:`, names: name, custom: true })) : [];
  const standard = (pickerList || QUICK_REACTIONS.map(emoji => ({ emoji, names: '' }))).filter(item => !query || item.names.includes(query));
  const items = [...custom, ...standard].slice(0, 320);
  $('emoji-grid').replaceChildren(...items.map(item => {
    const button = element('button', 'emoji-choice'); button.type = 'button'; button.dataset.emoji = item.emoji; button.title = item.custom ? item.emoji : `:${item.names.split(' ')[0]}:`;
    button.setAttribute('aria-label', item.custom ? item.emoji : item.names.split(' ')[0].replace(/_/g, ' '));
    if (window.Emoji) window.Emoji.render(button, item.emoji); else button.textContent = item.emoji;
    return button;
  }));
  if (!items.length) $('emoji-grid').append(element('p', 'note', 'No emoji match. Try another word.'));
}
function closeEmojiPicker() { $('emoji-picker').hidden = true; pickerChoice = null; }
$('emoji-search').addEventListener('input', paintEmojiPicker);
$('emoji-search').addEventListener('keydown', event => {
  if (event.key === 'Escape') { event.preventDefault(); closeEmojiPicker(); $('chat-input').focus(); }
  if (event.key === 'Enter') { event.preventDefault(); $('emoji-grid').querySelector('.emoji-choice')?.click(); }
});
$('emoji-grid').addEventListener('click', event => {
  const choice = event.target.closest?.('.emoji-choice');
  if (!choice) return;
  const pick = pickerChoice; closeEmojiPicker(); pick?.(choice.dataset.emoji);
});
document.addEventListener('pointerdown', event => { if (!$('emoji-picker').hidden && !event.target.closest?.('#emoji-picker, #msg-actions')) closeEmojiPicker(); });

$('msg-actions').addEventListener('click', event => {
  const button = event.target.closest?.('button'), id = actionTarget, record = shown.get(id);
  if (!button || !record) return;
  if (button.dataset.react) { react(id, button.dataset.react); hideActions(); return; }
  const action = button.dataset.action;
  if (action === 'more') openEmojiPicker(emoji => react(id, emoji, true));
  else if (action === 'reply') startReply(record);
  else if (action === 'edit') startEdit(record);
  else if (action === 'copy') { navigator.clipboard.writeText(shownText(record)).then(() => chatStatus('Copied.'), () => chatStatus('Couldn’t copy. Select the text instead.')); hideActions(); }
});
// Pointer devices: the bar follows the hovered message. Touch: a tap on a bubble shows it; swipe right replies.
$('chat-log').addEventListener('mouseover', event => {
  if (!window.matchMedia?.('(hover: hover)')?.matches) return;
  const row = event.target.closest?.('li[data-message-id]');
  if (row && row.dataset.messageId !== actionTarget) showActions(row);
});
$('chat-log').closest('.chat-section').addEventListener('mouseleave', () => { if ($('emoji-picker').hidden) hideActions(); });
$('chat-log').addEventListener('scroll', () => { hideActions(); updateJump(); }, { passive: true });
let swipe = null;
$('chat-log').addEventListener('touchstart', event => {
  const row = event.target.closest?.('li[data-message-id]'), touch = event.touches[0];
  swipe = row && event.touches.length === 1 ? { row, x: touch.clientX, y: touch.clientY, dx: 0 } : null;
}, { passive: true });
$('chat-log').addEventListener('touchmove', event => {
  if (!swipe) return;
  const touch = event.touches[0], dx = touch.clientX - swipe.x, dy = touch.clientY - swipe.y;
  if (Math.abs(dy) > 24 && Math.abs(dy) > Math.abs(dx)) { swipe.row.style.removeProperty('--swipe'); swipe = null; return; }
  swipe.dx = Math.max(0, Math.min(80, dx));
  swipe.row.style.setProperty('--swipe', `${swipe.dx}px`);
}, { passive: true });
$('chat-log').addEventListener('touchend', () => {
  if (!swipe) return;
  const { row, dx } = swipe; swipe = null; row.style.removeProperty('--swipe');
  if (dx >= 60) startReply(shown.get(row.dataset.messageId));
});
$('chat-log').addEventListener('dblclick', event => {
  if (event.target.closest?.('button, a, video, audio, .media-frame, .voice, .file-card, .link-card')) return;
  const row = event.target.closest?.('li[data-message-id]');
  if (!row || !canReact(shown.get(row.dataset.messageId))) return;
  window.getSelection?.()?.removeAllRanges();
  react(row.dataset.messageId, '❤️');
});
// Everything clickable inside messages: quotes, reactions, media, files, voice and upload controls.
$('chat-log').addEventListener('click', event => {
  const target = event.target, row = target.closest?.('li[data-message-id]'), record = row && shown.get(row.dataset.messageId);
  const quote = target.closest?.('.reply-quote'); if (quote) { flash(quote.dataset.target); return; }
  const pill = target.closest?.('.reaction'); if (pill && record) { react(record.id, pill.dataset.emoji); return; }
  const cancel = target.closest?.('[data-cancel-upload]');
  if (cancel) { const item = uploads.get(cancel.dataset.cancelUpload); if (item) { uploads.delete(item.id); item.controller?.abort(); refreshHistory(); } return; }
  const retryUpload = target.closest?.('[data-retry-upload]'); if (retryUpload) { const item = uploads.get(retryUpload.dataset.retryUpload); if (item) runUpload(item); return; }
  if (!record?.attachment) {
    if (row && !window.matchMedia?.('(hover: hover)')?.matches && !target.closest?.('a, button')) { if (actionTarget === row.dataset.messageId) hideActions(); else showActions(row); }
    return;
  }
  const box = row.querySelector('.attachment'), file = record.attachment;
  if (target.closest?.('.media-retry')) { if (file.kind === 'voice') voiceAudio(row.querySelector('.voice'), record).catch(() => {}); else loadMedia(box, record); return; }
  if (target.closest?.('.media-frame')) {
    if (file.kind === 'video') loadMedia(box, record, 'play');
    else loadMedia(box, record).then(url => { if (url) openLightbox(url, file.name); });
    return;
  }
  if (target.closest?.('.file-action')) { openFile(box, record); return; }
  const player = target.closest?.('.voice');
  if (player) {
    if (target.closest?.('.voice-play')) toggleVoice(player, record);
    else if (target.closest?.('.voice-speed')) {
      const rates = [1, 1.5, 2], next = rates[(rates.indexOf(Number(player.dataset.rate || 1)) + 1) % rates.length];
      player.dataset.rate = String(next); const label = `${next}×`, speed = player.querySelector('.voice-speed');
      speed.textContent = label; speed.setAttribute('aria-label', `Playback speed ${label}`);
      if (player.audio) player.audio.playbackRate = next;
    } else if (target.closest?.('.voice-wave')) {
      const wave = player.querySelector('.voice-wave'), box = wave.getBoundingClientRect();
      seekVoice(player, record, (event.clientX - box.left) / box.width);
    }
  }
});
// Keyboard: Tab into the transcript, then ↑/↓ move between messages and show their action bar (Tab reaches it).
$('chat-log').tabIndex = 0;
$('chat-log').addEventListener('keydown', event => {
  if (!['ArrowUp', 'ArrowDown'].includes(event.key) || event.target.closest?.('.voice-wave, button, a, video, audio')) return;
  const rows = [...$('chat-log').querySelectorAll('li[data-message-id]')];
  if (!rows.length) return;
  const at = rows.indexOf(event.target.closest?.('li[data-message-id]'));
  const next = rows[at === -1 ? rows.length - 1 : Math.max(0, Math.min(rows.length - 1, at + (event.key === 'ArrowDown' ? 1 : -1)))];
  event.preventDefault(); next.tabIndex = -1; next.focus(); next.scrollIntoView?.({ block: 'nearest' }); showActions(next);
});
$('chat-log').addEventListener('keydown', event => {
  const wave = event.target.closest?.('.voice-wave');
  if (!wave || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  const row = wave.closest('li[data-message-id]'), record = shown.get(row.dataset.messageId), player = wave.closest('.voice');
  event.preventDefault();
  voiceAudio(player, record).then(audio => {
    const total = Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : record.attachment.duration || 1;
    const at = event.key === 'Home' ? 0 : event.key === 'End' ? total : audio.currentTime + (event.key === 'ArrowRight' ? 5 : -5);
    seekVoice(player, record, at / total);
  }).catch(() => {});
});

// ---------- Jump to newest ----------
function updateJump() {
  const log = $('chat-log'), distance = log.scrollHeight - log.scrollTop - log.clientHeight;
  if (distance < 80) unseenBelow = 0;
  $('jump-newest').hidden = distance < 300;
  $('jump-count').hidden = !unseenBelow; $('jump-count').textContent = unseenBelow > 99 ? '99+' : String(unseenBelow);
  $('jump-newest').setAttribute('aria-label', unseenBelow ? `Jump to newest message, ${unseenBelow} new` : 'Jump to newest message');
}
$('jump-newest').onclick = () => { const log = $('chat-log'); log.scrollTo({ top: log.scrollHeight, behavior: reducedMotion() ? 'auto' : 'smooth' }); unseenBelow = 0; updateJump(); };

// ---------- Typing indicator ----------
function showTyping(on) {
  $('typing').hidden = !on;
  if (on) $('typing-text').textContent = `${peerLabel()} ${peerLabel() === 'They' ? 'are' : 'is'} typing`;
}

// ---------- Find in conversation ----------
let findMatches = [], findIndex = 0;
function openFind() {
  if (!(validInvite || accountChat || selectedHistory)) return;
  $('find-bar').hidden = false; $('find-input').focus(); $('find-input').select?.(); runFind(true);
}
function closeFind() {
  $('find-bar').hidden = true; findMatches = [];
  for (const row of $('chat-log').querySelectorAll('.found')) row.classList.remove('found', 'found-current');
  globalThis.CSS?.highlights?.delete('find'); globalThis.CSS?.highlights?.delete('find-current');
  $('chat-input').focus();
}
function runFind(jump) {
  const query = $('find-input').value.trim().toLowerCase(), previous = findMatches[findIndex]?.row;
  for (const row of $('chat-log').querySelectorAll('.found')) row.classList.remove('found', 'found-current');
  findMatches = [];
  if (query) for (const row of $('chat-log').querySelectorAll('li[data-message-id]')) {
    const ranges = [];
    for (const part of row.querySelectorAll('.message-text, .file-name, .link-title')) {
      const walker = document.createTreeWalker(part, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const text = node.data.toLowerCase();
        for (let at = text.indexOf(query); at !== -1; at = text.indexOf(query, at + query.length)) { const range = document.createRange(); range.setStart(node, at); range.setEnd(node, at + query.length); ranges.push(range); }
      }
    }
    if (ranges.length) findMatches.push({ row, ranges });
  }
  const kept = findMatches.findIndex(match => match.row === previous);
  findIndex = jump || kept === -1 ? findMatches.length - 1 : kept;
  paintFind(jump);
}
function paintFind(scroll) {
  const highlights = globalThis.CSS?.highlights, Highlight = globalThis.Highlight;
  findMatches.forEach((match, index) => { match.row.classList.add('found'); match.row.classList.toggle('found-current', index === findIndex); });
  $('find-count').textContent = !$('find-input').value.trim() ? '' : findMatches.length ? `${findIndex + 1} of ${findMatches.length}` : 'No matches';
  if (highlights && Highlight) {
    highlights.set('find', new Highlight(...findMatches.flatMap(match => match.ranges)));
    highlights.set('find-current', new Highlight(...(findMatches[findIndex]?.ranges || [])));
  }
  if (scroll && findMatches[findIndex]) findMatches[findIndex].row.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
}
function stepFind(delta) { if (!findMatches.length) return; findIndex = (findIndex + delta + findMatches.length) % findMatches.length; for (const row of $('chat-log').querySelectorAll('.found-current')) row.classList.remove('found-current'); paintFind(true); }
$('find-input').addEventListener('input', () => runFind(true));
$('find-input').addEventListener('keydown', event => {
  if (event.key === 'Enter') { event.preventDefault(); stepFind(event.shiftKey ? 1 : -1); }
  else if (event.key === 'Escape') { event.preventDefault(); closeFind(); }
});
$('find-prev').onclick = () => stepFind(-1);
$('find-next').onclick = () => stepFind(1);
$('find-close').onclick = closeFind;
$('conv-find').onclick = () => { $('conv-menu').open = false; openFind(); };
const chatVisible = () => Boolean($('chat-log').offsetParent) && (accountChat || validInvite || $('app').dataset.state !== 'lobby');
document.addEventListener('keydown', event => {
  if ((event.metaKey || event.ctrlKey) && !event.altKey && event.key.toLowerCase() === 'f' && chatVisible()) { event.preventDefault(); openFind(); }
  else if (event.key === 'Escape' && !$('emoji-picker').hidden) closeEmojiPicker();
});

// ---------- Composer: link previews, voice recording, attachments, typing ----------
let linkDraft = null, unfurlTimer;
const removedLinks = new Set();
function paintLinkDraft() {
  const link = linkDraft?.link;
  $('compose-link').hidden = !link;
  if (link) {
    $('compose-link-title').textContent = link.title || link.site || link.url;
    let host = ''; try { host = new URL(link.url).hostname.replace(/^www\./, ''); } catch {}
    $('compose-link-site').textContent = link.site || host;
    $('compose-link-thumb').hidden = !link.thumb; if (link.thumb) $('compose-link-thumb').src = thumbUrl(link.thumb);
  }
  $('compose-context').hidden = $('compose-quote').hidden && $('compose-link').hidden;
}
/** Link previews are made by the sender only, through this server's checked unfurler; receivers never fetch. */
function scheduleUnfurl() {
  clearTimeout(unfurlTimer);
  const url = accountChat && linkPreviewsOn() && !editing && window.Markdown ? window.Markdown.firstUrl($('chat-input').value) : null;
  if (!url || removedLinks.has(url)) { if (linkDraft) { linkDraft = null; paintLinkDraft(); } return; }
  if (linkDraft?.url === url) return;
  unfurlTimer = setTimeout(() => unfurl(url), 600);
}
async function unfurl(url) {
  linkDraft = { url, link: null };
  try {
    const response = await fetch(`/api/unfurl?url=${encodeURIComponent(url)}`, { credentials: 'same-origin', cache: 'no-store' });
    const data = response.ok ? await response.json() : null;
    if (linkDraft?.url !== url || !data) return;
    const text = (value, max) => typeof value === 'string' && value.trim() ? clip(value.replace(/\s+/g, ' ').trim(), max) : undefined;
    const link = { url, title: text(data.title, 200), description: text(data.description, 300), site: text(data.site, 60) };
    if (!link.title && !link.description) { linkDraft = null; paintLinkDraft(); return; }
    if (typeof data.image === 'string' && data.image.startsWith('https://')) link.thumb = await window.Files?.linkThumb(data.image);
    if (linkDraft?.url !== url) return;
    linkDraft = { url, link: Object.fromEntries(Object.entries(link).filter(([, value]) => value !== undefined)) };
  } catch { if (linkDraft?.url === url) linkDraft = null; }
  paintLinkDraft();
}
$('compose-link-remove').onclick = () => { if (linkDraft) removedLinks.add(linkDraft.url); linkDraft = null; paintLinkDraft(); $('chat-input').focus(); };
function takeLink(text) {
  const link = linkDraft?.link && text.includes(linkDraft.url) ? linkDraft.link : undefined;
  linkDraft = null; removedLinks.clear(); clearTimeout(unfurlTimer); paintLinkDraft();
  return link;
}
function composerChanged() {
  const text = $('chat-input').value;
  $('chat-form').dataset.empty = String(!text.trim());
  scheduleUnfurl();
  window.App?.onTyping?.(Boolean(text.trim()) && !editing);
}
$('chat-input').addEventListener('input', composerChanged);
$('chat-input').addEventListener('blur', () => window.App?.onTyping?.(false));
$('chat-input').addEventListener('paste', event => {
  const files = [...event.clipboardData?.files || []];
  if (files.length && accountChat) { event.preventDefault(); sendFiles(files); }
});
$('attach').onclick = () => $('attach-input').click();
$('attach-input').onchange = () => { const files = [...$('attach-input').files]; $('attach-input').value = ''; sendFiles(files); };
{
  const section = $('chat-log').closest('.chat-section');
  let depth = 0;
  const hasFiles = event => [...event.dataTransfer?.types || []].includes('Files');
  section.addEventListener('dragenter', event => { if (!hasFiles(event) || !accountChat) return; depth++; section.dataset.drop = 'yes'; });
  section.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; delete section.dataset.drop; } });
  section.addEventListener('dragover', event => { if (hasFiles(event) && accountChat) event.preventDefault(); });
  section.addEventListener('drop', event => { if (!hasFiles(event) || !accountChat) return; event.preventDefault(); depth = 0; delete section.dataset.drop; sendFiles(event.dataTransfer.files); });
}
let recording = null;
async function startRecording() {
  if (!accountChat || recording || !window.Files?.voiceSupported()) { if (!window.Files?.voiceSupported()) chatStatus('This browser can’t record voice messages.'); return; }
  recording = { starting: true };
  try {
    const session = await window.Files.record(level => { $('record-level').style.setProperty('--level', level.toFixed(2)); });
    if (!recording) { session.cancel(); return; }
    recording = { session, timer: setInterval(() => { $('record-time').textContent = window.Files.duration(session.elapsed); if (session.elapsed >= 600) finishRecording(true); }, 250) };
    $('record-time').textContent = '0:00'; $('record-bar').hidden = false; view('recording', 'yes'); $('record-send').focus();
  } catch (error) {
    recording = null;
    chatStatus(error.name === 'NotAllowedError' ? 'Microphone access is off. Allow it in your browser settings to record voice messages.' : error.name === 'NotFoundError' ? 'No microphone found. Connect one to record a voice message.' : 'Couldn’t start recording on this device.');
  }
}
async function finishRecording(send) {
  const current = recording; recording = null;
  $('record-bar').hidden = true; view('recording', '');
  if (!current?.session) return;
  clearInterval(current.timer);
  if (!send) { current.session.cancel(); $('chat-input').focus(); return; }
  const result = await current.session.stop();
  $('chat-input').focus();
  if (result.duration < 0.7 || !result.blob.size) { chatStatus('That was too short to send. Hold on a little longer.'); return; }
  const extension = result.mime.includes('mp4') || result.mime.includes('aac') ? 'm4a' : result.mime.includes('ogg') ? 'ogg' : 'webm';
  const file = new File([result.blob], `Voice message.${extension}`, { type: result.mime.split(';')[0] });
  await sendAttachment(file, { kind: 'voice', mime: result.mime, duration: result.duration, waveform: result.waveform });
}
$('voice-record').onclick = () => startRecording();
$('record-cancel').onclick = () => finishRecording(false);
$('record-send').onclick = () => finishRecording(true);
$('record-bar').addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); finishRecording(false); } });

// ---------- Settings: read receipts and link previews ----------
for (const [id, key] of [['pref-read-receipts', 'read-receipts-v1'], ['pref-link-previews', 'link-previews-v1']]) {
  $(id).checked = preference(key);
  $(id).onchange = () => { try { localStorage.setItem(key, $(id).checked ? 'on' : 'off'); } catch {} transcriptSignature = ''; refreshHistory(); };
}

// ---------- Command palette actions ----------
window.Palette?.register(() => {
  const inConversation = Boolean(selectedHistory) && Boolean($('chat-log').offsetParent);
  const items = [
    { id: 'action:new', group: 'Actions', label: 'New conversation', keywords: 'add contact start chat', run: () => { if ($('app').dataset.auth === 'in') { if ($('app').dataset.screen === 'conversation') $('conv-back').click(); $('contact-input').focus(); } else $('invitation-panel').open = true; } },
    { id: 'action:settings', group: 'Actions', label: 'Settings', keywords: 'preferences backup notifications', run: () => { if ($('app').dataset.auth === 'in') $('account-settings').click(); else { $('settings').open = true; view('panel', 'settings'); } } },
    { id: 'action:theme', group: 'Actions', label: 'Theme…', keywords: 'appearance colour color dark light', run: () => window.Theme?.open('app') },
    { id: 'action:density', group: 'Actions', label: 'Toggle density', hint: window.Theme?.appearance.density === 'compact' ? 'Compact' : 'Comfortable', keywords: 'spacing compact comfortable', run: () => { const density = window.Theme?.toggleDensity(); chatStatus(density ? `Spacing: ${density}.` : ''); } },
    { id: 'action:bigger', group: 'Actions', label: 'Larger text', keywords: 'text size font zoom', run: () => { const sizes = ['s', 'm', 'l', 'xl'], at = sizes.indexOf(window.Theme?.appearance.size); window.Theme?.setAppearance({ size: sizes[Math.min(3, at + 1)] }); } },
    { id: 'action:smaller', group: 'Actions', label: 'Smaller text', keywords: 'text size font', run: () => { const sizes = ['s', 'm', 'l', 'xl'], at = sizes.indexOf(window.Theme?.appearance.size); window.Theme?.setAppearance({ size: sizes[Math.max(0, at - 1)] }); } },
  ];
  if (inConversation) items.push({ id: 'action:find', group: 'Actions', label: 'Search this chat', hint: '⌘F', keywords: 'find', run: openFind });
  return items;
});
/** Leaving a conversation drops its reply, edit, link preview, recording and find state. */
function resetComposerContext() {
  if (recording) finishRecording(false);
  if (editing) { $('chat-input').value = ''; resizeComposer(); }
  editing = null; replying = null; linkDraft = null; removedLinks.clear(); clearTimeout(unfurlTimer);
  paintContext(); paintLinkDraft(); hideActions(); closeEmojiPicker();
  if (!$('find-bar').hidden) { $('find-bar').hidden = true; findMatches = []; globalThis.CSS?.highlights?.delete('find'); globalThis.CSS?.highlights?.delete('find-current'); }
  $('chat-form').dataset.empty = String(!$('chat-input').value.trim());
}
  // Hooks for account.js: contact conversations reuse this call and chat engine unchanged.
window.App = {
  get active() { return active; }, get roomId() { return roomId; }, get conversationId() { return conversationId; },
  status, chatStatus, refreshHistory, view, messagePayload, accountId: null, myName: null,
  rescheduleReminders: () => scheduleReminders(),
  preview, showTyping, flash,
  get readReceipts() { return readReceiptsOn(); },
  openConversation(next) {
    if (active && conversationId !== next.conversationId) throw new Error('busy');
    if (conversationId !== next.conversationId) { resetComposerContext(); showTyping(false); }
    conversationId = selectedHistory = next.conversationId; peerName = next.peerName; peerKey = next.peerId || null; accountChat = true; transcriptSignature = '';
    window.Theme?.use(conversationId);
    if (!active) { validInvite = false; chatStatus(''); }
    // With a keyboard, opening a chat puts the cursor in the message box (phones keep their keyboard closed).
    refreshHistory().then(() => { if (window.matchMedia?.('(pointer: fine)')?.matches) $('chat-input').focus?.(); });
  },
  closeConversation() { if (!active) { resetComposerContext(); showTyping(false); accountChat = false; conversationId = null; peerKey = null; selectedHistory = ''; window.Theme?.use(null); refreshHistory(); } },
  async start(next) {
    if (active) { cleanup('Switching conversation…'); }
    lifecycle++; roomId = next.roomId; token = next.token; validInvite = true; peerBurned = false;
    conversationId = selectedHistory = next.conversationId; peerName = next.peerName; peerKey = next.peerId || peerKey; accountChat = true; window.Theme?.use(conversationId);
    $('remote').closest('figure').querySelector('figcaption').textContent = next.peerName;
    // audioOnly: a video call answered with the microphone only; the camera can be added later.
    await join(next.kind === 'chat' ? 'chat' : next.kind === 'voice' || next.audioOnly ? 'audio' : 'video');
  },
  end: () => endRoom('Conversation ended.'),
  leave() { if (active) cleanup('Conversation closed.'); },
};
refreshHistory();
window.Commands?.attach($('chat-input'), $('cmd-popup'), commandContext);
scheduleReminders();
