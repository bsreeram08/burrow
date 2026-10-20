'use strict';
(() => {
  const MAX_MESSAGES = 2000, MAX_PER_CONVERSATION = 500, CLOCK_SKEW = 300000, MAX_FILE = 10 * 1024 * 1024, MAX_AGE = 30 * 86400000;
  const ITERATIONS = 600000, encoder = new TextEncoder();
  const FIELDS = ['id', 'conversationId', 'direction', 'text', 'createdAt', 'status', 'expiresAt'];
  // Optional rich content. `text` is always a readable fallback, so anything that cannot show the rich
  // form still shows the message. kind 'action' is a /me line; kind 'poll' carries {question, options}
  // and local tallies in `votes` ({me, peer}: option index or null) — 1:1 chats have two voters.
  const OPTIONAL = ['kind', 'poll', 'votes'], MAX_OPTIONS = 10, MAX_OPTION = 200;
  // Phase 1 content (docs/phase1-protocol.md §1–3). `replyTo`, `attachment` and `link` arrive with the message
  // and never change. `reactions` ({me, peer}: emoji lists) and `editedText`/`editedAt` are later mutations.
  const CONTENT = ['replyTo', 'attachment', 'link'], MUTABLE = ['reactions', 'editedText', 'editedAt'];
  // Groups and channels (docs/m4-groups.md §10): the conversation id is the 22-character channel id. Incoming
  // records name their sender (`from`, and `fromName` as it was then); `mentions` arrive with the message;
  // `readBy` (user ids) is a later mutation of our own messages. Reactions are kept per person: `me` or a user id.
  const GROUP = ['from', 'fromName', 'mentions', 'readBy'], MAX_MENTIONS = 64, MAX_READERS = 1000, GROUP_KEEP = 500;
  // `imported: true`: history a linked device received from your other device (docs/m5-linking.md §2), shown as such.
  const LOCAL = ['imported'];
  const STATUSES = ['queued', 'sent', 'delivered', 'read', 'uncertain'], RANK = { queued: 0, uncertain: 0, sent: 1, delivered: 2, read: 3 };
  const MAX_PAYLOAD = 16384, MAX_BLOB = 25 * 1024 * 1024, MAX_REACTIONS = 20, MAX_READ_IDS = 100;
  const ATTACHMENT_KINDS = ['image', 'video', 'audio', 'voice', 'file'];
  const B64URL = /^[A-Za-z0-9_-]+$/, MIME = /^[a-z0-9][a-z0-9.+-]{0,40}\/[a-z0-9][a-z0-9.+-]{0,60}(?:;[ -~]{0,60})?$/i, CUSTOM = /^:[a-z0-9_+-]{2,32}:$/; // Custom emoji names as the server allows them.
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const ROOM = /^(?:[A-Za-z0-9_-]{22}|[A-Za-z0-9_-]{43})$/, USER = /^[A-Za-z0-9_-]{22}$/, USERNAME = /^[a-z0-9_]{3,20}$/;
  const isGroup = conversationId => typeof conversationId === 'string' && conversationId.length === 22;
  const FORMAT = 'webrtc-bun-chat-backup';
  const aad = encoder.encode(`${FORMAT}:1:PBKDF2-SHA256:${ITERATIONS}:AES-256-GCM`);
  let database;

  function exactObject(value, fields) {
    return value && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
  }
  const shortText = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
  /** A poll's question and 2–10 options, each at most 200 characters; returns a clean copy or throws. */
  function cleanPoll(poll) {
    if (!exactObject(poll, ['question', 'options']) || !shortText(poll.question, MAX_OPTION) || !Array.isArray(poll.options) ||
        poll.options.length < 2 || poll.options.length > MAX_OPTIONS || !poll.options.every(option => shortText(option, MAX_OPTION))) throw new Error('Invalid poll.');
    return { question: poll.question, options: [...poll.options] };
  }
  const bytes = text => encoder.encode(text).byteLength;
  const isInt = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
  const optional = (value, test) => value === undefined || test(value);
  const fieldsWithin = (value, allowed, required = []) => value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).every(key => allowed.includes(key)) && required.every(key => Object.hasOwn(value, key));
  /** A `data:image/jpeg;base64,` placeholder of at most 4 KB decoded. */
  const thumbOk = value => typeof value === 'string' && value.startsWith('data:image/jpeg;base64,') && value.length <= 23 + 5464 && /^[A-Za-z0-9+/]+={0,2}$/.test(value.slice(23));
  const httpsUrl = value => { if (typeof value !== 'string' || value.length > 2048) return false; try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password; } catch { return false; } };
  const graphemeCount = text => globalThis.Intl?.Segmenter ? [...new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text)].length : [...text].length;
  /** One emoji grapheme or a custom `:name:`, at most 40 UTF-8 bytes. */
  function emojiOk(value) {
    if (typeof value !== 'string' || !value || bytes(value) > 40) return false;
    if (CUSTOM.test(value)) return true;
    return graphemeCount(value) === 1 && /\p{Extended_Pictographic}|\p{Regional_Indicator}|[#*0-9]\uFE0F?\u20E3/u.test(value);
  }
  function cleanReply(reply) {
    if (!exactObject(reply, ['id', 'text']) || typeof reply.id !== 'string' || !UUID.test(reply.id) || typeof reply.text !== 'string' || reply.text.length > 140) throw new Error('Invalid reply.');
    return { id: reply.id.toLowerCase(), text: reply.text };
  }
  function cleanLink(link, text) {
    if (!fieldsWithin(link, ['url', 'title', 'description', 'site', 'thumb'], ['url']) || !httpsUrl(link.url) || !text.includes(link.url) ||
        !optional(link.title, value => typeof value === 'string' && value.length <= 200) || !optional(link.description, value => typeof value === 'string' && value.length <= 300) ||
        !optional(link.site, value => typeof value === 'string' && value.length <= 60) || !optional(link.thumb, thumbOk)) throw new Error('Invalid link preview.');
    return Object.fromEntries(['url', 'title', 'description', 'site', 'thumb'].filter(key => link[key] !== undefined).map(key => [key, link[key]]));
  }
  // Bidi controls, isolates and zero-width characters let "report\u202Efdp.exe" read as "reportexe.pdf": stored names drop them.
  const INVISIBLE = /[\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;
  const ATTACHMENT_FIELDS = ['kind', 'blob', 'key', 'sha256', 'mime', 'name', 'size', 'width', 'height', 'duration', 'waveform', 'thumb'];
  function cleanAttachment(file) {
    const visual = ['image', 'video'].includes(file?.kind), timed = ['audio', 'voice', 'video'].includes(file?.kind);
    if (!fieldsWithin(file, ATTACHMENT_FIELDS, ['kind', 'blob', 'key', 'sha256', 'mime', 'name', 'size']) || !ATTACHMENT_KINDS.includes(file.kind) ||
        typeof file.blob !== 'string' || file.blob.length < 16 || file.blob.length > 64 || !B64URL.test(file.blob) ||
        typeof file.key !== 'string' || file.key.length !== 43 || !B64URL.test(file.key) || typeof file.sha256 !== 'string' || file.sha256.length !== 43 || !B64URL.test(file.sha256) ||
        typeof file.mime !== 'string' || !MIME.test(file.mime) || typeof file.name !== 'string' || file.name.length > 120 || !isInt(file.size, 0, MAX_BLOB) ||
        !optional(file.width, value => visual && isInt(value, 1, 32768)) || !optional(file.height, value => visual && isInt(value, 1, 32768)) ||
        !optional(file.duration, value => timed && typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 86400) ||
        !optional(file.waveform, value => ['voice', 'audio'].includes(file.kind) && Array.isArray(value) && value.length <= 64 && value.every(level => isInt(level, 0, 31))) ||
        !optional(file.thumb, value => visual && thumbOk(value))) throw new Error('Invalid attachment.');
    const out = Object.fromEntries(ATTACHMENT_FIELDS.filter(key => file[key] !== undefined).map(key => [key, file[key]]));
    if (out.waveform) out.waveform = [...out.waveform];
    out.name = out.name.replace(INVISIBLE, '').trim() || 'file';
    return out;
  }
  const userList = (value, max) => Array.isArray(value) && value.length >= 1 && value.length <= max && value.every(id => typeof id === 'string' && USER.test(id)) && new Set(value).size === value.length;
  function cleanReactions(reactions, group) {
    const people = reactions && typeof reactions === 'object' && !Array.isArray(reactions) ? Object.keys(reactions) : null;
    if (!people || (group ? people.length > MAX_READERS + 1 || !people.every(who => who === 'me' || USER.test(who)) : !fieldsWithin(reactions, ['me', 'peer']))) throw new Error('Invalid reactions.');
    const out = {}, all = new Set();
    for (const [who, list] of Object.entries(reactions)) {
      if (!Array.isArray(list) || !list.every(emojiOk) || new Set(list).size !== list.length) throw new Error('Invalid reactions.');
      if (list.length) out[who] = [...list];
      for (const emoji of list) all.add(emoji);
    }
    if (all.size > MAX_REACTIONS) throw new Error('Invalid reactions.');
    return out;
  }
  const voteOk = (value, count) => value === null || Number.isSafeInteger(value) && value >= 0 && value < count;
  function cleanRich(message) {
    const extra = Object.keys(message).filter(key => !FIELDS.includes(key));
    if (extra.some(key => !OPTIONAL.includes(key) && !CONTENT.includes(key) && !MUTABLE.includes(key) && !GROUP.includes(key) && !LOCAL.includes(key))) throw new Error('Invalid chat message.');
    const out = {};
    if (message.kind === undefined) { if (message.poll !== undefined || message.votes !== undefined) throw new Error('Invalid chat message.'); return out; }
    if (message.direction === 'system' || !['action', 'poll'].includes(message.kind)) throw new Error('Invalid chat message.');
    out.kind = message.kind;
    if (message.kind === 'action') { if (message.poll !== undefined || message.votes !== undefined) throw new Error('Invalid chat message.'); return out; }
    out.poll = cleanPoll(message.poll);
    if (message.votes !== undefined) {
      const votes = message.votes;
      if (!votes || typeof votes !== 'object' || Array.isArray(votes) || Object.keys(votes).some(key => !['me', 'peer'].includes(key)) ||
          !Object.values(votes).every(value => voteOk(value, out.poll.options.length))) throw new Error('Invalid poll votes.');
      out.votes = { ...votes };
    }
    return out;
  }
  // 'system' rows (local notices such as a session reset) exist only on this device: only note() writes them
  // and stored records are read back with them allowed; put() and backup import never accept them.
  function validate(message, allowSystem = false) {
    if (!message || typeof message !== 'object' || Array.isArray(message) || !FIELDS.every(key => Object.hasOwn(message, key)) || typeof message.id !== 'string' || !UUID.test(message.id) ||
        typeof message.conversationId !== 'string' || !ROOM.test(message.conversationId) ||
        !(['incoming', 'outgoing'].includes(message.direction) || allowSystem && message.direction === 'system') || typeof message.text !== 'string' ||
        message.text.length === 0 && message.attachment === undefined || encoder.encode(message.text).byteLength > 4096 ||
        !Number.isSafeInteger(message.createdAt) || message.createdAt < 0 || message.createdAt > 8640000000000000 ||
        !STATUSES.includes(message.status) ||
        !(message.expiresAt === null || Number.isSafeInteger(message.expiresAt) &&
          message.expiresAt > message.createdAt && message.expiresAt <= Math.min(8640000000000000, message.createdAt + MAX_AGE))) {
      throw new Error('Invalid chat message. Only message content and delivery metadata are allowed.');
    }
    const rich = cleanRich(message), group = isGroup(message.conversationId);
    if (GROUP.some(key => message[key] !== undefined)) {
      // Senders only on incoming group rows (always there), mentions only in groups, read-by only on our own.
      const incoming = message.direction === 'incoming';
      if (!group || incoming !== (message.from !== undefined) || (message.fromName !== undefined && !incoming) ||
          !optional(message.from, value => typeof value === 'string' && USER.test(value)) || !optional(message.fromName, value => typeof value === 'string' && USERNAME.test(value)) ||
          !optional(message.mentions, value => userList(value, MAX_MENTIONS)) || !optional(message.readBy, value => message.direction === 'outgoing' && userList(value, MAX_READERS))) throw new Error('Invalid chat message.');
      for (const key of GROUP) if (message[key] !== undefined) rich[key] = Array.isArray(message[key]) ? [...message[key]] : message[key];
    } else if (group && message.direction === 'incoming') throw new Error('Invalid chat message.');
    if (message.imported !== undefined) {
      if (message.imported !== true || message.direction === 'system') throw new Error('Invalid chat message.');
      rich.imported = true;
    }
    const extra = Object.keys(message).filter(key => CONTENT.includes(key) || MUTABLE.includes(key));
    if (extra.length) {
      if (message.direction === 'system' || rich.kind === 'poll' && (message.attachment !== undefined || message.link !== undefined)) throw new Error('Invalid chat message.');
      try {
        if (message.replyTo !== undefined) rich.replyTo = cleanReply(message.replyTo);
        if (message.attachment !== undefined) rich.attachment = cleanAttachment(message.attachment);
        if (message.link !== undefined) rich.link = cleanLink(message.link, message.text);
        if (message.reactions !== undefined) { const reactions = cleanReactions(message.reactions, group); if (Object.keys(reactions).length) rich.reactions = reactions; }
        if ((message.editedText === undefined) !== (message.editedAt === undefined)) throw new Error('Invalid edit.');
        if (message.editedText !== undefined) {
          if (typeof message.editedText !== 'string' || message.editedText.length === 0 && !rich.attachment || bytes(message.editedText) > 4096 ||
              !isInt(message.editedAt, 0, 8640000000000000) || rich.kind === 'poll') throw new Error('Invalid edit.');
          rich.editedText = message.editedText; rich.editedAt = message.editedAt;
        }
      } catch { throw new Error('Invalid chat message.'); }
    }
    // The content a sender committed to (what travels in the payload) stays within the 16 KB payload bound.
    if (bytes(JSON.stringify([message.text, rich.kind, rich.poll, rich.replyTo, rich.attachment, rich.link])) > MAX_PAYLOAD) throw new Error('Invalid chat message.');
    // Explicitly construct the stored record: never serialize invitation tokens, keys or UI state.
    return { ...Object.fromEntries(FIELDS.map(key => [key, key === 'id' ? message.id.toLowerCase() : message[key]])), ...rich };
  }
  const expired = (message, now = Date.now()) => message.expiresAt !== null && message.expiresAt <= now;
  const key = message => `${message.conversationId}:${message.id.toLowerCase()}`;
  const sorted = messages => messages.sort((a, b) => a.createdAt - b.createdAt || key(a).localeCompare(key(b)));
  // Same message: identical fields, kind, poll, reply, attachment and link. Votes, reactions and edits are
  // later mutations and never conflict; the original `text` stays immutable so a redelivery still matches.
  const sameContent = (a, b) => FIELDS.every(field => field === 'status' || a[field] === b[field]) && a.kind === b.kind && a.from === b.from &&
    ['poll', 'mentions', ...CONTENT].every(field => JSON.stringify(a[field]) === JSON.stringify(b[field]));
  /** Delivery only moves forward once confirmed: delivered and read are never downgraded, and read beats delivered. */
  const forward = (previous, status) => ['delivered', 'read'].includes(previous) && RANK[previous] >= RANK[status] ? previous : status;
  function combine(previous, next) {
    if (previous && !sameContent(previous, next)) {
      throw new Error('A duplicate message has conflicting content or expiration. Nothing was imported.');
    }
    if (!previous) return next;
    const merged = { ...next, status: forward(previous.status, next.status) };
    if (previous.votes) merged.votes = previous.votes;
    if (previous.reactions) merged.reactions = previous.reactions;
    if (previous.readBy) merged.readBy = previous.readBy;
    if (previous.editedAt !== undefined && !(next.editedAt > previous.editedAt)) { merged.editedText = previous.editedText; merged.editedAt = previous.editedAt; }
    return merged;
  }
  function openDatabase() {
    if (!database) database = new Promise((resolve, reject) => {
      if (!globalThis.indexedDB) { reject(new Error('Device chat storage is unavailable in this browser.')); return; }
      const request = indexedDB.open('webrtc-bun-chat-v1', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('messages', { keyPath: ['conversationId', 'id'] });
      request.onerror = () => reject(new Error('Could not open device chat storage.'));
      request.onblocked = () => reject(new Error('Close other app windows and try device storage again.'));
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => { db.close(); database = undefined; };
        resolve(db);
      };
    }).catch(error => { database = undefined; throw error; });
    return database;
  }
  async function transaction(change) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite'), store = tx.objectStore('messages');
      let result, failure;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(failure || new Error('Could not save chats on this device. Storage may be full or unavailable.'));
      tx.onerror = () => { /* The abort event reports a single consistent storage error. */ };
      const request = store.getAll();
      request.onsuccess = () => {
        try {
          const active = new Map(), now = Date.now();
          for (const value of request.result) {
            const message = validate(value, true);
            if (expired(message, now)) store.delete([message.conversationId, message.id]);
            else active.set(key(message), message);
          }
          if (active.size > MAX_MESSAGES) throw new Error('Device chat storage exceeds the 2,000-message limit.');
          const update = change(active, now);
          if (update.clear) store.clear();
          for (const record of update.deletes || []) store.delete([record.conversationId, record.id]);
          for (const message of update.writes || []) store.put(message);
          result = update.result;
        } catch (error) { failure = error; tx.abort(); }
      };
    });
  }
  async function put(value) {
    const message = validate(value);
    if (expired(message)) throw new Error('This disappearing message has expired.');
    return transaction((active, now) => {
      if (expired(message, now)) throw new Error('This disappearing message has expired.');
      const previous = active.get(key(message));
      if (!previous && active.size >= MAX_MESSAGES) throw new Error('This device holds 2,000 messages. Clear chat history before adding more.');
      const next = combine(previous, message);
      return { writes: [next], result: next };
    });
  }
  const coded = (code, text) => Object.assign(new Error(text), { code });
  /**
   * Stores one decrypted incoming message, idempotent by id, using the same validation as every stored
   * record. Deterministic rejections carry a code so the caller acknowledges and discards the envelope
   * instead of retrying forever: 'invalid', 'conflict' (an id reused with other content),
   * 'conversation-full' (500 incoming messages from this conversation: only this sender is refused, so one
   * contact cannot crowd out the others) and 'full' (the 2,000-message device cap). Nothing is evicted.
   * Resolves to 'stored', 'duplicate' or 'expired'.
   */
  async function receive(conversationId, payload, sender) {
    let message, createdAt = payload?.createdAt, expiresAt = payload?.expiresAt;
    // A sender whose clock runs ahead must not lose messages (nor pin them to the end of every list):
    // date them on arrival and keep their disappearing lifetime.
    const now = Date.now();
    if (Number.isSafeInteger(createdAt) && createdAt > now + CLOCK_SKEW) {
      if (Number.isSafeInteger(expiresAt)) expiresAt -= createdAt - now;
      createdAt = now;
    }
    const rich = payload?.kind === undefined ? {} : payload.kind === 'poll' ? { kind: 'poll', poll: payload.poll } : { kind: payload.kind };
    for (const field of CONTENT) if (payload?.[field] !== undefined) rich[field] = payload[field];
    // A group message names its sender (from the MLS credential, never the payload) and may carry mentions.
    if (isGroup(conversationId)) {
      if (rich.kind === 'poll') throw coded('invalid', 'Invalid incoming message.');
      rich.from = sender?.from; if (sender?.fromName !== undefined) rich.fromName = sender.fromName;
      if (payload?.mentions !== undefined) rich.mentions = payload.mentions;
    } else if (payload?.mentions !== undefined) throw coded('invalid', 'Invalid incoming message.');
    try { message = validate({ id: payload?.id, conversationId, direction: 'incoming', text: payload?.text, createdAt, status: 'delivered', expiresAt, ...rich }); }
    catch { throw coded('invalid', 'Invalid incoming message.'); }
    if (expired(message)) return 'expired';
    return transaction((active, now) => {
      if (expired(message, now)) return { result: 'expired' };
      const previous = active.get(key(message));
      if (previous) {
        if (!sameContent(previous, message)) throw coded('conflict', 'A message identifier was reused with different content.');
        return { result: 'duplicate' };
      }
      // A group keeps its newest 500 messages: the oldest go, instead of refusing the new one (one sender can
      // still crowd out only that group). DMs refuse the 501st incoming message, as before.
      if (isGroup(conversationId)) {
        const mine = sorted([...active.values()].filter(value => value.conversationId === conversationId));
        const over = Math.max(0, mine.length + 1 - GROUP_KEEP, active.size + 1 - MAX_MESSAGES);
        if (over > mine.length) throw coded('full', 'This device holds 2,000 messages. Clear chat history to receive more.');
        return { writes: [message], deletes: mine.slice(0, over), result: 'stored' };
      }
      if (fromPeer(active, conversationId) >= MAX_PER_CONVERSATION) throw coded('conversation-full', 'This conversation holds 500 incoming messages.');
      if (active.size >= MAX_MESSAGES) throw coded('full', 'This device holds 2,000 messages. Clear chat history to receive more.');
      return { writes: [message], result: 'stored' };
    });
  }
  /**
   * Shape of a decrypted contact payload; message content itself is validated by receive().
   * 'rotate' asks the peer to drop old sessions; 'policy' carries the sender's rotation interval in ms
   * (only known choices take effect, see Signal.rotationInterval). Returns the payload type.
   */
  function checkPayload(payload) {
    const bad = () => coded('invalid', 'Invalid message');
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.v !== 1 || typeof payload.id !== 'string' || !UUID.test(payload.id)) throw bad();
    const size = Object.keys(payload).length, keys = Object.keys(payload);
    let encoded = Infinity; try { encoded = encoder.encode(JSON.stringify(payload)).byteLength; } catch {}
    if (encoded > MAX_PAYLOAD) throw bad();
    switch (payload.type) {
      case 'receipt': case 'burn': if (size === 3) return payload.type; break;
      // Plain, a /me action (+kind) or a poll (+kind, +poll), each optionally with a reply, one attachment and
      // a link preview; content is validated by receive().
      case 'message': {
        const base = ['v', 'type', 'id', 'text', 'createdAt', 'expiresAt'];
        if (!base.every(key => keys.includes(key)) || keys.some(key => !base.includes(key) && !['kind', 'poll', 'mentions', ...CONTENT].includes(key))) break;
        if (payload.mentions !== undefined && !userList(payload.mentions, MAX_MENTIONS)) break;
        if (payload.kind === undefined ? !('poll' in payload) && !('kind' in payload) : payload.kind === 'action' ? !('poll' in payload) : payload.kind === 'poll' && 'poll' in payload) return payload.type;
        break;
      }
      case 'react': if (size === 6 && typeof payload.target === 'string' && UUID.test(payload.target) && emojiOk(payload.emoji) && typeof payload.on === 'boolean') return payload.type; break;
      case 'edit': if (size === 6 && typeof payload.target === 'string' && UUID.test(payload.target) && typeof payload.text === 'string' && bytes(payload.text) <= 4096 && isInt(payload.editedAt, 0, 8640000000000000)) return payload.type; break;
      case 'read': if (size === 4 && Array.isArray(payload.ids) && payload.ids.length >= 1 && payload.ids.length <= MAX_READ_IDS && payload.ids.every(id => typeof id === 'string' && UUID.test(id))) return payload.type; break;
      case 'typing': if (size === 5 && isInt(payload.at, 0, 8640000000000000) && typeof payload.on === 'boolean') return payload.type; break;
      case 'vote': if (size === 5 && typeof payload.poll === 'string' && UUID.test(payload.poll) && (payload.option === null || Number.isSafeInteger(payload.option) && payload.option >= 0 && payload.option < MAX_OPTIONS)) return payload.type; break;
      case 'rotate': if (size === 4 && ['manual', 'scheduled'].includes(payload.reason)) return payload.type; break;
      case 'policy': if (size === 4 && Number.isSafeInteger(payload.rotateEveryMs) && payload.rotateEveryMs >= 0) return payload.type; break;
      // Groups only (docs/m4-groups.md §5): an admin's name and topic, and "remove me".
      case 'meta': if (size === 6 && typeof payload.name === 'string' && [...payload.name].length <= 64 && !/[\u0000-\u001f]/.test(payload.name) && typeof payload.topic === 'string' && [...payload.topic].length <= 256 && isInt(payload.at, 0, 8640000000000000)) return payload.type; break;
      case 'leave': if (size === 3) return payload.type; break;
      // The last Double Ratchet message of a 1:1 chat: it continues in this MLS DM group (docs/m5-linking.md §8.2).
      case 'mls-dm': if (size === 5 && typeof payload.channel === 'string' && USER.test(payload.channel) && isInt(payload.at, 0, 8640000000000000)) return payload.type; break;
    }
    throw bad();
  }
  /**
   * A local, never-sent system line (e.g. "secure session reset"), stored once per id. Peer-triggered lines
   * count toward the same caps as incoming messages, and one written within a minute of the previous
   * system line in that conversation replaces it instead of adding a row, so a contact cannot flood them.
   * Groups keep each line (who joined, left, was added) under their newest-500 rule instead.
   */
  async function note(conversationId, id, text) {
    const message = validate({ id, conversationId, direction: 'system', text, createdAt: Date.now(), status: 'delivered', expiresAt: null }, true);
    return transaction((active, now) => {
      if (active.has(key(message))) return { result: false };
      // A group keeps every membership line (the server rate-limits commits, and the newest-500 rule bounds them).
      if (isGroup(conversationId)) {
        const mine = sorted([...active.values()].filter(value => value.conversationId === conversationId));
        const over = Math.max(0, mine.length + 1 - GROUP_KEEP, active.size + 1 - MAX_MESSAGES);
        if (over > mine.length) throw coded('full', 'This device holds 2,000 messages. Clear chat history to receive more.');
        return { writes: [message], deletes: mine.slice(0, over), result: true };
      }
      const recent = [...active.values()].filter(value => value.conversationId === conversationId && value.direction === 'system' && now - value.createdAt < 60000).at(-1);
      if (recent) return { writes: [{ ...recent, text: message.text, createdAt: Math.max(recent.createdAt, message.createdAt) }], result: false };
      if (fromPeer(active, conversationId) >= MAX_PER_CONVERSATION) throw coded('conversation-full', 'This conversation holds 500 incoming messages.');
      if (active.size >= MAX_MESSAGES) throw coded('full', 'This device holds 2,000 messages. Clear chat history to receive more.');
      return { writes: [message], result: true };
    });
  }
  /**
   * Records one voter's choice on a poll in this conversation (null clears it). One vote per voter,
   * changeable; a vote for an unknown poll or option is ignored. Updates in place, so votes add no rows.
   */
  async function vote(conversationId, pollId, voter, option) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || typeof pollId !== 'string' || !UUID.test(pollId) || !['me', 'peer'].includes(voter)) throw coded('invalid', 'Invalid vote.');
    return transaction(active => {
      const poll = active.get(`${conversationId}:${pollId.toLowerCase()}`);
      if (poll?.kind !== 'poll' || !voteOk(option, poll.poll.options.length)) return { result: false };
      if ((poll.votes?.[voter] ?? null) === option) return { result: true };
      return { writes: [{ ...poll, votes: { ...poll.votes, [voter]: option } }], result: true };
    });
  }
  /** 'me' and 'peer' in a 1:1 chat; 'me' or a user id in a group. */
  const personOk = (conversationId, who) => who === 'me' || (isGroup(conversationId) ? typeof who === 'string' && USER.test(who) : who === 'peer');
  /**
   * Toggles one person's reaction on a message in this conversation ('me' or 'peer'; in a group 'me' or a user id).
   * Each person holds a set of emoji; at most 20 distinct emoji per message. Unknown targets are ignored.
   * Updates in place, so reactions add no rows. Resolves true when the target exists.
   */
  async function react(conversationId, targetId, who, emoji, on) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || typeof targetId !== 'string' || !UUID.test(targetId) || !personOk(conversationId, who) || !emojiOk(emoji) || typeof on !== 'boolean') throw coded('invalid', 'Invalid reaction.');
    return transaction(active => {
      const target = active.get(`${conversationId}:${targetId.toLowerCase()}`);
      if (!target || target.direction === 'system') return { result: false };
      const reactions = Object.fromEntries(Object.entries(target.reactions || {}).map(([person, list]) => [person, [...list]]));
      const mine = reactions[who] ||= [];
      if (on === mine.includes(emoji)) return { result: true };
      if (on) {
        if (new Set([...Object.values(reactions).flat(), emoji]).size > MAX_REACTIONS) return { result: true };
        mine.push(emoji);
      } else reactions[who] = mine.filter(value => value !== emoji);
      const next = { ...target }; delete next.reactions;
      const kept = Object.fromEntries(Object.entries(reactions).filter(([, list]) => list.length));
      if (Object.keys(kept).length) next.reactions = kept;
      return { writes: [next], result: true };
    });
  }
  /**
   * Applies an edit. Only the author may edit: 'peer' edits apply to incoming messages, 'me' edits to outgoing
   * ones, never polls. The latest editedAt wins, so a reordered or repeated edit is harmless. Attachments and
   * link previews are not editable. Resolves true when the edit is now the shown text.
   */
  async function edit(conversationId, targetId, who, text, editedAt) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || typeof targetId !== 'string' || !UUID.test(targetId) || !personOk(conversationId, who) ||
        typeof text !== 'string' || bytes(text) > 4096 || !isInt(editedAt, 0, 8640000000000000)) throw coded('invalid', 'Invalid edit.');
    return transaction(active => {
      const target = active.get(`${conversationId}:${targetId.toLowerCase()}`);
      // In a group only the message's own sender edits it.
      if (!target || target.direction !== (who === 'me' ? 'outgoing' : 'incoming') || target.kind === 'poll' || (who !== 'me' && who !== 'peer' && target.from !== who)) return { result: false };
      if (!text.trim() && !target.attachment) return { result: false };
      if (target.editedAt !== undefined && editedAt <= target.editedAt) return { result: editedAt === target.editedAt && text === target.editedText };
      return { writes: [validate({ ...target, editedText: text, editedAt })], result: true };
    });
  }
  /**
   * Marks messages read: 'outgoing' when the other person's read receipt arrives, 'incoming' once this device has
   * shown them (so each is reported once). At most 100 ids; unknown ids are ignored. Resolves the ids changed.
   */
  async function markRead(conversationId, ids, direction) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || !Array.isArray(ids) || ids.length > MAX_READ_IDS || !ids.every(id => typeof id === 'string' && UUID.test(id)) || !['incoming', 'outgoing'].includes(direction)) throw coded('invalid', 'Invalid read receipt.');
    return transaction(active => {
      const writes = [];
      for (const id of new Set(ids.map(value => value.toLowerCase()))) {
        const record = active.get(`${conversationId}:${id}`);
        if (record?.direction === direction && record.status !== 'read' && (direction === 'incoming' || ['sent', 'delivered', 'uncertain'].includes(record.status))) writes.push({ ...record, status: 'read' });
      }
      return { writes, result: writes.map(record => record.id) };
    });
  }
  /**
   * A group member read these messages of ours: their user id joins each one's `readBy` (unknown ids and other
   * people's messages are ignored). Resolves the ids changed.
   */
  async function markReadBy(conversationId, ids, reader) {
    if (!isGroup(conversationId) || !Array.isArray(ids) || ids.length > MAX_READ_IDS || !ids.every(id => typeof id === 'string' && UUID.test(id)) || typeof reader !== 'string' || !USER.test(reader)) throw coded('invalid', 'Invalid read receipt.');
    return transaction(active => {
      const writes = [];
      for (const id of new Set(ids.map(value => value.toLowerCase()))) {
        const record = active.get(`${conversationId}:${id}`);
        if (record?.direction === 'outgoing' && !(record.readBy || []).includes(reader) && (record.readBy || []).length < MAX_READERS) writes.push({ ...record, readBy: [...record.readBy || [], reader] });
      }
      return { writes, result: writes.map(record => record.id) };
    });
  }
  /** Rows a contact can cause on this device: their messages and the system lines their payloads add. */
  function fromPeer(active, conversationId) {
    let count = 0;
    for (const value of active.values()) if (value.conversationId === conversationId && value.direction !== 'outgoing') count++;
    return count;
  }
  /**
   * What to do with a mailbox envelope after trying to process it: acknowledge (the server deletes it)
   * or leave it for redelivery. Fails closed: only known permanent outcomes are acknowledged at once.
   * Storage errors and anything uncoded or unknown are retried, and acknowledged with a notice only
   * after `limit` attempts. Every discard except a true replay is reported.
   */
  const PERMANENT = { replay: null, full: 'storage-full', 'conversation-full': 'conversation-full', invalid: 'invalid', conflict: 'conflict', mismatch: 'mismatch', malformed: 'undecryptable', auth: 'undecryptable', 'skip-limit': 'undecryptable', 'unknown-session': 'undecryptable', 'unknown-spk': 'undecryptable', 'claim-limit': 'undecryptable' };
  function inboundDisposition(error, attempts, limit = 3) {
    if (!error) return { ack: true, notice: null };
    if (typeof error.code === 'string' && Object.hasOwn(PERMANENT, error.code)) return { ack: true, notice: PERMANENT[error.code] };
    return attempts >= limit ? { ack: true, notice: 'gave-up' } : { ack: false, notice: 'retrying' };
  }
  const list = () => transaction(active => ({ result: sorted([...active.values()]) }));
  async function setStatus(conversationId, id, status) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || typeof id !== 'string' || !UUID.test(id) ||
        !STATUSES.includes(status)) throw new Error('Invalid message delivery update.');
    return transaction(active => {
      const previous = active.get(`${conversationId}:${id.toLowerCase()}`);
      // A late ACK or send completion must never recreate cleared or expired content.
      if (!previous) return { result: false };
      // Nor may an old send completion turn freshly restored history back into an outbound queue.
      if (previous.status === 'uncertain' && ['queued', 'sent'].includes(status)) return { result: false };
      return { writes: [{ ...previous, status: forward(previous.status, status) }], result: true };
    });
  }
  // Burning one conversation deletes only its records, keyed by the room identifier.
  async function removeConversation(conversationId) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId)) throw new Error('Invalid conversation.');
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new Error('Could not delete this conversation.'));
      tx.objectStore('messages').delete(IDBKeyRange.bound([conversationId], [conversationId, []]));
    });
  }
  // Clearing must also work if an older or corrupted record cannot be validated.
  async function clear() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new Error('Could not clear device chat storage.'));
      tx.objectStore('messages').clear();
    });
  }
  function passwordBytes(password) {
    if (typeof password !== 'string' || password.length < 12 || encoder.encode(password).byteLength > 1024) {
      throw new Error('Use a backup password of at least 12 characters and at most 1,024 UTF-8 bytes.');
    }
    return encoder.encode(password);
  }
  async function derive(password, salt) {
    if (!globalThis.crypto?.subtle) throw new Error('Encrypted backups require a browser with Web Crypto over HTTPS.');
    const material = await crypto.subtle.importKey('raw', passwordBytes(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  function base64(bytes) {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    return btoa(binary);
  }
  function fromBase64(text, min, max) {
    if (typeof text !== 'string' || text.length % 4 !== 0 || text.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
      throw new Error('Invalid encrypted backup encoding.');
    }
    const bytes = Uint8Array.from(atob(text), character => character.charCodeAt(0));
    if (bytes.length < min || bytes.length > max || base64(bytes) !== text) throw new Error('Invalid encrypted backup encoding.');
    return bytes;
  }
  async function exportBackup(password) {
    passwordBytes(password);
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptionKey = await derive(password, salt);
    const messages = (await list()).filter(message => message.direction !== 'system'); // Local notices stay local.
    const plaintext = encoder.encode(JSON.stringify({ version: 1, messages }));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, encryptionKey, plaintext));
    const envelope = { format: FORMAT, version: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, cipher: 'AES-256-GCM', salt: base64(salt), iv: base64(iv), ciphertext: base64(ciphertext) };
    const blob = new Blob([JSON.stringify(envelope)], { type: 'application/json' });
    if (blob.size > MAX_FILE) throw new Error('Encrypted backup exceeds the 10 MiB file limit. Reduce local history before exporting.');
    return blob;
  }
  async function importBackup(file, password) {
    passwordBytes(password);
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > MAX_FILE || typeof file.text !== 'function') throw new Error('Choose an encrypted backup file no larger than 10 MiB.');
    const raw = await file.text();
    if (encoder.encode(raw).byteLength > MAX_FILE) throw new Error('Encrypted backup exceeds the 10 MiB file limit.');
    let envelope;
    try { envelope = JSON.parse(raw); } catch { throw new Error('Invalid encrypted backup file.'); }
    if (!exactObject(envelope, ['format', 'version', 'kdf', 'iterations', 'cipher', 'salt', 'iv', 'ciphertext']) ||
        envelope.format !== FORMAT || envelope.version !== 1 || envelope.kdf !== 'PBKDF2-SHA256' || envelope.iterations !== ITERATIONS || envelope.cipher !== 'AES-256-GCM') {
      throw new Error('Unsupported or invalid encrypted backup format.');
    }
    const salt = fromBase64(envelope.salt, 16, 16), iv = fromBase64(envelope.iv, 12, 12), ciphertext = fromBase64(envelope.ciphertext, 16, MAX_FILE);
    const encryptionKey = await derive(password, salt);
    let plaintext;
    try { plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, encryptionKey, ciphertext); }
    catch { throw new Error('Incorrect backup password or corrupted backup file. Nothing was imported.'); }
    let payload;
    try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
    catch { throw new Error('Invalid decrypted backup content. Nothing was imported.'); }
    if (!exactObject(payload, ['version', 'messages']) || payload.version !== 1 || !Array.isArray(payload.messages) || payload.messages.length > MAX_MESSAGES) {
      throw new Error('Backup must contain at most 2,000 valid messages. Nothing was imported.');
    }
    // Validate every record before opening the write transaction, including expired records.
    const incoming = payload.messages.map(message => validate(message)); // Never system rows.
    return transaction((active, now) => {
      const writes = new Map(); let count = 0;
      for (const message of incoming) {
        if (expired(message, now)) continue;
        const identity = key(message), previous = active.get(identity);
        combine(previous, message); // Reject conflicting immutable fields before accepting a duplicate.
        // Restored history is never an outbound queue. Existing live records win over old backups.
        if (previous) continue;
        const next = message.direction === 'outgoing' && !['delivered', 'read'].includes(message.status) ? { ...message, status: 'uncertain' } : message;
        count++; active.set(identity, next);
        writes.set(identity, next);
      }
      if (active.size > MAX_MESSAGES) throw new Error('Import would exceed 2,000 device messages. Nothing was imported.');
      return { writes: [...writes.values()], result: count };
    });
  }
  /**
   * History a linked device received from your other device (docs/m5-linking.md §2): every record validated like a
   * backup, marked `imported`, never an outbound queue, never overwriting what is here. Resolves the count added.
   */
  async function importLinked(records) {
    if (!Array.isArray(records) || records.length > MAX_MESSAGES) throw new Error('Invalid history.');
    const incoming = [];
    for (const record of records) {
      if (record?.direction === 'system') continue;
      try {
        const clean = validate({ ...record, imported: true });
        incoming.push(clean.direction === 'outgoing' && !['delivered', 'read'].includes(clean.status) ? { ...clean, status: 'uncertain' } : clean);
      } catch {} // One bad record is skipped, not the whole history.
    }
    return transaction((active, now) => {
      const writes = [];
      for (const message of incoming) if (!expired(message, now) && !active.has(key(message)) && active.size + writes.length < MAX_MESSAGES) writes.push(message);
      return { writes, result: writes.length };
    });
  }
  window.ChatStore = Object.freeze({ put, importLinked, list, clear, removeConversation, setStatus, exportBackup, importBackup, receive, note, vote, react, edit, markRead, markReadBy, checkPayload, inboundDisposition, emojiOk, isGroup, MAX_OPTIONS, MAX_BLOB, MAX_REACTIONS, isMessageId: id => typeof id === 'string' && UUID.test(id) });
})();
