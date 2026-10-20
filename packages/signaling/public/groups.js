'use strict';
// Group chats and channels over MLS (docs/m4-groups.md). account.js starts this once signed in and hands it the
// account (API, the 1:1 box for pins and the identity key, contacts) and every group frame of the event stream.
// The group engine runs in one tab per account (a Web Lock); the core it drives is a store of its own beside
// signal.js (core.js groupStore). 1:1 chats stay on Double Ratchet in account.js.
//
// Order is everything in MLS: each channel has one queue, and receiving, sending and committing all run in it.
(() => {
  const $ = id => document.getElementById(id);
  const ID = /^[A-Za-z0-9_-]{22}$/, PIN_ERROR = /no pinned account key for user ([A-Za-z0-9_-]{22})/, POISON = /poison ([0-9a-f]{64})/;
  const READ_RECEIPT_LIMIT = 50, KEYPACKAGES = 100, LOW_WATER = 20, CLAIM_BATCH = 16, EXTERNAL = 4294967295;
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const coded = (code, message) => Object.assign(new Error(message), { code });
  const element = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };

  let ctx = null, run = null, me = null, deviceId = null, instance = '', enabled = false, reason = '', starting = null, generation = 0;
  let channels = new Map(), names = {}, currentId = null;
  const queues = new Map(), cursorTimers = new Map(), pinned = new Set(), typingFrom = new Map();

  // ---------- Local state (per device: cursors are this device's) ----------
  const stateKey = () => `groups-v1:${instance}`, namesKey = () => `names-v1:${me.id}`;
  function load() {
    try { channels = new Map(Object.entries(JSON.parse(localStorage.getItem(stateKey()) || '{}') || {})); } catch { channels = new Map(); }
    for (const ch of channels.values()) delete ch.joining; // A join cut short by a reload is tried again.
    try { names = JSON.parse(localStorage.getItem(namesKey()) || '{}') || {}; } catch { names = {}; }
  }
  let saveTimer = null;
  function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => { try { localStorage.setItem(stateKey(), JSON.stringify(Object.fromEntries(channels))); localStorage.setItem(namesKey(), JSON.stringify(names)); } catch {} }, 50);
  }
  function channel(id, defaults = {}) {
    if (!channels.has(id)) channels.set(id, { kind: 'group_dm', serverName: null, meta: null, cursor: 0, status: 'active', unread: 0, mentioned: false, lastAt: 0, members: [], admins: [], ...defaults });
    return channels.get(id);
  }
  const usable = ch => ch && ch.status === 'active';
  const remember = (userId, username) => { if (ID.test(userId || '') && /^[a-z0-9_]{3,20}$/.test(username || '') && names[userId] !== username) { names[userId] = username; save(); } };
  function nameOf(userId) {
    if (userId === me?.id) return me.username;
    return names[userId] || ctx?.contacts().find(contact => contact.id === userId)?.username || 'someone';
  }
  function title(id) {
    const ch = channels.get(id);
    if (!ch) return 'Conversation';
    if (ch.meta?.name) return ch.meta.name;
    if (ch.kind === 'public' && ch.serverName) return ch.serverName;
    const others = ch.members.filter(member => member.userId !== me.id).map(member => member.username || nameOf(member.userId));
    return others.length ? others.slice(0, 4).join(', ') + (others.length > 4 ? ` and ${others.length - 4} more` : '') : ch.kind === 'group_dm' ? 'New group' : 'New channel';
  }
  const isChannel = ch => ch.kind === 'public' || ch.kind === 'private';
  const amAdmin = id => Boolean(channels.get(id)?.admins.includes(me.id));

  // ---------- HTTP ----------
  /** Like account.js api(), but answers with the status instead of throwing (409/423 are part of the protocol). */
  async function call(path, method = 'GET', payload, { retry = true } = {}) {
    // A burst (a chat moving to MLS, a device joining its groups) can meet the server's rate limits: those are
    // momentary, so wait a little and try again rather than failing the operation.
    for (let attempt = 0; ; attempt++) {
      const response = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', headers: payload === undefined ? {} : { 'Content-Type': 'application/json' }, body: payload === undefined ? undefined : JSON.stringify(payload) });
      const body = await response.json().catch(() => ({}));
      if (response.status !== 429 || !retry || attempt >= 5) return { status: response.status, body };
      await sleep(250 * 2 ** attempt + Math.random() * 250);
    }
  }
  async function must(path, method, payload) {
    const result = await call(path, method, payload);
    if (result.status >= 300) throw Object.assign(new Error(result.body.error || 'Something went wrong. Try again.'), { status: result.status, body: result.body });
    return result.body;
  }

  // ---------- Queues ----------
  function enqueue(id, task) {
    const next = (queues.get(id) || Promise.resolve()).then(task);
    const tail = next.catch(() => {});
    queues.set(id, tail);
    tail.then(() => { if (queues.get(id) === tail) queues.delete(id); });
    return next;
  }
  const idle = id => !queues.has(id);
  const failed = (id, error) => { if (error && error.code !== 'stale') status(id, error.message || 'Something went wrong with this conversation.'); };

  // ---------- Starting ----------
  /**
   * Called by account.js once keys are ready. Groups need the standard core (the experimental one can't sign
   * the device list yet), a listed device, and to be the one tab of this account that runs them.
   */
  function start(context) {
    stop();
    ctx = context; me = context.me; generation++;
    const mine = generation;
    if (context.backend === 'wasm') { reason = 'Groups and channels need the standard encryption core on this device (Settings → Advanced).'; ctx.render(); return; }
    if (!navigator.locks || !window.Core?.supported()) { reason = 'This browser is too old for groups and channels.'; ctx.render(); return; }
    reason = 'Getting groups ready…';
    navigator.locks.request(`groups:${me.id}`, { ifAvailable: true }, lock => {
      if (mine !== generation) return;
      if (lock) { starting = setup(mine); return new Promise(() => {}); }
      reason = 'Your groups are open in another tab of this browser. Use that tab, or close it to use them here.';
      ctx.render();
      // Take over when that tab goes away.
      navigator.locks.request(`groups:${me.id}`, () => { if (mine !== generation) return; starting = setup(mine); return new Promise(() => {}); });
    });
  }
  function stop() {
    generation++; enabled = false; ctx = null; run = null; me = null; currentId = null; channels = new Map(); queues.clear(); pinned.clear();
    for (const timer of cursorTimers.values()) clearTimeout(timer);
    cursorTimers.clear(); typingFrom.clear();
  }
  async function setup(mine) {
    try {
      const device = await window.DeviceFormat.deviceKey(me.id);
      deviceId = device.deviceId;
      // A linked device (docs/m5-linking.md §1) keeps the store it was linked with; its certificate came in the grant.
      const linked = linkedStore(me.id);
      const aik = linked ? null : (await ctx.box.identity()).pub.sign;
      // One store per (account, device, account key): a new device id or identity starts clean (m4 §9).
      instance = linked?.instance || `${me.id}-${deviceId}-${aik.slice(0, 12)}`;
      run = window.Core.groupStore(me.id, instance);
      load();
      const certified = `mls-cert-v1:${instance}`;
      if (!linked && localStorage.getItem(certified) !== '1') {
        const leaf = await run({ cmd: 'mlsDeviceLeaf' }), issuedAt = Date.now(), F = window.DeviceFormat;
        const sig = await ctx.signWithIdentity(F.mlsCertBytes(me.id, deviceId, 'web', leaf, aik, issuedAt));
        await run({ cmd: 'mlsSetDeviceCert', cert: F.mlsCertJson(me.id, deviceId, 'web', leaf, aik, issuedAt, sig), aik });
        try { localStorage.setItem(certified, '1'); } catch {}
      }
      if (mine !== generation) return;
      const count = await call('/api/mls/keypackages');
      if (count.status === 403 || count.status === 409) { reason = 'Groups start once this device is in your signed device list.'; ctx.render(); return; }
      enabled = true; reason = '';
      await topUp(count.body);
      await refreshChannels();
      await welcomes();
      for (const [id, ch] of channels) if (usable(ch)) enqueue(id, () => syncInner(id)).catch(error => failed(id, error));
      flushAll();
      ctx.render();
      removeOwnStale().catch(() => {});
    } catch (error) {
      if (mine !== generation) return;
      reason = `Groups are unavailable on this device: ${error.message || error}`;
      ctx?.render();
    }
  }
  /** When this device joins the signed list (or anything about our devices changes), try again. */
  function devicesChanged() { if (ctx && !enabled && run && !reason.includes('another tab')) starting = setup(generation); }
  // One upload at a time: start-up and a `keypackages` frame racing would both top up and overshoot the cap.
  let toppingUp = null;
  function topUp(count) {
    toppingUp ||= topUpNow(count).finally(() => { toppingUp = null; });
    return toppingUp;
  }
  async function topUpNow(count) {
    count ||= await must('/api/mls/keypackages');
    const want = Math.min(KEYPACKAGES, count.max ?? KEYPACKAGES) - count.oneTime;
    const body = {};
    if (count.oneTime < LOW_WATER && want > 0) body.keyPackages = await run({ cmd: 'mlsKeyPackages', count: want });
    if (!count.lastResort) body.lastResort = (await run({ cmd: 'mlsKeyPackages', count: 1, lastResort: true }))[0];
    if (body.keyPackages || body.lastResort) await must('/api/mls/keypackages', 'PUT', body);
  }

  // ---------- Pins (§3) ----------
  const same = (a, b) => a && b && a.dh === b.dh && a.sign === b.sign;
  /**
   * Makes sure the core can check these users' certificates. Contacts: the 1:1 pin (the security code you see),
   * mirrored. Everyone else: trust on first use from the server. `force`: re-check against what the server
   * publishes now. Returns users that can't be pinned until someone reviews a changed code, and whether a pin
   * was added or changed.
   */
  async function ensurePins(userIds, force = false) {
    const problems = [];
    let changed = false;
    for (const userId of new Set(userIds)) {
      if (!ID.test(userId || '') || userId === me.id || (!force && pinned.has(userId))) continue;
      const contact = ctx.contacts().find(value => value.id === userId && value.state === 'mutual');
      let mine = await run({ cmd: 'peer', contact: userId });
      const theirs = contact && ctx.box ? await ctx.box.peer(userId) : null; // A linked device has no 1:1 pins: its group store holds them.
      let published = null;
      if (force || (!theirs && !mine)) {
        const found = await call(`/api/users/${userId}/identity`);
        if (found.status === 200) { published = found.body.identity; remember(userId, found.body.username); }
      }
      if (theirs) {
        // The 1:1 pin is the authority. A newer published key goes through its review, never around it.
        if (published && !same(published, theirs.identity) && !theirs.blocked) await ctx.box.notePeer(userId, published).catch(() => {});
        const current = published && !same(published, theirs.identity) ? await ctx.box.peer(userId) : theirs;
        if (current.blocked) { problems.push(userId); continue; }
        // First sight is trust on first use; a different key than the group store knew is a change, and a change
        // waits for an explicit review (the group sheet, or accepting it in the 1:1 safety sheet). Never silent.
        if (mine && !same(mine.identity, current.identity)) rememberChange(userId, mine.identity, current.identity);
        if (!same(mine?.identity, current.identity)) { mine = await run({ cmd: 'notePeer', contact: userId, identity: current.identity }); changed = true; }
        if (mine.blocked) { problems.push(userId); continue; }
        pinned.add(userId); continue;
      }
      if (!mine && !published) { problems.push(userId); continue; }
      if (mine && published && !same(mine.identity, published)) rememberChange(userId, mine.identity, published);
      if (!mine || (published && !same(mine.identity, published))) { mine = await run({ cmd: 'notePeer', contact: userId, identity: published }); changed = true; }
      if (mine.blocked) { problems.push(userId); continue; }
      pinned.add(userId);
    }
    return { problems, changed };
  }
  // A changed code of someone met in a group: what it was and what it is now, kept until the user decides (§3).
  const changesKey = () => `pin-changes-v1:${instance}`;
  const readChanges = () => { try { return JSON.parse(localStorage.getItem(changesKey()) || '{}') || {}; } catch { return {}; } };
  function rememberChange(userId, before, after) {
    const all = readChanges();
    all[userId] = { before: all[userId]?.before || before, after };
    try { localStorage.setItem(changesKey(), JSON.stringify(all)); } catch {}
  }
  function forgetChange(userId) { const all = readChanges(); delete all[userId]; try { localStorage.setItem(changesKey(), JSON.stringify(all)); } catch {} }
  /** A security-code fingerprint: SHA-256 of `dh|sign`, as 12 groups of 5 digits (docs/m4-groups.md §3). */
  async function fingerprint(identity) {
    if (!identity?.dh || !identity?.sign) return 'not recorded';
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${identity.dh}|${identity.sign}`)));
    return Array.from({ length: 12 }, (_, at) => String(bytes[2 * at] * 256 + bytes[2 * at + 1]).padStart(5, '0')).join(' ');
  }
  /** The review sheet for someone you only know from groups: old and new code side by side, nothing accepted silently. */
  async function openReview(userId) {
    const change = readChanges()[userId], current = await run({ cmd: 'peer', contact: userId }).catch(() => null);
    reviewing = userId;
    $('pin-review-title').textContent = `${nameOf(userId)}'s security code changed`;
    $('pin-review-before').textContent = await fingerprint(change?.before);
    // The exact code on screen is the only one a tap here accepts (the core checks it, §3).
    reviewShown = current?.identity || change?.after || null;
    $('pin-review-after').textContent = await fingerprint(reviewShown);
    $('pin-review-status').textContent = '';
    $('pin-review').hidden = false; $('pin-review-cancel').focus();
  }
  let reviewing = null, reviewShown = null;
  async function decideReview(verified) {
    const userId = reviewing, shown = reviewShown;
    if (!userId || !shown) return;
    try {
      await run({ cmd: 'acceptChange', contact: userId, identity: shown });
      if (verified) await run({ cmd: 'setVerified', contact: userId, verified: true, identity: shown });
    } catch (error) {
      if (error.code !== 'mismatch') throw error;
      // It changed again while the sheet was open: show the new one; nothing was accepted.
      await openReview(userId);
      $('pin-review-status').textContent = 'The code changed again while you were looking. Compare this new one.';
      return;
    }
    forgetChange(userId);
    reviewing = null; $('pin-review').hidden = true;
    pinsChanged(userId);
  }
  /** Runs `task`; if the core names a user it can't check, pins them and runs it again (at most 3 times). */
  async function withPins(id, task) {
    for (let attempt = 0; ; attempt++) {
      try { return await task(); }
      catch (error) {
        const user = PIN_ERROR.exec(error.message || '')?.[1];
        if (!user || attempt >= 3) throw error;
        const { problems } = await ensurePins([user], true);
        if (problems.length) { pause(id, problems[0]); throw coded('stale', 'paused'); }
      }
    }
  }
  function pause(id, userId) {
    const ch = channels.get(id);
    if (!ch) return;
    ch.status = 'paused'; ch.pausedFor = userId; save(); paint(id);
  }
  /** The user accepted a changed security code (1:1 safety sheet or the group banner): resume what waited for it. */
  /**
   * The user accepted or verified a contact's changed code in the 1:1 safety sheet: that explicit decision covers
   * the same key here (only if the group store holds exactly the key the 1:1 pin now trusts). Then resume.
   */
  async function contactAccepted(userId) {
    if (!run || !ctx?.box) return;
    const [mine, theirs] = await Promise.all([run({ cmd: 'peer', contact: userId }).catch(() => null), ctx.box.peer(userId).catch(() => null)]);
    if (mine?.blocked && theirs && !theirs.blocked && same(mine.identity, theirs.identity)) { await run({ cmd: 'acceptChange', contact: userId, identity: theirs.identity }); forgetChange(userId); }
    pinsChanged(userId);
  }
  function pinsChanged(userId) {
    pinned.delete(userId);
    for (const [id, ch] of channels) if (ch.status === 'paused' && (!userId || ch.pausedFor === userId)) { ch.status = 'active'; delete ch.pausedFor; save(); enqueue(id, () => syncInner(id)).catch(error => failed(id, error)); flush(id); paint(id); }
  }

  // ---------- Channels and members ----------
  async function refreshChannels() {
    const { channels: list } = await must('/api/channels');
    const seen = new Set();
    for (const row of list) {
      seen.add(row.id);
      // Another device of ours is in it and this one isn't (a newly linked device): join it (m5 §3), unless we left it here.
      if (!row.member) { if (!['left', 'removed'].includes(channels.get(row.id)?.status)) joinOwn(row); continue; }
      const known = channels.has(row.id), ch = channel(row.id, { kind: row.kind, serverName: row.name });
      ch.kind = row.kind; ch.serverName = row.name;
      if (row.kind === 'dm' && row.peer?.id) ch.peer = row.peer.id; // A 1:1 chat on MLS (m5 §8): shown under its contact.
      if (row.frozen && ch.status === 'active') ch.status = 'frozen';
      else if (!row.frozen && ch.status === 'frozen') { ch.status = 'active'; delete ch.frozen; }
      if (!known || !ch.members.length) await members(row.id).catch(() => {});
    }
    // Gone from the server's list while this device thought it was in: removed while we were away.
    for (const [id, ch] of channels) if (!seen.has(id) && ch.status !== 'left' && ch.status !== 'removed') removed(id, false);
    save();
  }
  // ---------- Own devices (docs/m5-linking.md §3, §4) ----------
  const linkedStore = userId => { try { const value = JSON.parse(localStorage.getItem(`linked-store-v1:${userId}`) || 'null'); return value?.instance ? value : null; } catch { return null; } };
  let joinsAt = 0;
  /** This device joins a channel its account is in (the own-device rule), at most 3 joins a second, retried with backoff. */
  function joinOwn(row) {
    const id = row.id, ch = channel(id, { kind: row.kind, serverName: row.name });
    if (ch.joining) return;
    ch.joining = true; ch.status = 'join-pending'; save();
    const attempt = async tries => {
      const wait = Math.max(0, joinsAt - Date.now()); joinsAt = Math.max(Date.now(), joinsAt) + 350;
      await sleep(wait);
      try {
        await enqueue(id, async () => {
          // Only a group our account is really in: the tree must hold a current leaf of ours, for a device our verified
          // signed list names. Otherwise the server could pull this device into any channel (m5 §3).
          if (!await ownLeafProven(id)) throw Object.assign(new Error('not one of our groups'), { status: 403 });
          await run({ cmd: 'mlsForget', group: id }).catch(() => {});
          const seq = await joinExternal(id);
          Object.assign(ch, { kind: row.kind, serverName: row.name, status: 'active', cursor: seq, lastAt: Date.now() });
          delete ch.joining; save();
          // A moved 1:1 chat (m5 §3 step 5): usable here once it checks out as the DM of the two of us.
          if (row.kind === 'dm' && row.peer?.id) { ch.peer = row.peer.id; await run({ cmd: 'mlsCheckDm', group: id, peer: ch.peer }).then(() => { ch.dmChecked = true; }, () => {}); save(); }
          await members(id).catch(() => {});
          await note(id, `own-join:${seq}`, 'This device joined. Earlier messages stay on your other devices.');
        });
        ctx?.render();
      } catch (error) {
        if (tries >= 5 || [403, 404].includes(error.status)) { delete ch.joining; ch.status = 'join-pending'; save(); ctx?.render(); return; } // Retried on the next start.
        setTimeout(() => attempt(tries + 1), 1000 * 2 ** tries);
      }
    };
    attempt(0);
  }
  async function ownLeafProven(id) {
    const own = await ctx.verifiedOwnDevices?.().catch(() => null);
    if (!own) return false;
    const info = await call(`/api/channels/${id}/join-info`);
    if (info.status !== 200) return false;
    try {
      // The served tree, validated like a join (read-only): it must be this channel's group, holding a leaf of ours.
      const view = await run({ cmd: 'mlsInspectGroup', groupInfo: info.body.groupInfo, tree: info.body.tree });
      return view?.groupId === id && Array.isArray(view.members) && view.members.some(member => member.userId === me.id && !member.stale && member.deviceId !== deviceId && own.listed.has(member.deviceId));
    } catch { return false; }
  }
  let removedNote = null;
  /** Commits the removal of one of this account's own devices from one channel (m5 §4). "No such member" means done. */
  function removeOwnDevice(id, target) {
    return enqueue(id, async () => {
      const leaf = (await run({ cmd: 'mlsMembers', group: id })).find(member => member.userId === me.id && member.deviceId === target);
      if (!leaf || target === deviceId) return false;
      try { await commitInner(id, { removes: [{ userId: me.id, deviceId: target }] }); return true; }
      catch (error) { if (/no such member/i.test(error.message || '') || error.status === 409) return false; throw error; }
    });
  }
  /**
   * A revoked device of ours must leave the channel: one device of the account does it, after a random 0–3 s. The
   * frame is only a hint: the device goes only if a verified signed list has dropped it.
   */
  function onRemoveDevice(id, target) {
    if (!ID.test(target || '') || !usable(channels.get(id))) return;
    setTimeout(async () => {
      const own = await ctx?.verifiedOwnDevices?.().catch(() => null);
      if (!own?.dropped.has(target)) return;
      removeOwnDevice(id, target).then(done => {
      if (!done) return;
      removedNote ||= { count: 0 }; removedNote.count++;
      clearTimeout(removedNote.timer);
      removedNote.timer = setTimeout(() => { ctx?.notice(`Removed a revoked device from ${removedNote.count} ${removedNote.count === 1 ? 'group' : 'groups'}.`); removedNote = null; }, 2000);
      }).catch(() => {});
    }, Math.random() * 3000);
  }
  /**
   * At start: our own leaves go if a verified signed list dropped their device, or if the core finds them stale (a
   * certificate under an account key we no longer hold, m5 §7). A list we can't verify proves nothing: keep them.
   */
  async function removeOwnStale() {
    const own = await ctx.verifiedOwnDevices?.().catch(() => null);
    for (const [id, ch] of channels) {
      if (!usable(ch)) continue;
      const leaves = await run({ cmd: 'mlsMembers', group: id }).catch(() => []);
      for (const leaf of leaves) if (leaf.userId === me.id && leaf.deviceId !== deviceId && (leaf.stale || own?.dropped.has(leaf.deviceId))) await removeOwnDevice(id, leaf.deviceId).catch(() => {});
    }
  }

  /** Members from the server's mirror (usernames), admins from the group's own roles when we hold it. */
  async function members(id) {
    const ch = channel(id);
    const { members: devices } = await must(`/api/channels/${id}/members`);
    const users = new Map();
    for (const device of devices) { remember(device.userId, device.username); const user = users.get(device.userId) || { userId: device.userId, username: device.username, admin: false, devices: 0 }; user.admin ||= device.admin; user.devices++; users.set(device.userId, user); }
    ch.members = [...users.values()];
    try { ch.admins = (await run({ cmd: 'mlsRoles', group: id })).admins; } catch { ch.admins = ch.members.filter(user => user.admin).map(user => user.userId); }
    save();
    if (id === currentId) { paintHeader(); paintInfo(); }
    return ch.members;
  }
  const memberIds = id => (channels.get(id)?.members || []).map(member => member.userId);
  async function treeUsers(id) {
    try { return [...new Set((await run({ cmd: 'mlsMembers', group: id })).map(member => member.userId))]; } catch { return []; }
  }

  // ---------- Welcomes and joining ----------
  async function welcomes() {
    const { welcomes: list } = await must('/api/mls/welcomes');
    for (const item of list) await enqueue('welcome', () => takeWelcome(item.id)).catch(() => {});
  }
  async function takeWelcome(welcomeId, frame) {
    const full = frame?.welcome ? frame : await must(`/api/mls/welcomes/${welcomeId}`);
    const id = full.channel, ch = channels.get(id);
    const users = await members(id).then(list => list.map(user => user.userId)).catch(() => []);
    await ensurePins(users);
    if (ch && (ch.status === 'left' || ch.status === 'removed' || ch.status === 'broken')) await run({ cmd: 'mlsForget', group: id }).catch(() => {});
    try {
      await withPins(id, () => run({ cmd: 'mlsJoin', welcome: full.welcome, tree: full.tree }));
    } catch (error) {
      if (error.code === 'stale' || !error.code || error.code === 'storage') throw error; // Paused or transient: the Welcome waits.
      await call(`/api/mls/welcomes/${welcomeId}`, 'DELETE');
      ctx.notice(`Couldn't join a group ${nameOf(full.from)} added you to: ${error.message}`);
      return;
    }
    const info = await must(`/api/channels/${id}`).catch(() => ({}));
    const joined = channel(id, { kind: info.kind || 'group_dm', serverName: info.name ?? null });
    Object.assign(joined, { kind: info.kind || joined.kind, serverName: info.name ?? joined.serverName, status: 'active', cursor: full.seq, lastAt: Date.now() });
    if (info.kind === 'dm' && info.peer?.id) joined.peer = info.peer.id;
    delete joined.pausedFor;
    save();
    await call(`/api/channels/${id}/cursor`, 'POST', { seq: full.seq });
    await call(`/api/mls/welcomes/${welcomeId}`, 'DELETE');
    await members(id).catch(() => {});
    if (joined.kind === 'dm') ctx.dmJoined?.(id); // A 1:1 chat moving to MLS: its pointer may be waiting (m5 §8.3).
    else await note(id, `welcome:${welcomeId}`, `${nameOf(full.from)} added you. You'll see messages from now on.`);
    ctx.render();
    enqueue(id, () => syncInner(id)).catch(error => failed(id, error));
  }
  /** External join: a public channel from the directory, or this device's resync of a channel it is in. */
  async function joinExternal(id) {
    let info;
    for (let attempt = 0; ; attempt++) {
      const result = await call(`/api/channels/${id}/join-info`);
      if (result.status === 200) { info = result.body; break; }
      if (result.status !== 409 || attempt >= 5) throw Object.assign(new Error(result.body.error || 'Could not join.'), { status: result.status });
      await sleep(500 * 2 ** attempt); // Between epochs: the committer uploads the new GroupInfo right after merging.
    }
    const list = await call(`/api/channels/${id}/members`);
    if (list.status === 200) await ensurePins(list.body.members.map(member => member.userId));
    // The core refuses a GroupInfo for any other group than the one we mean to join.
    const out = await withPins(id, () => run({ cmd: 'mlsJoinExternal', groupInfo: info.groupInfo, tree: info.tree, group: id }));
    const result = await call(`/api/channels/${id}/join`, 'POST', { message: out.commit });
    if (result.status !== 201) { await run({ cmd: 'mlsClearOwn', group: id }).catch(() => {}); throw Object.assign(new Error(result.body.error || 'Could not join.'), { status: result.status }); }
    const view = await run({ cmd: 'mlsMergeOwn', group: id });
    await call(`/api/channels/${id}/group-info`, 'PUT', { epoch: view.epoch, groupInfo: view.groupInfo });
    return result.body.seq;
  }
  /** This device can't go on from where it is (log trimmed, rolled-back commit, unloadable group): join again. */
  async function resyncInner(id) {
    const ch = channels.get(id);
    await run({ cmd: 'mlsForget', group: id }).catch(() => {});
    try {
      const seq = await joinExternal(id);
      Object.assign(ch, { status: 'active', cursor: seq }); save();
      await note(id, `resync:${seq}`, 'This device rejoined the conversation. Messages sent while it was out of step can\'t be shown here.');
      await members(id).catch(() => {});
    } catch (error) {
      ch.status = 'broken'; save(); paint(id);
      throw error;
    }
  }

  // ---------- Receiving (§6) ----------
  /** Frames from account.js's event stream. */
  function frame(message) {
    if (!enabled) { if (message.type === 'devices') devicesChanged(); return; }
    if (message.type === 'group') onGroup(message);
    else if (message.type === 'welcome') enqueue('welcome', () => takeWelcome(message.id, message)).catch(() => {});
    else if (message.type === 'channel') onChannel(message);
    else if (message.type === 'keypackages') topUp().catch(() => {});
    else if (message.type === 'ephemeral') onEphemeral(message);
  }
  function onGroup(entry) {
    const id = entry.channel, ch = channels.get(id);
    if (!ID.test(id || '')) return;
    if (!ch) { refreshChannels().then(() => ctx?.render()).catch(() => {}); return; }
    if (ch.status === 'left') { sendCursor(id, entry.seq); return; } // We asked to leave: keep the log moving for the others.
    // Nothing is sequenced while a channel is frozen: a new entry means it was resolved (a missed `thawed`). Re-check.
    if (ch.status === 'frozen') { thawIfResolved(id); return; }
    enqueue(id, async () => {
      if (!usable(ch) || entry.seq <= ch.cursor) return;
      if (entry.seq === ch.cursor + 1 && entry.message) {
        if (await processEntry(id, entry) === 'stop') return;
        ch.cursor = entry.seq; save(); scheduleCursor(id);
      } else await syncInner(id);
    }).catch(error => failed(id, error));
  }
  async function syncInner(id) {
    const ch = channels.get(id);
    for (let pages = 0; pages < 400 && usable(ch); pages++) {
      const result = await call(`/api/channels/${id}/log?after=${ch.cursor}`);
      if (result.status === 404 || result.status === 403) { removed(id, true); return; }
      if (result.status !== 200) throw new Error(result.body.error || 'Could not read the conversation.');
      const page = result.body;
      if (page.gap) { await resyncInner(id); return; }
      let advanced = false;
      for (const entry of page.entries) {
        if (entry.seq <= ch.cursor) continue;
        if (await processEntry(id, entry) === 'stop') { if (advanced) sendCursor(id, ch.cursor); return; }
        ch.cursor = entry.seq; advanced = true;
      }
      save();
      if (advanced) sendCursor(id, ch.cursor);
      // Nothing is sequenced while a channel is frozen: stop here until it thaws.
      if (page.frozen && usable(ch)) { setFrozen(id, page.frozen); return; }
      if (!page.more || !page.entries.length) return;
    }
  }
  /** Processes one log entry. Returns 'stop' when the channel can't go past it now. */
  async function processEntry(id, entry) {
    const ch = channels.get(id);
    // Our last commit can only be redone (§7) until the group has moved past it.
    if (entry.kind === 'commit' && ch.lastCommit && entry.seq > ch.lastCommit.seq) { delete ch.lastCommit; save(); }
    if (entry.from.deviceId === deviceId) {
      // Our own: application messages are already stored; a commit is merged here only if it was left pending.
      if (entry.kind === 'commit' && await run({ cmd: 'mlsPending', group: id }).catch(() => null)) await run({ cmd: 'mlsReceive', group: id, message: entry.message, expect: 'commit' }).catch(() => {});
      return 'ok';
    }
    const before = entry.kind === 'commit' ? await treeUsers(id) : null, rolesBefore = entry.kind === 'commit' ? ch.admins.slice() : null;
    // A sender whose code changed can't be read until someone reviews it: pause here, never decide for the user.
    const sender = await ensurePins([entry.from.userId]);
    if (sender.problems.length) { pause(id, sender.problems[0]); return 'stop'; }
    let processed;
    for (let attempt = 0; ; attempt++) {
      // The log says what the entry is; the core refuses a message that is something else.
      try { processed = await withPins(id, () => run({ cmd: 'mlsReceive', group: id, message: entry.message, commit: false, expect: entry.kind === 'app' ? 'application' : 'commit' })); break; }
      catch (error) {
        if (error.code === 'stale') return 'stop';
        if (error.code === 'replay') return 'ok'; // Already processed (we stopped between storing it and moving the cursor).
        if (error.code === 'poison') { if (attempt === 0 && await pinsMoved(id, entry)) continue; return poisoned(id, entry, error); }
        if (error.code === 'unknown-group') { ch.status = 'broken'; save(); paint(id); return 'stop'; }
        if (error.code && error.code !== 'storage') { await note(id, `drop:${entry.seq}`, `A message from ${nameOf(entry.from.userId)} couldn't be read and was skipped.`); return 'ok'; }
        throw error; // Transient: try again later from here.
      }
    }
    // What the core found must be what the log says it is: an application entry never applies a commit, and a
    // commit entry never delivers a message. Otherwise the staged state is dropped and the entry skipped.
    if ((entry.kind === 'app') !== (processed.kind === 'application')) {
      await run({ cmd: 'mlsAbortReceived', pendingId: processed.pendingId }).catch(() => {});
      await note(id, `drop:${entry.seq}`, `A message from ${nameOf(entry.from.userId)} wasn't what the server said it was, and was skipped.`);
      return 'ok';
    }
    try {
      if (processed.kind === 'application') await deliver(id, processed.sender, entry, processed.plaintext);
    } catch (error) {
      await run({ cmd: 'mlsAbortReceived', pendingId: processed.pendingId }).catch(() => {});
      throw error;
    }
    await run({ cmd: 'mlsCommitReceived', pendingId: processed.pendingId });
    if (processed.kind === 'removed') { removed(id, true); return 'stop'; }
    if (processed.kind === 'commit') await describe(id, `commit:${entry.seq}:${processed.digest || ''}`, processed.sender.userId, processed.sender.leaf === EXTERNAL, before, rolesBefore);
    return 'ok';
  }
  /** A rejected commit may only mean a pin moved (a changed key, a person met for the first time): check first. */
  async function pinsMoved(id, entry) {
    const { problems, changed } = await ensurePins([entry.from.userId, ...memberIds(id), ...(await call(`/api/channels/${id}/members`).then(r => r.status === 200 ? r.body.members.map(m => m.userId) : [], () => []))], true);
    if (problems.length) { pause(id, problems[0]); return false; }
    return changed;
  }
  async function poisoned(id, entry, error) {
    if (channels.get(id)?.status === 'paused') return 'stop';
    const digest = POISON.exec(error.message || '')?.[1];
    const ch = channels.get(id);
    if (digest) ch.rejected = { seq: entry.seq, digest }; // This device's own verdict, for resolving it later.
    // A report's 429 is a once-a-minute rule, not a burst: no automatic retry here.
    const result = digest ? await call(`/api/channels/${id}/poison`, 'POST', { seq: entry.seq, digest }, { retry: false }) : { status: -1, body: {} };
    if (result.status === 202 || result.status === 200 || (result.status === 409 && result.body.frozen)) {
      // 202 answers `{ frozen: true }`; 409 names the commit the channel is frozen on.
      setFrozen(id, typeof result.body.frozen === 'object' ? result.body.frozen : { seq: entry.seq, digest });
      return 'stop';
    }
    // Rate limited or unreachable: stop here and try again later (the commit is still there to report).
    if (result.status === 429 || result.status === 0 || result.status >= 500) {
      setTimeout(() => { if (usable(channels.get(id))) enqueue(id, () => syncInner(id)).catch(error => failed(id, error)); }, 30000);
      return 'stop';
    }
    // Not the latest commit any more: it may simply have been rolled back meanwhile. Then the log goes on without it.
    if (result.status === 409 && digest) {
      const now = await call(`/api/channels/${id}/log?after=${entry.seq - 1}`);
      const same = now.status === 200 && now.body.entries.some(item => item.seq === entry.seq && item.message === entry.message);
      if (!same) { setTimeout(() => { if (usable(channels.get(id))) enqueue(id, () => syncInner(id)).catch(error => failed(id, error)); }, 0); return 'stop'; }
    }
    // The report can't be made (dismissed before, or the commit stays and can't be reported): this device can't follow; rejoin.
    await resyncInner(id).catch(() => {});
    return 'stop';
  }
  /** A commit (ours or someone else's) as a system line: who joined, left, was added or removed, became admin. */
  async function describe(id, key, author, external, before, rolesBefore) {
    const after = await treeUsers(id);
    const by = author === me.id ? 'You' : nameOf(author);
    await members(id).catch(() => {});
    const added = after.filter(user => !before.includes(user)), gone = before.filter(user => !after.includes(user));
    const ch = channels.get(id), nowAdmins = ch.admins.filter(user => !rolesBefore.includes(user) && after.includes(user));
    const lines = [];
    if (external && added.includes(author)) lines.push(`${by} joined`);
    else if (added.length) lines.push(`${by} added ${added.map(nameOf).join(', ')}`);
    for (const user of gone) lines.push(user === author || ch.leaving?.includes(user) ? `${nameOf(user)} left` : `${by} removed ${nameOf(user)}`);
    if (nowAdmins.length) lines.push(`${by} made ${nowAdmins.map(nameOf).join(', ')} ${nowAdmins.length > 1 ? 'admins' : 'an admin'}`);
    if (ch.leaving) ch.leaving = ch.leaving.filter(user => after.includes(user));
    if (lines.length) await note(id, key, lines.join(' · '));
    // Someone asked to leave and we can remove them now.
    for (const user of ch.leaving || []) if (amAdmin(id)) queueRemoval(id, user);
  }
  /** One decrypted application payload: the Phase 1 shapes plus `meta` and `leave` (§5). */
  /**
   * A message in a 1:1 chat that moved to MLS (m5 §8.4): stored in the chat's own conversation (its pairId), with the
   * 1:1 meaning of every payload. Only the two people are accepted, and only after this device has checked that the
   * group is exactly the DM of us two, chained to the pinned account keys (mlsCheckDm, §8.3).
   */
  async function deliverDm(id, ch, from, type, payload) {
    const peer = ch.peer, mine = from === me.id;
    if (!peer || (from !== peer && !mine)) return;
    if (!ch.dmChecked) { await run({ cmd: 'mlsCheckDm', group: id, peer }); ch.dmChecked = true; save(); }
    const conversation = await ctx.pairIdOf(peer);
    if (type === 'message') {
      if (mine) { const record = { id: payload.id, conversationId: conversation, direction: 'outgoing', text: payload.text, createdAt: payload.createdAt, status: 'sent', expiresAt: payload.expiresAt }; for (const field of ['kind', 'replyTo', 'attachment', 'link']) if (payload[field] !== undefined) record[field] = payload[field]; await window.ChatStore.put(record); }
      else if (await window.ChatStore.receive(conversation, payload) === 'stored') { ctx.dmIncoming?.(peer); ctx.dmTyping?.(peer, null); }
    }
    else if (type === 'react') await window.ChatStore.react(conversation, payload.target, mine ? 'me' : 'peer', payload.emoji, payload.on);
    else if (type === 'edit') await window.ChatStore.edit(conversation, payload.target, mine ? 'me' : 'peer', payload.text, Math.min(payload.editedAt, Date.now() + 300000));
    else if (type === 'read') await window.ChatStore.markRead(conversation, payload.ids, mine ? 'incoming' : 'outgoing');
    else if (type === 'typing') { if (!mine) ctx.dmTyping?.(peer, payload); }
    else if (type === 'vote') await window.ChatStore.vote(conversation, payload.poll, mine ? 'me' : 'peer', payload.option);
    ctx.dmChanged?.(peer);
  }
  async function deliver(id, sender, entry, plaintext) {
    let payload, type;
    try { payload = JSON.parse(plaintext); type = window.ChatStore.checkPayload(payload); }
    catch { await note(id, `drop:${entry.seq}`, `A message from ${nameOf(sender.userId)} had invalid content and was skipped.`); return; }
    const ch = channels.get(id), from = sender.userId, viewing = ctx.viewing(id);
    if (ch.kind === 'dm') {
      try { await deliverDm(id, ch, from, type, payload); }
      catch (error) { if (!error.code || error.code === 'storage') throw error; } // Anything else is dropped, like a bad 1:1 envelope.
      return;
    }
    try {
      if (type === 'message') {
        const fromName = nameOf(from) === 'someone' ? undefined : nameOf(from);
        const stored = await window.ChatStore.receive(id, payload, fromName ? { from, fromName } : { from });
        if (stored === 'stored') {
          ch.lastAt = Math.max(ch.lastAt, Date.now());
          if (!viewing) { ch.unread++; if (payload.mentions?.includes(me.id)) ch.mentioned = true; }
          typing(id, from, null);
        }
      } else if (type === 'react') await window.ChatStore.react(id, payload.target, from, payload.emoji, payload.on);
      else if (type === 'edit') await window.ChatStore.edit(id, payload.target, from, payload.text, Math.min(payload.editedAt, Date.now() + 300000));
      else if (type === 'read') await window.ChatStore.markReadBy(id, payload.ids, from);
      else if (type === 'typing') typing(id, from, payload);
      else if (type === 'meta') { if (sender.admin && !(ch.meta?.at >= payload.at)) { ch.meta = { name: payload.name, topic: payload.topic, at: payload.at }; if (id === currentId) paintHeader(); } }
      else if (type === 'leave') { ch.leaving = [...new Set([...ch.leaving || [], from])]; if (amAdmin(id)) queueRemoval(id, from); }
      // receipt, burn, vote, rotate and policy don't apply to groups (§5.1): spent and dropped.
    } catch (error) {
      if (error.code && error.code !== 'storage') { await note(id, `drop:${entry.seq}`, `A message from ${nameOf(from)} couldn't be saved and was skipped.`); return; }
      throw error;
    }
    save();
    if (viewing) window.App.refreshHistory(); else ctx.render();
  }
  async function note(id, key, text) {
    // Idempotent per log entry: a UUID-shaped id from the key, so reprocessing never adds a second line.
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${id}|${key}`)))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    const uuid = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
    await window.ChatStore.note(id, uuid, text).catch(() => {});
    if (ctx?.viewing(id)) window.App.refreshHistory();
  }
  function removed(id, tell) {
    const ch = channels.get(id);
    if (!ch || ch.status === 'removed') return;
    const wasLeaving = ch.status === 'left';
    ch.status = wasLeaving ? 'left' : 'removed'; save();
    run?.({ cmd: 'mlsForget', group: id }).catch(() => {});
    if (tell && !wasLeaving) note(id, 'removed', `You were removed from ${title(id)}.`);
    paint(id); ctx?.render();
  }
  function scheduleCursor(id) {
    if (cursorTimers.has(id)) return;
    cursorTimers.set(id, setTimeout(() => { cursorTimers.delete(id); const ch = channels.get(id); if (ch) sendCursor(id, ch.cursor); }, 150));
  }
  function sendCursor(id, seq) {
    const socket = ctx?.socket();
    if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'cursor', channel: id, seq }));
    else call(`/api/channels/${id}/cursor`, 'POST', { seq }).catch(() => {});
  }
  function onChannel(message) {
    const id = message.id;
    if (!ID.test(id || '')) return;
    const ch = channels.get(id);
    if (message.change === 'joined' || message.change === 'invited') { if (!ch) refreshChannels().then(() => ctx?.render()).catch(() => {}); }
    else if (message.change === 'updated') { if (ch) members(id).then(() => ctx.render()).catch(() => {}); }
    else if (message.change === 'left') { if (ch) removed(id, true); }
    else if (message.change === 'frozen') { if (ch && Number.isSafeInteger(message.seq) && /^[0-9a-f]{64}$/.test(message.digest || '')) { setFrozen(id, { seq: message.seq, digest: message.digest }); ctx.render(); } }
    else if (message.change === 'thawed') { if (ch?.status === 'frozen') { ch.status = 'active'; delete ch.frozen; save(); paint(id); enqueue(id, () => syncInner(id)).catch(error => failed(id, error)); flush(id); } }
    // `remove-needed` is not acted on: a frame alone never makes this device remove anyone. The device to remove
    // comes from this device's own signed rollback (resolve() below).
    else if (message.change === 'remove-device') { if (ch) onRemoveDevice(id, message.deviceId); }
    else if (message.change === 'rolled-back') { if (ch) rolledBack(id, message); }
    else if (message.change === 'gap') { if (usable(ch)) enqueue(id, () => resyncInner(id)).catch(error => failed(id, error)); }
  }
  function onEphemeral(message) {
    const id = message.channel, ch = channels.get(id);
    // Live-only and best effort: only when nothing else is running for the channel (§8), and only typing.
    if (!usable(ch) || !idle(id) || message.from?.deviceId === deviceId) return;
    enqueue(id, async () => {
      // Staged, never committed by default: only an application message whose payload is typing keeps its effect
      // (a spent key). Anything else is aborted, so a live frame can never move the group outside the sequenced log.
      let processed = null;
      try {
        processed = await run({ cmd: 'mlsReceive', group: id, message: message.message, commit: false, expect: 'application' });
        let payload = null;
        try { payload = JSON.parse(processed.plaintext ?? 'null'); } catch {}
        let type = null;
        try { type = processed.kind === 'application' ? window.ChatStore.checkPayload(payload) : null; } catch {}
        if (type !== 'typing') { await run({ cmd: 'mlsAbortReceived', pendingId: processed.pendingId }); return; }
        await run({ cmd: 'mlsCommitReceived', pendingId: processed.pendingId });
        typing(id, processed.sender.userId, payload);
      } catch { if (processed) await run({ cmd: 'mlsAbortReceived', pendingId: processed.pendingId }).catch(() => {}); }
    });
  }

  // ---------- Sending (§5) ----------
  /** Encrypts and posts one payload in the channel's current epoch; on 409 catches up and tries again. */
  async function sendInner(id, payload) {
    const ch = channels.get(id);
    for (let attempt = 0; attempt < 5; attempt++) {
      if (!usable(ch)) throw coded('stale', 'Not sendable');
      const message = await run({ cmd: 'mlsEncrypt', group: id, plaintext: JSON.stringify(payload) });
      const result = await call(`/api/channels/${id}/messages`, 'POST', { message });
      if (result.status === 201) return result.body;
      if (result.status === 409) {
        const local = await run({ cmd: 'mlsView', group: id }).catch(() => null);
        await syncInner(id);
        // Ahead of the server (we merged a commit that was rolled back): this copy can't continue.
        if (local && local.epoch > result.body.epoch) await resyncInner(id);
        continue;
      }
      if (result.status === 423) { setFrozen(id, result.body.frozen); throw coded('stale', 'Frozen'); }
      if (result.status === 404 || result.status === 403) { removed(id, true); throw coded('stale', 'Removed'); }
      throw new Error(result.body.error || 'Could not send.');
    }
    throw new Error('The group kept changing. Try again in a moment.');
  }
  const send = (id, payload) => enqueue(id, () => sendInner(id, payload));
  /** Sends every queued message of one group, oldest first. */
  function flush(id) {
    if (!enabled || !usable(channels.get(id))) return Promise.resolve();
    return enqueue(id, async () => {
      const queued = (await window.ChatStore.list()).filter(record => record.conversationId === id && record.direction === 'outgoing' && record.status === 'queued');
      for (const record of queued) {
        await sendInner(id, window.App.messagePayload(record));
        await window.ChatStore.setStatus(id, record.id, 'sent');
        channels.get(id).lastAt = Date.now();
      }
      if (queued.length) { save(); if (ctx.viewing(id)) window.App.refreshHistory(); ctx.render(); }
    }).catch(error => { if (error.code !== 'stale') status(id, `Not sent yet: ${error.message}`); });
  }
  function flushAll() { for (const [id, ch] of channels) if (usable(ch)) flush(id); }

  // ---------- Commits (§4) ----------
  /**
   * Builds, submits and merges one commit; on 409 processes the log and rebuilds (5 tries, backoff). A commit
   * whose answer never came stays pending: processing the log merges it if it was sequenced.
   */
  async function commitInner(id, change, claimed = []) {
    for (let attempt = 0; attempt < 5; attempt++) {
      await syncInner(id);
      if (await run({ cmd: 'mlsPending', group: id })) await run({ cmd: 'mlsClearOwn', group: id });
      const before = await treeUsers(id), rolesBefore = channels.get(id).admins.slice();
      const out = await withPins(id, () => run({ cmd: 'mlsCommit', group: id, adds: claimed.map(item => item.keyPackage), removes: change.removes, roles: change.roles, update: Boolean(change.update) }));
      const body = out.welcome ? { message: out.commit, welcome: out.welcome, joiners: claimed.map(item => item.deviceId) } : { message: out.commit };
      const result = await call(`/api/channels/${id}/commits`, 'POST', body);
      if (result.status === 201) {
        const view = await run({ cmd: 'mlsMergeOwn', group: id });
        await call(`/api/channels/${id}/group-info`, 'PUT', { epoch: view.epoch, groupInfo: view.groupInfo });
        await describe(id, `commit:${result.body.seq}:${result.body.digest}`, me.id, false, before, rolesBefore);
        // Kept until the next commit: if an admin rolls this one back, this device makes the same change again.
        channels.get(id).lastCommit = { seq: result.body.seq, digest: result.body.digest, epoch: out.epoch, removes: change.removes || null, roles: change.roles || null, update: Boolean(change.update), adds: [...new Set(claimed.map(item => item.userId))] };
        save();
        return result.body;
      }
      await run({ cmd: 'mlsClearOwn', group: id });
      if (result.status !== 409) throw Object.assign(new Error(result.body.error || 'The change was refused.'), { status: result.status });
      await sleep(500 * 2 ** attempt);
    }
    throw new Error('The group kept changing. Try again in a moment.');
  }
  /** One KeyPackage for every listed device of each person (yourself included: your other devices). */
  async function claim(users) {
    const keyPackages = [], missing = [];
    for (let at = 0; at < users.length; at += CLAIM_BATCH) {
      const result = await must('/api/mls/keypackages/claim', 'POST', { users: users.slice(at, at + CLAIM_BATCH) });
      keyPackages.push(...result.keyPackages); missing.push(...result.missing);
    }
    return { keyPackages, missing };
  }
  /** Adds every listed device of each person; `mine`: also this account's other devices (when creating). */
  async function addPeople(id, users, mine = false) {
    let unreachable = [];
    await enqueue(id, async () => { unreachable = await addInner(id, users, mine); });
    return unreachable;
  }
  /** The add path (inside the channel's queue): pins, fresh KeyPackages, one commit, then the name and topic. */
  async function addInner(id, users, mine = false) {
    await ensurePins(users);
    const { keyPackages } = await claim(mine ? [...users, me.id] : users);
    const reachable = new Set(keyPackages.map(item => item.userId));
    const fresh = keyPackages.filter(item => !(item.userId === me.id && item.deviceId === deviceId));
    if (fresh.some(item => item.userId !== me.id)) {
      await commitInner(id, {}, fresh);
      if (channels.get(id)?.kind !== 'dm') await sendMetaInner(id); // A DM has no name or topic.
    }
    return users.filter(user => !reachable.has(user));
  }
  async function sendMetaInner(id) {
    const ch = channels.get(id);
    if (!amAdmin(id)) return;
    if (!ch.meta) ch.meta = { name: '', topic: '', at: Date.now() };
    await sendInner(id, { v: 1, type: 'meta', id: crypto.randomUUID(), name: ch.meta.name, topic: ch.meta.topic, at: ch.meta.at });
  }
  /** An admin removes every device of one person. */
  const removeMember = (id, userId) => enqueue(id, () => commitInner(id, { removes: [{ userId }] }));
  function queueRemoval(id, userId) {
    enqueue(id, async () => {
      if (!(await treeUsers(id)).includes(userId)) return;
      await commitInner(id, { removes: [{ userId }] });
    }).catch(() => {});
  }
  /** Removes exactly one leaf: the device of that user (never another user's leaf that claims the same device id). */
  function removeDevice(id, userId, device) {
    if (!ID.test(userId || '') || !ID.test(device || '')) return;
    enqueue(id, async () => {
      const leaf = (await run({ cmd: 'mlsMembers', group: id })).find(member => member.userId === userId && member.deviceId === device);
      if (leaf) await commitInner(id, { removes: [{ userId, deviceId: device }] });
    }).catch(error => failed(id, error));
  }
  /**
   * m5 §8.2: the first sender moves a 1:1 chat to a DM group of the two of us (every listed device of both). Resolves
   * the channel id, or null when the other side already made one (they are the first sender; wait for their pointer).
   */
  async function createDm(peer) {
    if (!enabled) throw new Error(reason || 'Groups are not ready yet.');
    const id = window.DeviceFormat.b64(crypto.getRandomValues(new Uint8Array(16))), users = [me.id, peer.id].sort();
    const view = await run({ cmd: 'mlsCreate', group: id, roles: { v: 1, kind: 'dm', admins: users, joinPolicy: 'invite', dm: users } });
    const made = await call('/api/channels', 'POST', { id, kind: 'dm', peer: peer.username, groupInfo: view.groupInfo, tree: view.tree });
    if (made.status !== 201) { await run({ cmd: 'mlsForget', group: id }).catch(() => {}); if (made.status === 409) return null; throw new Error(made.body.error || 'Could not move this chat.'); }
    const ch = channel(id, { kind: 'dm' });
    Object.assign(ch, { kind: 'dm', peer: peer.id, cursor: 0, status: 'active', lastAt: Date.now(), dmChecked: false }); save();
    await call(`/api/channels/${id}/group-info`, 'PUT', { epoch: view.epoch, groupInfo: view.groupInfo });
    await enqueue(id, () => addInner(id, [peer.id], true));
    await enqueue(id, async () => { await run({ cmd: 'mlsCheckDm', group: id, peer: peer.id }); ch.dmChecked = true; save(); });
    return id;
  }
  /** Is this DM group ours with that contact, joined and checked (or checkable) here? Used before accepting a pointer. */
  async function acceptDm(id, peerId) {
    const ch = channels.get(id);
    if (!ch || ch.kind !== 'dm' || ch.peer !== peerId || !usable(ch)) return false;
    try { await enqueue(id, () => run({ cmd: 'mlsCheckDm', group: id, peer: peerId })); ch.dmChecked = true; save(); return true; } catch { return false; }
  }
  /** Sends one Phase 1 payload in a moved 1:1 chat; typing goes live-only (m5 §9). */
  function sendDm(id, payload) {
    if (payload?.type !== 'typing') return send(id, payload);
    if (!usable(channels.get(id)) || !idle(id)) return Promise.resolve();
    return enqueue(id, async () => { const message = await run({ cmd: 'mlsEncrypt', group: id, plaintext: JSON.stringify(payload) }); await call(`/api/channels/${id}/ephemeral`, 'POST', { message }); });
  }
  async function create({ kind, name, users }) {
    if (!enabled) throw new Error(reason || 'Groups are not ready yet.');
    const id = window.DeviceFormat.b64(crypto.getRandomValues(new Uint8Array(16)));
    const roles = { v: 1, kind: 'group', admins: [me.id], joinPolicy: kind === 'public' ? 'open' : 'invite' };
    const view = await run({ cmd: 'mlsCreate', group: id, roles });
    try { await must('/api/channels', 'POST', { id, kind, ...(kind === 'public' ? { name } : {}), groupInfo: view.groupInfo, tree: view.tree }); }
    catch (error) { await run({ cmd: 'mlsForget', group: id }).catch(() => {}); throw error; }
    const ch = channel(id, { kind, serverName: kind === 'public' ? name : null });
    Object.assign(ch, { cursor: 0, status: 'active', lastAt: Date.now(), admins: [me.id], members: [{ userId: me.id, username: me.username, admin: true, devices: 1 }], meta: { name: kind === 'public' ? '' : name || '', topic: '', at: Date.now() } });
    save();
    await call(`/api/channels/${id}/group-info`, 'PUT', { epoch: view.epoch, groupInfo: view.groupInfo });
    let unreachable = [];
    if (users.length) unreachable = await addPeople(id, users, true);
    else await send(id, { v: 1, type: 'meta', id: crypto.randomUUID(), name: ch.meta.name, topic: '', at: ch.meta.at });
    await note(id, 'created', kind === 'group_dm' ? 'You started this group.' : `You created ${kind === 'public' ? 'this public channel. Anyone here can find and join it' : 'this private channel. Only people you add can see it'}.`);
    ctx.render();
    return { id, unreachable };
  }
  async function join(id, name) {
    if (!enabled) throw new Error(reason || 'Groups are not ready yet.');
    await enqueue(id, async () => {
      const seq = await joinExternal(id);
      const ch = channel(id);
      Object.assign(ch, { kind: 'public', serverName: name ?? ch.serverName, status: 'active', cursor: seq, lastAt: Date.now() });
      save();
      await members(id).catch(() => {});
      await note(id, `joined:${seq}`, 'You joined. You\'ll see messages from now on.');
    });
    ctx.render();
  }
  async function leave(id) {
    const ch = channels.get(id);
    if (!ch) return;
    await enqueue(id, async () => {
      if (usable(ch)) {
        const users = await treeUsers(id), others = users.filter(user => user !== me.id);
        const roles = await run({ cmd: 'mlsRoles', group: id });
        // The last admin hands the group on first: MLS lets nobody remove themselves (§4).
        if (others.length && roles.admins.every(admin => admin === me.id || !users.includes(admin))) {
          const members = await run({ cmd: 'mlsMembers', group: id });
          const heir = members.filter(member => member.userId !== me.id).sort((a, b) => a.leaf - b.leaf)[0].userId;
          await commitInner(id, { roles: { ...roles, admins: [...roles.admins.filter(admin => users.includes(admin)), heir] } });
        }
        if (others.length) await sendInner(id, { v: 1, type: 'leave', id: crypto.randomUUID() });
      }
      ch.status = 'left'; save();
      await run({ cmd: 'mlsForget', group: id }).catch(() => {});
      const latest = await call(`/api/channels/${id}`);
      if (latest.status === 200) sendCursor(id, latest.body.seq);
      await note(id, 'left', 'You left. Messages already here stay on this device.');
    });
    paint(id); ctx.render();
  }
  async function rename(id, name, topic) {
    const ch = channels.get(id);
    ch.meta = { name, topic, at: Math.max(Date.now(), (ch.meta?.at || 0) + 1) }; save();
    await send(id, { v: 1, type: 'meta', id: crypto.randomUUID(), name, topic, at: ch.meta.at });
    paintHeader(); ctx.render();
  }
  const hex = bytes => [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  const digestOf = async message => hex(await crypto.subtle.digest('SHA-256', unb64(message)));
  const unb64 = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
  /**
   * An admin rolled a commit back. If it was ours, this device had already merged it: rejoin at the restored epoch
   * and make the same change again (§7). Anyone else's copy never merged it (every member rejected it).
   */
  function rolledBack(id, notice) {
    const ch = channels.get(id), mine = ch?.lastCommit;
    if (!mine || notice.action !== 'rollback' || notice.seq !== mine.seq || notice.digest !== mine.digest) return;
    enqueue(id, async () => {
      if (ch.lastCommit !== mine) return; // A later commit superseded it meanwhile.
      // The notice alone proves nothing (the server sends it): an admin of this group, as this device's own copy of
      // the group knows it, must have signed this exact resolution with its leaf key...
      try {
        await run({ cmd: 'mlsVerifyResolution', group: id, action: 'rollback', seq: notice.seq, digest: notice.digest, author: typeof notice.author === 'string' ? notice.author : '', by: notice.by, byUser: notice.byUser, signature: notice.signature });
      } catch { return; }
      // ...and the channel must really be back before our commit: at its epoch, without it in the log.
      const info = await call(`/api/channels/${id}`);
      if (info.status !== 200 || info.body.epoch !== mine.epoch) return;
      const log = await call(`/api/channels/${id}/log?after=${mine.seq - 1}`);
      if (log.status !== 200) return;
      for (const entry of log.body.entries) if (entry.kind === 'commit' && await digestOf(entry.message) === mine.digest) return;
      delete ch.lastCommit; save();
      for (let attempt = 0; ; attempt++) {
        try { await resyncInner(id); break; }
        catch (error) { if (attempt >= 4) throw error; await sleep(1000 * 2 ** attempt); } // The admin publishes the restored GroupInfo.
      }
      if (mine.adds.length) await addInner(id, mine.adds.filter(user => user !== me.id));
      else await commitInner(id, { removes: mine.removes || undefined, roles: mine.roles || undefined, update: mine.update });
      await note(id, `redo:${mine.seq}`, 'Your change was undone and redone: an admin rolled it back because other devices couldn\'t read it, and it was made again.');
    }).catch(error => failed(id, error));
  }
  async function thawIfResolved(id) {
    const ch = channels.get(id), info = await call(`/api/channels/${id}`);
    if (info.status !== 200 || info.body.frozen || ch?.status !== 'frozen') return;
    onChannel({ id, change: 'thawed' });
  }
  // Rollbacks for damage outside the author's signature never blame the author (§7), but an insider could keep
  // freezing the group that way. This admin device counts them per author device; from the second within 24 hours
  // it offers (never performs) removing that device, as an explicit, confirmed and signed removal.
  const TAG_WINDOW = 86400000, tagKey = () => `tag-rollbacks-v1:${instance}`;
  function tagRollbacks(device) {
    let all = {};
    try { all = JSON.parse(localStorage.getItem(tagKey()) || '{}') || {}; } catch {}
    return (all[device] || []).filter(at => Date.now() - at < TAG_WINDOW);
  }
  function recordTagRollback(device) {
    let all = {};
    try { all = JSON.parse(localStorage.getItem(tagKey()) || '{}') || {}; } catch {}
    all[device] = [...tagRollbacks(device), Date.now()].slice(-20);
    try { localStorage.setItem(tagKey(), JSON.stringify(all)); } catch {}
  }
  /** Whether this frozen commit's author may be removed by an explicit admin decision despite a tag-only failure. */
  const escalation = check => Boolean(check?.state === 'fails' && check.blame === 'tag' && check.authenticated && ID.test(check.author || '') && tagRollbacks(check.author).length >= 2);
  /** A reported commit froze the channel. Record it and, on an admin device, check it before offering a verdict. */
  function setFrozen(id, frozen) {
    const ch = channels.get(id);
    if (!ch) return;
    if (ch.status === 'active') ch.status = 'frozen';
    if (frozen && Number.isSafeInteger(frozen.seq) && /^[0-9a-f]{64}$/.test(frozen.digest || '')) {
      const same = ch.frozen?.seq === frozen.seq && ch.frozen?.digest === frozen.digest;
      ch.frozen = { seq: frozen.seq, digest: frozen.digest };
      if (!same) delete ch.check;
    }
    save(); paint(id);
    if (ch.frozen && !ch.check && amAdmin(id)) verifyFrozen(id);
  }
  /**
   * §7: before an admin may sign a rollback, this device re-checks the reported commit itself: the log entry at
   * the frozen seq, with the reported digest, run through the validator without keeping anything. `fails`: it is
   * rejected here too (Rollback offered). `ok`: it checks out (only Dismiss). `unknown`: it couldn't be checked.
   */
  function verifyFrozen(id) {
    const ch = channels.get(id), frozen = ch?.frozen;
    if (!frozen) return Promise.resolve();
    ch.check = { seq: frozen.seq, digest: frozen.digest, state: 'checking' }; paint(id);
    return enqueue(id, async () => {
      // `author`: the commit's author device, `authenticated` when this device's own tree verified its signature.
      // `blame`: 'signed-content' when what the author signed is itself invalid (only then is the author removed);
      // 'tag' when the failure lies outside the signature, which the server could have caused in transit.
      let state = 'unknown', author = null, authorUser = null, authenticated = false, blame = 'tag';
      try {
        const result = await call(`/api/channels/${id}/log?after=${frozen.seq - 1}`);
        const entry = result.status === 200 ? result.body.entries.find(item => item.seq === frozen.seq) : null;
        if (entry && ID.test(entry.from?.deviceId || '')) author = entry.from.deviceId;
        if (entry?.kind === 'commit' && entry.from.deviceId !== deviceId) {
          await ensurePins([entry.from.userId]);
          try {
            const checked = await run({ cmd: 'mlsCommitAuthor', group: id, message: entry.message });
            authenticated = checked.authenticated === true && ID.test(checked.author?.deviceId || '');
            if (authenticated) { author = checked.author.deviceId; authorUser = checked.author.userId; }
            blame = authenticated && checked.class === 'signed-content' ? 'signed-content' : 'tag';
          } catch {}
        }
        if (!entry || entry.kind !== 'commit' || hex(await crypto.subtle.digest('SHA-256', unb64(entry.message))) !== frozen.digest) state = 'unknown';
        else if (ch.rejected?.seq === frozen.seq && ch.rejected.digest === frozen.digest) state = 'fails';
        else if (entry.from.deviceId === deviceId || ch.cursor >= frozen.seq) state = 'ok'; // Built or merged here, after the same validator.
        else {
          await ensurePins([entry.from.userId]);
          let processed = null;
          try {
            processed = await run({ cmd: 'mlsReceive', group: id, message: entry.message, commit: false, expect: 'commit' });
            state = 'ok';
          } catch (error) { state = error.code === 'poison' ? 'fails' : 'unknown'; }
          if (processed) await run({ cmd: 'mlsAbortReceived', pendingId: processed.pendingId }).catch(() => {});
        }
      } catch { state = 'unknown'; }
      if (ch.frozen?.seq === frozen.seq && ch.frozen.digest === frozen.digest) { ch.check = { seq: frozen.seq, digest: frozen.digest, state, author, authorUser, authenticated, blame }; save(); paint(id); }
    }).catch(() => {});
  }
  async function resolve(id, action, { remove = false } = {}) {
    const ch = channels.get(id);
    if (!ch?.frozen) return;
    const check = ch.check?.seq === ch.frozen.seq && ch.check.digest === ch.frozen.digest ? ch.check : null;
    if (action === 'rollback' && check?.state !== 'fails') throw new Error('this device did not find that change invalid, so it won\'t roll it back');
    if (action === 'dismiss' && (!check || check.state === 'checking')) throw new Error('still checking the change');
    // Named (and so removed) only when its author signed invalid content and this device authenticated that author.
    // Or, for a repeated tag-only failure, when the admin explicitly chose to remove that device (never automatic).
    const blamed = check?.blame === 'signed-content' && check.authenticated && ID.test(check.author || '');
    if (remove && !escalation(check)) throw new Error('removing that device isn\'t offered for this change');
    const author = action === 'rollback' && (blamed || remove) ? check.author : '';
    const leafSignature = action === 'rollback' ? await run({ cmd: 'mlsSignResolution', group: id, action, seq: ch.frozen.seq, digest: ch.frozen.digest, author }) : undefined;
    const device = await window.DeviceFormat.deviceKey(me.id);
    // The signature names the author this device authenticated, so the server can't make it cut off someone else.
    const bytes = new TextEncoder().encode(`webrtc-bun-mlsresolve-v2\n${id}\n${action}\n${ch.frozen.seq}\n${ch.frozen.digest}\n${author}`);
    const answer = await must(`/api/channels/${id}/resolve`, 'POST', { action, seq: ch.frozen.seq, digest: ch.frozen.digest, author, ...(leafSignature ? { leafSignature } : {}), signature: await device.sign(bytes) });
    if (action === 'rollback' && !author && check.blame === 'tag' && check.authenticated && ID.test(check.author || '')) recordTagRollback(check.author);
    ch.status = 'active'; delete ch.frozen; delete ch.check; delete ch.rejected; save(); paint(id);
    // A rollback restores the epoch before the commit: publish its GroupInfo so devices can rejoin (the author's).
    if (action === 'rollback') enqueue(id, async () => { const view = await run({ cmd: 'mlsView', group: id }); await call(`/api/channels/${id}/group-info`, 'PUT', { epoch: view.epoch, groupInfo: view.groupInfo }); }).catch(() => {});
    enqueue(id, () => syncInner(id)).catch(error => failed(id, error));
    // Only the author this device authenticated, for content it signed, is removed; any other answer removes nobody.
    if (action === 'rollback' && author) {
      if (answer.removeDevice !== author) status(id, 'The server named a different device to remove than the one that made the change. Nobody was removed; ask another admin to check.');
      else removeDevice(id, check.authorUser, author);
    }
    flush(id);
  }

  // ---------- Typing (§5.1) ----------
  let typingSent = 0, typingOn = false;
  function onTyping(active) {
    const id = currentId, ch = channels.get(id);
    if (!usable(ch) || !enabled) { typingOn = false; return; }
    const post = on => { if (!idle(id)) return; enqueue(id, async () => {
      const message = await run({ cmd: 'mlsEncrypt', group: id, plaintext: JSON.stringify({ v: 1, type: 'typing', id: crypto.randomUUID(), at: Date.now(), on }) });
      await call(`/api/channels/${id}/ephemeral`, 'POST', { message });
    }).catch(() => {}); };
    if (active) { if (Date.now() - typingSent < 4000) return; typingSent = Date.now(); typingOn = true; post(true); }
    else if (typingOn) { typingOn = false; typingSent = 0; post(false); }
  }
  function typing(id, userId, payload) {
    if (channels.get(id)?.kind === 'dm') { if (userId !== me.id) ctx.dmTyping?.(userId, payload); return; }
    const people = typingFrom.get(id) || new Map();
    clearTimeout(people.get(userId));
    people.delete(userId);
    if (payload?.on && Date.now() - payload.at <= 15000 && payload.at - Date.now() <= 300000) people.set(userId, setTimeout(() => typing(id, userId, null), 6000));
    typingFrom.set(id, people);
    if (id === currentId) showTyping();
  }
  function showTyping() {
    const people = [...(typingFrom.get(currentId)?.keys() || [])].map(nameOf);
    window.App.showTyping(people.length > 0, people.length === 1 ? `${people[0]} is typing` : people.length === 2 ? `${people[0]} and ${people[1]} are typing` : `${people.length} people are typing`);
  }

  // ---------- Read receipts (§5.1) ----------
  let readTimer = null, readAt = 0;
  function onDisplayed() {
    if (readTimer || !currentId || !ctx.looking()) return;
    readTimer = setTimeout(sendReads, Math.max(0, 2000 - (Date.now() - readAt)));
  }
  async function sendReads() {
    readTimer = null;
    const id = currentId, ch = channels.get(id);
    if (!id || !ctx.looking()) return;
    const waiting = (await window.ChatStore.list()).filter(record => record.conversationId === id && record.direction === 'incoming' && record.status === 'delivered').map(record => record.id);
    if (!waiting.length) return;
    readAt = Date.now();
    const ids = await window.ChatStore.markRead(id, waiting.slice(-100), 'incoming');
    if (ids.length && window.App.readReceipts && usable(ch) && ch.kind !== 'public' && ch.members.length <= READ_RECEIPT_LIMIT) send(id, { v: 1, type: 'read', id: crypto.randomUUID(), ids }).catch(() => {});
    if (waiting.length > 100) onDisplayed();
  }

  // ---------- Conversation UI ----------
  function open(id) {
    const ch = channels.get(id);
    if (!ch) return;
    currentId = id; ch.unread = 0; ch.mentioned = false; save();
    window.App.openConversation({ conversationId: id, peerName: title(id), peerId: null, group: true });
    paintHeader(); paint(id); showTyping();
    if (usable(ch)) { members(id).catch(() => {}); flush(id); }
  }
  function close() { if (currentId) { onTyping(false); currentId = null; window.App.showTyping(false); $('group-banner').hidden = true; } }
  function paintHeader() {
    const id = currentId, ch = channels.get(id);
    if (!id || !ch) return;
    $('conv-name').textContent = `${isChannel(ch) ? '# ' : ''}${title(id)}`;
    $('conv-avatar').textContent = isChannel(ch) ? '#' : (title(id)[0] || '?').toUpperCase();
    $('conv-avatar').dataset.online = 'false';
    const people = ch.members.length;
    $('conv-presence').textContent = ch.meta?.topic || `${people} ${people === 1 ? 'member' : 'members'}${ch.kind === 'public' ? ' · public channel' : ch.kind === 'private' ? ' · private channel' : ''}`;
    window.App.setPeerName?.(title(id));
  }
  /** The banner over a group conversation: frozen, paused for a security code, removed or out of step. */
  function paint(id) {
    if (id !== currentId) return;
    const ch = channels.get(id), banner = $('group-banner');
    const admin = amAdmin(id);
    const check = ch?.frozen && ch.check?.seq === ch.frozen.seq && ch.check.digest === ch.frozen.digest ? ch.check.state : null;
    const verdict = {
      checking: `A member's device rejected a change to ${title(id)}. Checking it on this device…`,
      fails: ch?.check?.blame === 'signed-content'
        ? `A change to ${title(id)} was rejected by a member's device, and this device rejects it too: what its author signed is invalid. Roll it back (and cut off the device that made it), or dismiss the report.`
        : `A change to ${title(id)} was rejected by a member's device, and this device rejects it too, but it was damaged outside what its author signed (that can happen on the way). Roll it back: nobody is removed, and its author makes the change again.`,
      ok: `A member's device rejected a change to ${title(id)}, but it checks out on this device. Dismiss the report to let the conversation go on.`,
      unknown: `A member's device rejected a change to ${title(id)}. This device couldn't check it, so rolling back isn't offered. Dismiss the report, or ask another admin.`,
    };
    const text = !ch ? '' : ch.status === 'frozen' ? (admin && ch.frozen ? verdict[check || 'checking'] : 'This conversation is paused while an admin checks a change. Messages wait on this device.')
      : ch.status === 'paused' ? `${nameOf(ch.pausedFor)}'s security code changed. Review it to keep reading this conversation.`
      : ch.status === 'removed' ? 'You were removed from this conversation. Messages already here stay on this device.'
      : ch.status === 'left' ? 'You left this conversation. Messages already here stay on this device.'
      : ch.status === 'broken' ? 'This device fell out of step with the conversation.' : '';
    banner.hidden = !text;
    $('group-banner-text').textContent = text;
    const deciding = ch?.status === 'frozen' && admin && ch.frozen;
    $('group-rollback').hidden = !(deciding && check === 'fails');
    const escalate = deciding && escalation(ch.check);
    $('group-remove-author').hidden = !escalate;
    if (escalate) $('group-remove-author').textContent = `Remove ${nameOf(ch.check.authorUser)}'s device`;
    $('group-dismiss').hidden = !(deciding && check && check !== 'checking');
    $('group-review').hidden = ch?.status !== 'paused';
    $('group-rejoin').hidden = ch?.status !== 'broken';
    // Frozen or paused: writing still works and waits on this device; gone or out of step: read-only.
    window.App.setComposable?.(Boolean(ch) && !['left', 'removed', 'broken'].includes(ch.status));
  }
  const status = (id, text) => { if (id === currentId) window.App.chatStatus(text); else ctx?.notice(text); };

  // ---------- Dialogs: new conversation, channel browser, info sheet, receipts ----------
  let newKind = 'group_dm';
  function pickList(container, exclude = new Set()) {
    const people = (ctx?.contacts() || []).filter(contact => contact.state === 'mutual' && !exclude.has(contact.id));
    container.replaceChildren(...people.map(contact => {
      const row = element('li'), label = element('label', 'pick'), box = element('input');
      box.type = 'checkbox'; box.value = contact.id; box.dataset.name = contact.username;
      label.append(box, element('span', 'avatar small', contact.username[0].toUpperCase()), element('span', '', contact.username));
      row.append(label); return row;
    }));
    if (!people.length) container.append(element('li', 'empty', exclude.size ? 'Everyone you know is already here.' : 'Add contacts first: groups and channels start with people you know.'));
  }
  const picked = container => [...container.querySelectorAll('input:checked')].map(box => box.value);
  function openNew(kind = 'group_dm') {
    if (!enabled) { ctx.notice(reason || 'Groups are not ready yet.'); return; }
    newKind = kind;
    $('group-new-title').textContent = kind === 'group_dm' ? 'New group' : 'New channel';
    $('group-new-hint').textContent = kind === 'group_dm' ? 'Pick two or more people to start a group.' : 'Channels are for a topic. Public ones can be found and joined by anyone here; private ones only by the people you add.';
    $('group-new-visibility').hidden = kind === 'group_dm';
    $('group-new-name').value = ''; $('group-new-name').placeholder = kind === 'group_dm' ? 'Name (optional)' : 'Channel name';
    $('group-new-name').required = kind !== 'group_dm';
    $('group-new-status').textContent = '';
    for (const input of document.getElementsByName('group-visibility')) input.checked = input.value === 'private';
    pickList($('group-new-people'));
    $('group-new').hidden = false; $('group-new-name').focus();
  }
  async function submitNew(event) {
    event.preventDefault();
    const users = picked($('group-new-people')), name = $('group-new-name').value.trim();
    const kind = newKind === 'group_dm' ? 'group_dm' : [...document.getElementsByName('group-visibility')].find(input => input.checked)?.value || 'private';
    if (kind === 'group_dm' && users.length < 2) { $('group-new-status').textContent = 'Pick two or more people to start a group.'; return; }
    if (kind === 'group_dm' && users.length > 8) { $('group-new-status').textContent = 'A group holds up to 9 people. Make a channel for more.'; return; }
    if (kind !== 'group_dm' && !/^[\p{L}\p{N}_\- ]{1,64}$/u.test(name)) { $('group-new-status').textContent = 'Name it with up to 64 letters, digits, spaces, - or _.'; return; }
    $('group-new-create').disabled = true; $('group-new-status').textContent = 'Setting up encryption…';
    try {
      const { id, unreachable } = await create({ kind, name, users });
      $('group-new').hidden = true;
      ctx.openGroup(id);
      if (unreachable.length) window.App.chatStatus(`${unreachable.map(nameOf).join(', ')} couldn't be added yet: they haven't opened the app since groups arrived.`);
    } catch (error) { $('group-new-status').textContent = error.message || 'Could not create it.'; }
    finally { $('group-new-create').disabled = false; }
  }
  async function openBrowser() {
    if (!enabled) { ctx.notice(reason || 'Groups are not ready yet.'); return; }
    $('channel-browser').hidden = false; $('channel-browser-filter').value = ''; $('channel-browser-filter').focus();
    $('channel-browser-list').replaceChildren(element('li', 'empty', 'Looking for channels…'));
    try { directory = (await must('/api/channels/directory')).channels; paintBrowser(); }
    catch (error) { $('channel-browser-list').replaceChildren(element('li', 'empty', `Couldn't load channels: ${error.message}`)); }
  }
  let directory = [];
  function paintBrowser() {
    const query = $('channel-browser-filter').value.trim().toLowerCase();
    const list = directory.filter(item => !query || item.name.toLowerCase().includes(query));
    $('channel-browser-list').replaceChildren(...list.map(item => {
      const row = element('li', 'browse-row'), text = element('span', 'contact-text');
      text.append(element('strong', '', `# ${item.name}`), element('small', '', `${item.members} ${item.members === 1 ? 'member' : 'members'}`));
      const joined = item.joined && usable(channels.get(item.id));
      const button = element('button', joined ? '' : 'primary', joined ? 'Open' : 'Join'); button.type = 'button';
      button.setAttribute('aria-label', `${joined ? 'Open' : 'Join'} ${item.name}`);
      button.onclick = async () => {
        button.disabled = true;
        try { if (!joined) await join(item.id, item.name); $('channel-browser').hidden = true; ctx.openGroup(item.id); }
        catch (error) { button.disabled = false; $('channel-browser-status').textContent = `Couldn't join: ${error.message}`; }
      };
      row.append(element('span', 'avatar', '#'), text, button); return row;
    }));
    if (!list.length) $('channel-browser-list').append(element('li', 'empty', directory.length ? 'No channel matches that. Try another word, or start it yourself.' : 'No public channels yet. Start the first one, and people here can find it.'));
  }
  function openInfo() {
    if (!currentId) return;
    $('group-info').hidden = false; paintInfo();
    members(currentId).catch(() => {});
  }
  function paintInfo() {
    const id = currentId, ch = channels.get(id);
    if ($('group-info').hidden || !ch) return;
    const admin = amAdmin(id), active = usable(ch);
    $('group-info-title').textContent = `${isChannel(ch) ? '# ' : ''}${title(id)}`;
    $('group-info-kind').textContent = { group_dm: 'Group', private: 'Private channel: only people added can see it', public: 'Public channel: anyone here can find and join it' }[ch.kind] || 'Group';
    $('group-info-edit').hidden = !(admin && active);
    $('group-info-name').value = ch.meta?.name || (ch.kind === 'public' ? ch.serverName || '' : '');
    $('group-info-name').disabled = ch.kind === 'public';
    $('group-info-topic').value = ch.meta?.topic || '';
    $('group-info-members').replaceChildren(...ch.members.map(member => {
      const row = element('li', 'member-row'), name = element('span', 'contact-text');
      name.append(element('strong', '', member.userId === me.id ? `${member.username} (you)` : member.username), element('small', '', `${ch.admins.includes(member.userId) ? 'Admin' : 'Member'}${member.devices > 1 ? ` · ${member.devices} devices` : ''}`));
      row.append(element('span', 'avatar small', (member.username[0] || '?').toUpperCase()), name);
      if (admin && active && member.userId !== me.id) {
        const remove = element('button', 'link danger-text', 'Remove'); remove.type = 'button';
        remove.setAttribute('aria-label', `Remove ${member.username}`);
        remove.onclick = async () => {
          remove.disabled = true;
          try { await removeMember(id, member.userId); } catch (error) { $('group-info-status').textContent = `Couldn't remove: ${error.message}`; }
          finally { remove.disabled = false; paintInfo(); }
        };
        row.append(remove);
      }
      return row;
    }));
    const canAdd = active && (admin || ch.kind === 'public');
    $('group-info-add').hidden = !canAdd;
    if (canAdd) pickList($('group-info-people'), new Set(ch.members.map(member => member.userId)));
    $('group-info-leave').hidden = !active;
    $('group-info-leave').textContent = ch.kind === 'group_dm' ? 'Leave group' : 'Leave channel';
  }
  async function addFromInfo() {
    const id = currentId, users = picked($('group-info-people'));
    if (!users.length) { $('group-info-status').textContent = 'Pick someone to add.'; return; }
    $('group-info-add-button').disabled = true; $('group-info-status').textContent = 'Adding…';
    try {
      const unreachable = await addPeople(id, users);
      $('group-info-status').textContent = unreachable.length ? `${unreachable.map(nameOf).join(', ')} couldn't be added yet: they haven't opened the app since groups arrived.` : 'Added. They see messages from now on.';
    } catch (error) { $('group-info-status').textContent = `Couldn't add: ${error.message}`; }
    finally { $('group-info-add-button').disabled = false; paintInfo(); }
  }
  /** Who has read one of your messages, and who hasn't yet (Enclave's receipt info). */
  function receiptInfo(record) {
    const ch = channels.get(currentId);
    if (!ch || record.direction !== 'outgoing') return;
    const read = new Set(record.readBy || []), others = ch.members.filter(member => member.userId !== me.id);
    const list = (container, people, empty) => { container.replaceChildren(...people.map(member => element('li', '', member.username))); if (!people.length) container.append(element('li', 'empty', empty)); };
    list($('receipt-read'), others.filter(member => read.has(member.userId)), 'Nobody yet.');
    list($('receipt-waiting'), others.filter(member => !read.has(member.userId)), 'Everyone has read it.');
    $('receipt-note').textContent = ch.kind === 'public' || others.length > READ_RECEIPT_LIMIT ? 'Read receipts are off in public channels and in conversations of more than 50 people.' : 'People who turned off read receipts never show as having read it.';
    $('receipt-info').hidden = false; $('receipt-close').focus();
  }

  // ---------- Sidebar data for account.js ----------
  function sections() {
    const rows = [];
    for (const [id, ch] of channels) if (ch.kind !== 'dm') rows.push({ id, kind: ch.kind, channel: isChannel(ch), title: title(id), unread: ch.unread, mentioned: ch.mentioned, status: ch.status, lastAt: ch.lastAt, topic: ch.meta?.topic || '' });
    return { rows, enabled, reason };
  }
  /** For app.js: who is who in the open group. */
  function info() {
    const ch = channels.get(currentId);
    if (!ch) return null;
    return { id: currentId, kind: ch.kind, members: ch.members.map(member => ({ userId: member.userId, username: member.username })), me: me.id, readReceipts: ch.kind !== 'public' && ch.members.length <= READ_RECEIPT_LIMIT };
  }

  // ---------- Wiring ----------
  const wire = () => {
    $('group-new-form').addEventListener('submit', submitNew);
    $('group-new-cancel').onclick = () => { $('group-new').hidden = true; };
    $('channel-browser-filter').addEventListener('input', paintBrowser);
    $('channel-browser-close').onclick = () => { $('channel-browser').hidden = true; };
    $('channel-browser-new').onclick = () => { $('channel-browser').hidden = true; openNew('channel'); };
    $('group-info-close').onclick = () => { $('group-info').hidden = true; };
    $('group-info-add-button').onclick = addFromInfo;
    $('group-info-save').onclick = async () => {
      const name = $('group-info-name').value.trim(), topic = $('group-info-topic').value.trim();
      try { await rename(currentId, channels.get(currentId).kind === 'public' ? '' : name.slice(0, 64), topic.slice(0, 256)); $('group-info-status').textContent = 'Saved for everyone.'; paintInfo(); }
      catch (error) { $('group-info-status').textContent = `Couldn't save: ${error.message}`; }
    };
    $('group-info-leave').onclick = () => { $('group-leave-confirm').hidden = false; $('group-leave-cancel').focus(); };
    $('group-leave-cancel').onclick = () => { $('group-leave-confirm').hidden = true; };
    $('group-leave-yes').onclick = async () => {
      $('group-leave-confirm').hidden = true; $('group-info').hidden = true;
      try { await leave(currentId); } catch (error) { window.App.chatStatus(`Couldn't leave: ${error.message}`); }
    };
    $('receipt-close').onclick = () => { $('receipt-info').hidden = true; };
    $('group-rollback').onclick = () => resolve(currentId, 'rollback').catch(error => window.App.chatStatus(`Couldn't roll back: ${error.message}`));
    $('group-remove-author').onclick = () => {
      const ch = channels.get(currentId);
      if (!escalation(ch?.check)) return;
      $('group-remove-text').textContent = `${nameOf(ch.check.authorUser)}'s changes to this conversation arrived damaged ${tagRollbacks(ch.check.author).length + 1} times in a day. That can be their device, but also the network or the server, so nothing was blamed on them. Roll this one back and remove that device? They can be added again.`;
      $('group-remove-confirm').hidden = false; $('group-remove-cancel').focus();
    };
    $('group-remove-cancel').onclick = () => { $('group-remove-confirm').hidden = true; };
    $('group-remove-yes').onclick = () => { $('group-remove-confirm').hidden = true; resolve(currentId, 'rollback', { remove: true }).catch(error => window.App.chatStatus(`Couldn't remove it: ${error.message}`)); };
    $('group-dismiss').onclick = () => resolve(currentId, 'dismiss').catch(error => window.App.chatStatus(`Couldn't dismiss: ${error.message}`));
    $('group-rejoin').onclick = () => enqueue(currentId, () => resyncInner(currentId)).then(() => paint(currentId), error => window.App.chatStatus(`Couldn't rejoin: ${error.message}`));
    $('group-review').onclick = async () => {
      const ch = channels.get(currentId), userId = ch?.pausedFor;
      if (!userId) return;
      // Contact or not: the group's own review sheet, old and new code side by side, never a silent accept.
      openReview(userId);
    };
    $('pin-review-cancel').onclick = () => { reviewing = null; $('pin-review').hidden = true; };
    $('pin-review-accept').onclick = () => decideReview(false).catch(error => { $('pin-review-status').textContent = `Couldn't accept: ${error.message}`; });
    $('pin-review-verify').onclick = () => decideReview(true).catch(error => { $('pin-review-status').textContent = `Couldn't save: ${error.message}`; });
    $('conv-info').onclick = () => { $('conv-menu').open = false; openInfo(); };
    $('conv-leave').onclick = () => { $('conv-menu').open = false; $('group-leave-confirm').hidden = false; $('group-leave-cancel').focus(); };
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();

  window.Palette?.register(() => !enabled ? [] : [
    { id: 'action:new-group', group: 'Actions', label: 'New group', keywords: 'people start chat', run: () => openNew('group_dm') },
    { id: 'action:new-channel', group: 'Actions', label: 'New channel', keywords: 'topic public private', run: () => openNew('channel') },
    { id: 'action:browse', group: 'Actions', label: 'Browse channels', keywords: 'join public directory', run: openBrowser },
    ...[...channels].filter(([, ch]) => ch.status !== 'left' && ch.kind !== 'dm').map(([id, ch]) => ({ id: `group:${id}`, group: 'Conversations', label: `${isChannel(ch) ? '# ' : ''}${title(id)}`, hint: ch.unread ? `${ch.unread} unread` : '', run: () => { ctx.openGroup(id); } })),
  ]);

  window.Groups = Object.freeze({
    start, stop, frame, devicesChanged, pinsChanged, contactAccepted, removeMember, createDm, acceptDm, sendDm,
    /** A contact's verified succession chain (m5 §5.3): the group store moves its pin and keeps the old key as a predecessor. */
    async contactSucceeded(contactId, records) {
      if (!run || !enabled) return;
      if (!await run({ cmd: 'peer', contact: contactId }).catch(() => null)) return; // Not pinned here yet: the next pin takes the new key.
      await run({ cmd: 'acceptSuccession', contact: contactId, records });
      pinsChanged(contactId);
    },
    /** The DM group this device holds with a contact, if any (m5 §8). */
    dmChannelWith: peerId => [...channels].find(([, ch]) => ch.kind === 'dm' && ch.peer === peerId && ch.dmChecked && usable(ch))?.[0] || null,
    /** The link commands of this device's group store (docs/m5-linking.md §1.2): the primary's end of a link. */
    linkCore: command => enabled && /^link[A-Z]/.test(command?.cmd || '') ? run({ ...command, now: Date.now() }) : Promise.reject(new Error(reason || 'Groups are not ready on this device.')),
    /** Names and topics for a linked device's bundle (§2): private names exist only on devices. */
    bundleChannels: () => [...channels].filter(([, ch]) => ['active', 'frozen', 'paused'].includes(ch.status) && ch.kind !== 'dm').map(([id, ch]) => ({ id, kind: ch.kind, name: ch.meta?.name || ch.serverName || null, topic: ch.meta?.topic || null })), sections, open, close, info, nameOf, receiptInfo, openNew, openBrowser, openInfo,
    active: () => currentId, enabled: () => enabled, flush: () => currentId && flush(currentId),
    onReact: (target, emoji, on) => send(currentId, { v: 1, type: 'react', id: crypto.randomUUID(), target, emoji, on }),
    async onEdit(record, text) {
      const id = currentId, editedAt = Math.max(Date.now(), (record.editedAt || 0) + 1);
      if (!await window.ChatStore.edit(id, record.id, 'me', text, editedAt)) throw new Error('This message can no longer be edited.');
      const latest = (await window.ChatStore.list()).find(value => value.conversationId === id && value.id === record.id);
      if (latest?.status === 'queued') { flush(id); return; }
      await send(id, { v: 1, type: 'edit', id: crypto.randomUUID(), target: record.id, text, editedAt });
    },
    onDisplayed, onTyping,
    // For tests and diagnostics: the state of one channel on this device.
    /** For tests and diagnostics: the devices in this device's copy of a group's tree. */
    leaves: id => run ? run({ cmd: 'mlsMembers', group: id }).then(list => list.map(member => ({ userId: member.userId, deviceId: member.deviceId, stale: Boolean(member.stale) }))) : Promise.resolve([]),
    debug: id => { const ch = channels.get(id); return ch && { status: ch.status, cursor: ch.cursor, kind: ch.kind, members: ch.members.map(member => member.username), admins: ch.admins }; },
  });
})();
