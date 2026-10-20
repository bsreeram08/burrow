'use strict';
// Linking a device (docs/m5-linking.md §1–§3): the new browser (N) shows a QR, the primary (P) scans it or takes its
// text, both show the same 6-digit code, P signs N into the account and sends it a sealed grant and bundle through
// the server's blind relay. The screens are link.js; the link crypto runs in a chatcore group store (core.js); every
// signature by the account key is made here, in WebCrypto (a web primary's key never enters chatcore).
(() => {
  const POLL = 1500, LINK_TTL = 10 * 60000, CHUNK = 32 * 1024;
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const F = () => window.DeviceFormat;
  const b64 = bytes => F().b64(bytes);
  const utf8 = text => new TextEncoder().encode(text);
  let ctx = null;

  /** Plain fetch for the link endpoints (a new browser may have no session: the claim is its credential). */
  async function call(path, method = 'GET', payload, claim) {
    const headers = { ...(payload === undefined ? {} : { 'Content-Type': 'application/json' }), ...(claim ? { 'X-Link-Claim': claim } : {}) };
    const response = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', headers, body: payload === undefined ? undefined : JSON.stringify(payload) });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw Object.assign(new Error(body.error || 'Something went wrong. Try again.'), { status: response.status, body });
    return body;
  }
  /** Waits until `check()` returns a value, polling; gives up when the link expires or the dialog is closed. */
  async function until(check, live, deadline) {
    for (;;) {
      if (!live()) throw Object.assign(new Error('cancelled'), { cancelled: true });
      if (Date.now() > deadline) throw new Error('The link expired. Start again on both devices.');
      const value = await check();
      if (value) return value;
      await sleep(POLL);
    }
  }
  const spacedCode = code => `${code.slice(0, 3)} ${code.slice(3)}`;

  // ---------- N: this browser joins an account ----------
  async function linkThisBrowser() {
    // Signed out (the usual case) or signed in on a device the account doesn't list yet.
    const owner = ctx?.me()?.id || '__link__';
    let open = true, linkId = null, claim = null;
    try {
      const device = await F().deviceKey(owner);
      const deviceId = device.deviceId, instance = `link-${deviceId}`;
      const run = window.Core.groupStore(deviceId, instance);
      const signature = await device.sign(F().startBytes(deviceId, 'web', device.publicKey));
      const start = await call('/api/link/start', 'POST', { purpose: 'link', deviceId, deviceKey: device.publicKey, platform: 'web', signature });
      ({ linkId, claim } = start);
      const deadline = Math.min(start.expiresAt || Infinity, Date.now() + LINK_TTL);
      const { qr } = await run({ cmd: 'linkQr', linkId, now: Date.now() });
      const shown = window.Linking.open({
        title: 'Link this browser', qr, code: qr,
        hint: 'On your primary device, open Settings → Devices → Link a new device. Scan this code there, or type the text under it.',
        onCancel: () => { open = false; call(`/api/link/${linkId}`, 'DELETE', undefined, claim).catch(() => {}); run({ cmd: 'linkEnd', linkId }).catch(() => {}); },
      });
      const offered = await until(async () => { const state = await call(`/api/link/${linkId}`, 'GET', undefined, claim); if (state.state === 'expired') throw new Error('The link expired. Start again on both devices.'); return state.state === 'offered' || state.state === 'granted' ? state : null; }, () => open, deadline);
      const { code } = await run({ cmd: 'linkComplete', linkId, eph: offered.eph, now: Date.now() });
      // Say who we are, sealed: the primary shows this with the code before anyone signs anything.
      const leafSigKey = await run({ cmd: 'mlsDeviceLeaf' });
      const hello = { v: 1, type: 'hello', deviceId, platform: 'web', label: F().describeThisDevice(), leafSigKey, wantsHistory: true };
      await call(`/api/link/${linkId}/messages`, 'POST', { data: await run({ cmd: 'linkSeal', linkId, plaintext: JSON.stringify(hello), now: Date.now() }) }, claim);
      shown.status(`Check that your primary device shows ${spacedCode(code)}, then tap Link there.`);
      await until(async () => { const state = await call(`/api/link/${linkId}`, 'GET', undefined, claim); return state.state === 'granted' ? state : null; }, () => open, deadline);
      // Granted: take the session, then read and check what the primary sent.
      const claimSignature = await device.sign(F().linkClaimBytes(linkId, deviceId, claim));
      const { user } = await call(`/api/link/${linkId}/claim`, 'POST', { claim, signature: claimSignature });
      shown.status('Linked. Setting up this browser…');
      const { grant, bundle } = await receiveGrant(run, linkId, claim, deadline, () => open);
      open = false; // Past the point of cancelling: the account now lists this device.
      await install({ run, user, deviceId, instance, leafSigKey, grant, bundle });
      if (owner !== user.id) await F().adoptDeviceKey(owner, user.id);
      await run({ cmd: 'linkEnd', linkId }).catch(() => {});
      shown.done(`This browser is linked to ${user.username}. Your groups and channels arrive in a moment.`);
      setTimeout(() => location.reload(), 1200);
    } catch (error) {
      if (error.cancelled) return;
      window.Linking.open({ title: 'Link this browser', hint: '' }).fail(error.message || 'Linking didn’t work. Start again on both devices.');
    }
  }
  /** The sealed grant, then its bundle chunks, in order (a counter gap or replay is refused by the core). */
  async function receiveGrant(run, linkId, claim, deadline, live) {
    let after = 0, grant = null;
    const chunks = [];
    await until(async () => {
      const { messages } = await call(`/api/link/${linkId}/messages?after=${after}`, 'GET', undefined, claim);
      for (const message of messages) {
        after = message.seq;
        const value = JSON.parse(await run({ cmd: 'linkOpen', linkId, data: message.data, now: Date.now() }));
        if (!grant) { if (value?.type !== 'grant' || value.v !== 1) throw new Error('The other device sent something unexpected.'); grant = value; }
        else if (value?.type === 'bundle' && value.i === chunks.length && value.of === grant.chunks) chunks.push(value.data);
        else throw new Error('The other device sent something unexpected.');
      }
      return grant && chunks.length >= grant.chunks;
    }, live, deadline);
    const text = new TextDecoder().decode(chunks.length ? F().unb64(chunks.join('')) : utf8('{}'));
    let bundle = {};
    try { bundle = grant.chunks ? JSON.parse(text) : {}; } catch { throw new Error('The other device sent something unexpected.'); }
    return { grant, bundle };
  }
  /** §1.6: everything the grant says is checked before any of it is trusted; then this browser becomes a linked device. */
  async function install({ run, user, deviceId, instance, leafSigKey, grant, bundle }) {
    const wrong = () => new Error('This doesn’t look like your account. Nothing was set up.');
    const me = await call('/api/me');
    if (grant.deviceId !== deviceId || grant.userId !== user.id || me.user?.id !== user.id || grant.username !== user.username || me.user.username !== user.username) throw wrong();
    const identity = grant.identity;
    // The list the server serves must be the one the grant names, signed by the account key the primary showed us.
    const view = await call(`/api/devices/${encodeURIComponent(user.username)}`);
    const check = await F().verifyView({ userId: user.id, aikSign: identity?.sign, list: view.list, signature: view.signature, certs: view.certs, pin: undefined });
    if (!check.ok || view.list.version !== grant.listVersion || check.hash !== grant.listHash || !view.list.devices.some(device => device.deviceId === deviceId)) throw wrong();
    // The certificate must name this device and its leaf key and verify under that account key (checked by the core).
    const cert = await run({ cmd: 'companionSetup', userId: user.id, identity, cert: grant.cert });
    if (cert.deviceId !== deviceId || cert.leafSigKey !== leafSigKey || cert.userId !== user.id) throw wrong();
    try {
      const pins = JSON.parse(localStorage.getItem(`device-pins-v1:${user.id}`) || '{}') || {};
      pins[user.id] = check.pin; localStorage.setItem(`device-pins-v1:${user.id}`, JSON.stringify(pins));
      localStorage.setItem(`device-meta-key-v1:${user.id}`, grant.metaKey);
      localStorage.setItem(`mls-cert-v1:${instance}`, '1');
    } catch {}
    if (Array.isArray(bundle.pins)) await run({ cmd: 'importPins', pins: bundle.pins }).catch(() => 0);
    // Names and topics of private channels exist only on devices: they arrive with the bundle (later `meta` wins).
    if (Array.isArray(bundle.channels)) {
      const state = {};
      for (const item of bundle.channels.slice(0, 500)) {
        if (typeof item?.id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(item.id)) continue;
        state[item.id] = { kind: item.kind, serverName: item.kind === 'public' ? item.name : null, meta: { name: typeof item.name === 'string' ? item.name.slice(0, 64) : '', topic: typeof item.topic === 'string' ? item.topic.slice(0, 256) : '', at: 0 }, cursor: 0, status: 'join-pending', unread: 0, mentioned: false, lastAt: 0, members: [], admins: [] };
      }
      try { localStorage.setItem(`groups-v1:${instance}`, JSON.stringify(state)); } catch {}
    }
    if (Array.isArray(bundle.conversations)) {
      const records = bundle.conversations.slice(0, 20).flatMap(conversation => Array.isArray(conversation?.history) ? conversation.history.slice(-200) : []);
      await window.ChatStore.importLinked(records).catch(() => 0);
    }
    try { localStorage.setItem(`linked-store-v1:${user.id}`, JSON.stringify({ deviceId, instance, identity })); } catch {}
  }

  // ---------- P: the primary links a new device ----------
  async function linkNewDevice() {
    if (!await ctx.isPrimary()) { ctx.notice('Link new devices from your primary device: the one that holds your keys.'); return; }
    let open = true, linkId = null;
    const ui = window.Linking.open({
      title: 'Link a new device', entry: true,
      hint: 'On the new device, open this app and choose “Link to my other device”. Scan the code it shows, or type the text under it.',
      onEntry: async text => {
        if (!text.startsWith('wb-link1.')) throw new Error('That isn’t a link code from this app. Check the text and try again.');
        const accepted = await window.Groups.linkCore({ cmd: 'linkAccept', qr: text });
        linkId = accepted.linkId;
        accept(ui, accepted, () => open).catch(error => { if (!error.cancelled) ui.fail(error.message || 'Linking didn’t work. Start again on both devices.'); });
      },
      onCancel: () => { open = false; if (linkId) { call(`/api/link/${linkId}`, 'DELETE').catch(() => {}); window.Groups.linkCore({ cmd: 'linkEnd', linkId }).catch(() => {}); } },
    });
  }
  async function accept(ui, { linkId, eph, code }, live) {
    const deadline = Date.now() + LINK_TTL;
    const offer = await call(`/api/link/${linkId}/offer`, 'POST', { eph });
    if (offer.purpose !== 'link') throw new Error('That code is for something else. Start again on both devices.');
    ui.status('Waiting for the new device…');
    let after = 0;
    const hello = await until(async () => {
      const { messages } = await call(`/api/link/${linkId}/messages?after=${after}`);
      for (const message of messages) {
        after = message.seq;
        const value = JSON.parse(await window.Groups.linkCore({ cmd: 'linkOpen', linkId, data: message.data }));
        if (value?.type === 'hello') return value;
      }
      return null;
    }, live, deadline);
    // The device must be the one that registered this link, describing itself consistently.
    if (hello.v !== 1 || hello.deviceId !== offer.deviceId || hello.platform !== offer.platform || !F().PLATFORMS.includes(hello.platform) || !/^[A-Za-z0-9_-]{43}$/.test(hello.leafSigKey || '')) throw new Error('The new device sent something unexpected. Nothing was linked.');
    const label = String(hello.label || '').slice(0, 64) || ctx.platformName(hello.platform);
    ui.status(`${label} wants to link to your account.`);
    if (!await ui.compare(code)) { call(`/api/link/${linkId}`, 'DELETE').catch(() => {}); ui.fail('Nothing was linked. If you didn’t start this, someone may have shown you their code.'); return; }
    ui.status('Linking…');
    // 1. The next signed device list names it (§1.1 step 7).
    const listed = await ctx.addToList(hello.deviceId, { label, platform: hello.platform });
    // 2. Its MLS device certificate, signed by the account key over the core's own bytes (DeviceCert::tbs).
    const me = ctx.me(), aik = await ctx.aikSign(), issuedAt = Date.now();
    const sig = await ctx.signWithIdentity(F().mlsCertBytes(me.id, hello.deviceId, hello.platform, hello.leafSigKey, aik.sign, issuedAt));
    const cert = F().mlsCertJson(me.id, hello.deviceId, hello.platform, hello.leafSigKey, aik.sign, issuedAt, sig);
    // 3. The grant, the go-ahead, then the bundle.
    const bundle = utf8(JSON.stringify(await buildBundle(hello.wantsHistory === true)));
    const text = bundle.length > 2 ? b64(bundle) : '';
    const chunks = [];
    for (let at = 0; at < text.length; at += CHUNK) chunks.push(text.slice(at, at + CHUNK));
    if (chunks.length > 16) chunks.length = 0; // Too big to send: link without it rather than fail.
    const grant = { v: 1, type: 'grant', userId: me.id, username: me.username, identity: aik, deviceId: hello.deviceId, cert, listVersion: listed.version, listHash: listed.hash, metaKey: b64(await ctx.metaKeyBytes()), chunks: chunks.length };
    const send = async value => call(`/api/link/${linkId}/messages`, 'POST', { data: await window.Groups.linkCore({ cmd: 'linkSeal', linkId, plaintext: JSON.stringify(value) }) });
    await send(grant);
    await call(`/api/link/${linkId}/grant`, 'POST', {});
    for (const [i, data] of chunks.entries()) await send({ v: 1, type: 'bundle', i, of: chunks.length, data });
    await window.Groups.linkCore({ cmd: 'linkEnd', linkId }).catch(() => {});
    ui.done(`Linked ${label}. It joins your groups and channels by itself; 1:1 chats stay here until they move to the new encryption.`);
    ctx.devicesChanged();
  }
  /** §2: pins (not changed or blocked ones), channel names, and (if asked) recent history. Never a key. */
  async function buildBundle(withHistory) {
    const pins = [];
    for (const contact of ctx.contacts().filter(value => value.state === 'mutual')) {
      const peer = await ctx.peer(contact.id).catch(() => null);
      if (peer && !peer.changed && !peer.blocked) pins.push({ contact: contact.id, identity: { dh: peer.identity.dh, sign: peer.identity.sign }, verified: Boolean(peer.verified) });
    }
    const bundle = { v: 1, pins, channels: window.Groups?.bundleChannels() || [], conversations: [], settings: {} };
    if (withHistory) {
      const records = (await window.ChatStore.list()).filter(record => record.direction !== 'system' && !record.imported);
      const byConversation = new Map();
      for (const record of records) byConversation.set(record.conversationId, [...byConversation.get(record.conversationId) || [], record]);
      const recent = [...byConversation].sort((a, b) => b[1].at(-1).createdAt - a[1].at(-1).createdAt).slice(0, 20);
      let size = 0;
      for (const [id, list] of recent) {
        const history = list.slice(-200), bytes = utf8(JSON.stringify(history)).length;
        if (size + bytes > 512 * 1024) break;
        size += bytes;
        bundle.conversations.push({ id, peer: await ctx.peerOfConversation(id), history });
      }
    }
    return bundle;
  }

  /** account.js hands over what linking needs from the signed-in account, and the flows appear. */
  function attach(context) {
    ctx = context;
    window.Linking.register(context ? { linkNew: linkNewDevice, linkThis: linkThisBrowser } : null);
  }
  const wire = () => { const button = document.getElementById('signin-link'); if (button) button.onclick = () => linkThisBrowser(); };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
  window.DeviceLink = Object.freeze({ attach, linkThisBrowser });
})();
