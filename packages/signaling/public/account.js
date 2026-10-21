'use strict';
// Passkey accounts, contacts, presence and end-to-end encrypted messaging. Contact messages travel
// as Signal-protocol envelopes (signal.js) through the server mailbox, which can never read them;
// calls still run device-to-device through app.js.
(() => {
  const $ = id => document.getElementById(id);
  const body = $('app'), App = window.App;
  let me = null, contacts = [], events = null, retry = 0, retryTimer, current = null, ringing = null;
  let box = null, ready = Promise.resolve(false), inbound = Promise.resolve(), flushing = false, flushAgain = false, flushTimer;
  let unread = {}, flagged = new Set();
  const pairs = new Map(), mismatched = new Set();
  let missTimer, noAnswerTimer;
  const Ring = window.Ring || { incoming() {}, outgoing() {}, stop() {}, unlock() {} };
  const RING_TIMEOUT = 45000, USERNAME = /^[a-z0-9_]{3,20}$/;
  const clock = time => new Date(time).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const say = (id, text) => { $(id).textContent = text; };
  const initial = name => (name || '?').slice(0, 1).toUpperCase();

  async function api(path, method = 'GET', payload) {
    const response = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', headers: payload === undefined ? {} : { 'Content-Type': 'application/json' }, body: payload === undefined ? undefined : JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw Object.assign(new Error(data.error || 'Something went wrong. Try again.'), { status: response.status });
    return data;
  }
  // One stable, opaque ChatStore id per pair, so history survives across rooms and devices.
  async function pairId(otherId) {
    const key = [me.id, otherId].sort().join(':');
    if (!pairs.has(key)) {
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`webrtc-bun-pair-v1:${key}`)));
      pairs.set(key, btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    }
    return pairs.get(key);
  }
  const contactById = id => contacts.find(contact => contact.id === id);

  // ---------- Welcome: passkey sign-in and invite sign-up ----------
  async function guard(button, statusId, task) {
    button.disabled = true; say(statusId, '');
    try { await task(); }
    catch (error) { say(statusId, error.name === 'NotAllowedError' ? 'Passkey request was cancelled.' : error.message || 'Something went wrong.'); }
    finally { button.disabled = false; }
  }
  $('signin').onclick = () => guard($('signin'), 'account-status', async () => {
    const { flowId, options } = await api('/api/login/options', 'POST', {});
    const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
    signedIn((await api('/api/login/verify', 'POST', { flowId, response })).user);
  });
  $('register-form').addEventListener('submit', event => {
    event.preventDefault();
    guard($('register-submit'), 'account-status', async () => {
      const invite = $('register-invite').value.trim(), username = $('register-username').value.trim().toLowerCase();
      const { flowId, options } = await api('/api/register/options', 'POST', { invite, username });
      const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
      signedIn((await api('/api/register/verify', 'POST', { flowId, response })).user);
      $('register-invite').value = ''; $('register-username').value = '';
    });
  });

  function signedIn(user) {
    me = user; body.dataset.auth = 'in'; body.dataset.screen = 'list';
    say('me-name', `@${user.username}`); say('account-status', '');
    try { unread = JSON.parse(localStorage.getItem(`unread-v1:${me.id}`) || '{}') || {}; } catch { unread = {}; }
    ready = setupKeys(user);
    // Groups and channels (groups.js) start once this device's keys and device list are in place.
    ready.then(ok => {
      if (ok && me?.id === user.id && !inactive) window.Groups?.start(groupContext());
      if (ok && me?.id === user.id) window.DeviceLink?.attach(linkContext());
      // A device waiting for the account key asks (again) on every start, not only on frames (m6 §5).
      if (ok && me?.id === user.id && linked && !keyBox) followOwnSuccession().catch(() => false).then(() => takeRekey()).catch(() => {});
    });
    window.Theme?.setAccount(user.id); App.accountId = user.id; App.myName = user.username; App.rescheduleReminders?.(); loadEmoji();
    $('rotation-every').value = String(myRotation());
    loadContacts(); connectEvents(); window.Alerts?.signedIn(); showKeyChange();
  }
  function signedOut(message = '') {
    window.Groups?.stop(); window.DeviceLink?.attach(null); delete body.dataset.kind; linked = null; keyBox = null;
    unfinished = []; backupExists = false; coreKeyed = null;
    me = null; contacts = []; current = null; pairs.clear(); box = null; deviceView = null; announced = ''; metaKey = null; deviceWarning = ''; deviceNotice = ''; ready = Promise.resolve(false); flagged = new Set(); mismatched.clear();
    clearTimeout(retryTimer); clearTimeout(flushTimer); const previous = events; events = null; previous?.close();
    if (App.active) App.end(); App.closeConversation(); $('key-banner').hidden = true; $('keychange-notice').hidden = true;
    body.dataset.auth = 'out'; body.dataset.screen = ''; say('account-status', message);
    hideRing(); stopCalling(); window.Alerts?.signedOut(); window.Theme?.setAccount(null); App.accountId = null; App.myName = null; App.rescheduleReminders?.();
  }
  async function signOut(everywhere) {
    $('account-menu').open = false;
    try { await api(everywhere ? '/api/logout?all=1' : '/api/logout', 'POST', {}); } catch {}
    signedOut(everywhere ? 'Signed out on every device.' : 'Signed out.');
  }
  $('signout').onclick = () => signOut(false);
  $('signout-all').onclick = () => signOut(true);

  // ---------- Encryption keys ----------
  async function setupKeys(user) {
    if (!window.Signal || !await window.Signal.supported()) {
      say('chats-status', 'This browser is too old for encrypted messaging. Update it to send and receive messages; calls still work.');
      return false;
    }
    // A key change this browser started before it was closed (m6 §6.2) is finished, or dropped, first.
    await resumeRotation(user.id).catch(error => say('chats-status', `Couldn’t finish changing your account key: ${error.message}`));
    // A linked device (docs/m5-linking.md §1) holds no account identity key: no 1:1 keys here, ever (publishing
    // some would take messaging away from the inbox device). Groups, channels and moved DMs run in its group store.
    linked = linkedStore(user.id);
    if (linked) {
      backendName = 'linked'; box = null; keysLost = false; setInactive(false); showBackend();
      // m6 §2, §4: a linked browser that holds the account key keeps it in its key store, for signing only.
      keyBox = linked.full ? window.Signal.box(window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${user.id}`)) : null;
      $('identity-reset').hidden = true;
      return true;
    }
    // One key store per account on this device. Private keys never leave it.
    const store = window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${user.id}`);
    // Ask the browser not to evict the keys; and remember that this browser held them, so a browser that
    // silently drops site data (private tabs, in-app browsers) is named instead of looping on new keys.
    try { await navigator.storage?.persist?.(); } catch {}
    const hooks = { identityChanged: contactId => identityChanged(contactId) };
    // Which core this account uses on this device: a local setting (Settings → Advanced), never a link.
    // The experimental WebAssembly core (core.js) runs the same protocol from crates/chatcore with its own
    // sealed key store; switching is an explicit reset of this device's keys (see core-backend-switch).
    backendName = window.Core?.supported() ? await window.Core.backend(user.id) : 'signal';
    announceBackend = window.Core?.supported() ? window.Core.guard(user.id, backendName, () => location.reload()) : () => {};
    if (backendName === 'wasm') {
      keysLost = false;
      box = window.Core.box(user.id, hooks);
    } else {
      try { keysLost = !await store.get('identity') && localStorage.getItem(`keys-held-v1:${user.id}`) === '1'; } catch { keysLost = false; }
      box = window.Signal.box(store, hooks);
    }
    showBackend();
    flagged = new Set(await store.get('flagged') || []);
    flagged.store = store;
    // After a confirmed switch, the new core's fresh keys take over this account (the user chose to reset them).
    let switched = false;
    try { switched = localStorage.getItem(`core-switch-takeover-v1:${user.id}`) === '1'; localStorage.removeItem(`core-switch-takeover-v1:${user.id}`); } catch {}
    try { await publishKeys(switched); } catch (error) { say('chats-status', `Could not publish encryption keys: ${error.message}`); }
    return true;
  }
  /** One device per account holds messaging. Another device or browser (e.g. Safari vs the Home Screen app)
   *  never replaces it silently: it stays inactive (sends nothing, acknowledges nothing) until the user moves
   *  messaging here, so envelopes meant for the active device are never consumed by one that cannot read them. */
  let inactive = false, keysLost = false;
  function setInactive(value) {
    inactive = value; $('device-banner').hidden = !value;
    if (keysLost) say('device-banner-text', 'This browser lost your encryption keys since you last used it here. That happens in private tabs and in apps’ built-in browsers. Open this site in your browser itself, or from the Home Screen app, or unlock your account here again.');
    if (value) { say('chats-status', ''); if (current) App.chatStatus('Messaging is active on another device. Use this device from the chat list to send here.'); }
  }
  async function publishKeys(takeover = false) {
    if (!box || !me) return;
    const keys = await box.prekeys(), count = await api('/api/keys/count');
    const mine = count.identity, here = keys.identity;
    const other = Boolean(mine && (mine.dh !== here.dh || mine.sign !== here.sign));
    if (other && !takeover) {
      // The account key was replaced on another device while this one was away (m6 §6.2): follow it if it checks out.
      if (await followOwnSuccession().catch(() => false)) { setInactive(false); return; } // Now a device waiting for the new key.
      setInactive(true); announceDevice(null).catch(() => {});
      api(`/api/devices/${me.username}`).then(view => { deviceView = view; renderDevices(); }).catch(() => {}); // Whether a backup can unlock it here.
      return;
    }
    setInactive(false); keysLost = false;
    // Holding the published identity: this device takes the messaging inbox (unless a signed list names another primary).
    if (!other) await announceDevice(mine ? here : null).catch(() => {}); // Before the first upload there is nothing to prove: the upload claims.
    try { localStorage.setItem(`keys-held-v1:${me.id}`, '1'); } catch {}
    const upload = { identity: here, signedPreKey: keys.signedPreKey };
    // Taking over replaces the identity, and the server drops the previous device's prekeys with it.
    if (other || count.oneTimePreKeys < 20 || count.signedPreKeyId === null) upload.oneTimePreKeys = await box.oneTimePreKeys(other ? 100 : 100 - Math.min(count.oneTimePreKeys, 100) || 100);
    if (other || upload.oneTimePreKeys || keys.rotated || count.signedPreKeyId !== keys.signedPreKey.id) await api('/api/keys', 'PUT', upload);
    if (other) { await announceDevice(here).catch(() => {}); flushOutgoing(); }
    await syncDevices().catch(error => { deviceWarning = `Could not update the device list: ${error.message}`; renderDevices(); });
  }

  // ---------- Devices (docs/devices.md) ----------
  // This browser's device id, kept per account. The device holding the account identity key is the primary:
  // it signs the device list (AIK-signed, versioned, hash-chained) that contacts and the server go by.
  let deviceWarning = '', deviceNotice = '', deviceView = null;
  const Devices = window.DeviceFormat;
  // This browser's device id and its own non-extractable Ed25519 device key (devices.js), per account.
  const localDevice = () => Devices.deviceKey(me.id);

  // Highest verified list per account (own and contacts): a list may only move forward, never back or sideways.
  const readPins = () => { try { return JSON.parse(localStorage.getItem(`device-pins-v1:${me.id}`) || '{}') || {}; } catch { return {}; } };
  const writePins = pins => { try { localStorage.setItem(`device-pins-v1:${me.id}`, JSON.stringify(pins)); } catch {} };
  // m6: the account key may be on any listed device. The inbox device's box holds it (and runs 1:1); a linked browser
  // holding it keeps it in the same store, for signing only (it publishes no prekeys from there).
  const signer = () => linked ? keyBox : inactive ? null : box;
  const holdsKey = () => Boolean(signer());
  async function rawSign(bytes, from = signer()) {
    if (!from?.sign) throw new Error('this encryption core cannot sign device lists yet');
    return from.sign(bytes);
  }
  const signWithIdentity = async bytes => Devices.b64(await rawSign(bytes));
  // The key that seals device labels and platforms inside the list: derived from the identity key, per account.
  let metaKey = null;
  async function deviceMetaKey() {
    const aik = (await signer().identity()).pub.sign;
    if (metaKey?.aik !== aik) metaKey = { aik, key: Devices.deviceMetaKey(me.id, rawSign) };
    return metaKey.key;
  }
  /** Signs `list`, with an AIK-signed certificate for every device it names. */
  async function signList(list) {
    const certs = {};
    for (const device of list.devices) certs[device.deviceId] = await signWithIdentity(Devices.certBytes(Devices.certFor(me.id, device)));
    return { list, signature: await signWithIdentity(Devices.listBytes(list)), certs };
  }
  /** After publishing: advance our own pin (version, hash and tombstones for dropped devices) through the same checks contacts run. */
  /**
   * This account's devices as a verified signed list proves them (m5 §3, §4): the list must verify under our own
   * account key (held here, or pinned at link time on a linked device) and move forward from our pin. `dropped`:
   * devices an earlier pinned list named and a later verified one dropped (the only absence that is proven).
   * null when nothing can be verified: then nothing is removed or joined on the server's word.
   */
  async function verifiedOwnDevices() {
    const aikSign = linked ? linked.identity?.sign : box ? (await box.prekeys()).identity.sign : null;
    if (!me || !aikSign) return null;
    const view = await api(`/api/devices/${me.username}`).catch(() => null);
    const pins = readPins(), pin = pins[me.id];
    if (!view?.list) return null;
    const check = await Devices.verifyView({ userId: me.id, aikSign, list: view.list, signature: view.signature, certs: view.certs, pin });
    if (!check.ok) return null;
    pins[me.id] = check.pin; writePins(pins); rememberLabels(view.list).catch(() => {});
    // A key change starts a new list chain, so devices it dropped aren't tombstones there: they are remembered apart.
    const removed = readJson(`removed-devices-v1:${me.id}`, []).filter(id => !check.pin.devices.includes(id));
    return { listed: new Set(check.pin.devices), dropped: new Set([...check.pin.revoked, ...removed]) };
  }
  async function pinOwn(signed) {
    const pins = readPins(), own = (await signer().identity()).pub;
    const after = await Devices.verifyView({ userId: me.id, aikSign: own.sign, ...signed, pin: pins[me.id] });
    if (after.ok) { pins[me.id] = after.pin; writePins(pins); await rememberLabels(signed.list).catch(() => {}); }
  }
  /**
   * Binds this browser's session to its device id. A browser that does not hold the keys shows up as pending in
   * the owner's Settings → Devices; one that holds the published identity says so and gets the messaging inbox.
   */
  let announced = '', announcing = Promise.resolve();
  // One at a time: publishKeys runs from sign-in and from every reconnect.
  function announceDevice(identity) { const run = announcing.then(() => announceDeviceNow(identity)); announcing = run.catch(() => {}); return run; }
  async function announceDeviceNow(identity) {
    if (!me || !Devices) return;
    const key = `${me.id}|${identity ? identity.sign : ''}`;
    if (announced === key) return;
    // Proof of possession: the device key signs this session's single-use challenge.
    const device = await localDevice(), { challenge } = await api('/api/devices/challenge', 'POST', {});
    const signature = await device.sign(Devices.bindBytes(me.id, device.deviceId, challenge));
    // Holding the published identity: prove it with the identity key over the same challenge, to claim messaging.
    const identityProof = identity ? await (backendName === 'wasm' ? box.proveIdentity(me.id, device.deviceId, challenge) : signWithIdentity(Devices.claimBytes(me.id, device.deviceId, challenge))) : undefined;
    await api('/api/devices/announce', 'POST', { deviceId: device.deviceId, deviceKey: device.publicKey, challenge, signature, ...(identityProof ? { identityProof } : {}) });
    announced = key;
  }
  /** On the identity-key holder: verify the served list against our own key and pins, and publish the next one if this device is missing. */
  // One at a time: the key upload and a 'devices' event may both ask, and two signers would race for the same version.
  let syncing = Promise.resolve();
  function syncDevices() { const run = syncing.then(syncDevicesNow); syncing = run.catch(() => {}); return run; }
  async function syncDevicesNow() {
    const holder = signer();
    if (!me || !holder || !Devices || backendName === 'wasm') return; // The WebAssembly core cannot sign with the identity key yet (M2).
    const id = (await localDevice()).deviceId, own = (await holder.identity()).pub;
    const view = await api(`/api/devices/${me.username}`);
    if (!view.identity || view.identity.sign !== own.sign || view.identity.dh !== own.dh) return; // Not the key holder: publishKeys decides.
    const pins = readPins(), pin = pins[me.id];
    // A transfer cut short by a reload still starts its chain: the marker counts only for this key, before its list has a pin.
    newChain ||= Devices.chainMarker(readJson(`new-chain-v1:${me.id}`, null), own.sign, pin);
    let base = null;
    if (view.list) {
      const check = await Devices.verifyView({ userId: me.id, aikSign: own.sign, list: view.list, signature: view.signature, certs: view.certs, pin });
      // A new account key here (recovery or a primary transfer, m5 §5-§6): the old key's list ends; version 1 starts.
      if (!check.ok && newChain && check.reason === 'signature') base = null;
      else if (!check.ok) { deviceWarning = `The device list on the server is not one this device signed (${check.reason}). It was not changed.`; deviceView = view; renderDevices(); return; }
      else { pins[me.id] = check.pin; writePins(pins); base = { list: view.list, hash: check.hash }; await rememberLabels(view.list).catch(() => {}); }
      // Listed already (and, once it holds the key, no longer marked as short-code linked, m6 §5): nothing to sign.
      if (base && view.list.devices.some(device => device.deviceId === id) && (await ownMeta(view))?.via !== 'code') { deviceWarning = ''; deviceView = view; renderDevices(); return; }
    }
    // Next version: this device plus every listed device the server still has, chained to the current list. A new
    // chain keeps only the devices the transfer brought along (none after a recovery).
    const stillListed = device => device.deviceId !== id && view.devices.some(row => row.id === device.deviceId && ['listed', 'pending'].includes(row.state));
    const keep = base ? base.list.devices.filter(device => device.deviceId !== id && view.devices.some(row => row.id === device.deviceId && row.state === 'listed')) : (newChain?.keep || []).filter(stillListed);
    const listed = base?.list.devices.find(device => device.deviceId === id);
    // Our own entry, re-sealed without `via` once this browser holds the key itself (m6 §5).
    const label = (listed && (await ownMeta(view))?.label) || Devices.describeThisDevice();
    const self = { deviceId: id, addedAt: listed?.addedAt || Date.now(), meta: await Devices.sealMeta(await deviceMetaKey(), me.id, id, { label, platform: 'web' }) };
    const list = { v: 1, userId: me.id, version: (base?.list.version || 0) + 1, prevHash: base?.hash || '', devices: [...keep, self].sort((a, b) => a.deviceId < b.deviceId ? -1 : 1) };
    const signed = await signList(list);
    await api('/api/devices/list', 'PUT', { ...signed, deviceId: id });
    if (!base) { const pins = readPins(); delete pins[me.id]; writePins(pins); } // The new key's chain starts here.
    await pinOwn(signed);
    newChain = null; try { localStorage.removeItem(`new-chain-v1:${me.id}`); } catch {}
    deviceWarning = '';
    deviceView = await api(`/api/devices/${me.username}`);
    renderDevices();
  }
  /**
   * Linking (docs/m5-linking.md §1.1 step 7): the next signed list, with the new device. The current list must be
   * one we signed (verified against our pin); every device it names that the server still lists stays.
   */
  async function addToList(newId, { label, platform }, viaCode = false) {
    const id = (await localDevice()).deviceId, own = (await signer().identity()).pub;
    const view = await api(`/api/devices/${me.username}`);
    if (!view.list) throw new Error('Your device list isn’t published yet. Try again in a moment.');
    const pins = readPins();
    const check = await Devices.verifyView({ userId: me.id, aikSign: own.sign, list: view.list, signature: view.signature, certs: view.certs, pin: pins[me.id] });
    if (!check.ok) throw new Error(`The device list on the server isn’t one this device signed (${check.reason}). Nothing was linked.`);
    pins[me.id] = check.pin; writePins(pins); await rememberLabels(view.list).catch(() => {});
    const keep = view.list.devices.filter(device => device.deviceId !== newId && view.devices.some(row => row.id === device.deviceId && row.state === 'listed'));
    // m6 §5: a short-code link is marked, so no device ever hands it the account key by rekey (it unlocks with the passphrase).
    const added = { deviceId: newId, addedAt: Date.now(), meta: await Devices.sealMeta(await deviceMetaKey(), me.id, newId, { label, platform, ...(viaCode ? { via: 'code' } : {}) }) };
    const list = { v: 1, userId: me.id, version: view.list.version + 1, prevHash: check.hash, devices: [...keep, added].sort((a, b) => a.deviceId < b.deviceId ? -1 : 1) };
    const signed = await signList(list);
    await api('/api/devices/list', 'PUT', { ...signed, deviceId: id });
    await pinOwn(signed);
    return { version: list.version, hash: await Devices.hash(Devices.listBytes(list)) };
  }
  function linkContext() {
    return {
      me: () => me, notice: text => say('chats-status', text), platformName, addToList, signWithIdentity, contacts: () => contacts, recover,
      holdsKey, accountKey: accountKeyB64, backupKeys: () => readJson(`backup-keys-v1:${me.id}`, null),
      // Unlocking with the backup (§4): offered where it can help, on a browser without the key while a backup exists.
      ...(backupExists && !holdsKey() ? { restorePass: () => restoreWith('pass').catch(error => say('chats-status', error.message)), restoreWords: () => restoreWith('words').catch(error => say('chats-status', error.message)) } : {}),
      aikSign: async () => { const { pub } = await signer().identity(); return { dh: pub.dh, sign: pub.sign }; },
      metaKeyBytes: () => Devices.deviceMetaKeyBytes(me.id, rawSign),
      // The bundle's pins: the inbox device's 1:1 pins, or (elsewhere) the group store's.
      exportPins: async () => box ? (await Promise.all(contacts.filter(contact => contact.state === 'mutual').map(async contact => [contact.id, await box.peer(contact.id).catch(() => null)])))
        .filter(([, peer]) => peer && !peer.changed && !peer.blocked).map(([contact, peer]) => ({ contact, identity: { dh: peer.identity.dh, sign: peer.identity.sign }, verified: Boolean(peer.verified) }))
        : window.Groups?.exportPins().catch(() => []) ?? [],
      async peerOfConversation(id) { for (const contact of contacts) if (contact.state === 'mutual' && await pairId(contact.id) === id) return contact.id; return null; },
      devicesChanged: () => api(`/api/devices/${me.username}`).then(view => { deviceView = view; renderDevices(); }).catch(() => {}),
    };
  }
  /** Set by a recovery or a primary transfer: the next list starts a new chain under this device's new key. */
  let newChain = null;
  /**
   * Recovery without a primary (m5 §6): only after the explicit warning. This browser makes a new account key, takes
   * messaging over, and publishes a list naming only itself. Contacts see the code change; groups it was in see its
   * old devices as stale.
   */
  async function recover() {
    if (!box || linked) return;
    // m6 §6.5: with a backup, starting over without the passphrase waits a week, so the account's devices can cancel it.
    const view = await api(`/api/devices/${me.username}`).catch(() => deviceView);
    if (view?.backup) {
      const reset = view.reset;
      if (!reset) {
        if (!await window.Linking.confirmRecovery()) return;
        await api('/api/keys/reset', 'POST', {});
        say('chats-status', 'Your account key will be reset in 7 days unless one of your devices cancels it.');
        deviceView = await api(`/api/devices/${me.username}`); renderDevices();
        return;
      }
      if (Date.now() < reset.executeAfter) { say('chats-status', `Your account key will be reset on ${new Date(reset.executeAfter).toLocaleString()} unless one of your devices cancels it.`); return; }
      // The week is up: this session may start over now (the server deletes the backup, which holds the old key).
    } else if (!await window.Linking.confirmRecovery()) return;
    try {
      // Nothing from the server's list is carried over: the new key's list names only this browser.
      newChain = { keep: [] }; try { localStorage.removeItem(`new-chain-v1:${me.id}`); } catch {}
      await box.resetIdentity();
      writeJson(`rotation-told-v1:${me.id}`, {});
      await publishKeys(true);
      say('chats-status', 'This browser now holds your account. Everyone you talk to will see that your security code changed.');
      setTimeout(() => location.reload(), 1500);
    } catch (error) { newChain = null; say('chats-status', `Couldn’t start over: ${error.message}`); }
  }
  /**
   * Our account moved to a new key: another device replaced it (m6 §6.2). Followed only along signed records from the
   * key this device holds or pinned, and only if the new key's list still names this device and drops nothing but
   * devices the server shows revoked; otherwise the user is told and nothing is adopted. A device that held the old
   * key drops it and asks for the new one (rekey, §5). Resolves true when followed.
   */
  async function followOwnSuccession() {
    if (!me) return false;
    const holder = linked ? keyBox : box, pinned = linked ? linked.identity : holder ? (await holder.identity()).pub : null;
    if (!pinned) return false;
    const view = await api(`/api/devices/${me.username}`), served = view.identity;
    if (!served || (served.sign === pinned.sign && served.dh === pinned.dh)) return false;
    const path = view.succession?.length ? await Devices.verifySuccession(me.id, pinned, served, view.succession) : null;
    if (!path) { if (linked) { deviceWarning = 'Your account key changed without a record from your devices. Unlock this browser with your passphrase, or link it again.'; renderDevices(); } return false; }
    const self = (await localDevice()).deviceId;
    const fresh = view.list ? await Devices.verifyView({ userId: me.id, aikSign: served.sign, list: view.list, signature: view.signature, certs: view.certs, pin: undefined }) : null;
    if (!fresh?.ok) return false; // The new key's list isn't up yet: the next 'devices' frame tries again.
    // m6 §6.2 step 3: whether a removal was the user's own can't be told from the server (the rotation revokes what it
    // drops, and revoked rows aren't served), so it is compared with this device's own last verified list: anything
    // dropped from it is always shown, until dismissed; a list that drops this device is not followed.
    const before = readPins()[me.id]?.devices || [], dropped = before.filter(id => id !== self && !view.list.devices.some(device => device.deviceId === id));
    const kept = view.list.devices.some(device => device.deviceId === self);
    if (dropped.length || !kept) {
      const from = view.devices.find(row => row.primary), removed = [...(kept ? [] : ['this device']), ...await oldLabels(dropped)];
      showKeyChange(`Your account key was changed from ${platformName(from?.platform)}, which removed ${joinLabels(removed)}. If this wasn’t you, take your account back.`);
      if (!kept) { if (backupExists) window.DeviceLink?.attach(linkContext()); return false; } // Restore is offered (§6.4).
    }
    if (dropped.length) writeJson(`removed-devices-v1:${me.id}`, [...new Set([...readJson(`removed-devices-v1:${me.id}`, []), ...dropped])]);
    const instance = groupInstance(self, pinned.sign), run = keysCore(instance);
    // The inbox device's group store holds neither the key nor an account row: it takes the old key first, so it can
    // adopt the record (it then keeps the old key as a predecessor, like any device that held it).
    if (!linked && holder) {
      const secrets = await holder.exportIdentity();
      if (secrets) {
        try { await run({ cmd: 'importAccountKey', userId: me.id, key: Devices.b64(Devices.accountKeyBytes(me.id, secrets.signSeed, secrets.dhSecret)), published: pinned }); }
        finally { secrets.signSeed.fill(0); secrets.dhSecret.fill(0); }
      } else {
        // A legacy key can't move: a certificate under it, made here, enters the store as a companion of that key.
        const leaf = await run({ cmd: 'mlsDeviceLeaf' }), at = path[0].at;
        const cert = Devices.mlsCertJson(me.id, self, 'web', leaf, pinned.sign, at, Devices.b64(await holder.sign(Devices.mlsCertBytes(me.id, self, 'web', leaf, pinned.sign, at))));
        await run({ cmd: 'companionSetup', userId: me.id, identity: { dh: pinned.dh, sign: pinned.sign }, cert });
      }
    }
    for (const { signature, ...record } of path) await run({ cmd: 'adoptSuccession', userId: me.id, record, signature });
    // The old key is a predecessor now: it goes from here (the new one arrives by rekey).
    await holder?.resetIdentity().catch(() => {});
    linked = { deviceId: self, instance, identity: { dh: served.dh, sign: served.sign }, full: false };
    keyBox = null; box = null;
    writeJson(`linked-store-v1:${me.id}`, linked);
    const pins = readPins(); pins[me.id] = fresh.pin; writePins(pins);
    deviceNotice = 'Your account key was changed on another device. This one gets the new key in a moment.'; renderDevices();
    await askRekey().catch(() => {}); // Refused while the new key's list isn't up yet: asked again on the next 'devices'.
    return true;
  }
  /**
   * The labels of our own devices, kept from every verified list we pinned (opened with the label key this device holds
   * or derives); kept for a device a later list dropped, so a key change can still name what it removed (§6.2 step 3).
   */
  async function rememberLabels(list) {
    const holder = linked ? keyBox : inactive ? null : box, stored = localStorage.getItem(`device-meta-key-v1:${me.id}`);
    const key = holder ? await Devices.deviceMetaKey(me.id, bytes => holder.sign(bytes)).catch(() => null) : stored ? await Devices.metaKeyFromBytes(Devices.unb64(stored)).catch(() => null) : null;
    if (!key || !list) return;
    const labels = readJson(`device-labels-v1:${me.id}`, {});
    for (const device of list.devices) { const described = await Devices.openMeta(key, me.id, device.deviceId, device.meta); if (described?.label) labels[device.deviceId] = described.label; }
    writeJson(`device-labels-v1:${me.id}`, labels);
  }
  const oldLabels = async ids => { const labels = readJson(`device-labels-v1:${me.id}`, {}); return ids.map(id => labels[id] || 'a device'); };
  /** "A", "A and B", "A, B and C". */
  const joinLabels = items => items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
  /** The key-change notice (§6.2 step 3) stays until the user dismisses it, across reloads. */
  function showKeyChange(text) {
    if (text) writeJson(`keychange-notice-v1:${me.id}`, text);
    const shown = readJson(`keychange-notice-v1:${me.id}`, null);
    $('keychange-notice').hidden = !shown; say('keychange-notice-text', shown || '');
  }
  $('keychange-notice-dismiss').onclick = () => { try { localStorage.removeItem(`keychange-notice-v1:${me.id}`); } catch {} showKeyChange(); };
  /**
   * The inbox device follows a key change made elsewhere without a reload: once followed it runs as a device waiting
   * for the key (groups restart on the same store, which now pins the new key), and its rekey request is out.
   */
  let following = null;
  function followLive() {
    following ||= (async () => {
      if (linked) return false;
      if (!await followOwnSuccession()) return false;
      setInactive(false); keysLost = false; backendName = 'linked'; showBackend();
      window.Groups?.start(groupContext());
      window.DeviceLink?.attach(linkContext());
      await takeRekey().catch(() => {});
      return true;
    })().finally(() => { following = null; });
    return following;
  }
  // ---------- Rekey (m6 §5): a device without the account key asks a device that has it ----------
  async function askRekey() {
    if (!linked || keyBox || !me) return;
    const view = await api(`/api/devices/${me.username}`);
    if (view.identity?.sign !== linked.identity.sign) return; // Follow the account's chain first.
    if ((await ownMeta(view))?.via === 'code') return; // Unlocks with the passphrase (§2).
    const request = await keysCore(linked.instance)({ cmd: 'rekeyRequest', userId: me.id, deviceId: linked.deviceId, platform: 'web' });
    await api('/api/devices/rekey', 'PUT', { platform: 'web', eph: request.eph, leafSigKey: request.leafSigKey, signature: request.signature });
  }
  /** The answer, if there is one yet (a request the server lost is asked again): this browser then holds the key. */
  async function takeRekey() {
    if (!linked || keyBox || !me) return;
    let mine;
    try { mine = await api('/api/devices/rekey/mine'); } catch (error) { if (error.status === 404) await askRekey(); return; }
    if (!mine.box) return;
    const run = keysCore(linked.instance);
    const opened = await run({ cmd: 'rekeyOpen', userId: me.id, deviceId: linked.deviceId, platform: 'web', box: mine.box });
    const accountKey = await run({ cmd: 'exportAccountKey', userId: me.id }), secrets = Devices.parseAccountKey(Devices.unb64(accountKey), me.id);
    const held = window.Signal.box(window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${me.id}`));
    try { await held.adoptIdentity(secrets, linked.identity); } finally { secrets.signSeed.fill(0); secrets.dhSecret.fill(0); }
    if (opened?.backupKeys && opened.backupKeys.epoch >= (readJson(`backup-keys-v1:${me.id}`, null)?.epoch || 0)) writeJson(`backup-keys-v1:${me.id}`, opened.backupKeys);
    linked = { ...linked, full: true }; keyBox = held;
    writeJson(`linked-store-v1:${me.id}`, linked);
    await window.Groups.recertifyAll(linked.identity.sign); // The certificate in the answer reaches every group.
    await api('/api/devices/rekey', 'DELETE');
    deviceNotice = 'This browser can unlock your account again.'; renderDevices();
  }
  /**
   * A device holding the key answers waiting devices (§5 step 2), only for a device our verified signed list names,
   * not linked by short code, not revoked and not this one; the core then checks the request's leaf signature and
   * that a group we hold already contains exactly that leaf.
   */
  async function answerRekeys() {
    const holder = signer();
    if (!holder || !me || !window.Groups?.enabled()) return;
    const { requests } = await api('/api/devices/rekey');
    if (!requests.length || !await holder.exportable()) return; // A legacy key answers once it has been updated.
    await coreHoldsKey();
    const own = (await holder.identity()).pub, self = (await localDevice()).deviceId, view = await api(`/api/devices/${me.username}`);
    const owned = await Devices.ownDevices({ userId: me.id, aikSign: own.sign, view, pin: readPins()[me.id], metaKey: await deviceMetaKey() });
    for (const request of requests) {
      const entry = owned?.devices.find(device => device.deviceId === request.deviceId), platform = Devices.recertPlatform(owned, request.deviceId, self);
      if (!platform || entry.described?.via === 'code' || view.devices.find(row => row.id === request.deviceId)?.state !== 'listed') continue;
      const sealed = await window.Groups.rekeyAnswer({ ...request, platform, backupKeys: readJson(`backup-keys-v1:${me.id}`, null) }).catch(() => null); // 'auth': not proven; it asks again later.
      if (sealed) await api(`/api/devices/rekey/${request.deviceId}`, 'PUT', { box: sealed });
    }
  }
  /**
   * Pre-M6 companions (m6 §7) still ask for a certificate after a rotation (m5 §5.2.2): a device holding the key
   * certifies each waiting one's leaf under our key, but only a (device, leaf key) a group we hold
   * already contains (mlsLeafKnown): the server's word about which key is whose counts for nothing.
   */
  async function answerRecerts() {
    const holder = signer();
    if (!holder || !window.Groups?.enabled()) return;
    const { requests } = await api('/api/devices/recert');
    if (!requests.length) return;
    const own = (await holder.identity()).pub, self = (await localDevice()).deviceId;
    // Only a device our verified signed list still names (a dropped one may keep a leaf until it is removed), never
    // this one, with the platform its sealed label gives (not the server's request).
    const owned = await Devices.ownDevices({ userId: me.id, aikSign: own.sign, view: await api(`/api/devices/${me.username}`), pin: readPins()[me.id], metaKey: await deviceMetaKey() });
    for (const { deviceId, leafSigKey } of requests) {
      const platform = Devices.recertPlatform(owned, deviceId, self);
      if (!platform || !await window.Groups.leafKnown(deviceId, leafSigKey).catch(() => false)) continue; // Asks again later.
      const issuedAt = Date.now(), bytes = Devices.mlsCertBytes(me.id, deviceId, platform, leafSigKey, own.sign, issuedAt);
      await api(`/api/devices/recert/${deviceId}`, 'PUT', { cert: Devices.mlsCertJson(me.id, deviceId, platform, leafSigKey, own.sign, issuedAt, await signWithIdentity(bytes)) });
    }
  }
  const platformName = platform => ({ web: 'Web browser', ios: 'iPhone app', android: 'Android app', macos: 'Mac app', windows: 'Windows app', linux: 'Linux app' })[platform] || 'Device';
  // ---------- The account key and its backup (docs/m6-account-key.md §1, §3, §4) ----------
  /** The account key as AccountKey bytes (base64url), exported from this browser's key store. */
  async function accountKeyB64() {
    if (signer() && !await signer().exportable()) {
      if (!await upgradeKey()) throw new Error('This browser’s key needs updating before it can move to another device.');
    }
    const holder = signer(), secrets = holder && await holder.exportIdentity();
    if (!secrets) throw new Error('This device can’t unlock your account.');
    try { return Devices.b64(Devices.accountKeyBytes(me.id, secrets.signSeed, secrets.dhSecret)); } finally { secrets.signSeed.fill(0); secrets.dhSecret.fill(0); }
  }
  // The chatcore store the account-key commands run in: this browser's group store (a pending browser makes it now).
  const groupInstance = (deviceId, aikSign) => {
    const kept = readJson(`group-instance-v1:${me.id}`, null); // Kept across a rotation by this device (groups.js reads the same).
    return linked?.instance || window.Groups?.instance?.() || (kept?.aik === aikSign && kept.instance) || `${me.id}-${deviceId}-${aikSign.slice(0, 12)}`;
  };
  const keysCore = instance => window.Core.groupStore(me.id, instance);
  /** The account's safety-number fingerprint (as group reviews show it): 12 groups of 5 digits of SHA-256(dh|sign). */
  async function fingerprint(identity) {
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${identity.dh}|${identity.sign}`)));
    return Array.from({ length: 12 }, (_, at) => String(bytes[2 * at] * 256 + bytes[2 * at + 1]).padStart(5, '0')).join(' ');
  }
  /** The served backup record, only if the account's published key signed it (§4 step 1). Never the server's word. */
  // Reads are rate-limited and each one notifies the account's devices: the last record read here is kept (it is no
  // secret: the server holds it) and used again, checked again, while the owner view still names its epoch.
  async function verifiedRecord(published) {
    const fresh = await api(`/api/devices/${me.username}`).catch(() => null), kept = readJson(`backup-record-v1:${me.id}`, null);
    const record = kept && fresh?.backup?.epoch === kept.epoch ? kept : await api('/api/backup');
    if (record?.aikSign !== published.sign || !await Devices.verifyBytes(published.sign, Devices.backupKeysBytes(record), record.signature)) throw new Error('The backup on the server isn’t signed by your account. Nothing was changed.');
    const seen = readJson(`backup-keys-v1:${me.id}`, null)?.epoch || 0;
    if (record.epoch < seen) throw new Error('The backup on the server is older than one this device has seen. Nothing was changed.');
    writeJson(`backup-record-v1:${me.id}`, record);
    return record;
  }
  let backupExists = false;
  /** Unlocks this browser with the passphrase or the recovery words (§4): a pending browser, or a code-linked one (§2). */
  async function restoreWith(kind) {
    const view = await api(`/api/devices/${me.username}`), published = view.identity;
    if (!published) throw new Error('Your account has no published key yet.');
    const device = await localDevice(), instance = groupInstance(device.deviceId, published.sign);
    let record = null;
    const done = await window.Linking.restore(kind, async secret => {
      record ||= await verifiedRecord(published);
      let opened;
      try { opened = await keysCore(instance)({ cmd: 'backupOpen', userId: me.id, record, published, ...(kind === 'words' ? { words: secret } : { passphrase: secret }) }); }
      catch (error) {
        if (error.code === 'auth') throw new Error(kind === 'words' ? 'Those words don’t open your backup.' : 'That passphrase doesn’t open your backup.');
        if (error.code === 'invalid' && kind === 'words') throw new Error('Check the words: one isn’t a recovery word, or one is missing.');
        throw error;
      }
      await becomeFull({ ...opened, published, instance, device });
      return fingerprint(published);
    });
    if (done) location.reload();
  }
  /**
   * This browser now holds the account key (a restore, or a code-linked browser unlocking): kept in its key store
   * (signing only: the 1:1 inbox stays where it is, §2) and in its group store; a browser new to the account certifies
   * its own MLS leaf and publishes the next list naming itself.
   */
  async function becomeFull({ accountKey, backupKeys, published, instance, device }) {
    const run = keysCore(instance), secrets = Devices.parseAccountKey(Devices.unb64(accountKey), me.id);
    box = null; // A pending browser's own unpublished keys: never published now.
    const held = window.Signal.box(window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${me.id}`));
    try { await held.adoptIdentity(secrets, published); } finally { secrets.signSeed.fill(0); secrets.dhSecret.fill(0); }
    await run({ cmd: 'importAccountKey', userId: me.id, key: accountKey, published });
    if (backupKeys && backupKeys.epoch >= (readJson(`backup-keys-v1:${me.id}`, null)?.epoch || 0)) writeJson(`backup-keys-v1:${me.id}`, backupKeys);
    if (!linked) {
      const leaf = await run({ cmd: 'mlsDeviceLeaf' }), issuedAt = Date.now(), bytes = Devices.mlsCertBytes(me.id, device.deviceId, 'web', leaf, published.sign, issuedAt);
      await run({ cmd: 'mlsSetDeviceCert', cert: Devices.mlsCertJson(me.id, device.deviceId, 'web', leaf, published.sign, issuedAt, Devices.b64(await held.sign(bytes))), aik: published.sign });
      try { localStorage.setItem(`mls-cert-v1:${instance}`, '1'); localStorage.setItem(`mls-cert-aik-v1:${instance}`, published.sign); } catch {}
    }
    linked = { deviceId: device.deviceId, instance, identity: { dh: published.dh, sign: published.sign }, full: true }; keyBox = held; inactive = false;
    writeJson(`linked-store-v1:${me.id}`, linked);
    await syncDevicesNow(); // The next list names this browser (and, for a code-linked one, no longer as such).
  }
  /** Settings → Devices → Account backup: what exists and what this device may do. */
  function renderBackup() {
    const full = holdsKey(), state = deviceView?.backup ?? null, changed = backupExists !== Boolean(state);
    backupExists = Boolean(state);
    say('backup-state', !deviceView ? 'Checking…' : state ? `On. Last changed ${new Date(state.updatedAt).toLocaleString()}.` : 'Off. Turn on account backup so a lost device can’t lock you out.');
    $('backup-on').hidden = !full || Boolean(state);
    for (const id of ['backup-change-pass', 'backup-new-words', 'backup-off']) $(id).hidden = !full || !state;
    $('device-banner-nobackup').hidden = backupExists;
    // §6.5: a reset asked for without the passphrase waits a week; the account's listed devices may cancel it.
    const reset = deviceView?.reset, listedHere = deviceView?.devices?.find(row => row.current)?.state === 'listed';
    $('reset-cancel').hidden = !reset || !listedHere;
    if (reset && listedHere) deviceWarning = `Someone asked to reset your account key from ${platformName(reset.requestedBy?.platform)} on ${new Date(reset.at).toLocaleString()}. If this wasn’t you, cancel it.`;
    else if (reset && !holdsKey()) say('chats-status', Date.now() < reset.executeAfter ? `Your account key will be reset on ${new Date(reset.executeAfter).toLocaleString()} unless one of your devices cancels it.` : 'The week is up: choose “I can’t do any of these” again to start over here.');
    if (changed && me) window.DeviceLink?.attach(linkContext()); // The restore buttons follow whether a backup exists.
  }
  /** Turning the backup on, or changing it (§3.4): every change needs the current passphrase or recovery key. */
  async function changeBackup(mode) {
    const own = (await signer().identity()).pub, device = await localDevice(), run = keysCore(groupInstance(device.deviceId, own.sign));
    const local = readJson(`backup-keys-v1:${me.id}`, null);
    const prove = async (record, current) => (await run({ cmd: 'backupProve', record, ...(current.trim().split(/\s+/).length === 24 ? { words: current } : { passphrase: current }) })).proof;
    const done = await window.Linking.backupFlow(mode, {
      generate: () => run({ cmd: 'passphraseGenerate' }),
      async prepare({ passphrase, current }) {
        const accountKey = mode === 'off' ? null : await accountKeyB64();
        let out, proof, record;
        if (mode === 'on') out = await run({ cmd: 'backupCreate', userId: me.id, passphrase, accountKey, now: Date.now() });
        else {
          record = await verifiedRecord(own);
          proof = await prove(record, current).catch(error => { throw error.code === 'auth' || error.code === 'invalid' ? new Error('That isn’t your current passphrase or recovery key.') : error; });
          if (mode === 'off') return { publish: async () => { await api('/api/backup', 'DELETE', { proof }); localStorage.removeItem(`backup-keys-v1:${me.id}`); } };
          if (!local) throw new Error('This device doesn’t have your backup keys yet. Unlock it with your passphrase first.');
          out = await run({ cmd: 'backupReseal', userId: me.id, record, backupKeys: local, accountKey, ...(mode === 'pass' ? { passphrase } : { newRecovery: true }) });
        }
        return {
          words: out.words,
          async publish() {
            const signed = { ...out.record, signature: await signWithIdentity(Devices.backupKeysBytes(out.record)) };
            await api('/api/backup', 'PUT', { ...signed, ...(proof ? { proof } : {}), ...(out.passProof ? { passProof: out.passProof } : {}), ...(out.recoveryProof ? { recoveryProof: out.recoveryProof } : {}) });
            writeJson(`backup-keys-v1:${me.id}`, out.backupKeys);
          },
        };
      },
    });
    if (!done) return;
    deviceNotice = { on: 'Account backup is on. You can now use your account on a new device with your passphrase or recovery key.', pass: 'Your passphrase was changed.', words: 'Your new recovery key is saved. The old one no longer works.', off: 'Account backup is off.' }[mode];
    deviceView = await api(`/api/devices/${me.username}`); renderDevices();
  }
  $('backup-on').onclick = () => changeBackup('on').catch(error => { deviceWarning = error.message; renderDevices(); });
  $('backup-change-pass').onclick = () => changeBackup('pass').catch(error => { deviceWarning = error.message; renderDevices(); });
  $('backup-new-words').onclick = () => changeBackup('words').catch(error => { deviceWarning = error.message; renderDevices(); });
  $('device-finish').onclick = async () => {
    try { if (await finishRemoval(unfinished.map(value => value.id), { title: `${unfinished.map(deviceLabel).join(', ')} was removed. Change your account key now?` })) location.reload(); }
    catch (error) { deviceWarning = error.message; renderDevices(); }
  };
  $('reset-cancel').onclick = () => api('/api/keys/reset', 'DELETE').then(async () => { deviceWarning = ''; deviceNotice = 'The reset was cancelled.'; deviceView = await api(`/api/devices/${me.username}`); renderDevices(); }, error => { deviceWarning = error.message; renderDevices(); });
  $('backup-off').onclick = () => changeBackup('off').catch(error => { deviceWarning = error.message; renderDevices(); });

  /** This browser's own sealed list entry ({ label, platform, via? }), with the label key it holds or derives. */
  async function ownMeta(view) {
    const id = (await localDevice()).deviceId, entry = view?.list?.devices.find(device => device.deviceId === id);
    const stored = localStorage.getItem(`device-meta-key-v1:${me.id}`);
    const key = holdsKey() ? await deviceMetaKey().catch(() => null) : stored ? await Devices.metaKeyFromBytes(Devices.unb64(stored)).catch(() => null) : null;
    return key && entry ? Devices.openMeta(key, me.id, id, entry.meta) : null;
  }
  async function renderDevices() {
    const list = $('device-list');
    if (!list || !me) return;
    say('devices-status', deviceWarning || deviceNotice);
    // A snapshot: sign-out (or a refresh) may replace deviceView while this awaits keys.
    const view = deviceView, account = me, full = holdsKey();
    renderBackup();
    $('device-finish').hidden = !full || !unfinished.length;
    if (!view?.devices) { list.replaceChildren(); return; }
    // The labels are sealed under a key derived from the account key: a device holding it derives it, a linked one got it.
    const linkedKey = linked ? localStorage.getItem(`device-meta-key-v1:${me.id}`) : null;
    const key = full && backendName !== 'wasm' ? await deviceMetaKey().catch(() => null) : linkedKey ? await Devices.metaKeyFromBytes(Devices.unb64(linkedKey)).catch(() => null) : null;
    const rows = [];
    for (const row of view.devices) {
      const item = document.createElement('li'); item.className = 'device-row'; item.dataset.deviceId = row.id; item.dataset.state = row.state;
      const name = document.createElement('strong');
      const entry = view.list?.devices.find(device => device.deviceId === row.id);
      const described = key && entry ? await Devices.openMeta(key, account.id, row.id, entry.meta) : null;
      name.textContent = described?.label || platformName(described?.platform || row.platform);
      // m6 §7: no "primary" any more. Whether a device holds the key is shown for this one only (others can't be known).
      const standing = row.state === 'revoked' ? 'Removed' : row.state === 'pending' ? 'Signed in · not set up' : row.current ? (full ? 'Can unlock your account' : 'Waiting for keys') : described?.via === 'code' ? 'Linked by code' : null;
      const meta = document.createElement('small');
      meta.textContent = [row.current ? 'This browser' : null, standing, row.lastSeenAt ? `Last seen ${new Date(row.lastSeenAt).toLocaleString()}` : null].filter(Boolean).join(' · ');
      item.append(name, meta);
      const button = (text, className, run, label = `${text} ${name.textContent}`) => {
        const element = document.createElement('button'); element.type = 'button'; element.className = className; element.textContent = text;
        element.setAttribute('aria-label', label);
        element.onclick = () => run().catch(error => { deviceWarning = `${error.message || error}`; renderDevices(); });
        item.append(element);
      };
      if (row.current && linked && !full && backupExists) button('Enter passphrase', 'link device-unlock', () => restoreWith('pass'), 'Enter your passphrase to unlock this browser');
      if (row.current && linked) button('Unlink this browser', 'danger-text device-remove', () => revokeDevice(row), 'Unlink this browser');
      if (!row.current && row.state !== 'revoked') {
        // A device holding the account key removes another for good (and, once that one held the key, replaces the
        // key, m6 §6.2); any other device only cuts it off, and a device holding the key finishes it.
        if (full) button(row.state === 'listed' ? 'Revoke' : 'Remove', 'danger-text device-remove', () => removeDevice({ ...row, label: name.textContent }));
        else button('Revoke', 'danger-text device-remove', () => revokeDevice(row));
      }
      rows.push(item);
    }
    if (deviceView !== view) return; // Superseded while drawing.
    list.replaceChildren(...rows);
  }
  window.addEventListener('linking-flows', () => renderDevices());
  /** Revokes one of the account's devices from this (non-primary) device: the server cuts it off; the primary re-signs the list. */
  async function revokeDevice(row) {
    // m6 §6.3: with a backup, cutting off another device takes the passphrase (unlinking yourself doesn't).
    if (backupExists && !row.current) {
      const done = await window.Linking.confirmRotation({
        title: `Remove ${deviceLabel(row)}?`, action: 'Remove', proof: true,
        text: 'The device is signed out and can’t read new messages. A device that can unlock your account then changes your account key.',
        run: async secret => api(`/api/devices/${row.id}/revoke`, 'POST', { proof: await proveSecret(secret) }),
      });
      if (!done) return;
    } else await api(`/api/devices/${row.id}/revoke`, 'POST', {});
    if (row.current) { try { localStorage.removeItem(`linked-store-v1:${me.id}`); } catch {} signedOut('This browser was unlinked. Messages already here stay in it.'); return; }
    deviceView = await api(`/api/devices/${me.username}`);
    deviceNotice = 'Device revoked: it was signed out and can no longer receive messages. A device that can unlock your account finishes removing it.';
    renderDevices();
  }
  /**
   * From a device holding the account key (m6 §6.2): a pending device is simply removed; a listed one could unlock the
   * account, so removing it replaces the key, after the user confirms (with the passphrase when a backup exists).
   */
  async function removeDevice(row) {
    if (row.state !== 'listed') {
      await api(`/api/devices/${row.id}`, 'DELETE', {});
      deviceView = await api(`/api/devices/${me.username}`);
      deviceNotice = 'Device removed: it was signed out and can no longer receive messages.'; renderDevices();
      return;
    }
    const done = await finishRemoval([row.id], { title: `Remove ${deviceLabel(row)} and change your account key?`, revoke: true });
    if (done) {
      if (done.changePass) await changeBackup('pass').catch(error => { deviceWarning = error.message; });
      deviceNotice = 'Device removed, and your account has a new key. Your other devices pick it up by themselves.';
      setTimeout(() => location.reload(), 300);
    }
  }
  const deviceLabel = row => row?.label || platformName(row?.platform);
  /**
   * Confirms, proves the passphrase if a backup exists, revokes (`revoke`) and replaces the key without `ids`. Resolves
   * true when done; the caller reloads (this browser is then the inbox device under the new key).
   */
  async function finishRemoval(ids, { title, text, action, revoke = false }) {
    return window.Linking.confirmRotation({
      title, text, action, proof: backupExists,
      run: async secret => {
        const own = (await signer().identity()).pub;
        let proof;
        if (backupExists) proof = await proveSecret(secret);
        if (revoke) for (const id of ids) await api(`/api/devices/${id}/revoke`, 'POST', proof ? { proof } : {});
        await rotate({ removed: ids, proof });
      },
    });
  }
  /** The proof (§3.5) that the user knows the passphrase (or, as exactly 24 words, the recovery key), from the served record. */
  async function proveSecret(secret) {
    const published = (await api(`/api/devices/${me.username}`)).identity, record = await verifiedRecord(published);
    const words = secret.trim().split(/\s+/).length === 24, instance = groupInstance((await localDevice()).deviceId, published.sign);
    try { return (await keysCore(instance)({ cmd: 'backupProve', record, ...(words ? { words: secret } : { passphrase: secret }) })).proof; }
    catch (error) { throw error.code === 'auth' || error.code === 'invalid' ? new Error('That isn’t your passphrase or recovery key.') : error; }
  }
  /** m6 §7: a legacy (non-extractable) key can't move; it is replaced once, the first time it must. */
  const upgradeKey = () => finishRemoval([], { title: 'Update this browser’s account key?', action: 'Update key', text: 'This browser’s key is from before keys could move between your devices. It gets a new one now; your other devices pick it up by themselves and your contacts keep their verification.' });
  /**
   * A device another session revoked (any device may cut one off, m5 §4) while our verified list still names it: only a
   * device holding the key can finish it, by replacing the key, and only once the user agrees (§6.2).
   */
  let unfinished = [];
  async function finishRemovals() {
    const holder = signer();
    if (!holder || !me) return;
    const own = (await holder.identity()).pub, view = await api(`/api/devices/${me.username}`);
    if (view.identity?.sign !== own.sign) return;
    const owned = await Devices.ownDevices({ userId: me.id, aikSign: own.sign, view, pin: readPins()[me.id], metaKey: await deviceMetaKey().catch(() => null) });
    // Removed devices aren't served as rows at all: our list naming one the server no longer has is one to finish.
    unfinished = (owned?.devices || []).filter(device => !['listed', 'pending'].includes(view.devices.find(row => row.id === device.deviceId)?.state))
      .map(device => ({ id: device.deviceId, label: device.described?.label, platform: device.described?.platform }));
    if (unfinished.length) { deviceWarning = `${unfinished.map(deviceLabel).join(', ')} was removed. Change your account key now?`; deviceView = view; renderDevices(); }
  }
  /**
   * Replaces the account key (§6.2): the old key signs a record handing the account to a new one minted here; this
   * browser takes messaging over and publishes list version 1 naming every live device except `removed`; the backup
   * is re-sealed to the backup keys held here. Other devices follow the record and rekey.
   */
  async function rotate({ removed = [], proof } = {}) {
    const cur = signer(), old = (await cur.identity()).pub, self = (await localDevice()).deviceId;
    const view = await api(`/api/devices/${me.username}`);
    const owned = await Devices.ownDevices({ userId: me.id, aikSign: old.sign, view, pin: readPins()[me.id], metaKey: await deviceMetaKey() });
    if (!owned) throw new Error('The device list on the server isn’t one your devices signed. Nothing changed.');
    await coreHoldsKey(); // The group store swaps its key with ours (rotateIdentity needs it to hold the old one).
    const record0 = backupExists ? await verifiedRecord(old) : null, local = readJson(`backup-keys-v1:${me.id}`, null);
    const next = await window.Signal.generateIdentity(); // In memory until the server holds the record.
    const record = { v: 1, userId: me.id, oldSign: old.sign, newSign: next.pub.sign, newDh: next.pub.dh, at: Date.now() };
    const signature = Devices.b64(await cur.sign(Devices.successionBytes(record)));
    const newMeta = await Devices.deviceMetaKey(me.id, bytes => window.Signal.signWith(next, bytes));
    const keep = [];
    for (const device of owned.devices) {
      const row = view.devices.find(value => value.id === device.deviceId);
      if (device.deviceId === self || removed.includes(device.deviceId) || row?.state !== 'listed') continue;
      const platform = device.described?.platform || row.platform;
      // A short-code device stays marked as one under the new key: it unlocks with the passphrase, never by rekey.
      keep.push({ deviceId: device.deviceId, addedAt: device.addedAt, meta: await Devices.sealMeta(newMeta, me.id, device.deviceId, { label: device.described?.label || platformName(platform), platform, ...(device.described?.via ? { via: device.described.via } : {}) }) });
    }
    // Its leaves go from our groups after the key change (verifiedOwnDevices counts them as dropped).
    const gone = owned.devices.map(device => device.deviceId).filter(id => id !== self && !keep.some(device => device.deviceId === id));
    writeJson(`removed-devices-v1:${me.id}`, [...new Set([...readJson(`removed-devices-v1:${me.id}`, []), ...gone])]);
    // Two steps (the core keeps `rotation:pending`, which survives a closed tab): prepared, then published, then held.
    const secrets = await window.Signal.exportIdentity(next);
    const accountKey = Devices.b64(Devices.accountKeyBytes(me.id, secrets.signSeed, secrets.dhSecret));
    secrets.signSeed.fill(0); secrets.dhSecret.fill(0);
    const instance = groupInstance(self, old.sign), run = keysCore(instance);
    await run({ cmd: 'rotateIdentity', userId: me.id, key: accountKey, record, signature, at: record.at, commit: false });
    writeJson(`new-chain-v1:${me.id}`, { aik: record.newSign, keep });
    try { await api('/api/devices/succession', 'PUT', { record, signature, ...(proof ? { proof } : {}) }); }
    catch (error) {
      // Refused: nothing changed anywhere. No answer at all (the server may have taken it): kept, and settled on the next start.
      if (error.status) { await run({ cmd: 'rotationDrop' }).catch(() => {}); try { localStorage.removeItem(`new-chain-v1:${me.id}`); } catch {} }
      throw error;
    }
    await finishRotation(run, instance, { record, backup: record0 && local ? { record: record0, keys: local } : null });
  }
  /**
   * The server holds the record: the core takes the new key (committing the prepared rotation), this browser's key store
   * gets it from there, its own certificate moves to the new key, it takes messaging over (list v1 goes up from the
   * marker) and re-seals the backup. Also the resume after a restart (resumeRotation).
   */
  async function finishRotation(run, instance, { record, backup }) {
    await run({ cmd: 'rotateIdentity', userId: me.id });
    const accountKey = await run({ cmd: 'exportAccountKey', userId: me.id }), secrets = Devices.parseAccountKey(Devices.unb64(accountKey), me.id);
    const held = window.Signal.box(window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${me.id}`)), self = (await localDevice()).deviceId;
    try { await held.adoptIdentity(secrets, { dh: record.newDh, sign: record.newSign }); } finally { secrets.signSeed.fill(0); secrets.dhSecret.fill(0); }
    writeJson(`group-instance-v1:${me.id}`, { aik: record.newSign, instance });
    // This browser's own certificate under the new key; every group then gets a self-update carrying it.
    const leaf = await run({ cmd: 'mlsDeviceLeaf' }), issuedAt = Date.now();
    await run({ cmd: 'mlsSetDeviceCert', cert: Devices.mlsCertJson(me.id, self, 'web', leaf, record.newSign, issuedAt, Devices.b64(await held.sign(Devices.mlsCertBytes(me.id, self, 'web', leaf, record.newSign, issuedAt)))), aik: record.newSign });
    try { localStorage.setItem(`mls-cert-v1:${instance}`, '1'); localStorage.setItem(`mls-recertify-v1:${instance}`, '1'); localStorage.removeItem(`linked-store-v1:${me.id}`); } catch {}
    linked = null; keyBox = null; box = held; backendName = 'signal'; inactive = false; coreKeyed = Promise.resolve();
    window.Core?.setBackend(me.id, 'signal');
    // The old key's pin ends here; list v1 under the new key carries the devices the marker (bound to this key) names.
    const pins = readPins(); delete pins[me.id]; writePins(pins);
    newChain = Devices.chainMarker(readJson(`new-chain-v1:${me.id}`, null), record.newSign, undefined);
    await publishKeys(true); // The new key takes the inbox here, and list v1 goes up (from the marker, bound to this key).
    // The backup follows the key: re-sealed to the backup keys held here (the one proof-free re-seal, §3.5).
    if (backup) {
      const out = await run({ cmd: 'backupReseal', userId: me.id, record: backup.record, backupKeys: backup.keys, accountKey });
      await api('/api/backup', 'PUT', { ...out.record, signature: Devices.b64(await held.sign(Devices.backupKeysBytes(out.record))) });
      writeJson(`backup-keys-v1:${me.id}`, out.backupKeys);
    }
  }
  /**
   * On start: a rotation prepared here before the tab closed. Finished if the server took its record (or already serves
   * its key), dropped if the server never did. Resolves true when this browser now holds the new key.
   */
  async function resumeRotation(userId) {
    const stored = linkedStore(userId);
    if (stored && !stored.full) return false;
    // Only a browser whose key store already holds a key (a check that mints nothing: the wasm core keeps its own).
    if (!stored && !await window.Core?.hasKeys(userId, 'signal').catch(() => false)) return false;
    const held = window.Signal.box(window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${userId}`));
    const pub = (await held.identity()).pub, instance = stored?.instance || groupInstance((await localDevice()).deviceId, pub.sign), run = keysCore(instance);
    const pending = await run({ cmd: 'rotationPending' }).catch(() => null);
    if (!pending) return false;
    const view = await api(`/api/devices/${me.username}`), newSign = pending.identity.sign;
    // Committed only if the server publishes that key already, or its newest record names it and still authorizes it;
    // anything else (never taken, or replaced by a later record) is dropped: the old key stays.
    const open = view.rotation?.newSign === newSign && view.rotation.state === 'open';
    if (view.identity?.sign !== newSign && !open) { await run({ cmd: 'rotationDrop' }); try { localStorage.removeItem(`new-chain-v1:${me.id}`); } catch {} return false; }
    const { signature, ...record } = pending.record, local = readJson(`backup-keys-v1:${me.id}`, null);
    const record0 = view.backup && local ? await verifiedRecord({ sign: record.oldSign }).catch(() => null) : null;
    await finishRotation(run, instance, { record, backup: record0?.aikSign === record.oldSign ? { record: record0, keys: local } : null });
    return true;
  }
  /** The group store holds the account key too (m6 §1: the core answers rekeys); once per session. */
  let coreKeyed = null;
  function coreHoldsKey() {
    coreKeyed ||= (async () => {
      const own = (await signer().identity()).pub;
      await keysCore(groupInstance((await localDevice()).deviceId, own.sign))({ cmd: 'importAccountKey', userId: me.id, key: await accountKeyB64(), published: own });
    })().catch(error => { coreKeyed = null; throw error; });
    return coreKeyed;
  }
  /** The `backup` frame (§3.5): a read elsewhere is shown; a newer record means our backup keys are stale until a rekey. */
  function onBackupFrame(message) {
    if (message.read) { deviceNotice = 'Your backup was opened on a new device.'; say('chats-status', deviceNotice); }
    api(`/api/devices/${me.username}`).then(view => { deviceView = view; renderDevices(); }).catch(() => {});
  }
  /** A contact's served list, checked against the identity key we pinned for them (never the server's word). */
  async function verifyContactDevices(contact) {
    const peer = await box?.peer(contact.id);
    if (!peer?.identity?.sign || !Devices) return null;
    const view = await api(`/api/devices/${contact.username}`);
    if (!view.list) return { ok: false, reason: 'none' };
    const pins = readPins(), pin = pins[contact.id];
    const check = await Devices.verifyView({ userId: contact.id, aikSign: peer.identity.sign, list: view.list, signature: view.signature, certs: view.certs, pin });
    if (check.ok) { pins[contact.id] = check.pin; writePins(pins); }
    return { ...check, count: view.list.devices.length, version: view.list.version };
  }
  async function rememberFlag(id) {
    flagged.add(id);
    await flagged.store?.put('flagged', [...flagged].slice(-500));
  }

  // ---------- Presence and mailbox stream ----------
  function connectEvents() {
    if (!me || events) return;
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/events`);
    events = socket;
    socket.onopen = () => { retry = 0; };
    socket.onmessage = event => {
      let message; try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === 'hello') {
        for (const contact of contacts) contact.online = message.online.includes(contact.id);
        render(); ready.then(ok => { if (ok) { publishKeys().catch(() => {}); flushOutgoing(); } });
      }
      else if (message.type === 'presence') presence(message.id, message.online);
      else if (message.type === 'contacts') loadContacts();
      else if (message.type === 'incoming') incoming(message);
      else if (message.type === 'envelope') inbound = inbound.then(() => receiveEnvelope(socket, message)).catch(() => {});
      else if (['group', 'welcome', 'channel', 'keypackages', 'ephemeral'].includes(message.type)) window.Groups?.frame(message);
      else if (message.type === 'devices' && message.id === me?.id && linked) followOwnSuccession().then(takeRekey).then(() => window.Groups?.devicesChanged()).then(() => keyBox && finishRemovals()).catch(() => {});
      else if (message.type === 'rekey' && message.id === me?.id) (message.answered ? takeRekey() : answerRekeys()).catch(() => {});
      else if (message.type === 'recert' && message.id === me?.id && !message.answered) answerRecerts().catch(() => {});
      else if (message.type === 'backup' && message.id === me?.id) onBackupFrame(message);
      else if (message.type === 'reset' && message.id === me?.id) { if (message.cancelled) deviceWarning = ''; api(`/api/devices/${me.username}`).then(view => { deviceView = view; renderDevices(); if (!message.cancelled) say('chats-status', deviceWarning); }).catch(() => {}); }
      // The inbox device: another device may have replaced the account key (its list v1 comes after the keys), so it
      // follows first, live; otherwise the usual list upkeep.
      else if (message.type === 'devices' && message.id === me?.id) followLive().then(followed => { if (followed) return; if (!inactive) return syncDevices().then(() => window.Groups?.devicesChanged()); return api(`/api/devices/${me.username}`).then(view => { deviceView = view; renderDevices(); }); }).catch(() => {});
      else if (message.type === 'devices') { const contact = contactById(message.id); if (contact) verifyContactDevices(contact).catch(() => {}); }
      // Another device took messaging over: by replacing the account key (follow it), or a pre-M6 take-over.
      else if (message.type === 'keys' && message.id === me?.id) followLive().then(followed => followed || publishKeys()).catch(() => {});
      else if (message.type === 'keys') checkIdentity(message.id).then(flushOutgoing).catch(() => {});
      else if (message.type === 'ended' && ringing?.roomId === message.roomId) { const ring = ringing; ringing = null; hideRing(); say('chats-status', `Missed ${ring.kind} call from ${ring.contact.username} · ${clock(Date.now())}`); }
    };
    socket.onclose = event => {
      if (events !== socket) return;
      events = null;
      if (event.code === 4401) { signedOut('Your session ended. Sign in again.'); return; }
      retryTimer = setTimeout(connectEvents, Math.min(1000 * 2 ** retry++, 15000));
    };
  }
  function presence(id, online) {
    const contact = contactById(id);
    if (!contact) return;
    contact.online = online; render();
  }

  // ---------- Receiving ----------
  const coded = (code, text) => Object.assign(new Error(text), { code });
  const attempts = new Map();
  /** True when an envelope carries an X3DH header (or can't be read): it would open a new session. */
  function startsSession(envelope) {
    try { return JSON.parse(atob(String(envelope).replace(/-/g, '+').replace(/_/g, '/'))).x !== undefined; } catch { return true; }
  }
  async function receiveEnvelope(socket, message) {
    if (!await ready || !box) return; // Unacknowledged: redelivered once this device can decrypt.
    if (inactive) return; // Meant for the active device: never decrypt-fail and acknowledge it away.
    const from = message.from, conversationId = await pairId(from.id), viewing = () => body.dataset.screen === 'conversation' && current?.id === from.id;
    // Ephemeral envelopes (typing) were never stored by the server: nothing to acknowledge, nothing to report.
    if (message.ephemeral === true) {
      // Live-only envelopes may only continue an existing session: an X3DH initial message here would claim a
      // prekey slot and pin an identity outside the stored path's warnings. Anything but typing is discarded unsaved.
      if (startsSession(message.envelope)) return;
      try {
        await box.decryptFrom(from.id, message.envelope, async (payload, info) => {
          if (window.ChatStore.checkPayload(payload) !== 'typing' || info.identity || info.identityChanged || (await box.peer(from.id))?.blocked) throw new Error('ignored');
          typing(from.id, payload);
        });
      } catch {}
      return;
    }
    let receipt = null, burned = false, rotated = false, failure = null, pointer = null;
    try {
      await box.decryptFrom(from.id, message.envelope, async (payload, info) => {
        const type = window.ChatStore.checkPayload(payload); // Shape only; message content is validated by ChatStore.receive.
        // Defence in depth only: the pinned identity in signal.js (peer:<user id>, never deleted by burn,
        // contact removal or forget) is the trust boundary, because a hostile server controls this lookup too.
        // A mismatch with the published key still catches a mislabelled `from` from an honest-but-buggy relay.
        if (info.identity) {
          // A lookup that fails for network reasons is retried; only a real mismatch is discarded.
          const published = await api(`/api/keys/${from.username}/identity`).then(result => result.identity, error => { throw coded(error.status === 403 ? 'mismatch' : 'storage', error.message); });
          if (published.dh !== info.identity.dh || published.sign !== info.identity.sign) throw coded('mismatch', 'Identity mismatch');
        }
        // Until the user accepts a changed security code, the new identity may deliver (flagged) messages
        // but may not burn history or mark our messages delivered.
        const untrusted = info.identityChanged || Boolean((await box.peer(from.id))?.blocked);
        if (untrusted && type !== 'message') return;
        try {
          if (type === 'rotate') {
            rotated = true;
            await window.ChatStore.note(conversationId, payload.id, `🔄 ${payload.reason === 'manual' ? 'Secure session reset' : 'Keys rotated on schedule'} by ${from.username}`);
            return { rotate: true }; // The box keeps only the peer's new session, in its own write.
          }
          else if (type === 'policy') rememberPeerRotation(from.id, payload.rotateEveryMs);
          // Reactions, edits and read receipts change an existing row in place: no new row, no delivery receipt.
          else if (type === 'react') await window.ChatStore.react(conversationId, payload.target, 'peer', payload.emoji, payload.on);
          else if (type === 'edit') await window.ChatStore.edit(conversationId, payload.target, 'peer', payload.text, Math.min(payload.editedAt, Date.now() + 300000));
          else if (type === 'read') { if (App.readReceipts) await window.ChatStore.markRead(conversationId, payload.ids, 'outgoing'); }
          else if (type === 'typing') typing(from.id, payload); // A typing hint that came through the mailbox: shown only if still fresh.
          else if (type === 'vote') await window.ChatStore.vote(conversationId, payload.poll, 'peer', payload.option); // A tally update: no row, no receipt.
          else if (type === 'mls-dm') { await window.ChatStore.note(conversationId, payload.id, 'Messages in this chat now use the new encryption.'); pointer = payload; }
          else if (payload.type === 'receipt') await window.ChatStore.setStatus(conversationId, payload.id, 'delivered');
          else if (payload.type === 'burn') { await window.ChatStore.removeConversation(conversationId); burned = true; }
          else if (await window.ChatStore.receive(conversationId, payload) === 'stored') {
            // Idempotent by message id: duplicates are neither shown, counted nor acknowledged twice.
            if (untrusted) await rememberFlag(payload.id.toLowerCase());
            if (!viewing()) unread[from.id] = (unread[from.id] || 0) + 1;
            receipt = payload.id;
            typing(from.id, null); // A message ends their typing.
          }
        } catch (error) { throw error.code ? error : coded('storage', error.message); }
      });
    } catch (error) { failure = error; }
    const tries = (attempts.get(message.id) || 0) + 1;
    const outcome = window.ChatStore.inboundDisposition(failure, tries);
    if (!outcome.ack) { attempts.set(message.id, tries); say('chats-status', 'Could not save an incoming message yet. Retrying…'); return; }
    attempts.delete(message.id);
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ack', id: message.id }));
    const notice = {
      'storage-full': `A message from ${from.username} was discarded: this device holds 2,000 messages. Clear some history to receive more.`,
      'conversation-full': `A message from ${from.username} was discarded: this conversation holds 500 incoming messages. Burn or clear it to receive more from them.`,
      invalid: `A message from ${from.username} had invalid content and was discarded.`,
      conflict: `A message from ${from.username} reused an earlier message's id with different text, and was discarded.`,
      mismatch: `A message from ${from.username} came from keys that are not their active ones, and was discarded. If they use more than one browser or device (for example Safari and the Home Screen app), ask them to use the one where messaging is active.`,
      'gave-up': `A message from ${from.username} could not be saved after several tries and was discarded.`,
      undecryptable: `A message from ${from.username} could not be decrypted and was discarded.`,
    }[outcome.notice];
    if (notice) { if (viewing()) App.chatStatus(notice); else say('chats-status', notice); }
    try { localStorage.setItem(`unread-v1:${me.id}`, JSON.stringify(unread)); } catch {}
    if (burned) {
      delete unread[from.id];
      if (viewing()) App.chatStatus(`${from.username} burned this conversation. It was deleted on this device.`);
      else say('chats-status', `${from.username} burned your conversation. It was deleted on this device.`);
    }
    // Our policy rides on the new session, which also lets the peer drop its old chains.
    if (rotated && !failure) tellPolicy(from).catch(() => {});
    if (viewing()) { App.refreshHistory(); updateBanner(); }
    render();
    if (receipt) sendControl(from, { v: 1, type: 'receipt', id: receipt }).catch(() => {});
    if (pointer && !failure) { const contact = contactById(from.id); if (contact) acceptPointer(contact, pointer).catch(() => {}); }
  }

  // ---------- Sending ----------
  const bundleFor = contact => () => api(`/api/keys/${contact.username}`);
  async function sendControl(contact, payload) {
    if (!box) throw new Error('Encrypted messaging is unavailable in this browser.');
    const envelope = await box.encryptTo(contact.id, payload, bundleFor(contact));
    await api('/api/messages', 'POST', { to: contact.username, envelope });
  }
  // ---------- 1:1 chats on MLS (docs/m5-linking.md §8) ----------
  // A moved chat keeps its pairId as the conversation; its transport is the DM group. Double Ratchet stays
  // receive-only for it (the server refuses sends after 60 days), and typing never uses it any more (§9).
  const movedKey = () => `dm-moved-v1:${me.id}`;
  const readMoved = () => readJson(movedKey(), {});
  /** The DM group of a moved chat, if this device holds it (a linked device that hasn't joined yet doesn't). */
  async function dmChannel(contact) {
    const channel = window.Groups?.dmChannelWith(contact.id) || null;
    if (!channel) return null;
    // A linked device never sees the pointer: the checked DM group it joined as our own device is the proof.
    if (linked) return channel;
    return readMoved()[await pairId(contact.id)]?.channel === channel ? channel : null;
  }
  async function markMoved(contact, channel) {
    const all = readMoved(); all[await pairId(contact.id)] = { channel, at: Date.now() }; writeJson(movedKey(), all);
  }
  /** Every payload to a contact goes here: the DM group once moved, otherwise the 1:1 session (never typing). */
  async function sendToContact(contact, payload) {
    const channel = await dmChannel(contact);
    if (channel) return window.Groups.sendDm(channel, payload);
    if (payload.type === 'typing') return; // Typing hints travel only in MLS groups now.
    return sendControl(contact, payload);
  }
  const tried = new Map();
  /**
   * §8.2: the first sender moves the chat, when both of us have a device that can (and this one holds the 1:1
   * session to send the pointer over). At most one try per contact every 10 minutes.
   */
  async function maybeMove(contact) {
    if (!box || linked || !window.Groups?.enabled() || readMoved()[await pairId(contact.id)] || Date.now() - (tried.get(contact.id) || 0) < 600000) return;
    if (await window.Core?.testFlag?.('dm-move-test') === 'off') return; // Test runs of the 1:1 protocol itself (loopback only).
    tried.set(contact.id, Date.now());
    const capability = await api(`/api/mls/capability/${encodeURIComponent(contact.username)}`).catch(() => null);
    if (!capability || capability.devices < 1 || capability.channel) return; // They can't yet, or they are already moving it.
    const channel = await window.Groups.createDm(contact).catch(() => null);
    if (!channel) return;
    const pointer = { v: 1, type: 'mls-dm', id: crypto.randomUUID(), channel, at: Date.now() };
    await sendControl(contact, pointer); // The last Double Ratchet message of this chat.
    await markMoved(contact, channel);
    await window.ChatStore.note(await pairId(contact.id), pointer.id, 'Messages in this chat now use the new encryption.').catch(() => {});
  }
  /**
   * §8.3: their pointer moves the chat only when the group is really our DM, chained to the pinned keys. The Welcome
   * may arrive after the pointer: joining a DM group retries at once (dmJoined), otherwise with backoff for 10 minutes.
   */
  const pointers = new Map();
  async function acceptPointer(contact, payload) {
    const deadline = Date.now() + 600000;
    pointers.set(payload.channel, { contact, payload });
    for (let wait = 1000; me && pointers.has(payload.channel) && Date.now() < deadline; wait = Math.min(wait * 2, 15000)) {
      if (await tryPointer(payload.channel)) return;
      await new Promise(resolve => { const timer = setTimeout(resolve, wait); pointers.get(payload.channel) && (pointers.get(payload.channel).wake = () => { clearTimeout(timer); resolve(); }); });
    }
    pointers.delete(payload.channel);
  }
  async function tryPointer(channel) {
    const pending = pointers.get(channel);
    if (!pending) return true;
    const info = await api(`/api/channels/${channel}`).catch(() => null);
    if (info && (info.kind !== 'dm' || info.peer?.id !== pending.contact.id)) { pointers.delete(channel); return true; } // Not our DM: ignore the pointer.
    if (!info?.member || !await window.Groups?.acceptDm(channel, pending.contact.id)) return false;
    pointers.delete(channel);
    await markMoved(pending.contact, channel); render();
    if (current?.id === pending.contact.id) App.refreshHistory();
    return true;
  }
  /** Encrypts and posts every queued outgoing message, oldest first, one contact at a time. */
  async function flushOutgoing() {
    if (!me || !await ready || (!box && !linked) || inactive) return;
    if (flushing) { flushAgain = true; return; }
    flushing = true; flushAgain = false; clearTimeout(flushTimer);
    let retryLater = false;
    try {
      const records = await window.ChatStore.list();
      for (const contact of contacts.filter(value => value.state === 'mutual')) {
        const conversationId = await pairId(contact.id);
        const queued = records.filter(value => value.conversationId === conversationId && value.direction === 'outgoing' && value.status === 'queued');
        if (queued.length) await maybeMove(contact).catch(() => {});
        const channel = queued.length ? await dmChannel(contact) : null;
        if (!box && !channel) continue; // A linked device sends 1:1 only once the chat has moved.
        let prepared = Boolean(channel);
        for (const record of queued) {
          try {
            if (!prepared) { await rotateIfDue(contact); await tellPolicy(contact); prepared = true; }
            await sendToContact(contact, App.messagePayload(record)); // Plain, /me action or poll.
            await window.ChatStore.setStatus(conversationId, record.id, 'sent');
          } catch (error) {
            if (current?.id === contact.id) App.chatStatus(error.code === 'identity-blocked' ? `${contact.username}'s security code changed. Review it to keep sending.` : error.status === 404 ? `${contact.username} has not opened the app since encryption was enabled. Messages wait on this device.` : `Not sent yet: ${error.message}`);
            if (error.code === 'identity-blocked') updateBanner();
            else retryLater = true;
            break; // Keep this contact's order; try the next contact.
          }
        }
      }
    } finally {
      flushing = false;
      if (current) App.refreshHistory();
      render();
      if (flushAgain) flushOutgoing();
      else if (retryLater) flushTimer = setTimeout(flushOutgoing, 15000);
    }
  }
  App.onQueued = () => { if (window.Groups?.active()) { App.chatStatus(''); window.Groups.flush(); return; } if (current) App.chatStatus(''); flushOutgoing(); };
  App.onBurn = async () => {
    const contact = current && contactById(current.id);
    if (!contact) throw new Error('Open the conversation to burn it.');
    const conversationId = await pairId(contact.id);
    await sendControl(contact, { v: 1, type: 'burn', id: crypto.randomUUID() });
    await window.ChatStore.removeConversation(conversationId);
    App.chatStatus(`Burned on this device. ${contact.username}'s device deletes its copy when the encrypted request arrives.`);
  };
  App.flagged = record => flagged.has(record.id.toLowerCase());

  // ---------- Custom emoji (workspace pack) ----------
  let emojiTimer;
  async function loadEmoji() {
    clearTimeout(emojiTimer);
    if (!me || !window.Emoji) return;
    try {
      const { emoji } = await api('/api/emoji');
      window.Emoji.setCustom(emoji); paintEmojiList(emoji); App.refreshHistory();
    } catch {}
    emojiTimer = setTimeout(loadEmoji, 60000); // Pick up emoji other people add.
  }
  let emojiCheckedAt = 0;
  App.onUnknownEmoji = () => { if (me && Date.now() - emojiCheckedAt > 10000) { emojiCheckedAt = Date.now(); loadEmoji(); } };
  function paintEmojiList(list) {
    $('emoji-list').replaceChildren(...list.map(item => {
      const row = document.createElement('li'), img = document.createElement('img'), name = document.createElement('code');
      img.className = 'custom-emoji'; img.src = item.url; img.alt = ''; img.decoding = 'async'; name.textContent = `:${item.name}:`;
      row.append(img, name);
      if (item.mine) {
        const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'link danger-text'; remove.textContent = 'Delete';
        remove.setAttribute('aria-label', `Delete :${item.name}:`);
        remove.onclick = async () => {
          try { await api(`/api/emoji/${encodeURIComponent(item.name)}`, 'DELETE'); say('emoji-status', `Deleted :${item.name}:.`); loadEmoji(); }
          catch (error) { say('emoji-status', error.message); }
        };
        row.append(remove);
      }
      return row;
    }));
  }
  const readFile = file => new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = () => reject(new Error('Could not read that file.')); reader.readAsDataURL(file); });
  $('emoji-file').onchange = async () => {
    const file = $('emoji-file').files[0], preview = $('emoji-preview');
    if (!file) { preview.hidden = true; return; }
    if (!$('emoji-name').value) $('emoji-name').value = file.name.replace(/\.[a-z0-9]+$/i, '').toLowerCase().replace(/[^a-z0-9_+-]+/g, '_').slice(0, 32);
    if (preview.src.startsWith('blob:')) URL.revokeObjectURL(preview.src);
    preview.src = URL.createObjectURL(file); preview.hidden = false; // img-src allows blob: for this local preview only.
  };
  $('emoji-add').onclick = async () => {
    const name = $('emoji-name').value.trim().toLowerCase().replace(/^:|:$/g, ''), file = $('emoji-file').files[0], url = $('emoji-url').value.trim();
    if (!/^[a-z0-9_+-]{2,32}$/.test(name)) { say('emoji-status', 'Names are 2–32 characters: a–z, 0–9, _, + or -.'); return; }
    if (!file && !url) { say('emoji-status', 'Choose an image file or paste an image address.'); return; }
    if (file && file.size > 512 * 1024) { say('emoji-status', 'Images must be at most 512 KB.'); return; }
    $('emoji-add').disabled = true; say('emoji-status', 'Adding…');
    try {
      if (file) await api('/api/emoji', 'POST', { name, image: await readFile(file) });
      else await api('/api/emoji/import', 'POST', { name, url });
      say('emoji-status', `Added :${name}:. Type :${name.slice(0, 3)} in a message to use it.`);
      $('emoji-name').value = ''; $('emoji-file').value = ''; $('emoji-url').value = ''; $('emoji-preview').hidden = true;
      loadEmoji();
    } catch (error) { say('emoji-status', error.message); }
    finally { $('emoji-add').disabled = false; }
  };
  /** A poll vote travels end to end like any control payload; votes from an unaccepted identity are ignored on receipt. */
  App.onVote = async (poll, option) => {
    const contact = current && contactById(current.id);
    if (!contact) throw new Error('Open the conversation to vote.');
    await sendToContact(contact, { v: 1, type: 'vote', id: crypto.randomUUID(), poll, option });
  };

  // ---------- Reactions, edits, read receipts and typing (docs/phase1-protocol.md §2) ----------
  const openContact = () => {
    const contact = current && contactById(current.id);
    if (!contact || contact.state !== 'mutual') throw new Error('Open the conversation first.');
    if (inactive) throw new Error('Messaging is active on another device. Move it here first.');
    return contact;
  };
  App.onReact = async (target, emoji, on) => { if (window.Groups?.active()) return window.Groups.onReact(target, emoji, on); await sendToContact(openContact(), { v: 1, type: 'react', id: crypto.randomUUID(), target, emoji, on }); };
  App.onEdit = async (record, text) => {
    if (window.Groups?.active()) return window.Groups.onEdit(record, text);
    const contact = openContact(), conversationId = await pairId(contact.id);
    const editedAt = Math.max(Date.now(), (record.editedAt || 0) + 1);
    if (!await window.ChatStore.edit(conversationId, record.id, 'me', text, editedAt)) throw new Error('This message can no longer be edited.');
    // Not sent yet: it leaves this device with the new text. Otherwise the edit follows it end to end.
    const latest = (await window.ChatStore.list()).find(value => value.conversationId === conversationId && value.id === record.id);
    if (latest?.status === 'queued') { flushOutgoing(); return; }
    await sendToContact(contact, { v: 1, type: 'edit', id: crypto.randomUUID(), target: record.id, text, editedAt });
  };
  // Read receipts: once the conversation is on screen and focused, batched and at most once every 2 s.
  // Every shown message is marked read here (so it is reported once); the receipt is only sent when allowed.
  let readTimer = null, readAt = 0;
  const looking = () => Boolean(current) && body.dataset.screen === 'conversation' && document.visibilityState === 'visible' && document.hasFocus();
  App.onDisplayed = () => {
    if (window.Groups?.active()) { window.Groups.onDisplayed(); return; }
    if (readTimer || !looking() || (!box && !linked) || inactive) return;
    readTimer = setTimeout(sendReads, Math.max(0, 2000 - (Date.now() - readAt)));
  };
  async function sendReads() {
    readTimer = null;
    const contact = current && contactById(current.id);
    if (!contact || !looking() || (!box && !await dmChannel(contact)) || inactive) return;
    const conversationId = await pairId(contact.id);
    const waiting = (await window.ChatStore.list()).filter(value => value.conversationId === conversationId && value.direction === 'incoming' && value.status === 'delivered').map(value => value.id);
    if (!waiting.length) return;
    readAt = Date.now();
    const ids = await window.ChatStore.markRead(conversationId, waiting.slice(-100), 'incoming');
    if (ids.length && App.readReceipts) sendToContact(contact, { v: 1, type: 'read', id: crypto.randomUUID(), ids }).catch(() => {});
    if (waiting.length > 100) App.onDisplayed();
  }
  window.addEventListener('focus', () => App.onDisplayed());
  document.addEventListener('visibilitychange', () => App.onDisplayed());
  // Typing: only in a moved chat's DM group, as a live-only frame (m5 §9); never over the 1:1 session.
  // `on` at most every 4 s while there is text; `off` on send/clear/blur.
  let typingSent = 0, typingOn = false, typingHide = null, typingFrom = null;
  App.onTyping = active => {
    if (window.Groups?.active()) { window.Groups.onTyping(active); return; }
    const contact = current && contactById(current.id);
    if (!contact || contact.state !== 'mutual' || inactive) { typingOn = false; return; }
    if (active) {
      if (!contact.online || Date.now() - typingSent < 4000) return;
      typingSent = Date.now(); typingOn = true; sendTyping(contact, true);
    } else if (typingOn) { typingOn = false; typingSent = 0; sendTyping(contact, false); }
  };
  /** Typing goes only through a moved chat's DM group (m5 §9); an unmoved chat shows none. */
  async function sendTyping(contact, on) {
    try { const channel = await dmChannel(contact); if (channel) await window.Groups.sendDm(channel, { v: 1, type: 'typing', id: crypto.randomUUID(), at: Date.now(), on }); } catch {}
  }
  /** Shows "<name> is typing…" for 6 s after their last `on`; stale hints (over 15 s old) are dropped. */
  function typing(fromId, payload) {
    if (payload && (Date.now() - payload.at > 15000 || payload.at - Date.now() > 300000)) return;
    const on = Boolean(payload?.on);
    if (!on && typingFrom !== fromId) return;
    clearTimeout(typingHide); typingFrom = on ? fromId : null;
    if (on) typingHide = setTimeout(() => typing(fromId, null), 6000);
    if (current?.id === fromId || !on) App.showTyping?.(on && current?.id === fromId);
  }

  // ---------- Key rotation ----------
  // Sessions (ratchets) rotate; identities do not rotate on a timer — that would make security-code changes
  // routine and teach people to ignore them. Each side picks an interval; a chat uses the shorter one.
  const readJson = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
  const writeJson = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch {} };
  const myRotation = () => Number(readJson(`rotation-v1:${me.id}`, 0)) || 0;
  const peerRotation = id => Number(readJson(`rotation-peer-v1:${me.id}`, {})[id]?.value) || 0;
  /** A contact's interval: only known choices, and at most ten changes a minute from any contact. */
  function rememberPeerRotation(id, value) {
    if (!window.Signal.ROTATION_CHOICES.includes(value)) return;
    const all = readJson(`rotation-peer-v1:${me.id}`, {}), previous = all[id], now = Date.now();
    if (previous?.value === value) return;
    const changes = (previous?.changes || []).filter(time => now - time < 60000);
    if (changes.length >= 10) return;
    all[id] = { value, changes: [...changes, now] }; writeJson(`rotation-peer-v1:${me.id}`, all);
  }
  const effectiveRotation = id => window.Signal.rotationInterval(myRotation(), peerRotation(id));
  const every = ms => ({ 86400000: 'day', 604800000: 'week', 2592000000: '30 days' })[ms];
  /** Starts fresh session keys with a new handshake. The pinned identity (security code) is untouched. */
  async function rotateSession(contact, reason) {
    const conversationId = await pairId(contact.id), id = crypto.randomUUID();
    await box.rotate(contact.id);
    await sendControl(contact, { v: 1, type: 'rotate', id, reason });
    await window.ChatStore.note(conversationId, id, reason === 'manual' ? '🔄 Secure session reset by you' : `🔄 Keys rotated on schedule (every ${every(effectiveRotation(contact.id))})`);
    await tellPolicy(contact);
  }
  async function rotateIfDue(contact) {
    const interval = effectiveRotation(contact.id), info = interval ? await box.sessionInfo(contact.id) : null;
    if (info && Date.now() - info.startedAt >= interval) await rotateSession(contact, 'scheduled');
  }
  /** Tells a contact our interval once per session, and again whenever it changes. */
  async function tellPolicy(contact, force = false) {
    const told = readJson(`rotation-told-v1:${me.id}`, {}), mine = myRotation(), info = await box.sessionInfo(contact.id);
    if (!force && info && told[contact.id] === `${mine}|${info.sid}`) return;
    await sendControl(contact, { v: 1, type: 'policy', id: crypto.randomUUID(), rotateEveryMs: mine });
    const after = await box.sessionInfo(contact.id);
    told[contact.id] = `${mine}|${after?.sid}`; writeJson(`rotation-told-v1:${me.id}`, told);
  }
  $('rotation-every').onchange = async () => {
    const value = Number($('rotation-every').value);
    if (!window.Signal?.ROTATION_CHOICES.includes(value) || !me) return;
    writeJson(`rotation-v1:${me.id}`, value);
    say('security-status', value ? `Chat keys rotate every ${every(value)}, or sooner if a contact chose a shorter interval.` : 'Automatic rotation is off. A contact\'s shorter interval still applies to your chat with them.');
    if (!box || inactive) return;
    for (const contact of contacts.filter(value => value.state === 'mutual')) if (await box.sessionInfo(contact.id)) tellPolicy(contact, true).catch(() => {});
  };
  $('conv-rotate').onclick = () => { $('conv-menu').open = false; $('rotate-confirm').hidden = false; $('rotate-yes').focus(); };
  $('rotate-cancel').onclick = () => { $('rotate-confirm').hidden = true; };
  $('rotate-yes').onclick = async () => {
    $('rotate-confirm').hidden = true;
    const contact = current && contactById(current.id);
    if (!contact || !box) return;
    if (inactive) { App.chatStatus('Messaging is active on another device. Move it here first.'); return; }
    try { await rotateSession(contact, 'manual'); App.chatStatus('Secure session reset. New keys are in use for this chat.'); }
    catch (error) { App.chatStatus(error.code === 'identity-blocked' ? `${contact.username}'s security code changed. Review it before resetting.` : `Could not reset: ${error.message}`); }
    App.refreshHistory(); render();
  };
  // ---------- Encryption core (Settings → Advanced) ----------
  let backendName = 'signal', announceBackend = () => {};
  // Set by the link flow when this browser became a linked device: { deviceId, instance } (its group store).
  let linked = null, keyBox = null;
  const linkedStore = userId => { try { const value = JSON.parse(localStorage.getItem(`linked-store-v1:${userId}`) || 'null'); return value?.instance ? value : null; } catch { return null; } };
  function showBackend() {
    if (backendName === 'linked') {
      say('core-backend-state', 'This browser is linked to your primary device. It reads your groups and channels; your primary holds your keys.');
      $('core-backend-switch').hidden = true;
      return;
    }
    const wasm = backendName === 'wasm';
    say('core-backend-state', wasm ? 'This device uses the experimental WebAssembly core.' : 'This device uses the standard browser core.');
    say('core-backend-switch', wasm ? 'Go back to the standard core' : 'Use the experimental encryption core');
    $('core-backend-switch').disabled = !window.Core?.supported();
  }
  /** Switches only with nothing to lose (no keys here yet) or after the user confirmed resetting this device's keys. */
  async function switchBackend() {
    $('core-confirm').hidden = true;
    const next = backendName === 'wasm' ? 'signal' : 'wasm', id = me.id;
    if (await window.Core.hasKeys(id, backendName)) {
      // The keys being left behind are deleted, so switching back later can never resurrect a stale identity.
      await new Promise(done => { const request = indexedDB.deleteDatabase(backendName === 'wasm' ? `webrtc-bun-core-v1-${id}` : `webrtc-bun-signal-v1-${id}`); request.onsuccess = request.onerror = request.onblocked = done; });
      try { localStorage.setItem(`core-switch-takeover-v1:${id}`, '1'); } catch {}
    }
    window.Core.setBackend(id, next);
    announceBackend(next); // Other tabs of this account reload onto the new core: never two cores at once.
    location.reload();
  }
  $('core-backend-switch').onclick = async () => {
    if (!me || !window.Core?.supported()) return;
    // A device with no keys in its current core has nothing to reset: switch straight away.
    if (!await window.Core.hasKeys(me.id, backendName)) { await switchBackend(); return; }
    $('core-confirm').hidden = false; $('core-confirm-cancel').focus();
  };
  $('core-confirm-cancel').onclick = () => { $('core-confirm').hidden = true; };
  $('core-confirm-yes').onclick = () => switchBackend();

  $('identity-reset').onclick = () => { $('identity-confirm').hidden = false; $('identity-cancel').focus(); };
  $('identity-cancel').onclick = () => { $('identity-confirm').hidden = true; };
  $('identity-yes').onclick = async () => {
    $('identity-confirm').hidden = true;
    if (!box || !me) return;
    try {
      await box.resetIdentity();
      writeJson(`rotation-told-v1:${me.id}`, {});
      await publishKeys(true); // Takeover semantics: new identity, signed prekey and 100 one-time prekeys.
      say('security-status', 'New identity keys are in use. Your contacts will see that your security code changed.');
    } catch (error) { say('security-status', `Could not generate new keys: ${error.message}`); }
  };

  // ---------- Security codes ----------
  // One identity check per contact at a time: a refresh and a succession never interleave their pin writes.
  const identityChecks = new Map();
  function checkIdentity(contactId) {
    const next = (identityChecks.get(contactId) || Promise.resolve()).then(() => checkIdentityNow(contactId));
    identityChecks.set(contactId, next.catch(() => {}));
    return next;
  }
  async function checkIdentityNow(contactId) {
    const contact = contactById(contactId);
    if (!contact || !box) return;
    const { identity } = await api(`/api/keys/${contact.username}/identity`);
    const before = await box.peer(contactId);
    if (before && (before.identity.dh !== identity.dh || before.identity.sign !== identity.sign) && await followSuccession(contact, before, identity)) { if (current?.id === contactId) updateBanner(); return true; }
    await box.notePeer(contactId, identity);
    if (current?.id === contactId) updateBanner();
    return false;
  }
  /**
   * m5 §5.3: a contact moved their account to a new primary device. If a chain of records, each signed by the key
   * before it, leads from the key we pinned to the one served now, the new key is theirs: the pin moves and keeps
   * its verification, and a soft notice replaces the security-code review. Anything else: the usual review.
   */
  async function followSuccession(contact, before, served) {
    const view = await api(`/api/devices/${contact.username}`).catch(() => null);
    // Only from a code the user accepted: a pin still waiting for review may be the server's own key.
    const path = view?.succession?.length ? await Devices.successionFrom(contact.id, before, served, view.succession) : null;
    if (!path) return false;
    await window.Groups?.contactSucceeded(contact.id, path).catch(() => {}); // The group store keeps the old key as a predecessor.
    await box.notePeer(contact.id, served);
    // Accepted because the old key signed it over, not on the server's word: exactly the key the chain ends at. If
    // another key was pinned meanwhile, the box refuses ('mismatch') and that one goes to the usual review.
    try {
      await box.acceptChange(contact.id, served);
      if (before.verified) await box.setVerified(contact.id, true, served);
    } catch (error) { if (error.code === 'mismatch') return true; throw error; }
    const text = `${contact.username} updated their security key. Verification kept.`; // m6 §6.2
    await window.ChatStore.note(await pairId(contact.id), crypto.randomUUID(), text).catch(() => {});
    say('chats-status', text);
    if (current?.id === contact.id) App.refreshHistory();
    return true;
  }
  // Cross-check a changed identity against the server's published one; a mismatch is suspicious.
  async function identityChanged(contactId) {
    const contact = contactById(contactId);
    try {
      const published = contact ? (await api(`/api/keys/${contact.username}/identity`)).identity : null;
      const peer = await box.peer(contactId);
      if (published && peer && (published.dh !== peer.identity.dh || published.sign !== peer.identity.sign)) mismatched.add(contactId); else mismatched.delete(contactId);
    } catch {}
    if (current?.id === contactId) updateBanner();
    render();
  }
  async function updateBanner() {
    const banner = $('key-banner');
    if (!current || !box) { banner.hidden = true; return; }
    const peer = await box.peer(current.id);
    if (!peer || !(peer.changed || peer.blocked)) { banner.hidden = true; return; }
    const name = current.username;
    say('key-banner-text', mismatched.has(current.id)
      ? `Warning: ${name}'s security code changed, and the server publishes a different one. Verify in person before trusting new messages.`
      : peer.blocked ? `${name}'s security code changed. Sending is paused until you review it.` : `${name}'s security code changed. Compare it again to be sure no one is in the middle.`);
    banner.hidden = false;
  }
  async function openSafety() {
    $('conv-menu').open = false;
    const contact = current && contactById(current.id);
    if (!contact || !box) { App.chatStatus(linked ? 'Security codes for this chat are on your primary device.' : 'Encrypted messaging is unavailable in this browser.'); return; }
    try {
      if (!await box.peer(contact.id)) await box.notePeer(contact.id, (await api(`/api/keys/${contact.username}/identity`)).identity);
      const safety = await box.safety(me.username, contact.id, contact.username);
      say('safety-title', `Security code with ${contact.username}`);
      say('safety-number', safety.number);
      say('safety-state', safety.verified ? 'Verified on this device.' : safety.changed ? 'This code changed recently. Compare it before trusting new messages.' : 'Not verified yet. Compare these 60 digits with the ones on their screen, in person or on a call. If they match, no one — not even this server — can read your messages.');
      $('safety-verify').textContent = safety.verified ? 'Clear verification' : 'Mark as verified';
      $('safety-accept').hidden = !safety.blocked;
      const interval = effectiveRotation(contact.id), mine = myRotation(), theirs = peerRotation(contact.id);
      say('safety-rotation', interval ? `Chat keys rotate every ${every(interval)} (${mine === theirs ? 'both your settings' : interval === mine ? 'your setting' : 'their setting'}).` : 'Chat keys rotate when either of you resets the secure session. Automatic rotation is off for both of you.');
      say('safety-devices', '');
      verifyContactDevices(contact).then(result => {
        if (!result) return;
        say('safety-devices', result.ok ? `${contact.username} has ${result.count === 1 ? '1 device' : `${result.count} devices`} in a list signed by this security code (version ${result.version}).`
          : result.reason === 'none' ? `${contact.username} has not published a device list yet.`
          : `Warning: ${contact.username}'s device list failed verification (${result.reason}). Do not trust devices the server shows for them.`);
      }).catch(() => {});
      $('safety').hidden = false; $('safety-close').focus();
    } catch (error) { App.chatStatus(error.status === 404 ? `${contact.username} has not set up encrypted messaging yet.` : error.message); }
  }
  $('conv-safety').onclick = openSafety;
  $('key-banner-review').onclick = openSafety;
  $('safety-close').onclick = () => { $('safety').hidden = true; };
  $('safety-verify').onclick = async () => {
    const safety = await box.safety(me.username, current.id, current.username);
    await box.setVerified(current.id, !safety.verified);
    window.Groups?.contactAccepted(current.id); // An explicit decision on this code: groups waiting on it resume.
    $('safety').hidden = true; updateBanner(); flushOutgoing();
  };
  $('safety-accept').onclick = async () => { await box.acceptChange(current.id); window.Groups?.contactAccepted(current.id); $('safety').hidden = true; updateBanner(); flushOutgoing(); };

  // ---------- Contacts and chat list ----------
  async function loadContacts() {
    if (!me) return;
    try {
      const online = new Set(contacts.filter(contact => contact.online).map(contact => contact.id));
      contacts = (await api('/api/contacts')).contacts.map(contact => ({ ...contact, online: contact.online || online.has(contact.id) }));
      render(); flushOutgoing(); openPending();
    } catch (error) { if (error.status === 401) signedOut('Your session ended. Sign in again.'); }
  }
  // ---------- Chat list: pinned, channels, groups, direct messages ----------
  const pinsKey = () => `pins-v1:${me.id}`;
  const readPinned = () => { try { const list = JSON.parse(localStorage.getItem(pinsKey()) || '[]'); return Array.isArray(list) ? list : []; } catch { return []; } };
  function togglePin(key) {
    const list = readPinned(), next = list.includes(key) ? list.filter(value => value !== key) : [...list, key].slice(-20);
    try { localStorage.setItem(pinsKey(), JSON.stringify(next)); } catch {}
    render();
    return next.includes(key);
  }
  /** One row of the chat list: avatar, name, last message or state, time, unread badge, mention mark. */
  function convoRow({ className, avatar, online, title, sub, time, count, mentioned, label, onOpen }) {
    const row = document.createElement('li'); row.className = className;
    const face = document.createElement('span'); face.className = 'avatar'; face.textContent = avatar; face.setAttribute('aria-hidden', 'true');
    if (online !== undefined) face.dataset.online = String(online);
    const text = document.createElement('span'); text.className = 'contact-text';
    const name = document.createElement('strong'); name.textContent = title;
    const small = document.createElement('small'); small.textContent = sub;
    text.append(name, small); row.append(face, text);
    const side = document.createElement('span'); side.className = 'contact-side';
    const stamp = document.createElement('time'); stamp.textContent = time ? clock(time) : '';
    side.append(stamp);
    if (count || mentioned) {
      const badge = document.createElement('span'); badge.className = mentioned ? 'badge mention-badge' : 'badge';
      badge.textContent = mentioned ? '@' : count > 99 ? '99+' : String(count); side.append(badge); row.classList.add('unread');
    }
    const open = document.createElement('button'); open.type = 'button'; open.className = 'row-button';
    open.setAttribute('aria-label', label); open.onclick = onOpen;
    row.append(side, open);
    return row;
  }
  async function render() {
    if (!me) return;
    const records = window.ChatStore ? await window.ChatStore.list().catch(() => []) : [];
    const last = new Map(); for (const record of records) last.set(record.conversationId, record);
    const pinnedKeys = readPinned(), pinnedRows = [];
    const preview = recent => recent ? `${recent.direction === 'outgoing' ? 'You: ' : recent.fromName ? `${recent.fromName}: ` : ''}${App.preview ? App.preview(recent) : recent.text}` : null;
    const list = $('contact-list'), rows = [];
    for (const contact of contacts) {
      let row;
      if (contact.state === 'mutual') {
        const recent = last.get(await pairId(contact.id)), count = unread[contact.id] || 0;
        row = convoRow({ className: `contact ${contact.state}`, avatar: initial(contact.username), online: contact.online, title: contact.username,
          sub: preview(recent) || (contact.online ? 'Online' : 'Say hello. Messages are end-to-end encrypted.'), time: recent?.createdAt, count,
          label: `Open conversation with ${contact.username}${count ? `, ${count} unread` : ''}${contact.online ? ', online' : ''}`, onOpen: () => openConversation(contact) });
        if (pinnedKeys.includes(`dm:${contact.id}`)) { pinnedRows.push([pinnedKeys.indexOf(`dm:${contact.id}`), row]); continue; }
      } else {
        row = document.createElement('li'); row.className = `contact ${contact.state}`;
        const avatar = document.createElement('span'); avatar.className = 'avatar'; avatar.textContent = initial(contact.username); avatar.setAttribute('aria-hidden', 'true');
        const text = document.createElement('span'); text.className = 'contact-text';
        const name = document.createElement('strong'); name.textContent = contact.username;
        const sub = document.createElement('small');
        text.append(name, sub); row.append(avatar, text);
        if (contact.state === 'incoming') {
          sub.textContent = 'Wants to add you';
          row.append(action('Accept', 'primary', async () => { await api(`/api/contacts/${contact.username}/accept`, 'POST', {}); loadContacts(); }),
            action('Decline', '', async () => { await api(`/api/contacts/${contact.username}`, 'DELETE'); loadContacts(); }));
        } else {
          sub.textContent = 'Request sent';
          row.append(action('Cancel', '', async () => { await api(`/api/contacts/${contact.username}`, 'DELETE'); loadContacts(); }));
        }
      }
      rows.push(row);
    }
    list.replaceChildren(...rows);
    $('contacts-empty').hidden = rows.length > 0 || pinnedRows.length > 0;
    // Groups and channels, newest activity first.
    const groups = window.Groups?.sections() || { rows: [], enabled: false, reason: '' }, channelRows = [], groupRows = [];
    for (const item of groups.rows.sort((a, b) => Math.max(b.lastAt, last.get(b.id)?.createdAt || 0) - Math.max(a.lastAt, last.get(a.id)?.createdAt || 0))) {
      const recent = last.get(item.id);
      const state = item.status === 'left' ? 'You left' : item.status === 'removed' ? 'You were removed' : item.status === 'frozen' ? 'Paused while an admin checks a change' : item.status === 'paused' ? 'Paused: a security code changed' : item.status === 'join-pending' ? 'Join pending: this device is joining…' : null;
      const row = convoRow({ className: `contact group ${item.channel ? 'is-channel' : 'is-group'} status-${item.status}`, avatar: item.channel ? '#' : initial(item.title), title: item.title,
        sub: state || preview(recent) || item.topic || (item.channel ? 'Say what this channel is for.' : 'Say hello to everyone.'), time: recent?.createdAt || item.lastAt, count: item.unread, mentioned: item.mentioned,
        label: `Open ${item.channel ? 'channel' : 'group'} ${item.title}${item.mentioned ? ', you were mentioned' : ''}${item.unread ? `, ${item.unread} unread` : ''}`, onOpen: () => openGroup(item.id) });
      row.dataset.channel = item.id;
      if (pinnedKeys.includes(`g:${item.id}`)) pinnedRows.push([pinnedKeys.indexOf(`g:${item.id}`), row]);
      else (item.channel ? channelRows : groupRows).push(row);
    }
    $('channel-list').replaceChildren(...channelRows); $('group-list').replaceChildren(...groupRows);
    $('channels-empty').textContent = groups.enabled || !groups.reason ? 'Channels keep a topic in one place. Start one, or browse the public ones to join.' : groups.reason;
    $('channels-empty').hidden = channelRows.length > 0;
    $('groups-empty').hidden = groupRows.length > 0;
    $('pinned-list').replaceChildren(...pinnedRows.sort((a, b) => a[0] - b[0]).map(([, row]) => row));
    $('pinned-section').hidden = pinnedRows.length === 0;
    if (current) updateHeader();
  }
  function action(label, kind, task) {
    const button = document.createElement('button'); button.type = 'button'; button.textContent = label; if (kind) button.className = kind;
    button.onclick = () => guard(button, 'chats-status', task);
    return button;
  }
  $('contact-form').addEventListener('submit', event => {
    event.preventDefault();
    guard($('contact-add'), 'chats-status', async () => {
      const username = $('contact-input').value.trim().toLowerCase();
      await api('/api/contacts', 'POST', { username });
      $('contact-input').value = '';
      say('chats-status', `Request sent to @${username}. They appear in your chats once they accept.`);
      loadContacts();
    });
  });
  $('invite-create').onclick = () => { $('account-menu').open = false; guard($('invite-create'), 'chats-status', async () => {
    const { code, expiresAt } = await api('/api/invites', 'POST', {});
    $('invite-link').value = `${location.origin}/#invite=${code}`;
    say('invite-expiry', `Works once, until ${new Date(expiresAt).toLocaleDateString([], { month: 'short', day: 'numeric' })}. Share it privately.`);
    $('invite-result').hidden = false;
  }); };
  $('invite-copy').onclick = async () => {
    try { await navigator.clipboard.writeText($('invite-link').value); say('invite-expiry', 'Copied. Share it privately; it works once.'); }
    catch { $('invite-link').select(); }
  };
  $('invite-close').onclick = () => { $('invite-result').hidden = true; $('invite-link').value = ''; };
  $('account-settings').onclick = () => { $('account-menu').open = false; $('settings').open = true; App.view('panel', 'settings'); };
  $('settings').addEventListener('toggle', () => { if ($('settings').open && me) api(`/api/devices/${me.username}`).then(view => { deviceView = view; renderDevices(); }).catch(() => {}); });

  // ---------- Conversation ----------
  function updateHeader() {
    const contact = contactById(current.id) || current;
    say('conv-name', contact.username); say('conv-avatar', initial(contact.username));
    $('conv-avatar').dataset.online = String(Boolean(contact.online));
    say('conv-presence', contact.state !== 'mutual' ? 'not a contact' : contact.online ? 'online' : 'offline');
    $('conv-voice').disabled = $('conv-video').disabled = !contact.online || contact.state !== 'mutual';
  }
  async function openConversation(contact) {
    const conversationId = await pairId(contact.id);
    if (App.active && App.conversationId !== conversationId) await App.end();
    window.Groups?.close(); body.dataset.kind = 'dm';
    current = contact; body.dataset.screen = 'conversation'; updateHeader();
    delete unread[contact.id]; try { localStorage.setItem(`unread-v1:${me.id}`, JSON.stringify(unread)); } catch {}
    if (!App.active) App.openConversation({ conversationId, peerName: contact.username, peerId: contact.id, online: contact.online });
    if (!await ready) App.chatStatus('This browser is too old for encrypted messaging. Update it to send and receive messages.');
    else if (linked && !await dmChannel(contact)) App.chatStatus(`This chat stays on your primary device until it moves to the new encryption. Groups and channels work here.`);
    updateBanner(); flushOutgoing();
  }
  /** A group or channel: the same conversation screen, driven by groups.js. Calls stay 1:1. */
  async function openGroup(id) {
    if (App.active) { say('chats-status', 'Finish the call first. Group calls come later.'); return; }
    App.onTyping(false); App.showTyping?.(false);
    current = null; $('key-banner').hidden = true;
    body.dataset.screen = 'conversation'; body.dataset.kind = 'group';
    window.Groups.open(id);
    render();
  }
  function groupContext() {
    return {
      me, backend: backendName, box, signWithIdentity, followOwnSuccession, followContact: async contactId => Boolean(contactById(contactId) && box && await checkIdentity(contactId)), recerts: () => Promise.all([takeRekey(), answerRekeys(), answerRecerts(), keyBox || (box && !inactive) ? finishRemovals() : null].map(task => Promise.resolve(task).catch(() => {}))), contacts: () => contacts, render: () => render(), notice: text => say('chats-status', text),
      viewing: id => body.dataset.screen === 'conversation' && window.Groups?.active() === id,
      looking: () => body.dataset.screen === 'conversation' && document.visibilityState === 'visible' && document.hasFocus(),
      socket: () => events, openGroup, verifiedOwnDevices,
      pairIdOf: id => pairId(id),
      dmIncoming: peerId => { if (!(body.dataset.screen === 'conversation' && current?.id === peerId)) { unread[peerId] = (unread[peerId] || 0) + 1; writeJson(`unread-v1:${me.id}`, unread); } },
      dmTyping: (peerId, payload) => typing(peerId, payload),
      dmJoined: channel => pointers.get(channel)?.wake?.(),
      dmChanged: peerId => { if (current?.id === peerId && body.dataset.screen === 'conversation') App.refreshHistory(); render(); },
    };
  }
  $('channels-new').onclick = () => window.Groups?.openNew('channel');
  $('channels-browse').onclick = () => window.Groups?.openBrowser();
  $('groups-new').onclick = () => window.Groups?.openNew('group_dm');
  $('conv-pin').onclick = () => {
    $('conv-menu').open = false;
    const key = window.Groups?.active() ? `g:${window.Groups.active()}` : current ? `dm:${current.id}` : null;
    if (key) App.chatStatus(togglePin(key) ? 'Pinned to the top of your chats.' : 'Unpinned.');
  };
  /** Notification taps only choose which conversation to show. They never start or answer a call:
   *  an incoming call keeps ringing on its sheet until the user taps Accept in the app. */
  async function openPending() {
    const pending = window.pendingOpen;
    if (!pending || !me) return;
    window.pendingOpen = null;
    const contact = USERNAME.test(pending.user || '') && contacts.find(value => value.username === pending.user && value.state === 'mutual');
    if (!contact || App.active) return;
    if (!pending.call) { openConversation(contact); return; }
    // A call notification must not start chat here: that would take over the waiting call's room.
    current = contact; body.dataset.screen = 'conversation'; updateHeader();
    App.openConversation({ conversationId: await pairId(contact.id), peerName: contact.username, peerId: contact.id, online: contact.online });
  }
  if (window.Alerts) window.Alerts.onOpen = data => { window.pendingOpen = { user: data.user, call: Boolean(data.call) }; openPending(); };
  function stopCalling() { clearTimeout(noAnswerTimer); noAnswerTimer = undefined; Ring.stop(); }
  async function call(kind) {
    if (!current) return;
    const contact = current;
    try {
      const conversationId = await pairId(contact.id);
      Ring.unlock(); // This click is the gesture that lets the ringback play.
      if (App.active) App.leave();
      const session = await api(`/api/conversations/${contact.username}/session`, 'POST', { kind });
      await App.start({ ...session, kind, conversationId, peerName: contact.username, peerId: contact.id });
      if (!App.active) return;
      Ring.outgoing();
      clearTimeout(noAnswerTimer);
      noAnswerTimer = setTimeout(async () => {
        noAnswerTimer = undefined; Ring.stop();
        if (App.roomId !== session.roomId) return;
        await App.end();
        App.status(`No answer from ${contact.username}.`); say('chats-status', `No answer from ${contact.username} · ${clock(Date.now())}`);
      }, RING_TIMEOUT);
    } catch (error) { stopCalling(); App.status(error.message); }
  }
  $('conv-voice').onclick = () => call('voice');
  $('conv-video').onclick = () => call('video');
  $('conv-back').onclick = () => {
    App.onTyping(false); App.showTyping?.(false);
    if (window.Groups?.active()) { window.Groups.close(); App.closeConversation(); body.dataset.screen = 'list'; delete body.dataset.kind; render(); return; }
    body.dataset.screen = 'list'; $('key-banner').hidden = true;
    if (!App.active) { App.closeConversation(); current = null; }
    render();
  };
  $('conv-burn').onclick = () => { $('conv-menu').open = false; if (!$('burn').disabled) $('burn').click(); };
  $('conv-remove').onclick = () => { $('conv-menu').open = false; $('remove-confirm').hidden = false; };
  $('remove-cancel').onclick = () => { $('remove-confirm').hidden = true; };
  $('remove-yes').onclick = () => guard($('remove-yes'), 'chats-status', async () => {
    $('remove-confirm').hidden = true;
    const contact = current;
    if (App.active) App.leave();
    await api(`/api/contacts/${contact.username}`, 'DELETE');
    current = null; App.closeConversation(); body.dataset.screen = 'list'; $('key-banner').hidden = true;
    say('chats-status', `Removed @${contact.username}. Messages on this device are unchanged.`);
    loadContacts();
  });

  // ---------- Incoming calls ----------
  async function incoming(message) {
    // Contact chats use the encrypted mailbox now; only calls ring.
    if (message.kind === 'chat') return;
    const contact = contactById(message.from.id) || { ...message.from, state: 'mutual', online: true };
    const conversationId = await pairId(contact.id);
    ringing = { ...message, contact, conversationId };
    say('incoming-avatar', initial(contact.username)); say('incoming-title', contact.username);
    say('incoming-kind', message.kind === 'video' ? 'Incoming video call' : 'Incoming voice call');
    // Video calls can be answered with the microphone only; nothing is captured until one of these is tapped.
    $('incoming-accept-audio').hidden = message.kind !== 'video';
    say('incoming-accept-label', message.kind === 'video' ? 'Video' : 'Accept');
    $('incoming').dataset.kind = message.kind;
    $('incoming').hidden = false; $('incoming-accept').focus();
    Ring.incoming(); acknowledgeRinging();
    clearTimeout(missTimer);
    missTimer = setTimeout(() => {
      if (ringing?.roomId !== message.roomId) return;
      ringing = null; hideRing();
      say('chats-status', `Missed ${message.kind} call from ${contact.username} · ${clock(Date.now())}`);
    }, RING_TIMEOUT);
  }
  // Tells the server this call is ringing on a visible screen, so it need not wake the phone by push.
  function acknowledgeRinging() {
    if (ringing && document.visibilityState === 'visible' && events?.readyState === WebSocket.OPEN) events.send(JSON.stringify({ type: 'ringing', roomId: ringing.roomId }));
  }
  document.addEventListener('visibilitychange', acknowledgeRinging);
  function hideRing() { $('incoming').hidden = true; clearTimeout(missTimer); missTimer = undefined; Ring.stop(); }
  async function accept(audioOnly) {
    Ring.unlock();
    const ring = ringing; ringing = null; hideRing();
    if (!ring) return;
    if (App.active) App.leave();
    current = ring.contact; body.dataset.screen = 'conversation'; updateHeader(); updateBanner();
    await App.start({ roomId: ring.roomId, token: ring.token, kind: ring.kind, audioOnly, conversationId: ring.conversationId, peerName: ring.contact.username, peerId: ring.contact.id });
  }
  $('incoming-accept').onclick = () => accept(false);
  $('incoming-accept-audio').onclick = () => accept(true);
  $('incoming-decline').onclick = async () => {
    const ring = ringing; ringing = null; hideRing();
    if (ring) { try { await api(`/api/conversations/${ring.contact.username}/decline`, 'POST', { roomId: ring.roomId }); } catch {} }
  };

  // Command palette: every mutual contact is a conversation to jump to.
  window.Palette?.register(() => !me ? [] : contacts.filter(contact => contact.state === 'mutual').map(contact => ({
    id: `chat:${contact.id}`, group: 'Conversations', label: contact.username, hint: unread[contact.id] ? `${unread[contact.id]} unread` : contact.online ? 'online' : '',
    run: () => { if (App.active && App.conversationId) return; openConversation(contact); },
  })));

  App.onInvite = invite => { if (!me) { $('register-invite').value = invite; $('register-panel').open = true; $('register-username').focus(); } };
  App.onEnd = () => { stopCalling(); if (me) { if (current) updateHeader(); render(); } };
  App.onPeerJoined = () => stopCalling();

  // ---------- Start ----------
  (async () => {
    if (window.pendingAccountInvite) App.onInvite(window.pendingAccountInvite);
    try { signedIn((await api('/api/me')).user); }
    catch (error) { body.dataset.auth = error.status === 404 ? 'off' : 'out'; if (body.dataset.auth === 'out' && !App.roomId) $('invitation-panel').open = false; }
  })();
})();
