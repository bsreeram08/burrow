'use strict';
// Device lists and device certificates (docs/workspace-architecture.md §1.2, §2.2, §3; docs/devices.md).
// One implementation of the canonical bytes, shared by the browser and the server (server.ts imports this
// file), so what a device signs and what anyone verifies can never drift apart.
//
// A DeviceList names every device of an account; a DeviceCert binds one device. Both are signed with the
// account identity key (AIK), the Ed25519 half of the identity whose safety number contacts verify. Clients
// trust a device only if a list signed by the pinned AIK names it, never because the server says so.
// Each entry's label and platform travel inside the list as `meta`, sealed under a key only the account's own
// devices hold (deviceMetaKey below): the server and contacts see device ids and dates, nothing else.
(() => {
  const root = typeof window !== 'undefined' ? window : globalThis;
  const PLATFORMS = Object.freeze(['web', 'ios', 'android', 'macos', 'windows', 'linux']);
  const MAX_DEVICES = 16, MAX_VERSION = 2 ** 31 - 1;
  const USER_ID = /^[A-Za-z0-9_-]{1,64}$/, DEVICE_ID = /^[A-Za-z0-9_-]{22}$/, HASH = /^[A-Za-z0-9_-]{43}$/, KEY = /^[A-Za-z0-9_-]{43}$/, SIG = /^[A-Za-z0-9_-]{86}$/;
  // Sealed metadata: 12-byte IV, at least the 16-byte tag, at most 512 bytes in all.
  const META = /^[A-Za-z0-9_-]{38,683}$/, META_MAX_LABEL = 64;
  const LIST_LABEL = 'webrtc-bun-devicelist-v1', CERT_LABEL = 'webrtc-bun-devicecert-v1', META_LABEL = 'webrtc-bun-devicemeta-v1', BIND_LABEL = 'webrtc-bun-devicebind-v1', CLAIM_LABEL = 'webrtc-bun-deviceclaim-v1';
  const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
  const encoder = new TextEncoder();

  function b64(bytes) {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64(text) {
    const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
    if (b64(bytes) !== text) throw new Error('Non-canonical base64');
    return bytes;
  }
  const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  const fail = text => { throw Object.assign(new Error(text), { code: 'invalid-device-list' }); };

  /** TLS-style writer: u8/u16-length-prefixed byte strings, big-endian integers, no optional fields. */
  function writer() {
    const parts = [];
    const api = {
      u8(value) { parts.push(Uint8Array.of(value)); return api; },
      u16(value) { parts.push(Uint8Array.of(value >>> 8 & 255, value & 255)); return api; },
      u32(value) { parts.push(Uint8Array.of(value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255)); return api; },
      // Millisecond timestamps exceed 32 bits: split into high and low words (safe integers only).
      u64(value) { return api.u32(Math.floor(value / 2 ** 32)).u32(value >>> 0); },
      bytes8(value) { if (value.length > 255) fail('Field too long'); parts.push(Uint8Array.of(value.length), value); return api; },
      bytes16(value) { if (value.length > 65535) fail('Field too long'); api.u16(value.length); parts.push(value); return api; },
      text16(value) { const bytes = encoder.encode(value); if (bytes.length > 65535) fail('Field too long'); api.u16(bytes.length); parts.push(bytes); return api; },
      done() { const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let at = 0; for (const part of parts) { out.set(part, at); at += part.length; } return out; },
    };
    return api;
  }
  const timestamp = value => Number.isSafeInteger(value) && value >= 0;

  /** Strict schema check: exact keys, canonical encodings, devices sorted by id with no duplicates. */
  function validateList(list) {
    if (!exact(list, ['v', 'userId', 'version', 'prevHash', 'devices'])) fail('Device list has unexpected fields');
    if (list.v !== 1 || typeof list.userId !== 'string' || !USER_ID.test(list.userId)) fail('Invalid device list owner');
    if (!Number.isSafeInteger(list.version) || list.version < 1 || list.version > MAX_VERSION) fail('Invalid device list version');
    if (list.version === 1 ? list.prevHash !== '' : typeof list.prevHash !== 'string' || !HASH.test(list.prevHash)) fail('Invalid previous-list hash');
    if (!Array.isArray(list.devices) || list.devices.length < 1 || list.devices.length > MAX_DEVICES) fail(`A device list names 1–${MAX_DEVICES} devices`);
    let previous = '';
    for (const device of list.devices) {
      if (!exact(device, ['deviceId', 'addedAt', 'meta'])) fail('Device entry has unexpected fields');
      if (typeof device.deviceId !== 'string' || !DEVICE_ID.test(device.deviceId)) fail('Invalid device id');
      if (!timestamp(device.addedAt)) fail('Invalid device timestamp');
      // Empty when the signer could not describe the device; otherwise sealed { label, platform }.
      if (device.meta !== '' && !(typeof device.meta === 'string' && META.test(device.meta))) fail('Invalid device metadata');
      // Byte order of base64url ids: one canonical order, so a reordered list is a different (invalid) list.
      if (device.deviceId <= previous) fail('Devices must be sorted by id without duplicates');
      previous = device.deviceId;
    }
    return list;
  }
  function listBytes(list) {
    validateList(list);
    const out = writer().text16(LIST_LABEL).text16(list.userId).u32(list.version).bytes8(list.prevHash ? unb64(list.prevHash) : new Uint8Array()).u16(list.devices.length);
    for (const device of list.devices) out.text16(device.deviceId).u64(device.addedAt).bytes16(device.meta ? unb64(device.meta) : new Uint8Array());
    return out.done();
  }
  function validateCert(cert) {
    if (!exact(cert, ['v', 'userId', 'deviceId', 'leafSigKey', 'issuedAt'])) fail('Device certificate has unexpected fields');
    if (cert.v !== 1 || typeof cert.userId !== 'string' || !USER_ID.test(cert.userId) || typeof cert.deviceId !== 'string' || !DEVICE_ID.test(cert.deviceId)) fail('Invalid device certificate subject');
    // The MLS leaf signature key arrives with M2; until then a certificate binds the device id alone.
    if (cert.leafSigKey !== '' && !(typeof cert.leafSigKey === 'string' && KEY.test(cert.leafSigKey))) fail('Invalid leaf signature key');
    if (!timestamp(cert.issuedAt)) fail('Invalid certificate timestamp');
    return cert;
  }
  function certBytes(cert) {
    validateCert(cert);
    return writer().text16(CERT_LABEL).text16(cert.userId).text16(cert.deviceId).bytes8(cert.leafSigKey ? unb64(cert.leafSigKey) : new Uint8Array()).u64(cert.issuedAt).done();
  }
  /**
   * What a device signs with its own device key to bind a session to its id: the server's single-use
   * challenge for this session, the account and the device. Proof of possession, so knowing a device id
   * (or holding another session of the account) is never enough to become that device.
   */
  function bindBytes(userId, deviceId, challenge) {
    if (typeof userId !== 'string' || !USER_ID.test(userId) || typeof deviceId !== 'string' || !DEVICE_ID.test(deviceId)) fail('Invalid device binding');
    if (typeof challenge !== 'string' || !CHALLENGE.test(challenge)) fail('Invalid device challenge');
    return writer().text16(BIND_LABEL).text16(userId).text16(deviceId).bytes8(unb64(challenge)).done();
  }
  /**
   * What the account identity key signs to claim the account's messaging inbox for a device (announce
   * `identityProof`): knowing the public identity is not enough; holding its key is. Same challenge as the
   * binding, a distinct label, so neither signature can stand in for the other. crates/chatcore builds the
   * same bytes (`claim_bytes`) and signs nothing else for it.
   */
  function claimBytes(userId, deviceId, challenge) {
    if (typeof userId !== 'string' || !USER_ID.test(userId) || typeof deviceId !== 'string' || !DEVICE_ID.test(deviceId)) fail('Invalid identity claim');
    if (typeof challenge !== 'string' || !CHALLENGE.test(challenge)) fail('Invalid device challenge');
    return writer().text16(CLAIM_LABEL).text16(userId).text16(deviceId).bytes8(unb64(challenge)).done();
  }
  async function hash(bytes) { return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))); }
  async function verifyBytes(aikSign, bytes, signature) {
    if (typeof aikSign !== 'string' || !KEY.test(aikSign) || typeof signature !== 'string' || !SIG.test(signature)) return false;
    try {
      const key = await crypto.subtle.importKey('raw', unb64(aikSign), { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify('Ed25519', key, unb64(signature), bytes);
    } catch { return false; }
  }
  /** The certificate a list implies for one of its devices (M1: no leaf key yet). */
  const certFor = (userId, device) => ({ v: 1, userId, deviceId: device.deviceId, leafSigKey: '', issuedAt: device.addedAt });

  /**
   * A list (as served) is trusted only if: it is well formed and canonical, names its owner, carries a valid
   * AIK signature, every device has a valid AIK-signed certificate, and it does not go back on the pin: not an
   * older version, not a different list at the pinned version, the next version chains to the pinned hash, and
   * no device the pinned history removed comes back. Returns { ok, reason, hash, pin } with the pin to store.
   */
  async function verifyView({ userId, aikSign, list, signature, certs, pin }) {
    try {
      if (!list) return { ok: false, reason: 'none' };
      if (list.userId !== userId) return { ok: false, reason: 'owner' };
      const bytes = listBytes(list);
      if (!await verifyBytes(aikSign, bytes, signature)) return { ok: false, reason: 'signature' };
      for (const device of list.devices) if (!await verifyBytes(aikSign, certBytes(certFor(userId, device)), certs?.[device.deviceId])) return { ok: false, reason: 'certificate' };
      const digest = await hash(bytes), ids = list.devices.map(device => device.deviceId);
      const same = pin && pin.aik === aikSign;
      if (same) {
        if (list.version < pin.version) return { ok: false, reason: 'rollback' };
        if (list.version === pin.version && digest !== pin.hash) return { ok: false, reason: 'equivocation' };
        if (list.version === pin.version + 1 && list.prevHash !== pin.hash) return { ok: false, reason: 'fork' };
        if (ids.some(id => (pin.revoked || []).includes(id))) return { ok: false, reason: 'revoked' };
      }
      // Tombstones: every device a pinned list named and a later one dropped stays removed for good.
      const revoked = same ? [...new Set([...(pin.revoked || []), ...(pin.devices || []).filter(id => !ids.includes(id))])].slice(-256) : [];
      return { ok: true, hash: digest, pin: { aik: aikSign, version: list.version, hash: digest, devices: ids, revoked } };
    } catch { return { ok: false, reason: 'malformed' }; }
  }
  const newDeviceId = () => b64(crypto.getRandomValues(new Uint8Array(16)));

  // ---------- Sealed device metadata ----------
  // The key is derived from an AIK signature over a fixed, account-bound message. Ed25519 signatures are
  // deterministic (RFC 8032), so every holder of the AIK derives the same key and nobody else can: the
  // signature never leaves the device and signs nothing else. Linked companions (M5) receive the key in
  // their provisioning bundle. `sign(bytes)` signs with the AIK and returns the raw 64-byte signature.
  async function deviceMetaKey(userId, sign) {
    const seed = await sign(writer().text16(META_LABEL).text16(userId).done());
    const base = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode(META_LABEL) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  const metaAad = (userId, deviceId) => writer().text16(META_LABEL).text16(userId).text16(deviceId).done();
  /** Seals { label, platform } for one list entry; the AAD binds it to that account and device. */
  async function sealMeta(key, userId, deviceId, { label, platform }) {
    if (!PLATFORMS.includes(platform)) fail('Invalid device platform');
    const plain = encoder.encode(JSON.stringify({ label: String(label || '').slice(0, META_MAX_LABEL), platform }));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: metaAad(userId, deviceId) }, key, plain));
    const out = new Uint8Array(12 + sealed.length); out.set(iv); out.set(sealed, 12);
    return b64(out);
  }
  /** The entry's { label, platform }, or null if it is empty, not ours, or tampered with. */
  async function openMeta(key, userId, deviceId, meta) {
    if (!meta) return null;
    try {
      const bytes = unb64(meta);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: metaAad(userId, deviceId) }, key, bytes.subarray(12));
      const value = JSON.parse(new TextDecoder().decode(plain));
      return exact(value, ['label', 'platform']) && typeof value.label === 'string' && PLATFORMS.includes(value.platform) ? value : null;
    } catch { return null; }
  }
  // ---------- Browser-only: this browser's device key ----------
  // Each browser keeps, per account, its device id with a non-extractable Ed25519 key (WebKit persists
  // Ed25519 CryptoKeys, as it does the identity signing key). The id and key live and die together: a browser
  // that lost either starts as a new device.
  const deviceKeys = new Map();
  function deviceKey(userId) {
    if (deviceKeys.has(userId)) return deviceKeys.get(userId);
    const opened = new Promise((resolve, reject) => {
      const request = indexedDB.open('webrtc-bun-device-key-v1', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('kv');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    }).then(async db => {
      const read = () => new Promise(done => { const get = db.transaction('kv').objectStore('kv').get(userId); get.onsuccess = () => done(get.result); get.onerror = () => done(null); });
      let record = await read();
      if (!(record?.privateKey instanceof CryptoKey) || !DEVICE_ID.test(record.deviceId || '') || !KEY.test(record.publicKey || '')) {
        const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
        const fresh = { deviceId: newDeviceId(), privateKey: pair.privateKey, publicKey: b64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))) };
        // put() replaces a broken record; two tabs racing settle on whichever wrote last, re-read below.
        await new Promise(done => { const tx = db.transaction('kv', 'readwrite'); tx.objectStore('kv').put(fresh, userId); tx.oncomplete = tx.onerror = tx.onabort = done; });
        record = await read();
        if (!(record?.privateKey instanceof CryptoKey)) throw new Error('This browser cannot keep a device key');
      }
      return { deviceId: record.deviceId, publicKey: record.publicKey, sign: async bytes => b64(new Uint8Array(await crypto.subtle.sign('Ed25519', record.privateKey, bytes))) };
    });
    deviceKeys.set(userId, opened);
    opened.catch(() => deviceKeys.delete(userId));
    return opened;
  }
  function describeThisDevice() {
    const agent = typeof navigator !== 'undefined' ? navigator.userAgent : '';
    const browserName = /Edg\//.test(agent) ? 'Edge' : /Firefox\//.test(agent) ? 'Firefox' : /Chrome\//.test(agent) ? 'Chrome' : /Safari\//.test(agent) ? 'Safari' : 'Browser';
    const os = /iPhone|iPad/.test(agent) ? 'iPhone' : /Android/.test(agent) ? 'Android' : /Mac OS X/.test(agent) ? 'Mac' : /Windows/.test(agent) ? 'Windows' : /Linux/.test(agent) ? 'Linux' : 'device';
    return `${browserName} on ${os}`;
  }

  root.DeviceFormat = Object.freeze({ PLATFORMS, MAX_DEVICES, validateList, listBytes, validateCert, certBytes, certFor, hash, verifyBytes, verifyView, newDeviceId, bindBytes, claimBytes, deviceKey, deviceMetaKey, sealMeta, openMeta, describeThisDevice, b64, unb64 });
})();
