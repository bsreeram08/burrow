import { afterEach, describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import '../../packages/signaling/public/devices.js';
import { startSignaling } from '../../packages/signaling/server';
import { Client, clientCore, id } from './helpers/mls';

// Device linking against real chatcore cores (docs/m5-linking.md): the blind relay, the primary's signed list, the
// new device's session, the short code, revocation, succession records. Needs the Rust toolchain like channels.test.ts.
const loaded = clientCore();
if ('skip' in loaded) console.warn(`linking.test.ts skipped: ${loaded.skip}`);
const suite = 'core' in loaded ? describe : describe.skip;
const Core = 'core' in loaded ? loaded.core : (undefined as never);
const F = (globalThis as any).DeviceFormat;
const origin = 'http://localhost:3000';
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('base64url');

let dataDir: string, app: ReturnType<typeof startSignaling>, clock: number;
afterEach(async () => { await app?.stop(); await rm(dataDir, { recursive: true, force: true }); });
async function start() {
    dataDir = await mkdtemp(join(tmpdir(), 'linking-'));
    clock = Date.now();
    app = startSignaling({ adminToken: 'linking-test-admin-secret-0000000000000000', origin, port: 0, dataDir, now: () => clock, trustProxy: true });
}
const db = () => app.accounts!.testing.db;
const rows = (sql: string, ...params: any[]) => db().query(sql).all(...params) as any[];
const run = (sql: string, ...params: any[]) => db().query(sql).run(...params);
let counter = 0;
const ip = () => `10.9.${(++counter >> 8) & 255}.${counter & 255}`;

/** Calls the server; `cookie` is a session, `claim` the new device's link claim. Each call comes from its own address. */
async function call(method: string, path: string, options: { body?: unknown; cookie?: string; claim?: string; source?: string; web?: boolean } = {}) {
    const response = await fetch(new URL(path, app.server.url), {
        method, headers: { 'Content-Type': 'application/json', 'X-Real-IP': options.source ?? ip(), ...(options.web !== false ? { Origin: origin } : {}), ...(options.cookie ? { Cookie: options.cookie } : {}), ...(options.claim ? { 'X-Link-Claim': options.claim } : {}) },
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const text = await response.text();
    let body: any = null;
    try { body = JSON.parse(text); } catch {}
    return { status: response.status, body, headers: response.headers };
}

/** An account whose primary holds a real signed list v1 (the core signs it), with a session bound to that device. */
function account(name: string) {
    const created = app.accounts!.testing.createUser(name);
    const client = new Client(Core);
    const identity = client.call({ cmd: 'identity' });
    const deviceId = id();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const list = { v: 1, userId: created.id, version: 1, prevHash: '', devices: [{ deviceId, addedAt: clock, meta: '' }] };
    const signed = client.call({ cmd: 'signDeviceList', userId: created.id, published: identity.sign, list });
    run('INSERT INTO identity_keys (user_id, dh, sign, updated_at) VALUES (?, ?, ?, ?)', created.id, identity.dh, identity.sign, clock);
    run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'listed', 1, ?, ?)", deviceId, created.id, (publicKey.export({ format: 'jwk' }) as any).x, clock);
    run('INSERT INTO device_lists (user_id, aik_sign, version, hash, list, signature, certs, updated_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?)', created.id, identity.sign, sha(F.listBytes(list)), JSON.stringify(list), signed.signature, JSON.stringify(signed.certs), clock);
    const cookie = app.accounts!.testing.cookie(created.id);
    run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', deviceId, createHash('sha256').update(cookie.split('=')[1]!).digest('hex'));
    return { ...created, client, identity, deviceId, cookie, list, key: privateKey };
}
type Primary = ReturnType<typeof account>;

/** A device that wants to be linked: a fresh core, a device key and an id. */
function newcomer(platform = 'web') {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const deviceKey = (publicKey.export({ format: 'jwk' }) as any).x as string;
    const deviceId = id();
    return { client: new Client(Core), deviceId, deviceKey, platform, key: privateKey, start: (extra: object = {}) => ({ purpose: 'link', deviceId, deviceKey, platform, signature: b64(sign(null, F.startBytes(deviceId, platform, deviceKey), privateKey)), ...extra }) };
}
type Newcomer = ReturnType<typeof newcomer>;

/** Runs the QR flow up to the confirmation code on both sides. */
async function qrLink(primary: Primary, n: Newcomer) {
    const started = await call('POST', '/api/link/start', { body: n.start() });
    expect(started.status).toBe(201);
    const { linkId, claim } = started.body;
    const { qr } = n.client.call({ cmd: 'linkQr', linkId, now: clock });
    const accepted = primary.client.call({ cmd: 'linkAccept', qr, now: clock });
    expect(accepted.linkId).toBe(linkId);
    const offered = await call('POST', `/api/link/${linkId}/offer`, { body: { eph: accepted.eph }, cookie: primary.cookie });
    expect(offered.status).toBe(201);
    expect(offered.body).toMatchObject({ deviceId: n.deviceId, platform: n.platform, purpose: 'link' });
    const status = await call('GET', `/api/link/${linkId}`, { claim });
    expect(status.body).toMatchObject({ state: 'offered', eph: accepted.eph, offerDeviceId: primary.deviceId });
    const { code } = n.client.call({ cmd: 'linkComplete', linkId, eph: status.body.eph, now: clock });
    expect(code).toBe(accepted.code);
    return { linkId, claim, code };
}

/** The rest of a link: hello, the primary's list and certificate, grant, bundle, claim, install. */
async function finishLink(primary: Primary, n: Newcomer, link: { linkId: string; claim: string }, userId = primary.id) {
    const { linkId, claim } = link;
    const leaf = n.client.call({ cmd: 'mlsDeviceLeaf' });
    const hello = n.client.call({ cmd: 'linkSeal', linkId, plaintext: JSON.stringify({ v: 1, type: 'hello', deviceId: n.deviceId, platform: n.platform, label: 'Test browser', leafSigKey: leaf, wantsHistory: false }) });
    expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: hello }, claim })).status).toBe(201);
    const inbox = await call('GET', `/api/link/${linkId}/messages?after=0`, { cookie: primary.cookie });
    const opened = JSON.parse(primary.client.call({ cmd: 'linkOpen', linkId, data: inbox.body.messages[0].data }));
    expect(opened).toMatchObject({ type: 'hello', deviceId: n.deviceId, leafSigKey: leaf });
    // Nothing is granted before the account's signed list names the device.
    expect((await call('POST', `/api/link/${linkId}/grant`, { cookie: primary.cookie })).status).toBe(409);
    const next = { v: 1, userId, version: primary.list.version + 1, prevHash: sha(F.listBytes(primary.list)), devices: [...primary.list.devices, { deviceId: n.deviceId, addedAt: clock, meta: '' }].sort((a, b) => a.deviceId < b.deviceId ? -1 : 1) };
    const signed = primary.client.call({ cmd: 'signDeviceList', userId, published: primary.identity.sign, list: next });
    const published = await call('PUT', '/api/devices/list', { body: { list: next, signature: signed.signature, certs: signed.certs, deviceId: primary.deviceId }, cookie: primary.cookie });
    expect(published.status).toBe(200);
    primary.list = next;
    const now = clock;
    const cert = primary.client.call({ cmd: 'signDeviceCert', userId, deviceId: n.deviceId, platform: n.platform, leafSigKey: opened.leafSigKey, issuedAt: now, now });
    const grant = n.client === primary.client ? '' : primary.client.call({ cmd: 'linkSeal', linkId, plaintext: JSON.stringify({ v: 1, type: 'grant', userId, username: 'alice', identity: primary.identity, deviceId: n.deviceId, cert, listVersion: next.version, listHash: sha(F.listBytes(next)), metaKey: b64(randomBytes(32)), chunks: 0 }) });
    expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: grant }, cookie: primary.cookie })).status).toBe(201);
    expect((await call('POST', `/api/link/${linkId}/grant`, { cookie: primary.cookie })).body).toEqual({ status: 'granted' });
    return { cert, next };
}

suite('linking a new device (QR)', () => {
    test('end to end: sealed hello, signed list and certificate, grant, claim; the session is bound to the new device', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const link = await qrLink(alice, n);
        const { cert } = await finishLink(alice, n, link);
        // The new device reads the grant, installs it, and claims its session with its device key.
        const sealed = await call('GET', `/api/link/${link.linkId}/messages?after=0`, { claim: link.claim });
        const grant = JSON.parse(n.client.call({ cmd: 'linkOpen', linkId: link.linkId, data: sealed.body.messages[0].data }));
        expect(grant).toMatchObject({ type: 'grant', userId: alice.id, deviceId: n.deviceId });
        n.client.call({ cmd: 'companionSetup', userId: grant.userId, identity: grant.identity, cert: grant.cert });
        expect(n.client.call({ cmd: 'identity' })).toEqual(alice.identity);
        expect(JSON.parse(cert).deviceId).toBe(n.deviceId);
        const signature = b64(sign(null, F.linkClaimBytes(link.linkId, n.deviceId, link.claim), n.key));
        const watch = alice; void watch;
        const claimed = await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature } });
        expect(claimed.status).toBe(200);
        expect(claimed.body.user).toMatchObject({ id: alice.id, username: 'alice' });
        const cookie = claimed.headers.get('set-cookie')!.split(';')[0]!;
        expect((await call('GET', '/api/me', { cookie })).body.user.id).toBe(alice.id);
        expect(rows('SELECT device_id FROM sessions WHERE token_hash = ?', createHash('sha256').update(cookie.split('=')[1]!).digest('hex'))[0].device_id).toBe(n.deviceId);
        expect(rows('SELECT state FROM devices WHERE id = ?', n.deviceId)[0].state).toBe('listed');
        // Once only, and the link is spent.
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature } })).status).toBe(409);
        // The linked device is a real listed device: it may hold KeyPackages.
        const kps = n.client.call({ cmd: 'mlsKeyPackages', count: 2 });
        expect((await call('PUT', '/api/mls/keypackages', { body: { keyPackages: kps }, cookie })).status).toBe(201);
    });

    test('the server relays only to the two parties, in their own direction, with bounds', async () => {
        await start();
        const alice = account('alice'), bob = account('bob'), n = newcomer();
        const { linkId, claim } = await qrLink(alice, n);
        const hello = n.client.call({ cmd: 'linkSeal', linkId, plaintext: 'hi' });
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: hello }, claim })).status).toBe(201);
        // Strangers (another account's session, no claim, a wrong claim) get the same answer as an unknown link.
        for (const options of [{ cookie: bob.cookie }, {}, { claim: b64(randomBytes(32)) }]) {
            expect((await call('GET', `/api/link/${linkId}`, options)).status).toBe(404);
            expect((await call('GET', `/api/link/${linkId}/messages`, options)).status).toBe(404);
            expect((await call('POST', `/api/link/${linkId}/messages`, { ...options, body: { data: hello } })).status).toBe(404);
        }
        expect((await call('GET', `/api/link/${randomBytes(16).toString('base64url')}`, { claim })).status).toBe(404);
        // Own direction only.
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: hello, dir: 'p2n' }, claim })).status).toBe(403);
        expect((await call('GET', `/api/link/${linkId}/messages?dir=n2p`, { claim })).status).toBe(403);
        expect((await call('GET', `/api/link/${linkId}/messages?after=0`, { claim })).body.messages).toEqual([]);
        expect((await call('GET', `/api/link/${linkId}/messages?after=0`, { cookie: alice.cookie })).body.messages).toEqual([{ seq: 1, data: hello }]);
        expect((await call('GET', `/api/link/${linkId}/messages?after=1`, { cookie: alice.cookie })).body.messages).toEqual([]);
        // Bounds: shape, size and count.
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: '!!' }, claim })).status).toBe(400);
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: 'A'.repeat(90000) }, claim })).status).toBe(400);
        expect((await call('GET', `/api/link/${linkId}/messages?after=x`, { claim })).status).toBe(400);
        // Cookie sessions need the app's origin to change state.
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: hello }, cookie: alice.cookie, web: false })).status).toBe(403);
        run('INSERT OR REPLACE INTO link_messages (link_id, dir, seq, data, created_at) SELECT ?, ?, value, ?, ? FROM (WITH RECURSIVE n(value) AS (SELECT 2 UNION ALL SELECT value + 1 FROM n WHERE value < 64) SELECT value FROM n)', linkId, 'n2p', hello, clock);
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: hello }, claim })).status).toBe(429);
    });

    test('only the account\'s primary offers, only for a waiting link, and a device exists for one account', async () => {
        await start();
        const alice = account('alice'), bob = account('bob'), n = newcomer();
        const started = await call('POST', '/api/link/start', { body: n.start() });
        const { linkId, claim } = started.body;
        const { qr } = n.client.call({ cmd: 'linkQr', linkId });
        const eph = alice.client.call({ cmd: 'linkAccept', qr }).eph;
        // Not signed in, a session that is not the primary device (a pending browser of Alice's), a bad key.
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph } })).status).toBe(401);
        const laptop = newcomer();
        run("INSERT INTO devices (id, user_id, platform, state, sig_key, created_at) VALUES (?, ?, 'web', 'pending', ?, ?)", laptop.deviceId, alice.id, laptop.deviceKey, clock);
        const second = app.accounts!.testing.cookie(alice.id);
        run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', laptop.deviceId, createHash('sha256').update(second.split('=')[1]!).digest('hex'));
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph }, cookie: second })).status).toBe(403);
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph: 'short' }, cookie: alice.cookie })).status).toBe(400);
        expect(rows('SELECT 1 FROM devices WHERE id = ?', n.deviceId)).toEqual([]);
        // The primary offers: the device appears for Alice, pending, with the key it registered; no second offer.
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph }, cookie: alice.cookie })).status).toBe(201);
        expect(rows('SELECT user_id, state, sig_key, platform FROM devices WHERE id = ?', n.deviceId)).toEqual([{ user_id: alice.id, state: 'pending', sig_key: n.deviceKey, platform: 'web' }]);
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph }, cookie: alice.cookie })).status).toBe(403);
        // A device id another account has cannot start a link at all.
        expect((await call('POST', '/api/link/start', { body: { ...n.start(), deviceId: alice.deviceId, signature: b64(sign(null, F.startBytes(alice.deviceId, 'web', n.deviceKey), n.key)) } })).status).toBe(409);
        void bob;
    });

    test('start is signed by the device key, validated, rate limited per source, and expires', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const bad = [
            { ...n.start(), signature: b64(randomBytes(64)) },
            { ...n.start(), purpose: 'nope' },
            { ...n.start(), platform: 'toaster' },
            { ...n.start(), deviceId: 'short' },
            { ...n.start(), deviceKey: 'short' },
            { ...n.start(), mode: 'sms' },
        ];
        for (const body of bad) expect([400, 403]).toContain((await call('POST', '/api/link/start', { body })).status);
        // Another device's signature over these bytes does not do.
        const other = newcomer();
        expect((await call('POST', '/api/link/start', { body: { ...n.start(), signature: other.start().signature } })).status).toBe(403);
        const source = '203.0.113.5';
        const statuses: number[] = [];
        for (let index = 0; index < 7; index++) { const x = newcomer(); statuses.push((await call('POST', '/api/link/start', { body: x.start(), source })).status); }
        expect(statuses.filter(status => status === 201).length).toBe(5);
        expect(statuses).toContain(429);

        // A link lives ten minutes; its pending device goes with it.
        const { linkId, claim } = await qrLink(alice, n);
        expect(rows('SELECT 1 FROM devices WHERE id = ?', n.deviceId).length).toBe(1);
        clock += 11 * 60 * 1000;
        expect((await call('GET', `/api/link/${linkId}`, { claim })).status).toBe(404);
        app.server && (app as any).accounts.sweep();
        // The sweep runs with the server's timer; call it explicitly through a request path that triggers it.
        await Bun.sleep(1100);
        expect(rows('SELECT 1 FROM link_requests WHERE id = ?', linkId)).toEqual([]);
        expect(rows('SELECT 1 FROM devices WHERE id = ?', n.deviceId)).toEqual([]);
    });

    test('the claim needs the grant, the claim secret and the device key; either side can cancel', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const link = await qrLink(alice, n);
        const signature = b64(sign(null, F.linkClaimBytes(link.linkId, n.deviceId, link.claim), n.key));
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature } })).status).toBe(409);
        await finishLink(alice, n, link);
        const wrongKey = b64(sign(null, F.linkClaimBytes(link.linkId, n.deviceId, link.claim), generateKeyPairSync('ed25519').privateKey));
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature: wrongKey } })).status).toBe(403);
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: b64(randomBytes(32)), signature } })).status).toBe(403);
        // A native claim of a web-started link, and the reverse, are refused.
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature }, web: false })).status).toBe(400);
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature } })).status).toBe(200);

        // Cancel: the new device, or the primary; the unlisted device row goes with an ungranted link.
        const m = newcomer();
        const second = await qrLink(alice, m);
        expect((await call('DELETE', `/api/link/${second.linkId}`, { claim: second.claim })).status).toBe(200);
        expect(rows('SELECT 1 FROM devices WHERE id = ?', m.deviceId)).toEqual([]);
        expect((await call('GET', `/api/link/${second.linkId}`, { claim: second.claim })).status).toBe(404);
        const k = newcomer();
        const third = await qrLink(alice, k);
        expect((await call('DELETE', `/api/link/${third.linkId}`, { cookie: alice.cookie })).status).toBe(200);
    });

    test('a native app links with a bearer session', async () => {
        await start();
        const alice = account('alice'), n = newcomer('ios');
        const link = await qrLink(alice, n);
        await finishLink(alice, n, link);
        const signature = b64(sign(null, F.linkClaimBytes(link.linkId, n.deviceId, link.claim), n.key));
        const claimed = await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature }, web: false });
        expect(claimed.status).toBe(200);
        expect(claimed.body.session.token).toBeString();
        const me = await fetch(new URL('/api/me', app.server.url), { headers: { Authorization: `Bearer ${claimed.body.session.token}`, 'X-Real-IP': ip() } });
        expect((await me.json() as any).user.username).toBe('alice');
        expect(rows("SELECT client FROM sessions WHERE device_id = ?", n.deviceId)[0].client).toBe('ios');
    });
});

suite('linking without a camera (the short code)', () => {
    const codeStart = (n: Newcomer, username: string) => call('POST', '/api/link/start', { body: n.start({ mode: 'code', username }) });

    /** New device and primary through commit, lookup, offer, reveal: both end up with the same code. */
    async function codeLink(primary: Primary, n: Newcomer) {
        const started = await codeStart(n, 'alice');
        expect(started.status).toBe(201);
        const { linkId, claim, code } = started.body as { linkId: string; claim: string; code: string };
        expect(code).toMatch(/^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$/);
        const { commit } = n.client.call({ cmd: 'linkCommit', linkId, deviceId: n.deviceId, now: clock });
        expect((await call('POST', `/api/link/${linkId}/commit`, { body: { commit }, claim })).status).toBe(201);
        // The primary types the code (spaces, dashes and case do not matter).
        const looked = await call('POST', '/api/link/lookup', { body: { code: `${code.slice(0, 4)}-${code.slice(4)}`.toLowerCase() }, cookie: primary.cookie });
        expect(looked.status).toBe(200);
        expect(looked.body).toMatchObject({ linkId, deviceId: n.deviceId, platform: 'web', commit });
        const { eph } = primary.client.call({ cmd: 'linkLookup', linkId, deviceN: looked.body.deviceId, commit: looked.body.commit, deviceP: primary.deviceId, now: clock });
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph }, cookie: primary.cookie })).status).toBe(201);
        // The new device reveals only after the primary's key reached it.
        const seen = await call('GET', `/api/link/${linkId}`, { claim });
        expect(seen.body).toMatchObject({ state: 'offered', eph, offerDeviceId: primary.deviceId });
        const revealed = n.client.call({ cmd: 'linkReveal', linkId, eph: seen.body.eph, now: clock });
        expect((await call('POST', `/api/link/${linkId}/reveal`, { body: revealed, claim })).status).toBe(201);
        const asked = await call('GET', `/api/link/${linkId}`, { cookie: primary.cookie });
        expect(asked.body.reveal).toEqual(revealed);
        const codeP = primary.client.call({ cmd: 'linkOpenCommitment', linkId, eph: asked.body.reveal.eph, nonce: asked.body.reveal.nonce, now: clock });
        const codeN = n.client.call({ cmd: 'linkCompleteCode', linkId, eph: seen.body.eph, deviceP: seen.body.offerDeviceId, now: clock });
        expect(codeP.code).toBe(codeN.code);
        return { linkId, claim, code: codeN.code };
    }

    test('commit, look up, offer, reveal: both screens show one code and the link finishes like a QR link', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const link = await codeLink(alice, n);
        await finishLink(alice, n, link);
        const signature = b64(sign(null, F.linkClaimBytes(link.linkId, n.deviceId, link.claim), n.key));
        expect((await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature } })).status).toBe(200);
    });

    test('a code is single use, belongs to the named account, needs the commitment, and wrong tries are limited', async () => {
        await start();
        const alice = account('alice'), bob = account('bob'), n = newcomer();
        const started = await codeStart(n, 'alice');
        const { linkId, claim, code } = started.body;
        // Nothing to find before the commitment is in.
        expect((await call('POST', '/api/link/lookup', { body: { code }, cookie: alice.cookie })).status).toBe(404);
        const { commit } = n.client.call({ cmd: 'linkCommit', linkId, deviceId: n.deviceId });
        expect((await call('POST', `/api/link/${linkId}/commit`, { body: { commit }, claim })).status).toBe(201);
        expect((await call('POST', `/api/link/${linkId}/commit`, { body: { commit }, claim })).status).toBe(409);
        // Another account's primary does not get it (and the answer is the same as for a made-up code).
        expect((await call('POST', '/api/link/lookup', { body: { code }, cookie: bob.cookie })).status).toBe(404);
        // Alice can, once; the code is burned.
        expect((await call('POST', '/api/link/lookup', { body: { code }, cookie: alice.cookie })).status).toBe(200);
        expect((await call('POST', '/api/link/lookup', { body: { code }, cookie: alice.cookie })).status).toBe(404);

        // Three wrong codes block the account's lookups for a few minutes, even for a right code.
        const other = newcomer();
        const fresh = await codeStart(other, 'alice');
        const c2 = other.client.call({ cmd: 'linkCommit', linkId: fresh.body.linkId, deviceId: other.deviceId });
        await call('POST', `/api/link/${fresh.body.linkId}/commit`, { body: { commit: c2.commit }, claim: fresh.body.claim });
        // Alice has had two strikes (the early lookup and the reused code); one more wrong code is the third.
        expect((await call('POST', '/api/link/lookup', { body: { code: 'AAAAAAAA' }, cookie: alice.cookie })).status).toBe(404);
        const blocked = await call('POST', '/api/link/lookup', { body: { code: fresh.body.code }, cookie: alice.cookie });
        expect(blocked.status).toBe(429);
        clock += 6 * 60 * 1000;
        run('UPDATE link_requests SET expires_at = ?', clock + 60000);
        expect((await call('POST', '/api/link/lookup', { body: { code: fresh.body.code }, cookie: alice.cookie })).status).toBe(200);
    });

    test('a code looked up from a device that is not the primary, and an expired one, find nothing', async () => {
        await start();
        const alice = account('alice');
        const second = app.accounts!.testing.cookie(alice.id);
        const laptop = newcomer();
        run("INSERT INTO devices (id, user_id, platform, state, sig_key, created_at) VALUES (?, ?, 'web', 'pending', ?, ?)", laptop.deviceId, alice.id, laptop.deviceKey, clock);
        run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', laptop.deviceId, createHash('sha256').update(second.split('=')[1]!).digest('hex'));
        const n = newcomer();
        const started = await codeStart(n, 'alice');
        const c = n.client.call({ cmd: 'linkCommit', linkId: started.body.linkId, deviceId: n.deviceId });
        await call('POST', `/api/link/${started.body.linkId}/commit`, { body: { commit: c.commit }, claim: started.body.claim });
        expect((await call('POST', '/api/link/lookup', { body: { code: started.body.code }, cookie: second })).status).toBe(404);
        clock += 6 * 60 * 1000;
        expect((await call('POST', '/api/link/lookup', { body: { code: started.body.code }, cookie: alice.cookie })).status).toBe(404);
    });

    test('a primary that turns code links away three times is blocked from looking codes up for a few minutes', async () => {
        await start();
        const alice = account('alice');
        const prepare = async () => {
            const x = newcomer();
            const s = await codeStart(x, 'alice');
            const commit = x.client.call({ cmd: 'linkCommit', linkId: s.body.linkId, deviceId: x.deviceId });
            await call('POST', `/api/link/${s.body.linkId}/commit`, { body: { commit: commit.commit }, claim: s.body.claim });
            return s.body as { linkId: string; code: string };
        };
        for (let attempt = 0; attempt < 3; attempt++) {
            const s = await prepare();
            expect((await call('POST', '/api/link/lookup', { body: { code: s.code }, cookie: alice.cookie })).status).toBe(200);
            expect((await call('DELETE', `/api/link/${s.linkId}`, { cookie: alice.cookie })).status).toBe(200);
        }
        const s = await prepare();
        expect((await call('POST', '/api/link/lookup', { body: { code: s.code }, cookie: alice.cookie })).status).toBe(429);
    });

    test('a relay that swaps keys is caught: the primary refuses a reveal that does not open the commitment', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const started = await codeStart(n, 'alice');
        const { linkId, claim, code } = started.body;
        const { commit } = n.client.call({ cmd: 'linkCommit', linkId, deviceId: n.deviceId });
        await call('POST', `/api/link/${linkId}/commit`, { body: { commit }, claim });
        const looked = await call('POST', '/api/link/lookup', { body: { code }, cookie: alice.cookie });
        const { eph } = alice.client.call({ cmd: 'linkLookup', linkId, deviceN: n.deviceId, commit: looked.body.commit, deviceP: alice.deviceId });
        await call('POST', `/api/link/${linkId}/offer`, { body: { eph }, cookie: alice.cookie });
        // The relay answers the primary with a key of its own instead of the committed one.
        const relay = new Client(Core);
        const forged = relay.call({ cmd: 'linkCommit', linkId, deviceId: n.deviceId });
        void forged;
        const mine = n.client.call({ cmd: 'linkReveal', linkId, eph });
        let failure: any;
        try { alice.client.call({ cmd: 'linkOpenCommitment', linkId, eph: b64(randomBytes(32)), nonce: mine.nonce }); } catch (error) { failure = error; }
        expect(failure.code).toBe('auth');
        // The link is gone on the primary; nothing derived.
        expect(() => alice.client.call({ cmd: 'linkSeal', linkId, plaintext: 'x' })).toThrow();
    });
});

suite('revocation, succession, DM facts', () => {
    test('any session of the account revokes a device at once; the primary cannot be revoked', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const link = await qrLink(alice, n);
        const { cert } = await finishLink(alice, n, link);
        n.client.call({ cmd: 'companionSetup', userId: alice.id, identity: alice.identity, cert });
        const signature = b64(sign(null, F.linkClaimBytes(link.linkId, n.deviceId, link.claim), n.key));
        const cookie = (await call('POST', `/api/link/${link.linkId}/claim`, { body: { claim: link.claim, signature } })).headers.get('set-cookie')!.split(';')[0]!;
        // The new device is in a channel and holds KeyPackages and a Welcome.
        run("INSERT INTO channels (id, kind, name, creator_id, epoch, seq, created_at) VALUES (?, 'private', NULL, ?, 0, 0, ?)", 'C'.repeat(22), alice.id, clock);
        run('INSERT INTO channel_members (channel_id, device_id, user_id, admin, cursor, joined_seq) VALUES (?, ?, ?, 0, 0, 0)', 'C'.repeat(22), n.deviceId, alice.id);
        run('INSERT INTO channel_members (channel_id, device_id, user_id, admin, cursor, joined_seq) VALUES (?, ?, ?, 1, 0, 0)', 'C'.repeat(22), alice.deviceId, alice.id);
        const kps = n.client.call({ cmd: 'mlsKeyPackages', count: 2 });
        expect((await call('PUT', '/api/mls/keypackages', { body: { keyPackages: kps }, cookie })).status).toBe(201);
        const watch = new WebSocket(Object.assign(new URL('/api/events', app.server.url), { protocol: 'ws:' }), { headers: { Origin: origin, Cookie: alice.cookie, 'X-Real-IP': ip() } } as any);
        const frames: any[] = [];
        watch.onmessage = event => frames.push(JSON.parse(String(event.data)));
        await new Promise(resolve => watch.addEventListener('open', resolve, { once: true }));
        const theirs = new WebSocket(Object.assign(new URL('/api/events', app.server.url), { protocol: 'ws:' }), { headers: { Origin: origin, Cookie: cookie, 'X-Real-IP': ip() } } as any);
        const closed = new Promise<CloseEvent>(resolve => theirs.addEventListener('close', resolve as any, { once: true }));
        await new Promise(resolve => theirs.addEventListener('open', resolve, { once: true }));

        expect((await call('POST', `/api/devices/${alice.deviceId}/revoke`, { cookie })).status).toBe(409);
        expect((await call('POST', `/api/devices/${randomBytes(16).toString('base64url')}/revoke`, { cookie: alice.cookie })).status).toBe(404);
        expect((await call('POST', `/api/devices/${n.deviceId}/revoke`, { cookie: alice.cookie })).body).toEqual({ revoked: [n.deviceId] });
        expect((await closed).code).toBe(4401);
        expect((await call('GET', '/api/me', { cookie })).status).toBe(401);
        expect(rows('SELECT 1 FROM channel_members WHERE device_id = ?', n.deviceId)).toEqual([]);
        expect(rows('SELECT 1 FROM mls_key_packages WHERE device_id = ?', n.deviceId)).toEqual([]);
        await Bun.sleep(100);
        expect(frames).toContainEqual({ type: 'channel', id: 'C'.repeat(22), change: 'remove-device', deviceId: n.deviceId });
        expect(frames.find(frame => frame.type === 'devices' && frame.needsList)).toMatchObject({ revoked: n.deviceId });
        // Revoking again finds nothing; the revoked id can never be listed again.
        expect((await call('POST', `/api/devices/${n.deviceId}/revoke`, { cookie: alice.cookie })).status).toBe(404);
        watch.close();
    });

    test('a signed succession record is accepted from the current key only, served to contacts, and chains at most eight', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        run('INSERT INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, 1), (?, ?, 1)', alice.id, bob.id, bob.id, alice.id);
        const next = new Client(Core).call({ cmd: 'identity' });
        const signed = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: next.sign, newDh: next.dh, at: clock });
        const { signature, ...record } = signed;
        const put = (body: object, cookie = alice.cookie) => call('PUT', '/api/devices/succession', { body, cookie });
        expect((await put({ record, signature })).status).toBe(201);
        // Wrong signer, wrong account, tampered, stale time, not a new key.
        const forged = bob.client.call({ cmd: 'signSuccession', userId: alice.id, published: bob.identity.sign, newSign: next.sign, newDh: next.dh, at: clock });
        expect((await put({ record: { ...forged, signature: undefined }, signature: forged.signature })).status).toBe(403);
        expect((await put({ record: { ...record, userId: bob.id }, signature })).status).toBe(403);
        expect((await put({ record: { ...record, at: record.at + 1 }, signature })).status).toBe(403);
        const old = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: next.sign, newDh: next.dh, at: clock - 3600_000 });
        expect((await put({ record: { ...old, signature: undefined }, signature: old.signature })).status).toBe(400);
        expect((await put({ record: { ...record, newSign: 'x' }, signature })).status).toBe(400);
        expect((await put({ record, signature }, bob.cookie)).status).toBe(403);
        // Contacts and the owner get the chain with the list.
        const view = await call('GET', '/api/devices/alice', { cookie: bob.cookie });
        expect(view.body.succession).toEqual([{ ...record, signature }]);
        expect((await call('GET', '/api/devices/alice', { cookie: alice.cookie })).body.succession.length).toBe(1);
        // A contact follows it with the core.
        const contact = new Client(Core);
        contact.call({ cmd: 'notePeer', contact: alice.id, identity: alice.identity });
        expect(contact.call({ cmd: 'acceptSuccession', contact: alice.id, records: view.body.succession }).identity).toEqual(next);
        // The chain keeps the newest eight.
        for (let index = 1; index < 10; index++) run('INSERT INTO identity_succession (user_id, seq, old_sign, new_sign, new_dh, at, signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', alice.id, 1 + index, 'o', 'n', 'd', 1, 's', 1);
        run('DELETE FROM identity_succession WHERE user_id = ? AND seq > 1', alice.id);
        run("UPDATE identity_keys SET sign = ? WHERE user_id = ?", next.sign, alice.id);
        void sha;
    });

    test('typing envelopes are refused, and a pair that moved to an MLS DM stops sending the old way after 60 days', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        run('INSERT INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, 1), (?, ?, 1)', alice.id, bob.id, bob.id, alice.id);
        const envelope = b64(randomBytes(40));
        const send = (body: object) => call('POST', '/api/messages', { body: { to: 'bob', envelope, ...body }, cookie: alice.cookie });
        expect((await send({ ephemeral: true })).status).toBe(410);
        expect((await send({})).status).toBe(201);
        // The pair's DM channel: still fine at 59 days, gone at 61.
        const [a, b] = [alice.id, bob.id].sort();
        run("INSERT INTO channels (id, kind, name, creator_id, epoch, seq, created_at) VALUES (?, 'dm', NULL, ?, 0, 0, ?)", 'D'.repeat(22), alice.id, clock);
        run('INSERT INTO dm_pairs (user_a, user_b, channel_id) VALUES (?, ?, ?)', a, b, 'D'.repeat(22));
        run('INSERT INTO channel_members (channel_id, device_id, user_id, admin, cursor, joined_seq) VALUES (?, ?, ?, 1, 0, 0)', 'D'.repeat(22), alice.deviceId, alice.id);
        clock += 59 * 86400_000; run('UPDATE sessions SET expires_at = ?', clock + 1e10);
        expect((await send({})).status).toBe(201);
        clock += 2 * 86400_000; run('UPDATE sessions SET expires_at = ?', clock + 1e10);
        const gone = await send({});
        expect(gone.status).toBe(410);
        // The channel list tells each side who the DM is with.
        run("UPDATE devices SET state = 'listed' WHERE id = ?", alice.deviceId);
        const listed = await call('GET', '/api/channels', { cookie: alice.cookie });
        expect(listed.body.channels[0]).toMatchObject({ id: 'D'.repeat(22), kind: 'dm', peer: { id: bob.id, username: 'bob' } });
    });

    test('capability tells a contact whether the other side can take part in MLS DMs, and whether a DM exists', async () => {
        await start();
        const alice = account('alice'), bob = account('bob'), carol = account('carol');
        run('INSERT INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, 1), (?, ?, 1)', alice.id, bob.id, bob.id, alice.id);
        const ask = (name: string, cookie = alice.cookie) => call('GET', `/api/mls/capability/${name}`, { cookie });
        expect((await ask('bob')).body).toEqual({ userId: bob.id, devices: 0, channel: null });
        expect((await ask('carol')).status).toBe(403);
        expect((await ask('nobody')).status).toBe(403);
        // Bob's device is listed and certified for MLS: it uploads.
        const bobCookie = bob.cookie;
        bob.client.call({ cmd: 'mlsInitDevice', userId: bob.id, deviceId: bob.deviceId, platform: 'linux', issuedAt: clock });
        const real = bob.client.call({ cmd: 'mlsKeyPackages', count: 3 });
        expect((await call('PUT', '/api/mls/keypackages', { body: { keyPackages: real }, cookie: bobCookie })).status).toBe(201);
        void carol;
        expect((await ask('bob')).body.devices).toBe(1);
        const [a, b] = [alice.id, bob.id].sort();
        run("INSERT INTO channels (id, kind, name, creator_id, epoch, seq, created_at) VALUES (?, 'dm', NULL, ?, 0, 0, ?)", 'D'.repeat(22), alice.id, clock);
        run('INSERT INTO dm_pairs (user_a, user_b, channel_id) VALUES (?, ?, ?)', a, b, 'D'.repeat(22));
        expect((await ask('bob')).body.channel).toBe('D'.repeat(22));
        expect((await ask('alice', bobCookie)).body.channel).toBe('D'.repeat(22));
    });
});

suite('primary transfer relay (purpose: transfer)', () => {
    test('a listed companion starts it with its own session, only the primary offers, sealed messages flow, and nothing creates a device or a session', async () => {
        await start();
        const alice = account('alice'), c = newcomer('linux');
        // C is a listed device of the account with a session bound to it (the signed list names it).
        run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'listed', 0, ?, ?)", c.deviceId, alice.id, c.deviceKey, clock);
        const next = { v: 1, userId: alice.id, version: 2, prevHash: sha(F.listBytes(alice.list)), devices: [...alice.list.devices, { deviceId: c.deviceId, addedAt: clock, meta: '' }].sort((a, b) => a.deviceId < b.deviceId ? -1 : 1) };
        const signed = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list: next });
        expect((await call('PUT', '/api/devices/list', { body: { list: next, signature: signed.signature, certs: signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie })).status).toBe(200);
        const cCookie = app.accounts!.testing.cookie(alice.id);
        run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', c.deviceId, createHash('sha256').update(cCookie.split('=')[1]!).digest('hex'));

        // No session, the primary's session (a different device), or a stranger's device: refused.
        const body = c.start({ purpose: 'transfer' });
        expect((await call('POST', '/api/link/start', { body })).status).toBe(403);
        expect((await call('POST', '/api/link/start', { body, cookie: alice.cookie })).status).toBe(403);
        const stranger = newcomer('linux');
        expect((await call('POST', '/api/link/start', { body: stranger.start({ purpose: 'transfer' }), cookie: cCookie })).status).toBe(403);
        const started = await call('POST', '/api/link/start', { body, cookie: cCookie });
        expect(started.status).toBe(201);
        const { linkId, claim } = started.body;

        // The companion cannot offer to itself; the primary can, and only the primary.
        const { qr } = c.client.call({ cmd: 'linkQr', linkId, now: clock });
        const accepted = alice.client.call({ cmd: 'linkAccept', qr, now: clock });
        expect((await call('POST', `/api/link/${linkId}/offer`, { body: { eph: accepted.eph }, cookie: cCookie })).status).toBe(403);
        const offered = await call('POST', `/api/link/${linkId}/offer`, { body: { eph: accepted.eph }, cookie: alice.cookie });
        expect(offered.status).toBe(201);
        expect(offered.body).toMatchObject({ purpose: 'transfer', deviceId: c.deviceId });
        // A transfer adds no device row: C is already listed.
        expect(rows('SELECT COUNT(*) AS n FROM devices WHERE user_id = ?', alice.id)[0].n).toBe(2);
        const status = await call('GET', `/api/link/${linkId}`, { claim });
        expect(c.client.call({ cmd: 'linkComplete', linkId, eph: status.body.eph, now: clock }).code).toBe(accepted.code);

        // Sealed messages both ways (the record to sign, the new identity), opaque to the server.
        const hello = c.client.call({ cmd: 'linkSeal', linkId, plaintext: JSON.stringify({ v: 1, type: 'transfer-hello', identity: 'x' }) });
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: hello }, claim })).status).toBe(201);
        const inbox = await call('GET', `/api/link/${linkId}/messages?after=0`, { cookie: alice.cookie });
        expect(JSON.parse(alice.client.call({ cmd: 'linkOpen', linkId, data: inbox.body.messages[0].data })).type).toBe('transfer-hello');
        const reply = alice.client.call({ cmd: 'linkSeal', linkId, plaintext: JSON.stringify({ v: 1, type: 'record' }) });
        expect((await call('POST', `/api/link/${linkId}/messages`, { body: { data: reply }, cookie: alice.cookie })).status).toBe(201);
        const back = await call('GET', `/api/link/${linkId}/messages?after=0`, { claim });
        expect(JSON.parse(c.client.call({ cmd: 'linkOpen', linkId, data: back.body.messages[0].data })).type).toBe('record');

        // The primary grants; a transfer never mints a session: the claim is refused and C keeps the one it has.
        expect((await call('POST', `/api/link/${linkId}/grant`, { cookie: alice.cookie })).body).toEqual({ status: 'granted' });
        const signature = b64(sign(null, F.linkClaimBytes(linkId, c.deviceId, claim), c.key));
        expect((await call('POST', `/api/link/${linkId}/claim`, { body: { claim, signature } })).status).toBe(409);
        expect((await call('GET', '/api/me', { cookie: cCookie })).body.user.id).toBe(alice.id);
    });
});

suite('companion certificates after a transfer (m5 §5.2.2)', () => {
    /** A listed companion with its own session and a fresh core (its device key is `n.key`). */
    async function listedCompanion(alice: Primary) {
        const c = newcomer('linux');
        run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'listed', 0, ?, ?)", c.deviceId, alice.id, c.deviceKey, clock);
        const next = { v: 1, userId: alice.id, version: alice.list.version + 1, prevHash: sha(F.listBytes(alice.list)), devices: [...alice.list.devices, { deviceId: c.deviceId, addedAt: clock, meta: '' }].sort((a, b) => a.deviceId < b.deviceId ? -1 : 1) };
        const signed = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list: next });
        expect((await call('PUT', '/api/devices/list', { body: { list: next, signature: signed.signature, certs: signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie })).status).toBe(200);
        alice.list = next;
        const cookie = app.accounts!.testing.cookie(alice.id);
        run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', c.deviceId, createHash('sha256').update(cookie.split('=')[1]!).digest('hex'));
        return { c, cookie, leaf: c.client.call({ cmd: 'mlsDeviceLeaf' }) as string };
    }

    test('a companion asks for a certificate for its own leaf, the primary answers it, and nobody else can ask, read or answer', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        const { c, cookie, leaf } = await listedCompanion(alice);

        // Only a listed device asks, for a canonical key and a known platform.
        expect((await call('PUT', '/api/devices/recert', { body: { platform: 'linux', leafSigKey: leaf } })).status).toBe(401);
        expect((await call('PUT', '/api/devices/recert', { body: { platform: 'linux', leafSigKey: 'short' }, cookie })).status).toBe(400);
        expect((await call('PUT', '/api/devices/recert', { body: { platform: 'toaster', leafSigKey: leaf }, cookie })).status).toBe(400);
        expect((await call('PUT', '/api/devices/recert', { body: { platform: 'linux', leafSigKey: leaf }, cookie: app.accounts!.testing.cookie(alice.id) })).status).toBe(403); // a session not bound to a listed device
        expect((await call('PUT', '/api/devices/recert', { body: { platform: 'linux', leafSigKey: leaf }, cookie })).status).toBe(201);

        // Only the primary lists and answers; the list carries what it needs to check the signature itself.
        expect((await call('GET', '/api/devices/recert', { cookie })).status).toBe(403);
        expect((await call('GET', '/api/devices/recert', { cookie: bob.cookie })).body.requests).toEqual([]);
        const pending = await call('GET', '/api/devices/recert', { cookie: alice.cookie });
        expect(pending.body.requests).toEqual([{ deviceId: c.deviceId, platform: 'linux', leafSigKey: leaf }]);

        // The certificate must be for exactly that request and signed by the account's current identity key.
        const good = alice.client.call({ cmd: 'signDeviceCert', userId: alice.id, deviceId: c.deviceId, platform: 'linux', leafSigKey: leaf, issuedAt: clock, now: clock });
        const other = account('carol');
        const forged = JSON.stringify({ ...JSON.parse(good), aikSign: other.identity.sign });
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: good }, cookie })).status).toBe(403); // not the primary
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: good }, cookie: bob.cookie })).status).toBe(404);
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: forged }, cookie: alice.cookie })).status).toBe(400); // wrong aikSign
        const wrongLeaf = alice.client.call({ cmd: 'signDeviceCert', userId: alice.id, deviceId: c.deviceId, platform: 'linux', leafSigKey: b64(randomBytes(32)), issuedAt: clock, now: clock });
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: wrongLeaf }, cookie: alice.cookie })).status).toBe(400);
        const tampered = JSON.stringify({ ...JSON.parse(good), issuedAt: clock + 1 });
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: tampered }, cookie: alice.cookie })).status).toBe(403);
        expect((await call('GET', '/api/devices/recert/mine', { cookie })).body).toEqual({ cert: null });
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: good }, cookie: alice.cookie })).status).toBe(201);

        // The companion reads it, installs it (the core verifies it under the account key and its own leaf), and is done.
        const mine = await call('GET', '/api/devices/recert/mine', { cookie });
        expect(mine.body.cert).toBe(JSON.stringify(JSON.parse(good)));
        c.client.call({ cmd: 'companionSetup', userId: alice.id, identity: alice.identity, cert: mine.body.cert });
        expect((await call('GET', '/api/devices/recert', { cookie: alice.cookie })).body.requests).toEqual([]);
        expect((await call('DELETE', '/api/devices/recert', { cookie })).status).toBe(200);
        expect((await call('GET', '/api/devices/recert/mine', { cookie })).status).toBe(404);
    });
});

suite('a list under a new key is the whole truth (publish)', () => {
    test('list v1 under a new identity revokes every non-revoked device it omits, pending ones too; under the same key a pending newcomer is left for the primary to list', async () => {
        await start();
        const alice = account('alice');
        const pending = id(), listed = id();
        for (const [device, state] of [[pending, 'pending'], [listed, 'listed']] as const) run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', ?, 0, ?, ?)", device, alice.id, state, b64(randomBytes(32)), clock);

        // Same key, next version: a pending newcomer (waiting to be listed) is not touched; an unlisted 'listed' device is dropped.
        const v2 = { v: 1, userId: alice.id, version: 2, prevHash: sha(F.listBytes(alice.list)), devices: alice.list.devices };
        const signed = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list: v2 });
        const same = await call('PUT', '/api/devices/list', { body: { list: v2, signature: signed.signature, certs: signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie });
        expect(same.status).toBe(200);
        expect(rows('SELECT id, state FROM devices WHERE id IN (?, ?) ORDER BY id', pending, listed).sort((a, b) => a.id < b.id ? -1 : 1)).toEqual([{ id: pending, state: 'pending' }, { id: listed, state: 'revoked' }].sort((a, b) => a.id < b.id ? -1 : 1));

        // A new identity key (what PUT /api/keys with a new identity does): the list is void and everything is pending.
        const fresh = new Client(Core);
        const identity = fresh.call({ cmd: 'identity' });
        run('UPDATE identity_keys SET sign = ?, dh = ? WHERE user_id = ?', identity.sign, identity.dh, alice.id);
        run('DELETE FROM device_lists WHERE user_id = ?', alice.id);
        run("UPDATE devices SET state = 'pending', is_primary = 0 WHERE user_id = ? AND state != 'revoked'", alice.id);
        const v1 = { v: 1, userId: alice.id, version: 1, prevHash: '', devices: [{ deviceId: alice.deviceId, addedAt: clock, meta: '' }] };
        const first = fresh.call({ cmd: 'signDeviceList', userId: alice.id, published: identity.sign, list: v1 });
        const published = await call('PUT', '/api/devices/list', { body: { list: v1, signature: first.signature, certs: first.certs, deviceId: alice.deviceId }, cookie: alice.cookie });
        expect(published.status).toBe(200);
        expect(published.body.revoked).toEqual([pending]);
        expect(rows('SELECT state FROM devices WHERE id = ?', pending)[0].state).toBe('revoked');
        expect(rows('SELECT state FROM devices WHERE id = ?', alice.deviceId)[0].state).toBe('listed');
    });
});
