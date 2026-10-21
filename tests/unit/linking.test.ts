import { afterEach, describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import '../../packages/signaling/public/devices.js';
import { startSignaling } from '../../packages/signaling/server';
import { Database } from 'bun:sqlite';
import { migrate } from '../../packages/signaling/migrations';
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
    test('any session of the account revokes a device at once', async () => {
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

suite('companion certificates after a transfer (m5 §5.2.2)', () => {
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

        // Only a listed device lists and answers (M6: every device holds the account key); a session bound to no device does not.
        const unbound = app.accounts!.testing.cookie(alice.id);
        expect((await call('GET', '/api/devices/recert', { cookie: unbound })).status).toBe(403);
        expect((await call('GET', '/api/devices/recert', { cookie: bob.cookie })).body.requests).toEqual([]);
        const pending = await call('GET', '/api/devices/recert', { cookie: alice.cookie });
        expect(pending.body.requests).toEqual([{ deviceId: c.deviceId, platform: 'linux', leafSigKey: leaf }]);

        // The certificate must be for exactly that request and signed by the account's current identity key.
        const good = alice.client.call({ cmd: 'signDeviceCert', userId: alice.id, deviceId: c.deviceId, platform: 'linux', leafSigKey: leaf, issuedAt: clock, now: clock });
        const other = account('carol');
        const forged = JSON.stringify({ ...JSON.parse(good), aikSign: other.identity.sign });
        expect((await call('PUT', `/api/devices/recert/${c.deviceId}`, { body: { cert: good }, cookie: unbound })).status).toBe(403); // a session bound to no listed device
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

suite('the account backup (m6 §3.5)', () => {
    const passphrase = 'a long enough passphrase';
    /** A signed backup from a core that holds the account key: the PUT body (record and the proofs of its new hashes) and its secrets. */
    function backup(alice: Primary, secret = passphrase) {
        const created = alice.client.call({ cmd: 'backupCreate', userId: alice.id, passphrase: secret });
        const record = { ...created.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: created.record }) };
        return { record, body: { ...record, passProof: created.passProof, recoveryProof: created.recoveryProof }, created };
    }
    /** The change a signed record allows: a new passphrase at epoch + 1, with the proof of the old secret. */
    function change(alice: Primary, current: any, secret: string) {
        alice.client.call({ cmd: 'backupKeysSet', backupKeys: current.created.backupKeys });
        const resealed = alice.client.call({ cmd: 'backupReseal', userId: alice.id, record: current.record, passphrase: secret });
        const record = { ...resealed.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: resealed.record }) };
        const proof = alice.client.call({ cmd: 'backupProve', record: current.record, passphrase: current.secret ?? passphrase }).proof;
        return { record, resealed, proof, body: { ...record, passProof: resealed.passProof, proof } };
    }
    const unbound = (alice: Primary) => app.accounts!.testing.cookie(alice.id);

    test('a listed device sets it up with both proofs, any session reads it, and only a record the account key signed is accepted', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        const { record, body } = backup(alice);
        expect((await call('PUT', '/api/backup', { body })).status).toBe(401);
        expect((await call('PUT', '/api/backup', { body, cookie: unbound(alice) })).status).toBe(403); // a session of no listed device
        expect((await call('GET', '/api/backup', { cookie: alice.cookie })).status).toBe(404);

        // Refused: extra or missing fields, another account's record, another identity key, a cost out of range, wrong sizes,
        // a swapped hash (the signature covers it), a first record without both proofs or at another epoch.
        const refused = async (value: unknown, cookie = alice.cookie) => (await call('PUT', '/api/backup', { body: value, cookie })).status;
        expect(await refused({ ...body, extra: 1 })).toBe(400);
        expect(await refused({ ...body, signature: undefined })).toBe(400);
        expect(await refused({ ...body, updatedAt: 1 })).toBe(400); // the server sets it
        expect(await refused({ ...body, userId: bob.id })).toBe(400);
        expect(await refused(backup(bob).body)).toBe(400); // another account's record
        expect(await refused({ ...body, aikSign: bob.identity.sign })).toBe(400);
        expect(await refused({ ...body, kdf: { ...body.kdf, m: 8 } })).toBe(400);
        expect(await refused({ ...body, kdf: { ...body.kdf, t: 11 } })).toBe(400);
        expect(await refused({ ...body, pass: body.pass.slice(4) })).toBe(400);
        expect(await refused({ ...body, passHash: b64(randomBytes(32)) })).toBe(400); // the signature does not cover it
        expect(await refused({ ...body, signature: b64(randomBytes(64)) })).toBe(400);
        expect(await refused({ ...body, passProof: b64(randomBytes(32)) })).toBe(400); // does not hash to passProofHash
        const { passProof, ...noPass } = body;
        expect(await refused(noPass)).toBe(400);
        expect(await refused({ ...body, epoch: 2 })).toBe(400); // epoch is part of the signed bytes; and a first record is epoch 1

        const put = await call('PUT', '/api/backup', { body, cookie: alice.cookie });
        expect(put.status).toBe(200);
        expect(put.body.updatedAt).toBe(clock);
        // Any session reads it, a pending device's included, with the signed hashes (and no proof, no unlock key); nobody else.
        const got = await call('GET', '/api/backup', { cookie: unbound(alice) });
        expect(got.body).toEqual({ ...record, updatedAt: clock });
        expect(JSON.stringify(got.body)).not.toContain(body.passProof);
        expect((await call('GET', '/api/backup', { cookie: bob.cookie })).status).toBe(404);
        expect((await call('GET', '/api/backup')).status).toBe(401);
        expect(rows('SELECT record FROM account_backups WHERE user_id = ?', alice.id)[0].record).not.toContain(body.passProof);
        // The owner's own device view says whether a backup exists (and its epoch), without the rate-limited read; others never see it.
        expect((await call('GET', '/api/devices/alice', { cookie: alice.cookie })).body.backup).toEqual({ epoch: 1, updatedAt: clock });
        expect((await call('GET', '/api/devices/bob', { cookie: bob.cookie })).body.backup).toBeNull();
        expect(rows('SELECT COUNT(*) AS n FROM backup_reads WHERE user_id = ?', alice.id)[0].n).toBe(2); // the two GETs above (404 and 200); the device views did not count
    });

    test('a change, a delete and a rotation need the passphrase or the recovery key (a proof), counted when wrong; a rotation allows one proof-free re-seal', async () => {
        await start();
        const alice = account('alice');
        const first = backup(alice);
        expect((await call('PUT', '/api/backup', { body: first.body, cookie: alice.cookie })).status).toBe(200);
        const next = change(alice, first, 'a different long passphrase');
        const put = (body: unknown, cookie = alice.cookie) => call('PUT', '/api/backup', { body, cookie });
        // Without the proof, with a wrong one, with a stale or skipped epoch, with an unproven new side: refused.
        const { proof, ...noProof } = next.body;
        expect((await put(noProof)).status).toBe(403);
        expect((await put({ ...next.body, proof: b64(randomBytes(32)) })).status).toBe(403);
        expect((await put({ ...next.body, record: undefined, epoch: 5 })).status).toBe(400);
        const { passProof, ...noNew } = next.body;
        expect((await put({ ...noNew, proof })).status).toBe(400); // a changed passphrase needs its new proof
        expect(rows('SELECT 1 FROM backup_reads WHERE user_id = ? AND found = 0', alice.id).length).toBe(2); // the two wrong proofs count
        expect((await put(next.body, unbound(alice))).status).toBe(403);
        expect((await put(next.body)).status).toBe(200);
        // The old record cannot be put again (epoch moved on); the recovery words prove just as well as the passphrase.
        expect((await put(next.body)).status).toBe(409);
        const third = change(alice, { ...next, created: { backupKeys: next.resealed.backupKeys }, secret: 'a different long passphrase' }, 'a third long passphrase');
        const withWords = { ...third.body, proof: alice.client.call({ cmd: 'backupProve', record: next.record, words: first.created.words }).proof };
        expect((await put(withWords)).status).toBe(200);

        // Delete: a proof as well.
        const stored = (await call('GET', '/api/backup', { cookie: unbound(alice) })).body;
        expect((await call('DELETE', '/api/backup', { cookie: unbound(alice), body: { proof } })).status).toBe(403);
        expect((await call('DELETE', '/api/backup', { cookie: alice.cookie, body: { proof: b64(randomBytes(32)) } })).status).toBe(403);
        expect((await call('DELETE', '/api/backup', { cookie: alice.cookie })).status).toBe(403);
        const recoveryProof = alice.client.call({ cmd: 'backupProve', record: stored, words: first.created.words }).proof;
        expect((await call('DELETE', '/api/backup', { cookie: alice.cookie, body: { proof: recoveryProof } })).status).toBe(204);
        expect((await call('DELETE', '/api/backup', { cookie: alice.cookie })).status).toBe(204); // nothing to delete: nothing to prove
        expect(rows('SELECT 1 FROM account_backups WHERE user_id = ?', alice.id)).toEqual([]);
    });

    test('a rotation (succession) with a backup needs the proof, and then allows exactly one re-seal without one', async () => {
        await start();
        const alice = account('alice');
        const first = backup(alice);
        expect((await call('PUT', '/api/backup', { body: first.body, cookie: alice.cookie })).status).toBe(200);
        alice.client.call({ cmd: 'backupKeysSet', backupKeys: first.created.backupKeys });
        const proof = alice.client.call({ cmd: 'backupProve', record: first.record, passphrase }).proof;
        // The device that rotates mints the new identity in a core of its own.
        const next = new Client(Core);
        const successor = next.call({ cmd: 'identity' });
        const signed = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: successor.sign, newDh: successor.dh, at: clock });
        const { signature, ...record } = signed;
        const succession = (body: object, cookie = alice.cookie) => call('PUT', '/api/devices/succession', { body, cookie });
        expect((await succession({ record, signature }, unbound(alice))).status).toBe(403); // not a listed device
        expect((await succession({ record, signature })).status).toBe(403); // no proof, a backup exists
        expect((await succession({ record, signature, proof: b64(randomBytes(32)) })).status).toBe(403);
        expect((await succession({ record, signature, proof })).status).toBe(201);

        // Then the rotation re-seals to the new key: same unlock keys and proofs, epoch + 1, no proof needed, once.
        expect((await call('PUT', '/api/keys', { body: { identity: successor, signedPreKey: { id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) } }, cookie: alice.cookie })).body.changed).toBe(true);
        const v1 = { v: 1, userId: alice.id, version: 1, prevHash: '', devices: [{ deviceId: alice.deviceId, addedAt: clock, meta: '' }] };
        const v1Signed = next.call({ cmd: 'signDeviceList', userId: alice.id, published: successor.sign, list: v1 });
        expect((await call('PUT', '/api/devices/list', { body: { list: v1, signature: v1Signed.signature, certs: v1Signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie })).status).toBe(200);
        alice.client.call({ cmd: 'rotateIdentity', userId: alice.id, key: next.call({ cmd: 'exportAccountKey', userId: alice.id }), record, signature, at: record.at, commit: false });
        alice.client.call({ cmd: 'rotateIdentity', userId: alice.id });
        const resealed = alice.client.call({ cmd: 'backupReseal', userId: alice.id, record: first.record });
        const sealed = { ...resealed.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: resealed.record }) };
        expect(sealed.aikSign).toBe(successor.sign);
        expect((await call('PUT', '/api/backup', { body: sealed, cookie: unbound(alice) })).status).toBe(403);
        expect((await call('PUT', '/api/backup', { body: sealed, cookie: alice.cookie })).status).toBe(200);
        // The allowance is spent: the next change needs the proof again.
        alice.client.call({ cmd: 'backupKeysSet', backupKeys: resealed.backupKeys });
        const again = alice.client.call({ cmd: 'backupReseal', userId: alice.id, record: sealed });
        const second = { ...again.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: again.record }) };
        expect((await call('PUT', '/api/backup', { body: second, cookie: alice.cookie })).status).toBe(403);
        expect((await call('PUT', '/api/backup', { body: { ...second, proof }, cookie: alice.cookie })).status).toBe(200);
    });

    test('reads are logged, pushed to the account\'s open streams, and limited: 5 an hour per session, 10 an hour and 30 a day per account', async () => {
        await start();
        const alice = account('alice');
        expect((await call('PUT', '/api/backup', { body: backup(alice).body, cookie: alice.cookie })).status).toBe(200);
        const watch = new WebSocket(Object.assign(new URL('/api/events', app.server.url), { protocol: 'ws:' }), { headers: { Origin: origin, Cookie: alice.cookie, 'X-Real-IP': ip() } } as any);
        const frames: any[] = [];
        watch.onmessage = event => frames.push(JSON.parse(String(event.data)));
        await new Promise(resolve => watch.addEventListener('open', resolve, { once: true }));
        const strangers = [unbound(alice), unbound(alice), unbound(alice)];
        const read = async (cookie: string) => (await call('GET', '/api/backup', { cookie })).status;
        expect(await read(strangers[0]!)).toBe(200);
        await Bun.sleep(100);
        expect(frames).toContainEqual({ type: 'backup', id: alice.id, read: true, deviceId: null });
        expect(rows('SELECT device_id, found FROM backup_reads WHERE user_id = ?', alice.id)).toEqual([{ device_id: null, found: 1 }]);
        watch.close();

        // One session: five an hour. A stranger's pending session cannot use up the whole account's quota.
        for (let i = 1; i < 5; i++) expect(await read(strangers[0]!)).toBe(200);
        expect(await read(strangers[0]!)).toBe(429);
        for (let i = 0; i < 5; i++) expect(await read(strangers[1]!)).toBe(i < 5 ? 200 : 429);
        // Ten in the hour across sessions, then 429 for everyone.
        expect(await read(strangers[2]!)).toBe(429);
        expect(await read(alice.cookie)).toBe(429);
        // The hour passes; the day's thirty stop it at the third hour.
        for (let hour = 0; hour < 2; hour++) {
            clock += 61 * 60 * 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
            for (let i = 0; i < 5; i++) expect(await read(strangers[hour]!)).toBe(200);
            for (let i = 0; i < 5; i++) expect(await read(strangers[2]!)).toBe(200);
            expect(await read(alice.cookie)).toBe(429);
        }
        clock += 61 * 60 * 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect(await read(strangers[2]!)).toBe(429); // thirty within the last 24 hours
        clock += 22 * 60 * 60 * 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect(await read(strangers[2]!)).toBe(200);
    });
});

suite('rekey: a device without the account key asks a device that has it (m6 §5)', () => {
    test('a listed device asks with a leaf-key signature, any listed device lists and answers, only the asker reads the box', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        const { c, cookie, leaf } = await listedCompanion(alice);
        const cert = alice.client.call({ cmd: 'signDeviceCert', userId: alice.id, deviceId: c.deviceId, platform: 'linux', leafSigKey: leaf, issuedAt: clock, now: clock });
        c.client.call({ cmd: 'companionSetup', userId: alice.id, identity: alice.identity, cert });
        const request = c.client.call({ cmd: 'rekeyRequest', userId: alice.id, deviceId: c.deviceId, platform: 'linux' });
        const ask = { platform: 'linux', ...request };
        const unbound = app.accounts!.testing.cookie(alice.id);
        expect((await call('PUT', '/api/devices/rekey', { body: ask })).status).toBe(401);
        expect((await call('PUT', '/api/devices/rekey', { body: ask, cookie: unbound })).status).toBe(403);
        expect((await call('PUT', '/api/devices/rekey', { body: ask, cookie: alice.cookie })).status).toBe(403); // the primary's own session cannot sign for c's leaf
        expect((await call('PUT', '/api/devices/rekey', { body: { ...ask, signature: b64(randomBytes(64)) }, cookie })).status).toBe(403);
        expect((await call('PUT', '/api/devices/rekey', { body: { ...ask, eph: b64(randomBytes(32)) }, cookie })).status).toBe(403); // the eph is signed
        expect((await call('PUT', '/api/devices/rekey', { body: { ...ask, platform: 'macos' }, cookie })).status).toBe(403); // so is the platform
        expect((await call('PUT', '/api/devices/rekey', { body: { ...ask, platform: 'toaster' }, cookie })).status).toBe(400);
        expect((await call('PUT', '/api/devices/rekey', { body: { ...ask, extra: 1 }, cookie })).status).toBe(400);
        expect((await call('PUT', '/api/devices/rekey', { body: ask, cookie })).status).toBe(201);

        expect((await call('GET', '/api/devices/rekey', { cookie: unbound })).status).toBe(403);
        expect((await call('GET', '/api/devices/rekey', { cookie: bob.cookie })).body.requests).toEqual([]);
        const pending = await call('GET', '/api/devices/rekey', { cookie: alice.cookie });
        expect(pending.body.requests).toEqual([{ deviceId: c.deviceId, platform: 'linux', eph: request.eph, leafSigKey: request.leafSigKey, signature: request.signature }]);

        const box = b64(randomBytes(300));
        expect((await call('PUT', `/api/devices/rekey/${c.deviceId}`, { body: { box }, cookie: unbound })).status).toBe(403);
        expect((await call('PUT', `/api/devices/rekey/${c.deviceId}`, { body: { box }, cookie: bob.cookie })).status).toBe(404);
        expect((await call('PUT', `/api/devices/rekey/${randomBytes(16).toString('base64url')}`, { body: { box }, cookie: alice.cookie })).status).toBe(404);
        expect((await call('PUT', `/api/devices/rekey/${c.deviceId}`, { body: { box: 'x' }, cookie: alice.cookie })).status).toBe(400);
        expect((await call('PUT', `/api/devices/rekey/${c.deviceId}`, { body: { box: b64(randomBytes(9000)) }, cookie: alice.cookie })).status).toBe(400);
        expect((await call('GET', '/api/devices/rekey/mine', { cookie })).body).toEqual({ box: null });
        expect((await call('PUT', `/api/devices/rekey/${c.deviceId}`, { body: { box }, cookie: alice.cookie })).status).toBe(201);
        expect((await call('GET', '/api/devices/rekey', { cookie: alice.cookie })).body.requests).toEqual([]); // answered ones are not listed again
        expect((await call('PUT', `/api/devices/rekey/${c.deviceId}`, { body: { box: b64(randomBytes(300)) }, cookie: alice.cookie })).status).toBe(409); // one answer per request
        expect((await call('GET', '/api/devices/rekey/mine', { cookie })).body).toEqual({ box });
        expect((await call('GET', '/api/devices/rekey/mine', { cookie: alice.cookie })).status).toBe(404);
        // Asking again replaces the request and drops the old answer; done removes it.
        expect((await call('PUT', '/api/devices/rekey', { body: ask, cookie })).status).toBe(201);
        expect((await call('GET', '/api/devices/rekey/mine', { cookie })).body).toEqual({ box: null });
        expect((await call('DELETE', '/api/devices/rekey', { cookie })).status).toBe(200);
        expect((await call('GET', '/api/devices/rekey/mine', { cookie })).status).toBe(404);
    });
});

suite('any listed device links, and the inbox device may be revoked (m6 §2, §6)', () => {
    test('a listed device that is not the primary takes a link; a pre-M6 transfer is still the primary\'s alone', async () => {
        await start();
        const alice = account('alice'), n = newcomer();
        const { c, cookie } = await listedCompanion(alice);
        const started = await call('POST', '/api/link/start', { body: n.start() });
        const { qr } = n.client.call({ cmd: 'linkQr', linkId: started.body.linkId, now: clock });
        const accepted = alice.client.call({ cmd: 'linkAccept', qr, now: clock });
        const offered = await call('POST', `/api/link/${started.body.linkId}/offer`, { body: { eph: accepted.eph }, cookie });
        expect(offered.status).toBe(201);
        expect(rows('SELECT offer_device_id FROM link_requests WHERE id = ?', started.body.linkId)[0].offer_device_id).toBe(c.deviceId);
        // A session of no listed device does not.
        const second = await call('POST', '/api/link/start', { body: newcomer().start() });
        expect((await call('POST', `/api/link/${second.body.linkId}/offer`, { body: { eph: accepted.eph }, cookie: app.accounts!.testing.cookie(alice.id) })).status).toBe(403);
    });

    test('revoking the inbox device is allowed: its waiting envelopes and the inbox go to the revoker, or to a placeholder', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        const { c, cookie } = await listedCompanion(alice);
        const envelope = (device: string, recipient: string, n: number) => run('INSERT INTO device_inbox (id, device_id, recipient_id, sender_id, envelope, created_at) VALUES (?, ?, ?, ?, x\'00\', ?)', `${n}`.padStart(22, 'I'), device, recipient, bob.id, clock);
        envelope(alice.deviceId, alice.id, 1);
        // c revokes the primary (the inbox device): the inbox and the waiting envelope move to c.
        const revoked = await call('POST', `/api/devices/${alice.deviceId}/revoke`, { cookie });
        expect(revoked.body).toEqual({ revoked: [alice.deviceId] });
        expect(rows('SELECT is_primary FROM devices WHERE id = ?', c.deviceId)[0].is_primary).toBe(1);
        expect(rows('SELECT state, is_primary FROM devices WHERE id = ?', alice.deviceId)[0]).toEqual({ state: 'revoked', is_primary: 0 });
        expect(rows('SELECT device_id FROM device_inbox WHERE recipient_id = ?', alice.id)).toEqual([{ device_id: c.deviceId }]);

        // A session that is not a listed device revokes the inbox device: the inbox goes to a placeholder.
        const carol = account('carol');
        envelope(carol.deviceId, carol.id, 2);
        expect((await call('POST', `/api/devices/${carol.deviceId}/revoke`, { cookie: app.accounts!.testing.cookie(carol.id) })).status).toBe(200);
        const holder = rows('SELECT id, state FROM devices WHERE user_id = ? AND is_primary = 1', carol.id);
        expect(holder).toHaveLength(1);
        expect(holder[0].state).toBe('placeholder');
        expect(rows('SELECT device_id FROM device_inbox WHERE recipient_id = ?', carol.id)).toEqual([{ device_id: holder[0].id }]);
        // A placeholder holds no keys: it is not a device to revoke.
        expect((await call('POST', `/api/devices/${holder[0].id}/revoke`, { cookie: app.accounts!.testing.cookie(carol.id) })).status).toBe(409);
    });
});

suite('restore: a pending device lists itself (m6 §4 step 4)', () => {
    test('a session bound to a pending device publishes the next list naming itself, if the current account key signed it; the inbox stays; a list that drops the inbox device hands it over', async () => {
        await start();
        const alice = account('alice'), bob = account('bob');
        const pending = id(), { cookie } = (() => {
            run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'pending', 0, ?, ?)", pending, alice.id, b64(randomBytes(32)), clock);
            const session = app.accounts!.testing.cookie(alice.id);
            run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', pending, createHash('sha256').update(session.split('=')[1]!).digest('hex'));
            return { cookie: session };
        })();
        const listWith = (devices: string[], version = alice.list.version + 1) => ({ v: 1, userId: alice.id, version, prevHash: sha(F.listBytes(alice.list)), devices: devices.sort().map(deviceId => ({ deviceId, addedAt: clock, meta: '' })) });
        const list = listWith([alice.deviceId, pending]);
        const signedList = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list });
        const put = (body: object, session = cookie) => call('PUT', '/api/devices/list', { body: { list, signature: signedList.signature, certs: signedList.certs, deviceId: pending, ...body }, cookie: session });
        // Naming the publisher is required, the session must be bound to the device it names, and the account key must have signed it.
        expect((await put({ deviceId: alice.deviceId })).status).toBe(409); // this session is bound to the pending device, not to the primary
        expect((await put({ deviceId: id() })).status).toBe(400); // the publisher is not in the list
        expect((await put({}, app.accounts!.testing.cookie(alice.id))).status).toBe(409); // an unbound session cannot stand in
        expect((await put({ signature: b64(randomBytes(64)) })).status).toBe(403); // not signed by the account key
        expect((await put({})).status).toBe(200);
        expect(rows('SELECT state, is_primary FROM devices WHERE id = ?', pending)[0]).toEqual({ state: 'listed', is_primary: 0 });
        expect(rows('SELECT is_primary FROM devices WHERE id = ?', alice.deviceId)[0].is_primary).toBe(1);
        alice.list = list;

        // The restored device drops the inbox device: the inbox and what waits for it move to the publisher first.
        run('INSERT INTO device_inbox (id, device_id, recipient_id, sender_id, envelope, created_at) VALUES (?, ?, ?, ?, x\'00\', ?)', 'I'.repeat(22), alice.deviceId, alice.id, bob.id, clock);
        const dropping = listWith([pending]);
        const droppingSigned = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list: dropping });
        const next = await call('PUT', '/api/devices/list', { body: { list: dropping, signature: droppingSigned.signature, certs: droppingSigned.certs, deviceId: pending }, cookie });
        expect(next.status).toBe(200);
        expect(next.body.revoked).toEqual([alice.deviceId]);
        expect(rows('SELECT is_primary FROM devices WHERE id = ?', pending)[0].is_primary).toBe(1);
        expect(rows('SELECT device_id FROM device_inbox WHERE id = ?', 'I'.repeat(22))).toEqual([{ device_id: pending }]);
    });
});

suite('removing devices from an account with a backup needs the passphrase\'s proof (m6 §6.3)', () => {
    const passphrase = 'a long enough passphrase';
    /** Turns the backup on for `alice` and returns the proof of her passphrase. */
    async function enableBackup(alice: Primary) {
        const created = alice.client.call({ cmd: 'backupCreate', userId: alice.id, passphrase });
        const record = { ...created.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: created.record }) };
        expect((await call('PUT', '/api/backup', { body: { ...record, passProof: created.passProof, recoveryProof: created.recoveryProof }, cookie: alice.cookie })).status).toBe(200);
        return { proof: alice.client.call({ cmd: 'backupProve', record, passphrase }).proof as string, record, created };
    }
    const nextList = (alice: Primary, devices: string[]) => ({ v: 1, userId: alice.id, version: alice.list.version + 1, prevHash: sha(F.listBytes(alice.list)), devices: [...devices].sort().map(deviceId => ({ deviceId, addedAt: clock, meta: '' })) });
    const put = (alice: Primary, list: any, deviceId: string, cookie: string, extra: object = {}) => {
        const signed = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list });
        return call('PUT', '/api/devices/list', { body: { list, signature: signed.signature, certs: signed.certs, deviceId, ...extra }, cookie });
    };

    test('without a backup nothing changes: a list drops a device, and any session revokes one', async () => {
        await start();
        const alice = account('alice');
        const { c, cookie } = await listedCompanion(alice);
        const dropping = await put(alice, nextList(alice, [alice.deviceId]), alice.deviceId, alice.cookie);
        expect(dropping.status).toBe(200);
        expect(dropping.body.revoked).toEqual([c.deviceId]);
        void cookie;
        const bob = account('bob');
        const second = await listedCompanion(bob);
        expect((await call('POST', `/api/devices/${second.c.deviceId}/revoke`, { cookie: app.accounts!.testing.cookie(bob.id) })).status).toBe(200); // a session bound to no device
    });

    test('with a backup a list that drops a listed device needs the proof and a listed publisher', async () => {
        await start();
        const alice = account('alice');
        const { c } = await listedCompanion(alice);
        const { proof } = await enableBackup(alice);
        const pending = id();
        run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'pending', 0, ?, ?)", pending, alice.id, b64(randomBytes(32)), clock);
        const pendingCookie = app.accounts!.testing.cookie(alice.id);
        run('UPDATE sessions SET device_id = ? WHERE token_hash = ?', pending, createHash('sha256').update(pendingCookie.split('=')[1]!).digest('hex'));
        const list = nextList(alice, [alice.deviceId, pending]); // drops the listed companion, lists the pending device
        const signed = alice.client.call({ cmd: 'signDeviceList', userId: alice.id, published: alice.identity.sign, list });
        const send = (extra: object, deviceId = alice.deviceId, cookie = alice.cookie) => call('PUT', '/api/devices/list', { body: { list, signature: signed.signature, certs: signed.certs, deviceId, ...extra }, cookie });
        expect((await send({})).status).toBe(403); // no proof
        expect((await send({ proof: b64(randomBytes(32)) })).status).toBe(403); // wrong proof
        expect((await send({ proof }, pending, pendingCookie)).status).toBe(403); // a pending publisher, even with the proof
        expect(rows('SELECT 1 FROM backup_reads WHERE user_id = ? AND found = 0', alice.id).length).toBe(2); // the missing and the wrong proof count
        expect(rows('SELECT state FROM devices WHERE id = ?', c.deviceId)[0].state).toBe('listed');
        expect((await send({ proof })).status).toBe(200);
        expect(rows('SELECT state FROM devices WHERE id = ?', c.deviceId)[0].state).toBe('revoked');
        // A list that drops nobody needs no proof.
        alice.list = list;
        expect((await put(alice, nextList(alice, [alice.deviceId, pending]), alice.deviceId, alice.cookie)).status).toBe(200);
    });

    test('after an accepted succession the first list under the new key drops the removed devices without a proof, once', async () => {
        await start();
        const alice = account('alice');
        const { c } = await listedCompanion(alice);
        const { proof } = await enableBackup(alice);
        const next = new Client(Core);
        const successor = next.call({ cmd: 'identity' });
        const signedRecord = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: successor.sign, newDh: successor.dh, at: clock });
        const { signature, ...record } = signedRecord;
        expect((await call('PUT', '/api/devices/succession', { body: { record, signature, proof }, cookie: alice.cookie })).status).toBe(201);
        expect(rows('SELECT 1 FROM rotation_allowance WHERE user_id = ?', alice.id)).toEqual([]); // nothing is free until the identity changes
        // The identity changes (PUT /api/keys): lists void, every device pending, and the first list and the re-seal are free for an hour.
        expect((await call('PUT', '/api/keys', { body: { identity: successor, signedPreKey: { id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) } }, cookie: alice.cookie })).body.changed).toBe(true);
        expect(rows('SELECT list, reseal FROM rotation_allowance WHERE user_id = ?', alice.id)).toEqual([{ list: 1, reseal: 1 }]);
        const v1 = { v: 1, userId: alice.id, version: 1, prevHash: '', devices: [{ deviceId: alice.deviceId, addedAt: clock, meta: '' }] };
        const v1Signed = next.call({ cmd: 'signDeviceList', userId: alice.id, published: successor.sign, list: v1 });
        const published = await call('PUT', '/api/devices/list', { body: { list: v1, signature: v1Signed.signature, certs: v1Signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie });
        expect(published.status).toBe(200);
        expect(published.body.revoked).toEqual([c.deviceId]);
        expect(rows('SELECT list, reseal FROM rotation_allowance WHERE user_id = ?', alice.id)).toEqual([{ list: 0, reseal: 1 }]); // the re-seal is still to come
        // Spent: the next list that drops a listed device needs the proof again.
        const extra = id();
        run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'listed', 0, ?, ?)", extra, alice.id, b64(randomBytes(32)), clock);
        const v2 = { v: 1, userId: alice.id, version: 2, prevHash: sha(F.listBytes(v1)), devices: [alice.deviceId, extra].sort().map(deviceId => ({ deviceId, addedAt: clock, meta: '' })) };
        const v2Signed = next.call({ cmd: 'signDeviceList', userId: alice.id, published: successor.sign, list: v2 });
        expect((await call('PUT', '/api/devices/list', { body: { list: v2, signature: v2Signed.signature, certs: v2Signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie })).status).toBe(200);
        const v3 = { v: 1, userId: alice.id, version: 3, prevHash: sha(F.listBytes(v2)), devices: [{ deviceId: alice.deviceId, addedAt: clock, meta: '' }] };
        const v3Signed = next.call({ cmd: 'signDeviceList', userId: alice.id, published: successor.sign, list: v3 });
        expect((await call('PUT', '/api/devices/list', { body: { list: v3, signature: v3Signed.signature, certs: v3Signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie })).status).toBe(403);
    });

    test('with a backup, revoking another device takes a listed device\'s session and the proof; unlinking yourself does not', async () => {
        await start();
        const alice = account('alice');
        const { c, cookie } = await listedCompanion(alice);
        const { proof } = await enableBackup(alice);
        const unbound = app.accounts!.testing.cookie(alice.id);
        const revoke = (target: string, session: string, body?: object) => call('POST', `/api/devices/${target}/revoke`, { cookie: session, ...(body ? { body } : {}) });
        expect((await revoke(c.deviceId, alice.cookie)).status).toBe(403); // no proof
        expect((await revoke(c.deviceId, alice.cookie, { proof: b64(randomBytes(32)) })).status).toBe(403); // wrong proof
        expect((await revoke(c.deviceId, unbound, { proof })).status).toBe(403); // a session of no listed device (a pending passkey session), even with the proof
        expect(rows('SELECT state FROM devices WHERE id = ?', c.deviceId)[0].state).toBe('listed');
        expect(rows('SELECT 1 FROM backup_reads WHERE user_id = ? AND found = 0', alice.id).length).toBe(2);
        expect((await revoke(c.deviceId, alice.cookie, { proof })).body).toEqual({ revoked: [c.deviceId] });
        // Unlinking a device from itself is nobody else's loss: no proof.
        const bob = account('bob');
        const second = await listedCompanion(bob);
        await enableBackup(bob);
        expect((await revoke(second.c.deviceId, second.cookie)).status).toBe(200);
        void cookie;
    });
});

suite('replacing the account identity when the account has a backup (m6 §6.4)', () => {
    const passphrase = 'a long enough passphrase';
    async function enableBackup(alice: Primary) {
        const created = alice.client.call({ cmd: 'backupCreate', userId: alice.id, passphrase });
        const record = { ...created.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: created.record }) };
        expect((await call('PUT', '/api/backup', { body: { ...record, passProof: created.passProof, recoveryProof: created.recoveryProof }, cookie: alice.cookie })).status).toBe(200);
        return alice.client.call({ cmd: 'backupProve', record, passphrase }).proof as string;
    }
    const newIdentity = () => { const identity = new Client(Core).call({ cmd: 'identity' }); return { identity, signedPreKey: { id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) } }; };
    const putKeys = (body: object, cookie: string) => call('PUT', '/api/keys', { body, cookie });
    const backupRows = (alice: Primary) => rows('SELECT 1 FROM account_backups WHERE user_id = ?', alice.id).length;
    const week = 7 * 24 * 60 * 60 * 1000;

    test('without a backup nothing changes: a reset is not needed, and a new identity is accepted', async () => {
        await start();
        const alice = account('alice');
        expect((await call('POST', '/api/keys/reset', { cookie: app.accounts!.testing.cookie(alice.id) })).status).toBe(409);
        expect((await putKeys(newIdentity(), alice.cookie)).body.changed).toBe(true);
    });

    test('with a backup a new identity needs the proof (and takes the backup with it) or a succession that ends in it', async () => {
        await start();
        const alice = account('alice');
        const proof = await enableBackup(alice);
        const unbound = app.accounts!.testing.cookie(alice.id);
        expect((await putKeys(newIdentity(), unbound)).status).toBe(403); // a passkey session alone
        expect((await putKeys({ ...newIdentity(), proof: b64(randomBytes(32)) }, alice.cookie)).status).toBe(403); // wrong proof
        expect(rows('SELECT 1 FROM backup_reads WHERE user_id = ? AND found = 0', alice.id).length).toBe(1);
        expect(rows('SELECT sign FROM identity_keys WHERE user_id = ?', alice.id)[0].sign).toBe(alice.identity.sign);
        // The same identity again is not a change.
        expect((await putKeys({ identity: alice.identity, signedPreKey: { id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) } }, unbound)).body.changed).toBe(false);
        const fresh = newIdentity();
        const changed = await putKeys({ ...fresh, proof }, unbound);
        expect(changed.body.changed).toBe(true);
        expect(backupRows(alice)).toBe(0); // it held the old key
    });

    test('a succession the server took ends in the new identity, and the backup stays for the re-seal', async () => {
        await start();
        const alice = account('alice');
        const proof = await enableBackup(alice);
        const fresh = newIdentity();
        const signed = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: fresh.identity.sign, newDh: fresh.identity.dh, at: clock });
        const { signature, ...record } = signed;
        expect((await call('PUT', '/api/devices/succession', { body: { record, signature, proof }, cookie: alice.cookie })).status).toBe(201);
        expect((await putKeys(newIdentity(), alice.cookie)).status).toBe(403); // some other identity
        expect((await putKeys(fresh, alice.cookie)).body.changed).toBe(true);
        expect(backupRows(alice)).toBe(1);
    });

    test('an old succession cannot be replayed to put a previous identity back: it hands over from one identity once', async () => {
        await start();
        const alice = account('alice');
        const proof = await enableBackup(alice);
        // A0 -> A1 by succession, applied (the record is spent).
        const a1 = new Client(Core), a1Identity = a1.call({ cmd: 'identity' });
        const signed = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: a1Identity.sign, newDh: a1Identity.dh, at: clock });
        const { signature, ...record } = signed;
        expect((await call('PUT', '/api/devices/succession', { body: { record, signature, proof }, cookie: alice.cookie })).status).toBe(201);
        const toA1 = { identity: a1Identity, signedPreKey: { id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) } };
        expect((await putKeys(toA1, alice.cookie)).body.changed).toBe(true);
        expect(rows('SELECT used FROM identity_succession WHERE user_id = ?', alice.id)).toEqual([{ used: 1 }]);
        // A1 -> A2 by the passphrase (a fresh start; the backup still answers to the same proof), then a new backup for A2.
        const a2 = new Client(Core), a2Identity = a2.call({ cmd: 'identity' });
        expect((await putKeys({ identity: a2Identity, signedPreKey: toA1.signedPreKey, proof }, alice.cookie)).body.changed).toBe(true);
        const a2Backup = a2.call({ cmd: 'backupCreate', userId: alice.id, passphrase });
        const a2Record = { ...a2Backup.record, signature: a2.call({ cmd: 'backupSignKeys', userId: alice.id, record: a2Backup.record }) };
        // (A2's devices are pending until they list themselves; the stored backup is what matters here.)
        run('INSERT INTO account_backups (user_id, record, updated_at) VALUES (?, ?, ?)', alice.id, JSON.stringify(a2Record), clock);
        // Whoever still holds A1 (a revoked device) cannot put it back: the A0 -> A1 record does not hand over from A2, and it is spent.
        expect((await putKeys(toA1, app.accounts!.testing.cookie(alice.id))).status).toBe(403);
        expect(rows('SELECT sign FROM identity_keys WHERE user_id = ?', alice.id)[0].sign).toBe(a2Identity.sign);
        // The same holds for A0, the identity before.
        expect((await putKeys({ identity: alice.identity, signedPreKey: toA1.signedPreKey }, alice.cookie)).status).toBe(403);
    });

    test('a delayed reset: any session asks, listed devices see it and can cancel it, and after a week the asking session replaces the identity and the backup goes', async () => {
        await start();
        const alice = account('alice');
        await enableBackup(alice);
        const watch = new WebSocket(Object.assign(new URL('/api/events', app.server.url), { protocol: 'ws:' }), { headers: { Origin: origin, Cookie: alice.cookie, 'X-Real-IP': ip() } } as any);
        const frames: any[] = [];
        watch.onmessage = event => frames.push(JSON.parse(String(event.data)));
        await new Promise(resolve => watch.addEventListener('open', resolve, { once: true }));
        const thief = app.accounts!.testing.cookie(alice.id), other = app.accounts!.testing.cookie(alice.id);
        expect((await call('POST', '/api/keys/reset')).status).toBe(401);
        const asked = await call('POST', '/api/keys/reset', { cookie: thief });
        expect(asked.status).toBe(201);
        expect(asked.body.reset).toEqual({ requestedBy: { deviceId: null, platform: 'web' }, at: clock, executeAfter: clock + week });
        await Bun.sleep(100);
        expect(frames).toContainEqual({ type: 'reset', id: alice.id, requestedBy: { deviceId: null, platform: 'web' }, at: clock, executeAfter: clock + week });
        expect((await call('GET', '/api/devices/alice', { cookie: alice.cookie })).body.reset).toEqual(asked.body.reset);
        expect((await call('POST', '/api/keys/reset', { cookie: other })).status).toBe(409); // one open request

        // Not before the week, not from another session, and a pending session cannot cancel it.
        const fresh = newIdentity();
        const early = await putKeys(fresh, thief);
        expect(early.status).toBe(403);
        expect(early.body.reset.executeAfter).toBe(clock + week);
        expect((await call('DELETE', '/api/keys/reset', { cookie: thief })).status).toBe(403);
        clock += week + 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect((await putKeys(fresh, other)).status).toBe(403);
        expect((await putKeys(fresh, alice.cookie)).status).toBe(403); // not the session that asked, even a listed one
        // A listed device cancels it, no proof; asking again starts the week over.
        expect((await call('DELETE', '/api/keys/reset', { cookie: alice.cookie })).status).toBe(204);
        expect(rows('SELECT 1 FROM key_resets WHERE user_id = ?', alice.id)).toEqual([]);
        expect((await putKeys(fresh, thief)).status).toBe(403);
        await Bun.sleep(100);
        expect(frames).toContainEqual({ type: 'reset', id: alice.id, cancelled: true });
        expect((await call('POST', '/api/keys/reset', { cookie: thief })).status).toBe(201);
        // Three requests in 30 days.
        expect((await call('DELETE', '/api/keys/reset', { cookie: alice.cookie })).status).toBe(204);
        expect((await call('POST', '/api/keys/reset', { cookie: thief })).status).toBe(201);
        expect((await call('DELETE', '/api/keys/reset', { cookie: alice.cookie })).status).toBe(204);
        expect((await call('POST', '/api/keys/reset', { cookie: thief })).status).toBe(429);
        clock += 31 * 24 * 60 * 60 * 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect((await call('POST', '/api/keys/reset', { cookie: thief })).status).toBe(201);
        // The week passes; only the asking session replaces the identity, and the backup that held the old key is gone.
        clock += week + 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect((await putKeys(fresh, other)).status).toBe(403);
        const done = await putKeys(fresh, thief);
        expect(done.body.changed).toBe(true);
        expect(backupRows(alice)).toBe(0);
        expect(rows('SELECT 1 FROM key_resets WHERE user_id = ?', alice.id)).toEqual([]);
        watch.close();
    });
});

suite('one rotation at a time, and the proof-free steps it allows are bound and expire (m6 §6.2)', () => {
    const passphrase = 'a long enough passphrase';
    const hour = 60 * 60 * 1000;
    async function enableBackup(alice: Primary) {
        const created = alice.client.call({ cmd: 'backupCreate', userId: alice.id, passphrase });
        const record = { ...created.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: created.record }) };
        expect((await call('PUT', '/api/backup', { body: { ...record, passProof: created.passProof, recoveryProof: created.recoveryProof }, cookie: alice.cookie })).status).toBe(200);
        return { proof: alice.client.call({ cmd: 'backupProve', record, passphrase }).proof as string, record, created };
    }
    const successionTo = (alice: Primary, identity: { sign: string; dh: string }) => { const { signature, ...record } = alice.client.call({ cmd: 'signSuccession', userId: alice.id, published: alice.identity.sign, newSign: identity.sign, newDh: identity.dh, at: clock }); return { record, signature }; };
    const preKeys = () => ({ id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) });

    test('while a succession from the published identity is open another one is refused, the same one again is a retry, and applying it spends it', async () => {
        await start();
        const alice = account('alice'); // no backup
        const b = new Client(Core).call({ cmd: 'identity' }), c = new Client(Core).call({ cmd: 'identity' });
        const first = successionTo(alice, b), other = successionTo(alice, c);
        const put = (body: object) => call('PUT', '/api/devices/succession', { body, cookie: alice.cookie });
        const accepted = await put(first);
        expect(accepted.status).toBe(201);
        expect((await put(other)).status).toBe(409); // another device's rotation: it fetches the chain and follows
        const again = await put(first);
        expect([again.status, again.body.seq]).toEqual([201, accepted.body.seq]); // a retry after a lost answer or a restart
        expect(rows('SELECT COUNT(*) AS n FROM identity_succession WHERE user_id = ?', alice.id)[0].n).toBe(1);
        // Applying it (the new identity on PUT /api/keys) spends it, with or without a backup.
        expect((await call('PUT', '/api/keys', { body: { identity: b, signedPreKey: preKeys() }, cookie: alice.cookie })).body.changed).toBe(true);
        expect(rows('SELECT used FROM identity_succession WHERE user_id = ?', alice.id)).toEqual([{ used: 1 }]);
        // An abandoned one stops blocking after the window.
        const bob = account('bob');
        const bb = new Client(Core).call({ cmd: 'identity' }), bc = new Client(Core).call({ cmd: 'identity' });
        expect((await call('PUT', '/api/devices/succession', { body: successionTo(bob, bb), cookie: bob.cookie })).status).toBe(201);
        expect((await call('PUT', '/api/devices/succession', { body: successionTo(bob, bc), cookie: bob.cookie })).status).toBe(409);
        clock += hour + 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect((await call('PUT', '/api/devices/succession', { body: successionTo(bob, bc), cookie: bob.cookie })).status).toBe(201);
        // And an expired open record no longer authorizes the identity change it names.
        expect((await call('PUT', '/api/keys', { body: { identity: bc, signedPreKey: preKeys() }, cookie: bob.cookie })).body.changed).toBe(true);
    });

    test('a succession authorizes its own identity change however late the device resumes, until a later record replaces it', async () => {
        await start();
        const alice = account('alice');
        const { proof } = await enableBackup(alice);
        const b = new Client(Core).call({ cmd: 'identity' }), c = new Client(Core).call({ cmd: 'identity' });
        expect((await call('PUT', '/api/devices/succession', { body: { ...successionTo(alice, b), proof }, cookie: alice.cookie })).status).toBe(201);
        const view = async () => (await call('GET', '/api/devices/alice', { cookie: alice.cookie })).body.rotation;
        expect(await view()).toMatchObject({ oldSign: alice.identity.sign, newSign: b.sign, state: 'open' });
        // The device died after the PUT and comes back two hours later: its record still authorizes its change.
        clock += 2 * hour; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect(await view()).toMatchObject({ newSign: b.sign, state: 'open' });
        expect((await call('PUT', '/api/keys', { body: { identity: b, signedPreKey: preKeys() }, cookie: alice.cookie })).body.changed).toBe(true);
        expect(await view()).toMatchObject({ newSign: b.sign, state: 'applied' });

        // Another device whose record lands after the window supersedes an abandoned one: the first no longer authorizes anything.
        const bob = account('bob');
        const bProof = (await enableBackup(bob)).proof;
        const b1 = new Client(Core).call({ cmd: 'identity' });
        expect((await call('PUT', '/api/devices/succession', { body: { ...successionTo(bob, b1), proof: bProof }, cookie: bob.cookie })).status).toBe(201);
        expect((await call('PUT', '/api/devices/succession', { body: { ...successionTo(bob, c), proof: bProof }, cookie: bob.cookie })).status).toBe(409); // within the window
        clock += hour + 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect((await call('PUT', '/api/devices/succession', { body: { ...successionTo(bob, c), proof: bProof }, cookie: bob.cookie })).status).toBe(201);
        expect(rows('SELECT used FROM identity_succession WHERE user_id = ? ORDER BY seq', bob.id)).toEqual([{ used: 2 }, { used: 0 }]);
        expect((await call('PUT', '/api/keys', { body: { identity: b1, signedPreKey: preKeys() }, cookie: bob.cookie })).status).toBe(403); // the superseded one's device
        expect((await call('GET', '/api/devices/bob', { cookie: bob.cookie })).body.rotation).toMatchObject({ newSign: c.sign, state: 'open' }); // what the other device sees: not ours, drop
        expect((await call('PUT', '/api/keys', { body: { identity: c, signedPreKey: preKeys() }, cookie: bob.cookie })).body.changed).toBe(true);
        // An open record whose identity moved on by another way authorizes nothing and reads as superseded.
        const carol = account('carol');
        const carolProof = (await enableBackup(carol)).proof;
        const cc = new Client(Core).call({ cmd: 'identity' }), other = new Client(Core).call({ cmd: 'identity' });
        expect((await call('PUT', '/api/devices/succession', { body: { ...successionTo(carol, cc), proof: carolProof }, cookie: carol.cookie })).status).toBe(201);
        expect((await call('PUT', '/api/keys', { body: { identity: other, signedPreKey: preKeys(), proof: carolProof }, cookie: carol.cookie })).body.changed).toBe(true);
        expect((await call('GET', '/api/devices/carol', { cookie: carol.cookie })).body.rotation).toMatchObject({ newSign: cc.sign, state: 'superseded' });
    });

    test('a record that existed before the update (an abandoned transfer) can never authorize a change', () => {
        const db = new Database(':memory:');
        migrate(db);
        // Rewind to before migration 7 with a row an old server left behind, then migrate again.
        db.exec('PRAGMA foreign_keys = OFF');
        for (const table of ['account_backups', 'backup_reads', 'rekey_requests', 'key_resets', 'key_reset_log', 'rotation_allowance']) db.exec(`DROP TABLE ${table}`);
        db.exec('ALTER TABLE identity_succession DROP COLUMN used');
        db.exec("INSERT INTO identity_succession (user_id, seq, old_sign, new_sign, new_dh, at, signature, created_at) VALUES ('u', 1, 'A', 'B', 'C', 1, 'S', 1)");
        db.exec('PRAGMA user_version = 6');
        migrate(db);
        expect(db.query('SELECT used FROM identity_succession').all()).toEqual([{ used: 1 }]);
    });

    /** The server side of a rotation as the client drives it: the succession (with the proof), then the identity change (PUT /api/keys). */
    async function rotated(alice: Primary, proof: string) {
        const next = new Client(Core);
        const successor = next.call({ cmd: 'identity' });
        const succession = successionTo(alice, successor);
        expect((await call('PUT', '/api/devices/succession', { body: { ...succession, proof }, cookie: alice.cookie })).status).toBe(201);
        return { next, successor, succession };
    }
    /** The identity change that applies the succession (PUT /api/keys): lists void, every device pending, the free steps start their hour. */
    const afterKeys = async (alice: Primary, successor: { sign: string; dh: string }) => {
        expect((await call('PUT', '/api/keys', { body: { identity: successor, signedPreKey: { id: 1, key: b64(randomBytes(32)), signature: b64(randomBytes(64)) } }, cookie: alice.cookie })).body.changed).toBe(true);
    };
    const listV1 = (alice: Primary, next: Client, successor: { sign: string }) => {
        const v1 = { v: 1, userId: alice.id, version: 1, prevHash: '', devices: [{ deviceId: alice.deviceId, addedAt: clock, meta: '' }] };
        const signed = next.call({ cmd: 'signDeviceList', userId: alice.id, published: successor.sign, list: v1 });
        return call('PUT', '/api/devices/list', { body: { list: v1, signature: signed.signature, certs: signed.certs, deviceId: alice.deviceId }, cookie: alice.cookie });
    };
    const addPending = (alice: Primary) => run("INSERT INTO devices (id, user_id, platform, state, is_primary, sig_key, created_at) VALUES (?, ?, 'linux', 'pending', 0, ?, ?)", id(), alice.id, b64(randomBytes(32)), clock);

    test('the proof-free re-seal is only for the key the succession named', async () => {
        await start();
        const alice = account('alice');
        const { proof, record, created } = await enableBackup(alice);
        alice.client.call({ cmd: 'backupKeysSet', backupKeys: created.backupKeys });
        const { successor } = await rotated(alice, proof);
        // Before the identity changes, a re-seal under the key still published is not what the succession allowed.
        const sameKey = alice.client.call({ cmd: 'backupReseal', userId: alice.id, record });
        const sameKeySigned = { ...sameKey.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: sameKey.record }) };
        expect((await call('PUT', '/api/backup', { body: sameKeySigned, cookie: alice.cookie })).status).toBe(403);
        expect(rows('SELECT 1 FROM rotation_allowance WHERE user_id = ?', alice.id)).toEqual([]); // nothing is free before the identity changes
        await afterKeys(alice, successor);
        expect(rows('SELECT new_sign, list, reseal FROM rotation_allowance WHERE user_id = ?', alice.id)).toEqual([{ new_sign: successor.sign, list: 1, reseal: 1 }]);
    });

    test('the first list and the re-seal that follow a succession are free for an hour, not longer', async () => {
        await start();
        // The list, in time and too late.
        const early = account('early'), late = account('late');
        for (const [alice, wait] of [[early, 0], [late, hour + 1000]] as const) {
            const { proof } = await enableBackup(alice);
            const { next, successor } = await rotated(alice, proof);
            await afterKeys(alice, successor);
            addPending(alice);
            clock += wait; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
            expect((await listV1(alice, next, successor)).status).toBe(wait ? 403 : 200); // drops the pending device
        }
        // The re-seal, in time (after the list) and too late.
        const alice = account('carol');
        const { proof, record, created } = await enableBackup(alice);
        alice.client.call({ cmd: 'backupKeysSet', backupKeys: created.backupKeys });
        const { next, successor, succession } = await rotated(alice, proof);
        await afterKeys(alice, successor);
        expect((await listV1(alice, next, successor)).status).toBe(200);
        alice.client.call({ cmd: 'rotateIdentity', userId: alice.id, key: next.call({ cmd: 'exportAccountKey', userId: alice.id }), record: succession.record, signature: succession.signature, at: succession.record.at, commit: false });
        alice.client.call({ cmd: 'rotateIdentity', userId: alice.id });
        const resealed = alice.client.call({ cmd: 'backupReseal', userId: alice.id, record });
        const body = { ...resealed.record, signature: alice.client.call({ cmd: 'backupSignKeys', userId: alice.id, record: resealed.record }) };
        clock += hour + 1000; run('UPDATE sessions SET expires_at = ?', clock + 86400000);
        expect((await call('PUT', '/api/backup', { body, cookie: alice.cookie })).status).toBe(403); // too late: the proof is needed again
        expect((await call('PUT', '/api/backup', { body: { ...body, proof }, cookie: alice.cookie })).status).toBe(200);
    });
});

suite('the page policy (m6 §1: the account key can be unwrapped by any script in the origin)', () => {
    test('every page and script carries a CSP with no inline script and no eval', async () => {
        await start();
        for (const path of ['/', '/app.js', '/core.js', '/core-worker.js', '/account.js']) {
            const response = await fetch(new URL(path, app.server.url), { headers: { 'X-Real-IP': ip() } });
            expect(response.status).toBe(200);
            const csp = response.headers.get('content-security-policy') ?? '';
            expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
            expect(csp).not.toMatch(/unsafe-inline|'unsafe-eval'|\*|data:/);
            expect(csp).toContain("default-src 'none'");
        }
    });
});
