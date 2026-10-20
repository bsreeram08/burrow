import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import '../../packages/signaling/public/devices.js';
import { openDatabase } from '../../packages/signaling/accounts';
import { SCHEMA_VERSION } from '../../packages/signaling/migrations';
import { startSignaling } from '../../packages/signaling/server';

const F = (globalThis as any).DeviceFormat;
const origin = 'http://localhost:3000';
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const deviceId = () => randomBytes(16).toString('base64url');
type Aik = { pub: string; key: KeyObject };
function aik(): Aik { const { publicKey, privateKey } = generateKeyPairSync('ed25519'); return { pub: (publicKey.export({ format: 'jwk' }) as any).x, key: privateKey }; }
const signBytes = (key: Aik, bytes: Uint8Array) => b64(sign(null, bytes, key.key));
function signed(key: Aik, list: any) {
    const certs: Record<string, string> = {};
    for (const device of list.devices) certs[device.deviceId] = signBytes(key, F.certBytes(F.certFor(list.userId, device)));
    return { list, signature: signBytes(key, F.listBytes(list)), certs };
}
const listOf = (userId: string, version: number, prevHash: string, ids: string[]) => ({ v: 1, userId, version, prevHash, devices: [...ids].sort().map(id => ({ deviceId: id, addedAt: 1_800_000_000_000, meta: '' })) });
const hashOf = (list: any) => createHash('sha256').update(F.listBytes(list)).digest('base64url');

describe('device list format', () => {
    test('canonical bytes are stable and documented (a fixed vector)', () => {
        const meta = Buffer.alloc(40, 9).toString('base64url');
        const list = { v: 1, userId: 'user_1', version: 2, prevHash: 'A'.repeat(43), devices: [{ deviceId: 'a'.repeat(22), addedAt: 1_800_000_000_123, meta }, { deviceId: 'b'.repeat(22), addedAt: 7, meta: '' }] };
        const u64 = (value: number) => { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; };
        const expected = Buffer.concat([
            Buffer.from([0, 24]), Buffer.from('webrtc-bun-devicelist-v1'), Buffer.from([0, 6]), Buffer.from('user_1'), Buffer.from([0, 0, 0, 2]),
            Buffer.from([32]), Buffer.alloc(32), Buffer.from([0, 2]),
            Buffer.from([0, 22]), Buffer.from('a'.repeat(22)), u64(1_800_000_000_123), Buffer.from([0, 40]), Buffer.alloc(40, 9),
            Buffer.from([0, 22]), Buffer.from('b'.repeat(22)), u64(7), Buffer.from([0, 0]),
        ]);
        expect(Buffer.from(F.listBytes(list)).equals(expected)).toBe(true);
        // Pinned digest of that vector, so any change to the format shows up here and in docs/devices.md.
        expect(createHash('sha256').update(expected).digest('hex')).toBe('31f9b6f38de5a0d6180afcf54233e7272add9dd22c49e86e40fa3a7c48e938e6');
        expect(createHash('sha256').update(F.certBytes(F.certFor('user_1', list.devices[0]))).digest('hex')).toBe('5115e92bead7431b81c136519282f62e4a85a21c7907d8c3f97571205dcebcea');
        expect(createHash('sha256').update(F.bindBytes('user_1', 'a'.repeat(22), 'A'.repeat(43))).digest('hex')).toBe('e11ceff09f689bbea340eef1c1fcc013f3fff12ff1167b7d44d664fbf5101b18');
        // Pinned in crates/chatcore/tests/signal.rs too (prove_identity signs exactly these bytes).
        expect(createHash('sha256').update(F.claimBytes('user_1', 'a'.repeat(22), 'A'.repeat(43))).digest('hex')).toBe('2238b7912ca08441271c164e5591d1f62afd2ae2afec60aa8b5a49054366ef40');
        // Key order of the JSON object does not matter; the canonical bytes do.
        const reordered = { devices: list.devices.map(device => ({ meta: device.meta, addedAt: device.addedAt, deviceId: device.deviceId })), prevHash: list.prevHash, version: 2, userId: 'user_1', v: 1 };
        expect(Buffer.from(F.listBytes(reordered)).equals(Buffer.from(F.listBytes(list)))).toBe(true);
    });
    test('device-meta seed bytes, key and sealing are pinned (same vector in chatcore and apps/chat)', async () => {
        let seeded: Uint8Array | null = null;
        const key = await F.deviceMetaKey('user_1', async (bytes: Uint8Array) => { seeded = bytes; return new Uint8Array(64).fill(7); });
        expect(createHash('sha256').update(seeded!).digest('hex')).toBe('64af139533103232deb371d33f3f5879ff5c4d2259c243745d86b10f4b7b1c44');
        // Sealed by the app (apps/chat/test/devices_test.dart) under HKDF(seed = 64 × 0x07) with IV = 12 × 0x03.
        const sealed = 'AwMDAwMDAwMDAwMDGHB1mKscvERwIyTohJwm7EUEWZwtQS_mptDtAQajSQK2noBM4pRz0d5LshDjOeUsDYriASS_';
        expect(await F.openMeta(key, 'user_1', 'a'.repeat(22), sealed)).toEqual({ label: 'Mac app', platform: 'macos' });
    });
    test('non-canonical or malformed lists are refused', () => {
        const good = listOf('user_1', 1, '', [deviceId(), deviceId()]);
        const bad = [
            { ...good, extra: true },
            { ...good, devices: [...good.devices].reverse() },
            { ...good, devices: [good.devices[0], good.devices[0]] },
            { ...good, version: 2 }, // v2 needs the previous list's hash
            { ...good, prevHash: 'A'.repeat(43) }, // v1 has none
            { ...good, version: 0 },
            { ...good, devices: [] },
            { ...good, devices: Array.from({ length: 17 }, (_, index) => ({ deviceId: `${String(index).padStart(2, '0')}${'x'.repeat(20)}`, addedAt: 1, meta: '' })) },
            { ...good, devices: [{ ...good.devices[0], meta: 'too-short' }] },
            { ...good, devices: [{ ...good.devices[0], platform: 'web' }] }, // platforms are sealed in meta, never in clear
            { ...good, devices: [{ ...good.devices[0], extra: 1 }] },
            { ...good, version: 2, prevHash: 'A'.repeat(42) + 'B' }, // non-canonical base64 (trailing bits set)
            { ...good, userId: 'no spaces' },
        ];
        for (const list of bad) expect(() => F.listBytes(list)).toThrow();
    });
    test('labels and platforms are sealed per entry under a key only the identity-key holder derives', async () => {
        const ed25519 = async () => await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as unknown as CryptoKeyPair;
        const pair = await ed25519(), other = await ed25519();
        const signer = (keys: CryptoKeyPair) => async (bytes: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.sign('Ed25519', keys.privateKey, bytes));
        // Ed25519 is deterministic: deriving twice gives the same key, so any AIK holder can open what another sealed.
        const [key, again, stranger] = [await F.deviceMetaKey('alice', signer(pair)), await F.deviceMetaKey('alice', signer(pair)), await F.deviceMetaKey('alice', signer(other))];
        const [a, b] = [deviceId(), deviceId()];
        const meta = await F.sealMeta(key, 'alice', a, { label: 'Firefox on Linux', platform: 'linux' });
        expect(await F.openMeta(again, 'alice', a, meta)).toEqual({ label: 'Firefox on Linux', platform: 'linux' });
        expect(await F.openMeta(stranger, 'alice', a, meta)).toBeNull(); // another identity key
        expect(await F.openMeta(key, 'alice', b, meta)).toBeNull(); // moved to another entry
        expect(await F.openMeta(key, 'bob', a, meta)).toBeNull(); // moved to another account
        // The list carries only ciphertext; it is canonical and signed like any other entry.
        const list = { v: 1, userId: 'alice', version: 1, prevHash: '', devices: [{ deviceId: a, addedAt: 1, meta }] };
        expect(() => F.listBytes(list)).not.toThrow();
        expect(JSON.stringify(list)).not.toContain('linux');
        await expect(F.sealMeta(key, 'alice', a, { label: 'x', platform: 'toaster' })).rejects.toThrow();
    });
    test('verification: signature, certificates, owner, rollback and equivocation', async () => {
        const key = aik(), other = aik(), ids = [deviceId(), deviceId()];
        const v1 = signed(key, listOf('alice', 1, '', ids));
        const ok = await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v1 });
        expect(ok.ok).toBe(true);
        expect((await F.verifyView({ userId: 'alice', aikSign: other.pub, ...v1 })).reason).toBe('signature');
        expect((await F.verifyView({ userId: 'bob', aikSign: key.pub, ...v1 })).reason).toBe('owner');
        // A server-injected device: added to the list without the account key's signature.
        const injected = { ...v1, list: listOf('alice', 1, '', [...ids, deviceId()]) };
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...injected })).reason).toBe('signature');
        // A device whose certificate is missing or signed by another key.
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v1, certs: { [ids[0]!]: v1.certs[ids[0]!] } })).reason).toBe('certificate');
        const v2 = signed(key, listOf('alice', 2, ok.hash, ids.slice(0, 1)));
        const pinned = { aik: key.pub, version: 2, hash: hashOf(v2.list) };
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v1, pin: pinned })).reason).toBe('rollback');
        const fork = signed(key, listOf('alice', 2, ok.hash, ids)); // Same version, different content.
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...fork, pin: pinned })).reason).toBe('equivocation');
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v2, pin: pinned })).ok).toBe(true);
    });
    test('pins chain versions and keep tombstones: forks and returning removed devices are refused', async () => {
        const key = aik(), [a, b] = [deviceId(), deviceId()];
        const v1 = signed(key, listOf('alice', 1, '', [a, b]));
        const first = await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v1 });
        expect(first.pin).toEqual({ aik: key.pub, version: 1, hash: first.hash, devices: [a, b].sort(), revoked: [] });
        // The next version must name the pinned list as its predecessor.
        const forked = signed(key, listOf('alice', 2, 'A'.repeat(43), [a]));
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...forked, pin: first.pin })).reason).toBe('fork');
        const v2 = signed(key, listOf('alice', 2, first.hash, [a]));
        const second = await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v2, pin: first.pin });
        expect(second.pin.revoked).toEqual([b]);
        // b was dropped: a later list (even correctly signed and chained) cannot bring it back.
        const v3 = signed(key, listOf('alice', 3, second.hash, [a, b]));
        expect((await F.verifyView({ userId: 'alice', aikSign: key.pub, ...v3, pin: second.pin })).reason).toBe('revoked');
    });
});

let dataDir: string, app: ReturnType<typeof startSignaling>;
beforeEach(async () => { owners.clear(); deviceKeys.clear(); bound.clear(); dataDir = await mkdtemp(join(tmpdir(), 'devices-')); app = startSignaling({ adminToken: 'devices-test-admin-secret-0000000000000000', origin, port: 0, dataDir }); });
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });
const request = (path: string, method: string, cookie: string, body?: unknown) => fetch(new URL(path, app.server.url), {
    method, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(method !== 'GET' ? { Origin: origin } : {}) }, body: body === undefined ? undefined : JSON.stringify(body),
});
const read = async (response: Response) => ({ status: response.status, body: await response.json() as any });
// Which account each session (cookie or bearer token) belongs to, and each device's own key.
const owners = new Map<string, string>(), deviceKeys = new Map<string, Aik>(), bound = new Set<string>();
function account(name: string) {
    const created = app.accounts!.testing.createUser(name), key = aik();
    const session = () => { const cookie = app.accounts!.testing.cookie(created.id); owners.set(cookie, created.id); return cookie; };
    return { ...created, key, cookie: session(), session };
}
/** A native session (bearer token) of an account. */
function bearerFor(userId: string, client: string) { const token = app.accounts!.testing.bearer(userId, client); owners.set(token, userId); return token; }
/** POST from a web session (cookie) or a native one (bearer token). */
const post = (auth: string, path: string, body: unknown) => owners.has(auth) && auth.includes('=') ? request(path, 'POST', auth, body) : native(path, 'POST', auth, body);
/**
 * Binds a session to a device the way clients do: a fresh challenge signed with the device's own key
 * (created on first use of an id). `key` overrides the key that signs, to test impersonation.
 */
async function announce(auth: string, id: string, extra: Record<string, unknown> = {}, key?: Aik, prove?: Aik) {
    const userId = owners.get(auth)!;
    const { challenge } = (await read(await post(auth, '/api/devices/challenge', {}))).body;
    if (!deviceKeys.has(id)) deviceKeys.set(id, aik());
    const signer = key ?? deviceKeys.get(id)!;
    // `prove`: claim messaging with the account identity key's signature over this challenge (identityProof).
    const proof = prove ? { identityProof: signBytes(prove, F.claimBytes(userId, id, challenge)) } : {};
    const response = await post(auth, '/api/devices/announce', { deviceId: id, deviceKey: signer.pub, challenge, signature: signBytes(signer, F.bindBytes(userId, id, challenge)), ...proof, ...extra });
    if (response.status === 200) bound.add(auth);
    return response;
}
/** PUT /api/devices/list from a session, which (like the web client) first binds itself to the publishing device. */
async function publish(cookie: string, body: Record<string, any>) {
    if (!bound.has(cookie) && typeof body.deviceId === 'string') await announce(cookie, body.deviceId);
    return request('/api/devices/list', 'PUT', cookie, body);
}
async function publishKeys(user: ReturnType<typeof account>, cookie = user.cookie) {
    const prekey = randomBytes(32).toString('base64url'), identity = { dh: randomBytes(32).toString('base64url'), sign: user.key.pub };
    expect((await request('/api/keys', 'PUT', cookie, { identity, signedPreKey: { id: 1, key: prekey, signature: signBytes(user.key, Buffer.from(prekey)) }, oneTimePreKeys: [] })).status).toBe(200);
    return identity;
}
/** A native app's request: a bearer token and no Origin header. */
const native = (path: string, method: string, bearer: string, body?: unknown) => fetch(new URL(path, app.server.url), {
    method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body),
});
async function befriend(a: ReturnType<typeof account>, b: ReturnType<typeof account>) {
    expect((await request('/api/contacts', 'POST', a.cookie, { username: b.username })).status).toBe(202);
    expect((await request(`/api/contacts/${a.username}/accept`, 'POST', b.cookie, {})).status).toBe(200);
}
function events(cookie: string, bearer?: string) {
    const url = new URL('/api/events', app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { headers: bearer ? { Authorization: `Bearer ${bearer}` } : { Origin: origin, Cookie: cookie } } as any);
    const inbox: any[] = []; const waiters: ((value: any) => void)[] = [];
    socket.onmessage = event => { const message = JSON.parse(String(event.data)); const waiter = waiters.shift(); if (waiter) waiter(message); else inbox.push(message); };
    const raw = () => inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((resolve, reject) => { const timer = setTimeout(() => reject(new Error('timeout')), 2000); waiters.push(value => { clearTimeout(timer); resolve(value); }); });
    const next = async (type: string) => { for (;;) { const message = await raw(); if (message.type === type) return message; } };
    return { socket, next, opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })), closed: new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve as any, { once: true })) };
}

describe('device registry', () => {
    test('the identity-key holder publishes list v1; lists only move forward and only from the primary', async () => {
        const alice = account('alice'), mine = deviceId();
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(409); // keys first
        await publishKeys(alice);
        const v1 = signed(alice.key, listOf(alice.id, 1, '', [mine]));
        expect((await publish(alice.cookie, { ...v1, signature: signBytes(aik(), F.listBytes(v1.list)), deviceId: mine })).status).toBe(403); // wrong key
        expect((await publish(alice.cookie, { ...v1, deviceId: deviceId() })).status).toBe(400); // publisher not in the list
        expect((await publish(alice.cookie, { ...v1, deviceId: mine })).status).toBe(200);
        expect((await publish(alice.cookie, { ...v1, deviceId: mine })).status).toBe(409); // replay of v1
        const view = (await read(await request(`/api/devices/${alice.username}`, 'GET', alice.cookie))).body;
        expect(view.list).toEqual(v1.list);
        expect(view.devices).toEqual([expect.objectContaining({ id: mine, state: 'listed', primary: true, current: true })]);
        const second = deviceId(), hash1 = hashOf(v1.list);
        // A list that does not chain to the current one, and one from another session of the same account, are refused:
        // an unbound session, and one bound to another device.
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 2, 'A'.repeat(43), [mine, second])), deviceId: mine })).status).toBe(409);
        expect((await request('/api/devices/list', 'PUT', alice.session(), { ...signed(alice.key, listOf(alice.id, 2, hash1, [mine, second])), deviceId: mine })).status).toBe(403);
        const other = alice.session();
        expect((await announce(other, second)).status).toBe(200);
        expect((await request('/api/devices/list', 'PUT', other, { ...signed(alice.key, listOf(alice.id, 2, hash1, [mine, second])), deviceId: mine })).status).toBe(403);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 2, hash1, [mine, second])), deviceId: mine })).status).toBe(200);
        // A replay of an older version after v2 is refused too.
        expect((await publish(alice.cookie, { ...v1, deviceId: mine })).status).toBe(409);
    });
    test('lists are bound to the session account, exactly the next version, and never revive a revoked device', async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId(), gone = deviceId(), goneCookie = alice.session();
        await publishKeys(alice); await publishKeys(bob);
        // A list alice signed, uploaded by bob's session: the signed userId is not the caller.
        const forAlice = signed(alice.key, listOf(alice.id, 1, '', [mine]));
        expect((await request('/api/devices/list', 'PUT', bob.cookie, { ...forAlice, deviceId: mine })).status).toBe(400);
        // A list naming bob but signed with alice's key fails bob's stored identity key.
        expect((await request('/api/devices/list', 'PUT', bob.cookie, { ...signed(alice.key, listOf(bob.id, 1, '', [deviceId()])), deviceId: deviceId() })).status).toBe(403);
        await announce(goneCookie, gone);
        const v1 = signed(alice.key, listOf(alice.id, 1, '', [mine, gone]));
        expect((await publish(alice.cookie, { ...v1, deviceId: mine })).status).toBe(200);
        // Skipping a version, or the same version with other content, is refused.
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 3, hashOf(v1.list), [mine])), deviceId: mine })).status).toBe(409);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(409);
        // A listed device cannot remove itself; the primary drops it with v2 (a tombstone stays).
        expect((await request(`/api/devices/${gone}`, 'DELETE', goneCookie, {})).status).toBe(403);
        const v2 = signed(alice.key, listOf(alice.id, 2, hashOf(v1.list), [mine]));
        expect((await publish(alice.cookie, { ...v2, deviceId: mine })).status).toBe(200);
        expect((await request('/api/me', 'GET', goneCookie)).status).toBe(401);
        const v3 = signed(alice.key, listOf(alice.id, 3, hashOf(v2.list), [mine, gone]));
        expect((await publish(alice.cookie, { ...v3, deviceId: mine })).status).toBe(409);
        expect((await announce(alice.session(), gone)).status).toBe(409);
    });
    test('a pending device may remove only itself; it cannot remove the primary or another account\'s device', async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId(), pending = deviceId(), pendingCookie = alice.session(), bobDevice = deviceId();
        await publishKeys(alice); await publishKeys(bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        expect((await publish(bob.cookie, { ...signed(bob.key, listOf(bob.id, 1, '', [bobDevice])), deviceId: bobDevice })).status).toBe(200);
        await announce(pendingCookie, pending);
        expect((await request(`/api/devices/${mine}`, 'DELETE', pendingCookie, {})).status).toBe(403);
        expect((await request(`/api/devices/${bobDevice}`, 'DELETE', alice.cookie, {})).status).toBe(404);
        expect((await request(`/api/devices/${pending}`, 'DELETE', pendingCookie, {})).status).toBe(200);
        expect((await request('/api/me', 'GET', pendingCookie)).status).toBe(401);
        expect((await request('/api/me', 'GET', alice.cookie)).status).toBe(200);
    });
    test('device ids belong to one account, and an account has at most 16 devices', async () => {
        const alice = account('alice'), bob = account('bob'), aliceDevice = deviceId();
        await publishKeys(alice); await publishKeys(bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [aliceDevice])), deviceId: aliceDevice })).status).toBe(200);
        const bobDevice = deviceId();
        expect((await publish(bob.cookie, { ...signed(bob.key, listOf(bob.id, 1, '', [bobDevice, aliceDevice])), deviceId: bobDevice })).status).toBe(409);
        expect((await announce(bob.cookie, aliceDevice)).status).toBe(409);
        for (let index = 0; index < 15; index++) expect((await announce(alice.session(), deviceId())).status).toBe(200);
        expect((await announce(alice.session(), deviceId())).status).toBe(429);
    });
    test('contacts see only the signed list; strangers see nothing', async () => {
        const alice = account('alice'), bob = account('bob'), carol = account('carol'), mine = deviceId();
        await publishKeys(alice); await befriend(alice, bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine, label: 'A'.repeat(40) })).status).toBe(200);
        await announce(alice.session(), deviceId());
        const seen = (await read(await request(`/api/devices/${alice.username}`, 'GET', bob.cookie))).body;
        expect(Object.keys(seen).sort()).toEqual(['certs', 'identity', 'list', 'signature', 'userId']);
        expect((await F.verifyView({ userId: alice.id, aikSign: alice.key.pub, ...seen })).ok).toBe(true);
        expect((await request(`/api/devices/${alice.username}`, 'GET', carol.cookie)).status).toBe(403);
    });
    test('the primary removes a pending device: its sessions end and its stream closes; others cannot remove', async () => {
        const alice = account('alice'), mine = deviceId(), other = deviceId(), otherCookie = alice.session();
        await publishKeys(alice);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        expect((await announce(otherCookie, other)).status).toBe(200);
        const stream = events(otherCookie); await stream.opened;
        expect((await request(`/api/devices/${mine}`, 'DELETE', otherCookie, {})).status).toBe(403);
        expect((await request(`/api/devices/${mine}`, 'DELETE', alice.cookie, {})).status).toBe(400); // not itself
        expect((await request(`/api/devices/${other}`, 'DELETE', alice.cookie, {})).status).toBe(200);
        expect((await stream.closed).code).toBe(4401);
        expect((await request('/api/me', 'GET', otherCookie)).status).toBe(401);
        const view = (await read(await request(`/api/devices/${alice.username}`, 'GET', alice.cookie))).body;
        expect(view.devices.map((row: any) => row.id)).toEqual([mine]);
    });
    test('removing a listed device needs the next signed list without it', async () => {
        const alice = account('alice'), mine = deviceId(), other = deviceId(), otherCookie = alice.session();
        await publishKeys(alice);
        await announce(otherCookie, other);
        const v1 = signed(alice.key, { ...listOf(alice.id, 1, '', [mine, other]), devices: [mine, other].sort().map(id => ({ deviceId: id, addedAt: 5, meta: '' })) });
        expect((await publish(alice.cookie, { ...v1, deviceId: mine })).status).toBe(200);
        expect((await request(`/api/devices/${other}`, 'DELETE', alice.cookie, {})).status).toBe(400);
        const v2 = signed(alice.key, { ...listOf(alice.id, 2, hashOf(v1.list), [mine]), devices: [{ deviceId: mine, addedAt: 5, meta: '' }] });
        expect((await read(await request(`/api/devices/${other}`, 'DELETE', alice.cookie, v2))).body.revoked).toEqual([other]);
        expect((await request('/api/me', 'GET', otherCookie)).status).toBe(401);
    });
    test('envelopes go to the messaging device: a placeholder until the key holder publishes, then that device', async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId();
        await publishKeys(alice); await befriend(alice, bob);
        const early = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        expect(early.status).toBe(201);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        const db = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect(db.query('SELECT device_id FROM device_inbox WHERE id = ?').get(early.body.id)).toEqual({ device_id: mine });
        expect((db.query("SELECT COUNT(*) AS count FROM devices WHERE state = 'placeholder'").get() as any).count).toBe(0);
        db.close();
        // A pending (non-key-holding) browser does not read the primary's inbox; the primary does.
        const pendingCookie = alice.session();
        await announce(pendingCookie, deviceId());
        const pending = events(pendingCookie); await pending.opened; await pending.next('hello');
        const primary = events(alice.cookie); await primary.opened;
        expect((await primary.next('envelope')).id).toBe(early.body.id);
        await expect(pending.next('envelope')).rejects.toThrow('timeout');
        pending.socket.close(); primary.socket.close();
    });
    test('before any list is published, every signed-in device reads the placeholder inbox (pre-M1 behaviour)', async () => {
        const alice = account('alice'), bob = account('bob'), pendingCookie = alice.session();
        await publishKeys(alice); await befriend(alice, bob);
        await announce(pendingCookie, deviceId());
        const sent = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        const stream = events(pendingCookie); await stream.opened;
        expect((await stream.next('envelope')).id).toBe(sent.body.id);
        stream.socket.close();
    });
    test('a new identity voids the old lists; the new key holder starts again at version 1', async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId();
        await publishKeys(alice); await befriend(alice, bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        const watch = events(bob.cookie); await watch.opened;
        const newcomer = account('alice2'); // only for a fresh key pair
        const fresh = alice.session(), next = deviceId();
        await publishKeys({ ...alice, key: newcomer.key }, fresh);
        expect(await watch.next('devices')).toEqual({ type: 'devices', id: alice.id });
        const view = (await read(await request(`/api/devices/${alice.username}`, 'GET', alice.cookie))).body;
        expect(view.list).toBeNull();
        expect((await publish(fresh, { ...signed(newcomer.key, listOf(alice.id, 2, 'A'.repeat(43), [next])), deviceId: next })).status).toBe(409);
        expect((await publish(fresh, { ...signed(newcomer.key, listOf(alice.id, 1, '', [next])), deviceId: next })).status).toBe(200);
        watch.socket.close();
    });
});

describe('messaging device and per-device delivery', () => {
    test('a native app holding the published identity claims the inbox; other devices read only their own', async () => {
        const alice = account('alice'), bob = account('bob'), phone = deviceId(), laptop = deviceId(), laptopCookie = alice.session();
        const identity = await publishKeys(alice); await befriend(alice, bob);
        const early = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        const bearer = bearerFor(alice.id, 'ios');
        // A wrong identity is just a pending device; the published one moves messaging (and the waiting envelope) there.
        // Naming the (public) identity proves nothing; a proof by another key is refused; the identity key's proof claims.
        expect((await read(await announce(bearer, phone, { identity }))).body).toEqual({ deviceId: phone, state: 'pending', primary: false });
        expect((await announce(bearer, phone, {}, undefined, aik())).status).toBe(403);
        expect((await read(await announce(bearer, phone, {}, undefined, alice.key))).body).toEqual({ deviceId: phone, state: 'pending', primary: true });
        expect((await announce(laptopCookie, laptop)).status).toBe(200);
        const db = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect(db.query('SELECT device_id FROM device_inbox WHERE id = ?').get(early.body.id)).toEqual({ device_id: phone });
        expect(db.query('SELECT platform FROM devices WHERE id = ?').get(phone)).toEqual({ platform: 'ios' });
        expect((db.query("SELECT COUNT(*) AS count FROM devices WHERE state = 'placeholder'").get() as any).count).toBe(0);
        db.close();
        const phoneStream = events('', bearer), laptopStream = events(laptopCookie);
        await phoneStream.opened; await laptopStream.opened; await laptopStream.next('hello');
        expect((await phoneStream.next('envelope')).id).toBe(early.body.id);
        // A receipt is an ordinary envelope: it reaches the messaging device only, and only that device may acknowledge it.
        const receipt = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(48).toString('base64url') }));
        expect((await phoneStream.next('envelope')).id).toBe(receipt.body.id);
        laptopStream.socket.send(JSON.stringify({ type: 'ack', id: receipt.body.id }));
        // Typing no longer travels as a 1:1 envelope (it goes over MLS): refused, and nothing is stored or delivered.
        expect((await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(32).toString('base64url'), ephemeral: true }))).status).toBe(410);
        await Bun.sleep(50);
        const after = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect((after.query('SELECT device_id FROM device_inbox ORDER BY created_at').all() as any[]).map(row => row.device_id)).toEqual([phone, phone]);
        after.close();
        phoneStream.socket.send(JSON.stringify({ type: 'ack', id: receipt.body.id }));
        await Bun.sleep(50);
        const acked = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect(acked.query('SELECT id FROM device_inbox WHERE id = ?').get(receipt.body.id)).toBeNull();
        acked.close();
        phoneStream.socket.close(); laptopStream.socket.close();
    });
    test('claiming needs the identity key: proofs replayed from another challenge, device or account, and key re-uploads, claim nothing', async () => {
        const alice = account('alice'), bob = account('bob'), phone = deviceId(), other = deviceId();
        const identity = await publishKeys(alice); await publishKeys(bob); await befriend(alice, bob);
        const waiting = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        const bearer = bearerFor(alice.id, 'ios');
        const placeholder = () => { const db = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true }); const row = db.query('SELECT d.state FROM device_inbox i JOIN devices d ON d.id = i.device_id WHERE i.id = ?').get(waiting.body.id) as any; db.close(); return row?.state; };
        // Bind without a claim, then try proofs made for something else.
        expect((await read(await announce(bearer, phone))).body.primary).toBe(false);
        const challenge = async () => (await read(await native('/api/devices/challenge', 'POST', bearer, {}))).body.challenge as string;
        const attempt = async (proofFor: (challenge: string) => Uint8Array, nonce?: string) => {
            const fresh = nonce ?? await challenge();
            return native('/api/devices/announce', 'POST', bearer, { deviceId: phone, challenge: fresh, signature: signBytes(deviceKeys.get(phone)!, F.bindBytes(alice.id, phone, fresh)), identityProof: signBytes(alice.key, proofFor(fresh)) });
        };
        const old = await challenge();
        expect((await attempt(() => F.claimBytes(alice.id, phone, old))).status).toBe(403); // another challenge
        expect((await attempt(fresh => F.claimBytes(alice.id, other, fresh))).status).toBe(403); // another device
        expect((await attempt(fresh => F.claimBytes(bob.id, phone, fresh))).status).toBe(403); // another account
        expect((await attempt(fresh => F.bindBytes(alice.id, phone, fresh))).status).toBe(403); // a binding signature is not a claim
        // Re-uploading the unchanged public identity from the bound session claims nothing either.
        expect((await native('/api/keys', 'PUT', bearer, { identity, oneTimePreKeys: [] })).status).toBe(200);
        expect(placeholder()).toBe('placeholder');
        // The identity key's proof for this challenge, device and account claims the inbox.
        expect((await read(await attempt(fresh => F.claimBytes(alice.id, phone, fresh)))).body.primary).toBe(true);
        expect(placeholder()).toBe('pending');
    });
    test('a signed list outranks a claim: the listed primary keeps the inbox', async () => {
        const alice = account('alice'), mine = deviceId(), phone = deviceId();
        const identity = await publishKeys(alice);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        const bearer = bearerFor(alice.id, 'android');
        expect((await read(await announce(bearer, phone, {}, undefined, alice.key))).body).toEqual({ deviceId: phone, state: 'pending', primary: false });
        const view = (await read(await request(`/api/devices/${alice.username}`, 'GET', alice.cookie))).body;
        expect(view.devices.find((row: any) => row.primary).id).toBe(mine);
    });
    test('taking over with new keys moves the inbox to the uploading device', async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId(), phone = deviceId();
        await publishKeys(alice); await befriend(alice, bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        const waiting = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        const phoneCookie = alice.session();
        expect((await announce(phoneCookie, phone)).status).toBe(200);
        await publishKeys({ ...alice, key: aik() }, phoneCookie); // a new identity from the phone's session
        const db = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect(db.query('SELECT device_id FROM device_inbox WHERE id = ?').get(waiting.body.id)).toEqual({ device_id: phone });
        expect(db.query('SELECT state, is_primary FROM devices WHERE id = ?').get(phone)).toEqual({ state: 'pending', is_primary: 1 });
        expect(db.query('SELECT state, is_primary FROM devices WHERE id = ?').get(mine)).toEqual({ state: 'pending', is_primary: 0 });
        db.close();
    });
});

describe('binding a session to a device needs proof of possession', () => {
    test("a second session cannot become the primary by announcing its id; the real device (signed in again) can", async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId();
        await publishKeys(alice); await befriend(alice, bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        const intruder = alice.session();
        // No challenge, a replayed challenge, another key, and a proof made for another account: all refused.
        expect((await request('/api/devices/announce', 'POST', intruder, { deviceId: mine, deviceKey: aik().pub, challenge: 'A'.repeat(43), signature: 'A'.repeat(86) })).status).toBe(401);
        expect((await announce(intruder, mine, {}, aik())).status).toBe(403);
        const { challenge } = (await read(await request('/api/devices/challenge', 'POST', intruder, {}))).body;
        const key = deviceKeys.get(mine)!;
        expect((await request('/api/devices/announce', 'POST', intruder, { deviceId: mine, challenge, signature: signBytes(key, F.bindBytes(bob.id, mine, challenge)) })).status).toBe(403);
        expect((await request('/api/devices/announce', 'POST', intruder, { deviceId: mine, challenge, signature: signBytes(key, F.bindBytes(alice.id, mine, challenge)) })).status).toBe(401); // spent
        // The intruder is still unbound: no inbox, no list changes, and the primary keeps its inbox.
        const sent = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        const stream = events(intruder); await stream.opened; await stream.next('hello');
        await expect(stream.next('envelope')).rejects.toThrow('timeout');
        stream.socket.close();
        expect((await request(`/api/devices/${deviceId()}`, 'DELETE', intruder, {})).status).toBe(403);
        // The same browser, signed in again, proves it holds the device key and gets its inbox back.
        const again = alice.session();
        expect((await read(await announce(again, mine))).body).toEqual({ deviceId: mine, state: 'listed', primary: true });
        const back = events(again); await back.opened;
        expect((await back.next('envelope')).id).toBe(sent.body.id);
        back.socket.close();
    });
    test('overlapping challenges of one session are each usable once (tabs, reconnects)', async () => {
        const alice = account('alice'), id = deviceId(), key = aik();
        const ask = async () => (await read(await request('/api/devices/challenge', 'POST', alice.cookie, {}))).body.challenge as string;
        const [first, second] = [await ask(), await ask()];
        const bind = (challenge: string) => request('/api/devices/announce', 'POST', alice.cookie, { deviceId: id, deviceKey: key.pub, challenge, signature: signBytes(key, F.bindBytes(alice.id, id, challenge)) });
        expect((await bind(second)).status).toBe(200);
        expect((await bind(first)).status).toBe(200);
        expect((await bind(first)).status).toBe(401);
    });
    test('an unbound session of a listed account gets no envelopes and cannot acknowledge any', async () => {
        const alice = account('alice'), bob = account('bob'), mine = deviceId();
        await publishKeys(alice); await befriend(alice, bob);
        expect((await publish(alice.cookie, { ...signed(alice.key, listOf(alice.id, 1, '', [mine])), deviceId: mine })).status).toBe(200);
        const sent = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        // A legacy native app (never announces) and a fresh browser session: no fallback to the primary's inbox.
        const legacy = events('', bearerFor(alice.id, 'android')), fresh = events(alice.session());
        await legacy.opened; await fresh.opened; await legacy.next('hello'); await fresh.next('hello');
        await expect(legacy.next('envelope')).rejects.toThrow('timeout');
        await expect(fresh.next('envelope')).rejects.toThrow('timeout');
        fresh.socket.send(JSON.stringify({ type: 'ack', id: sent.body.id }));
        await Bun.sleep(50);
        const db = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect(db.query('SELECT device_id FROM device_inbox WHERE id = ?').get(sent.body.id)).toEqual({ device_id: mine });
        db.close();
        legacy.socket.close(); fresh.socket.close();
    });
    test('legacy state: while the primary is a placeholder, an unbound session (an old app) still gets its mail', async () => {
        const alice = account('alice'), bob = account('bob');
        await publishKeys(alice); await befriend(alice, bob);
        const sent = await read(await request('/api/messages', 'POST', bob.cookie, { to: 'alice', envelope: randomBytes(64).toString('base64url') }));
        const legacy = events('', bearerFor(alice.id, 'ios')); await legacy.opened;
        const delivered = await legacy.next('envelope');
        expect(delivered.id).toBe(sent.body.id);
        legacy.socket.send(JSON.stringify({ type: 'ack', id: sent.body.id }));
        await Bun.sleep(50);
        const db = new Database(join(dataDir, 'accounts.sqlite'), { readonly: true });
        expect(db.query('SELECT 1 FROM device_inbox WHERE id = ?').get(sent.body.id)).toBeNull();
        db.close();
        legacy.socket.close();
    });
});

describe('bind challenges are bounded', () => {
    test('one account cannot exhaust challenges: per-account rate limit, and a cap on sessions holding them', async () => {
        const alice = account('alice'), bob = account('bob');
        const statuses: number[] = [];
        for (let i = 0; i < 40; i++) statuses.push((await request('/api/devices/challenge', 'POST', alice.cookie, {})).status);
        expect(statuses.slice(0, 30).every(status => status === 200)).toBe(true);
        expect(statuses.slice(30)).toContain(429);
        // Another account is unaffected.
        expect((await request('/api/devices/challenge', 'POST', bob.cookie, {})).status).toBe(200);
    });
});

describe('migrations', () => {
    // 0: production before numbering; 1: a v1 (numbered, pre-M1) database. Both hold waiting mail and sessions.
    test.each([0, 1])('a populated pre-M1 database (user_version %d) migrates once: mailbox → device inboxes, sessions gain devices', async version => {
        const dir = await mkdtemp(join(tmpdir(), 'devices-migrate-'));
        try {
            const old = new Database(join(dir, 'accounts.sqlite'), { create: true });
            // The schema exactly as production ran it before numbered migrations.
            old.exec(`
                CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
                CREATE TABLE credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL);
                CREATE TABLE invites (code_hash TEXT PRIMARY KEY, created_by TEXT REFERENCES users(id) ON DELETE SET NULL, expires_at INTEGER NOT NULL, used_by TEXT REFERENCES users(id) ON DELETE SET NULL);
                CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, client TEXT NOT NULL DEFAULT 'web');
                CREATE TABLE contacts (user_id TEXT NOT NULL, contact_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, contact_id));
                CREATE TABLE identity_keys (user_id TEXT PRIMARY KEY, dh TEXT NOT NULL, sign TEXT NOT NULL, updated_at INTEGER NOT NULL);
                CREATE TABLE signed_prekeys (user_id TEXT PRIMARY KEY, key_id INTEGER NOT NULL, key TEXT NOT NULL, signature TEXT NOT NULL);
                CREATE TABLE one_time_prekeys (user_id TEXT NOT NULL, key_id INTEGER NOT NULL, key TEXT NOT NULL, PRIMARY KEY (user_id, key_id));
                CREATE TABLE mailbox (id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, envelope BLOB NOT NULL, created_at INTEGER NOT NULL);
                CREATE INDEX mailbox_recipient ON mailbox (recipient_id, created_at);
                CREATE INDEX mailbox_age ON mailbox (created_at);
                CREATE TABLE contact_requests (user_id TEXT NOT NULL, username TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, username));
                CREATE TABLE push_subscriptions (endpoint TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_hash TEXT NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL);
            `);
            const now = Date.now();
            for (const [id, name] of [['u1', 'alice'], ['u2', 'bob'], ['u3', 'carol']]) old.query('INSERT INTO users VALUES (?, ?, ?)').run(id, name, now);
            const migratedKey = aik();
            old.query('INSERT INTO identity_keys VALUES (?, ?, ?, ?)').run('u1', 'D'.repeat(43), migratedKey.pub, now);
            old.query("INSERT INTO sessions VALUES ('t1', 'u1', ?, 'web')").run(now + 1e9);
            for (let index = 0; index < 3; index++) old.query('INSERT INTO mailbox VALUES (?, ?, ?, ?, ?)').run(`m${index}${'x'.repeat(20)}`, index < 2 ? 'u1' : 'u2', 'u3', new Uint8Array([index]), now + index);
            old.exec(`PRAGMA user_version = ${version}`);
            old.close();

            const db = openDatabase(dir);
            expect((db.query('PRAGMA user_version').get() as any).user_version).toBe(SCHEMA_VERSION);
            expect(db.query("SELECT name FROM sqlite_master WHERE name = 'mailbox'").get()).toBeNull();
            const inbox = db.query('SELECT i.id, i.recipient_id, d.state, d.is_primary FROM device_inbox i JOIN devices d ON d.id = i.device_id ORDER BY i.created_at').all() as any[];
            expect(inbox.map(row => [row.id.slice(0, 2), row.recipient_id, row.state, row.is_primary])).toEqual([['m0', 'u1', 'placeholder', 1], ['m1', 'u1', 'placeholder', 1], ['m2', 'u2', 'placeholder', 1]]);
            expect(db.query("SELECT device_id FROM sessions WHERE token_hash = 't1'").get()).toEqual({ device_id: null });
            expect(db.query("SELECT sign FROM identity_keys WHERE user_id = 'u1'").get()).toEqual({ sign: migratedKey.pub }); // safety numbers unchanged
            db.close();
            // Opening again changes nothing.
            const again = openDatabase(dir);
            expect((again.query('SELECT COUNT(*) AS count FROM devices').get() as any).count).toBe(2);
            expect((again.query('SELECT COUNT(*) AS count FROM device_inbox').get() as any).count).toBe(3);
            again.close();
            // End to end: alice's key-holding app claims the placeholder and receives the mail that waited across the migration.
            const migrated = startSignaling({ adminToken: 'devices-test-admin-secret-0000000000000000', origin, port: 0, dataDir: dir });
            try {
                const bearer = migrated.accounts!.testing.bearer('u1', 'android'), phone = deviceId();
                const call = (path: string, body: unknown) => fetch(new URL(path, migrated.server.url), { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: JSON.stringify(body) });
                const { challenge } = await (await call('/api/devices/challenge', {})).json() as any, key = aik();
                const announced = await call('/api/devices/announce', { deviceId: phone, deviceKey: key.pub, challenge, signature: signBytes(key, F.bindBytes('u1', phone, challenge)), identityProof: signBytes(migratedKey, F.claimBytes('u1', phone, challenge)) });
                expect(((await announced.json()) as any).primary).toBe(true);
                const url = new URL('/api/events', migrated.server.url); url.protocol = 'ws:';
                const socket = new WebSocket(url, { headers: { Authorization: `Bearer ${bearer}` } } as any);
                const ids: string[] = [];
                await new Promise<void>((resolve, reject) => {
                    const timer = setTimeout(() => reject(new Error('timeout')), 2000);
                    socket.onmessage = event => { const message = JSON.parse(String(event.data)); if (message.type === 'envelope') ids.push(message.id.slice(0, 2)); if (ids.length === 2) { clearTimeout(timer); resolve(); } };
                });
                expect(ids).toEqual(['m0', 'm1']);
                socket.close();
            } finally { await migrated.stop(); }
        } finally { await rm(dir, { recursive: true, force: true }); }
    });
    test('a database newer than this server is refused', async () => {
        const dir = await mkdtemp(join(tmpdir(), 'devices-future-'));
        try {
            const db = new Database(join(dir, 'accounts.sqlite'), { create: true });
            db.exec(`PRAGMA user_version = ${SCHEMA_VERSION + 1}`); db.close();
            expect(() => openDatabase(dir)).toThrow('newer than this server');
        } finally { await rm(dir, { recursive: true, force: true }); }
    });
});
