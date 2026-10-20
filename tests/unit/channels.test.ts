import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cpSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import '../../packages/signaling/public/devices.js';
import { startSignaling } from '../../packages/signaling/server';
import { resolveBytes } from '../../packages/signaling/channels';
import { Client, clientCore, enroll, id, pinAll, type Device, type User } from './helpers/mls';

// The MLS delivery service end to end: real chatcore clients (WebAssembly) against a real server. Skipped, loudly,
// where the Rust toolchain isn't available (CI's `core` job runs them).
const loaded = clientCore();
if ('skip' in loaded) console.warn(`channels.test.ts skipped: ${loaded.skip}`);
const suite = 'core' in loaded ? describe : describe.skip;
const origin = 'http://localhost:3000';

let dataDir: string, app: ReturnType<typeof startSignaling>, clock: number;
const Core = 'core' in loaded ? loaded.core : (undefined as never);
/** What devices talk to: always the current server (a test may restart it). */
const ctx = { get server() { return app.server; }, get accounts() { return app.accounts; } };

async function start(options: Record<string, unknown> = {}) {
    dataDir = await mkdtemp(join(tmpdir(), 'channels-'));
    clock = Date.now();
    app = startSignaling({ adminToken: 'channels-test-admin-secret-0000000000000', origin, port: 0, dataDir, now: () => clock, trustProxy: true, ...options });
}
afterEach(async () => { await app?.stop(); await rm(dataDir, { recursive: true, force: true }); });

const request = (path: string, method: string, cookie: string, body?: unknown) => fetch(new URL(path, app.server.url), {
    method, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(method !== 'GET' ? { Origin: origin } : {}) }, body: body === undefined ? undefined : JSON.stringify(body),
});
function user(name: string): User & { cookie: string } { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; }
async function befriend(a: ReturnType<typeof user>, b: ReturnType<typeof user>) {
    expect((await request('/api/contacts', 'POST', a.cookie, { username: b.username })).status).toBe(202);
    expect((await request(`/api/contacts/${a.username}/accept`, 'POST', b.cookie, {})).status).toBe(200);
}

/** Alice (admin, two devices), Bob (two devices) and Carol (one), all mutual contacts, every device listed and pinned. */
async function world() {
    await start();
    const [alice, bob, carol] = [user('alice'), user('bob'), user('carol')];
    await befriend(alice, bob); await befriend(alice, carol); await befriend(bob, carol);
    const a1 = enroll(ctx, alice, new Client(Core)), a2 = enroll(ctx, alice, a1.client.sibling(), 'ios');
    const b1 = enroll(ctx, bob, new Client(Core), 'web'), b2 = enroll(ctx, bob, b1.client.sibling(), 'android');
    const c1 = enroll(ctx, carol, new Client(Core), 'macos');
    const all = [a1, a2, b1, b2, c1];
    pinAll(all);
    for (const device of all) await device.uploadKeyPackages(10);
    return { alice, bob, carol, a1, a2, b1, b2, c1, all };
}
/** A private channel created by a1 with everyone in it and every device caught up. */
async function populated() {
    const w = await world();
    const { channel } = await w.a1.createChannel('private');
    const added = await w.a1.add(channel, [w.alice.id, w.bob.id, w.carol.id]);
    expect(added.status).toBe(201);
    for (const device of [w.a2, w.b1, w.b2, w.c1]) expect(await device.joinWelcomes()).toEqual([channel]);
    return { ...w, channel };
}


/** Moves the clock, keeps every session alive and runs the retention sweep. */
function advance(ms: number) { clock += ms; run('UPDATE sessions SET expires_at = ?', clock + 86400000); app.channels!.sweep(true); }
const flip = (text: string, at: number) => { const bytes = Buffer.from(text, 'base64url'); bytes[at < 0 ? bytes.length + at : at] ^= 1; return bytes.toString('base64url'); };
const rows = (sql: string, ...params: any[]) => app.accounts!.testing.db.query(sql).all(...params) as any[];
const one = (sql: string, ...params: any[]) => rows(sql, ...params)[0];
const run = (sql: string, ...params: any[]) => app.accounts!.testing.db.query(sql).run(...params);

suite('KeyPackages', () => {
    beforeEach(async () => { await start(); });
    async function pair() {
        const [alice, bob, carol] = [user('alice'), user('bob'), user('carol')];
        await befriend(alice, bob);
        const a1 = enroll(ctx, alice, new Client(Core)), b1 = enroll(ctx, bob, new Client(Core)), a2 = enroll(ctx, alice, a1.client.sibling());
        pinAll([a1, b1, a2]);
        return { alice, bob, carol, a1, a2, b1 };
    }

    test('only a listed device uploads, and only KeyPackages certified for it by its account key', async () => {
        const { a1, a2, b1 } = await pair();
        const kps = a1.client.call({ cmd: 'mlsKeyPackages', count: 2 });
        // Another account's session, or another device of the same account, can't store them.
        expect([400, 403]).toContain((await b1.api('PUT', '/api/mls/keypackages', { keyPackages: kps })).status); // unverifiable here, or not certified for bob
        expect((await a2.api('PUT', '/api/mls/keypackages', { keyPackages: kps })).status).toBe(403);
        // A device that isn't in the signed list (pending, revoked) is refused before anything is read.
        run("UPDATE devices SET state = 'pending' WHERE id = ?", a1.deviceId);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: kps })).status).toBe(403);
        expect((await a1.api('POST', '/api/mls/keypackages/claim', { users: [a1.user.id] })).status).toBe(403);
        run("UPDATE devices SET state = 'listed' WHERE id = ?", a1.deviceId);
        // After an identity change the lists are void: the device is no longer eligible even though it is 'listed'.
        run("UPDATE device_lists SET aik_sign = 'other' WHERE user_id = ?", a1.user.id);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: kps })).status).toBe(403);
        run('UPDATE device_lists SET aik_sign = (SELECT sign FROM identity_keys WHERE user_id = ?) WHERE user_id = ?', a1.user.id, a1.user.id);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: kps })).status).toBe(201);
        // Garbage, duplicates, wrong slots and oversize.
        await Bun.sleep(1100); // upload is rate limited
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: ['AAAA'] })).status).toBe(400);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: [kps[0]] })).status).toBe(409);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: [flip(kps[0], 40)] })).status).toBe(400);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: ['A'.repeat(6000)] })).status).toBe(400);
        const lastResort = a1.client.call({ cmd: 'mlsKeyPackages', count: 1, lastResort: true })[0];
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: [lastResort] })).status).toBe(400); // a last-resort one goes in lastResort
        await Bun.sleep(1100);
        expect((await a1.api('PUT', '/api/mls/keypackages', { lastResort: a1.client.call({ cmd: 'mlsKeyPackages', count: 1 })[0] })).status).toBe(400);
        expect((await a1.api('PUT', '/api/mls/keypackages', {})).status).toBe(400);
        expect((await a1.api('PUT', '/api/mls/keypackages', { lastResort })).status).toBe(201);
        expect(await (await a1.api('GET', '/api/mls/keypackages')).body).toMatchObject({ oneTime: 2, lastResort: true, low: true, max: 100 });
    });

    test('at most 100 one-time KeyPackages per device; the low-water mark is reported', async () => {
        const { a1 } = await pair();
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: a1.client.call({ cmd: 'mlsKeyPackages', count: 100 }) })).body).toMatchObject({ oneTime: 100, low: false });
        const more = a1.client.call({ cmd: 'mlsKeyPackages', count: 1 });
        const over = await a1.api('PUT', '/api/mls/keypackages', { keyPackages: more });
        expect(over.status).toBe(400);
        expect(over.body.oneTime).toBe(100);
        expect((await a1.api('PUT', '/api/mls/keypackages', { keyPackages: Array(101).fill(more[0]) })).status).toBe(400);
    });

    test('lifetimes: a KeyPackage is kept until it expires (about 90 days) and then swept', async () => {
        const { a1 } = await pair();
        await a1.uploadKeyPackages(3);
        const stored = one('SELECT expires_at FROM mls_key_packages WHERE device_id = ? AND last_resort = 0', a1.deviceId);
        const days = (stored.expires_at * 1000 - clock) / 86400000;
        expect(days).toBeGreaterThan(89); expect(days).toBeLessThan(91.1);
        advance(89 * 86400000);
        expect(rows('SELECT 1 FROM mls_key_packages').length).toBe(4);
        advance(3 * 86400000);
        expect(rows('SELECT 1 FROM mls_key_packages').length).toBe(0);
    });

    test('claims hand out one package per device, spend one-time ones, then fall back to the reusable last-resort one', async () => {
        const { alice, bob, a1, b1 } = await pair();
        const b2 = enroll(ctx, bob, b1.client.sibling());
        pinAll([a1, b1, b2]);
        expect((await b1.api('PUT', '/api/mls/keypackages', { keyPackages: b1.client.call({ cmd: 'mlsKeyPackages', count: 2 }), lastResort: b1.client.call({ cmd: 'mlsKeyPackages', count: 1, lastResort: true })[0] })).status).toBe(201);
        await b2.uploadKeyPackages(1);
        const claim = async () => (await a1.must('POST', '/api/mls/keypackages/claim', { users: [bob.id] }, 200));
        let got = await claim();
        expect(got.keyPackages.map((item: any) => item.deviceId).sort()).toEqual([b1.deviceId, b2.deviceId].sort());
        expect(got.keyPackages.every((item: any) => !item.lastResort)).toBe(true);
        got = await claim(); // b1's second one-time package; b2 is out of one-time ones and uses its last-resort one
        const byDevice = Object.fromEntries(got.keyPackages.map((item: any) => [item.deviceId, item]));
        expect(byDevice[b1.deviceId].lastResort).toBe(false);
        expect(byDevice[b2.deviceId].lastResort).toBe(true);
        got = await claim(); // everyone is down to the reusable ones
        expect(got.keyPackages.every((item: any) => item.lastResort)).toBe(true);
        const again = await claim();
        expect(again.keyPackages.map((item: any) => item.keyPackage).sort()).toEqual(got.keyPackages.map((item: any) => item.keyPackage).sort()); // reusable
        expect(await (await b1.api('GET', '/api/mls/keypackages')).body).toMatchObject({ oneTime: 0, lastResort: true });
        // A device with nothing at all is reported, not skipped silently.
        run('DELETE FROM mls_key_packages WHERE device_id = ?', b2.deviceId);
        expect((await claim()).missing).toEqual([{ userId: bob.id, deviceId: b2.deviceId }]);
        void alice;
    });

    test('claims reach only yourself and accepted contacts, in bounded batches', async () => {
        const { carol, a1, a2 } = await pair();
        await a2.uploadKeyPackages(2);
        const stranger = enroll(ctx, carol, new Client(Core));
        await stranger.uploadKeyPackages(1);
        expect((await a1.api('POST', '/api/mls/keypackages/claim', { users: [carol.id] })).status).toBe(403);
        expect((await a1.api('POST', '/api/mls/keypackages/claim', { users: [id()] })).status).toBe(403); // not even whether they exist
        expect((await a1.api('POST', '/api/mls/keypackages/claim', { users: [] })).status).toBe(400);
        expect((await a1.api('POST', '/api/mls/keypackages/claim', { users: Array.from({ length: 17 }, id) })).status).toBe(400);
        expect((await a1.api('POST', '/api/mls/keypackages/claim', { users: [a1.user.id, a1.user.id] })).status).toBe(400);
        const own = await a1.must('POST', '/api/mls/keypackages/claim', { users: [a1.user.id] }, 200); // your own other devices
        expect(own.keyPackages.map((item: any) => item.deviceId)).toEqual([a2.deviceId]);
    });

    test('a device is told when its one-time packages run low', async () => {
        const { bob, a1, b1 } = await pair();
        await b1.uploadKeyPackages(21);
        const watch = b1.events(); await watch.opened;
        await a1.must('POST', '/api/mls/keypackages/claim', { users: [bob.id] }, 200); // 20 left: not yet
        await a1.must('POST', '/api/mls/keypackages/claim', { users: [bob.id] }, 200); // 19 left
        expect(await watch.next('keypackages')).toEqual({ type: 'keypackages', deviceId: b1.deviceId, remaining: 19 });
        watch.socket.close();
    });
});

suite('channels', () => {
    test('smoke: create, add every device of every member, Welcomes, messages in both directions', async () => {
        const w = await populated();
        expect((await w.b2.send(w.channel, 'hello from bob')).status).toBe(201);
        for (const device of [w.a1, w.a2, w.b1, w.c1]) expect(await device.sync(w.channel)).toEqual(['hello from bob']);
        expect((await w.a1.send(w.channel, 'and back')).status).toBe(201);
        for (const device of [w.a2, w.b1, w.b2, w.c1]) expect(await device.sync(w.channel)).toEqual(['and back']);
        const members = await w.c1.must('GET', `/api/channels/${w.channel}/members`);
        expect(members.members.length).toBe(5);
        expect(members.members.filter((member: any) => member.admin).map((member: any) => member.userId)).toEqual([w.alice.id, w.alice.id]);
    });

    test('creation checks the kind against the roles, the name, the contact and the creating device', async () => {
        const w = await world();
        const make = async (kind: string, extra: Record<string, unknown>, roles: Record<string, unknown>) => {
            const channel = id();
            const view = w.a1.client.call({ cmd: 'mlsCreate', group: channel, roles });
            return w.a1.api('POST', '/api/channels', { id: channel, kind, groupInfo: view.groupInfo, tree: view.tree, ...extra });
        };
        const group = (joinPolicy: string) => ({ v: 1, kind: 'group', admins: [w.alice.id], joinPolicy });
        expect((await make('private', {}, group('invite'))).status).toBe(201);
        expect((await make('private', {}, group('open'))).status).toBe(422); // an open group isn't a private channel
        expect((await make('public', { name: 'general' }, group('invite'))).status).toBe(422);
        expect((await make('public', { name: 'general' }, group('open'))).status).toBe(201);
        expect((await make('public', {}, group('open'))).status).toBe(400); // public channels are named
        expect((await make('public', { name: '<b>' }, group('open'))).status).toBe(400);
        expect((await make('private', { name: 'secret' }, group('invite'))).status).toBe(400); // private names stay off the server
        expect((await make('self', {}, group('invite'))).status).toBe(201);
        expect((await make('galaxy', {}, group('invite'))).status).toBe(400);
        await Bun.sleep(1100); // creation is rate limited
        // DMs: a mutual contact, the right two users, once.
        const dm = (peer: string, users: string[]) => make('dm', { peer }, { v: 1, kind: 'dm', admins: users.sort(), joinPolicy: 'invite', dm: users.sort() });
        expect((await dm('nobody', [w.alice.id, w.bob.id])).status).toBe(403);
        expect((await dm('bob', [w.alice.id, w.carol.id])).status).toBe(422);
        expect((await dm('bob', [w.alice.id, w.bob.id])).status).toBe(201);
        expect((await dm('bob', [w.alice.id, w.bob.id])).status).toBe(409);
        expect((await dm('alice', [w.alice.id, w.bob.id])).status).toBe(403); // not with yourself
        // A taken id, a malformed group, someone else's creation and an unlisted device.
        const taken = await w.a1.createChannel('private');
        expect((await w.a1.api('POST', '/api/channels', { id: taken.channel, kind: 'private', groupInfo: taken.view.groupInfo, tree: taken.view.tree })).status).toBe(409);
        expect((await w.a1.api('POST', '/api/channels', { id: id(), kind: 'private', groupInfo: 'AAAA', tree: 'AAAA' })).status).toBe(422);
        const view = w.b1.client.call({ cmd: 'mlsCreate', group: id(), roles: { v: 1, kind: 'group', admins: [w.bob.id], joinPolicy: 'invite' } });
        expect((await w.a1.api('POST', '/api/channels', { id: id(), kind: 'private', groupInfo: view.groupInfo, tree: view.tree })).status).toBe(422);
        run("UPDATE devices SET state = 'pending' WHERE id = ?", w.c1.deviceId);
        expect((await w.c1.createChannel('private')).response.status).toBe(403);
    });

    test('a channel lists for its members only', async () => {
        const w = await populated();
        expect((await w.a1.must('GET', '/api/channels')).channels).toMatchObject([{ id: w.channel, kind: 'private', name: null, epoch: 1, seq: 1, member: true, admin: true, frozen: false }]);
        expect((await w.b2.must('GET', '/api/channels')).channels[0]).toMatchObject({ admin: false, member: true });
        const outsider = enroll(ctx, user('dave'), new Client(Core));
        expect((await outsider.must('GET', '/api/channels')).channels).toEqual([]);
        for (const [method, path] of [['GET', ''], ['GET', '/members'], ['GET', '/log'], ['POST', '/messages'], ['POST', '/commits'], ['POST', '/poison'], ['POST', '/resolve'], ['PUT', '/group-info'], ['POST', '/cursor']] as const) {
            expect((await outsider.api(method, `/api/channels/${w.channel}${path}`, method === 'GET' ? undefined : { seq: 1, epoch: 1 })).status).toBe(404);
        }
        expect((await outsider.api('GET', `/api/channels/${w.channel}/join-info`)).status).toBe(404); // private: no external joins for strangers
    });

    test('every device of every member receives the log over its stream, and acknowledges with a cursor', async () => {
        const w = await populated();
        const watchers = [w.a1, w.a2, w.b1, w.b2, w.c1].map(device => ({ device, watch: device.events() }));
        for (const { watch } of watchers) { await watch.opened; await watch.next('hello'); }
        await w.b1.send(w.channel, 'to everyone');
        const sent = await w.b1.api('GET', `/api/channels/${w.channel}/log?after=0`);
        const seq = sent.body.entries.at(-1).seq;
        for (const { device, watch } of watchers) {
            // Welcomes (for the five devices that joined) and the commit arrive too; wait for the application message.
            let frame: any;
            do { frame = await watch.next('group'); } while (frame.seq !== seq);
            expect(frame).toMatchObject({ type: 'group', channel: w.channel, kind: 'app', seq, from: { userId: w.bob.id, deviceId: w.b1.deviceId } });
            expect(frame.message).toBeString();
            void device;
        }
        // The acknowledgement moves the cursor; a bad one closes the stream.
        const [{ watch, device }] = watchers;
        watch.send({ type: 'cursor', channel: w.channel, seq });
        await Bun.sleep(100);
        expect(one('SELECT cursor FROM channel_members WHERE channel_id = ? AND device_id = ?', w.channel, device.deviceId).cursor).toBe(seq);
        watch.send({ type: 'cursor', channel: w.channel, seq: seq + 100 }); // beyond the log: ignored
        await Bun.sleep(100);
        expect(one('SELECT cursor FROM channel_members WHERE channel_id = ? AND device_id = ?', w.channel, device.deviceId).cursor).toBe(seq);
        watch.send({ type: 'cursor', channel: 7 });
        expect((await watch.closed).code).toBe(1008);
        for (const { watch } of watchers) watch.socket.close();
    });

    test('a device that was offline gets its Welcome and the log from its cursor when it connects', async () => {
        const w = await world();
        const { channel } = await w.a1.createChannel('private');
        await w.a1.add(channel, [w.bob.id]);
        const watch = w.b2.events(); await watch.opened;
        const welcome = await watch.next('welcome');
        expect(welcome).toMatchObject({ channel, epoch: 1, seq: 1, from: w.alice.id });
        watch.send({ type: 'ack', id: welcome.id });
        await Bun.sleep(100);
        expect(rows('SELECT 1 FROM mls_welcomes WHERE id = ?', welcome.id)).toEqual([]);
        // An ack for someone else's Welcome deletes nothing.
        const other = one('SELECT id FROM mls_welcomes WHERE device_id = ?', w.b1.deviceId);
        watch.send({ type: 'ack', id: other.id });
        await Bun.sleep(100);
        expect(rows('SELECT 1 FROM mls_welcomes WHERE id = ?', other.id).length).toBe(1);
        watch.socket.close();
    });

    test('Welcomes and log entries too large for a frame are announced and fetched over HTTP', async () => {
        const w = await populated();
        const big = Buffer.alloc(80_000, 7);
        run('INSERT INTO mls_welcomes (id, device_id, channel_id, sender_id, epoch, seq, welcome, tree, created_at) VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?)', 'W'.repeat(22), w.c1.deviceId, w.channel, w.alice.id, big, Buffer.alloc(10), clock);
        run("INSERT INTO group_log (channel_id, seq, epoch, kind, sender_user, sender_device, digest, message, created_at) VALUES (?, 2, 1, 'app', ?, ?, ?, ?, ?)", w.channel, w.alice.id, w.a1.deviceId, '0'.repeat(64), big, clock);
        run('UPDATE channels SET seq = 2 WHERE id = ?', w.channel);
        const watch = w.c1.events(); await watch.opened;
        const welcome = await watch.next('welcome');
        expect(welcome).toMatchObject({ id: 'W'.repeat(22), welcome: null, tree: null, large: true });
        const frame = await watch.next('group');
        expect(frame).toMatchObject({ seq: 2, message: null, large: true });
        expect(Buffer.from((await w.c1.must('GET', `/api/mls/welcomes/${welcome.id}`)).welcome, 'base64url').length).toBe(80_000);
        const page = await w.c1.must('GET', `/api/channels/${w.channel}/log?after=1`);
        expect(page.entries[0].message.length).toBe(Math.ceil(80_000 * 4 / 3));
        watch.socket.close();
    });

    test('concurrent commits: the second gets 409 with {epoch, seq}, catches up, rebuilds and is accepted', async () => {
        const w = await populated();
        const first = await w.a1.commit(w.channel, { update: true });
        expect(first.status).toBe(201);
        const second = await w.a2.commit(w.channel, { update: true });
        expect(second.status).toBe(409);
        expect(second.body).toMatchObject({ epoch: 2, seq: 2 });
        // The loser's state did not move; it processes the log and builds again.
        await w.a2.sync(w.channel);
        const third = await w.a2.commit(w.channel, { update: true });
        expect(third.status).toBe(201);
        expect(third.body).toMatchObject({ epoch: 3, seq: 3 });
        for (const device of [w.a1, w.b1, w.b2, w.c1]) await device.sync(w.channel);
        expect((await w.c1.send(w.channel, 'still one group')).status).toBe(201);
        expect(await w.a2.sync(w.channel)).toEqual(['still one group']);
    });

    test('application messages from a stale epoch are rejected, not delivered', async () => {
        const w = await populated();
        const late = w.b1.client.call({ cmd: 'mlsEncrypt', group: w.channel, plaintext: 'late' });
        await w.a1.commit(w.channel, { update: true });
        const result = await w.b1.api('POST', `/api/channels/${w.channel}/messages`, { message: late });
        expect(result.status).toBe(409);
        expect(result.body).toMatchObject({ epoch: 2, seq: 2 });
        expect(rows("SELECT 1 FROM group_log WHERE kind = 'app'")).toEqual([]);
    });

    test('tampered or malformed handshakes are rejected and leave the group untouched', async () => {
        const w = await populated();
        const out = w.a1.client.call({ cmd: 'mlsCommit', group: w.channel, update: true });
        const before = one('SELECT epoch, seq FROM channels WHERE id = ?', w.channel);
        let rejected = 0;
        for (const at of [30, 60, 100, 200, 250]) {
            const result = await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: flip(out.commit, at) });
            expect([422, 400]).toContain(result.status);
            rejected++;
        }
        expect(rejected).toBe(5);
        expect(one('SELECT epoch, seq FROM channels WHERE id = ?', w.channel)).toEqual(before);
        // Not an MLS message, a Welcome sent as a commit, a commit as a message, an application message as a commit.
        expect((await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: 'AAAA' })).status).toBe(400);
        expect((await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: '!!!!' })).status).toBe(400);
        expect((await w.a1.api('POST', `/api/channels/${w.channel}/messages`, { message: out.commit })).status).toBe(400);
        expect((await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: w.b1.client.call({ cmd: 'mlsEncrypt', group: w.channel, plaintext: 'x' }) })).status).toBe(400);
        expect((await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: out.commit, welcome: 'AAAA', joiners: [w.b1.deviceId] })).status).toBe(422); // this commit adds nobody
        // The genuine commit still goes through.
        expect((await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: out.commit })).status).toBe(201);
    });

    test('the validator enforces roles: a plain member cannot add or remove people', async () => {
        const w = await populated();
        const dave = enroll(ctx, user('dave'), new Client(Core));
        await befriend(user('x1'), user('x2')).catch(() => {});
        // Bob builds a removal of Carol without his own checks (a modified client): the server refuses it.
        const out = w.b1.client.call({ cmd: 'mlsCommit', group: w.channel, update: true });
        w.b1.client.call({ cmd: 'mlsClearOwn', group: w.channel });
        // Re-signed commits can't be forged here; the engine's own refusal is what an honest client sees.
        expect(() => w.b1.client.call({ cmd: 'mlsCommit', group: w.channel, removes: [{ userId: w.carol.id }] })).toThrow();
        expect(() => w.b1.client.call({ cmd: 'mlsCommit', group: w.channel, adds: dave.client.call({ cmd: 'mlsKeyPackages', count: 1 }) })).toThrow();
        void out;
    });

    test('commits that add devices must come with a matching Welcome for listed devices of accepted contacts', async () => {
        const w = await world();
        const { channel } = await w.a1.createChannel('private');
        const claimed = await w.a1.must('POST', '/api/mls/keypackages/claim', { users: [w.bob.id] }, 200);
        const out = w.a1.client.call({ cmd: 'mlsCommit', group: channel, adds: claimed.keyPackages.map((item: any) => item.keyPackage) });
        const joiners = claimed.keyPackages.map((item: any) => item.deviceId);
        const send = (body: object) => w.a1.api('POST', `/api/channels/${channel}/commits`, { message: out.commit, ...body });
        expect((await send({})).status).toBe(422); // adds devices but brings no Welcome
        expect((await send({ welcome: out.welcome, joiners: [joiners[0]] })).status).toBe(422); // missing a joiner
        expect((await send({ welcome: out.welcome, joiners: [...joiners, w.c1.deviceId] })).status).toBe(422); // Carol's device isn't one this commit adds
        expect((await send({ welcome: out.welcome, joiners: [...joiners, id()] })).status).toBe(403); // not a device at all
        run("UPDATE devices SET state = 'pending' WHERE id = ?", joiners[0]);
        expect((await send({ welcome: out.welcome, joiners })).status).toBe(403); // a device the signed list doesn't name
        run("UPDATE devices SET state = 'listed' WHERE id = ?", joiners[0]);
        // None of that moved the group.
        expect(one('SELECT epoch, seq FROM channels WHERE id = ?', channel)).toEqual({ epoch: 0, seq: 0 });
        expect((await send({ welcome: out.welcome, joiners })).status).toBe(201);
        // Contacts only: Dave is nobody's contact.
        const dave = enroll(ctx, user('dave'), new Client(Core));
        pinAll([w.a1, dave]);
        await dave.uploadKeyPackages(1);
        w.a1.client.call({ cmd: 'mlsMergeOwn', group: channel });
        const kp = dave.client.call({ cmd: 'mlsKeyPackages', count: 1 });
        const add = w.a1.client.call({ cmd: 'mlsCommit', group: channel, adds: kp });
        const refused = await w.a1.api('POST', `/api/channels/${channel}/commits`, { message: add.commit, welcome: add.welcome, joiners: [dave.deviceId] });
        expect(refused.status).toBe(403);
        w.a1.client.call({ cmd: 'mlsClearOwn', group: channel });
    });

    test('a device that was removed from the group stops receiving it', async () => {
        const w = await populated();
        const watch = w.b2.events(); await watch.opened;
        await w.a1.commit(w.channel, { removes: [{ userId: w.bob.id, deviceId: w.b2.deviceId }] });
        const frame = await watch.next('channel');
        expect(frame).toMatchObject({ id: w.channel, change: 'updated' }); // bob is still in through b1
        await w.a1.send(w.channel, 'after the removal');
        await Bun.sleep(150);
        // b2 learns of its own removal from the commit, then nothing: no later entry is sent or readable.
        const seen = watch.pending('group').map(message => message.seq);
        expect(seen).toEqual([]);
        expect((await w.b2.api('GET', `/api/channels/${w.channel}/log`)).status).toBe(404);
        expect((await w.b2.send(w.channel, 'still here?')).status).toBe(404);
        expect(rows('SELECT device_id FROM channel_members WHERE channel_id = ? AND device_id = ?', w.channel, w.b2.deviceId)).toEqual([]);
        // The rest of bob's devices carry on.
        expect(await w.b1.sync(w.channel)).toEqual(['after the removal']);
        // Removing a whole user ends the stream of all their devices and tells them they left.
        const left = w.b1.events(); await left.opened;
        await w.a1.commit(w.channel, { removes: [{ userId: w.bob.id }] });
        expect(await left.next('channel')).toMatchObject({ id: w.channel, change: 'left' });
        expect((await w.b1.must('GET', '/api/channels')).channels).toEqual([]);
        watch.socket.close(); left.socket.close();
    });

    test('external joins: anyone in a public channel, a member\'s new device in a private one, nobody else', async () => {
        const w = await world();
        const pub = await w.a1.createChannel('public', { name: 'general' });
        await w.a1.api('PUT', `/api/channels/${pub.channel}/group-info`, { epoch: 0, groupInfo: pub.view.groupInfo });
        const dave = enroll(ctx, user('dave'), new Client(Core));
        pinAll([w.a1, dave]);
        const joined = await dave.joinExternal(pub.channel);
        expect(joined.status).toBe(201);
        await w.a1.sync(pub.channel);
        expect((await dave.send(pub.channel, 'hi everyone')).status).toBe(201);
        expect(await w.a1.sync(pub.channel)).toEqual(['hi everyone']);
        expect((await dave.must('GET', `/api/channels/${pub.channel}/members`)).members.length).toBe(2);

        // Private: a stranger gets nothing, even from join-info; a new device of a member joins.
        const { channel } = await w.a1.createChannel('private');
        await w.a1.api('PUT', `/api/channels/${channel}/group-info`, { epoch: 0, groupInfo: w.a1.client.call({ cmd: 'mlsView', group: channel }).groupInfo });
        expect((await dave.api('GET', `/api/channels/${channel}/join-info`)).status).toBe(404);
        expect((await dave.api('POST', `/api/channels/${channel}/join`, { message: 'AAAA' })).status).toBe(404);
        const a3 = enroll(ctx, w.alice, w.a1.client.sibling(), 'windows');
        pinAll([w.a1, a3]);
        const mine = await a3.joinExternal(channel);
        expect(mine.status).toBe(201);
        await w.a1.sync(channel);
        expect((await a3.send(channel, 'my new laptop')).status).toBe(201);
        expect(await w.a1.sync(channel)).toEqual(['my new laptop']);
        expect(one('SELECT COUNT(*) AS n FROM channel_members WHERE channel_id = ?', channel).n).toBe(2);
    });

    test('resync: a member forgets its copy and joins again with the same device', async () => {
        const w = await populated();
        w.b2.client.call({ cmd: 'mlsForget', group: w.channel });
        const info = await w.a1.must('GET', `/api/channels/${w.channel}/join-info`);
        expect(info.epoch).toBe(1);
        const result = await w.b2.joinExternal(w.channel);
        expect(result.status).toBe(201);
        for (const device of [w.a1, w.a2, w.b1, w.c1]) await device.sync(w.channel);
        expect(one('SELECT COUNT(*) AS n FROM channel_members WHERE channel_id = ?', w.channel).n).toBe(5);
        await w.c1.send(w.channel, 'welcome back');
        expect(await w.b2.sync(w.channel)).toEqual(['welcome back']);
    });

    test('join-info is only offered once the new epoch\'s GroupInfo has been uploaded, and only at the current epoch', async () => {
        const w = await populated();
        run('UPDATE channels SET group_info_epoch = 0 WHERE id = ?', w.channel);
        expect((await w.a1.api('GET', `/api/channels/${w.channel}/join-info`)).status).toBe(409);
        const view = w.a1.client.call({ cmd: 'mlsView', group: w.channel });
        expect((await w.a1.api('PUT', `/api/channels/${w.channel}/group-info`, { epoch: 0, groupInfo: view.groupInfo })).status).toBe(409);
        expect((await w.a1.api('PUT', `/api/channels/${w.channel}/group-info`, { epoch: 1, groupInfo: 'x'.repeat(90000) })).status).toBe(400);
        expect((await w.a1.api('PUT', `/api/channels/${w.channel}/group-info`, { epoch: 1, groupInfo: view.groupInfo })).status).toBe(200);
        expect((await w.a1.api('GET', `/api/channels/${w.channel}/join-info`)).status).toBe(200);
    });

    test('cursors only move forward, never past the log, and the log is dropped once every device has read it', async () => {
        const w = await populated();
        await w.a1.send(w.channel, 'one'); await w.a1.send(w.channel, 'two');
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel).map(row => row.seq)).toEqual([2, 3]); // the Welcome's commit (1) was read by everyone as they joined
        const cursor = (device: Device, seq: number) => device.api('POST', `/api/channels/${w.channel}/cursor`, { seq });
        expect((await cursor(w.a1, 99)).status).toBe(404);
        expect((await cursor(w.a1, -1)).status).toBe(404);
        expect((await cursor(w.a1, 1.5)).status).toBe(400);
        // One lagging device keeps everything after its position.
        for (const device of [w.a1, w.a2, w.b1, w.b2]) expect((await cursor(device, 3)).body).toEqual({ cursor: 3 });
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel).length).toBeGreaterThan(0);
        expect((await cursor(w.a1, 1)).body).toEqual({ cursor: 3 }); // never backwards
        expect((await cursor(w.c1, 3)).body).toEqual({ cursor: 3 });
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel)).toEqual([]);
        // Nothing left to read, and the position is where the log ended.
        const page = await w.c1.must('GET', `/api/channels/${w.channel}/log`);
        expect(page).toMatchObject({ entries: [], seq: 3, cursor: 3, gap: false });
    });

    test('retention: unread entries live 30 days, then a lagging device is told it fell behind; Welcomes and idle devices expire too', async () => {
        const w = await populated();
        await w.a1.send(w.channel, 'old');
        for (const device of [w.a1, w.a2, w.b1, w.b2]) await device.must('POST', `/api/channels/${w.channel}/cursor`, { seq: 2 });
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel).map(row => row.seq)).toEqual([2]); // carol hasn't read it
        run('INSERT INTO mls_welcomes (id, device_id, channel_id, sender_id, epoch, seq, welcome, tree, created_at) VALUES (?, ?, ?, ?, 1, 1, x\'00\', x\'00\', ?)', 'O'.repeat(22), w.b1.deviceId, w.channel, w.alice.id, clock);
        advance(29 * 86400000);
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel).length).toBe(1);
        await w.a1.send(w.channel, 'newer');
        advance(2 * 86400000);
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel).map(row => row.seq)).toEqual([3]);
        expect(rows('SELECT 1 FROM mls_welcomes WHERE id = ?', 'O'.repeat(22))).toEqual([]);
        // Carol was behind the trimmed part of the log.
        const page = await w.c1.must('GET', `/api/channels/${w.channel}/log`);
        expect(page.gap).toBe(true);
        const watch = w.c1.events(); await watch.opened;
        expect(await watch.next('channel')).toMatchObject({ id: w.channel, change: 'gap', oldest: 3 });
        watch.socket.close();
        // A revoked device no longer holds anyone's log back.
        run("UPDATE devices SET state = 'revoked' WHERE id = ?", w.c1.deviceId);
        app.channels!.sweep(true);
        expect(rows('SELECT 1 FROM channel_members WHERE device_id = ?', w.c1.deviceId)).toEqual([]);
    });

    test('a channel with too many unread entries refuses more until members catch up', async () => {
        const w = await populated();
        const insert = app.accounts!.testing.db.query("INSERT INTO group_log (channel_id, seq, epoch, kind, sender_user, sender_device, digest, message, created_at) VALUES (?, ?, 1, 'app', ?, ?, ?, x'00', ?)");
        app.accounts!.testing.db.transaction(() => { for (let seq = 2; seq <= 10001; seq++) insert.run(w.channel, seq, w.alice.id, w.a1.deviceId, '0'.repeat(64), clock); })();
        run('UPDATE channels SET seq = 10001 WHERE id = ?', w.channel);
        const result = await w.b1.send(w.channel, 'one too many');
        expect(result.status).toBe(507);
    });

    test('rate limits apply per account on every endpoint', async () => {
        const w = await populated();
        const statuses: number[] = [];
        for (let index = 0; index < 60; index++) statuses.push((await w.b1.api('GET', `/api/channels/${w.channel}/log`)).status);
        expect(statuses).toContain(429);
        const created: number[] = [];
        for (let index = 0; index < 20; index++) created.push((await w.c1.api('POST', '/api/channels', { id: id(), kind: 'private', groupInfo: 'AAAA', tree: 'AAAA' })).status);
        expect(created).toContain(429);
        const kps: number[] = [];
        for (let index = 0; index < 8; index++) kps.push((await w.c1.api('PUT', '/api/mls/keypackages', {})).status);
        expect(kps).toContain(429);
    });

    test('bodies are bounded by who is asking, and checked before they are read', async () => {
        const w = await populated();
        const post = (device: Device, path: string, size: number) => fetch(new URL(path, app.server.url), {
            method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: `session=${device.token}`, Origin: origin },
            body: JSON.stringify({ message: 'A'.repeat(size) }),
        });
        // A plain member's commit is small (a self-update or leaving); an admin may send a large one.
        expect((await post(w.b1, `/api/channels/${w.channel}/commits`, 200_000)).status).toBe(413);
        expect((await post(w.a1, `/api/channels/${w.channel}/commits`, 200_000)).status).toBe(400); // admitted, then not an MLS message
        expect((await post(w.a1, `/api/channels/${w.channel}/commits`, 9_000_000)).status).toBe(413);
        // Application messages are at most 64 KiB.
        expect((await post(w.b1, `/api/channels/${w.channel}/messages`, 200_000)).status).toBe(413);
        expect((await post(w.b1, `/api/channels/${w.channel}/messages`, 100_000)).status).toBe(400);
        // Nobody who isn't in the channel gets a body read at all.
        const outsider = enroll(ctx, user('dave'), new Client(Core));
        expect((await post(outsider, `/api/channels/${w.channel}/commits`, 9_000_000)).status).toBe(413); // the server's own cap
        expect((await post(outsider, `/api/channels/${w.channel}/commits`, 1_000_000)).status).toBe(404);
        // Oversize application messages from a hostile client are refused by the validator's own limit.
        expect((await w.b1.api('POST', '/api/channels', { id: id(), kind: 'private', groupInfo: 'A'.repeat(100_000), tree: 'AAAA' })).status).toBe(400);
    });

    test('requests need a session, the app\'s origin, and a device in the signed list', async () => {
        const w = await populated();
        const raw = (method: string, path: string, headers: Record<string, string>, body?: unknown) => fetch(new URL(path, app.server.url), { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
        expect((await raw('GET', '/api/channels', {})).status).toBe(401);
        expect((await raw('POST', `/api/channels/${w.channel}/messages`, { Cookie: `session=${w.b1.token}` }, { message: 'AAAA' })).status).toBe(403); // no Origin
        expect((await raw('POST', `/api/channels/${w.channel}/messages`, { Cookie: `session=${w.b1.token}`, Origin: 'http://evil.example' }, { message: 'AAAA' })).status).toBe(403);
        // A session that never announced a device (or a pending one) can't use groups.
        const loose = user('loose');
        expect((await raw('GET', '/api/mls/keypackages', { Cookie: loose.cookie })).status).toBe(409);
        run("UPDATE devices SET state = 'pending' WHERE id = ?", w.b1.deviceId);
        for (const [method, path] of [['GET', `/api/channels/${w.channel}/log`], ['GET', '/api/mls/welcomes'], ['POST', `/api/channels/${w.channel}/cursor`]] as const) {
            expect((await w.b1.api(method, path, method === 'GET' ? undefined : { seq: 1 })).status).toBe(403);
        }
    });

    test('the DM of two contacts is one conversation per pair', async () => {
        const w = await world();
        const { channel, response } = await w.a1.createChannel('dm', { peer: { id: w.bob.id, username: 'bob' } });
        expect(response.status).toBe(201);
        const added = await w.a1.add(channel, [w.alice.id, w.bob.id]);
        expect(added.status).toBe(201);
        expect(await w.b1.joinWelcomes()).toEqual([channel]);
        expect(await w.b2.joinWelcomes()).toEqual([channel]);
        expect(await w.a2.joinWelcomes()).toEqual([channel]);
        expect((await w.b1.send(channel, 'dm')).status).toBe(201);
        expect(await w.a2.sync(channel)).toEqual(['dm']);
        // A third person can't be added to a DM.
        await w.c1.uploadKeyPackages(1);
        expect(() => w.a1.client.call({ cmd: 'mlsCommit', group: channel, adds: w.c1.client.call({ cmd: 'mlsKeyPackages', count: 1 }) })).toThrow();
        expect((await w.b1.createChannel('dm', { peer: { id: w.alice.id, username: 'alice' } })).response.status).toBe(409);
        expect((await w.b1.must('GET', '/api/channels')).channels[0]).toMatchObject({ kind: 'dm' });
    });

    test('a self group holds only its owner\'s devices', async () => {
        const w = await world();
        const { channel, response } = await w.a1.createChannel('self');
        expect(response.status).toBe(201);
        expect((await w.a1.add(channel, [w.alice.id])).status).toBe(201);
        expect(await w.a2.joinWelcomes()).toEqual([channel]);
        expect((await w.a1.add(channel, [w.bob.id])).status).toBe(422); // the validator lets an admin invite; the server keeps this one private
        await w.a1.api('POST', `/api/channels/${channel}/cursor`, { seq: 1 });
    });

    test('state survives a restart of the server', async () => {
        const w = await populated();
        await w.b1.send(w.channel, 'before');
        const dir = dataDir;
        await app.stop();
        app = startSignaling({ adminToken: 'channels-test-admin-secret-0000000000000', origin, port: 0, dataDir: dir, now: () => clock, trustProxy: true });
        for (const device of [w.a1, w.a2, w.b2, w.c1]) expect(await device.sync(w.channel)).toEqual(['before']);
        expect((await w.a1.commit(w.channel, { update: true })).status).toBe(201);
        for (const device of [w.a2, w.b1, w.b2, w.c1]) await device.sync(w.channel);
        expect((await w.c1.send(w.channel, 'after')).status).toBe(201);
        expect(await w.b1.sync(w.channel)).toEqual(['after']);
    });

    test('the server refuses to start with a tampered validator core', async () => {
        dataDir = await mkdtemp(join(tmpdir(), 'channels-'));
        const copy = await mkdtemp(join(tmpdir(), 'ds-core-'));
        cpSync(fileURLToPath(new URL('../../packages/signaling/ds-core/', import.meta.url)), copy, { recursive: true });
        writeFileSync(join(copy, 'extra.wasm'), 'x');
        expect(() => startSignaling({ adminToken: 'channels-test-admin-secret-0000000000000', origin, port: 0, dataDir, dsCoreDir: copy })).toThrow('failed verification');
        await rm(copy, { recursive: true, force: true });
    });
});

suite('commit classification', () => {
    test('what a plain member signed that policy forbids is signed-content (and the DS never sequences it); a corrupted tag is not', async () => {
        const w = await populated();
        // A modified client (test build only): bob removes carol, which only an admin may do.
        const evil = w.b1.client.call({ cmd: 'mlsTestUnchecked', group: w.channel, removes: [{ userId: w.carol.id }] });
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/commits`, { message: evil.commit })).status).toBe(422);
        w.b1.client.call({ cmd: 'mlsClearOwn', group: w.channel });
        // Members that are handed it anyway (a faulty DS) reject it and may blame its author: he signed it.
        const failure = (() => { try { w.c1.client.call({ cmd: 'mlsReceive', group: w.channel, message: evil.commit }); } catch (error: any) { return error; } })();
        expect(failure.code).toBe('poison');
        const check = w.a2.client.call({ cmd: 'mlsCommitAuthor', group: w.channel, message: evil.commit });
        expect(check).toMatchObject({ authenticated: true, signedContentInvalid: true, class: 'signed-content', author: { deviceId: w.b1.deviceId } });
        // With only its tag flipped it is still his content...
        expect(w.a2.client.call({ cmd: 'mlsCommitAuthor', group: w.channel, message: flip(evil.commit, -1) }).class).toBe('signed-content');
        // ...while an honest commit with a flipped tag blames nobody.
        const honest = w.a1.client.call({ cmd: 'mlsCommit', group: w.channel, update: true });
        expect(w.a2.client.call({ cmd: 'mlsCommitAuthor', group: w.channel, message: flip(honest.commit, -1) })).toMatchObject({ authenticated: true, signedContentInvalid: false, class: 'tag' });
        w.a1.client.call({ cmd: 'mlsClearOwn', group: w.channel });
    });
});

suite('signed-content removal (a faulty DS sequences what the validator would refuse)', () => {
    test('members blame the author, an admin signs a rollback naming him, the server cuts that device off, members verify the notice and go on', async () => {
        const w = await populated();
        const digestOf = (message: string) => createHash('sha256').update(Buffer.from(message, 'base64url')).digest('hex');
        // Bob's modified client (test build only) signs a commit that removes carol, which only an admin may do.
        const evil = w.b1.client.call({ cmd: 'mlsTestUnchecked', group: w.channel, removes: [{ userId: w.carol.id }] });
        w.b1.client.call({ cmd: 'mlsClearOwn', group: w.channel });
        // An honest commit gives the server a real pre-commit snapshot; the faulty DS then logs bob's commit in its place.
        const honest = await w.a1.commit(w.channel, { update: true });
        expect(honest.status).toBe(201);
        const seq = honest.body.seq as number, digest = digestOf(evil.commit);
        run('UPDATE group_log SET message = ?, sender_user = ?, sender_device = ?, digest = ? WHERE channel_id = ? AND seq = ?', Buffer.from(evil.commit, 'base64url'), w.bob.id, w.b1.deviceId, digest, w.channel, seq);

        // Two members process it from the log: both reject it as poison, blaming what its author signed.
        for (const device of [w.a2, w.c1]) {
            const entry = (await device.must('GET', `/api/channels/${w.channel}/log?after=${seq - 1}`)).entries[0];
            let failure: any;
            try { device.client.call({ cmd: 'mlsReceive', group: w.channel, message: entry.message, commit: false, expect: 'commit' }); } catch (error) { failure = error; }
            expect(failure).toMatchObject({ code: 'poison', failureClass: 'signed-content' });
            expect(failure.message).toContain(`poison ${digest}`);
            expect(device.client.call({ cmd: 'mlsCommitAuthor', group: w.channel, message: entry.message })).toMatchObject({ authenticated: true, signedContentInvalid: true, class: 'signed-content', author: { userId: w.bob.id, deviceId: w.b1.deviceId } });
        }
        const watch = w.c1.events(); await watch.opened;
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest })).status).toBe(202);

        // The admin (a2) names the author its own tree authenticated, in both signatures: device key (server) and leaf key (members).
        const author = w.b1.deviceId;
        const leafSignature = w.a2.client.call({ cmd: 'mlsSignResolution', group: w.channel, action: 'rollback', seq, digest, author });
        const done = await w.a2.api('POST', `/api/channels/${w.channel}/resolve`, { action: 'rollback', seq, digest, author, leafSignature, signature: w.a2.resolution(w.channel, 'rollback', seq, digest, author) });
        expect(done).toMatchObject({ status: 200, body: { resolved: 'rollback', seq: seq - 1, removeDevice: author } });
        expect(rows('SELECT device_id FROM channel_bans WHERE channel_id = ?', w.channel)).toEqual([{ device_id: author }]);
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ? AND seq = ?', w.channel, seq)).toEqual([]);
        expect((await w.b1.api('GET', `/api/channels/${w.channel}/log`)).status).toBe(404); // cut off at once
        expect((await w.b1.send(w.channel, 'still here?')).status).toBe(404);

        // Carol's device checks the notice against its own tree: an admin of this group signed exactly this rollback.
        let notice: any;
        do { notice = await watch.next('channel'); } while (notice.change !== 'rolled-back');
        expect(notice).toMatchObject({ action: 'rollback', seq, digest, author, by: w.a2.deviceId });
        expect(w.c1.client.call({ cmd: 'mlsVerifyResolution', group: w.channel, action: notice.action, seq: notice.seq, digest: notice.digest, author: notice.author, by: notice.by, byUser: notice.byUser, signature: notice.signature })).toMatchObject({ userId: w.alice.id, deviceId: w.a2.deviceId });
        expect(() => w.c1.client.call({ cmd: 'mlsVerifyResolution', group: w.channel, action: 'rollback', seq, digest, author: '', by: notice.by, byUser: notice.byUser, signature: notice.signature })).toThrow(); // not what was signed
        expect(() => w.c1.client.call({ cmd: 'mlsVerifyResolution', group: w.channel, action: 'rollback', seq, digest, author, by: w.b2.deviceId, byUser: w.bob.id, signature: w.b2.client.call({ cmd: 'mlsSignResolution', group: w.channel, action: 'rollback', seq, digest, author }) })).toThrow(); // not an admin

        // The admin removes bob's device from the tree; the group goes on without it.
        const removal = await w.a2.commit(w.channel, { removes: [{ userId: w.bob.id, deviceId: author }] });
        expect(removal.status).toBe(201);
        for (const device of [w.b2, w.c1]) await device.sync(w.channel);
        expect((await w.c1.send(w.channel, 'carried on')).status).toBe(201);
        expect(await w.b2.sync(w.channel)).toEqual(['carried on']);
        expect(w.c1.client.call({ cmd: 'mlsMembers', group: w.channel }).map((member: any) => member.deviceId)).not.toContain(author);
        watch.socket.close();
    });
});

suite('poison commits', () => {
    /** a1 builds a self-update, and the last byte (a confirmation tag only members can check) is flipped. */
    async function poisoned() {
        const w = await populated();
        const out = w.a1.client.call({ cmd: 'mlsCommit', group: w.channel, update: true });
        const bad = flip(out.commit, -1);
        const result = await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: bad });
        expect(result.status).toBe(201); // the DS cannot see the tags
        w.a1.client.call({ cmd: 'mlsClearOwn', group: w.channel });
        return { ...w, bad, seq: result.body.seq as number, digest: result.body.digest as string };
    }

    test('members reject it, report it, the channel freezes, an admin device signs a rollback, the author is cut off', async () => {
        const w = await poisoned();
        // Every honest member rejects it as poison and says so.
        const entry = (await w.b1.must('GET', `/api/channels/${w.channel}/log?after=${w.seq - 1}`)).entries[0];
        let error: any;
        try { w.b1.client.call({ cmd: 'mlsReceive', group: w.channel, message: entry.message }); } catch (caught) { error = caught; }
        expect(error.code).toBe('poison');
        expect(error.message).toContain(`poison ${w.digest}`);

        const watch = w.a2.events(); await watch.opened;
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/poison`, { seq: w.seq, digest: w.digest, reason: error.message })).status).toBe(202);
        expect(await watch.next('channel')).toMatchObject({ change: 'frozen', seq: w.seq, digest: w.digest });
        // Frozen: nothing more is sequenced or joined, but reading goes on.
        expect((await w.c1.send(w.channel, 'x')).status).toBe(423);
        expect((await w.c1.commit(w.channel, { update: true })).status).toBe(423);
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/join`, { message: 'AAAA' })).status).toBe(423);
        expect((await w.c1.api('GET', `/api/channels/${w.channel}/log`)).body.frozen).toEqual({ seq: w.seq, digest: w.digest });
        // Reporting again is idempotent; a different report is refused.
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq: w.seq, digest: w.digest })).body).toEqual({ frozen: true });
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq: w.seq, digest: '1'.repeat(64) })).status).toBe(409);

        // The admin's own copy of the group authenticates who signed the commit (nothing changes). A broken tag is
        // outside the signature: class 'tag', which never justifies removing the author (the client then signs no author).
        const check = w.a2.client.call({ cmd: 'mlsCommitAuthor', group: w.channel, message: entry.message });
        expect(check).toMatchObject({ authenticated: true, class: 'tag', author: { userId: w.alice.id, deviceId: w.a1.deviceId } });
        let tampered: any = null;
        try { tampered = w.a2.client.call({ cmd: 'mlsCommitAuthor', group: w.channel, message: flip(entry.message, 40) }); } catch {}
        expect(tampered?.authenticated ?? false).toBe(false);
        // The server mechanics of a rollback with a removal (the client asks for one only for class 'signed-content').
        // Only an admin device, with its own signature over exactly this resolution, naming the commit's author.
        const a = w.a1.deviceId;
        const leafSignature = 'L'.repeat(86); // passed on to members, who check it (not the server)
        const resolve = (device: Device, action: string, signature?: string, named = a) => device.api('POST', `/api/channels/${w.channel}/resolve`, { action, seq: w.seq, digest: w.digest, author: named, leafSignature, signature: signature ?? device.resolution(w.channel, action as any, w.seq, w.digest, named) });
        expect((await resolve(w.b1, 'rollback')).status).toBe(403); // not an admin
        expect((await resolve(w.a2, 'rollback', w.a2.resolution(w.channel, 'dismiss', w.seq, w.digest, a))).status).toBe(403); // signed for another action
        expect((await resolve(w.a2, 'rollback', w.a1.resolution(w.channel, 'rollback', w.seq, w.digest, a))).status).toBe(403); // someone else's signature
        expect((await resolve(w.a2, 'rollback', 'A'.repeat(86))).status).toBe(403);
        expect((await resolve(w.a2, 'rollback', w.a2.resolution(w.channel, 'rollback', w.seq, w.digest, w.c1.deviceId), a)).status).toBe(403); // signed for another author
        expect((await resolve(w.a2, 'rollback', undefined, w.c1.deviceId)).status).toBe(409); // signed, but not the commit's author
        expect((await w.a2.api('POST', `/api/channels/${w.channel}/resolve`, { action: 'rollback', seq: w.seq + 1, digest: w.digest, author: a, leafSignature, signature: w.a2.resolution(w.channel, 'rollback', w.seq + 1, w.digest, a) })).status).toBe(409);
        const done = await resolve(w.a2, 'rollback');
        expect(done.status).toBe(200);
        expect(done.body).toMatchObject({ resolved: 'rollback', epoch: 1, seq: w.seq - 1, removeDevice: w.a1.deviceId });
        let change: any; const seen: string[] = [];
        do { change = await watch.next('channel'); seen.push(change.change); } while (change.change !== 'remove-needed');
        expect(change).toMatchObject({ deviceId: w.a1.deviceId });
        expect(seen).toContain('thawed'); // members who reported it resume

        // The poison commit and its state are gone; the author can no longer write or read here.
        expect(one('SELECT epoch, seq, frozen_seq FROM channels WHERE id = ?', w.channel)).toEqual({ epoch: 1, seq: w.seq - 1, frozen_seq: null });
        expect(rows('SELECT 1 FROM group_log WHERE channel_id = ? AND seq = ?', w.channel, w.seq)).toEqual([]);
        expect((await w.a1.send(w.channel, 'still me')).status).toBe(404); // no longer a member here
        expect((await w.a1.api('GET', `/api/channels/${w.channel}/log`)).status).toBe(404);
        // An admin removes it for real, and the group carries on at the restored epoch.
        w.a1.client.call({ cmd: 'mlsForget', group: w.channel });
        const removal = await w.a2.commit(w.channel, { removes: [{ userId: w.alice.id, deviceId: w.a1.deviceId }] });
        expect(removal.status).toBe(201);
        expect(removal.body).toMatchObject({ epoch: 2, seq: w.seq });
        for (const device of [w.b1, w.b2, w.c1]) await device.sync(w.channel);
        expect((await w.c1.send(w.channel, 'back to normal')).status).toBe(201);
        expect(await w.b2.sync(w.channel)).toEqual(['back to normal']);
        watch.socket.close();
    });

    test('a report of an honest commit is dismissed by an admin, and the channel goes on', async () => {
        const w = await populated();
        const honest = await w.a1.commit(w.channel, { update: true });
        expect(honest.status).toBe(201);
        const seq = honest.body.seq, digest = honest.body.digest;
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest })).status).toBe(202); // a faulty or hostile report
        expect((await w.a1.send(w.channel, 'x')).status).toBe(423);
        const resolve = (device: Device, action: string) => device.api('POST', `/api/channels/${w.channel}/resolve`, { action, seq, digest, author: '', signature: device.resolution(w.channel, action as any, seq, digest, '') });
        expect((await resolve(w.c1, 'dismiss')).status).toBe(403);
        expect((await resolve(w.a2, 'dismiss')).body).toEqual({ resolved: 'dismiss' });
        expect(one('SELECT frozen_seq FROM channels WHERE id = ?', w.channel).frozen_seq).toBeNull();
        for (const device of [w.a2, w.b1, w.b2, w.c1]) await device.sync(w.channel);
        expect((await w.c1.send(w.channel, 'fine')).status).toBe(201);
        expect(await w.a1.sync(w.channel)).toEqual(['fine']);
        // Nothing to resolve any more.
        expect((await resolve(w.a2, 'dismiss')).status).toBe(409);
    });

    test('only the latest commit can be reported, by a member who did not write it', async () => {
        const w = await populated();
        const first = await w.a1.commit(w.channel, { update: true });
        const second = await w.a2.commit(w.channel, { update: true });
        expect(second.status).toBe(409); // a2 was behind
        await w.a2.sync(w.channel);
        const latest = await w.a2.commit(w.channel, { update: true });
        const report = (device: Device, seq: number, digest: string) => device.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest });
        expect((await report(w.b1, first.body.seq, first.body.digest)).status).toBe(409); // older: members built on it
        expect((await report(w.a2, latest.body.seq, latest.body.digest)).status).toBe(403); // the author
        expect((await report(w.b1, latest.body.seq, '2'.repeat(64))).status).toBe(409); // wrong digest
        expect((await report(w.b1, latest.body.seq, 'nope')).status).toBe(400);
        const outsider = enroll(ctx, user('dave'), new Client(Core));
        expect((await report(outsider, latest.body.seq, latest.body.digest)).status).toBe(404);
        // Application messages are never poison.
        await w.b1.sync(w.channel);
        const message = await w.b1.send(w.channel, 'chat');
        expect((await report(w.c1, message.body.seq, message.body.digest)).status).toBe(409);
    });
});

suite('review fixes', () => {
    test('a dismissed report cannot freeze the channel again, and one device cannot keep reporting', async () => {
        const w = await populated();
        const honest = await w.a1.commit(w.channel, { update: true });
        const { seq, digest } = honest.body;
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest })).status).toBe(202);
        const dismiss = await w.a2.api('POST', `/api/channels/${w.channel}/resolve`, { action: 'dismiss', seq, digest, author: '', signature: w.a2.resolution(w.channel, 'dismiss', seq, digest, '') });
        expect(dismiss.status).toBe(200);
        // The same commit is not reportable any more...
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest })).status).toBe(409);
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest })).status).toBe(409);
        expect(one('SELECT prev_state, frozen_seq FROM channels WHERE id = ?', w.channel)).toEqual({ prev_state: null, frozen_seq: null });
        // ...and a new commit can be reported by that device only once a minute.
        for (const device of [w.a2, w.b1, w.b2, w.c1]) await device.sync(w.channel);
        const next = await w.a1.commit(w.channel, { update: true });
        const again = await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq: next.body.seq, digest: next.body.digest });
        expect(again.status).toBe(429);
        advance(61_000);
        expect((await w.c1.api('POST', `/api/channels/${w.channel}/poison`, { seq: next.body.seq, digest: next.body.digest })).status).toBe(202);
    });

    test('a device that left the signed list is owed nothing over the stream, and loses its place', async () => {
        const w = await populated();
        run('INSERT INTO mls_welcomes (id, device_id, channel_id, sender_id, epoch, seq, welcome, tree, created_at) VALUES (?, ?, ?, ?, 1, 1, x\'00\', x\'00\', ?)', 'E'.repeat(22), w.c1.deviceId, w.channel, w.alice.id, clock);
        await w.b1.send(w.channel, 'secret');
        run("UPDATE devices SET state = 'pending' WHERE id = ?", w.c1.deviceId);
        const watch = w.c1.events(); await watch.opened; await watch.next('hello');
        await w.b1.send(w.channel, 'more');
        await Bun.sleep(150);
        expect(watch.pending('group')).toEqual([]);
        expect(watch.pending('welcome')).toEqual([]);
        // Its frames are ignored too, and its rows are gone.
        watch.send({ type: 'cursor', channel: w.channel, seq: 3 });
        watch.send({ type: 'ack', id: 'E'.repeat(22) });
        await Bun.sleep(100);
        expect(rows('SELECT 1 FROM channel_members WHERE device_id = ?', w.c1.deviceId)).toEqual([]);
        expect(rows('SELECT 1 FROM mls_welcomes WHERE device_id = ?', w.c1.deviceId)).toEqual([]);
        watch.socket.close();
        // A device that never reconnects is cleaned by the sweep.
        run("UPDATE devices SET state = 'pending' WHERE id = ?", w.b2.deviceId);
        run('INSERT INTO mls_welcomes (id, device_id, channel_id, sender_id, epoch, seq, welcome, tree, created_at) VALUES (?, ?, ?, ?, 1, 1, x\'00\', x\'00\', ?)', 'F'.repeat(22), w.b2.deviceId, w.channel, w.alice.id, clock);
        app.channels!.sweep(true);
        expect(rows('SELECT 1 FROM channel_members WHERE device_id = ?', w.b2.deviceId)).toEqual([]);
        expect(rows('SELECT 1 FROM mls_welcomes WHERE device_id = ?', w.b2.deviceId)).toEqual([]);
        // And the log no longer waits for it.
        for (const device of [w.a1, w.a2, w.b1]) await device.sync(w.channel);
        expect(rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel)).toEqual([]);
    });

    test('a device that joins late reads nothing from before it joined, whatever it asks for', async () => {
        const w = await populated();
        await w.b1.send(w.channel, 'before you');
        await w.a1.send(w.channel, 'also before');
        const a3 = enroll(ctx, w.alice, w.a1.client.sibling(), 'windows');
        pinAll([w.a1, w.b1, w.c1, a3]);
        expect((await a3.joinExternal(w.channel)).status).toBe(201);
        const joined = one('SELECT joined_seq FROM channel_members WHERE device_id = ?', a3.deviceId).joined_seq;
        expect(joined).toBe(4);
        const page = await a3.must('GET', `/api/channels/${w.channel}/log?after=0`);
        expect(page.entries).toEqual([]);
        expect(page.gap).toBe(false);
        // Entries sent afterwards are readable from any lower position.
        await w.c1.sync(w.channel);
        expect((await w.c1.send(w.channel, 'after you')).status).toBe(201);
        const later = await a3.must('GET', `/api/channels/${w.channel}/log?after=0`);
        expect(later.entries.map((entry: any) => entry.seq)).toEqual([5]);
        expect(await a3.sync(w.channel)).toEqual(['after you']);
        // The stream starts at the join point too, even though the older entries are still in the log for others.
        const lagging = rows('SELECT seq FROM group_log WHERE channel_id = ?', w.channel).map(row => row.seq);
        expect(lagging.some(seq => seq < joined)).toBe(true); // b1/c1 haven't read them all
        run('UPDATE channel_members SET cursor = 0 WHERE device_id = ?', a3.deviceId);
        const watch = a3.events(); await watch.opened;
        const frame = await watch.next('group');
        expect(frame.seq).toBeGreaterThan(joined);
        watch.socket.close();
    });
});

suite('M4 client additions (docs/m4-groups.md §8)', () => {
    test('the public channel directory lists public channels with their size, for listed devices only', async () => {
        const w = await world();
        const pub = await w.a1.createChannel('public', { name: 'general' });
        await w.a1.createChannel('private');
        await w.a1.add(pub.channel, [w.bob.id]);
        const seen = await w.c1.must('GET', '/api/channels/directory');
        expect(seen.channels).toEqual([{ id: pub.channel, name: 'general', members: 2, joined: false }]);
        expect((await w.b1.must('GET', '/api/channels/directory')).channels[0].joined).toBe(true);
        const stranger = user('erin');
        expect((await request('/api/channels/directory', 'GET', stranger.cookie)).status).toBe(409); // no device announced
    });

    test('anyone signed in can look up a user\'s published identity by id, and nothing else', async () => {
        const w = await world();
        const stranger = user('erin');
        const found = await request(`/api/users/${w.carol.id}/identity`, 'GET', stranger.cookie);
        expect(found.status).toBe(200);
        expect(await found.json()).toEqual({ userId: w.carol.id, username: 'carol', identity: w.c1.client.call({ cmd: 'identity' }) });
        expect((await request(`/api/users/${id()}/identity`, 'GET', stranger.cookie)).status).toBe(404);
        expect((await request(`/api/users/${stranger.id}/identity`, 'GET', stranger.cookie)).status).toBe(404); // no keys yet
        expect((await fetch(new URL(`/api/users/${w.carol.id}/identity`, app.server.url))).status).toBe(401);
    });

    test('ephemeral messages reach the other member devices live, once, and are never logged', async () => {
        const w = await populated();
        const watchers = [w.a1, w.a2, w.b2, w.c1].map(device => ({ device, watch: device.events() }));
        for (const { watch } of watchers) { await watch.opened; await watch.next('hello'); }
        const own = w.b1.events(); await own.opened; await own.next('hello');
        const seqBefore = one('SELECT seq FROM channels WHERE id = ?', w.channel).seq;
        const typing = JSON.stringify({ v: 1, type: 'typing', id: crypto.randomUUID(), at: Date.now(), on: true });
        const message = w.b1.client.call({ cmd: 'mlsEncrypt', group: w.channel, plaintext: typing });
        const sent = await w.b1.api('POST', `/api/channels/${w.channel}/ephemeral`, { message });
        expect(sent).toEqual({ status: 202, body: { delivered: true } });
        for (const { device, watch } of watchers) {
            const frame = await watch.next('ephemeral');
            expect(frame).toMatchObject({ channel: w.channel, from: { userId: w.bob.id, deviceId: w.b1.deviceId }, message });
            expect(device.client.call({ cmd: 'mlsReceive', group: w.channel, message: frame.message }).plaintext).toBe(typing);
        }
        await Bun.sleep(100);
        expect(own.pending('ephemeral')).toEqual([]);
        expect(one('SELECT seq FROM channels WHERE id = ?', w.channel).seq).toBe(seqBefore);
        expect(one('SELECT COUNT(*) AS n FROM group_log WHERE channel_id = ? AND seq > ?', w.channel, seqBefore).n).toBe(0);
        // Bounded, private-message only, current epoch only, members only.
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/ephemeral`, { message: Buffer.alloc(2100).toString('base64url') })).status).toBe(400);
        const commit = w.a1.client.call({ cmd: 'mlsCommit', group: w.channel, update: true });
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/ephemeral`, { message: commit.commit })).status).toBe(400);
        w.a1.client.call({ cmd: 'mlsClearOwn', group: w.channel });
        expect((await w.a1.commit(w.channel, { update: true })).status).toBe(201);
        const stale = w.b1.client.call({ cmd: 'mlsEncrypt', group: w.channel, plaintext: typing });
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/ephemeral`, { message: stale })).status).toBe(409);
        const dave = enroll(ctx, user('dave'), new Client(Core));
        expect((await dave.api('POST', `/api/channels/${w.channel}/ephemeral`, { message })).status).toBe(404);
        for (const { watch } of [...watchers, { watch: own }]) watch.socket.close();
    });

    test('a core without a 1:1 identity takes a certificate signed outside it (the web\'s WebCrypto AIK), once', async () => {
        await start();
        const F = (globalThis as any).DeviceFormat;
        const { publicKey, privateKey } = generateKeyPairSync('ed25519');
        const aik = (publicKey.export({ format: 'jwk' }) as any).x as string;
        const [userId, deviceId, issuedAt] = [id(), id(), Date.now()];
        const mlsOnly = new Client(Core);
        const leaf = mlsOnly.call({ cmd: 'mlsDeviceLeaf' });
        const sig = sign(null, F.mlsCertBytes(userId, deviceId, 'web', leaf, aik, issuedAt), privateKey).toString('base64url');
        const cert = F.mlsCertJson(userId, deviceId, 'web', leaf, aik, issuedAt, sig);
        expect(() => mlsOnly.call({ cmd: 'mlsSetDeviceCert', cert })).toThrow(/account key is needed/);
        const other = (generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as any).x;
        expect(() => mlsOnly.call({ cmd: 'mlsSetDeviceCert', cert, aik: other })).toThrow();
        expect(mlsOnly.call({ cmd: 'mlsSetDeviceCert', cert, aik })).toMatchObject({ userId, deviceId, leafSigKey: leaf, aikSign: aik });
        expect(mlsOnly.call({ cmd: 'mlsKeyPackages', count: 1 })).toHaveLength(1);
        expect(mlsOnly.rows.identity).toBeUndefined(); // no 1:1 identity was minted
        // A core with its own identity certifies under that key only, whatever the caller names.
        const holder = new Client(Core);
        holder.call({ cmd: 'identity' });
        const leaf2 = holder.call({ cmd: 'mlsDeviceLeaf' });
        const forged = F.mlsCertJson(userId, deviceId, 'web', leaf2, aik, issuedAt, sign(null, F.mlsCertBytes(userId, deviceId, 'web', leaf2, aik, issuedAt), privateKey).toString('base64url'));
        expect(() => holder.call({ cmd: 'mlsSetDeviceCert', cert: forged, aik })).toThrow();
    });

    test('acceptChange and setVerified take the exact identity reviewed, and refuse a newer one', async () => {
        await start();
        const core = new Client(Core), contact = id();
        const [first, second] = [new Client(Core).call({ cmd: 'identity' }), new Client(Core).call({ cmd: 'identity' })];
        core.call({ cmd: 'notePeer', contact, identity: first });
        expect(core.call({ cmd: 'notePeer', contact, identity: second }).blocked).toBe(true);
        let error: any;
        try { core.call({ cmd: 'acceptChange', contact, identity: first }); } catch (caught) { error = caught; }
        expect(error?.code).toBe('mismatch');
        expect(core.call({ cmd: 'peer', contact }).blocked).toBe(true);
        expect(() => core.call({ cmd: 'setVerified', contact, verified: true, identity: first })).toThrow(/changed again/);
        core.call({ cmd: 'acceptChange', contact, identity: second });
        core.call({ cmd: 'setVerified', contact, verified: true, identity: second });
        expect(core.call({ cmd: 'peer', contact })).toMatchObject({ blocked: false, verified: true, identity: second });
    });

    test('a rollback without a removal restores the state and removes nobody; a dismissal names no author', async () => {
        const w = await populated();
        const out = w.a1.client.call({ cmd: 'mlsCommit', group: w.channel, update: true });
        const result = await w.a1.api('POST', `/api/channels/${w.channel}/commits`, { message: flip(out.commit, -1) });
        expect(result.status).toBe(201);
        const { seq, digest } = result.body;
        expect((await w.b1.api('POST', `/api/channels/${w.channel}/poison`, { seq, digest })).status).toBe(202);
        const watch = w.c1.events(); await watch.opened;
        const sign = (author: string, action = 'rollback') => ({ action, seq, digest, author, leafSignature: 'L'.repeat(86), signature: w.a2.resolution(w.channel, action as any, seq, digest, author) });
        expect((await w.a2.api('POST', `/api/channels/${w.channel}/resolve`, sign(w.a1.deviceId, 'dismiss'))).status).toBe(400); // a dismissal removes nobody
        expect((await w.a2.api('POST', `/api/channels/${w.channel}/resolve`, { ...sign(''), leafSignature: undefined })).status).toBe(400); // members need the leaf signature
        const done = await w.a2.api('POST', `/api/channels/${w.channel}/resolve`, sign(''));
        expect(done.status).toBe(200);
        expect(done.body).toEqual({ resolved: 'rollback', epoch: 1, seq: seq - 1 });
        expect(rows('SELECT device_id FROM channel_bans WHERE channel_id = ?', w.channel)).toEqual([]);
        let change: any; const seen: string[] = [];
        let rolled: any;
        do { change = await watch.next('channel'); seen.push(change.change); if (change.change === 'rolled-back') rolled = change; } while (change.change !== 'thawed');
        expect(seen).toContain('rolled-back');
        expect(seen).not.toContain('remove-needed');
        expect(rolled).toMatchObject({ action: 'rollback', seq, digest, author: '', by: w.a2.deviceId, byUser: w.alice.id, signature: 'L'.repeat(86) });

        // The resolving admin publishes the restored epoch's GroupInfo; the author's device is still a member and
        // rejoins with it (its own copy had merged the rolled-back commit), then goes on.
        const view = w.a2.client.call({ cmd: 'mlsView', group: w.channel });
        expect((await w.a2.api('PUT', `/api/channels/${w.channel}/group-info`, { epoch: view.epoch, groupInfo: view.groupInfo })).status).toBe(200);
        w.a1.client.call({ cmd: 'mlsForget', group: w.channel });
        expect((await w.a1.joinExternal(w.channel)).status).toBe(201);
        watch.socket.close();
    });

    test('resolve bytes v2: a fixed vector shared with the app (apps/chat/test/group_sync_test.dart)', async () => {
        await start(); // this file's teardown expects a server
        const bytes = resolveBytes('C'.repeat(22), 'rollback', 7, 'd'.repeat(64), 'a'.repeat(22));
        expect(createHash('sha256').update(bytes).digest('hex')).toBe('15911786d65cec6da7b01ae0de4df45929815e2d0073cad52665c981f5710bd3');
        expect(bytes.toString()).toBe(`webrtc-bun-mlsresolve-v2\n${'C'.repeat(22)}\nrollback\n7\n${'d'.repeat(64)}\n${'a'.repeat(22)}`);
    });
});

suite('identity change in a channel (docs/m5-linking.md §7)', () => {
    test('a member recovering under a new key no longer wedges the channel: the DS follows the registry, their old devices go stale and can be removed', async () => {
        const w = await populated();
        const fresh = new Client(Core).call({ cmd: 'identity' });
        run('UPDATE identity_keys SET sign = ?, dh = ? WHERE user_id = ?', fresh.sign, fresh.dh, w.bob.id);
        // Before M5 this was a 409 "identity changed" for every commit in every channel Bob is in.
        const update = await w.a1.commit(w.channel, { update: true });
        expect(update.status).toBe(201);
        // Alice's devices review Bob's new code; his old devices are stale for them, and cannot be added to anything.
        for (const dev of [w.a1, w.a2, w.c1]) dev.client.call({ cmd: 'notePeer', contact: w.bob.id, identity: fresh });
        for (const dev of [w.a1, w.a2, w.c1]) dev.client.call({ cmd: 'acceptChange', contact: w.bob.id });
        const stale = w.a1.client.call({ cmd: 'mlsMembers', group: w.channel }).filter((m: any) => m.stale).map((m: any) => m.deviceId).sort();
        expect(stale).toEqual([w.b1.deviceId, w.b2.deviceId].sort());
        const cleanup = await w.a1.commit(w.channel, { removes: [{ userId: w.bob.id, deviceId: w.b1.deviceId }, { userId: w.bob.id, deviceId: w.b2.deviceId }] });
        expect(cleanup.status).toBe(201);
        for (const dev of [w.a2, w.c1]) await dev.sync(w.channel);
        expect(w.a2.client.call({ cmd: 'mlsMembers', group: w.channel }).some((m: any) => m.stale)).toBe(false);
    });

    test('a signed succession keeps the old devices current for what they were certified before it', async () => {
        const w = await populated();
        const fresh = new Client(Core).call({ cmd: 'identity' });
        const oldIdentity = w.b1.client.call({ cmd: 'identity' });
        const signed = w.b1.client.call({ cmd: 'signSuccession', userId: w.bob.id, published: oldIdentity.sign, newSign: fresh.sign, newDh: fresh.dh, at: clock + 60_000 }); // after every certificate issued so far
        const { signature, ...record } = signed;
        expect((await w.b1.api('PUT', '/api/devices/succession', { record, signature })).status).toBe(201);
        run('UPDATE identity_keys SET sign = ?, dh = ? WHERE user_id = ?', fresh.sign, fresh.dh, w.bob.id);
        expect((await w.a1.commit(w.channel, { update: true })).status).toBe(201);
        // Alice's devices follow the chain the server serves for Bob (his pin moves, verification kept) and see no stale device.
        const view = await w.a1.must('GET', '/api/devices/bob');
        for (const dev of [w.a1, w.a2, w.c1]) dev.client.call({ cmd: 'acceptSuccession', contact: w.bob.id, records: view.succession });
        expect(w.a1.client.call({ cmd: 'mlsMembers', group: w.channel }).some((m: any) => m.stale)).toBe(false);
        for (const dev of [w.a2, w.c1, w.b1, w.b2]) { try { await dev.sync(w.channel); } catch {} }
        // Bob's old device still writes, and Alice's devices still read it.
        w.b1.client.call({ cmd: 'notePeer', contact: w.bob.id, identity: oldIdentity });
        await w.a2.sync(w.channel);
        expect((await w.a2.sync(w.channel))).toEqual([]);
    });
});
