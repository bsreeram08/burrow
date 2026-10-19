import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../packages/signaling/accounts';
import { BLOB_MAX } from '../../packages/signaling/blobs';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000', DAY = 86400000;
let dataDir: string, app: ReturnType<typeof startSignaling>, clock: number;
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'blobs-'));
    clock = Date.now();
    app = startSignaling({ adminToken: 'blobs-test-admin-secret-0000000000000000000', origin, port: 0, dataDir, now: () => clock });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });
async function restart(blobBudget: number) {
    await app.stop();
    app = startSignaling({ adminToken: 'blobs-test-admin-secret-0000000000000000000', origin, port: 0, dataDir, now: () => clock, blobBudget });
}
const files = () => readdirSync(join(dataDir, 'blobs'));
/** A raw upload that declares `length` bytes but sends only `sent` of them and stays open until closed. */
async function partialUpload(cookie: string, length: number, sent: number) {
    const socket = await Bun.connect({ hostname: '127.0.0.1', port: app.server.port!, socket: { data() {} } });
    socket.write(`POST /api/blobs HTTP/1.1\r\nHost: localhost\r\nOrigin: ${origin}\r\nCookie: ${cookie}\r\nContent-Type: application/octet-stream\r\nContent-Length: ${length}\r\n\r\n`);
    socket.write(new Uint8Array(sent));
    return socket;
}
const until = async (check: () => boolean) => { for (let index = 0; index < 100 && !check(); index++) await Bun.sleep(20); expect(check()).toBe(true); };
const user = (name: string) => { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; };
const upload = (bytes: Uint8Array, headers: Record<string, string>) => fetch(new URL('/api/blobs', app.server.url), { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', ...headers }, body: bytes });
const download = (id: string, headers: Record<string, string> = {}) => fetch(new URL(`/api/blobs/${id}`, app.server.url), { headers });

describe('encrypted attachments', () => {
    test('upload and download round-trip the exact bytes for any signed-in account', async () => {
        const alice = user('alice'), bob = user('bob'), bytes = new Uint8Array(randomBytes(70000));
        const created = await upload(bytes, { Cookie: alice.cookie, Origin: origin });
        expect(created.status).toBe(201);
        const { id } = await created.json() as { id: string };
        expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
        const fetched = await download(id, { Cookie: bob.cookie });
        expect(fetched.status).toBe(200);
        expect(fetched.headers.get('content-type')).toBe('application/octet-stream');
        expect(fetched.headers.get('cache-control')).toBe('private, max-age=31536000, immutable');
        expect(fetched.headers.get('x-content-type-options')).toBe('nosniff');
        expect(new Uint8Array(await fetched.arrayBuffer())).toEqual(bytes);
        // Native apps: bearer token, no Origin.
        const native = await upload(bytes.subarray(0, 100), { Authorization: `Bearer ${app.accounts!.testing.bearer(bob.id)}` });
        expect(native.status).toBe(201);
        expect(new Uint8Array(await (await download((await native.json() as { id: string }).id, { Authorization: `Bearer ${app.accounts!.testing.bearer(alice.id)}` })).arrayBuffer())).toEqual(bytes.subarray(0, 100));
    });
    test('both directions need a session; uploads need this origin and octet-stream', async () => {
        const alice = user('alice'), bytes = new Uint8Array(randomBytes(64));
        expect((await upload(bytes, { Origin: origin })).status).toBe(401);
        const { id } = await (await upload(bytes, { Cookie: alice.cookie, Origin: origin })).json() as { id: string };
        expect((await download(id)).status).toBe(401);
        expect((await upload(bytes, { Cookie: alice.cookie })).status).toBe(403);
        expect((await upload(bytes, { Cookie: alice.cookie, Origin: 'https://evil.example' })).status).toBe(403);
        expect((await upload(bytes, { Cookie: alice.cookie, Origin: origin, 'Content-Type': 'text/html' })).status).toBe(415);
        expect((await upload(bytes, { Authorization: `Bearer ${app.accounts!.testing.bearer(alice.id)}`, Origin: origin })).status).toBe(401);
    });
    test('unknown, malformed and traversal ids are 404', async () => {
        const alice = user('alice');
        for (const id of ['A'.repeat(22), 'short', '..%2Faccounts.sqlite', 'A'.repeat(22) + '.part']) expect((await download(id, { Cookie: alice.cookie })).status).toBe(404);
    });
    test('bodies over 25 MiB plus the nonce and tag are refused before they are read', async () => {
        const alice = user('alice');
        expect((await upload(new Uint8Array(BLOB_MAX + 1), { Cookie: alice.cookie, Origin: origin })).status).toBe(413);
        expect((await upload(new Uint8Array(0), { Cookie: alice.cookie, Origin: origin })).status).toBe(400);
        // Other paths keep their 128 KiB limit.
        const response = await fetch(new URL('/api/messages', app.server.url), { method: 'POST', headers: { Cookie: alice.cookie, Origin: origin, 'Content-Type': 'application/json' }, body: new Uint8Array(200000) });
        expect(response.status).toBe(413);
    });
    test('accepts exactly the maximum size', async () => {
        const alice = user('alice');
        expect((await upload(new Uint8Array(BLOB_MAX), { Cookie: alice.cookie, Origin: origin })).status).toBe(201);
    });
    test('each account holds at most 1 GiB of live blobs', async () => {
        const alice = user('alice'), bob = user('bob');
        const db = openDatabase(dataDir);
        db.query('INSERT INTO blobs (id, owner_id, size, created_at) VALUES (?, ?, ?, ?)').run('q'.repeat(22), alice.id, 1024 ** 3 - 100, clock);
        db.close();
        expect((await upload(new Uint8Array(101), { Cookie: alice.cookie, Origin: origin })).status).toBe(507);
        expect((await upload(new Uint8Array(100), { Cookie: alice.cookie, Origin: origin })).status).toBe(201);
        expect((await upload(new Uint8Array(101), { Cookie: bob.cookie, Origin: origin })).status).toBe(201);
    });
    test('uploads are rate limited per account', async () => {
        const alice = user('alice');
        const statuses = await Promise.all(Array.from({ length: 8 }, () => upload(new Uint8Array(16), { Cookie: alice.cookie, Origin: origin }).then(response => response.status)));
        expect(statuses).toContain(201);
        expect(statuses).toContain(429);
    });
    test('blobs expire after 30 days and the sweep deletes their files', async () => {
        const alice = user('alice');
        const { id } = await (await upload(new Uint8Array(randomBytes(32)), { Cookie: alice.cookie, Origin: origin })).json() as { id: string };
        expect(existsSync(join(dataDir, 'blobs', id))).toBe(true);
        clock += 29 * DAY;
        expect((await download(id, { Cookie: app.accounts!.testing.cookie(alice.id) })).status).toBe(200);
        clock += 2 * DAY;
        const cookie = app.accounts!.testing.cookie(alice.id);
        expect((await download(id, { Cookie: cookie })).status).toBe(404);
        app.blobs!.sweep();
        expect(existsSync(join(dataDir, 'blobs', id))).toBe(false);
        const db = openDatabase(dataDir);
        expect((db.query('SELECT COUNT(*) AS count FROM blobs').get() as { count: number }).count).toBe(0);
        db.close();
    });
    test('pages may render decrypted media from blob: URLs, and nothing else is loosened', async () => {
        const csp = (await fetch(new URL('/', app.server.url))).headers.get('content-security-policy')!;
        expect(csp).toContain("img-src 'self' blob:;");
        expect(csp).toContain("media-src 'self' blob:;");
        expect(csp).toContain("connect-src 'self';");
        expect(csp).not.toContain('data:');
        expect(csp).not.toContain('*');
    });
    test('uploads stream to disk, at most two at once per account, and a short body leaves nothing behind', async () => {
        const alice = user('alice'), bob = user('bob');
        const first = await partialUpload(alice.cookie, 1_000_000, 4096), second = await partialUpload(alice.cookie, 1_000_000, 4096);
        // Both are being written before their bodies are complete: nothing is buffered whole in memory.
        await until(() => files().filter(name => name.endsWith('.part')).length === 2);
        expect((await upload(new Uint8Array(16), { Cookie: alice.cookie, Origin: origin })).status).toBe(429);
        expect((await upload(new Uint8Array(16), { Cookie: bob.cookie, Origin: origin })).status).toBe(201);
        first.end(); second.end();
        await until(() => files().every(name => !name.endsWith('.part')));
        expect(files()).toHaveLength(1); // only bob's
        await Bun.sleep(1000); // the per-second rate limit, not the concurrency cap
        expect((await upload(new Uint8Array(16), { Cookie: alice.cookie, Origin: origin })).status).toBe(201);
        const db = openDatabase(dataDir);
        expect((db.query('SELECT COUNT(*) AS count FROM blobs').get() as { count: number }).count).toBe(2);
        db.close();
    });
    test('the server-wide budget refuses uploads once stored bytes would exceed it', async () => {
        await restart(1000);
        const alice = user('alice'), bob = user('bob');
        expect((await upload(new Uint8Array(600), { Cookie: alice.cookie, Origin: origin })).status).toBe(201);
        expect((await upload(new Uint8Array(401), { Cookie: bob.cookie, Origin: origin })).status).toBe(507);
        expect((await upload(new Uint8Array(400), { Cookie: bob.cookie, Origin: origin })).status).toBe(201);
    });
    test('a deleted account\'s files are removed by the periodic orphan scan', async () => {
        const alice = user('alice');
        const { id } = await (await upload(new Uint8Array(32), { Cookie: alice.cookie, Origin: origin })).json() as { id: string };
        const db = openDatabase(dataDir);
        db.query('DELETE FROM users WHERE id = ?').run(alice.id);
        expect((db.query('SELECT COUNT(*) AS count FROM blobs').get() as { count: number }).count).toBe(0);
        db.close();
        app.blobs!.sweep();
        expect(existsSync(join(dataDir, 'blobs', id))).toBe(true); // scans are throttled
        clock += 10 * 60000;
        app.blobs!.sweep();
        expect(existsSync(join(dataDir, 'blobs', id))).toBe(false);
    });
});
