import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../packages/signaling/accounts';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
let dataDir: string, app: ReturnType<typeof startSignaling>, pushes: unknown[];
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'ephemeral-'));
    pushes = [];
    app = startSignaling({ adminToken: 'ephemeral-test-admin-secret-00000000000000', origin, port: 0, dataDir, pushSend: async (...args: unknown[]) => { pushes.push(args); return { statusCode: 201 }; } });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });

const request = (path: string, method: string, cookie: string, body?: unknown) => fetch(new URL(path, app.server.url), {
    method, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(method !== 'GET' ? { Origin: origin } : {}) }, body: body === undefined ? undefined : JSON.stringify(body),
});
function user(name: string) { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; }
async function befriend(a: ReturnType<typeof user>, b: ReturnType<typeof user>) {
    expect((await request('/api/contacts', 'POST', a.cookie, { username: b.username })).status).toBe(202);
    expect((await request(`/api/contacts/${a.username}/accept`, 'POST', b.cookie, {})).status).toBe(200);
}
const envelope = (bytes = 64) => randomBytes(bytes).toString('base64url');
function events(cookie: string) {
    const url = new URL('/api/events', app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { headers: { Origin: origin, Cookie: cookie } } as any);
    const inbox: any[] = [];
    socket.onmessage = event => inbox.push(JSON.parse(String(event.data)));
    return { socket, inbox, opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })) };
}
const stored = () => { const db = openDatabase(dataDir); const count = (db.query('SELECT COUNT(*) AS count FROM mailbox').get() as { count: number }).count; db.close(); return count; };

describe('ephemeral envelopes', () => {
    test('reach every open stream of the recipient and are never stored', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const phone = events(bob.cookie), laptop = events(bob.cookie);
        await phone.opened; await laptop.opened; await Bun.sleep(50);
        const sent = envelope(200);
        const response = await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: sent, ephemeral: true });
        expect(response.status).toBe(202);
        expect(await response.json()).toEqual({ delivered: true });
        await Bun.sleep(100);
        for (const stream of [phone, laptop]) {
            const frames = stream.inbox.filter(message => message.type === 'envelope');
            expect(frames).toHaveLength(1);
            expect(frames[0]).toMatchObject({ type: 'envelope', from: { id: alice.id, username: 'alice' }, envelope: sent, ephemeral: true });
            stream.socket.close();
        }
        expect(stored()).toBe(0);
    });
    test('are dropped when the recipient is offline: no mailbox row, no push, nothing on reconnect', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const p256dh = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 7)]).toString('base64url'), auth = Buffer.alloc(16, 9).toString('base64url');
        expect((await request('/api/push/subscribe', 'POST', bob.cookie, { subscription: { endpoint: 'https://fcm.googleapis.com/fcm/send/device-1', keys: { p256dh, auth } } })).status).toBe(201);
        const response = await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(), ephemeral: true });
        expect(response.status).toBe(202);
        expect(await response.json()).toEqual({ delivered: false });
        expect(stored()).toBe(0);
        const later = events(bob.cookie);
        await later.opened; await Bun.sleep(150);
        expect(later.inbox.map(message => message.type)).toEqual(['hello']);
        later.socket.close();
        await Bun.sleep(50);
        expect(pushes).toEqual([]);
        // A stored message to the same offline recipient does push, so the silence above is the ephemeral rule.
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).status).toBe(201);
        await Bun.sleep(50);
        expect(pushes).toHaveLength(1);
    });
    test('same contact rules as messages, at most 2 KB, and a strict flag', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob);
        expect((await request('/api/messages', 'POST', carol.cookie, { to: 'bob', envelope: envelope(), ephemeral: true })).status).toBe(403);
        expect((await fetch(new URL('/api/messages', app.server.url), { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ to: 'bob', envelope: envelope(), ephemeral: true }) })).status).toBe(401);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(2049), ephemeral: true })).status).toBe(413);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(2048), ephemeral: true })).status).toBe(202);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: 'not base64url!', ephemeral: true })).status).toBe(400);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(), ephemeral: 'yes' })).status).toBe(400);
        expect(stored()).toBe(0);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(), ephemeral: false })).status).toBe(201);
        expect(stored()).toBe(1);
    });
});
