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
const stored = () => { const db = openDatabase(dataDir); const count = (db.query('SELECT COUNT(*) AS count FROM device_inbox').get() as { count: number }).count; db.close(); return count; };

describe('ephemeral envelopes are gone (docs/m5-linking.md §9)', () => {
    test('typing hints no longer use the Double Ratchet: a 1:1 envelope marked ephemeral is refused and delivered to nobody', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob);
        const watch = events(bob.cookie); await watch.opened; await Bun.sleep(50);
        const response = await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(), ephemeral: true });
        expect(response.status).toBe(410);
        expect(((await response.json()) as any).error).toContain('MLS');
        await Bun.sleep(100);
        expect(watch.inbox.filter(message => message.type === 'envelope')).toEqual([]);
        expect(stored()).toBe(0);
        // Contacts and shapes are still checked first; a normal envelope still goes through and is stored.
        expect((await request('/api/messages', 'POST', carol.cookie, { to: 'bob', envelope: envelope(), ephemeral: true })).status).toBe(403);
        expect((await fetch(new URL('/api/messages', app.server.url), { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ to: 'bob', envelope: envelope(), ephemeral: true }) })).status).toBe(401);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(), ephemeral: 'yes' })).status).toBe(400);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).status).toBe(201);
        await Bun.sleep(100);
        expect(watch.inbox.filter(message => message.type === 'envelope').length).toBe(1);
        expect(stored()).toBe(1);
        watch.socket.close();
    });
});
