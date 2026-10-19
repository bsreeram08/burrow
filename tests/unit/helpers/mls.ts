import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveBytes } from '../../../packages/signaling/channels';

// Test harness for the MLS delivery service: real chatcore clients (the WebAssembly core with the `mls` feature,
// built on demand into a scratch directory; it is not a committed artifact) against a real Bun server. A "device"
// here is one client core with its own store, one server session bound to a listed device, and a cursor per channel.

const root = join(import.meta.dir, '..', '..', '..');
const origin = 'http://localhost:3000';
export const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
export const id = () => randomBytes(16).toString('base64url');
type CoreClass = new (rows: string, existed: boolean) => { call(command: string): string };

function run(command: string, args: string[], env: Record<string, string> = {}) {
    const result = Bun.spawnSync([command, ...args], { env: { ...process.env, ...env }, stdout: 'pipe', stderr: 'pipe' });
    return { ok: result.exitCode === 0, out: result.stdout.toString(), err: result.stderr.toString() };
}

/** The client core, or null (with the reason) when the Rust toolchain isn't available: those tests are skipped. */
export function clientCore(): { core: CoreClass } | { skip: string } {
    if (!run('cargo', ['--version']).ok || !run('wasm-bindgen', ['--version']).ok) return { skip: 'cargo and wasm-bindgen are needed to build the MLS client core' };
    const dir = join(tmpdir(), `webrtc-bun-mls-client-${process.getuid?.() ?? 0}`);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const target = join(root, 'crates/chatcore-wasm/target');
    const built = run('cargo', ['build', '--release', '--quiet', '--target', 'wasm32-unknown-unknown', '--features', 'mls,ds', '--manifest-path', join(root, 'crates/chatcore-wasm/Cargo.toml')], { CARGO_TARGET_DIR: target });
    if (!built.ok) return { skip: `the MLS client core did not build: ${built.err.slice(-300)}` };
    const wasm = join(target, 'wasm32-unknown-unknown/release/chatcore_wasm.wasm');
    const stamp = join(dir, `cc-${statSync(wasm).mtimeMs}`);
    if (!existsSync(stamp)) {
        const out = join(dir, `cc-${statSync(wasm).mtimeMs}`);
        const bindgen = run('wasm-bindgen', ['--target', 'nodejs', '--no-typescript', '--out-name', 'cc', '--out-dir', out, wasm]);
        if (!bindgen.ok) return { skip: `wasm-bindgen failed: ${bindgen.err.slice(-300)}` };
    }
    return { core: (createRequire(import.meta.url)(join(stamp, 'cc.js')) as { ChatCore: CoreClass }).ChatCore };
}

export class CoreError extends Error { constructor(message: string, readonly code: string | null) { super(message); } }

/** One chatcore instance with its key database in memory. */
export class Client {
    rows: Record<string, unknown> = {};
    private core;
    constructor(private Core: CoreClass, rows: Record<string, unknown> = {}) { this.rows = { ...rows }; this.core = new Core(JSON.stringify(this.rows), false); }
    call(command: Record<string, unknown>): any {
        const out = JSON.parse(this.core.call(JSON.stringify(command))) as { ok?: unknown; error?: string; code?: string | null; writes: ({ put: string; value: unknown } | { delete: string })[] };
        for (const write of out.writes) { if ('put' in write) this.rows[write.put] = write.value; else delete this.rows[write.delete]; }
        if (out.error !== undefined) throw new CoreError(out.error, out.code ?? null);
        return out.ok;
    }
    /** Another device of the same account: same identity key, its own store. */
    sibling() { return new Client(this.Core, { identity: this.rows.identity }); }
}

export type User = { id: string; username: string };

/** A listed device of an account: a client core, a bound session, a registered signing key, a position per channel. */
let devices = 0;
export class Device {
    readonly cursor = new Map<string, number>();
    /** Each device calls from its own address (the server must be started with trustProxy), as real devices do. */
    readonly ip = `10.7.${(++devices >> 8) & 255}.${devices & 255}`;
    constructor(readonly app: { server: { url: URL }; accounts?: any }, readonly user: User, readonly client: Client, readonly deviceId: string, readonly token: string, readonly key: KeyObject) {}

    /** Calls the server as this device. */
    async api(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
        const response = await fetch(new URL(path, this.app.server.url), {
            method, headers: { 'Content-Type': 'application/json', Cookie: `session=${this.token}`, 'X-Real-IP': this.ip, ...(method !== 'GET' ? { Origin: origin } : {}), ...headers },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        let data: any = null;
        try { data = JSON.parse(text); } catch {}
        return { status: response.status, body: data };
    }
    async must(method: string, path: string, body?: unknown, status?: number) {
        const result = await this.api(method, path, body);
        if (status !== undefined ? result.status !== status : result.status >= 300) throw new Error(`${method} ${path} -> ${result.status} ${JSON.stringify(result.body)}`);
        return result.body;
    }

    async uploadKeyPackages(count = 10) {
        const keyPackages = this.client.call({ cmd: 'mlsKeyPackages', count });
        const lastResort = this.client.call({ cmd: 'mlsKeyPackages', count: 1, lastResort: true })[0];
        return this.must('PUT', '/api/mls/keypackages', { keyPackages, lastResort }, 201);
    }
    async createChannel(kind: 'public' | 'private' | 'dm' | 'group_dm' | 'self', options: { id?: string; name?: string; peer?: User } = {}) {
        const channel = options.id ?? id();
        const roles = kind === 'dm' ? { v: 1, kind: 'dm', admins: [this.user.id, options.peer!.id].sort(), joinPolicy: 'invite', dm: [this.user.id, options.peer!.id].sort() }
            : { v: 1, kind: 'group', admins: [this.user.id], joinPolicy: kind === 'public' ? 'open' : 'invite' };
        const view = this.client.call({ cmd: 'mlsCreate', group: channel, roles });
        const response = await this.api('POST', '/api/channels', { id: channel, kind, name: options.name, peer: options.peer?.username, groupInfo: view.groupInfo, tree: view.tree });
        this.cursor.set(channel, 0);
        return { channel, response, view };
    }
    /** Claims KeyPackages for `users`, commits their devices in and sends the Welcome. Returns the server's answer. */
    async add(channel: string, users: string[]) {
        const claimed = await this.must('POST', '/api/mls/keypackages/claim', { users }, 200);
        const out = this.client.call({ cmd: 'mlsCommit', group: channel, adds: claimed.keyPackages.map((item: any) => item.keyPackage) });
        const result = await this.api('POST', `/api/channels/${channel}/commits`, { message: out.commit, welcome: out.welcome, joiners: claimed.keyPackages.map((item: any) => item.deviceId) });
        return this.settle(channel, out, result, claimed);
    }
    /** Builds a commit with the given changes and submits it. */
    async commit(channel: string, change: { adds?: string[]; removes?: { userId: string; deviceId?: string }[]; update?: boolean; roles?: unknown }, joiners?: string[]) {
        const out = this.client.call({ cmd: 'mlsCommit', group: channel, adds: change.adds, removes: change.removes, update: change.update, roles: change.roles });
        const result = await this.api('POST', `/api/channels/${channel}/commits`, { message: out.commit, ...(out.welcome ? { welcome: out.welcome, joiners } : {}) });
        return this.settle(channel, out, result);
    }
    private async settle(channel: string, out: any, result: { status: number; body: any }, claimed?: any) {
        if (result.status === 201) {
            const view = this.client.call({ cmd: 'mlsMergeOwn', group: channel });
            this.cursor.set(channel, result.body.seq);
            await this.api('PUT', `/api/channels/${channel}/group-info`, { epoch: view.epoch, groupInfo: view.groupInfo });
            await this.api('POST', `/api/channels/${channel}/cursor`, { seq: result.body.seq });
        } else this.client.call({ cmd: 'mlsClearOwn', group: channel });
        return { ...result, out, claimed };
    }
    /** Joins every Welcome waiting for this device; returns the channels joined. */
    async joinWelcomes() {
        const joined: string[] = [];
        for (const item of (await this.must('GET', '/api/mls/welcomes')).welcomes) {
            const full = await this.must('GET', `/api/mls/welcomes/${item.id}`);
            this.client.call({ cmd: 'mlsJoin', welcome: full.welcome, tree: full.tree });
            this.cursor.set(full.channel, full.seq);
            await this.must('POST', `/api/channels/${full.channel}/cursor`, { seq: full.seq });
            await this.must('DELETE', `/api/mls/welcomes/${item.id}`);
            joined.push(full.channel);
        }
        return joined;
    }
    /** An external join: this device (an extra device of a member, or anyone for a public channel) adds itself. */
    async joinExternal(channel: string) {
        const info = await this.must('GET', `/api/channels/${channel}/join-info`);
        const out = this.client.call({ cmd: 'mlsJoinExternal', groupInfo: info.groupInfo, tree: info.tree });
        const result = await this.api('POST', `/api/channels/${channel}/join`, { message: out.commit });
        if (result.status === 201) {
            const view = this.client.call({ cmd: 'mlsMergeOwn', group: channel });
            this.cursor.set(channel, result.body.seq);
            await this.api('PUT', `/api/channels/${channel}/group-info`, { epoch: view.epoch, groupInfo: view.groupInfo });
            await this.api('POST', `/api/channels/${channel}/cursor`, { seq: result.body.seq });
        } else this.client.call({ cmd: 'mlsClearOwn', group: channel });
        return { ...result, out };
    }
    send(channel: string, text: string) {
        const message = this.client.call({ cmd: 'mlsEncrypt', group: channel, plaintext: text });
        return this.api('POST', `/api/channels/${channel}/messages`, { message });
    }
    /** Reads the log from this device's cursor, processes it, acknowledges; returns the texts received. */
    async sync(channel: string) {
        const texts: string[] = [];
        for (;;) {
            const page = await this.must('GET', `/api/channels/${channel}/log?after=${this.cursor.get(channel) ?? 0}`);
            if (!page.entries.length) return texts;
            for (const entry of page.entries) {
                // Never process what this device sent itself (its own commit is merged when the DS accepts it).
                if (entry.from.deviceId !== this.deviceId) {
                    const processed = this.client.call({ cmd: 'mlsReceive', group: channel, message: entry.message });
                    if (processed.plaintext !== undefined) texts.push(processed.plaintext);
                }
                this.cursor.set(channel, entry.seq);
            }
            await this.must('POST', `/api/channels/${channel}/cursor`, { seq: this.cursor.get(channel) });
        }
    }
    /** What an admin device signs to resolve a frozen channel. */
    resolution(channel: string, action: 'rollback' | 'dismiss', seq: number, digest: string) {
        return b64(sign(null, resolveBytes(channel, action, seq, digest), this.key));
    }
    events() {
        const url = new URL('/api/events', this.app.server.url); url.protocol = 'ws:';
        const socket = new WebSocket(url, { headers: { Origin: origin, Cookie: `session=${this.token}`, 'X-Real-IP': this.ip } } as any);
        const inbox: any[] = []; const waiters: { type: string; resolve: (value: any) => void }[] = [];
        socket.onmessage = event => {
            const message = JSON.parse(String(event.data));
            const at = waiters.findIndex(waiter => waiter.type === message.type);
            if (at >= 0) waiters.splice(at, 1)[0]!.resolve(message); else inbox.push(message);
        };
        const next = (type: string, ms = 2000) => {
            const at = inbox.findIndex(message => message.type === type);
            if (at >= 0) return Promise.resolve(inbox.splice(at, 1)[0]);
            return new Promise<any>((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error(`timeout waiting for ${type}`)), ms);
                waiters.push({ type, resolve: value => { clearTimeout(timer); resolve(value); } });
            });
        };
        const pending = (type: string) => inbox.filter(message => message.type === type);
        return { socket, next, pending, send: (value: unknown) => socket.send(JSON.stringify(value)), opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })), closed: new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve as any, { once: true })) };
    }
}

/** Creates a user, a listed device for the client, and a session bound to that device. */
export function enroll(app: { server: { url: URL }; accounts?: any }, user: User & { cookie?: string }, client: Client, platform = 'linux'): Device {
    const db = app.accounts.testing.db;
    const identity = client.call({ cmd: 'identity' });
    const deviceId = id();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    db.query('INSERT OR REPLACE INTO identity_keys (user_id, dh, sign, updated_at) VALUES (?, ?, ?, ?)').run(user.id, identity.dh, identity.sign, Date.now());
    db.query("INSERT INTO devices (id, user_id, platform, state, sig_key, created_at) VALUES (?, ?, ?, 'listed', ?, ?)").run(deviceId, user.id, platform, (publicKey.export({ format: 'jwk' }) as any).x, Date.now());
    db.query('INSERT OR REPLACE INTO device_lists (user_id, aik_sign, version, hash, list, signature, certs, updated_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?)').run(user.id, identity.sign, 'h', '{}', 's', '{}', Date.now());
    const token = app.accounts.testing.cookie(user.id).split('=')[1] as string;
    db.query('UPDATE sessions SET device_id = ? WHERE token_hash = ?').run(deviceId, createHash('sha256').update(token).digest('hex'));
    client.call({ cmd: 'mlsInitDevice', userId: user.id, deviceId, platform, issuedAt: Date.now() });
    return new Device(app, user, client, deviceId, token, privateKey);
}

/** Makes two accounts' clients pin each other (TOFU contacts) so each verifies the other's device certificates. */
export function pin(a: Device, b: Device) {
    a.client.call({ cmd: 'notePeer', contact: b.user.id, identity: b.client.call({ cmd: 'identity' }) });
    b.client.call({ cmd: 'notePeer', contact: a.user.id, identity: a.client.call({ cmd: 'identity' }) });
}

/** Every device pins every other account's identity, as contacts do. */
export function pinAll(devices: Device[]) {
    for (const a of devices) for (const b of devices) if (a.user.id !== b.user.id) a.client.call({ cmd: 'notePeer', contact: b.user.id, identity: b.client.call({ cmd: 'identity' }) });
}
