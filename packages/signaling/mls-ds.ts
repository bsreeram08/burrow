import type { Database } from 'bun:sqlite';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { requestLimiter } from './rate-limit';
import { verifyCore } from './core-manifest';

// The MLS delivery service's validator and KeyPackage store (docs/workspace-architecture.md §1, §2; FINDINGS §1).
// The validator is chatcore's own `ds` code (packages/signaling/ds-core, built by scripts/build-wasm.ts): the very
// functions every client runs before it merges a commit, so a commit sequenced here is a commit every member
// accepts. The server holds public group state only (no secrets) and cannot read any message.

export const ONE_TIME_MAX = 100, LOW_WATER = 20, KEY_PACKAGE_B64_MAX = 5462, MAX_LIFETIME = 91 * 86400;
const DEVICE_ID = /^[A-Za-z0-9_-]{22}$/, USER_ID = /^[A-Za-z0-9_-]{22}$/;
const MAX_CLAIM_USERS = 16;

type Write = { put: string; value: unknown } | { delete: string };
/** A refusal from the validator, with chatcore's disposition code (`invalid`, `malformed`, `unknown-group`, …). */
export class DsError extends Error { constructor(message: string, readonly code: string | null) { super(message); } }
/** Thrown by a caller's own checks after the validator already advanced: the whole transaction is discarded. */
export class Abort extends Error { constructor(readonly status: number, message: string, readonly extra: object = {}) { super(message); } }

type Glue = { initSync(options: { module: Uint8Array }): unknown; ChatCore: new (rows: string, existed: boolean) => { call(command: string): string } };
export type Call = (command: Record<string, unknown>) => any;

/**
 * The validator, persisted in `mls_ds_rows`. One long-lived core holds every group's public state; each call's
 * writes are stored in the same SQLite transaction as the server's own rows for that request. If a request fails
 * after the core advanced (a failed check of ours, a failed write), the core is reloaded from the database, so
 * memory never runs ahead of disk. Refusals by the validator itself leave it untouched.
 */
export function createDsCore(options: { db: Database; dir: string }) {
    const { db } = options;
    const files = verifyCore(options.dir); // Fail closed at startup: the same verification as the browser core.
    const manifest = JSON.parse(Buffer.from(files.get('manifest.json')!.bytes).toString('utf8')) as { js: string; wasm: string };
    let core: InstanceType<Glue['ChatCore']> | undefined;
    function open() {
        if (!core) {
            const glue = createRequire(import.meta.url)(join(options.dir, manifest.js)) as Glue;
            glue.initSync({ module: new Uint8Array(files.get(manifest.wasm)!.bytes) });
            const rows: Record<string, unknown> = {};
            for (const row of db.query<{ k: string; v: string }, []>('SELECT k, v FROM mls_ds_rows').all()) rows[row.k] = JSON.parse(row.v);
            core = new glue.ChatCore(JSON.stringify(rows), false);
        }
        return core;
    }
    const reload = () => { core = undefined; };

    /** Runs `work` and the validator's writes in one transaction. `call` throws DsError on a refusal. */
    function transaction<T>(work: (call: Call) => T): T {
        const pending: Write[] = [];
        let dirty = false;
        const call: Call = command => {
            const out = JSON.parse(open().call(JSON.stringify(command))) as { ok?: unknown; error?: string; code?: string | null; writes: Write[] };
            if (out.error !== undefined) {
                // A refusal rolled its own work back; writes alongside one would be an engine bug: don't trust the core.
                if (out.writes.length) dirty = true;
                throw new DsError(out.error, out.code ?? null);
            }
            if (out.writes.length) { pending.push(...out.writes); dirty = true; }
            return out.ok;
        };
        try {
            return db.transaction(() => {
                const result = work(call);
                for (const write of pending) {
                    if ('put' in write) db.query('INSERT OR REPLACE INTO mls_ds_rows (k, v) VALUES (?, ?)').run(write.put, JSON.stringify(write.value));
                    else db.query('DELETE FROM mls_ds_rows WHERE k = ?').run(write.delete);
                }
                return result;
            })();
        } catch (error) {
            // A refusal that changed nothing needs no reload; anything else may have left the core ahead of the database.
            if (dirty || !(error instanceof DsError)) reload();
            throw error;
        }
    }
    return { transaction, reload };
}
export type DsCore = ReturnType<typeof createDsCore>;

type Deps = {
    db: Database; now: () => number; ds: DsCore;
    eligible(userId: string, deviceId: string | null): boolean;
    sessionDevice(session: string): string | null;
    aikOf(userId: string): string | null;
    identityChange?(userId: string): { aik: string; event: string } | null;
    mutual(a: string, b: string): boolean;
    notify(userId: string, event: object): void;
};
type Caller = { id: string; session: string };
const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });

/** Pins the account keys the registry holds for `userIds`, so the validator can check certificates against them. */
export function pinAccounts(deps: Pick<Deps, 'aikOf'> & { successions?(userId: string): object[]; identityChange?(userId: string): { aik: string; event: string } | null }, call: Call, userIds: Iterable<string>) {
    for (const userId of new Set(userIds)) {
        const aik = deps.aikOf(userId);
        if (!aik) throw new Abort(409, 'A member has not published an identity key.');
        try { call({ cmd: 'dsPin', userId, aik }); }
        catch (error) {
            if (!(error instanceof DsError)) throw error;
            // The registry's key moved. Follow the signed succession records from the pinned key if they lead to it
            // (older devices stay valid for what they were certified before). Otherwise the key is replaced only if an
            // authenticated identity change to exactly this key was recorded (PUT /api/keys; the user recovered under a
            // new key and their old devices are stale: removable, unable to act). Anything else keeps the 409.
            const records = deps.successions?.(userId) ?? [];
            let followed = false;
            if (records.length) { try { call({ cmd: 'dsSucceed', userId, records }); followed = true; } catch (inner) { if (!(inner instanceof DsError)) throw inner; } }
            try { call({ cmd: 'dsPin', userId, aik }); }
            catch (inner) {
                if (!(inner instanceof DsError)) throw inner;
                const change = deps.identityChange?.(userId);
                if (!change || change.aik !== aik) throw new Abort(409, 'A member\'s identity key does not match the one this channel was built on.', { code: 'identity', userId });
                call({ cmd: 'dsRepin', userId, aik });
            }
            void followed;
        }
    }
}

/** KeyPackage upload, claim and top-up signal. */
export function createKeyPackages(deps: Deps) {
    const { db, now } = deps;
    const allowUpload = requestLimiter({ perSource: 5, global: 200 }), allowClaim = requestLimiter({ perSource: 10, global: 500 }), allowClaimPair = requestLimiter({ perSource: 5, global: 500 }), allowCount = requestLimiter({ perSource: 10, global: 500 });
    const oneTime = (deviceId: string) => db.query<{ count: number }, [string, number]>('SELECT COUNT(*) AS count FROM mls_key_packages WHERE device_id = ? AND last_resort = 0 AND expires_at > ?').get(deviceId, Math.floor(now() / 1000))!.count;
    const stored = (deviceId: string) => ({ oneTime: oneTime(deviceId), lastResort: Boolean(db.query('SELECT 1 FROM mls_key_packages WHERE device_id = ? AND last_resort = 1 AND expires_at > ?').get(deviceId, Math.floor(now() / 1000))) });

    /** The caller's session device, if it may hold MLS leaves; otherwise the refusal. */
    function device(user: Caller): [string, null] | [null, Response] {
        const id = deps.sessionDevice(user.session);
        if (!id) return [null, json({ error: 'Announce this device first.' }, 409)];
        if (!deps.eligible(user.id, id)) return [null, json({ error: 'This device is not in your signed device list.' }, 403)];
        return [id, null];
    }

    async function upload(request: Request, user: Caller, readBody: () => Promise<Record<string, any> | null>): Promise<Response> {
        const [id, refusal] = device(user);
        if (refusal) return refusal;
        if (!allowUpload(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readBody();
        const list = body?.keyPackages ?? [], lastResort = body?.lastResort;
        const text = (value: unknown) => typeof value === 'string' && value.length > 0 && value.length <= KEY_PACKAGE_B64_MAX && /^[A-Za-z0-9_-]+$/.test(value);
        if (!Array.isArray(list) || list.length > ONE_TIME_MAX || !list.every(text) || (lastResort !== undefined && !text(lastResort)) || (!list.length && lastResort === undefined)) return json({ error: 'Invalid KeyPackages' }, 400);
        if (new Set(list).size !== list.length) return json({ error: 'Duplicate KeyPackages' }, 400);
        const aik = deps.aikOf(user.id);
        if (!aik) return json({ error: 'Publish encryption keys first.' }, 409);
        try {
            const have = oneTime(id!);
            if (have + list.length > ONE_TIME_MAX) return json({ error: `At most ${ONE_TIME_MAX} one-time KeyPackages per device.`, oneTime: have }, 400);
            deps.ds.transaction(call => {
                pinAccounts(deps, call, [user.id]);
                const check = (kp: string, last: boolean) => {
                    const info = call({ cmd: 'dsKeyPackage', keyPackage: kp }) as { userId: string; deviceId: string; aikSign: string; lastResort: boolean; notAfter: number; notBefore: number };
                    // Bound to this very device and to the account key its signed list chains to.
                    if (info.userId !== user.id || info.deviceId !== id || info.aikSign !== aik) throw new Abort(403, 'A KeyPackage must be certified for this device by your account key.');
                    if (info.lastResort !== last) throw new Abort(400, last ? 'That is not a last-resort KeyPackage.' : 'Last-resort KeyPackages go in lastResort.');
                    const seconds = Math.floor(now() / 1000);
                    if (info.notAfter <= seconds || info.notAfter - seconds > MAX_LIFETIME) throw new Abort(400, 'KeyPackages must expire within 90 days.');
                    return info;
                };
                for (const kp of list as string[]) {
                    const info = check(kp, false);
                    db.query('INSERT INTO mls_key_packages (id, device_id, user_id, kp, last_resort, created_at, expires_at) VALUES (?, ?, ?, ?, 0, ?, ?)').run(randomBytes(16).toString('base64url'), id, user.id, kp, now(), info.notAfter);
                }
                if (lastResort !== undefined) {
                    const info = check(lastResort, true);
                    db.query('DELETE FROM mls_key_packages WHERE device_id = ? AND last_resort = 1').run(id);
                    db.query('INSERT INTO mls_key_packages (id, device_id, user_id, kp, last_resort, created_at, expires_at) VALUES (?, ?, ?, ?, 1, ?, ?)').run(randomBytes(16).toString('base64url'), id, user.id, lastResort, now(), info.notAfter);
                }
            });
        } catch (error) {
            if (error instanceof Abort) return json({ error: error.message }, error.status);
            if (error instanceof DsError) return json({ error: error.message }, 400);
            if (String((error as Error)?.message).includes('UNIQUE')) return json({ error: 'That KeyPackage is already stored.' }, 409);
            throw error;
        }
        const now_ = stored(id!);
        return json({ ...now_, low: now_.oneTime < LOW_WATER }, 201);
    }

    function count(user: Caller): Response {
        const [id, refusal] = device(user);
        if (refusal) return refusal;
        if (!allowCount(user.id)) return json({ error: 'Rate limited' }, 429);
        const mine = stored(id!);
        return json({ ...mine, low: mine.oneTime < LOW_WATER, max: ONE_TIME_MAX });
    }

    /** One KeyPackage per listed device of each requested user: a one-time one if any are left, else the last-resort one. */
    async function claim(request: Request, user: Caller, readBody: () => Promise<Record<string, any> | null>): Promise<Response> {
        const [id, refusal] = device(user);
        if (refusal) return refusal;
        if (!allowClaim(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readBody();
        const users = body?.users;
        if (!Array.isArray(users) || users.length < 1 || users.length > MAX_CLAIM_USERS || !users.every(value => typeof value === 'string' && USER_ID.test(value)) || new Set(users).size !== users.length) return json({ error: 'Name 1–16 distinct users.' }, 400);
        // Yourself and mutual contacts only; nothing about anyone else, not even that they exist.
        if (!users.every(target => target === user.id || deps.mutual(user.id, target))) return json({ error: 'You can only reach accepted contacts.' }, 403);
        for (const target of users) if (target !== user.id && !allowClaimPair(`${user.id}>${target}`)) return json({ error: 'Rate limited' }, 429);
        const seconds = Math.floor(now() / 1000);
        const out: { userId: string; deviceId: string; keyPackage: string; lastResort: boolean }[] = [], missing: { userId: string; deviceId: string }[] = [], low: { userId: string; deviceId: string; remaining: number }[] = [];
        db.transaction(() => {
            for (const target of users as string[]) {
                const devices = db.query<{ id: string }, [string]>("SELECT id FROM devices WHERE user_id = ? AND state = 'listed' ORDER BY created_at, id").all(target).filter(row => deps.eligible(target, row.id));
                for (const { id: deviceId } of devices) {
                    // The claiming device does not need a package for itself.
                    if (deviceId === id) continue;
                    const row = db.query<{ id: string; kp: string }, [string, number]>('SELECT id, kp FROM mls_key_packages WHERE device_id = ? AND last_resort = 0 AND expires_at > ? ORDER BY created_at, id LIMIT 1').get(deviceId, seconds)
                        ?? db.query<{ id: string; kp: string }, [string, number]>('SELECT id, kp FROM mls_key_packages WHERE device_id = ? AND last_resort = 1 AND expires_at > ?').get(deviceId, seconds);
                    if (!row) { missing.push({ userId: target, deviceId }); continue; }
                    const last = Boolean(db.query('SELECT 1 FROM mls_key_packages WHERE id = ? AND last_resort = 1').get(row.id));
                    // One-time packages are spent; the last-resort one stays for the next claimant.
                    if (!last) db.query('DELETE FROM mls_key_packages WHERE id = ?').run(row.id);
                    out.push({ userId: target, deviceId, keyPackage: row.kp, lastResort: last });
                    const remaining = oneTime(deviceId);
                    if (!last && remaining < LOW_WATER) low.push({ userId: target, deviceId, remaining });
                }
            }
        })();
        for (const item of low) deps.notify(item.userId, { type: 'keypackages', deviceId: item.deviceId, remaining: item.remaining });
        return json({ keyPackages: out, missing });
    }

    function sweep() {
        db.query('DELETE FROM mls_key_packages WHERE expires_at <= ?').run(Math.floor(now() / 1000));
        db.query("DELETE FROM mls_key_packages WHERE device_id IN (SELECT id FROM devices WHERE state != 'listed')").run();
    }
    return { upload, count, claim, sweep };
}
export type KeyPackages = ReturnType<typeof createKeyPackages>;
export const isDeviceId = (value: unknown): value is string => typeof value === 'string' && DEVICE_ID.test(value);
