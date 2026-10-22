import type { Database } from 'bun:sqlite';
import { createHash, timingSafeEqual } from 'node:crypto';
import { ed25519Verify, Format, ROTATION_WINDOW } from './devices';

// The account key on every device (docs/m6-account-key.md): the end-to-end encrypted backup of it (§3.5) and the rekey
// relay a device without the key uses to get it from one that has it (§5). The server stores and relays opaque boxes. It
// never has an unlock key: only hashes of them (and of the proofs of knowing the passphrase or the recovery key), the
// account key's signature over those, and sizes it can check without any secret. A change to the backup, a delete and a
// rotation need a proof, so a stolen but unlocked device cannot take the account over without the passphrase.
const KEY = /^[A-Za-z0-9_-]{43}$/, DEVICE_ID = /^[A-Za-z0-9_-]{22}$/, B64 = /^[A-Za-z0-9_-]+$/;
const HOUR = 60 * 60 * 1000, DAY = 24 * HOUR, READS_PER_HOUR = 10, READS_PER_DAY = 30, READS_PER_SESSION_HOUR = 5, RETAIN_READS = 30 * DAY;
/** The Argon2id cost a record may name (a client never derives at a cost outside it). */
const KDF_RANGE = { m: [65536, 1048576], t: [3, 10], p: [1, 4] } as const;
const RECORD_KEYS = ['v', 'userId', 'aikSign', 'epoch', 'kdf', 'passHash', 'recoveryHash', 'pass', 'recovery', 'passProofHash', 'recoveryProofHash', 'signature'];
const PROOF_KEYS = ['proof', 'passProof', 'recoveryProof'];
const MAX_REKEY_BOX = 6000;
/** A reset of the account key by someone without the passphrase waits this long for a listed device to cancel it; three requests per 30 days. */
const RESET_DELAY = 7 * DAY, RESETS_PER_30_DAYS = 3;

type Caller = { id: string; session: string; client: string };
type Deps = {
    db: Database; now: () => number;
    notify(userId: string, event: object): void;
    sessionDevice(session: string): string | null;
    eligible(userId: string, deviceId: string | null): boolean;
    aikOf(userId: string): string | null;
};
type Stored = { epoch: number; kdf: { alg: string; salt: string; m: number; t: number; p: number }; passHash: string; recoveryHash: string; passProofHash: string; recoveryProofHash: string; [key: string]: unknown };

const text16 = (text: string) => { const bytes = Buffer.from(text); const length = Buffer.alloc(2); length.writeUInt16BE(bytes.length); return Buffer.concat([length, bytes]); };
const bytes8 = (bytes: Buffer) => Buffer.concat([Buffer.from([bytes.length]), bytes]);
const u32 = (value: number) => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };
const raw = (text: string) => Buffer.from(text, 'base64url');
const canonical = (text: unknown, length: number): text is string => typeof text === 'string' && B64.test(text) && raw(text).length === length && raw(text).toString('base64url') === text;
const sha = (text: string) => createHash('sha256').update(raw(text)).digest('base64url');
/** Equality of two hashes in constant time (a proof is compared by its SHA-256 against what is stored). */
const same = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const inRange = (value: unknown, [low, high]: readonly [number, number]) => Number.isSafeInteger(value) && (value as number) >= low && (value as number) <= high;

/** What the account key signs over a backup's public record (docs/m6-account-key.md §3.3). */
export function backupKeysBytes(record: { userId: string; aikSign: string; epoch: number; kdf: { salt: string; m: number; t: number; p: number }; passHash: string; recoveryHash: string; passProofHash: string; recoveryProofHash: string }) {
    return Buffer.concat([text16('webrtc-bun-backup-keys-v2'), text16(record.userId), bytes8(raw(record.aikSign)), u32(record.epoch), bytes8(raw(record.kdf.salt)), u32(record.kdf.m), u32(record.kdf.t), u32(record.kdf.p),
        bytes8(raw(record.passHash)), bytes8(raw(record.recoveryHash)), bytes8(raw(record.passProofHash)), bytes8(raw(record.recoveryProofHash))]);
}
/** What a companion's MLS leaf key signs to ask for the account key, and what the answer is bound to (§5). */
export function rekeyBytes(userId: string, deviceId: string, platform: string, eph: string, leafSigKey: string, aikSign: string) {
    return Buffer.concat([text16('webrtc-bun-rekey-v1'), text16(userId), text16(deviceId), text16(platform), bytes8(raw(eph)), bytes8(raw(leafSigKey)), bytes8(raw(aikSign))]);
}

const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
async function readJson(request: Request): Promise<Record<string, any> | null> {
    try { const text = await request.text(); if (text.length > 65536) return null; const value = JSON.parse(text); return value && typeof value === 'object' && !Array.isArray(value) ? value : null; } catch { return null; }
}
const exactly = (value: unknown, keys: string[]): value is Record<string, any> => Boolean(value) && typeof value === 'object' && !Array.isArray(value) && Object.keys(value as object).length === keys.length && keys.every(key => Object.hasOwn(value as object, key));
/** An object whose keys are all among `allowed` and include all of `required`. */
const keysWithin = (value: unknown, required: string[], optional: string[]): value is Record<string, any> => Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && required.every(key => Object.hasOwn(value as object, key)) && Object.keys(value as object).every(key => required.includes(key) || optional.includes(key));

export function createAccountKey(deps: Deps) {
    const { db, now } = deps;
    const listed = (user: Caller) => { const device = deps.sessionDevice(user.session); return device && deps.eligible(user.id, device) ? device : null; };
    const touched = new Map<string, number[]>();
    const stored = (userId: string): (Stored & { updatedAt: number }) | null => {
        const row = db.query<{ record: string; updated_at: number }, [string]>('SELECT record, updated_at FROM account_backups WHERE user_id = ?').get(userId);
        return row ? { ...JSON.parse(row.record), updatedAt: row.updated_at } : null;
    };

    // ---------- Rate limit: every try to read a backup and every wrong proof counts ----------

    const tries = (userId: string, since: number, session?: string) => session
        ? db.query<{ n: number }, [string, string, number]>('SELECT COUNT(*) AS n FROM backup_reads WHERE user_id = ? AND session = ? AND at > ?').get(userId, session, since)!.n
        : db.query<{ n: number }, [string, number]>('SELECT COUNT(*) AS n FROM backup_reads WHERE user_id = ? AND at > ?').get(userId, since)!.n;
    const limited = (userId: string) => tries(userId, now() - HOUR) >= READS_PER_HOUR || tries(userId, now() - DAY) >= READS_PER_DAY;
    const record = (user: Caller, found: boolean) => db.transaction(() => {
        db.query('INSERT INTO backup_reads (user_id, session, device_id, at, found) VALUES (?, ?, ?, ?, ?)').run(user.id, user.session, deps.sessionDevice(user.session), now(), found ? 1 : 0);
        db.query('DELETE FROM backup_reads WHERE at < ?').run(now() - RETAIN_READS);
    })();

    /** Whether `proof` is the passphrase's or the recovery key's for the stored backup. A wrong or missing one is counted like a failed restore. */
    function proven(user: Caller, backup: Stored, proof: unknown): boolean {
        let fine = false;
        if (canonical(proof, 32)) {
            const hash = sha(proof);
            const [pass, recovery] = [same(hash, backup.passProofHash), same(hash, backup.recoveryProofHash)]; // both compared, whichever matches
            fine = pass || recovery;
        }
        if (!fine) record(user, false);
        return fine;
    }

    // ---------- Backup (§3.5) ----------

    /** The reason a record is refused, or null. Mirrors what every client checks before it trusts one. */
    function refuse(user: Caller, body: Record<string, any>, previous: Stored | null): string | null {
        const aik = deps.aikOf(user.id);
        if (!aik || body.aikSign !== aik) return 'The backup is not for this account\'s identity key.';
        if (body.v !== 1 || body.userId !== user.id || !Number.isSafeInteger(body.epoch) || body.epoch < 1 || body.epoch > 2 ** 32 - 1) return 'Invalid backup';
        const { kdf } = body;
        if (!exactly(kdf, ['alg', 'salt', 'm', 't', 'p']) || kdf.alg !== 'argon2id' || !canonical(kdf.salt, 16) || !inRange(kdf.m, KDF_RANGE.m) || !inRange(kdf.t, KDF_RANGE.t) || !inRange(kdf.p, KDF_RANGE.p)) return 'Invalid backup';
        for (const name of ['aikSign', 'passHash', 'recoveryHash', 'passProofHash', 'recoveryProofHash']) if (!canonical(body[name], 32)) return 'Invalid backup';
        // Each box: ephemeral key (32) + nonce (12) + the account key (95 + the user id) + two bytes8 keys (66) + the GCM tag (16).
        const boxLength = 32 + 12 + 95 + user.id.length + 66 + 16;
        if (!canonical(body.pass, boxLength) || !canonical(body.recovery, boxLength) || !canonical(body.signature, 64)) return 'Invalid backup';
        if (!ed25519Verify(aik, backupKeysBytes(body as any), body.signature)) return 'The backup\'s unlock hashes are not signed by this account\'s identity key.';
        for (const name of PROOF_KEYS) if (Object.hasOwn(body, name) && !canonical(body[name], 32)) return 'Invalid proof';
        // The new proofs are what the record's proof hashes name; a side without one must be exactly what is stored.
        for (const [proof, hash, key] of [['passProof', 'passProofHash', 'passHash'], ['recoveryProof', 'recoveryProofHash', 'recoveryHash']] as const) {
            if (Object.hasOwn(body, proof)) { if (sha(body[proof]) !== body[hash]) return 'Invalid proof'; }
            else if (!previous || body[hash] !== previous[hash] || body[key] !== previous[key]) return 'A new unlock key needs its proof.';
        }
        return null;
    }

    async function put(request: Request, user: Caller) {
        if (!listed(user)) return json({ error: 'Only a listed device of the account can set up the backup.' }, 403);
        const body = await readJson(request);
        if (!keysWithin(body, RECORD_KEYS, PROOF_KEYS)) return json({ error: 'Invalid backup' }, 400);
        const previous = stored(user.id);
        const reason = refuse(user, body, previous);
        if (reason) return json({ error: reason }, 400);
        if (previous) {
            if (body.epoch !== previous.epoch + 1) return json({ error: 'The backup changed meanwhile.', epoch: previous.epoch }, 409);
            if (limited(user.id)) return json({ error: 'Too many tries. Try again later.' }, 429);
            // A change needs the passphrase or the recovery key, except the one re-seal a rotation makes: same unlock keys, same proofs, same cost.
            const unchanged = ['passHash', 'recoveryHash', 'passProofHash', 'recoveryProofHash'].every(name => body[name] === previous[name]) && JSON.stringify(body.kdf) === JSON.stringify(previous.kdf);
            const allowance = unchanged && body.aikSign === allowed(user.id, 'reseal');
            if (!allowance && !proven(user, previous, body.proof)) return json({ error: 'The passphrase or recovery key is needed.' }, 403);
            if (allowance && body.proof !== undefined && !proven(user, previous, body.proof)) return json({ error: 'The passphrase or recovery key is needed.' }, 403);
            if (allowance) spend(user.id, 'reseal');
        } else if (body.epoch !== 1 || !Object.hasOwn(body, 'passProof') || !Object.hasOwn(body, 'recoveryProof')) return json({ error: 'A first backup is epoch 1 with both proofs.' }, 400);
        const stripped = Object.fromEntries(Object.entries(body).filter(([name]) => !PROOF_KEYS.includes(name)));
        const updatedAt = now();
        db.query('INSERT OR REPLACE INTO account_backups (user_id, record, updated_at) VALUES (?, ?, ?)').run(user.id, JSON.stringify(stripped), updatedAt);
        deps.notify(user.id, { type: 'backup', id: user.id, epoch: body.epoch });
        return json({ updatedAt });
    }

    /** Any session of the account, a pending device's too (that is the restore). Limited per account and per session, every try counted. */
    function get(user: Caller) {
        if (limited(user.id) || tries(user.id, now() - HOUR, user.session) >= READS_PER_SESSION_HOUR) return json({ error: 'Too many tries to open the backup. Try again later.' }, 429);
        const backup = stored(user.id);
        record(user, Boolean(backup));
        if (!backup) return json({ error: 'No backup.' }, 404);
        deps.notify(user.id, { type: 'backup', id: user.id, read: true, deviceId: deps.sessionDevice(user.session) });
        return json(backup);
    }

    async function del(request: Request, user: Caller) {
        if (!listed(user)) return json({ error: 'Only a listed device of the account can turn the backup off.' }, 403);
        const backup = stored(user.id);
        if (backup) {
            if (limited(user.id)) return json({ error: 'Too many tries. Try again later.' }, 429);
            const body = await readJson(request);
            if (!proven(user, backup, body?.proof)) return json({ error: 'The passphrase or recovery key is needed.' }, 403);
            db.query('DELETE FROM account_backups WHERE user_id = ?').run(user.id);
            deps.notify(user.id, { type: 'backup', id: user.id });
        }
        return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
    }

    // ---------- Rotation (docs/m6-account-key.md §6.2) ----------

    /** Who may replace the account key: a listed device and, when the account has a backup, a proof. Null when allowed. */
    function authorizeSuccession(user: Caller, body: Record<string, any> | null): Response | null {
        if (!listed(user)) return json({ error: 'Only a listed device of the account can change the account key.' }, 403);
        const backup = stored(user.id);
        if (!backup) return null;
        if (limited(user.id)) return json({ error: 'Too many tries. Try again later.' }, 429);
        return proven(user, backup, body?.proof) ? null : json({ error: 'The passphrase or recovery key is needed.' }, 403);
    }
    /** The identity key a succession named, while one of its proof-free steps is still open (an hour at most); else null. */
    function allowed(userId: string, step: 'list' | 'reseal'): string | null {
        const row = db.query<{ new_sign: string }, [string, number]>(`SELECT new_sign FROM rotation_allowance WHERE user_id = ? AND ${step} = 1 AND since > ?`).get(userId, now() - ROTATION_WINDOW);
        return row?.new_sign ?? null;
    }
    /** Uses up one of the proof-free steps a succession allows; the row goes when both are used. */
    function spend(userId: string, step: 'list' | 'reseal') {
        db.query(`UPDATE rotation_allowance SET ${step} = 0 WHERE user_id = ?`).run(userId);
        db.query('DELETE FROM rotation_allowance WHERE user_id = ? AND list = 0 AND reseal = 0').run(userId);
    }
    /**
     * Who may remove devices from an account that has a backup (docs/m6-account-key.md §6.3): a session bound to a device that is already
     * listed and the passphrase's or recovery key's proof. The first list under a new key that follows an accepted succession is the
     * exception, once. An account without a backup has no proof to ask for. Null when allowed.
     */
    function authorizeRemoval(user: Caller, body: Record<string, any> | null, firstUnderKey = false): [number, object] | null {
        const backup = stored(user.id);
        if (!backup) return null;
        // The first list under the new key may drop the removed devices, once, if it is under the key the succession named.
        if (firstUnderKey && deps.aikOf(user.id) === allowed(user.id, 'list')) { spend(user.id, 'list'); return null; }
        if (!listed(user)) return [403, { error: 'Only a listed device of the account can remove devices.' }];
        if (limited(user.id)) return [429, { error: 'Too many tries. Try again later.' }];
        return proven(user, backup, body?.proof) ? null : [403, { error: 'The passphrase or recovery key is needed.' }];
    }
    // ---------- Delayed reset (docs/m6-account-key.md §6.4) ----------

    type Reset = { requestedBy: { deviceId: string | null; platform: string }; at: number; executeAfter: number };
    const resetRow = (userId: string) => db.query<{ session: string; device_id: string | null; platform: string; requested_at: number; execute_after: number }, [string]>('SELECT * FROM key_resets WHERE user_id = ?').get(userId);
    /** The open reset request, for the owner's own device view and the frames. */
    function resetStatus(userId: string): Reset | null {
        const row = resetRow(userId);
        return row ? { requestedBy: { deviceId: row.device_id, platform: row.platform }, at: row.requested_at, executeAfter: row.execute_after } : null;
    }
    /** Any session of the account (a pending passkey session too) asks for a reset; listed devices can cancel it for a week. */
    function requestReset(user: Caller) {
        if (!stored(user.id)) return json({ error: 'This account has no backup: start over directly.' }, 409);
        const open = resetStatus(user.id);
        if (open) return json({ error: 'A reset is already waiting.', reset: open }, 409);
        if (db.query<{ n: number }, [string, number]>('SELECT COUNT(*) AS n FROM key_reset_log WHERE user_id = ? AND at > ?').get(user.id, now() - 30 * DAY)!.n >= RESETS_PER_30_DAYS) return json({ error: 'Too many reset requests. Try again later.' }, 429);
        const at = now(), executeAfter = at + RESET_DELAY;
        db.transaction(() => {
            db.query('INSERT INTO key_resets (user_id, session, device_id, platform, requested_at, execute_after) VALUES (?, ?, ?, ?, ?, ?)').run(user.id, user.session, deps.sessionDevice(user.session), user.client, at, executeAfter);
            db.query('INSERT INTO key_reset_log (user_id, at) VALUES (?, ?)').run(user.id, at);
            db.query('DELETE FROM key_reset_log WHERE at < ?').run(at - 30 * DAY);
        })();
        const reset = resetStatus(user.id)!;
        deps.notify(user.id, { type: 'reset', id: user.id, ...reset });
        return json({ reset }, 201);
    }
    /** Any listed device cancels it; no proof (cancelling can only keep the account as it is). */
    function cancelReset(user: Caller) {
        if (!listed(user)) return json({ error: 'Only a listed device of the account can cancel a reset.' }, 403);
        if (db.query('DELETE FROM key_resets WHERE user_id = ? RETURNING 1').get(user.id)) deps.notify(user.id, { type: 'reset', id: user.id, cancelled: true });
        return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
    }
    /**
     * `PUT /api/keys` with a new identity on an account that has a backup: allowed when a succession the server took ends in that
     * identity, or with the passphrase's proof (a fresh start by someone who knows it), or from the session that asked for a
     * reset once its week is up. The last two replace the account key for good, so the backup that holds the old one goes
     * (`wipe`). An account without a backup is not asked.
     */
    function authorizeIdentityChange(user: Caller, body: Record<string, any> | null, newSign: string, currentSign: string): { refused?: Response; wipe?: boolean; succession?: boolean } {
        // The newest record must hand over from the identity published now to this one, and each record authorizes one change: after a
        // later change by proof or reset, the old keys of a revoked device cannot be put back with it.
        const last = db.query<{ old_sign: string; new_sign: string; used: number; created_at: number }, [string]>('SELECT old_sign, new_sign, used, created_at FROM identity_succession WHERE user_id = ? ORDER BY seq DESC LIMIT 1').get(user.id);
        if (last && !last.used && last.old_sign === currentSign && last.new_sign === newSign) return { succession: true }; // no age limit: it authorizes its own change until a later record supersedes it
        const backup = stored(user.id);
        if (!backup) return {};
        if (body?.proof !== undefined) {
            if (limited(user.id)) return { refused: json({ error: 'Too many tries. Try again later.' }, 429) };
            return proven(user, backup, body.proof) ? { wipe: true } : { refused: json({ error: 'The passphrase or recovery key is needed.' }, 403) };
        }
        const reset = resetRow(user.id);
        if (reset && reset.session === user.session && reset.execute_after <= now()) return { wipe: true };
        return { refused: json({ error: 'The account key can only be replaced with the passphrase, after a succession, or after a reset has waited.', reset: resetStatus(user.id) }, 403) };
    }
    /** The identity changed: an open reset is spent, and a replaced account key takes the backup that held the old one with it. */
    function identityChanged(userId: string, wipe: boolean, succession = false, newSign = '') {
        db.query('DELETE FROM key_resets WHERE user_id = ?').run(userId);
        if (succession) {
            db.query('UPDATE identity_succession SET used = 1 WHERE user_id = ? AND seq = (SELECT MAX(seq) FROM identity_succession WHERE user_id = ?)').run(userId, userId);
            // The rotation is applied: the first list under the new key and the backup re-seal that follow are free for an hour from now.
            if (!wipe && stored(userId)) db.query('INSERT OR REPLACE INTO rotation_allowance (user_id, new_sign, since, list, reseal) VALUES (?, ?, ?, 1, 1)').run(userId, newSign, now());
        }
        if (wipe) {
            db.query('DELETE FROM account_backups WHERE user_id = ?').run(userId);
            db.query('DELETE FROM rotation_allowance WHERE user_id = ?').run(userId);
            deps.notify(userId, { type: 'backup', id: userId });
        }
    }
    /**
     * The owner's view of their newest succession, so a device that prepared a rotation and restarted can tell whether to resume it:
     * `open` (it still authorizes its identity change), `applied` (the identity it names is published) or `superseded` (a later
     * record replaced it, or the identity moved on: it authorizes nothing). Null when there is none.
     */
    function rotationStatus(userId: string, publishedSign: string | null): { oldSign: string; newSign: string; at: number; state: 'open' | 'applied' | 'superseded' } | null {
        const last = db.query<{ old_sign: string; new_sign: string; at: number; used: number }, [string]>('SELECT old_sign, new_sign, at, used FROM identity_succession WHERE user_id = ? ORDER BY seq DESC LIMIT 1').get(userId);
        if (!last) return null;
        const state = last.used === 2 ? 'superseded' : last.used === 1 ? 'applied' : last.old_sign === publishedSign ? 'open' : 'superseded';
        return { oldSign: last.old_sign, newSign: last.new_sign, at: last.at, state };
    }

    // ---------- Rekey (§5) ----------

    /** A device that does not hold the account key asks for it. The signature is the leaf key's over the request, naming the account key it pins. */
    async function rekeyAsk(request: Request, user: Caller) {
        const device = listed(user);
        if (!device) return json({ error: 'Only a listed device of the account can ask.' }, 403);
        const body = await readJson(request);
        if (!exactly(body, ['platform', 'eph', 'leafSigKey', 'signature']) || !Format.PLATFORMS.includes(body.platform) || !canonical(body.eph, 32) || !canonical(body.leafSigKey, 32) || !canonical(body.signature, 64)) return json({ error: 'Invalid request' }, 400);
        const aik = deps.aikOf(user.id);
        // The device pins the published key (it follows a rotation before it asks), so the bytes name the key published now.
        if (!aik || !ed25519Verify(body.leafSigKey, rekeyBytes(user.id, device, body.platform, body.eph, body.leafSigKey, aik), body.signature)) return json({ error: 'The request is not signed by that device\'s leaf key for this account key.' }, 403);
        db.query('INSERT OR REPLACE INTO rekey_requests (device_id, user_id, platform, eph, leaf_sig_key, signature, box, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)').run(device, user.id, body.platform, body.eph, body.leafSigKey, body.signature, now());
        deps.notify(user.id, { type: 'rekey', id: user.id, deviceId: device });
        return json({ status: 'requested' }, 201);
    }

    /** A listed device lists the requests that still wait. Nothing here is proof of anything: the full device checks each itself. */
    function rekeyPending(user: Caller) {
        if (!listed(user)) return json({ error: 'Only a listed device of the account can answer.' }, 403);
        const rows = db.query<{ device_id: string; platform: string; eph: string; leaf_sig_key: string; signature: string }, [string]>('SELECT device_id, platform, eph, leaf_sig_key, signature FROM rekey_requests WHERE user_id = ? AND box IS NULL ORDER BY created_at').all(user.id);
        return json({ requests: rows.filter(row => deps.eligible(user.id, row.device_id)).map(row => ({ deviceId: row.device_id, platform: row.platform, eph: row.eph, leafSigKey: row.leaf_sig_key, signature: row.signature })) });
    }

    async function rekeyAnswer(request: Request, user: Caller, deviceId: string) {
        if (!listed(user)) return json({ error: 'Only a listed device of the account can answer.' }, 403);
        const found = DEVICE_ID.test(deviceId) ? db.query('SELECT 1 FROM rekey_requests WHERE device_id = ? AND user_id = ?').get(deviceId, user.id) : null;
        if (!found) return json({ error: 'No request from that device.' }, 404);
        const body = await readJson(request);
        if (!exactly(body, ['box']) || typeof body.box !== 'string' || !B64.test(body.box) || body.box.length > MAX_REKEY_BOX || raw(body.box).length < 32 + 12 + 16 || raw(body.box).toString('base64url') !== body.box) return json({ error: 'Invalid box' }, 400);
        // One answer per request: a later one cannot replace it (a device asks again to start over).
        if (!db.query('UPDATE rekey_requests SET box = ? WHERE device_id = ? AND box IS NULL').run(body.box, deviceId).changes) return json({ error: 'That request was answered already.' }, 409);
        deps.notify(user.id, { type: 'rekey', id: user.id, deviceId, answered: true });
        return json({ status: 'answered' }, 201);
    }

    function rekeyMine(user: Caller) {
        const device = deps.sessionDevice(user.session);
        const row = device ? db.query<{ box: string | null }, [string]>('SELECT box FROM rekey_requests WHERE device_id = ?').get(device) : null;
        if (!row) return json({ error: 'No request.' }, 404);
        return json({ box: row.box });
    }

    function rekeyDone(user: Caller) {
        const device = deps.sessionDevice(user.session);
        if (device) db.query('DELETE FROM rekey_requests WHERE device_id = ? AND user_id = ?').run(device, user.id);
        return json({ status: 'done' });
    }

    /** Routes `/api/backup` and `/api/devices/rekey*` for a signed-in session; null for anything else. */
    async function handle(request: Request, path: string, user: Caller): Promise<Response | null> {
        // Writes are limited per account (reads have their own, stricter limit above).
        const writeLimited = () => { const recent = (touched.get(user.id) ?? []).filter(at => at > now() - 60000); touched.set(user.id, [...recent, now()]); return recent.length >= 30; };
        if (path === '/api/backup') {
            if (request.method === 'GET') return get(user);
            if (request.method === 'PUT') return writeLimited() ? json({ error: 'Rate limited' }, 429) : put(request, user);
            if (request.method === 'DELETE') return writeLimited() ? json({ error: 'Rate limited' }, 429) : del(request, user);
            return null;
        }
        if (path === '/api/keys/reset') {
            if (request.method === 'POST') return requestReset(user);
            if (request.method === 'DELETE') return cancelReset(user);
            return null;
        }
        if (path === '/api/devices/rekey') {
            if (request.method === 'GET') return rekeyPending(user);
            if (request.method === 'PUT') return writeLimited() ? json({ error: 'Rate limited' }, 429) : rekeyAsk(request, user);
            if (request.method === 'DELETE') return rekeyDone(user);
            return null;
        }
        if (path === '/api/devices/rekey/mine' && request.method === 'GET') return rekeyMine(user);
        const answer = /^\/api\/devices\/rekey\/([A-Za-z0-9_-]{22})$/.exec(path);
        if (answer && request.method === 'PUT') return writeLimited() ? json({ error: 'Rate limited' }, 429) : rekeyAnswer(request, user, answer[1]!);
        return null;
    }

    /** The owner's view of their backup, for `GET /api/devices/<own username>`: no key material, nothing rate limited or logged. */
    function status(userId: string): { epoch: number; updatedAt: number } | null {
        const backup = stored(userId);
        return backup ? { epoch: backup.epoch, updatedAt: backup.updatedAt } : null;
    }

    return { handle, authorizeSuccession, authorizeRemoval, rotationStatus, status, resetStatus, authorizeIdentityChange, identityChanged };
}
