import type { Database } from 'bun:sqlite';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import './public/devices.js'; // Defines globalThis.DeviceFormat: the same canonical bytes the clients sign.

// Device registry (docs/workspace-architecture.md §1.2, §3; docs/devices.md). The server keeps the account's
// signed device list verbatim and routes envelopes per device. It cannot make clients trust a device: they
// verify every list and certificate against the account identity key (AIK) they pinned.
type DeviceEntry = { deviceId: string; addedAt: number; meta: string };
type DeviceList = { v: 1; userId: string; version: number; prevHash: string; devices: DeviceEntry[] };
type Format = {
    MAX_DEVICES: number; PLATFORMS: readonly string[];
    validateList(list: unknown): DeviceList; listBytes(list: DeviceList): Uint8Array;
    certBytes(cert: object): Uint8Array; certFor(userId: string, device: DeviceEntry): object;
    bindBytes(userId: string, deviceId: string, challenge: string): Uint8Array;
    claimBytes(userId: string, deviceId: string, challenge: string): Uint8Array;
};
const Format = (globalThis as any).DeviceFormat as Format & { successionBytes(record: object): Uint8Array; startBytes(deviceId: string, platform: string, deviceKey: string): Uint8Array; linkClaimBytes(linkId: string, deviceId: string, claim: string): Uint8Array };
export { Format };
export const MAX_DEVICES = Format.MAX_DEVICES;
const DEVICE_ID = /^[A-Za-z0-9_-]{22}$/, SIG = /^[A-Za-z0-9_-]{86}$/, KEY = /^[A-Za-z0-9_-]{43}$/;
/** A bind challenge is single use, for one session, and short lived. */
const CHALLENGE_LIFETIME = 2 * 60 * 1000, MAX_CHALLENGES = 10000, MAX_SESSION_CHALLENGES = 4, MAX_ACCOUNT_CHALLENGE_SESSIONS = 32;
/** The caller: a signed-in session. `client` is 'web' or the native platform it signed in with. */
type Caller = { id: string; session: string; client: string };

// platform is the session's client kind ('web', 'ios', …), which the server already knows from sign-in; the
// device's label and platform as the account sees them are sealed inside the signed list.
export type DeviceRow = { id: string; user_id: string; platform: string; state: string; is_primary: number; created_at: number; last_seen_at: number | null };
type Deps = {
    db: Database; now: () => number;
    /** Sends an event to every open stream of a user. */
    notify(userId: string, event: object): void;
    mutualIds(userId: string): string[];
    /** Called after sessions were deleted: forget their push tokens and close their streams. */
    sessionsEnded(userId: string, sessions: string[]): void;
    /** A session was bound or an inbox moved: deliver what now waits for the user's open streams. */
    inboxChanged(userId: string): void;
    /** Devices were revoked (by the account, or dropped by a new list): group memberships and the like go with them. */
    devicesRevoked?(userId: string, ids: string[]): void;
};

/** Ed25519 verification of a base64url signature under a base64url public key (the AIK or a device key). */
export function ed25519Verify(aikSign: string, bytes: Uint8Array, signature: unknown) {
    if (typeof signature !== 'string' || !SIG.test(signature)) return false;
    try { return verify(null, bytes, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: aikSign }, format: 'jwk' }), Buffer.from(signature, 'base64url')); }
    catch { return false; }
}
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('base64url');

export function createDevices(deps: Deps) {
    const { db, now } = deps;
    const live = (userId: string) => db.query<DeviceRow, [string]>("SELECT * FROM devices WHERE user_id = ? AND state != 'revoked' ORDER BY created_at, id").all(userId);
    const sessionDevice = (session: string) => db.query<{ device_id: string | null }, [string]>('SELECT device_id FROM sessions WHERE token_hash = ?').get(session)?.device_id ?? null;
    const aikOf = (userId: string) => db.query<{ sign: string }, [string]>('SELECT sign FROM identity_keys WHERE user_id = ?').get(userId)?.sign ?? null;

    /** The device that receives this account's envelopes: the primary, or a placeholder created for it. */
    function primary(userId: string) {
        const row = db.query<{ id: string }, [string]>("SELECT id FROM devices WHERE user_id = ? AND is_primary = 1 AND state != 'revoked'").get(userId);
        if (row) return row.id;
        const id = randomBytes(16).toString('base64url');
        db.query("INSERT INTO devices (id, user_id, platform, state, is_primary, created_at) VALUES (?, ?, 'unknown', 'placeholder', 1, ?)").run(id, userId, now());
        return id;
    }
    /**
     * Where a stream's envelopes come from: its session's own device inbox, or none for an unbound session.
     * Legacy state only: while the primary is a placeholder (a migrated account no device has claimed yet),
     * the server cannot tell which signed-in device holds the keys, so every session reads the placeholder's
     * inbox as before M1; the inactive ones never acknowledge what they cannot read. Once a device holds
     * messaging (claimed or listed), an unbound session gets nothing until it binds with proof of possession.
     */
    function inboxFor(userId: string, session: string): string | null {
        const own = sessionDevice(session), main = primary(userId);
        if (own === main) return main;
        const state = db.query<{ state: string }, [string]>('SELECT state FROM devices WHERE id = ?').get(main)?.state;
        return state === 'placeholder' ? main : own;
    }

    /** Revokes devices: their sessions end (streams close with 4401), push tokens and waiting envelopes go. */
    function revoke(userId: string, ids: string[]) {
        if (!ids.length) return;
        const ended: string[] = [];
        db.transaction(() => {
            for (const id of ids) {
                for (const row of db.query<{ token_hash: string }, [string, string]>('SELECT token_hash FROM sessions WHERE device_id = ? AND user_id = ?').all(id, userId)) ended.push(row.token_hash);
                db.query('DELETE FROM sessions WHERE device_id = ? AND user_id = ?').run(id, userId);
                db.query('DELETE FROM device_inbox WHERE device_id = ?').run(id);
                db.query("UPDATE devices SET state = 'revoked', is_primary = 0, revoked_at = ? WHERE id = ? AND user_id = ?").run(now(), id, userId);
            }
        })();
        deps.sessionsEnded(userId, ended);
        deps.devicesRevoked?.(userId, ids);
    }
    function announceChange(userId: string) {
        deps.notify(userId, { type: 'devices', id: userId });
        for (const contact of deps.mutualIds(userId)) deps.notify(contact, { type: 'devices', id: userId });
    }

    /**
     * The account identity changed (messaging moved to a device with new keys). Lists signed by the old key are
     * void: every device drops to pending and a fresh placeholder primary takes the waiting envelopes until the
     * new key holder publishes list v1. Sessions stay signed in, as before.
     */
    function identityChanged(userId: string, event = 'keys-put') {
        db.transaction(() => {
            const old = live(userId).map(row => row.id);
            db.query('DELETE FROM device_lists WHERE user_id = ?').run(userId);
            db.query("UPDATE devices SET is_primary = 0, state = CASE WHEN state = 'placeholder' THEN 'revoked' ELSE 'pending' END WHERE user_id = ? AND state != 'revoked'").run(userId);
            const next = primary(userId);
            for (const id of old) db.query('UPDATE device_inbox SET device_id = ? WHERE device_id = ?').run(next, id);
        })();
        db.query('INSERT OR REPLACE INTO identity_changes (user_id, aik, event, at) VALUES (?, ?, ?, ?)').run(userId, aikOf(userId) ?? '', event, now());
        announceChange(userId);
    }

    /** The last authenticated identity change for the user, which is what lets the MLS validator re-pin their key. */
    const identityChange = (userId: string) => db.query<{ aik: string; event: string }, [string]>('SELECT aik, event FROM identity_changes WHERE user_id = ?').get(userId);

    /** A new signed list from the account's identity-key holder. Returns [status, body]. */
    function publish(user: Caller, body: Record<string, any> | null): [number, object] {
        const aik = aikOf(user.id);
        if (!aik) return [409, { error: 'Publish encryption keys before a device list.' }];
        let list: DeviceList;
        try { list = Format.validateList(body?.list); } catch (error: any) { return [400, { error: error.message || 'Invalid device list' }]; }
        if (list.userId !== user.id) return [400, { error: 'This list names another account.' }];
        const bytes = Format.listBytes(list);
        if (!ed25519Verify(aik, bytes, body!.signature)) return [403, { error: 'The list is not signed by this account\'s identity key.' }];
        const certs: Record<string, string> = {};
        for (const device of list.devices) {
            const signature = body!.certs?.[device.deviceId];
            if (!ed25519Verify(aik, Format.certBytes(Format.certFor(user.id, device)), signature)) return [403, { error: `Invalid certificate for device ${device.deviceId}.` }];
            certs[device.deviceId] = signature;
        }
        const deviceId = body!.deviceId;
        if (typeof deviceId !== 'string' || !list.devices.some(device => device.deviceId === deviceId)) return [400, { error: 'The publishing device must be in the list.' }];
        const stored = db.query<{ version: number; hash: string; aik_sign: string }, [string]>('SELECT version, hash, aik_sign FROM device_lists WHERE user_id = ?').get(user.id);
        if (stored && stored.aik_sign === aik) {
            // Lists only move forward, each naming the one before it: a replayed or forked list is refused.
            // Exactly the next version: no replays, no forks at the same version, no skipping ahead.
            if (list.version !== stored.version + 1) return [409, { error: 'A device list must be the next version.', version: stored.version }];
            if (list.prevHash !== stored.hash) return [409, { error: 'The list does not follow the current one.', version: stored.version }];
            // Changes come only from the primary device's own session.
            const current = db.query<{ id: string }, [string]>("SELECT id FROM devices WHERE user_id = ? AND is_primary = 1 AND state = 'listed'").get(user.id);
            if (!current || sessionDevice(user.session) !== current.id || deviceId !== current.id) return [403, { error: 'Only the primary device can change the device list.' }];
        } else if (list.version !== 1) return [409, { error: 'The first device list is version 1.', version: 0 }];
        // The publisher must have bound its session to its device with proof of possession (announce).
        if (sessionDevice(user.session) !== deviceId) return [409, { error: 'Announce this device before publishing a list.' }];
        // A device id is the account's own: never one of another account's devices.
        for (const device of list.devices) {
            const owner = db.query<{ user_id: string; state: string }, [string]>('SELECT user_id, state FROM devices WHERE id = ?').get(device.deviceId);
            if (owner && (owner.user_id !== user.id || owner.state === 'revoked')) return [409, { error: `Device ${device.deviceId} cannot be listed.` }];
        }
        const listed = new Set(list.devices.map(device => device.deviceId));
        const dropped = live(user.id).filter(row => row.state === 'listed' && !listed.has(row.id)).map(row => row.id);
        db.transaction(() => {
            // The device that held this account's envelopes (a placeholder, or an unlisted device that claimed
            // messaging) hands them to the device the signed list now makes primary.
            const previous = db.query<{ id: string; state: string }, [string]>("SELECT id, state FROM devices WHERE user_id = ? AND is_primary = 1 AND state != 'revoked'").get(user.id);
            db.query("UPDATE devices SET is_primary = 0 WHERE user_id = ? AND state != 'revoked'").run(user.id);
            for (const device of list.devices) {
                // A listed device the server has not seen yet (a companion added by the primary) keeps 'unknown'.
                db.query(`INSERT INTO devices (id, user_id, platform, state, is_primary, cert, created_at) VALUES (?1, ?2, 'unknown', 'listed', 0, ?3, ?4)
                    ON CONFLICT (id) DO UPDATE SET state = 'listed', cert = ?3`).run(device.deviceId, user.id, certs[device.deviceId]!, now());
            }
            db.query('UPDATE devices SET is_primary = 1, platform = ?, last_seen_at = ? WHERE id = ?').run(user.client, now(), deviceId);
            if (previous && previous.id !== deviceId) {
                db.query('UPDATE device_inbox SET device_id = ? WHERE device_id = ?').run(deviceId, previous.id);
                if (previous.state === 'placeholder') db.query('DELETE FROM devices WHERE id = ?').run(previous.id);
            }
            db.query('INSERT OR REPLACE INTO device_lists (user_id, aik_sign, version, hash, list, signature, certs, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                .run(user.id, aik, list.version, digest(bytes), JSON.stringify(list), body!.signature, JSON.stringify(certs), now());
        })();
        revoke(user.id, dropped);
        announceChange(user.id);
        deps.inboxChanged(user.id);
        return [200, { version: list.version, revoked: dropped }];
    }

    /**
     * The account's messaging moves to `deviceId` while no list signed by the current identity key names a
     * primary: the placeholder (or a previous unlisted claimer) hands over its inbox. This is how devices that
     * cannot sign lists yet (native apps, the WebAssembly core) get their own inbox. It needs only what the
     * server already trusted before M1 (the session that holds the published identity, see announce and
     * PUT /api/keys); it gives no client a reason to trust the device, which takes a signed list.
     */
    function claim(userId: string, deviceId: string) {
        const current = db.query<{ id: string; state: string }, [string]>("SELECT id, state FROM devices WHERE user_id = ? AND is_primary = 1 AND state != 'revoked'").get(userId);
        if (current?.id === deviceId || current?.state === 'listed') return false;
        db.transaction(() => {
            const from = current?.id ?? primary(userId);
            db.query('UPDATE devices SET is_primary = 0 WHERE id = ?').run(from);
            db.query('UPDATE devices SET is_primary = 1 WHERE id = ?').run(deviceId);
            db.query('UPDATE device_inbox SET device_id = ? WHERE device_id = ?').run(deviceId, from);
            db.query("DELETE FROM devices WHERE id = ? AND state = 'placeholder'").run(from);
        })();
        return true;
    }
    function keysUploaded(user: Caller, newIdentity: boolean) {
        if (!newIdentity) return;
        const id = sessionDevice(user.session);
        if (id && claim(user.id, id)) { deps.notify(user.id, { type: 'devices', id: user.id }); deps.inboxChanged(user.id); }
    }

    // Outstanding bind challenges by session hash: a few each (tabs and retries may overlap), oldest dropped.
    // Bounded per session, per account and overall; expired entries are swept at most once a second.
    const challenges = new Map<string, { user: string; items: { value: string; expiresAt: number }[] }>();
    let sweptAt = 0;
    function sweepChallenges() {
        if (now() - sweptAt < 1000) return;
        sweptAt = now();
        for (const [key, entry] of challenges) { entry.items = entry.items.filter(item => item.expiresAt > now()); if (!entry.items.length) challenges.delete(key); }
    }
    /** A fresh single-use challenge for this session to sign with its device key (announce). */
    function challenge(user: Caller): [number, object] {
        sweepChallenges();
        const own = challenges.get(user.session);
        if (!own) {
            let mine = 0;
            for (const entry of challenges.values()) if (entry.user === user.id) mine++;
            if (mine >= MAX_ACCOUNT_CHALLENGE_SESSIONS) return [429, { error: 'Too many devices signing in at once. Try again in a few minutes.' }];
            if (challenges.size >= MAX_CHALLENGES) return [503, { error: 'Busy, try again' }];
        }
        const value = randomBytes(32).toString('base64url');
        const items = [...(own?.items ?? []), { value, expiresAt: now() + CHALLENGE_LIFETIME }].slice(-MAX_SESSION_CHALLENGES);
        challenges.set(user.session, { user: user.id, items });
        return [200, { challenge: value }];
    }
    /** Spends one of this session's outstanding challenges; false if it was never issued, expired or used. */
    function spend(session: string, value: unknown) {
        const list = challenges.get(session)?.items ?? [], index = list.findIndex(item => item.value === value);
        if (index < 0) return false;
        const [item] = list.splice(index, 1);
        if (!list.length) challenges.delete(session);
        return item!.expiresAt > now();
    }

    /**
     * A signed-in device makes itself known and binds its session to a device id, proving possession of that
     * device's key: `signature` is the device key's signature over bindBytes(userId, deviceId, challenge) for
     * this session's single-use challenge. A new id registers `deviceKey`; an existing id is bound only with
     * its registered key, so another session of the account (or a stolen cookie) cannot become that device.
     * It shows up as pending for the owner until a signed list names it. `identityProof` proves this device
     * holds the account identity key: the published identity's signature over claimBytes(userId, deviceId,
     * challenge), the same single-use challenge. With it the device takes the messaging inbox (claim) unless a
     * signed list says otherwise. The identity itself is public, so naming it proves nothing.
     */
    function announce(user: Caller, body: Record<string, any> | null): [number, object] {
        const deviceId = body?.deviceId, proof = body?.identityProof, nonce = body?.challenge;
        if (typeof deviceId !== 'string' || !DEVICE_ID.test(deviceId) || (proof !== undefined && typeof proof !== 'string')) return [400, { error: 'Invalid device' }];
        // The challenge is spent by any attempt that names it, right or wrong.
        if (typeof nonce !== 'string' || !spend(user.session, nonce)) return [401, { error: 'The device challenge expired. Ask for a new one.' }];
        const bound = sessionDevice(user.session);
        if (bound && bound !== deviceId) return [409, { error: 'This session belongs to another device.' }];
        const existing = db.query<{ user_id: string; state: string; sig_key: string | null }, [string]>('SELECT user_id, state, sig_key FROM devices WHERE id = ?').get(deviceId);
        if (existing && (existing.user_id !== user.id || existing.state === 'revoked' || existing.state === 'placeholder' || !existing.sig_key)) return [409, { error: 'That device id cannot be used.' }];
        const key = existing ? existing.sig_key! : body!.deviceKey;
        if (typeof key !== 'string' || !KEY.test(key)) return [400, { error: 'Invalid device key' }];
        if (!ed25519Verify(key, Format.bindBytes(user.id, deviceId, nonce), body!.signature)) return [403, { error: 'This session could not prove it is that device.' }];
        // A claim must be signed by the published identity key for this challenge, account and device.
        const published = aikOf(user.id);
        const holder = proof !== undefined && published !== null && ed25519Verify(published, Format.claimBytes(user.id, deviceId, nonce), proof);
        if (proof !== undefined && !holder) return [403, { error: 'The identity proof does not verify.' }];
        if (!existing && live(user.id).filter(row => row.state !== 'placeholder').length >= MAX_DEVICES) return [429, { error: `At most ${MAX_DEVICES} devices per account. Remove one in Settings → Devices.` }];
        const platform = Format.PLATFORMS.includes(user.client) ? user.client : 'unknown';
        db.transaction(() => {
            if (!existing) db.query("INSERT INTO devices (id, user_id, platform, state, sig_key, created_at, last_seen_at) VALUES (?, ?, ?, 'pending', ?, ?, ?)").run(deviceId, user.id, platform, key, now(), now());
            else db.query('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(now(), deviceId);
            db.query('UPDATE sessions SET device_id = ? WHERE token_hash = ?').run(deviceId, user.session);
        })();
        const claimed = holder && claim(user.id, deviceId);
        if (!existing || claimed) deps.notify(user.id, { type: 'devices', id: user.id });
        deps.inboxChanged(user.id); // This session now reads its device's inbox.
        const row = db.query<{ state: string; is_primary: number }, [string]>('SELECT state, is_primary FROM devices WHERE id = ?').get(deviceId)!;
        return [200, { deviceId, state: row.state, primary: Boolean(row.is_primary) }];
    }

    /**
     * Any signed-in session of the account may revoke one of its other devices at once (docs/m5-linking.md §4): its
     * sessions end, its keys and mail go, it leaves every fan-out. The signed list still names a listed device until
     * the primary publishes the next version, which the primary is told to do. The primary itself is handed over,
     * never revoked.
     */
    function revokeAny(user: Caller, deviceId: string): [number, object] {
        const row = DEVICE_ID.test(deviceId) ? db.query<DeviceRow, [string, string]>("SELECT * FROM devices WHERE id = ? AND user_id = ? AND state != 'revoked'").get(deviceId, user.id) : null;
        if (!row) return [404, { error: 'No such device.' }];
        if (row.state === 'placeholder' || row.is_primary) return [409, { error: 'The primary device cannot be revoked. Hand the account to another device first.' }];
        revoke(user.id, [deviceId]);
        deps.notify(user.id, { type: 'devices', id: user.id, needsList: row.state === 'listed', revoked: deviceId });
        announceChange(user.id);
        return [200, { revoked: [deviceId] }];
    }

    // ---------- Succession (docs/m5-linking.md §5) ----------
    const SUCCESSION_MAX = 8;
    type SuccessionRow = { old_sign: string; new_sign: string; new_dh: string; at: number; signature: string };
    /** The account's records, oldest first, as served and as the delivery service's pin follows them. */
    function successions(userId: string) {
        return db.query<SuccessionRow, [string]>('SELECT old_sign, new_sign, new_dh, at, signature FROM identity_succession WHERE user_id = ? ORDER BY seq').all(userId)
            .map(row => ({ v: 1, userId, oldSign: row.old_sign, newSign: row.new_sign, newDh: row.new_dh, at: row.at, signature: row.signature }));
    }
    /** The old identity key hands the account to a new one. Self-authenticating: only its signature counts. */
    function putSuccession(user: Caller, body: Record<string, any> | null): [number, object] {
        const record = body?.record, signature = body?.signature;
        const current = aikOf(user.id);
        if (!current) return [409, { error: 'Publish encryption keys first.' }];
        let bytes: Uint8Array;
        try { bytes = Format.successionBytes(record); } catch { return [400, { error: 'Invalid succession record' }]; }
        if (record.userId !== user.id || record.oldSign !== current || record.newSign === record.oldSign) return [403, { error: 'The record is not from this account\'s current identity key.' }];
        if (!ed25519Verify(current, bytes, signature)) return [403, { error: 'The record is not signed by the current identity key.' }];
        if (Math.abs(record.at - now()) > 10 * 60 * 1000) return [400, { error: 'The record\'s time is not now.' }];
        const count = db.query<{ n: number; max: number | null }, [string]>('SELECT COUNT(*) AS n, MAX(seq) AS max FROM identity_succession WHERE user_id = ?').get(user.id)!;
        db.transaction(() => {
            // The chain keeps its newest records; older ones fall off (contacts that old review the code instead).
            if (count.n >= SUCCESSION_MAX) db.query('DELETE FROM identity_succession WHERE user_id = ? AND seq = (SELECT MIN(seq) FROM identity_succession WHERE user_id = ?)').run(user.id, user.id);
            db.query('INSERT INTO identity_succession (user_id, seq, old_sign, new_sign, new_dh, at, signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                .run(user.id, (count.max ?? 0) + 1, record.oldSign, record.newSign, record.newDh, record.at, signature, now());
        })();
        return [201, { seq: (count.max ?? 0) + 1 }];
    }

    /** The served view of an account's devices. Contacts see only the signed list; the owner also sees pending devices and when each was last seen. */
    function view(owner: { id: string }, viewer: Caller) {
        const stored = db.query<{ list: string; signature: string; certs: string }, [string]>('SELECT list, signature, certs FROM device_lists WHERE user_id = ?').get(owner.id);
        const signed = stored ? { list: JSON.parse(stored.list), signature: stored.signature, certs: JSON.parse(stored.certs) } : { list: null, signature: null, certs: {} };
        const identity = db.query<{ dh: string; sign: string }, [string]>('SELECT dh, sign FROM identity_keys WHERE user_id = ?').get(owner.id) ?? null;
        const succession = successions(owner.id);
        if (owner.id !== viewer.id) return { userId: owner.id, identity, ...signed, ...(succession.length ? { succession } : {}) };
        const mine = sessionDevice(viewer.session);
        const devices = live(owner.id).filter(row => row.state !== 'placeholder').map(row => ({ id: row.id, platform: row.platform, state: row.state, primary: Boolean(row.is_primary), createdAt: row.created_at, lastSeenAt: row.last_seen_at, current: row.id === mine }));
        return { userId: owner.id, identity, ...signed, ...(succession.length ? { succession } : {}), devices, currentDevice: mine };
    }

    /** Removes one of the owner's devices. A listed device also needs the new signed list without it. */
    function remove(user: Caller, deviceId: string, body: Record<string, any> | null): [number, object] {
        const caller = sessionDevice(user.session);
        const current = db.query<{ id: string; state: string }, [string]>("SELECT id, state FROM devices WHERE user_id = ? AND is_primary = 1 AND state != 'revoked'").get(user.id);
        // A device that is not the primary may remove only itself, and only while it is not in the signed list
        // (a listed device leaves through the primary's next list).
        if (caller === deviceId && current?.id !== deviceId) {
            const own = db.query<{ state: string }, [string, string]>("SELECT state FROM devices WHERE id = ? AND user_id = ? AND state != 'revoked'").get(deviceId, user.id);
            if (!own) return [404, { error: 'No such device.' }];
            if (own.state === 'listed') return [403, { error: 'A listed device is removed by the primary device.' }];
            revoke(user.id, [deviceId]);
            deps.notify(user.id, { type: 'devices', id: user.id });
            return [200, { revoked: [deviceId] }];
        }
        // Everything else comes from the primary device's own session; who is primary is server state, never input.
        if (!current || current.state !== 'listed' || caller !== current.id) return [403, { error: 'Only the primary device can remove devices.' }];
        const target = db.query<{ state: string }, [string, string]>("SELECT state FROM devices WHERE id = ? AND user_id = ? AND state != 'revoked'").get(deviceId, user.id);
        if (!target) return [404, { error: 'No such device.' }];
        if (deviceId === current.id) return [400, { error: 'The primary device cannot remove itself.' }];
        if (target.state === 'listed') {
            if (body?.list?.devices?.some?.((device: DeviceEntry) => device?.deviceId === deviceId)) return [400, { error: 'The new list still names that device.' }];
            return publish(user, { ...body, deviceId: current.id });
        }
        revoke(user.id, [deviceId]);
        deps.notify(user.id, { type: 'devices', id: user.id });
        return [200, { revoked: [deviceId] }];
    }

    /**
     * A device that may hold an MLS leaf: named by the signed device list, whose signer is the account's current
     * identity key (so its certificate chains to the AIK the list is signed with). Pending, revoked and placeholder
     * devices, and any device after an identity change (which voids the lists), are not.
     */
    function eligible(userId: string, deviceId: string | null) {
        if (!deviceId) return false;
        const row = db.query<{ state: string }, [string, string]>('SELECT state FROM devices WHERE id = ? AND user_id = ?').get(deviceId, userId);
        const list = db.query<{ aik_sign: string }, [string]>('SELECT aik_sign FROM device_lists WHERE user_id = ?').get(userId);
        const aik = aikOf(userId);
        return row?.state === 'listed' && Boolean(list && aik && list.aik_sign === aik);
    }
    /** The device's own registered Ed25519 key (its announce), which verifies what the device signs. */
    const sigKey = (deviceId: string) => db.query<{ sig_key: string | null }, [string]>('SELECT sig_key FROM devices WHERE id = ?').get(deviceId)?.sig_key ?? null;

    function touch(session: string) { const id = sessionDevice(session); if (id) db.query('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(now(), id); }

    return { primary, inboxFor, publish, challenge, announce, keysUploaded, view, remove, revokeAny, putSuccession, successions, identityChanged, identityChange, touch, sessionDevice, eligible, sigKey, aikOf };
}
export type Devices = ReturnType<typeof createDevices>;
