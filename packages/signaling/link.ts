import type { Database } from 'bun:sqlite';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { ed25519Verify, Format, MAX_DEVICES } from './devices';
import { requestLimiter } from './rate-limit';

// Device linking (docs/m5-linking.md §1): a blind relay between a new device and the primary. The two ends derive
// their keys from an ephemeral exchange the server only carries (authenticated by the QR's link secret, or by the
// short code's commit-and-reveal), so the server sees ciphertext, the platform and that a link happened. What it
// does decide is the plumbing: who may offer, that a device exists only for the account that was offered it, that
// nothing is granted before the primary's signed list names the device, and that the new device's session is
// issued once, bound to that device.
const QR_TTL = 10 * 60 * 1000, CODE_TTL = 5 * 60 * 1000, MAX_OPEN = 1000, MAX_MESSAGES = 64, DATA_MAX = 87400;
const STARTS_PER_MINUTE = 5, LOOKUP_STRIKES = 3, LOOKUP_BLOCK = 5 * 60 * 1000;
const ID = /^[A-Za-z0-9_-]{22}$/, KEY = /^[A-Za-z0-9_-]{43}$/, B64 = /^[A-Za-z0-9_-]+$/, SIG = /^[A-Za-z0-9_-]{86}$/;
/** Unambiguous letters and digits: 31 symbols, 8 characters (about 39.6 bits). */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const NATIVE = new Set(['ios', 'android', 'macos', 'windows', 'linux']);

type SessionUser = { id: string; username: string; session: string; client: string };
type Link = {
    id: string; purpose: 'link' | 'transfer'; mode: 'qr' | 'code'; device_id: string; device_key: string; platform: string; claim_hash: string;
    expect_user: string | null; code_hash: string | null; commit_hash: string | null; reveal: string | null; user_id: string | null; offer_device_id: string | null;
    eph: string | null; state: 'waiting' | 'offered' | 'granted' | 'claimed'; strikes: number; created_at: number; expires_at: number;
};
type Deps = {
    db: Database; now: () => number; origin: string;
    sessionUser(request: Request): SessionUser | null;
    sessionDevice(session: string): string | null;
    notify(userId: string, event: object): void;
    /** A session for the linked device, answered the way sign-in answers (cookie for the web, bearer for native apps). */
    issueSession(user: { id: string; username: string }, client: string, deviceId: string): Response;
    eligible(userId: string, deviceId: string | null): boolean;
    sigKey(deviceId: string): string | null;
};

const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
const sha = (text: string) => createHash('sha256').update(text).digest('hex');
async function readJson(request: Request): Promise<Record<string, any> | null> {
    try { const text = await request.text(); if (text.length > 131072) return null; const value = JSON.parse(text); return value && typeof value === 'object' && !Array.isArray(value) ? value : null; } catch { return null; }
}
const canonicalKey = (text: unknown) => typeof text === 'string' && KEY.test(text) && Buffer.from(text, 'base64url').length === 32 && Buffer.from(text, 'base64url').toString('base64url') === text;

export function createLink(deps: Deps) {
    const { db, now } = deps;
    const allowStart = new Map<string, number[]>();
    const allowMessage = requestLimiter({ perSource: 20, global: 1000 }), allowPoll = requestLimiter({ perSource: 8, global: 1000 }), allowClaim = requestLimiter({ perSource: 5, global: 200 }), allowLookup = requestLimiter({ perSource: 5, global: 200 });
    // Failed or rejected code lookups per account: three strikes block lookups for five minutes.
    const strikes = new Map<string, { count: number; until: number }>();

    const row = (id: string) => ID.test(id) ? db.query<Link, [string]>('SELECT * FROM link_requests WHERE id = ?').get(id) : null;
    const live = (link: Link | null): link is Link => Boolean(link && link.expires_at > now());
    const primaryOf = (userId: string) => db.query<{ id: string }, [string]>("SELECT id FROM devices WHERE user_id = ? AND is_primary = 1 AND state != 'revoked'").get(userId)?.id ?? null;
    const openCount = () => db.query<{ n: number }, [number]>('SELECT COUNT(*) AS n FROM link_requests WHERE expires_at > ?').get(now())!.n;
    const claimMatches = (link: Link, claim: unknown) => typeof claim === 'string' && KEY.test(claim) && (() => { const a = Buffer.from(sha(claim), 'hex'), b = Buffer.from(link.claim_hash, 'hex'); return a.length === b.length && timingSafeEqual(a, b); })();
    /** Which end the request is: the new device (it holds the claim) or the primary that took the link. */
    function role(request: Request, link: Link, user: SessionUser | null): 'n' | 'p' | null {
        if (claimMatches(link, request.headers.get('x-link-claim'))) return 'n';
        if (user && link.user_id === user.id && link.offer_device_id && deps.sessionDevice(user.session) === link.offer_device_id) return 'p';
        return null;
    }
    function strike(userId: string) {
        const entry = strikes.get(userId);
        const count = (entry && entry.until > now() - LOOKUP_BLOCK ? entry.count : 0) + 1;
        strikes.set(userId, { count, until: now() + (count >= LOOKUP_STRIKES ? LOOKUP_BLOCK : 0) });
        if (strikes.size > 10000) for (const [key, value] of strikes) if (value.until <= now() - LOOKUP_BLOCK) strikes.delete(key);
    }
    const blocked = (userId: string) => (strikes.get(userId)?.until ?? 0) > now();

    // ---------- Starting ----------

    async function start(request: Request, source: string, user: SessionUser | null): Promise<Response> {
        const body = await readJson(request);
        const purpose = body?.purpose, mode = body?.mode ?? 'qr';
        if (!body || !['link', 'transfer'].includes(purpose) || !['qr', 'code'].includes(mode) || typeof body.deviceId !== 'string' || !ID.test(body.deviceId) || !canonicalKey(body.deviceKey) || !Format.PLATFORMS.includes(body.platform)) return json({ error: 'Invalid link' }, 400);
        let bytes: Uint8Array;
        try { bytes = Format.startBytes(body.deviceId, body.platform, body.deviceKey); } catch { return json({ error: 'Invalid link' }, 400); }
        if (!ed25519Verify(body.deviceKey, bytes, body.signature)) return json({ error: 'The link request is not signed by that device key.' }, 403);
        // A few starts per minute per source and a global ceiling: this endpoint takes no session for a new device.
        const recent = (allowStart.get(source) ?? []).filter(at => at > now() - 60000);
        if (recent.length >= STARTS_PER_MINUTE || openCount() >= MAX_OPEN) return json({ error: 'Rate limited' }, 429);
        allowStart.set(source, [...recent, now()]);
        if (allowStart.size > 10000) for (const [key, times] of allowStart) if (!times.some(at => at > now() - 60000)) allowStart.delete(key);
        let userId: string | null = null, expect: string | null = null;
        if (purpose === 'transfer') {
            // A listed companion asks to become primary: it proves who it is with its session and its registered key.
            if (!user || deps.sessionDevice(user.session) !== body.deviceId || !deps.eligible(user.id, body.deviceId) || deps.sigKey(body.deviceId) !== body.deviceKey) return json({ error: 'Only a listed device of the account can take over as primary.' }, 403);
            userId = user.id; expect = user.id;
        } else {
            // A signed-in browser the account doesn't list yet links under the id it announced: same key (the signature above proves it), same account only.
            const existing = db.query<{ user_id: string; state: string; sig_key: string | null }, [string]>('SELECT user_id, state, sig_key FROM devices WHERE id = ?').get(body.deviceId);
            if (existing && !(existing.state === 'pending' && existing.sig_key === body.deviceKey)) return json({ error: 'That device id is taken.' }, 409);
            if (existing) expect = existing.user_id;
        }
        let code: string | null = null, codeHash: string | null = null;
        if (mode === 'code') {
            if (purpose === 'link') {
                const name = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
                const owner = db.query<{ id: string }, [string]>('SELECT id FROM users WHERE username = ?').get(name);
                // Only the named account's primary can complete a code link; not finding it says nothing about the account.
                expect = expect ?? owner?.id ?? randomBytes(16).toString('base64url');
            }
            code = Array.from(randomBytes(8), byte => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join('');
            codeHash = sha(code);
        }
        const id = randomBytes(16).toString('base64url'), claim = randomBytes(32).toString('base64url');
        try {
            db.query(`INSERT INTO link_requests (id, purpose, mode, device_id, device_key, platform, claim_hash, expect_user, code_hash, user_id, state, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?)`).run(id, purpose, mode, body.deviceId, body.deviceKey, body.platform, sha(claim), expect, codeHash, userId, now(), now() + (mode === 'code' ? CODE_TTL : QR_TTL));
        } catch { return json({ error: 'Try again.' }, 409); }
        return json({ linkId: id, claim, expiresAt: now() + (mode === 'code' ? CODE_TTL : QR_TTL), ...(code ? { code } : {}) }, 201);
    }

    // ---------- The short code ----------

    /** The new device commits to its ephemeral key (code mode), before any primary can see the code. */
    async function commit(request: Request, link: Link): Promise<Response> {
        if (link.mode !== 'code' || link.state !== 'waiting' || link.commit_hash) return json({ error: 'Not now.' }, 409);
        const body = await readJson(request);
        if (!canonicalKey(body?.commit)) return json({ error: 'Invalid commitment' }, 400);
        db.query('UPDATE link_requests SET commit_hash = ? WHERE id = ?').run(body!.commit, link.id);
        return json({ status: 'committed' }, 201);
    }

    /** The primary types the code. One answer for every failure; three strikes block further tries for five minutes. */
    async function lookup(request: Request, user: SessionUser): Promise<Response> {
        if (blocked(user.id)) return json({ error: 'Too many wrong codes. Try again in a few minutes.' }, 429);
        if (!allowLookup(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request);
        const typed = typeof body?.code === 'string' ? body.code.toUpperCase().replace(/[\s-]/g, '') : '';
        const device = deps.sessionDevice(user.session);
        const link = typed.length === 8 && [...typed].every(c => CODE_ALPHABET.includes(c)) ? db.query<Link, [string]>('SELECT * FROM link_requests WHERE code_hash = ?').get(sha(typed)) : null;
        const fine = live(link) && link.state === 'waiting' && link.commit_hash && link.user_id === null && link.purpose === 'link' && link.expect_user === user.id && device !== null && deps.eligible(user.id, device);
        if (!fine) { strike(user.id); return json({ error: 'No link with that code.' }, 404); }
        // Single use: the code stops existing the moment a primary has it.
        db.query('UPDATE link_requests SET code_hash = NULL, user_id = ?, offer_device_id = ? WHERE id = ?').run(user.id, device, link.id);
        return json({ linkId: link.id, deviceId: link.device_id, platform: link.platform, commit: link.commit_hash, expiresAt: link.expires_at });
    }

    /** The new device opens its commitment, once the primary's key is in (code mode). */
    async function reveal(request: Request, link: Link): Promise<Response> {
        if (link.mode !== 'code' || link.state !== 'offered' || link.reveal) return json({ error: 'Not now.' }, 409);
        const body = await readJson(request);
        if (!canonicalKey(body?.eph) || typeof body?.nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(body.nonce)) return json({ error: 'Invalid reveal' }, 400);
        db.query('UPDATE link_requests SET reveal = ? WHERE id = ?').run(JSON.stringify({ eph: body.eph, nonce: body.nonce }), link.id);
        if (link.user_id) deps.notify(link.user_id, { type: 'link', id: link.id, event: 'reveal' });
        return json({ status: 'revealed' }, 201);
    }

    // ---------- Offer, relay, grant, claim ----------

    async function offer(request: Request, link: Link, user: SessionUser): Promise<Response> {
        const device = deps.sessionDevice(user.session);
        // Any listed device of the account links another (every device holds the account key, docs/m6-account-key.md §2); a pre-M6 transfer is still the primary's alone.
        const allowed = link.purpose === 'transfer' ? device === primaryOf(user.id) : deps.eligible(user.id, device);
        if (link.state !== 'waiting' || !device || !allowed) return json({ error: 'Only a listed device of the account links devices.' }, 403);
        if (link.mode === 'code' ? (link.user_id !== user.id || link.offer_device_id !== device) : false) return json({ error: 'Look the code up first.' }, 409);
        if (link.mode === 'qr' && link.user_id && link.user_id !== user.id) return json({ error: 'This link belongs to another account.' }, 403);
        if (link.expect_user && link.expect_user !== user.id) return json({ error: 'This link was not started for your account.' }, 403);
        const body = await readJson(request);
        if (!canonicalKey(body?.eph)) return json({ error: 'Invalid key' }, 400);
        db.transaction(() => {
            if (link.purpose === 'link') {
                const live_ = db.query<{ n: number }, [string]>("SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND state NOT IN ('revoked', 'placeholder')").get(user.id)!.n;
                if (live_ >= MAX_DEVICES) throw Object.assign(new Error('full'), { status: 429 });
                // The device exists for this account only, with the key it registered, until the primary's list names it.
                // Already there when a signed-in pending browser started the link (start bound expect_user to its account).
                db.query("INSERT OR IGNORE INTO devices (id, user_id, platform, state, sig_key, created_at) VALUES (?, ?, ?, 'pending', ?, ?)").run(link.device_id, user.id, link.platform, link.device_key, now());
            }
            db.query("UPDATE link_requests SET state = 'offered', user_id = ?, offer_device_id = ?, eph = ? WHERE id = ?").run(user.id, device, body!.eph, link.id);
        })();
        return json({ deviceId: link.device_id, platform: link.platform, purpose: link.purpose, mode: link.mode }, 201);
    }

    function status(request: Request, link: Link, who: 'n' | 'p'): Response {
        const base = { state: link.state, purpose: link.purpose, mode: link.mode, platform: link.platform, expiresAt: link.expires_at };
        if (who === 'n') return json({ ...base, ...(link.eph ? { eph: link.eph, offerDeviceId: link.offer_device_id } : {}) });
        return json({ ...base, deviceId: link.device_id, ...(link.commit_hash ? { commit: link.commit_hash } : {}), ...(link.reveal ? { reveal: JSON.parse(link.reveal) } : {}) });
    }

    async function post(request: Request, link: Link, who: 'n' | 'p'): Promise<Response> {
        if (link.state !== 'offered' && link.state !== 'granted') return json({ error: 'The link is not open for messages.' }, 409);
        if (!allowMessage(link.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request);
        const dir = who === 'n' ? 'n2p' : 'p2n';
        if (body?.dir !== undefined && body.dir !== dir) return json({ error: 'Not your direction.' }, 403);
        if (typeof body?.data !== 'string' || !body.data.length || body.data.length > DATA_MAX || !B64.test(body.data)) return json({ error: 'Invalid message' }, 400);
        const count = db.query<{ n: number }, [string, string]>('SELECT COUNT(*) AS n FROM link_messages WHERE link_id = ? AND dir = ?').get(link.id, dir)!.n;
        if (count >= MAX_MESSAGES) return json({ error: 'Too many messages on this link.' }, 429);
        db.query('INSERT INTO link_messages (link_id, dir, seq, data, created_at) VALUES (?, ?, ?, ?, ?)').run(link.id, dir, count + 1, body.data, now());
        if (who === 'n' && link.user_id) deps.notify(link.user_id, { type: 'link', id: link.id, event: 'message', dir, seq: count + 1 });
        return json({ seq: count + 1 }, 201);
    }

    function messages(url: URL, link: Link, who: 'n' | 'p'): Response {
        const dir = who === 'n' ? 'p2n' : 'n2p';
        if (url.searchParams.get('dir') !== null && url.searchParams.get('dir') !== dir) return json({ error: 'Not your direction.' }, 403);
        const raw = url.searchParams.get('after') ?? '0';
        const after = /^\d{1,6}$/.test(raw) ? Number(raw) : -1;
        if (after < 0) return json({ error: 'Invalid position' }, 400);
        const rows = db.query<{ seq: number; data: string }, [string, string, number]>('SELECT seq, data FROM link_messages WHERE link_id = ? AND dir = ? AND seq > ? ORDER BY seq LIMIT 64').all(link.id, dir, after);
        return json({ messages: rows });
    }

    /** The primary says the list naming the new device is published and the bundle is sent. */
    function grant(link: Link): Response {
        if (link.state !== 'offered') return json({ error: 'Nothing to grant.' }, 409);
        if (link.purpose === 'link') {
            // Nothing is granted before the account's signed list (under its current identity key) names the device.
            if (!link.user_id || !deps.eligible(link.user_id, link.device_id)) return json({ error: 'Publish the device list naming this device first.' }, 409);
            if (db.query<{ n: number }, [string, string]>('SELECT COUNT(*) AS n FROM link_messages WHERE link_id = ? AND dir = ?').get(link.id, 'p2n')!.n === 0) return json({ error: 'Send the grant first.' }, 409);
        }
        db.query("UPDATE link_requests SET state = 'granted' WHERE id = ?").run(link.id);
        return json({ status: 'granted' });
    }

    async function claim(request: Request, link: Link): Promise<Response> {
        if (link.purpose !== 'link' || link.state !== 'granted' || !link.user_id) return json({ error: 'This link is not ready.' }, 409);
        const body = await readJson(request);
        if (!claimMatches(link, body?.claim) || typeof body?.signature !== 'string' || !SIG.test(body.signature)) return json({ error: 'Invalid claim' }, 403);
        let bytes: Uint8Array;
        try { bytes = Format.linkClaimBytes(link.id, link.device_id, body.claim); } catch { return json({ error: 'Invalid claim' }, 400); }
        if (!ed25519Verify(link.device_key, bytes, body.signature)) return json({ error: 'The claim is not signed by this device\'s key.' }, 403);
        if (!deps.eligible(link.user_id, link.device_id)) return json({ error: 'The device is no longer in the account\'s list.' }, 409);
        // The web gets a cookie, native apps a bearer; the kind of client is the one the link was started as.
        const web = request.headers.get('origin') !== null;
        if (web !== (link.platform === 'web')) return json({ error: 'This link was started on another kind of client.' }, 400);
        const owner = db.query<{ id: string; username: string }, [string]>('SELECT id, username FROM users WHERE id = ?').get(link.user_id);
        if (!owner || (!web && !NATIVE.has(link.platform))) return json({ error: 'Invalid claim' }, 400);
        const response = deps.issueSession(owner, link.platform, link.device_id);
        db.query("UPDATE link_requests SET state = 'claimed' WHERE id = ?").run(link.id);
        deps.notify(owner.id, { type: 'link', id: link.id, event: 'claimed' });
        deps.notify(owner.id, { type: 'devices', id: owner.id });
        return response;
    }

    function cancel(link: Link, who: 'n' | 'p'): Response {
        // A primary that turns a code link away is a strike against its account (three block code lookups).
        if (who === 'p' && link.mode === 'code' && link.state !== 'granted' && link.user_id) strike(link.user_id);
        remove(link);
        return json({ status: 'cancelled' });
    }
    function remove(link: Link) {
        db.transaction(() => {
            // The pending device the offer created goes with a link that never got its list.
            if (link.purpose === 'link' && link.state !== 'claimed') db.query("DELETE FROM devices WHERE id = ? AND state = 'pending' AND sig_key = ? AND NOT EXISTS (SELECT 1 FROM sessions WHERE device_id = devices.id)").run(link.device_id, link.device_key);
            db.query('DELETE FROM link_requests WHERE id = ?').run(link.id);
        })();
    }

    function sweep() {
        for (const link of db.query<Link, [number]>('SELECT * FROM link_requests WHERE expires_at <= ?').all(now())) remove(link);
    }

    // ---------- Routing ----------

    async function handle(request: Request, url: URL, source: string): Promise<Response> {
        const user = deps.sessionUser(request);
        const method = request.method, path = url.pathname, origin = request.headers.get('origin');
        // A page of another site never reaches any of this; a cookie session also needs this app's own origin to change state.
        if (origin !== null && origin !== deps.origin) return json({ error: 'Origin denied' }, 403);
        const bearer = request.headers.get('authorization')?.startsWith('Bearer ') ?? false;
        if (method !== 'GET' && user && !bearer && origin !== deps.origin) return json({ error: 'Origin required' }, 403);
        if (path === '/api/link/start' && method === 'POST') return start(request, source, user);
        if (path === '/api/link/lookup' && method === 'POST') return user ? lookup(request, user) : json({ error: 'Unauthorized' }, 401);
        const match = /^\/api\/link\/([A-Za-z0-9_-]{22})(?:\/([a-z]+))?$/.exec(path);
        if (!match) return json({ error: 'Not found' }, 404);
        const link = row(match[1]!), action = match[2];
        if (!live(link)) return json({ error: 'No such link, or it expired.' }, 404);
        // Claiming is the one call that needs no session: the claim secret and the device key's signature are the proof.
        if (action === 'claim' && method === 'POST') return allowClaim(source) ? claim(request, link) : json({ error: 'Rate limited' }, 429);
        if (action === 'offer' && method === 'POST') return user ? offer(request, link, user) : json({ error: 'Unauthorized' }, 401);
        const who = role(request, link, user);
        // Not a party: the same answer as no such link.
        if (!who) return json({ error: 'No such link, or it expired.' }, 404);
        if (!action && method === 'GET') return allowPoll(link.id) ? status(request, link, who) : json({ error: 'Rate limited' }, 429);
        if (!action && method === 'DELETE') return cancel(link, who);
        if (action === 'messages' && method === 'POST') return post(request, link, who);
        if (action === 'messages' && method === 'GET') return allowPoll(link.id) ? messages(url, link, who) : json({ error: 'Rate limited' }, 429);
        if (who === 'n' && action === 'commit' && method === 'POST') return commit(request, link);
        if (who === 'n' && action === 'reveal' && method === 'POST') return reveal(request, link);
        if (who === 'p' && action === 'grant' && method === 'POST') return grant(link);
        return json({ error: 'Not found' }, 404);
    }

    return { handle, sweep };
}
export type LinkRelay = ReturnType<typeof createLink>;
