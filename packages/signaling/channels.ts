import type { Database } from 'bun:sqlite';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import type { ServerWebSocket } from 'bun';
import { requestLimiter } from './rate-limit';
import { Abort, DsError, pinAccounts, type DsCore, type KeyPackages } from './mls-ds';

// Channels: MLS groups on the server (docs/workspace-architecture.md §1, §2; docs/signaling-api.md "Channels").
// The server sequences each group's messages (epoch check, shared validator), keeps the log until every member
// device has read it, mirrors membership for fan-out, delivers Welcomes into a per-device inbox, and runs the
// poison-commit protocol. It never sees plaintext, roles beyond what the public tree shows, or any key.

export const KINDS = ['public', 'private', 'dm', 'group_dm', 'self'] as const;
type Kind = typeof KINDS[number];
/** Users per kind (architecture §2): a DM is 2 people, a group DM 9, a private channel 500, a public one 1,000. Leaves cap devices. */
const MAX_USERS: Record<Kind, number> = { dm: 2, group_dm: 9, private: 500, public: 1000, self: 1 };
const MAX_LEAVES: Record<Kind, number> = { dm: 16, group_dm: 64, private: 1000, public: 1000, self: 16 };
export const LOG_TTL = 30 * 86400000, WELCOME_TTL = 30 * 86400000, MAX_BACKLOG = 10000, MAX_WELCOMES_PER_DEVICE = 100, WELCOME_COPY_BUDGET = 64 * 1024 * 1024;
const COMMIT_MAX = 8 * 1024 * 1024, SMALL_MAX = 131072, INFLIGHT = 32, INLINE_MAX = 48 * 1024, PAGE = 50, PAGE_BYTES = 2 * 1024 * 1024, SWEEP_EVERY = 60000, REPORT_INTERVAL = 60000;
const ID = /^[A-Za-z0-9_-]{22}$/, B64 = /^[A-Za-z0-9_-]+$/, DIGEST = /^[0-9a-f]{64}$/, SIG = /^[A-Za-z0-9_-]{86}$/;
const NAME = /^[\p{L}\p{N}_\- ]{1,64}$/u;
const EPHEMERAL_B64_MAX = Math.ceil(2048 * 4 / 3) + 4, GROUP_INFO_B64_MAX = 87382, WELCOME_B64_MAX = Math.ceil(4 * 1024 * 1024 * 4 / 3), COMMIT_B64_MAX = Math.ceil(1024 * 1024 * 4 / 3) + 4, APP_B64_MAX = Math.ceil(64 * 1024 * 4 / 3) + 4;

type Caller = { id: string; username: string; session: string };
type Row = { id: string; kind: Kind; name: string | null; creator_id: string; epoch: number; seq: number; group_info: string | null; group_info_epoch: number | null; prev_state: string | null; prev_epoch: number | null; frozen_seq: number | null; frozen_digest: string | null; frozen_by: string | null; frozen_at: number | null };
type Member = { channel_id: string; device_id: string; user_id: string; admin: number; cursor: number; joined_seq: number };
type MemberView = { userId: string; deviceId: string; admin: boolean };
export type GroupConnection = { kind: 'events'; userId: string; session: string; sent: Set<string>; groups: Map<string, number> };
const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });

/**
 * What an admin device signs to resolve a frozen channel: its device key over these exact UTF-8 bytes. `author` is
 * empty unless the rollback removes the commit's author: then it is that device as the admin's own copy of the
 * group authenticated it, and only when the failure lay in what the author signed (a tag the server could have
 * corrupted in transit proves nothing about the author). The server can neither choose whom a rollback cuts off
 * nor apply the signature to another commit.
 */
export const resolveBytes = (channelId: string, action: string, seq: number, digest: string, author: string) => Buffer.from(`webrtc-bun-mlsresolve-v2\n${channelId}\n${action}\n${seq}\n${digest}\n${author}`);

type Deps = {
    db: Database; now: () => number; origin: string; ds: DsCore; keyPackages: KeyPackages;
    eligible(userId: string, deviceId: string | null): boolean;
    sessionDevice(session: string): string | null;
    sigKey(deviceId: string): string | null;
    aikOf(userId: string): string | null;
    identityChange?(userId: string): { aik: string; event: string } | null;
    mutual(a: string, b: string): boolean;
    userByName(username: string): { id: string; username: string } | null;
    notify(userId: string, event: object): void;
    streams(userId: string): Iterable<ServerWebSocket<GroupConnection>>;
    /** Delivers what now waits to the user's open streams. */
    pumpUser(userId: string): void;
};

function ed25519Verify(key: string, bytes: Uint8Array, signature: unknown) {
    if (typeof signature !== 'string' || !SIG.test(signature)) return false;
    try { return verify(null, bytes, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key }, format: 'jwk' }), Buffer.from(signature, 'base64url')); } catch { return false; }
}
async function readJson(request: Request, max: number): Promise<Record<string, any> | null> {
    try { const text = await request.text(); if (text.length > max) return null; const value = JSON.parse(text); return value && typeof value === 'object' && !Array.isArray(value) ? value : null; } catch { return null; }
}
/** The wire format of an MLS message (RFC 9420 §6): 1 public (handshake), 2 private (application). */
function wireFormat(bytes: Buffer) { return bytes.length >= 4 && bytes[0] === 0 && bytes[1] === 1 ? (bytes[2]! << 8) | bytes[3]! : 0; }
const decode = (text: unknown, max: number) => {
    if (typeof text !== 'string' || !text.length || text.length > max || !B64.test(text)) return null;
    const bytes = Buffer.from(text, 'base64url');
    return bytes.toString('base64url') === text ? bytes : null;
};

export function createChannels(deps: Deps) {
    const { db, now } = deps;
    const allowCreate = requestLimiter({ perSource: 10, global: 200 }), allowMessage = requestLimiter({ perSource: 30, global: 2000 }), allowCommit = requestLimiter({ perSource: 15, global: 300 });
    const allowRead = requestLimiter({ perSource: 40, global: 1000 }), allowCursor = requestLimiter({ perSource: 100, global: 4000 }), allowPoison = requestLimiter({ perSource: 10, global: 100 });
    const lastFreeze = new Map<string, number>();
    const allowJoin = requestLimiter({ perSource: 3, global: 100 }), allowInfo = requestLimiter({ perSource: 10, global: 200 });
    const allowEphemeral = requestLimiter({ perSource: 10, global: 2000 }), allowIdentity = requestLimiter({ perSource: 20, global: 1000 });

    const channelRow = (id: string) => db.query<Row, [string]>('SELECT * FROM channels WHERE id = ?').get(id);
    const memberRow = (channelId: string, deviceId: string) => db.query<Member, [string, string]>('SELECT * FROM channel_members WHERE channel_id = ? AND device_id = ?').get(channelId, deviceId);
    const members = (channelId: string) => db.query<Member, [string]>('SELECT * FROM channel_members WHERE channel_id = ? ORDER BY device_id').all(channelId);
    const userInChannel = (channelId: string, userId: string) => Boolean(db.query('SELECT 1 FROM channel_members WHERE channel_id = ? AND user_id = ? LIMIT 1').get(channelId, userId));
    const banned = (channelId: string, deviceId: string) => Boolean(db.query('SELECT 1 FROM channel_bans WHERE channel_id = ? AND device_id = ?').get(channelId, deviceId));
    const usersOf = (rows: { user_id: string }[]) => [...new Set(rows.map(row => row.user_id))];
    const welcomeBudget = (deviceId: string) => db.query<{ count: number }, [string]>('SELECT COUNT(*) AS count FROM mls_welcomes WHERE device_id = ?').get(deviceId)!.count;

    /** The caller's session device, if it may use groups at all. */
    function deviceOf(user: Caller): [string, null] | [null, Response] {
        const id = deps.sessionDevice(user.session);
        if (!id) return [null, json({ error: 'Announce this device first.' }, 409)];
        if (!deps.eligible(user.id, id)) return [null, json({ error: 'This device is not in your signed device list.' }, 403)];
        return [id, null];
    }

    // ---------- Membership mirror ----------

    /**
     * Replaces the channel's member rows with the validator's view of the tree. New devices must be listed devices
     * of their account (a certificate-valid leaf for a device the signed list does not name is refused); the kind's
     * user and leaf limits hold. Returns who joined and who left.
     */
    function mirror(channel: Row, tree: MemberView[], seq: number) {
        const old = new Map(members(channel.id).map(row => [row.device_id, row]));
        const blocked = new Set(db.query<{ device_id: string }, [string]>('SELECT device_id FROM channel_bans WHERE channel_id = ?').all(channel.id).map(row => row.device_id));
        const next = tree.filter(member => !blocked.has(member.deviceId));
        if (next.length > MAX_LEAVES[channel.kind] || new Set(next.map(member => member.userId)).size > MAX_USERS[channel.kind]) throw new Abort(422, `A ${channel.kind.replace('_', ' ')} is limited to ${MAX_USERS[channel.kind]} people and ${MAX_LEAVES[channel.kind]} devices.`);
        if (channel.kind === 'self' && next.some(member => member.userId !== channel.creator_id)) throw new Abort(422, 'A self group holds only its owner\'s devices.');
        const added: { userId: string; deviceId: string }[] = [], keep = new Set<string>();
        for (const member of next) {
            keep.add(member.deviceId);
            if (!old.has(member.deviceId)) {
                if (!deps.eligible(member.userId, member.deviceId)) throw new Abort(422, 'A group member is not a device in its owner\'s signed device list.');
                added.push({ userId: member.userId, deviceId: member.deviceId });
                db.query('INSERT INTO channel_members (channel_id, device_id, user_id, admin, cursor, joined_seq) VALUES (?, ?, ?, ?, ?, ?)').run(channel.id, member.deviceId, member.userId, member.admin ? 1 : 0, seq, seq);
            } else {
                const row = old.get(member.deviceId)!;
                db.query('UPDATE channel_members SET admin = ?, cursor = ?, joined_seq = ? WHERE channel_id = ? AND device_id = ?').run(member.admin ? 1 : 0, Math.min(row.cursor, seq), Math.min(row.joined_seq, seq), channel.id, member.deviceId);
            }
        }
        const removed = [...old.values()].filter(row => !keep.has(row.device_id)).map(row => ({ userId: row.user_id, deviceId: row.device_id }));
        for (const gone of removed) db.query('DELETE FROM channel_members WHERE channel_id = ? AND device_id = ?').run(channel.id, gone.deviceId);
        return { added, removed };
    }
    const treeOf = (call: (c: Record<string, unknown>) => any, id: string): MemberView[] => (call({ cmd: 'dsMembers', group: id }).members as { userId: string; deviceId: string; admin: boolean }[]).map(m => ({ userId: m.userId, deviceId: m.deviceId, admin: m.admin }));

    /** Tells the affected users' open streams what changed, after the transaction committed. */
    function announce(channelId: string, change: { added?: { userId: string; deviceId: string }[]; removed?: { userId: string; deviceId: string }[]; extra?: object }) {
        const stay = new Set(usersOf(members(channelId)));
        for (const user of new Set((change.added ?? []).map(item => item.userId))) deps.notify(user, { type: 'channel', id: channelId, change: 'joined' });
        for (const user of new Set((change.removed ?? []).map(item => item.userId))) deps.notify(user, { type: 'channel', id: channelId, change: stay.has(user) ? 'updated' : 'left' });
        for (const user of stay) deps.pumpUser(user);
        for (const user of new Set((change.added ?? []).map(item => item.userId))) deps.pumpUser(user);
    }

    // ---------- Creating channels ----------

    async function create(request: Request, user: Caller): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        if (!allowCreate(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request, 262144);
        const kind = body?.kind as Kind;
        if (!body || !ID.test(body.id) || !KINDS.includes(kind)) return json({ error: 'Invalid channel' }, 400);
        const groupInfo = decode(body.groupInfo, GROUP_INFO_B64_MAX), tree = decode(body.tree, 262144);
        if (!groupInfo || !tree) return json({ error: 'Invalid group' }, 400);
        let name: string | null = null;
        if (kind === 'public') {
            name = typeof body.name === 'string' ? body.name.trim() : '';
            if (!NAME.test(name)) return json({ error: 'Public channels have a name of 1–64 letters, digits, spaces, - or _.' }, 400);
        } else if (body.name !== undefined && body.name !== null) return json({ error: 'Only public channels have a name the server can see.' }, 400);
        let peer: { id: string; username: string } | null = null;
        if (kind === 'dm') {
            peer = typeof body.peer === 'string' ? deps.userByName(body.peer) : null;
            if (!peer || peer.id === user.id || !deps.mutual(user.id, peer.id)) return json({ error: 'You can only reach accepted contacts.' }, 403);
            const [a, b] = [user.id, peer.id].sort();
            if (db.query('SELECT 1 FROM dm_pairs WHERE user_a = ? AND user_b = ?').get(a, b)) return json({ error: 'You already have a conversation with that person.' }, 409);
        }
        if (channelRow(body.id)) return json({ error: 'That channel id is taken.' }, 409);
        try {
            deps.ds.transaction(call => {
                pinAccounts(deps, call, peer ? [user.id, peer.id] : [user.id]);
                call({ cmd: 'dsCreate', groupInfo: body.groupInfo, tree: body.tree });
                const state = call({ cmd: 'dsMembers', group: body.id }) as { epoch: number; roles: { kind: string; admins: string[]; joinPolicy: string; dm?: string[] }; members: { userId: string; deviceId: string; admin: boolean }[] };
                // The creator's own device is the group's only leaf, and the roles say what the channel's kind says.
                if (state.members.length !== 1 || state.members[0]!.deviceId !== deviceId || state.members[0]!.userId !== user.id) throw new Abort(422, 'A new group holds only the creating device.');
                const { roles } = state;
                const fits = kind === 'dm' ? roles.kind === 'dm' && roles.dm?.join() === [user.id, peer!.id].sort().join()
                    : roles.kind === 'group' && roles.joinPolicy === (kind === 'public' ? 'open' : 'invite') && roles.admins.includes(user.id) && (kind !== 'self' || roles.admins.join() === user.id);
                if (!fits) throw new Abort(422, 'The group\'s roles do not match this kind of channel.');
                db.query('INSERT INTO channels (id, kind, name, creator_id, epoch, seq, group_info, group_info_epoch, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)').run(body.id, kind, name, user.id, state.epoch, body.groupInfo, state.epoch, now());
                db.query('INSERT INTO channel_members (channel_id, device_id, user_id, admin, cursor, joined_seq) VALUES (?, ?, ?, ?, 0, 0)').run(body.id, deviceId, user.id, state.members[0]!.admin ? 1 : 0);
                if (peer) { const [a, b] = [user.id, peer.id].sort(); db.query('INSERT INTO dm_pairs (user_a, user_b, channel_id) VALUES (?, ?, ?)').run(a, b, body.id); }
            });
        } catch (error) {
            if (error instanceof Abort) return json({ error: error.message, ...error.extra }, error.status);
            if (error instanceof DsError) return json({ error: error.message, code: error.code }, 422);
            if (String((error as Error)?.message).includes('UNIQUE')) return json({ error: 'That channel already exists.' }, 409);
            throw error;
        }
        deps.notify(user.id, { type: 'channel', id: body.id, change: 'joined' });
        if (peer) deps.notify(peer.id, { type: 'channel', id: body.id, change: 'invited' });
        return json({ id: body.id, epoch: 0, seq: 0 }, 201);
    }

    // ---------- Sequencing ----------

    /**
     * Sequences one message of a channel. `kind`: an application message, a commit by a member, or an external
     * join. Everything happens in one transaction with the validator's state: the epoch check and the shared
     * validator, the log entry, the membership mirror, Welcomes. Anything that fails afterwards (limits, a joiner
     * who is not a listed device, a Welcome that doesn't match the tree) discards the validator's advance too.
     */
    function sequence(user: Caller, deviceId: string, channelId: string, text: string, bytes: Buffer, mode: 'app' | 'commit' | 'external', extra: { welcome?: Buffer; joiners?: string[] }): Response {
        let result: { status: number; body: object; announce?: Parameters<typeof announce>[1] };
        try {
            result = deps.ds.transaction(call => {
                const channel = channelRow(channelId);
                if (!channel) throw new Abort(404, 'No such channel.');
                if (channel.frozen_seq !== null) throw new Abort(423, 'This channel is frozen while a rejected commit is resolved.', { frozen: { seq: channel.frozen_seq, digest: channel.frozen_digest } });
                const current = members(channelId);
                if (mode !== 'external' && !current.some(row => row.device_id === deviceId)) throw new Abort(403, 'This device is not in that channel.');
                if (banned(channelId, deviceId)) throw new Abort(403, 'This device was removed from that channel.');
                const backlog = db.query<{ count: number }, [string]>('SELECT COUNT(*) AS count FROM group_log WHERE channel_id = ?').get(channelId)!.count;
                if (backlog >= MAX_BACKLOG) throw new Abort(507, 'This channel has too many unread messages. Members must catch up first.');
                const joinerRows = (extra.joiners ?? []).map(id => db.query<{ id: string; user_id: string }, [string]>('SELECT id, user_id FROM devices WHERE id = ?').get(id));
                for (const row of joinerRows) {
                    if (!row || !deps.eligible(row.user_id, row.id)) throw new Abort(403, 'A joiner is not a device in its owner\'s signed device list.');
                    // New people come from the committer's contacts (or are the committer's own devices); public channels
                    // are joined by the person themselves, and the validator decides who may add whom.
                    if (row.user_id !== user.id && !userInChannel(channelId, row.user_id) && !deps.mutual(user.id, row.user_id)) throw new Abort(403, 'You can only add accepted contacts.');
                }
                // Certificates are checked against pinned account keys: needed for handshakes, not for application messages.
                if (mode !== 'app') pinAccounts(deps, call, [user.id, ...usersOf(current), ...joinerRows.map(row => row!.user_id)]);
                const before = mode === 'app' ? null : call({ cmd: 'dsSnapshot', group: channelId }) as string;
                const verdict = call({ cmd: 'dsSubmit', group: channelId, message: text, expect: mode === 'app' ? 'application' : 'commit' }) as { accepted?: { epoch: number; digest: string }; conflict?: { epoch: number } };
                if (verdict.conflict) return { status: 409, body: { error: 'The group moved on. Fetch the log from your cursor, rebuild and retry.', epoch: verdict.conflict.epoch, seq: channel.seq } };
                const seq = channel.seq + 1, digest = verdict.accepted!.digest, created = now();
                db.query('INSERT INTO group_log (channel_id, seq, epoch, kind, sender_user, sender_device, digest, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
                    .run(channelId, seq, channel.epoch, mode === 'app' ? 'app' : 'commit', user.id, deviceId, digest, bytes, created);
                if (mode === 'app') {
                    db.query('UPDATE channels SET seq = ? WHERE id = ?').run(seq, channelId);
                    return { status: 201, body: { epoch: channel.epoch, seq, digest }, announce: {} };
                }
                const epoch = verdict.accepted!.epoch;
                const updated: Row = { ...channel, epoch, seq };
                const change = mirror(updated, treeOf(call, channelId), seq);
                const added = change.added.map(item => item.deviceId).sort();
                if (mode === 'external') {
                    // An external join adds at most the caller's own device (a resync replaces it in place).
                    if (!members(channelId).some(row => row.device_id === deviceId) || change.added.some(item => item.deviceId !== deviceId)) throw new Abort(422, 'An external join adds only the joining device.');
                    db.query('UPDATE channel_members SET cursor = ?, joined_seq = ? WHERE channel_id = ? AND device_id = ?').run(seq, seq, channelId, deviceId);
                } else if (JSON.stringify(added) !== JSON.stringify([...new Set(extra.joiners ?? [])].sort()) || (added.length > 0) !== (extra.welcome !== undefined)) {
                    throw new Abort(422, 'The Welcome and its joiners must match the devices this commit adds.');
                }
                if (extra.welcome && added.length) {
                    if (extra.welcome.length * added.length > WELCOME_COPY_BUDGET) throw new Abort(413, 'That Welcome is too large for this many devices.');
                    const treeBytes = Buffer.from(call({ cmd: 'dsTree', group: channelId }) as string, 'base64url');
                    for (const id of added) {
                        if (welcomeBudget(id) >= MAX_WELCOMES_PER_DEVICE) throw new Abort(429, 'A device has too many Welcomes waiting.');
                        db.query('INSERT INTO mls_welcomes (id, device_id, channel_id, sender_id, epoch, seq, welcome, tree, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
                            .run(randomBytes(16).toString('base64url'), id, channelId, user.id, epoch, seq, extra.welcome, treeBytes, created);
                    }
                }
                db.query('UPDATE channels SET epoch = ?, seq = ?, prev_state = ?, prev_epoch = ? WHERE id = ?').run(epoch, seq, before, channel.epoch, channelId);
                return { status: 201, body: { epoch, seq, digest }, announce: change };
            });
        } catch (error) {
            if (error instanceof Abort) return json({ error: error.message, ...error.extra }, error.status);
            if (error instanceof DsError) return json({ error: error.message, code: error.code }, error.code === 'unknown-group' ? 404 : 422);
            throw error;
        }
        if (result.announce) announce(channelId, result.announce);
        return json(result.body, result.status);
    }

    /** Common gate for the three sequencing endpoints: auth, membership, freeze and rate limits, before any body is read. */
    async function submit(request: Request, user: Caller, channelId: string, mode: 'app' | 'commit' | 'external'): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const channel = channelRow(channelId);
        // Not a member (and not allowed to be) looks the same as no such channel.
        const member = channel ? memberRow(channelId, deviceId!) : null;
        if (!channel || (mode === 'external' ? !(channel.kind === 'public' || userInChannel(channelId, user.id)) : !member)) return json({ error: 'No such channel.' }, 404);
        if (banned(channelId, deviceId!)) return json({ error: 'This device was removed from that channel.' }, 403);
        if (channel.frozen_seq !== null) return json({ error: 'This channel is frozen while a rejected commit is resolved.', frozen: { seq: channel.frozen_seq, digest: channel.frozen_digest } }, 423);
        if (!(mode === 'app' ? allowMessage : mode === 'commit' ? allowCommit : allowJoin)(user.id)) return json({ error: 'Rate limited' }, 429);
        // Roles before the body: only admins (and anyone in a public channel) may send large commits; a plain
        // member's commit is a self-update or removing their own device, which is small.
        const declared = Number(request.headers.get('content-length') ?? 0);
        const cap = mode === 'app' ? SMALL_MAX : mode === 'external' ? SMALL_MAX : (member!.admin || channel.kind === 'public') ? COMMIT_MAX : SMALL_MAX;
        if (declared > cap) return json({ error: 'Request too large' }, 413);
        const body = await readJson(request, cap);
        const bytes = decode(body?.message, mode === 'app' ? APP_B64_MAX : COMMIT_B64_MAX);
        if (!body || !bytes) return json({ error: 'Invalid message' }, 400);
        const wf = wireFormat(bytes);
        if (wf !== (mode === 'app' ? 2 : 1)) return json({ error: mode === 'app' ? 'Application messages are private MLS messages.' : 'Commits are public MLS messages.' }, 400);
        let welcome: Buffer | undefined, joiners: string[] | undefined;
        if (mode === 'commit') {
            if (body.welcome !== undefined) {
                const w = decode(body.welcome, WELCOME_B64_MAX);
                if (!w || !Array.isArray(body.joiners) || !body.joiners.length || body.joiners.length > 128 || !body.joiners.every((id: unknown) => typeof id === 'string' && ID.test(id))) return json({ error: 'Invalid Welcome' }, 400);
                welcome = w; joiners = body.joiners;
            } else if (body.joiners !== undefined && !(Array.isArray(body.joiners) && !body.joiners.length)) return json({ error: 'Joiners need a Welcome.' }, 400);
        } else if (body.welcome !== undefined || body.joiners !== undefined) return json({ error: 'Only commits carry a Welcome.' }, 400);
        return sequence(user, deviceId!, channelId, body.message, bytes, mode, { welcome, joiners });
    }

    // ---------- Reading ----------

    const logEntry = (row: { seq: number; epoch: number; kind: string; sender_user: string; sender_device: string; message: Uint8Array; created_at: number }) =>
        ({ seq: row.seq, epoch: row.epoch, kind: row.kind, from: { userId: row.sender_user, deviceId: row.sender_device }, message: Buffer.from(row.message).toString('base64url'), createdAt: row.created_at });
    const LOG_COLUMNS = 'seq, epoch, kind, sender_user, sender_device, message, created_at';

    function log(url: URL, user: Caller, channelId: string): Response {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const member = memberRow(channelId, deviceId!);
        if (!member) return json({ error: 'No such channel.' }, 404);
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const raw = url.searchParams.get('after');
        const requested = raw === null ? member.cursor : /^\d{1,12}$/.test(raw) ? Number(raw) : -1;
        if (requested < 0) return json({ error: 'Invalid cursor' }, 400);
        // A device reads only what was sequenced after it joined, whatever it asks for.
        const after = Math.max(requested, member.joined_seq);
        const rows = db.query<any, [string, number, number]>(`SELECT ${LOG_COLUMNS} FROM group_log WHERE channel_id = ? AND seq > ? ORDER BY seq LIMIT ?`).all(channelId, after, PAGE);
        const entries: object[] = [];
        let bytes = 0;
        for (const row of rows) {
            bytes += row.message.length;
            if (entries.length && bytes > PAGE_BYTES) break;
            entries.push(logEntry(row));
        }
        const channel = channelRow(channelId)!;
        const oldest = db.query<{ seq: number | null }, [string]>('SELECT MIN(seq) AS seq FROM group_log WHERE channel_id = ?').get(channelId)!.seq;
        // The log has been trimmed past this device's position: it can't catch up from here.
        const gap = after < channel.seq && oldest !== null && oldest > after + 1 || (oldest === null && after < channel.seq);
        return json({ epoch: channel.epoch, seq: channel.seq, cursor: member.cursor, entries, more: entries.length < rows.length || rows.length === PAGE, gap, ...(channel.frozen_seq !== null ? { frozen: { seq: channel.frozen_seq, digest: channel.frozen_digest } } : {}) });
    }

    function info(user: Caller, channelId: string): Response {
        const channel = channelRow(channelId);
        if (!channel || !userInChannel(channelId, user.id)) return json({ error: 'No such channel.' }, 404);
        return json(describe(channel, user));
    }
    function describe(channel: Row, user: Caller) {
        const mine = db.query<Member, [string, string]>('SELECT * FROM channel_members WHERE channel_id = ? AND user_id = ? ORDER BY device_id').all(channel.id, user.id);
        const device = deps.sessionDevice(user.session);
        const here = mine.find(row => row.device_id === device);
        const base = { id: channel.id, kind: channel.kind, name: channel.name, epoch: channel.epoch, seq: channel.seq, frozen: channel.frozen_seq !== null, member: Boolean(here), cursor: here?.cursor ?? null, admin: mine.some(row => row.admin) };
        if (channel.kind !== 'dm') return base;
        // A DM names the other person, so a client can tie it to the 1:1 conversation it replaces (docs/m5-linking.md §8).
        const pair = db.query<{ user_a: string; user_b: string }, [string]>('SELECT user_a, user_b FROM dm_pairs WHERE channel_id = ?').get(channel.id);
        const peerId = pair ? (pair.user_a === user.id ? pair.user_b : pair.user_a) : null;
        const peer = peerId ? db.query<{ id: string; username: string }, [string]>('SELECT id, username FROM users WHERE id = ?').get(peerId) : null;
        return { ...base, peer: peer ? { id: peer.id, username: peer.username } : null };
    }
    function list(user: Caller): Response {
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const rows = db.query<Row, [string]>('SELECT c.* FROM channels c WHERE c.id IN (SELECT channel_id FROM channel_members WHERE user_id = ?) ORDER BY c.created_at, c.id').all(user.id);
        return json({ channels: rows.map(row => describe(row, user)) });
    }
    function memberList(user: Caller, channelId: string): Response {
        if (!userInChannel(channelId, user.id)) return json({ error: 'No such channel.' }, 404);
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const rows = db.query<{ user_id: string; username: string; device_id: string; admin: number; cursor: number }, [string]>('SELECT m.user_id, u.username, m.device_id, m.admin, m.cursor FROM channel_members m JOIN users u ON u.id = m.user_id WHERE m.channel_id = ? ORDER BY m.user_id, m.device_id').all(channelId);
        return json({ members: rows.map(row => ({ userId: row.user_id, username: row.username, deviceId: row.device_id, admin: Boolean(row.admin) })) });
    }

    /** What a device needs to join externally: the latest GroupInfo and the tree of the same epoch. */
    function joinInfo(user: Caller, channelId: string): Response {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const channel = channelRow(channelId);
        if (!channel || !(channel.kind === 'public' || userInChannel(channelId, user.id)) || banned(channelId, deviceId!)) return json({ error: 'No such channel.' }, 404);
        if (!allowInfo(user.id)) return json({ error: 'Rate limited' }, 429);
        if (channel.group_info === null || channel.group_info_epoch !== channel.epoch) return json({ error: 'The group is between epochs. Try again shortly.', epoch: channel.epoch }, 409);
        const tree = deps.ds.transaction(call => call({ cmd: 'dsTree', group: channelId }) as string);
        return json({ epoch: channel.epoch, seq: channel.seq, groupInfo: channel.group_info, tree });
    }
    async function putGroupInfo(request: Request, user: Caller, channelId: string): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const channel = channelRow(channelId);
        if (!channel || !memberRow(channelId, deviceId!)) return json({ error: 'No such channel.' }, 404);
        if (!allowInfo(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request, SMALL_MAX);
        if (!body || !Number.isSafeInteger(body.epoch) || !decode(body.groupInfo, GROUP_INFO_B64_MAX)) return json({ error: 'Invalid GroupInfo' }, 400);
        // Only for the epoch the group is at now; joiners verify its signature and its tree themselves.
        if (body.epoch !== channel.epoch) return json({ error: 'The group is at another epoch.', epoch: channel.epoch }, 409);
        db.query('UPDATE channels SET group_info = ?, group_info_epoch = ? WHERE id = ?').run(body.groupInfo, body.epoch, channelId);
        return json({ epoch: body.epoch });
    }

    // ---------- M5: capability, revoked devices (docs/m5-linking.md §4, §8) ----------

    /** Whether a contact can take part in MLS DMs: how many of their listed devices hold KeyPackages, and the DM that exists. */
    function capability(user: Caller, username: string): Response {
        const target = deps.userByName(username);
        if (!target || (target.id !== user.id && !deps.mutual(user.id, target.id))) return json({ error: 'You can only reach accepted contacts.' }, 403);
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const seconds = Math.floor(now() / 1000);
        const holders = db.query<{ device_id: string }, [string, number]>('SELECT DISTINCT device_id FROM mls_key_packages WHERE user_id = ? AND expires_at > ?').all(target.id, seconds).filter(row => deps.eligible(target.id, row.device_id));
        const [a, b] = [user.id, target.id].sort();
        const pair = db.query<{ channel_id: string }, [string, string]>('SELECT channel_id FROM dm_pairs WHERE user_a = ? AND user_b = ?').get(a!, b!);
        return json({ userId: target.id, devices: holders.length, channel: pair?.channel_id ?? null });
    }

    /** A device was revoked: it leaves every fan-out and its other devices are told to remove its leaves. */
    function devicesRevoked(userId: string, ids: string[]) {
        for (const deviceId of ids) {
            const where = db.query<{ channel_id: string }, [string]>('SELECT channel_id FROM channel_members WHERE device_id = ?').all(deviceId);
            db.query('DELETE FROM channel_members WHERE device_id = ?').run(deviceId);
            db.query('DELETE FROM mls_welcomes WHERE device_id = ?').run(deviceId);
            db.query('DELETE FROM mls_key_packages WHERE device_id = ?').run(deviceId);
            for (const { channel_id } of where) { deps.notify(userId, { type: 'channel', id: channel_id, change: 'remove-device', deviceId }); trim(channel_id); }
        }
    }

    // ---------- M4: directory, identities, ephemeral messages (docs/m4-groups.md §8) ----------

    /** Public channels anyone may join: their names are the one thing the server sees anyway. */
    function directory(user: Caller): Response {
        const [, refusal] = deviceOf(user);
        if (refusal) return refusal;
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const rows = db.query<{ id: string; name: string; members: number; joined: number }, [string]>(
            "SELECT c.id, c.name, (SELECT COUNT(DISTINCT m.user_id) FROM channel_members m WHERE m.channel_id = c.id) AS members, EXISTS (SELECT 1 FROM channel_members j WHERE j.channel_id = c.id AND j.user_id = ?) AS joined FROM channels c WHERE c.kind = 'public' ORDER BY c.created_at DESC, c.id LIMIT 500").all(user.id);
        return json({ channels: rows.map(row => ({ id: row.id, name: row.name, members: row.members, joined: Boolean(row.joined) })) });
    }
    /**
     * A user's published identity, for pinning people met in a channel (trust on first use). User ids are 128-bit
     * random, so this names no one the caller couldn't already name; the key is the one the validator pins.
     */
    function identity(user: Caller, userId: string): Response {
        if (!allowIdentity(user.id)) return json({ error: 'Rate limited' }, 429);
        const row = db.query<{ id: string; username: string; dh: string; sign: string }, [string]>('SELECT u.id, u.username, k.dh, k.sign FROM users u JOIN identity_keys k ON k.user_id = u.id WHERE u.id = ?').get(userId);
        return row ? json({ userId: row.id, username: row.username, identity: { dh: row.dh, sign: row.sign } }) : json({ error: 'No such user.' }, 404);
    }
    /**
     * A live-only application message (typing): checked for the current epoch, then handed to the open streams of
     * the channel's other member devices. Never logged, stored, pushed or replayed.
     */
    async function ephemeral(request: Request, user: Caller, channelId: string): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const channel = channelRow(channelId);
        if (!channel || !memberRow(channelId, deviceId!)) return json({ error: 'No such channel.' }, 404);
        if (banned(channelId, deviceId!)) return json({ error: 'This device was removed from that channel.' }, 403);
        if (channel.frozen_seq !== null) return json({ error: 'This channel is frozen while a rejected commit is resolved.' }, 423);
        if (!allowEphemeral(user.id)) return json({ error: 'Rate limited' }, 429);
        if (Number(request.headers.get('content-length') ?? 0) > 4096) return json({ error: 'Request too large' }, 413);
        const body = await readJson(request, 4096);
        const bytes = decode(body?.message, EPHEMERAL_B64_MAX);
        if (!body || !bytes || Object.keys(body).length !== 1) return json({ error: 'Invalid message' }, 400);
        if (wireFormat(bytes) !== 2) return json({ error: 'Application messages are private MLS messages.' }, 400);
        let verdict: { accepted?: unknown; conflict?: { epoch: number } };
        try { verdict = deps.ds.transaction(call => call({ cmd: 'dsSubmit', group: channelId, message: body.message, expect: 'application' })); }
        catch (error) { if (error instanceof DsError) return json({ error: error.message, code: error.code }, 422); throw error; }
        if (verdict.conflict) return json({ error: 'The group moved on.', epoch: verdict.conflict.epoch }, 409);
        const frame = JSON.stringify({ type: 'ephemeral', channel: channelId, from: { userId: user.id, deviceId }, message: body.message, createdAt: now() });
        let delivered = false;
        const devices = new Set(members(channelId).filter(row => row.device_id !== deviceId).map(row => row.device_id));
        for (const userId of usersOf(members(channelId))) {
            for (const socket of deps.streams(userId)) {
                // Best effort: a stream that is closing or backed up simply misses a typing hint.
                if (socket.readyState !== 1 || socket.getBufferedAmount() > 65536) continue;
                const device = deps.sessionDevice(socket.data.session);
                if (device && devices.has(device) && deps.eligible(userId, device)) { socket.send(frame); delivered = true; }
            }
        }
        return json({ delivered }, 202);
    }

    // ---------- Cursors and retention ----------

    /** Drops the log entries every member device has read. */
    function trim(channelId: string) {
        const channel = channelRow(channelId);
        const floor = db.query<{ floor: number | null }, [string]>("SELECT MIN(m.cursor) AS floor FROM channel_members m JOIN devices d ON d.id = m.device_id WHERE m.channel_id = ? AND d.state != 'revoked'").get(channelId)?.floor;
        if (!channel || floor === null || floor === undefined || floor <= 0) return;
        // A frozen commit stays until it is resolved.
        db.query('DELETE FROM group_log WHERE channel_id = ? AND seq <= ? AND seq < ?').run(channelId, floor, channel.frozen_seq ?? Number.MAX_SAFE_INTEGER);
    }
    function setCursor(user: { id: string }, deviceId: string, channelId: string, seq: number): number | null {
        const channel = channelRow(channelId), member = channel ? memberRow(channelId, deviceId) : null;
        if (!channel || !member || seq > channel.seq || seq < 0) return null;
        const next = Math.max(member.cursor, seq);
        if (next !== member.cursor) db.query('UPDATE channel_members SET cursor = ? WHERE channel_id = ? AND device_id = ?').run(next, channelId, deviceId);
        trim(channelId);
        return next;
    }
    async function cursorRequest(request: Request, user: Caller, channelId: string): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        if (!allowCursor(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request, 1024);
        if (!body || !Number.isSafeInteger(body.seq)) return json({ error: 'Invalid cursor' }, 400);
        const cursor = setCursor(user, deviceId!, channelId, body.seq);
        return cursor === null ? json({ error: 'No such channel or position.' }, 404) : json({ cursor });
    }

    // ---------- Welcomes ----------

    function welcomes(user: Caller): Response {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const rows = db.query<any, [string, number]>('SELECT id, channel_id, sender_id, epoch, seq, LENGTH(welcome) + LENGTH(tree) AS size, created_at FROM mls_welcomes WHERE device_id = ? AND created_at > ? ORDER BY created_at, id LIMIT 100').all(deviceId!, now() - WELCOME_TTL);
        return json({ welcomes: rows.map(row => ({ id: row.id, channel: row.channel_id, from: row.sender_id, epoch: row.epoch, seq: row.seq, size: row.size, createdAt: row.created_at })) });
    }
    function welcome(user: Caller, id: string, remove: boolean): Response {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        if (!allowRead(user.id)) return json({ error: 'Rate limited' }, 429);
        const row = db.query<any, [string, string]>('SELECT * FROM mls_welcomes WHERE id = ? AND device_id = ?').get(id, deviceId!);
        if (!row) return json({ error: 'No such Welcome.' }, 404);
        if (remove) { db.query('DELETE FROM mls_welcomes WHERE id = ?').run(id); return json({ status: 'removed' }); }
        return json({ id: row.id, channel: row.channel_id, from: row.sender_id, epoch: row.epoch, seq: row.seq, welcome: Buffer.from(row.welcome).toString('base64url'), tree: Buffer.from(row.tree).toString('base64url'), createdAt: row.created_at });
    }

    // ---------- Poison commits ----------

    /**
     * A member reports a sequenced commit it rejected. The validator can't check a commit's confirmation and
     * membership tags (they need epoch secrets), so a faulty or malicious member can sequence a commit every member
     * rejects. Reports freeze the channel: only the latest commit can be reported, nothing more is sequenced, and
     * an admin device (which re-checks the commit itself) resolves it with a signature.
     */
    async function poison(request: Request, user: Caller, channelId: string): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const channel = channelRow(channelId);
        if (!channel || !memberRow(channelId, deviceId!)) return json({ error: 'No such channel.' }, 404);
        if (!allowPoison(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request, 2048);
        if (!body || !Number.isSafeInteger(body.seq) || typeof body.digest !== 'string' || !DIGEST.test(body.digest)) return json({ error: 'Invalid report' }, 400);
        if (channel.frozen_seq !== null) return channel.frozen_seq === body.seq && channel.frozen_digest === body.digest ? json({ frozen: true }) : json({ error: 'This channel is already frozen.', frozen: { seq: channel.frozen_seq, digest: channel.frozen_digest } }, 409);
        const entry = db.query<{ kind: string; digest: string; sender_device: string }, [string, number]>('SELECT kind, digest, sender_device FROM group_log WHERE channel_id = ? AND seq = ?').get(channelId, body.seq);
        // Only the latest commit: anything older was accepted by members that built on it.
        if (!entry || entry.kind !== 'commit' || entry.digest !== body.digest || body.seq !== channel.seq || channel.prev_state === null) return json({ error: 'That is not the latest sequenced commit.' }, 409);
        if (entry.sender_device === deviceId) return json({ error: 'A commit\'s author cannot report it.' }, 403);
        // One freeze per reporting device per channel per minute, so reports can't keep a channel down.
        const key = `${channelId}:${deviceId}`;
        if (now() - (lastFreeze.get(key) ?? -Infinity) < REPORT_INTERVAL) return json({ error: 'Too many reports from this device. Try again later.' }, 429);
        lastFreeze.set(key, now());
        if (lastFreeze.size > 10000) for (const [k, at] of lastFreeze) if (now() - at >= REPORT_INTERVAL) lastFreeze.delete(k);
        db.query('UPDATE channels SET frozen_seq = ?, frozen_digest = ?, frozen_by = ?, frozen_at = ? WHERE id = ?').run(body.seq, body.digest, deviceId!, now(), channelId);
        for (const admin of usersOf(members(channelId).filter(row => row.admin))) deps.notify(admin, { type: 'channel', id: channelId, change: 'frozen', seq: body.seq, digest: body.digest });
        return json({ frozen: true }, 202);
    }

    /** An admin device resolves a frozen channel: roll the commit back (and remove its author) or dismiss the report. */
    async function resolve(request: Request, user: Caller, channelId: string): Promise<Response> {
        const [deviceId, refusal] = deviceOf(user);
        if (refusal) return refusal;
        const channel = channelRow(channelId), member = channel ? memberRow(channelId, deviceId!) : null;
        if (!channel || !member) return json({ error: 'No such channel.' }, 404);
        if (!member.admin) return json({ error: 'Only an admin device resolves a frozen channel.' }, 403);
        if (!allowPoison(user.id)) return json({ error: 'Rate limited' }, 429);
        const body = await readJson(request, 2048);
        if (!body || !['rollback', 'dismiss'].includes(body.action) || !Number.isSafeInteger(body.seq) || typeof body.digest !== 'string' || !DIGEST.test(body.digest) || typeof body.author !== 'string' || !(body.author === '' || (body.action === 'rollback' && ID.test(body.author)))) return json({ error: 'Invalid resolution' }, 400);
        // A rollback also carries the admin's signature with its MLS leaf key (members check it against their own copy
        // of the group, docs/m4-groups.md §7); the server only passes it on, in the `rolled-back` notice.
        if (body.action === 'rollback' && (typeof body.leafSignature !== 'string' || !SIG.test(body.leafSignature))) return json({ error: 'Invalid resolution' }, 400);
        if (channel.frozen_seq === null || channel.frozen_seq !== body.seq || channel.frozen_digest !== body.digest) return json({ error: 'That commit is not the one this channel is frozen on.' }, 409);
        // The admin device signs exactly what it resolves: the server cannot do this on its own.
        const key = deps.sigKey(deviceId!);
        if (!key || !ed25519Verify(key, resolveBytes(channelId, body.action, body.seq, body.digest, body.author), body.signature)) return json({ error: 'The resolution is not signed by this device.' }, 403);
        // A removal names the author the admin's device authenticated; it must be the device that sent that commit.
        const removing = body.author !== '';
        const reported = db.query<{ sender_device: string }, [string, number]>('SELECT sender_device FROM group_log WHERE channel_id = ? AND seq = ?').get(channelId, body.seq);
        if (removing && (!reported || reported.sender_device !== body.author)) return json({ error: 'That is not the author of the frozen commit.' }, 409);
        if (body.action === 'dismiss') {
            // The dismissed commit can't be reported again: the rollback state it needed is dropped with the report.
            db.query('UPDATE channels SET frozen_seq = NULL, frozen_digest = NULL, frozen_by = NULL, frozen_at = NULL, prev_state = NULL, prev_epoch = NULL WHERE id = ?').run(channelId);
            for (const member of usersOf(members(channelId))) deps.notify(member, { type: 'channel', id: channelId, change: 'thawed' });
            for (const id of usersOf(members(channelId))) deps.pumpUser(id);
            return json({ resolved: 'dismiss' });
        }
        let removed: { userId: string; deviceId: string }[] = [], added: { userId: string; deviceId: string }[] = [], author: string;
        try {
            deps.ds.transaction(call => {
                const fresh = channelRow(channelId)!;
                const entry = db.query<{ sender_device: string; digest: string }, [string, number]>('SELECT sender_device, digest FROM group_log WHERE channel_id = ? AND seq = ?').get(channelId, body.seq);
                if (!entry || entry.digest !== body.digest || fresh.prev_state === null || fresh.prev_epoch === null || fresh.seq !== body.seq) throw new Abort(409, 'That commit can no longer be rolled back.');
                author = entry.sender_device;
                // The validator goes back to the state before the commit; the log entry, its Welcomes and the epoch follow.
                call({ cmd: 'dsRestore', group: channelId, snapshot: fresh.prev_state });
                db.query('DELETE FROM group_log WHERE channel_id = ? AND seq = ?').run(channelId, body.seq);
                db.query('DELETE FROM mls_welcomes WHERE channel_id = ? AND seq = ?').run(channelId, body.seq);
                db.query('UPDATE channels SET epoch = ?, seq = ?, prev_state = NULL, prev_epoch = NULL, group_info_epoch = NULL, frozen_seq = NULL, frozen_digest = NULL, frozen_by = NULL, frozen_at = NULL WHERE id = ?').run(fresh.prev_epoch, body.seq - 1, channelId);
                if (removing) db.query('INSERT OR IGNORE INTO channel_bans (channel_id, device_id, banned_at) VALUES (?, ?, ?)').run(channelId, author, now());
                const restored = { ...fresh, epoch: fresh.prev_epoch, seq: body.seq - 1 };
                ({ added, removed } = mirror(restored, treeOf(call, channelId), body.seq - 1));
            });
        } catch (error) {
            if (error instanceof Abort) return json({ error: error.message, ...error.extra }, error.status);
            if (error instanceof DsError) return json({ error: error.message, code: error.code }, 422);
            throw error;
        }
        announce(channelId, { added, removed });
        // Everyone learns which commit is gone (its author, if it stays, rejoins and makes the change again); then
        // sequencing resumes (members who reported it are waiting for this, as after a dismissal).
        const notice = { type: 'channel', id: channelId, change: 'rolled-back', action: 'rollback', seq: body.seq, digest: body.digest, author: body.author, by: deviceId, byUser: user.id, signature: body.leafSignature };
        for (const member of usersOf(members(channelId))) deps.notify(member, notice);
        for (const member of usersOf(members(channelId))) deps.notify(member, { type: 'channel', id: channelId, change: 'thawed' });
        const restored = { resolved: 'rollback', epoch: channelRow(channelId)!.epoch, seq: body.seq - 1 };
        if (!removing) return json(restored);
        // The author is still a leaf in the restored tree: an admin removes it with an ordinary commit.
        for (const admin of usersOf(members(channelId).filter(row => row.admin))) deps.notify(admin, { type: 'channel', id: channelId, change: 'remove-needed', deviceId: author! });
        return json({ ...restored, removeDevice: author! });
    }

    // ---------- Fan-out ----------

    /** A device that is no longer eligible holds no place in any channel and has no Welcomes waiting. */
    function dropDevice(deviceId: string) {
        // Only a revoked or deleted device loses its place. One that is merely unlisted for now (an account identity change
        // voids the list until the new key's list v1; docs/m5-linking.md §5.3) is withheld by the eligibility gate, not forgotten.
        if (db.query("SELECT 1 FROM devices WHERE id = ? AND state != 'revoked'").get(deviceId)) return;
        db.query('DELETE FROM channel_members WHERE device_id = ?').run(deviceId);
        db.query('DELETE FROM mls_welcomes WHERE device_id = ?').run(deviceId);
    }

    /** Sends a stream's device what it has not been sent: Welcomes, then each channel's log from its cursor. */
    function pump(socket: ServerWebSocket<GroupConnection>) {
        const { session, sent, groups } = socket.data;
        if (socket.readyState !== 1) return;
        const deviceId = deps.sessionDevice(session);
        if (!deviceId) return;
        // The same gate as the HTTP paths: a device that left the signed list (or was revoked) is owed nothing.
        if (!deps.eligible(socket.data.userId, deviceId)) { dropDevice(deviceId); return; }
        const room = () => sent.size < INFLIGHT && socket.getBufferedAmount() <= 16384;
        if (!room()) return;
        for (const row of db.query<any, [string, number]>('SELECT id, channel_id, sender_id, epoch, seq, LENGTH(welcome) + LENGTH(tree) AS size, created_at FROM mls_welcomes WHERE device_id = ? AND created_at > ? ORDER BY created_at, id LIMIT 16').all(deviceId, now() - WELCOME_TTL)) {
            if (sent.has(row.id)) continue;
            if (!room()) return;
            sent.add(row.id);
            const inline = row.size * 4 / 3 <= INLINE_MAX;
            const full = inline ? db.query<any, [string]>('SELECT welcome, tree FROM mls_welcomes WHERE id = ?').get(row.id) : null;
            socket.send(JSON.stringify({ type: 'welcome', id: row.id, channel: row.channel_id, from: row.sender_id, epoch: row.epoch, seq: row.seq, createdAt: row.created_at,
                welcome: full ? Buffer.from(full.welcome).toString('base64url') : null, tree: full ? Buffer.from(full.tree).toString('base64url') : null, ...(inline ? {} : { large: true }) }));
        }
        for (const member of db.query<Member & { frozen_seq: number | null }, [string]>("SELECT m.*, c.frozen_seq FROM channel_members m JOIN channels c ON c.id = m.channel_id WHERE m.device_id = ?").all(deviceId)) {
            let from = Math.max(member.cursor, member.joined_seq, groups.get(member.channel_id) ?? 0);
            const oldest = db.query<{ seq: number | null }, [string]>('SELECT MIN(seq) AS seq FROM group_log WHERE channel_id = ?').get(member.channel_id)!.seq;
            if (oldest !== null && oldest > from + 1 && from === Math.max(member.cursor, member.joined_seq)) {
                // The log was trimmed past this device (30 days): tell it once; it resyncs with an external join.
                socket.send(JSON.stringify({ type: 'channel', id: member.channel_id, change: 'gap', oldest }));
                groups.set(member.channel_id, oldest - 1); from = oldest - 1;
            }
            const budget = INFLIGHT - (from - member.cursor);
            if (budget <= 0) continue;
            for (const row of db.query<any, [string, number, number]>(`SELECT ${LOG_COLUMNS} FROM group_log WHERE channel_id = ? AND seq > ? ORDER BY seq LIMIT ?`).all(member.channel_id, from, budget)) {
                if (!room()) return;
                const inline = row.message.length * 4 / 3 <= INLINE_MAX;
                socket.send(JSON.stringify({ type: 'group', channel: member.channel_id, ...logEntry(row), message: inline ? Buffer.from(row.message).toString('base64url') : null, ...(inline ? {} : { large: true }) }));
                groups.set(member.channel_id, row.seq);
            }
        }
    }
    /** A `cursor` frame: this stream's device has processed the channel up to `seq`. */
    function cursorFrame(socket: ServerWebSocket<GroupConnection>, message: { channel: string; seq: number }) {
        const deviceId = deps.sessionDevice(socket.data.session);
        if (!deviceId || !deps.eligible(socket.data.userId, deviceId)) return;
        if (ID.test(message.channel)) setCursor({ id: socket.data.userId }, deviceId, message.channel, message.seq);
        pump(socket);
    }
    /** An `ack` frame for a Welcome: the device has stored it. */
    function ackWelcome(socket: ServerWebSocket<GroupConnection>, id: string) {
        const deviceId = deps.sessionDevice(socket.data.session);
        if (deviceId && deps.eligible(socket.data.userId, deviceId)) db.query('DELETE FROM mls_welcomes WHERE id = ? AND device_id = ?').run(id, deviceId);
    }

    // ---------- Retention ----------

    let lastSweep = 0;
    /** Drops what retention allows: entries every device has read were dropped on ack; this handles age and departed devices. */
    function sweep(force = false) {
        if (!force && now() - lastSweep < SWEEP_EVERY) return;
        lastSweep = now();
        db.transaction(() => {
            // A revoked device no longer holds a place in anyone's retention.
            const held = db.query<{ device_id: string; user_id: string }, []>('SELECT DISTINCT device_id, user_id FROM channel_members UNION SELECT device_id, (SELECT user_id FROM devices WHERE id = device_id) FROM mls_welcomes').all();
            for (const { device_id, user_id } of held) if (!deps.eligible(user_id, device_id)) dropDevice(device_id);
            db.query('DELETE FROM mls_welcomes WHERE created_at <= ?').run(now() - WELCOME_TTL);
            // The log lives 30 days at most, read or not; a frozen commit waits for its resolution.
            db.query('DELETE FROM group_log WHERE created_at <= ? AND (SELECT frozen_seq FROM channels WHERE id = group_log.channel_id) IS NULL').run(now() - LOG_TTL);
            for (const { id } of db.query<{ id: string }, []>('SELECT id FROM channels').all()) trim(id);
        })();
        deps.keyPackages.sweep();
    }

    // ---------- HTTP ----------

    async function handle(request: Request, url: URL, user: Caller | null): Promise<Response> {
        const keyPackages = deps.keyPackages;
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const bearer = request.headers.get('authorization')?.startsWith('Bearer ') ?? false, origin = request.headers.get('origin');
        // Same rule as every state change: this app's own origin, or a native app's bearer token without one.
        if (request.method !== 'GET' && origin !== deps.origin && !(origin === null && bearer)) return json({ error: 'Origin required' }, 403);
        const path = url.pathname, method = request.method;
        const bodyOf = () => readJson(request, SMALL_MAX);
        if (path === '/api/mls/keypackages') {
            if (method === 'PUT') return keyPackages.upload(request, user, bodyOf);
            if (method === 'GET') return keyPackages.count(user);
        }
        if (path === '/api/mls/keypackages/claim' && method === 'POST') return keyPackages.claim(request, user, bodyOf);
        if (path === '/api/mls/welcomes' && method === 'GET') return welcomes(user);
        const welcomeMatch = /^\/api\/mls\/welcomes\/([A-Za-z0-9_-]{22})$/.exec(path);
        if (welcomeMatch && (method === 'GET' || method === 'DELETE')) return welcome(user, welcomeMatch[1]!, method === 'DELETE');
        if (path === '/api/channels' && method === 'GET') return list(user);
        if (path === '/api/channels/directory' && method === 'GET') return directory(user);
        const capabilityMatch = /^\/api\/mls\/capability\/([a-z0-9_]{3,20})$/.exec(path);
        if (capabilityMatch && method === 'GET') return capability(user, capabilityMatch[1]!);
        const userMatch = /^\/api\/users\/([A-Za-z0-9_-]{22})\/identity$/.exec(path);
        if (userMatch && method === 'GET') return identity(user, userMatch[1]!);
        if (path === '/api/channels' && method === 'POST') return create(request, user);
        const match = /^\/api\/channels\/([A-Za-z0-9_-]{22})(?:\/([a-z-]+))?$/.exec(path);
        if (match) {
            const [, id, action] = match as unknown as [string, string, string | undefined];
            if (!action && method === 'GET') return info(user, id);
            if (action === 'members' && method === 'GET') return memberList(user, id);
            if (action === 'log' && method === 'GET') return log(url, user, id);
            if (action === 'messages' && method === 'POST') return submit(request, user, id, 'app');
            if (action === 'ephemeral' && method === 'POST') return ephemeral(request, user, id);
            if (action === 'commits' && method === 'POST') return submit(request, user, id, 'commit');
            if (action === 'join' && method === 'POST') return submit(request, user, id, 'external');
            if (action === 'join-info' && method === 'GET') return joinInfo(user, id);
            if (action === 'group-info' && method === 'PUT') return putGroupInfo(request, user, id);
            if (action === 'cursor' && method === 'POST') return cursorRequest(request, user, id);
            if (action === 'poison' && method === 'POST') return poison(request, user, id);
            if (action === 'resolve' && method === 'POST') return resolve(request, user, id);
        }
        return json({ error: 'Not found' }, 404);
    }

    return { handle, pump, cursorFrame, ackWelcome, sweep, devicesRevoked };
}
export type Channels = ReturnType<typeof createChannels>;
