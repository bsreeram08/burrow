import type { Database } from 'bun:sqlite';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { open, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { requestLimiter } from './rate-limit';

// Encrypted attachments. Clients encrypt each file with a fresh key that travels only inside the end-to-end
// encrypted message; the server stores ciphertext under a random id, which is the capability to download it.
// Blobs live 30 days like mailbox envelopes; each account may hold 1 GiB of them and the server `budget` in total.
export const BLOB_MAX = 25 * 1024 * 1024 + 28, BLOB_TTL = 30 * 86400000, QUOTA = 1024 ** 3, DEFAULT_BUDGET = 20 * 1024 ** 3, ORPHAN_SCAN = 10 * 60000;
const USER_UPLOADS = 2, UPLOADS = 16;
const ID = /^[A-Za-z0-9_-]{22}$/;
type User = { id: string };
const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });

export function createBlobs(options: { db: Database; dataDir: string; origin: string; now: () => number; budget?: number }) {
    const { db, now } = options, budget = options.budget ?? DEFAULT_BUDGET;
    if (!Number.isSafeInteger(budget) || budget < 1) throw new Error('BLOB_BUDGET_BYTES must be a positive integer');
    const directory = join(options.dataDir, 'blobs');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    db.run('CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, size INTEGER NOT NULL, created_at INTEGER NOT NULL)');
    db.run('CREATE INDEX IF NOT EXISTS blobs_owner ON blobs (owner_id, created_at)');
    db.run('CREATE INDEX IF NOT EXISTS blobs_age ON blobs (created_at)');
    const fileFor = (id: string) => join(directory, id);
    // Uploads in progress, by user: their count and declared bytes. The bytes count against the quota and the budget
    // so parallel uploads cannot overshoot either; the count bounds open files and sockets.
    const active = new Map<string, { count: number; bytes: number }>(), writing = new Set<string>();
    let uploading = 0, uploadingBytes = 0, lastScan = 0;
    /** Files without a live row (interrupted uploads, deleted accounts, expired rows) are removed. */
    function removeOrphans() {
        lastScan = now();
        const known = new Set(db.query<{ id: string }, []>('SELECT id FROM blobs').all().map(row => row.id));
        for (const name of readdirSync(directory)) if (!known.has(name) && !writing.has(name)) rmSync(join(directory, name), { force: true });
    }
    removeOrphans();
    const allowUpload = requestLimiter({ perSource: 4, global: 200 });
    const stored = () => db.query<{ bytes: number }, []>('SELECT COALESCE(SUM(size), 0) AS bytes FROM blobs').get()!.bytes;
    const used = (userId: string) => db.query<{ bytes: number }, [string, number]>('SELECT COALESCE(SUM(size), 0) AS bytes FROM blobs WHERE owner_id = ? AND created_at > ?').get(userId, now() - BLOB_TTL)!.bytes;

    async function upload(request: Request, user: User): Promise<Response> {
        const bearer = request.headers.get('authorization')?.startsWith('Bearer ') ?? false, origin = request.headers.get('origin');
        if (origin !== options.origin && !(origin === null && bearer)) return json({ error: 'Origin required' }, 403);
        if (request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/octet-stream') return json({ error: 'Send the ciphertext as application/octet-stream.' }, 415);
        // Content-Length is required and capped by the server before this runs; check the quota before reading a byte.
        const declared = Number(request.headers.get('content-length'));
        if (!declared) return json({ error: 'Empty upload' }, 400);
        if (declared > BLOB_MAX) return json({ error: 'Files can be at most 25 MB.' }, 413);
        if (!allowUpload(user.id)) return json({ error: 'Rate limited' }, 429);
        const mine = active.get(user.id) ?? { count: 0, bytes: 0 };
        if (mine.count >= USER_UPLOADS || uploading >= UPLOADS) return json({ error: 'Too many uploads at once. Try again shortly.' }, 429);
        if (used(user.id) + mine.bytes + declared > QUOTA) return json({ error: 'You have 1 GB of attachments waiting on the server. Older ones expire after 30 days.' }, 507);
        if (stored() + uploadingBytes + declared > budget) return json({ error: 'The server has no room for attachments right now. Try again later.' }, 507);
        active.set(user.id, { count: mine.count + 1, bytes: mine.bytes + declared }); uploading++; uploadingBytes += declared;
        const id = randomBytes(16).toString('base64url'), part = `${id}.part`;
        writing.add(part);
        try {
            // Streamed to disk as it arrives: memory stays at one chunk, and the count must end exactly at the declared length.
            const file = await open(fileFor(part), 'wx', 0o600);
            let size = 0;
            try {
                if (request.body) for await (const chunk of request.body) {
                    size += chunk.byteLength;
                    if (size > declared) throw new Error('length');
                    await file.write(chunk);
                }
            } finally { await file.close(); }
            if (size !== declared) throw new Error('length');
            await rename(fileFor(part), fileFor(id));
            db.query('INSERT INTO blobs (id, owner_id, size, created_at) VALUES (?, ?, ?, ?)').run(id, user.id, size, now());
            return json({ id }, 201);
        } catch {
            await rm(fileFor(part), { force: true }); await rm(fileFor(id), { force: true });
            return json({ error: 'The upload did not complete.' }, 400);
        } finally {
            writing.delete(part);
            const left = active.get(user.id)!;
            if (left.count > 1) active.set(user.id, { count: left.count - 1, bytes: left.bytes - declared }); else active.delete(user.id);
            uploading--; uploadingBytes -= declared;
        }
    }
    function download(id: string): Response {
        const row = db.query<{ size: number }, [string, number]>('SELECT size FROM blobs WHERE id = ? AND created_at > ?').get(id, now() - BLOB_TTL);
        if (!row || !existsSync(fileFor(id))) return json({ error: 'Not found' }, 404);
        // Ciphertext addressed by an unguessable id never changes, so clients may cache it for good.
        return new Response(Bun.file(fileFor(id)), { headers: {
            'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=31536000, immutable', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'; sandbox", 'Content-Disposition': 'attachment', 'Cross-Origin-Resource-Policy': 'same-origin', 'Referrer-Policy': 'no-referrer',
        } });
    }
    async function handle(request: Request, url: URL, user: User | null): Promise<Response> {
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (url.pathname === '/api/blobs' && request.method === 'POST') return upload(request, user);
        const match = /^\/api\/blobs\/([^/]+)$/.exec(url.pathname);
        if (match && request.method === 'GET') return ID.test(match[1]!) ? download(match[1]!) : json({ error: 'Not found' }, 404);
        return json({ error: 'Not found' }, 404);
    }
    function sweep() {
        const expired = db.query<{ id: string }, [number]>('SELECT id FROM blobs WHERE created_at <= ? LIMIT 1000').all(now() - BLOB_TTL);
        for (const { id } of expired) { rmSync(fileFor(id), { force: true }); db.query('DELETE FROM blobs WHERE id = ?').run(id); }
        // Rows of deleted accounts vanish by cascade; their files go on the next scan.
        if (now() - lastScan >= ORPHAN_SCAN) removeOrphans();
    }
    return { handle, sweep };
}
export type Blobs = ReturnType<typeof createBlobs>;
