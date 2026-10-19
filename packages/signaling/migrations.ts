import type { Database } from 'bun:sqlite';
import { randomBytes } from 'node:crypto';

/**
 * Numbered schema migrations, tracked in `PRAGMA user_version`. Each runs once, in its own transaction, in order.
 * Version 1 is the schema as it stood before numbering; it is idempotent so an existing production database
 * (user_version 0 with every table already present) adopts the numbering without change.
 * push.ts and emoji.ts still create their own self-contained tables.
 */
const MIGRATIONS: ((db: Database) => void)[] = [
    // 1: accounts, passkeys, invites, sessions, contacts, prekeys and the per-user mailbox (pre-M1).
    db => {
        db.exec(`
            CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS invites (code_hash TEXT PRIMARY KEY, created_by TEXT REFERENCES users(id) ON DELETE SET NULL, expires_at INTEGER NOT NULL, used_by TEXT REFERENCES users(id) ON DELETE SET NULL);
            CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS contacts (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, contact_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, contact_id));
            CREATE TABLE IF NOT EXISTS identity_keys (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, dh TEXT NOT NULL, sign TEXT NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS signed_prekeys (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, key_id INTEGER NOT NULL, key TEXT NOT NULL, signature TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS one_time_prekeys (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, key_id INTEGER NOT NULL, key TEXT NOT NULL, PRIMARY KEY (user_id, key_id));
            CREATE TABLE IF NOT EXISTS mailbox (id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, envelope BLOB NOT NULL, created_at INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS mailbox_recipient ON mailbox (recipient_id, created_at);
            CREATE INDEX IF NOT EXISTS mailbox_age ON mailbox (created_at);
            CREATE TABLE IF NOT EXISTS contact_requests (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, username TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, username));
        `);
        // Which client a session belongs to: 'web' sessions live in a cookie, native ones in a bearer token.
        if (!columns(db, 'sessions').includes('client')) db.exec("ALTER TABLE sessions ADD COLUMN client TEXT NOT NULL DEFAULT 'web'");
    },
    // 2 (M1): device registry, signed device lists, sessions bound to devices, and a per-device inbox.
    db => {
        db.exec(`
            -- state: 'placeholder' (the account's messaging device before it published a list: migrated accounts,
            -- native apps), 'pending' (signed in, not in the signed list), 'listed' (named by the signed list),
            -- 'revoked'. platform is the signed-in session's client kind (already known from sign-in); labels and
            -- platforms as the account describes them are sealed inside the signed list (device_lists.list).
            -- sig_key is the device's own Ed25519 key: binding a session to an existing device needs its signature.
            CREATE TABLE devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                platform TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('placeholder', 'pending', 'listed', 'revoked')),
                is_primary INTEGER NOT NULL DEFAULT 0, sig_key TEXT, cert TEXT, created_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER);
            CREATE INDEX devices_user ON devices (user_id, state);
            -- At most one live primary (the device holding the account identity key) per account.
            CREATE UNIQUE INDEX devices_primary ON devices (user_id) WHERE is_primary = 1 AND state != 'revoked';
            -- The latest list signed by the account identity key, verbatim; aik_sign records which key signed it.
            CREATE TABLE device_lists (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, aik_sign TEXT NOT NULL,
                version INTEGER NOT NULL, hash TEXT NOT NULL, list TEXT NOT NULL, signature TEXT NOT NULL, certs TEXT NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE device_inbox (id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                envelope BLOB NOT NULL, created_at INTEGER NOT NULL);
            CREATE INDEX device_inbox_device ON device_inbox (device_id, created_at);
            CREATE INDEX device_inbox_pair ON device_inbox (recipient_id, sender_id);
            CREATE INDEX device_inbox_age ON device_inbox (created_at);
        `);
        if (!columns(db, 'sessions').includes('device_id')) db.exec('ALTER TABLE sessions ADD COLUMN device_id TEXT REFERENCES devices(id) ON DELETE SET NULL');
        // Every envelope waiting in the per-user mailbox moves to that user's messaging device (a placeholder the
        // active device claims when it first publishes its list), keeping ids, order and timestamps.
        const now = Date.now();
        const recipients = db.query<{ id: string }, []>('SELECT DISTINCT recipient_id AS id FROM mailbox').all();
        for (const { id } of recipients) {
            const device = randomBytes(16).toString('base64url');
            db.query("INSERT INTO devices (id, user_id, platform, state, is_primary, created_at) VALUES (?, ?, 'unknown', 'placeholder', 1, ?)").run(device, id, now);
            db.query('INSERT INTO device_inbox (id, device_id, recipient_id, sender_id, envelope, created_at) SELECT id, ?, recipient_id, sender_id, envelope, created_at FROM mailbox WHERE recipient_id = ?').run(device, id);
        }
        db.exec('DROP TABLE mailbox');
    },
];

function columns(db: Database, table: string) { return db.query<{ name: string }, []>(`PRAGMA table_info(${table})`).all().map(column => column.name); }

export const SCHEMA_VERSION = MIGRATIONS.length;

/** Brings the database to SCHEMA_VERSION. A database newer than this code is refused rather than misread. */
export function migrate(db: Database) {
    const current = db.query<{ user_version: number }, []>('PRAGMA user_version').get()!.user_version;
    if (current > MIGRATIONS.length) throw new Error(`Database schema ${current} is newer than this server (${MIGRATIONS.length}); deploy the matching version.`);
    for (let version = current + 1; version <= MIGRATIONS.length; version++) {
        db.transaction(() => {
            MIGRATIONS[version - 1]!(db);
            db.exec(`PRAGMA user_version = ${version}`);
        })();
    }
    return { from: current, to: MIGRATIONS.length };
}
