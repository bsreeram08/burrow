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
    // 3 (M3): the MLS delivery service: validator state, KeyPackages, channels, per-device membership and cursors,
    // the group log, Welcomes, and DMs. See mls-ds.ts and channels.ts.
    db => {
        db.exec(`
            -- The validator's public state (the wasm core's journal), keyed exactly as the core keys it.
            CREATE TABLE mls_ds_rows (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            -- One-time KeyPackages (at most 100 per device) and one last-resort one, each bound to a listed device.
            CREATE TABLE mls_key_packages (id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, kp TEXT NOT NULL UNIQUE, last_resort INTEGER NOT NULL,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
            CREATE INDEX mls_kp_device ON mls_key_packages (device_id, last_resort, created_at);
            CREATE UNIQUE INDEX mls_kp_last_resort ON mls_key_packages (device_id) WHERE last_resort = 1;
            CREATE INDEX mls_kp_expiry ON mls_key_packages (expires_at);
            -- id is the MLS group id. epoch/seq: the group's epoch and the position of its last log entry.
            -- prev_state is the validator's public state before the latest sequenced commit (the poison rollback).
            CREATE TABLE channels (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('public', 'private', 'dm', 'group_dm', 'self')),
                name TEXT, creator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, epoch INTEGER NOT NULL, seq INTEGER NOT NULL DEFAULT 0,
                group_info TEXT, group_info_epoch INTEGER, prev_state TEXT, prev_epoch INTEGER,
                frozen_seq INTEGER, frozen_digest TEXT, frozen_by TEXT, frozen_at INTEGER, created_at INTEGER NOT NULL);
            -- A mirror of the MLS tree for fan-out (authoritative roles live inside MLS): one row per member device.
            CREATE TABLE channel_members (channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                admin INTEGER NOT NULL DEFAULT 0, cursor INTEGER NOT NULL DEFAULT 0, joined_seq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, device_id));
            CREATE INDEX channel_members_device ON channel_members (device_id);
            CREATE INDEX channel_members_user ON channel_members (user_id, channel_id);
            -- Devices a rolled-back poison commit's author may no longer use in this channel.
            CREATE TABLE channel_bans (channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, device_id TEXT NOT NULL, banned_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id));
            CREATE TABLE dm_pairs (user_a TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, user_b TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                channel_id TEXT NOT NULL UNIQUE REFERENCES channels(id) ON DELETE CASCADE, PRIMARY KEY (user_a, user_b));
            CREATE TABLE group_log (channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, seq INTEGER NOT NULL, epoch INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('commit', 'app')), sender_user TEXT NOT NULL, sender_device TEXT NOT NULL, digest TEXT NOT NULL,
                message BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (channel_id, seq));
            CREATE INDEX group_log_age ON group_log (created_at);
            -- The per-device Welcome inbox (large, opaque blobs: kept apart from 1:1 envelopes).
            CREATE TABLE mls_welcomes (id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                epoch INTEGER NOT NULL, seq INTEGER NOT NULL, welcome BLOB NOT NULL, tree BLOB NOT NULL, created_at INTEGER NOT NULL);
            CREATE INDEX mls_welcomes_device ON mls_welcomes (device_id, created_at);
            CREATE INDEX mls_welcomes_channel ON mls_welcomes (channel_id, seq);
        `);
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
