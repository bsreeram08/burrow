# chatcore API

`chatcore` is the end-to-end messaging core for the native apps (Flutter, through
flutter_rust_bridge) and, later, the web app (through WASM). It is a port of
`packages/signaling/public/signal.js` (X3DH + Double Ratchet, safety numbers) and `verify.js`
(call verification code). It's wire-compatible with them; `bun run test:interop` checks that both ways.

The functions below live in `src/api.rs`. They take and return owned values (no lifetimes), and
every error is a `ChatError { code, message }`:

- **`code` is set** for a permanent outcome. The app may acknowledge or discard the envelope:
  - `malformed`, `auth`, `replay`, `skip-limit`, `unknown-session`, `unknown-spk`, `claim-limit`;
  - `invalid` (the plaintext isn't JSON), `mismatch` (the published identity differs), `identity-blocked`;
  - `storage`. This one is transient: retry.
- **`code` is `None`** for a transient failure. Retry, up to the app's attempt cap, exactly as
  `ChatStore.inboundDisposition` does on the web.

## Setup

| Function | Returns | Notes |
|---|---|---|
| `init(db_path, store_key, expect_existing)` | `()` | Opens the account's sealed SQLite key database (AES-256-GCM, each value bound to its row and store; all-or-nothing open). `expect_existing` = the keystore already held this key: a missing marker means the database was deleted or reset, and fails with `storage`. Otherwise only an empty database is initialized. No implicit migration, no fresh start; a failed open closes any previously open store. In an existing database a missing identity is a `storage` error; only `reset_identity` replaces it. |
| `identity()` | `IdentityPub { dh, sign }` | Created on first call: separate X25519 and Ed25519 keys. |
| `prepare_prekeys(now_ms)` | `PrekeyUpload { identity, rotated, signedPreKey }` | The signed prekey rotates weekly. When it rotates, claims under the retired one are pruned. |
| `one_time_prekeys(count)` | `Vec<{ id, key }>` | Upload them when the server reports fewer than 20, as `account.js` `publishKeys` does. |

## Messaging

| Function | Returns | Notes |
|---|---|---|
| `encrypt_to(contact_id, plaintext_json, bundle_json?)` | `Envelope(String)` or `NeedsBundle` | `NeedsBundle` means there's no sending session: fetch `/api/keys/<username>` and call again with that JSON. Fails with `identity-blocked` while the contact's security code change hasn't been accepted. |
| `decrypt_from(contact_id, envelope, published_identity?)` | `Decrypted { pending_id, plaintext_json, identity_changed, first_contact, identity }` | Phase 1: authenticates, claims a new session once (global lock, at most 20 per contact per signed prekey) and returns the plaintext. The stored ratchet doesn't advance yet. |
| `commit(pending_id, rotate)` | `bool` (a changed identity was recorded) | Phase 2, called after the app stored the message (signal.js runs `handle()` first, then persists). One atomic batch writes the session, the pinned identity, the completed claim and the one-time prekey deletion. If the contact's sessions changed in between, it returns a transient error; decrypt the envelope again. |
| `abort(pending_id)` | `()` | Drops a pending decrypt, e.g. when storing the message failed. Redelivering the envelope processes it again. |

Use `identity_changed` to show the message with the security-code warning. Using
`published_identity` gives defence in depth only: it's circular when the server is the attacker.

Each app session should handle incoming envelopes in order: decrypt → store → commit → acknowledge.

`rotate` is true when the stored payload was the peer's `{type:'rotate'}` session reset (signal.js `handle()`
answering `{ rotate: true }`): the core keeps only the session it arrived on, and only if that session is new
(the peer's fresh handshake) or the one our own rotation opened. A reset arriving on an older session is ignored.

## Chat key rotation

| Function | Returns |
|---|---|
| `rotate(contact_id)` | `()`. The next `encrypt_to` opens a fresh session (returns `NeedsBundle`). Older sessions stay (bounded) so in-flight messages decrypt; a late message never revives them; they are dropped once the peer answers on the new one. The pinned identity is untouched. |
| `session_info(contact_id)` | `Option<SessionInfo { sid, started_at }>` for scheduled rotation. |
| `rotation_interval(mine, theirs)` | The shorter non-off interval (ms) of the two; unknown values are ignored. |
| `reset_identity()` | `()`. A new identity for this device (explicit user action only): sessions, prekeys and claims go, pinned contacts stay, pending decrypts are dropped. Upload with takeover semantics afterwards. |

## Trust

| Function | Returns |
|---|---|
| `safety(my_username, contact_id, their_username)` | `Option<Safety { number, verified, changed, blocked }>`. `number` is 60 digits in 12 groups of 5, the same on both sides. |
| `peer(contact_id)` | `Option<PeerRecord>` |
| `set_verified(contact_id, bool)`, `accept_change(contact_id)` | `()`. Either one unblocks sending after a key change. |
| `set_verified_for(contact_id, bool, identity)`, `accept_change_for(contact_id, identity)` | `()`, only if `identity` is the pinned identity now (the one the user reviewed); else `mismatch`. JSON: `setVerified` / `acceptChange` with optional `identity`. |
| `forget(contact_id)` | `()`. Drops sessions but keeps the pinned identity. |
| `note_peer(contact_id, identity)` | `()`. Records a server-published identity (key-change events); a change is flagged and blocks sending. |

## Call verification code

| Function | Returns |
|---|---|
| `sas_new_nonce()` | 64 lowercase hex characters |
| `sas_commitment(nonce)` | Hex SHA-256 of the nonce text. Send `{type:'commit', hash}` first. |
| `sas_check_reveal(peer_commitment, peer_nonce)` | `bool`. Reveal your own nonce only after receiving the peer's commitment. |
| `sas_code(local_sdp, remote_sdp, my_nonce, peer_nonce)` | `"123 456"`. Each SDP must contain exactly one `a=fingerprint:sha-256` value; anything else that looks like a fingerprint line fails closed. |

## Store

`store::Store` (`get`, `put`, `delete`, `delete_prefix`, atomic `batch`, with JSON values)
matches signal.js's backend contract:
- `SqliteStore` is the native implementation.
- `MemoryStore` is for tests.
- A WASM build can implement the trait over IndexedDB.

`core::Core` is the same logic as an instance (`Core::new(Box<dyn Store>)`), for tests and multi-account use.

# Groups over MLS

Groups (DMs, group DMs, channels) run on MLS (RFC 9420) through OpenMLS 0.9.0 (pinned exactly), ciphersuite
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. The design is `docs/workspace-architecture.md` §2; the spike's
findings that shaped this code are on branch `spike/openmls` (`crates/mls-spike/FINDINGS.md`). The code is
`src/mls/`; the flat API is the `mls_*` functions in `src/api.rs`, and the same operations are JSON commands for the
browser worker, node and Bun (`mls*` and `ds*`, see `src/mls/commands.rs`).

Cargo features: `mls` (the client engine, default) and `ds` (the delivery-service validator, default). The Bun delivery
service builds `chatcore-wasm` with `--no-default-features --features ds`; the browser with `--features mls`.

## Model

- **Identity.** Each device has its own Ed25519 leaf key. Its MLS credential is a `DeviceCert` (canonical JSON, fields
  `v, userId, deviceId, platform, leafSigKey, aikSign, issuedAt, sig`) signed by the user's account identity key
  (the Ed25519 half of the 1:1 identity). Ids are 16 random bytes, base64url without padding (22 characters).
- **Pins.** A certificate is accepted only if it verifies under the account key *pinned* for its user. On a client the
  pin is the 1:1 contact record `peer:<userId>` (so a contact id must be the user's id; a blocked/changed identity
  is not a pin), plus this device's own account. On the delivery service it is `Ds::pin` (the device registry);
  a user is never re-pinned to another key.
- **Roles** (group-context extension `0xF0A1`, with `required_capabilities` as the only other extension):
  `{v, kind: group|dm, admins, joinPolicy: open|invite, dm?}`. Strictly decoded and canonical (re-encodes to the
  same bytes); 1-64 admins; a DM names its two users (sorted), who are its admins; `kind` never changes.
- **No standalone proposals.** Only inline proposals inside a commit. Proposals sent alone, and commits that refer to
  them, are refused.
- **Wire format.** Handshake messages are public (so the delivery service validates them), application messages
  private (`MIXED_PLAINTEXT` policy, needed for external commits).

## Policy (one validator)

`policy::validate_staged` runs on the *pre-commit* roles, in the delivery service before it sequences a commit, in
every member before it merges one, and in the committer before it submits and again before `merge_own`. A commit the
DS accepts is therefore one every member accepts (except tag bytes only members can check: see poison commits).

- Every added or changed leaf carries a valid certificate that names its own leaf key; an update (or UpdatePath)
  keeps the same user and device.
- Adding a new user: an admin, or any member of an `open` group. A DM never gains a third user.
- Removing another user's device: an admin (never in a DM). Anyone may remove their own devices.
- Changing roles: an admin only, judged by the roles before the commit; the result must be valid roles.
- External join: a user already in the group (a new device of theirs, or a resync), or any user in an `open`
  group. Never a stranger in an `invite` group, and in a DM only one of its two users.
- Limits, checked before parsing: at most 128 proposals per commit, 1,000 leaves, commit/message 1 MiB, application
  message 64 KiB (60 KiB of plaintext), Welcome 4 MiB, ratchet tree 4 MiB, GroupInfo 64 KiB, KeyPackage 4 KiB,
  certificate 1 KiB, roles 4 KiB, 64 admins; 1-100 KeyPackages per call.

## Gates

| Entry point | What runs before state changes |
|---|---|
| `create` | roles valid; creator is an admin (or one of the DM's users) |
| `join` (Welcome) | byte limits; whole-group validation: every member's certificate, roles, size, DM membership |
| `join_external` | byte limits; whole-group validation of the GroupInfo's tree; the shared validator on its own commit; again at `merge_own` |
| `commit` (build) | proposal count; the shared validator on the built commit |
| `merge_own` | the shared validator again, then merge |
| `process` (commit) | byte limits; epoch; the shared validator; any failure is `poison` |
| `process` (proposal) | refused |
| first use of a group after a restart (the load gate) | whole-group validation under today's pins, and this device's own leaf matches its certificate. A group that fails stays unusable; others are unaffected |
| `Ds::create` | whole-group validation like a Welcome |
| `Ds::submit` | byte limits; epoch (`conflict`); the shared validator; application messages: size and epoch only; proposals refused |

## Flows

**Device setup.** `mls_init_device(userId, deviceId, platform, issuedAtMs)` creates the leaf key and a certificate
signed with this core's account key. Where the account key lives elsewhere (WebCrypto), call `mlsDeviceLeaf`, sign
`DeviceCert::tbs` (or build the cert) outside, and install it with `mlsSetDeviceCert`; it must verify under *this
core's* account key and name the prepared leaf key. Keep 100 one-time KeyPackages and one last-resort one on the
server (`mls_key_packages(count, last_resort)`); top up below 20.

**Commit.** `mls_commit(group, adds, removes, roles, update)` builds a commit and keeps it pending (one at a time) and
returns `Outgoing { groupId, commit, welcome?, digest, epoch }`. Submit `commit` to the DS for `epoch`:
accepted, call `mls_merge_own`, then send `welcome` (with the DS's `ds_tree`) to the added devices; `conflict`, call
`mls_clear_own`, process the log from your cursor, rebuild (max 5 tries with backoff); unknown outcome (timeout), look for
`digest` in the log on reconnect: found, merge (processing the log does it, `kind: "own"`), otherwise `mls_clear_own`
and rebuild. `mls_pending_commit` returns `{digest, epoch}` for a pending commit, also after a restart.

**Receive.** `mls_receive(group, message)` authenticates and decrypts without persisting and returns
`Processed { pendingId, kind, plaintext?, sender, epoch, digest? }` (`kind`: `application`, `commit`, `own`, or `removed`
when this device was removed). Store the message, then `mls_receive_commit(pendingId)`; `mls_receive_abort` drops it
(redelivery processes it again). Process a group's log in order and never feed a device its own application messages.
Validate each decrypted payload with `mls_validate_payload` (the v2 schema in `payload.rs`; unknown fields rejected).

**Errors.** Codes as above plus: `invalid` (policy or limit violation; permanent), `poison` (a sequenced commit this
device rejects; message `poison <digest>: <reason>`; report it to the DS), `unknown-group`, `replay`, `skip-limit`,
`auth`, `malformed`, and `storage` (reload; the engine marks itself stale and `Core::groups()` reloads it).

**External joins.** `mls_join_external(groupInfo, tree)` returns the commit to submit (then `mls_merge_own`). Resync of a
broken local copy: `mls_forget_group` first, then join externally with the same leaf key (the old leaf is replaced).

**Poison commits.** The DS cannot check a commit's confirmation and membership tags, so a member can wedge a group
with a commit the DS sequences but every member rejects. `Ds::snapshot(group)` before sequencing a commit and
`Ds::restore(group, snapshot)` roll the public state back after members report `poison`; the rollback protocol
(freeze, an admin device re-checks, truncate the log, remove the committer) is the delivery service's (M3).

**Who a rejected commit blames.** A commit's signature covers its content; the membership and confirmation tags are
*not* covered, and whoever relays the commit can flip them without breaking the signature (the spike's byte-flip probe
did exactly that). So a commit rejected for its tags says nothing about its author, and removing the author for it would
let a malicious server get an innocent member removed. A `poison` failure therefore carries a class (`class` beside
`code` in the JSON error; `ChatError.class`), and `mls_commit_author` / `mlsCommitAuthor` returns the same judgement for
any commit at the current epoch, computed the way the DS sees it (signature and signed content, no tags):

| Field | Meaning |
|---|---|
| `authenticated` | the signature verifies under the author's leaf key in this device's tree |
| `signedContentInvalid` | authenticated, and the signed content fails validation or policy (invalid proposals or path, a non-admin's add, a bad roles change...) |
| `class` | `signed-content` iff both are true, otherwise `tag` (a bad tag, a bad signature, anything outside the signature) |
| `author` | the member who signed it, only when `authenticated` |

Policy: a `tag` failure may be rolled back to unwedge the group but the author is NOT removed (its client sees the
rollback, resyncs and tries again); only `signed-content` failures justify removing the author. Unknowns default to `tag`.

## Delivery service (`Ds`, namespace `mlsds`)

`Ds::new(store)`, `pin(userId, aik)`, `create(groupInfo, tree)`, `submit(group, message)` -> `accepted {epoch, digest}`
or `conflict {epoch}` (or an error), `epoch`, `tree`, `snapshot`, `restore`. It holds public state only (no secrets).
JSON commands: `dsPin`, `dsCreate`, `dsSubmit`, `dsEpoch`, `dsTree`, `dsSnapshot`, `dsRestore`.

## Storage

Rows in the account store (so the sealed SQLite database natively and the journal in the browser carry them): OpenMLS
state is keyed by group first, `mls:g:<group tag>:k:<hex key>`, and values over 8 KiB are split into content-defined
chunks (`...:c:<hash>`, ~4 KiB, shared and ref-counted), so a message or a commit rewrites only what changed. Device
identity `mlsx:device`, pending commits `mlsx:pending:<group>`. Every call's writes go out in one atomic batch, and a
failed call rolls back in memory. Loading fails closed on a malformed row, a chunk that does not match its name or a
row under the wrong group; OpenMLS never sees a panic from a corrupt row.

## Functions (`src/api.rs`)

| Function | Returns |
|---|---|
| `mls_init_device(user_id, device_id, platform, issued_at_ms)` | `DeviceCert` |
| `mls_key_packages(count, last_resort)` | `Vec<String>` |
| `mls_create_group(group_id, roles)` | `GroupView { groupId, epoch, groupInfo, tree }` |
| `mls_commit(group_id, adds, removes: Vec<Removal>, roles?, update)` | `Outgoing` |
| `mls_merge_own(group_id)` / `mls_clear_own(group_id)` / `mls_pending_commit(group_id)` | `GroupView` / `()` / `Option<PendingCommit>` |
| `mls_join(welcome, tree)` | `GroupView` |
| `mls_join_external(group_info, tree)` | `Outgoing` |
| `mls_forget_group(group_id)` | `()` |
| `mls_encrypt(group_id, plaintext)` | message (base64url) |
| `mls_receive(group_id, message)` / `mls_receive_commit(pending_id)` / `mls_receive_abort(pending_id)` | `Processed` / `()` / `()` |
| `mls_members(group_id)` / `mls_roles(group_id)` / `mls_group_view(group_id)` | `Vec<MemberView>` / `Roles` / `GroupView` |
| `mls_validate_payload(payload_json, context)` | the payload type |
| `mls_sign_resolution(group_id, action, seq, digest, author)` / `mls_verify_resolution(group_id, action, seq, digest, author, by, signature)` | A frozen-channel resolution signed with this device's MLS leaf key over `"webrtc-bun-mlsresolve-leaf-v1\n" + group + "\n" + action + "\n" + seq + "\n" + digest + "\n" + author` (action `rollback` or `dismiss`, digest 64 lowercase hex, author empty or a device id; nothing else is ever signed this way). Verifying finds device `by` in this device's tree, checks its certificate under the pinned account key, requires its user to be an admin, and returns `{ userId, deviceId }`; `auth` for a bad signature, `invalid` otherwise. Commands `mlsSignResolution`, `mlsVerifyResolution`. |
| `mls_commit_author(group_id, message)` | `CommitCheck { authenticated, signedContentInvalid, class, author? }`: who signed a commit at the current epoch and whether what they signed is valid, judged on this device's tree without the tags (changes nothing). For resolving a reported commit; see "Who a rejected commit blames". |

JSON commands: `mlsInitDevice`, `mlsDeviceLeaf`, `mlsSetDeviceCert`, `mlsKeyPackages`, `mlsCreate`, `mlsCommit`,
`mlsMergeOwn`, `mlsClearOwn`, `mlsPending`, `mlsJoin`, `mlsJoinExternal`, `mlsForget`, `mlsEncrypt`, `mlsReceive`, `mlsCommitAuthor`
(`commit: false` to stage), `mlsCommitReceived`, `mlsAbortReceived`, `mlsMembers`, `mlsRoles`, `mlsView`,
`mlsValidate`; fields are the camelCase names of the parameters above (`group`, `adds`, `removes: [{userId, deviceId?}]`,
`roles`, `update`, `welcome`, `tree`, `groupInfo`, `plaintext`, `message`, `pendingId`).
