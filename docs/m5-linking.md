# M5: linked devices, identity succession, and DMs on MLS (shared contract)

Contract for the web client (`packages/signaling/public/`), the Flutter app (`apps/chat/`), the server (`packages/signaling/`) and chatcore (`crates/chatcore`) for [workspace plan](workspace-architecture.md) §3 (linked devices) and §2 ("Migration from 1:1 sessions"). It builds on [devices.md](devices.md) (device registry, DeviceList, pins) and [m4-groups.md](m4-groups.md) (groups). Anything not said here stays as it is.

**Parts.** A: linking, revocation, primary transfer, recovery (§1-§6). B: identity succession in groups (§7). C: DM to MLS migration, and typing off the Double Ratchet (§8-§9). §10 lists the commands, endpoints and frames; §11 who builds what; §12 the pinned vectors.

## 0. Words

| Term | Meaning |
| --- | --- |
| AIK | The account identity key: today's `{ dh, sign }` identity. Safety numbers are its fingerprint. Only the **primary** holds its secret. |
| Primary | The one device holding the AIK. It signs DeviceLists, device certificates and MLS device certificates. |
| Companion | A device with its own device key and MLS leaf key and certificates signed by the AIK, but **no AIK secret**. It reads groups and (after §8) DMs. It cannot do 1:1 Double Ratchet (that identity is the AIK). |
| Device key | The Ed25519 key a device registered with `announce` (`devices.sig_key`). Browser: non-extractable, in IndexedDB. App: Keychain/Keystore seed. |
| Leaf key | The MLS leaf signature key (`mlsDeviceLeaf`), inside chatcore. Different from the device key. |
| Link | One linking session between a **new device** (N) that shows a QR and a **primary** (P) that scans it, relayed (blind) by the server. |

Companions never receive the AIK secret. A companion core is in **companion mode**: it stores `account` (the account's public identity, learned at link time and pinned) and refuses to mint an identity or do 1:1 crypto (error code `companion`).

## 1. Linking a new device (QR from the primary)

N is a device that is not yet in the account's DeviceList: a fresh browser or app install. N may have no session at all (the usual case: signing in with a passkey is **not** needed, and passkey sign-in alone never makes a trusted device) or a session as a `pending` device (the existing "Link this browser" button).

### 1.1 Steps

1. **N starts.** N generates its device key (or uses its announced one) and `POST /api/link/start` (no session needed) with `{ purpose: 'link', deviceId, deviceKey, platform, client?, signature }`. `deviceId` is a fresh 16-byte id (22 base64url chars), `deviceKey` the base64url Ed25519 public key, `platform` one of `web ios android macos windows linux`, `signature` the device key's signature over the *start bytes* (§1.3). Answer: `{ linkId, claim, expiresAt }` (`claim` is a secret only N sees; `linkId` is 16 random bytes, 22 chars; TTL 10 minutes).
2. **N shows the QR.** `linkQr { linkId }` (chatcore) creates N's ephemeral X25519 key and a 16-byte link secret and returns the QR text (§1.2). The QR is the only place the link secret exists: the server never sees it.
3. **P scans.** P's user chooses "Link a device" and scans. `linkAccept { qr }` (chatcore) checks the QR, creates P's ephemeral key, derives the keys and returns `{ linkId, eph, code }`. P `POST /api/link/:linkId/offer { eph }` (session of the primary). The server attaches the link to P's account, creates the device row for N (state `pending`, with the registered device key) and tells N.
4. **N completes.** N polls `GET /api/link/:linkId` (with its claim) until `state: 'offered'` and `eph`; `linkComplete { linkId, eph }` (chatcore) derives the same keys and returns the same `code`.
5. **Confirmation code.** Both screens show the 6-digit `code` ("123 456"). P's user checks it matches N's screen and N's platform/label (from the hello, step 6) and taps **Link**. If they differ (or P did not scan this QR) nothing has been signed yet: cancel (`DELETE /api/link/:linkId`).
6. **N says hello (before the user confirms on P).** After `linkComplete`, N sends one sealed message `hello` (§1.4) via `POST /api/link/:linkId/messages { dir: 'n2p', data }`. P reads it (`link` frame or `GET .../messages`), opens it (`linkOpen`), and shows the label/platform with the code.
7. **P signs and publishes.** On **Link**: P builds DeviceList version + 1 naming N's `deviceId` (sealed `meta` `{ label, platform }` from the hello) plus every device already listed, signs it with `sign_device_list` (with the served head, [devices.md](devices.md) "App list signing") and publishes `PUT /api/devices/list`. Then `signDeviceCert { userId, deviceId, platform, leafSigKey, issuedAt }` (chatcore) signs N's **MLS device certificate** (§1.5; only for a device in the last signed list). Then `POST /api/link/:linkId/grant` (the server checks N is `listed` now and marks the link granted).
8. **P sends the grant and the bundle** (sealed, `dir: 'p2n'`): one `grant` message and 0..16 `bundle` chunks (§1.4, §2).
9. **N claims.** `POST /api/link/:linkId/claim { claim, signature, client? }`: the signature is the device key's over the *claim bytes* (§1.3). The server issues N a session bound to its device: web gets `Set-Cookie`, native gets `{ user, session: { token, expiresAt } }`. The link is then consumed. N fetches the sealed messages (they stay readable for the 10 minutes), opens them with `linkOpen`, installs: `companionSetup { userId, identity, cert }`, `importPins`, local data (§2), then joins its groups (§3).

`GET /api/link/:linkId` and `.../messages` need the claim (N) or P's session; the server relays opaque data and never learns the code, the link secret, the bundle or the cert (it does learn the platform and that a link happened).

### 1.2 Crypto (chatcore `link`)

X25519, HKDF-SHA-256, AES-256-GCM. All values are raw bytes; text is base64url without padding.

- **QR text** = `"wb-link1."` + base64url( `0x01` ‖ `linkId` (16) ‖ `ephN` (32, X25519 public) ‖ `secret` (16) ). 65 bytes.
- **Shared keys.** `dh = X25519(ephP_secret, ephN_public)` (same from N's side). `ikm = dh (32) ‖ secret (16)`. `salt = SHA-256("webrtc-bun-link-v1" ‖ linkId (16) ‖ ephN (32) ‖ ephP (32))`. Then HKDF-Expand over `HKDF-Extract(salt, ikm)`:
  - `k_n2p` = info `"webrtc-bun-link-v1 n2p"`, 32 bytes (N to P).
  - `k_p2n` = info `"webrtc-bun-link-v1 p2n"`, 32 bytes (P to N).
  - `code` = info `"webrtc-bun-link-v1 code"`, 4 bytes, read as u32 big-endian, `mod 1000000`, zero-padded to 6 digits; shown as `"123 456"`.
- **Sealed message** = base64url( `counter` (u64 BE) ‖ AES-256-GCM(key, nonce, plaintext) ) with `nonce = 0x00000000 ‖ counter (u64 BE)` and `AAD = "webrtc-bun-link-msg-v1" ‖ linkId (16) ‖ dir (0x01 n2p, 0x02 p2n) ‖ counter (u64 BE)`. Each direction has its own counter starting at 0; a receiver accepts only `counter == next expected` (no gaps, no replays, no reordering) and then increments. A message is at most 64 KiB sealed (the plaintext at most 48 KiB).
- **State** lives in the core's store (`link:<linkId>`: ephemeral secret, link secret, keys, counters, creation time), deleted by `linkEnd` or after 15 minutes. One active link per device.

### 1.3 Server-side byte layouts

TLS-style as in devices.js: `text16` = u16 length + UTF-8; `bytes8` = u8 length + bytes; integers big-endian.

- **Start bytes** (device key signs): `text16("webrtc-bun-linkstart-v1") ‖ text16(deviceId) ‖ text16(platform) ‖ bytes8(deviceKey raw 32)`.
- **Claim bytes** (device key signs): `text16("webrtc-bun-linkclaim-v1") ‖ text16(linkId) ‖ text16(deviceId) ‖ bytes8(claim raw 32)`.

`claim` is 32 random bytes (43 chars); the server stores only its SHA-256.

### 1.4 Messages inside the sealed channel (JSON, UTF-8, exactly these fields)

N to P, `hello`:

```
{ "v": 1, "type": "hello", "deviceId": "<22>", "platform": "web|ios|…", "label": "<=64 chars>",
  "leafSigKey": "<43 base64url>", "wantsHistory": true|false }
```

`deviceId` must equal the one registered at `link/start`; P refuses otherwise.

P to N, `grant`:

```
{ "v": 1, "type": "grant", "userId": "<22>", "username": "…",
  "identity": { "dh": "<43>", "sign": "<43>" },          // the account's public AIK
  "deviceId": "<22>", "cert": "<DeviceCert JSON text>",    // MLS device certificate (§1.5)
  "listVersion": n, "listHash": "<43>",                    // the list that names N
  "metaKey": "<43 base64url, 32 bytes>",                   // device-label sealing key (devices.md)
  "chunks": n }                                            // number of bundle messages that follow
```

P to N, `bundle` (0..16 chunks, in order): `{ "v": 1, "type": "bundle", "i": k, "of": n, "data": "<base64url of a slice of the bundle JSON>" }`. N concatenates `data` and parses the bundle (§2). A bundle is at most 768 KiB in total.

### 1.5 The new device's MLS certificate

A chatcore `DeviceCert` (`webrtc-bun-devcert-v1`, [API.md](../crates/chatcore/API.md)): `userId`, `deviceId`, `platform`, `leafSigKey` (from the hello), `aikSign` (the AIK), `issuedAt` (ms), signature by the AIK. P's core builds the bytes itself and signs only for a `deviceId` in the **last list this core signed** (it remembers the ids with `devlist:last`), a known platform, a canonical key, and an `issuedAt` within 10 minutes of now.

## 2. What the bundle carries (and what it does not)

```
bundle = { "v": 1,
  "pins": [ { "contact": "<userId>", "identity": { "dh", "sign" }, "verified": bool } ],     // exportPins
  "channels": [ { "id", "kind", "name": "…"|null, "topic": "…"|null } ],                       // local names (private names live only here)
  "conversations": [ { "id": "<pairId or channel id>", "peer": "<userId>"|null, "name"?, "pinned"?, "history"?: [ <stored messages, newest last> ] } ],
  "settings": { … } }                                                                          // optional, client-defined, small
```

- **Never**: the AIK secret, the device key of any device, chat keys, ratchet state, MLS epoch secrets (N joins by itself, §3).
- **Pins.** `exportPins` returns every pinned contact **except** those whose code changed and is unreviewed (`changed` or `blocked`). The receiver imports with `importPins`: it creates a pin only where none exists, copies `verified`, and never overwrites an existing pin. A contact whose pin differs is left for the usual review.
- **History** is optional (`wantsHistory`), at most the newest 200 messages of at most 20 conversations and 512 KiB of bundle in total; N stores it as received (marked `imported`). Group history before N's join is never decryptable by N; the bundle is the only source and is labelled "from your other device".
- N verifies the grant before trusting any of it (§1.6) and only then imports.

### 1.6 N's checks

1. `grant.deviceId` is N's id; `cert` decodes (canonical), names `userId`/`deviceId`/N's `leafSigKey`, and verifies under `grant.identity.sign` (`mlsSetDeviceCert` with the companion's pinned key).
2. `listHash`/`listVersion` match the list the server serves for the account (`GET /api/devices/:username`, fetched with N's new session) and that list verifies under `grant.identity.sign` and names N. A mismatch aborts the link ("This doesn't look like your account").
3. `username` matches the session's `GET /api/me`.
4. The user sees "Linked to <username>. Safety number <n>" and can leave at once (`DELETE /api/devices/<id>` revokes itself).

The account identity N pins comes from the QR-authenticated primary, not from the server. A hostile server that substitutes P's ephemeral key cannot derive the keys (it lacks the link secret) and the codes would differ.

## 3. The new device joins its groups

For every channel in the bundle (and `GET /api/channels` as the source of truth; a channel the bundle lists but the server does not is dropped):

1. **Only a group the account is really in.** Before joining, check the served GroupInfo and tree read-only (`mlsInspectGroup { groupInfo, tree }`: the whole-group validation of a join, under today's pins, changing nothing). It must hold a non-stale leaf of this account for a device in our **verified** signed list (the list must verify under our own account key and move forward from our pin, as [devices.md](devices.md) "Pinning"). Otherwise don't join: the server could otherwise pull this device into any channel by listing it. Never rejoin a channel this device left.
2. Pin every member's identity (m4 §3), then `GET /api/channels/:id/join-info` and **external join** (the own-device rule: a user already in the channel may join a device by external commit): `mlsJoinExternal`, `POST .../join`, `mlsMergeOwn`, `PUT .../group-info`, cursor. N keeps no history from before its join point (server `joined_seq` rule).
3. Names/topics from the bundle's `channels` apply immediately; later `meta` payloads override them.
4. N uploads KeyPackages (100 one-time + 1 last-resort) so others can add it to new groups.
5. DMs: N is a leaf of every migrated DM group via the same rule (§8); unmigrated 1:1 chats stay on the primary until migration.

Joins are retried with backoff; at most 3 per second (server limit). A failed join leaves the channel marked "Join pending" and retries on the next start.

## 4. Revocation (from any device)

`POST /api/devices/:deviceId/revoke` from **any signed-in session of the account** (a listed device, a pending one, or a fresh passkey sign-in): it cuts the target immediately and works even for devices the DeviceList still names.

- Server: the device becomes `revoked`; its sessions end (streams close 4401), push tokens, KeyPackages, Welcomes and 1:1 inbox rows go; it leaves every channel mirror. The primary cannot be revoked this way (transfer, §5). Answer `{ revoked: [deviceId] }`.
- Frames: the account's streams get `devices` and, for each channel the device was in, `channel { id, change: 'remove-device', deviceId }`; the primary also gets `devices { id, needsList: true }`.
- **List.** The primary publishes version + 1 without the device (its client does this when it sees `needsList` or finds a listed device the server calls revoked in `GET /api/devices/<me>`). Until it does, other accounts still see the device in the signed list but not in any group fan-out.
- **Leaves.** Removal needs an MLS commit by a member. A device of the same account removes an own leaf only when its absence is **proven**: a verified signed list (under our own account key, moving forward from our pin) dropped that device, i.e. it is in the pin's tombstones (devices an earlier pinned list named and a later one dropped). A device merely missing from an unverifiable or unpinned list proves nothing, and the `remove-device` frame is only a hint to re-fetch and verify. Leaves the core reports `stale` (§7) may also go. Leaves are always matched on `(userId, deviceId)`, never on the device id alone. Exactly one device acts: the primary if online, else the listed device with the smallest `deviceId` among those with an open stream (a client cannot know; it just tries after a random 0-3 s delay and treats "no such member" / 409 as done). It commits `mlsCommit { removes: [{ userId: me, deviceId }] }` in each such channel (own devices may always be removed, m4 §4), then PUTs the GroupInfo. Retry until the leaf is gone; show "Removed <label> from N groups".
- A revoked device that still holds its keys can no longer reach the server (no session), and members drop its messages once it is removed. Messages it sent before are not retracted.

## 5. Primary transfer (succession)

Moves the AIK to another device of the account **while the old primary is available**. Because the AIK secret never moves, transfer makes a **new AIK** on the new primary and links it to the old one with a succession record, so contacts keep their verification.

### 5.1 The record

`SuccessionRecord { v: 1, userId, oldSign, newSign, newDh, at }` signed by the **old** AIK over:

`text16("webrtc-bun-succession-v1") ‖ text16(userId) ‖ bytes8(oldSign raw 32) ‖ bytes8(newSign raw 32) ‖ bytes8(newDh raw 32) ‖ u64(at ms)`.

JSON: `{ v, userId, oldSign, newSign, newDh, at, signature }` (keys base64url). At most 8 records per account chain; each record's `oldSign` is the previous one's `newSign`.

### 5.2 Flow (same relay as linking, `purpose: 'transfer'`)

1. N (a listed companion, with a session) wants to become primary: `POST /api/link/start { purpose: 'transfer', deviceId (its own), … }` (session required, N must be listed), shows the QR (`linkQr`), P0 (the current primary) scans and offers (only the primary may offer a transfer), the code is confirmed on both screens exactly as in §1.
2. N: `becomePrimary` (chatcore: leaves companion mode, mints a fresh identity; it is **not** published yet) and sends sealed `succession-request { "v":1, "type":"succession-request", "newSign", "newDh", "leafSigKey" }`.
3. P0 shows "Make <label> your primary device?" with the code. On confirm: `signSuccession { userId, newSign, newDh, at }` (chatcore; signs only the record bytes; requires P0 to hold the published AIK) and sends sealed `succession { record, signature }`.
4. N publishes: `PUT /api/devices/succession { record, signature }` (server verifies under the current AIK, §5.3), then `PUT /api/keys` with the new identity (the server accepts the identity change **as a succession** because a matching record is stored), then publishes **DeviceList version 1 under the new AIK** naming all current devices (including P0), with the usual per-device certs, and signs fresh MLS certificates for itself (`mlsInitDevice`).
5. P0 receives a final sealed `demote { "v":1, "type":"demote", "identity": {dh, sign}, "cert"?: … }`, `retireIdentity` (chatcore: deletes its AIK secret, enters companion mode with the new account identity pinned, **keeps** its device key and MLS leaf), and asks N for a new MLS cert for its leaf with the same relay (`signDeviceCert` flow of §1.5, optional: its old certificate stays valid through the succession, §7). The 1:1 inbox moves to N (existing claim rules).
6. Other companions: on the `devices` frame they fetch the new list, verify it under the new AIK via the succession chain (§5.3) and `companionSetup` again with the new pinned identity (no user action).

### 5.3 Contacts and the server

- `GET /api/devices/:username` additionally serves `succession: [ record + signature, … ]` (oldest first) when any exist.
- A client with a pin for that account whose pinned `sign` differs from the served identity checks the chain: each record verifies under the previous key, the chain starts at **the pinned key** and ends at the served key. Then `acceptSuccession { contact, records }` (chatcore): the pin moves to the new identity, `verified` is kept, `previous: [{ sign, until: at }]` is recorded (§7), and the UI shows a **soft notice** ("<name> moved to a new device. Verification kept."). Without a valid chain the usual "security code changed" review applies.
- The server accepts a record only if: `userId` is the session's, `oldSign` equals the published identity, the signature verifies under it, `newSign`/`newDh` are canonical 32-byte keys, `at` is within 10 minutes of now, and the chain is at most 8 long. It stores records in `identity_succession`. A matching `PUT /api/keys` keeps the account's devices (state `pending` until list v1 under the new key) instead of treating the change as a takeover for the *group* registry (§7).

## 6. Recovery without a primary

Passkey sign-in on a new device when **no listed device is reachable** (lost phone). It cannot link (nobody to scan). The device may:

1. `becomeFresh` (chatcore `reset_identity` + new identity) and publish with `PUT /api/keys` (a changed identity: existing "takeover" semantics): every contact sees **"security code changed"** and must review; verification flags are lost for that contact; no succession exists, the old AIK is gone.
2. Publish DeviceList version 1 under the new AIK naming itself.
3. Rejoin its groups by external join (the account is still a member through its stale leaves, §7); it removes its own stale leaves (own-device removal). Old devices remain unable to act (§7).

Passkey sign-in alone never makes a trusted device: until step 1-2 the server issues a session but the device is `pending` and has no access to any group.

## 7. Identity succession in groups (validator rules)

Today a member's identity change makes **every** commit in their channels fail (their old leaves' certificates no longer chain to the pinned key). New rules, in `crates/chatcore/src/mls/policy.rs` (client, DS and Rust tests share them):

- **Standing of a leaf.** For each leaf certificate the validator derives one of:
  - **Current**: signed by the user's pinned AIK.
  - **Predecessor**: signed by an earlier AIK in the pin's `previous` list (from an accepted succession record, §5.3) and `cert.issuedAt <= until` (the record's `at`). Treated as Current (the old key cannot issue new certificates after the succession).
  - **Stale**: the user is pinned to a *different* AIK and the certificate is not a Predecessor. (A missing or blocked pin is still an error: unknown, not stale.)
- **Stale leaves can't act.** A stale leaf may not commit, update, or be the sender of an accepted application message (`mlsReceive` returns code `stale`; the message is dropped). A stale committer's commit is rejected (class `signed-content`: it signed it).
- **Stale leaves can be removed.** A commit may Remove stale leaves; allowed to an admin or to a Current/Predecessor device of the **same user** (the existing own-device rule). This is what makes a recovered or revoked identity's old devices removable.
- **Joining.** A stale user's *new* device may external-join: the user is still "in the group". The validator counts stale leaves' users as members.
- Everything else is unchanged: adds, updates and external joins of new leaves still need a Current/Predecessor certificate.
- `mlsMembers` reports `stale: bool` per leaf; clients show "Old device" and offer/do removal of own stale leaves after a succession/recovery.
- **DS pins.** The delivery service pins each user's registry key. When the registry's identity changes: with a stored succession chain from the pinned key, `dsSucceed` moves the pin and records the predecessor; otherwise (recovery/takeover) `dsRepin` replaces it. Old leaves become stale and removable; nothing blocks the channel (this is the gap the server returned `409 identity changed` for).
- Client pins: `acceptSuccession` (contacts, §5.3) writes the `previous` list that chatcore's directory reads; a plain accepted code change (`acceptChange`) gives no predecessor, so old leaves are stale.

## 8. DMs on MLS (migration from 1:1 sessions)

A 1:1 chat is identified by its **pairId** (unchanged). Its transport moves from the Double Ratchet to a 2-person MLS group (`kind: dm`, one per pair, [signaling-api.md](signaling-api.md)). The conversation keeps its `pairId` as the conversation id; the group's channel id is a transport detail stored with it.

### 8.1 When

Both users must have an MLS-capable device: `GET /api/mls/capability/:username` (mutual contacts only) returns `{ userId, devices, channel }`: the number of the contact's listed devices that have at least one KeyPackage, and the id of the existing DM channel with you (or `null`). Migrate when `devices >= 1` and you have a listed MLS-capable device.

### 8.2 The first sender

1. `mlsCreate` with DM roles (`kind: 'dm'`, both user ids, `joinPolicy: 'invite'`), `POST /api/channels { kind: 'dm', peer: <username>, … }`. 409 `You already have a conversation…` means the other side won the race: skip to 8.3 as the receiver (discard your local group with `mlsForget`).
2. Claim KeyPackages for **both users** (own other devices included), commit all of them, send the Welcome (`POST .../commits` with every joiner).
3. Then send the **pointer**, the last Double Ratchet message of this chat, over the existing pinned session:
   `{ "v": 1, "type": "mls-dm", "id": "<uuid>", "channel": "<22>", "at": <ms> }`
   (a Phase 1 payload; stored as a system line "Messages now use the new encryption", not shown as a bubble).
4. From then on the sender sends this chat **only** through the group and marks the conversation `migrated` (`channel`, `migratedAt`).

### 8.3 The receiver accepts only if

1. The pointer arrived as an ordinary decrypted 1:1 message over the **pinned** session (`decrypt` without `identityChanged`/blocked) and `channel` is a canonical id.
2. `GET /api/channels/<channel>` shows `kind: 'dm'` with `peer` equal to the sender's user id (the server includes `peer` for DM channels) and this device is a member (it received the Welcome; otherwise wait for it, retrying, or ignore after 10 minutes).
3. `mlsCheckDm { group, peer }` (chatcore) passes: the roles are DM roles naming exactly {me, peer}, and every leaf belongs to one of the two users with a Current/Predecessor certificate that chains to the **pinned** AIKs (the 1:1 pins). Any failure: ignore the pointer, keep Double Ratchet, show nothing.
4. Then it marks the conversation `migrated` and sends only through the group.

Duplicate pointers (both sides migrating at once) are ignored once `migrated`. Safety numbers are per account and do not change; the group uses the same AIKs.

### 8.4 After migration

- **History continues under pairId**: messages from both transports are interleaved by their own timestamps in the same conversation.
- **Double Ratchet is receive-only for 60 days** from `migratedAt`: still decrypt incoming 1:1 envelopes (stragglers from not-yet-migrated devices), never send. The server refuses `POST /api/messages` to a contact once the pair's DM channel is older than 60 days (`410 Gone`); within 60 days it still delivers (the pointer itself needs it). After 60 days clients drop incoming 1:1 envelopes for a migrated pair.
- **New devices** join the DM group by external join (§3). Unmigrated 1:1 chats stay on the primary.
- **Read state, reactions, edits, typing** use the group payloads exactly as in groups (m4 §5; a DM is not "public", so receipts follow the private-channel rule).

## 9. Typing no longer uses the Double Ratchet

`POST /api/messages` with `ephemeral: true` is refused (`410 Gone`, "Typing hints travel over MLS groups"). Typing hints go only through `POST /api/channels/:id/ephemeral` (m4 §8), so a 1:1 chat shows typing only once its DM is migrated. Clients stop sending the 1:1 ephemeral envelope and ignore any that still arrive.

## 10. Commands, endpoints, frames

### 10.1 chatcore (JSON command / Rust `api`)

| Command | Meaning |
| --- | --- |
| `linkQr { linkId }` | N: ephemeral key + link secret, stores link state; `{ qr }`. |
| `linkAccept { qr }` | P: parse/validate the QR, ephemeral key, derive keys; `{ linkId, eph, code }`. |
| `linkComplete { linkId, eph }` | N: derive keys from P's ephemeral; `{ code }`. |
| `linkSeal { linkId, plaintext }` / `linkOpen { linkId, data }` | AEAD of §1.2 (`dir` is implied by the core's role); counters kept in the store. |
| `linkEnd { linkId }` | Deletes the state. |
| `signDeviceCert { userId, deviceId, platform, leafSigKey, issuedAt }` | P: MLS certificate JSON for a device in the last signed list (§1.5). |
| `exportPins` / `importPins { pins }` | §2. |
| `companionSetup { userId, identity, cert }` | N: pins the account identity, installs the cert, enters companion mode. |
| `becomePrimary` / `retireIdentity { identity }` | §5.2 steps 2 and 5. |
| `signSuccession { userId, newSign, newDh, at }` | P0: signs the record of §5.1 (only if it holds the published AIK). |
| `acceptSuccession { contact, records }` | §5.3: verifies the chain from the pin, moves the pin, keeps `verified`. |
| `mlsMembers` | now includes `stale`. |
| `mlsCheckDm { group, peer }` | §8.3 step 3. |
| `mlsInspectGroup { groupInfo, tree }` | §3 step 1: the members `{ userId, deviceId, stale }` of a served GroupInfo/tree after the whole-group validation of a join; changes nothing. |
| `dsRepin { userId, aik }` / `dsSucceed { userId, record, signature }` | §7, DS side. |

### 10.2 Server

| Endpoint | Behaviour |
| --- | --- |
| `POST /api/link/start` | §1.1 step 1. No session for `purpose: 'link'`; a listed device's session for `'transfer'`. Rate limited per source (5/min) and globally (1,000 open links). |
| `POST /api/link/:id/offer { eph }` | The primary's session. For `link` creates N's pending device; for `transfer` the offerer must be the primary. |
| `GET /api/link/:id` | N (header `X-Link-Claim`) or the offering session: `{ state: 'waiting'\|'offered'\|'granted'\|'expired', eph?, purpose, platform }`. |
| `POST /api/link/:id/messages { dir, data }` · `GET /api/link/:id/messages?dir=&after=` | The sealed relay (≤ 64 messages per direction, ≤ 64 KiB each). `n2p` needs the claim, `p2n` the offering session. |
| `POST /api/link/:id/grant` | P, after publishing the list naming N. |
| `POST /api/link/:id/claim { claim, signature, client? }` | N. Issues the session; once. |
| `DELETE /api/link/:id` | Either side; drops it. |
| `POST /api/devices/:id/revoke` | §4. |
| `PUT /api/devices/succession { record, signature }` · `GET /api/devices/:username` (`succession`) | §5. |
| `GET /api/mls/capability/:username` | §8.1. |
| `GET /api/channels` (+`peer`) | DM channels carry `peer: { id, username }`. |
| `POST /api/messages` | `ephemeral: true` is 410; envelopes to a pair whose DM channel is over 60 days old are 410. |

Frames: `link { id, event: 'hello'\|'offer'\|'grant'\|'message' }` to the offering account's streams; `devices { id, needsList }`; `channel { change: 'remove-device', deviceId }`.

## 11. Who builds what

| Part | Owner |
| --- | --- |
| chatcore: link crypto, `signDeviceCert`, pins export/import, companion mode, succession (sign, accept, DS), stale-leaf validator, `mlsCheckDm`, `stale` in members; server: link relay, revoke, succession, capability, DM `peer`, typing/60-day rules; this document | mls-core |
| Web: QR (show/scan), confirmation screen, bundle build/import, companion mode in `account.js`/`groups.js`, revocation flow and leaf removal, primary transfer UI, recovery UI, DM migration (pointer, store `migrated`), typing via groups; browser tests | web-m4 |
| App: same on iOS/Android/macOS, camera QR scan, bridge for the new chatcore calls; widget and cross-client tests | flutter-m4 |

## 12. Pinned vectors

`crates/chatcore/tests/link.rs` pins, for fixed secrets: the QR text, `salt`, `k_n2p`, `k_p2n`, the 6-digit code, a sealed message, the start/claim/succession bytes (SHA-256) and a signed succession record. `tests/unit/link.test.ts` checks the same values against `packages/signaling/public/devices.js` (`startBytes`, `claimBytes`, `successionBytes`). Clients must reproduce them.
