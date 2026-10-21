# M6: the account key on every device, and an encrypted key backup (shared contract)

Contract for chatcore (`crates/chatcore`), the server (`packages/signaling/`), the web client (`packages/signaling/public/`) and the app (`apps/chat/`). It changes [m5-linking.md](m5-linking.md) (linking, revocation, transfer, recovery) and builds on [devices.md](devices.md). Anything not said here stays as it is.

**Why.** In M5 only the primary holds the account identity key (AIK); every other device is a companion that must be linked from it, and losing the primary means a new identity and a "security code changed" for every contact. M6 makes every trusted device hold the AIK (no primary for crypto) and lets a new device restore it from an end-to-end encrypted backup unlocked with a passphrase or a recovery key, so signing in on a new device needs no other device and keeps every contact's verification.

## 0. Words

| Term | Meaning |
| --- | --- |
| AIK | The account identity key `{ dh, sign }`, as in M5. Safety numbers are its fingerprint. |
| Full device | A listed device that holds the AIK secret. Every device ends up full. Replaces "primary" for everything that signs (lists, device certificates, succession records). |
| Companion | A listed device that does not hold the AIK (yet): one that has just followed a rotation (§6) or a pre-M6 companion (§7). It works as in M5 and asks to be rekeyed (§5). |
| Inbox device | The one device that runs the legacy 1:1 Double Ratchet: the server's `is_primary` device, unchanged in meaning for `/api/keys` and the 1:1 inbox. Nothing else about it is special. |
| AccountKey | The AIK secret in the byte form of §1. The only form in which it leaves a device. |
| Unlock keys | Two X25519 key pairs derived from the passphrase and from the recovery key (§3). The backup is sealed to their public halves. |

## 1. The AccountKey bytes

```
AccountKey = text16("webrtc-bun-account-key-v1") ‖ text16(userId) ‖ bytes8(signSeed, 32) ‖ bytes8(dhSecret, 32)
```

`signSeed` is the Ed25519 seed (RFC 8032), `dhSecret` the X25519 secret scalar as stored (RFC 7748 bytes, unclamped as generated). `text16`/`bytes8` as in m5 §1.3. 101 + len(userId) bytes.

An importer checks that `userId` is its account and that the public keys derived from the two secrets equal the account identity it pins (or, on restore, the identity the server publishes for the account, §4). Any mismatch: error `invalid`, nothing changes.

- **chatcore** `exportAccountKey { userId }` returns the bytes (base64url) on a full core; `companion` otherwise. `importAccountKey { userId, key }` turns a companion (or an empty core, on restore) into a full core holding that identity: the `account` row goes, `identity` is set, pins and MLS state are kept, `own-previous` entries are kept.
- **Web.** The AIK sign key must become exportable. New identities generate the Ed25519 key extractable and store it **wrapped** (pkcs8 under the non-extractable wrapping key), exactly like `dhPair()` already stores X25519 keys; it is unwrapped non-extractable for signing and extractable only inside export. A browser whose sign key is a legacy non-extractable `CryptoKey` cannot export it and upgrades by a self-rotation (§6.2) the first time it must export (setting up the backup, linking, or answering a rekey). Web code may instead move the AIK into its chatcore core; either way the bytes of §1 are the interface.
- The AccountKey is never logged, never stored unwrapped, never sent except inside the sealed boxes of §3, §5 and the link grant (§2).

## 2. Linking hands over the AIK

M5 §1 stays, with these changes:

- **Who links.** Any **full** device may scan a QR, look up a short code and offer (server: "the account's primary session" becomes "a session bound to a listed device of the account" in `/api/link/lookup` and `/api/link/:id/offer`). The full device signs the list naming N and N's certificate as the primary did.
- **The grant** gains one field: `"accountKey": "<base64url AccountKey>"`. It travels only inside the sealed link channel, after the 6-digit code was confirmed on both screens. N runs M5 §1.6 checks, then `importAccountKey` (or the web equivalent). N is full.
- **Transfer** (`purpose: 'transfer'`, M5 §5) is no longer offered between full devices. Clients drop the "Use this device instead" action. The server keeps the endpoint for pre-M6 clients.
- A device that was linked is the inbox device only if it claims the inbox as in M5 (it does not by default).

## 3. The encrypted backup

### 3.1 Unlock keys

- **Passphrase.** NFKC, UTF-8, at least 10 characters and not in the client's small common-passwords list. `seed = Argon2id(passphrase, salt, m = 65536 KiB, t = 3, p = 1, out = 32)` with a 16-byte random `salt`. `passSecret = HKDF-SHA-256(ikm = seed, salt = none, info = "webrtc-bun-backup-pass-v1", 32)`, used as an X25519 secret; `passPub` its public key.
- **Recovery key.** 32 random bytes shown once as **24 BIP-39 English words** (standard checksum). `recoverySecret = HKDF-SHA-256(ikm = entropy, salt = none, info = "webrtc-bun-backup-recovery-v1", 32)`; `recoveryPub` its public key. Input is accepted case-insensitively with any whitespace, and with each word's first four letters.

Both are computed in chatcore (web: the wasm core; the app: the native core) so both clients agree byte for byte.

### 3.2 The box

```
box(recipientPub, plaintext, aad, info):
  eph = new X25519 key
  key = HKDF-SHA-256(ikm = X25519(eph, recipientPub), salt = ephPub ‖ recipientPub, info, 32)
  nonce = 12 random bytes
  return base64url( ephPub (32) ‖ nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad) )
```

Backup boxes use `info = "webrtc-bun-backup-box-v1"` and `aad = text16("webrtc-bun-backup-v1") ‖ text16(userId) ‖ bytes8(aikSign)`; the plaintext is the AccountKey. Sealing needs only the public key, so **any full device can re-seal the backup without the passphrase or recovery key** (§6).

### 3.3 The record

The server stores one record per account:

```
{ "v": 1, "userId", "aikSign",                                         // the AIK the boxes hold
  "kdf": { "alg": "argon2id", "salt": "<22>", "m": 65536, "t": 3, "p": 1 },
  "passPub": "<43>", "recoveryPub": "<43>",
  "pass": "<box>", "recovery": "<box>",
  "signature": "<86>",                                                  // AIK over the keys bytes below
  "updatedAt": ms }
```

**Keys bytes** (signed by the AIK, checked by the server and by every device before it seals): `text16("webrtc-bun-backup-keys-v1") ‖ text16(userId) ‖ bytes8(aikSign) ‖ bytes8(salt) ‖ u32(m) ‖ u32(t) ‖ u32(p) ‖ bytes8(passPub) ‖ bytes8(recoveryPub)`. Without it a server could hand a device its own public keys and receive the next AIK.

### 3.4 Setting it up and changing it

On a full device (Settings > Devices > "Account backup"; and offered once after sign-in when the account has none):

1. The user picks a passphrase (typed twice).
2. The client shows the 24 recovery words once, with Copy, and asks the user to type three of them back (positions chosen at random) before continuing.
3. chatcore `backupCreate { userId, passphrase, accountKey? }` -> the record without `signature`/`updatedAt`; the client signs the keys bytes with the AIK (`backupSignKeys` in chatcore for a core-held AIK) and `PUT /api/backup`.

- **Change passphrase:** new salt and `passPub`, new `pass` box; `recoveryPub`/`recovery` unchanged. Needs only the new passphrase.
- **New recovery key:** new words, `recoveryPub`, `recovery`; the old words stop working.
- **Turn off:** `DELETE /api/backup`. Signing in on a new device then needs another device (M5 linking) or a fresh start.

### 3.5 The server

| Endpoint | Behaviour |
| --- | --- |
| `PUT /api/backup` | Session bound to a listed device. Body: the record without `updatedAt`. 400 unless every field is canonical (lengths, base64url, `kdf` exactly the values above, each box exactly 32 + 12 + len(AccountKey) + 16 bytes), `userId` is the session's, `aikSign` equals the published identity, and `signature` verifies the keys bytes under it. Replaces the record; 200 `{ updatedAt }`. Frame `backup { id }` to the account. |
| `GET /api/backup` | Any session of the account, **including a pending device's** (that is the restore case). The record or 404. Rate limited: 10 per hour and 30 per day per account, counted before the lookup; 429 after. Every successful read is logged in the account's security events and pushes a `backup { id, read: true, deviceId }` frame so the other devices can show "Your backup was opened on a new device". |
| `DELETE /api/backup` | Session bound to a listed device. 204. |

The server never sees the passphrase, the recovery words, an unlock secret or an AccountKey. Someone with the server's data can still try passphrases offline against `pass` at Argon2id cost; that is the accepted risk of a passphrase (the recovery key cannot be guessed).

## 4. Signing in on a new device (restore)

The screen a signed-in browser or app shows when the account has devices and this one is not listed (today's "Link this browser" screen) becomes:

> **Use your account here.** Your messages are end-to-end encrypted. Unlock them on this device with your backup, or link it from a device you already use.
> [Enter your passphrase] [Use your recovery key] [Link from another device] — and, small, "I can't do any of these" (M5 §6 fresh start, unchanged, with its warning).

When the account has no backup the first two are hidden and a line says "Turn on account backup on one of your devices to sign in without it next time."

Restore, after passkey sign-in (session, device `pending`):

1. `GET /api/backup`; the account's published identity (`GET /api/devices/:username`); the client checks the record's signature over the keys bytes under the published `sign` and that `aikSign` equals it.
2. The user enters the passphrase or the words. chatcore `backupOpen { record, passphrase | words }` derives the unlock secret, opens the matching box and returns the AccountKey. A wrong passphrase is error `auth` ("That passphrase doesn't open your backup.").
3. `importAccountKey` (checks against the published identity, §1). The device is full.
4. It publishes DeviceList version + 1 naming itself (409: re-fetch, re-apply, retry; §6.1), signs its own MLS certificate, uploads KeyPackages and joins its groups by external join exactly as a linked device (M5 §3). There is no bundle: history from before the restore is not available on this device; the conversation list comes from `GET /api/channels`.
5. Pins: the new device starts with no contact pins. It pins each contact on first use as a fresh device would; contacts' verification of *this account* is unaffected (same AIK). Clients say so on the success screen: "Your contacts don't need to re-verify you. Re-verify them from this device if you want the check marks here."

A restore is not a security-code change: nothing is published except the list. A server that serves a false identity and box can only hand the device a key it made itself; every contact then sees an unverified code change (no succession chain from the real AIK), so it is never a silent takeover.

## 5. Rekey: a companion becomes full again

Used after a rotation (§6) and to upgrade pre-M6 companions (§7). The server relays; it is not trusted for which leaf belongs to which device, exactly as recert (M5 §5.2.2), which it replaces for M6 clients.

1. **Companion** (its pinned account identity is the published one and it does not hold the AIK): chatcore `rekeyRequest { userId, deviceId }` makes an ephemeral X25519 key (kept in the store, `rekey:pending`) and returns `{ eph, leafSigKey, signature }`, where the **MLS leaf signature key** signs
   `text16("webrtc-bun-rekey-v1") ‖ text16(userId) ‖ text16(deviceId) ‖ bytes8(eph) ‖ bytes8(leafSigKey) ‖ bytes8(aikSign)` (`aikSign` = the account key it pins now). `PUT /api/devices/rekey { platform, eph, leafSigKey, signature }`: 403 unless the session is bound to a listed device; replaces an earlier request. Frame `rekey { id, deviceId }` to the account.
2. **Any full device** (on the frame, and on start): `GET /api/devices/rekey` (listed device's session) -> `{ requests: [ { deviceId, platform, eph, leafSigKey, signature } ] }`. For each it requires, in this order: the device is in the newest list it signed or verified and not revoked; the signature verifies under `leafSigKey` over the bytes above with **its own** current `aikSign`; `mlsLeafKnown { deviceId, leafSigKey, groups }` over all its channels (M5 §5.2.2). Only then: `rekeyAnswer { userId, deviceId, platform, eph, leafSigKey, now }` (chatcore, full core) returns `box(eph, plaintext, aad, "webrtc-bun-rekey-box-v1")` with
   `plaintext = { "v":1, "accountKey": "<base64url>", "cert": "<DeviceCert JSON for that leaf under the current AIK>" }` and `aad = text16("webrtc-bun-rekey-v1") ‖ text16(userId) ‖ text16(deviceId) ‖ bytes8(eph)`. `PUT /api/devices/rekey/:deviceId { box }` (201; 404 if no such request).
3. **Companion** (frame `rekey { answered: true }`, or polling `GET /api/devices/rekey/mine` -> `{ box }` or `{ box: null }`): `rekeyOpen { userId, deviceId, box }` opens it with the pending ephemeral secret, checks the AccountKey against its pinned identity and the cert (names its device and leaf, verifies under the AIK), installs both: the core is full. Then `mlsCommit { update: true }` in each group, `DELETE /api/devices/rekey`.

A device in no group that a full device shares cannot be answered (nothing proves its leaf); it waits and asks again on its next start. The UI can offer "Link again" for it.

## 6. Signing lists with many key holders, and revocation

### 6.1 Lists

Any full device signs the next DeviceList. The server's next-version-and-prevHash rule (devices.ts) already makes concurrent writers safe: on 409 the client fetches the current list, verifies it, re-applies its own change (add itself, drop a revoked device) and signs again; at most 5 attempts.

### 6.2 Rotation

Every holder of the AIK can sign anything, so **removing a device that holds the AIK means replacing the AIK**. The rotation is M5 succession run by one device on itself:

1. `successionStart` (or, web, mint a wrapped identity), `signSuccession` with the current AIK, `PUT /api/devices/succession`, adopt it (`successionComplete`), `PUT /api/keys` with the new identity (this moves the inbox to this device, as M5), DeviceList version 1 under the new AIK naming every live device except the removed one, its own new MLS certificate.
2. If a backup exists: re-seal `pass` and `recovery` to the **signed** `passPub`/`recoveryPub` (verified under the old AIK) with the new AccountKey, sign the keys bytes with the new AIK, `PUT /api/backup`. The removed device cannot open the new boxes.
3. Other devices follow the chain with `adoptSuccession` (M5 §5.2.1; they are companions for a moment) and rekey (§5). Contacts follow the succession with their verification kept (M5 §5.3); the notice reads "<name> updated their security key. Verification kept."

Rotation runs:

- **On revoke.** `POST /api/devices/:id/revoke` from a full device is followed by a rotation on that device. The server no longer refuses to revoke the inbox device (the 409 for the primary goes); revoking it moves the inbox to the revoker. A revoke from a session that is not full (a pending device, a companion) only cuts the device; the next full device to start sees `devices { needsRotation: true }` (set by the server when a revoked device was listed under the current AIK) and rotates.
- **For the web upgrade** (§1): same steps, nothing is removed.

Two devices rotating at once: the server accepts the first succession; the second gets 409 (its `oldSign` is no longer the published key), fetches the chain, adopts it and asks to be rekeyed.

What a revoked device keeps: the old AIK. With it, it can no longer publish anything (the server takes only the current key, and its sessions are gone), and contacts treat its key as a predecessor only until the record's time. It can still try the backup passphrase with a new passkey sign-in; the revoke screen offers "Also change your backup passphrase" and says why.

## 7. Moving existing accounts

- **The app primary** holds the AIK in chatcore: already exportable. It answers rekeys and can set up the backup at once.
- **A web primary** with a non-extractable sign key rotates once (§6.2) the first time it needs to export; until then it can still sign as before.
- **Existing companions** send a rekey request (§5) on their first start on an M6 client and become full when a full device answers. Until then they work as M5 companions.
- **Pre-M6 clients** keep working: they still see a signed list, certificates and successions. A pre-M6 companion whose account rotates follows the chain (M5) and waits for a recert it no longer gets; M6 full devices also answer `GET /api/devices/recert` requests (M5 §5.2.2) during the migration so old clients recover.
- UI: the words "primary" and "companion" disappear from settings. The device list shows each device with "Can unlock your account" (full) or "Waiting for keys" (companion).

## 8. Commands, endpoints, frames (additions)

### 8.1 chatcore

| Command | Result |
| --- | --- |
| `exportAccountKey { userId }` | base64url AccountKey. Full core only (`companion`). |
| `importAccountKey { userId, key }` | the identity `{ dh, sign }` now held. Checks §1 against the pinned account, or, on a core with no account (restore), against `published` given as `{ dh, sign }`. |
| `backupCreate { userId, passphrase, accountKey?, now }` | `{ record (unsigned), words }`. `accountKey` is required when the core is not full (the web keeps the AIK in WebCrypto). |
| `backupSignKeys { userId, record }` | the AIK signature over the keys bytes (full core). |
| `backupReseal { userId, record, accountKey?, passphrase?, newRecovery? }` | the updated unsigned record: re-seal after rotation (no secrets needed), change passphrase, new recovery key (returns `words`). Verifies the record's signature under the **current or previous** own AIK first. |
| `backupOpen { userId, record, passphrase? , words? }` | base64url AccountKey; `auth` on a wrong passphrase or words, `invalid` on bad words (checksum). |
| `rekeyRequest { userId, deviceId }` / `rekeyAnswer { … }` / `rekeyOpen { userId, deviceId, box }` | §5. |

Argon2id from the `argon2` crate, BIP-39 from a vendored English wordlist (no new runtime dependency on the web beyond the existing wasm core).

### 8.2 Server

`PUT|GET|DELETE /api/backup` (§3.5); `PUT|GET|DELETE /api/devices/rekey`, `PUT /api/devices/rekey/:deviceId`, `GET /api/devices/rekey/mine` (§5); `/api/link/lookup` and `/api/link/:id/offer` accept any listed device's session (§2); `POST /api/devices/:id/revoke` no longer 409s on the inbox device and sets `needsRotation` when the caller is not full (the server cannot know who is full: it sets it on every revoke of a device listed under the current AIK and clears it on the next succession). Migration `user_version` 7: `account_backups`, `rekey_requests`. Frames `backup { id, read? }`, `rekey { id, deviceId, answered? }`, `devices { needsRotation? }`.

## 9. Who builds what

| Part | Owner |
| --- | --- |
| chatcore §1, §3.1-3.2, §5, §8.1, wasm build, vectors; server §2, §3.5, §5, §6, §8.2; unit tests | mls-core |
| Web: wrapped exportable sign key and upgrade rotation, grant `accountKey`, backup setup/change/restore screens, rekey (both sides), rotation on revoke, device list wording; browser tests | web-m4 |
| App: same; bridge for the new commands; widget and cross-client tests | flutter-m4 |

## 10. Pinned vectors

`crates/chatcore/tests/account_key.rs` pins, for fixed inputs: AccountKey bytes; Argon2id seed, `passSecret`/`passPub` for passphrase `"correct horse battery staple"` and a fixed salt; the 24 words and `recoveryPub` for entropy `00..1f`; a box for a fixed ephemeral key and nonce; the keys bytes and their SHA-256; the rekey request bytes. `tests/unit/account-key.test.ts` checks the web's keys bytes and rekey bytes against the same values.
