# M6: the account key on every device, and an encrypted key backup (shared contract)

Contract for chatcore (`crates/chatcore`), the server (`packages/signaling/`), the web client (`packages/signaling/public/`) and the app (`apps/chat/`). It changes [m5-linking.md](m5-linking.md) (linking, revocation, transfer, recovery) and builds on [devices.md](devices.md). Anything not said here stays as it is.

**Why.** In M5 only the primary holds the account identity key (AIK); every other device is a companion that must be linked from it, and losing the primary means a new identity and a "security code changed" for every contact. M6 makes every trusted device hold the AIK (no primary for crypto) and lets a new device restore it from an end-to-end encrypted backup unlocked with a passphrase or a recovery key, so signing in on a new device needs no other device and keeps every contact's verification.

**Threat model.** The server is untrusted for key material and for which key or leaf belongs to which device. A thief may hold an unlocked stolen device until it is revoked. Passkey sign-in alone gives only a pending session. **The passphrase (or recovery key) is the final authority**: whoever knows it can always take the account back from a stolen device (§6.4), and a device without it cannot rotate the AIK or change the backup once a backup exists.

## 0. Words

| Term | Meaning |
| --- | --- |
| AIK | The account identity key `{ dh, sign }`, as in M5. Safety numbers are its fingerprint. |
| Full device | A listed device that holds the AIK secret. Replaces "primary" for everything that signs (lists, device certificates, succession records). |
| Companion | A listed device that does not hold the AIK (yet): one that has just followed a rotation (§6), one linked by short code (§2), or a pre-M6 companion (§7). It works as in M5. |
| Inbox device | The one device that runs the legacy 1:1 Double Ratchet: the server's `is_primary` device, unchanged in meaning for `/api/keys` and the 1:1 inbox. Nothing else about it is special. |
| AccountKey | The AIK secret in the byte form of §1. The only form in which it leaves a device. |
| Unlock keys | Two X25519 key pairs derived from the passphrase and from the recovery key (§3.1). Their public halves are **never given to the server**. |
| Backup keys | `{ epoch, passPub, recoveryPub }`: what a full device keeps locally so it can re-seal the backup (§3.3). |

## 1. The AccountKey bytes

```
AccountKey = text16("webrtc-bun-account-key-v1") ‖ text16(userId) ‖ bytes8(signSeed, 32) ‖ bytes8(dhSecret, 32)
```

`signSeed` is the Ed25519 seed (RFC 8032), `dhSecret` the X25519 secret as stored (RFC 7748 bytes). `text16`/`bytes8` as in m5 §1.3. 95 + len(userId) bytes (117 for a 22-character user id).

An importer checks that `userId` is its account and that the public keys derived from the two secrets equal the account identity it pins (or, on restore, the identity the server publishes for the account, §4). Any mismatch: error `invalid`, nothing changes.

- **chatcore** `exportAccountKey { userId }` returns the bytes (base64url) on a full core; `companion` otherwise. `importAccountKey { userId, key, published? }` turns a companion (or an empty core, on restore) into a full core holding that identity: the `account` row goes, `identity` is set, pins and MLS state are kept, `own-previous` entries are kept.
- **Web.** The AIK sign key must become exportable. New identities generate the Ed25519 key extractable and store it **wrapped** (pkcs8 under the non-extractable wrapping key), exactly like `dhPair()` already stores X25519 keys; it is unwrapped non-extractable for signing and extractable only inside export. A browser whose sign key is a legacy non-extractable `CryptoKey` cannot export it and upgrades by a self-rotation (§6.2) the first time it must export. Web code may instead move the AIK into its chatcore core; either way the bytes of §1 are the interface.
- **Web risk, stated.** Any script running in the app's origin can unwrap the wrapped key extractable, so an XSS bug now leaks the AIK instead of only using it. The web client therefore keeps the server's strict CSP (`script-src 'self'`, no inline script, no `eval`; verify `server.ts` sends it on every HTML response and add it where missing) and runs Argon2 inside the core worker. Export and wrapping stay with the WebCrypto key on the main thread (moving them to a worker would not help: the wrapping key in IndexedDB is reachable from the whole origin anyway); the AIK is also imported into the group core, which needs it to sign.
- The AccountKey is never logged, never stored unwrapped, never sent except inside the sealed boxes of §3, §5 and the QR link grant (§2). Buffers holding it are zeroed after use where the platform allows.

## 2. Linking

M5 §1 stays, with these changes:

- **Who links.** Any **full** device may scan a QR, look up a short code and offer (server: "the account's primary session" becomes "a session bound to a listed device of the account" in `/api/link/lookup` and `/api/link/:id/offer`). The full device signs the list naming N and N's certificate as the primary did.
- **QR links hand over the AIK.** The grant gains `"accountKey": "<base64url AccountKey>"` and `"backupKeys": { "epoch", "passPub", "recoveryPub" } | null`. They travel only inside the sealed link channel, after the 6-digit code was confirmed on both screens. N runs M5 §1.6 checks, then `importAccountKey` and stores the backup keys. N is full.
- **Short-code links do not.** In code mode the 6-digit code is the only thing that authenticates the exchange, so a lucky relay would get the AIK for good. A code-linked device is a companion (no `accountKey`, no `backupKeys` in the grant). It becomes full by entering the passphrase or recovery key (§4 steps 2-3, against its pinned identity) or by a QR link. The UI says so on the short-code screen: "To unlock everything on this device, enter your passphrase afterwards."
- **Transfer** (`purpose: 'transfer'`, M5 §5) is no longer offered between M6 devices. Clients drop the "Use this device instead" action. The server keeps the endpoint for pre-M6 clients.
- A linked device is the inbox device only if it claims the inbox as in M5 (it does not by default).

## 3. The encrypted backup

### 3.1 Unlock keys

- **Passphrase.** The client offers a **generated** passphrase by default (6 words from the BIP-39 English list, about 66 bits, shown with Copy). A custom passphrase must be at least 14 characters after NFKC normalisation and not in the client's common-passwords list. `seed = Argon2id(passphrase NFKC UTF-8, salt, m, t, p, out = 32)` with a 16-byte random `salt`; today `m = 65536` KiB, `t = 3`, `p = 1`.
  - `passSecret = HKDF-SHA-256(ikm = seed, salt = none, info = "webrtc-bun-backup-pass-v1", 32)`, an X25519 secret; `passPub` its public key.
  - `passProof = HKDF-SHA-256(ikm = seed, salt = none, info = "webrtc-bun-backup-pass-proof-v1", 32)`.
- **Recovery key.** 32 random bytes of **entropy**, shown once as **24 BIP-39 English words** (standard checksum). Only the raw 32 bytes are used, never the BIP-39 PBKDF2 seed. Input: NFKD, case-insensitive, any whitespace; each word may be given by its first four letters; a prefix matching no word, or a bad checksum, is error `invalid`. The screen says "This is not a wallet seed; don't enter it anywhere else."
  - `recoverySecret = HKDF-SHA-256(ikm = entropy, salt = none, info = "webrtc-bun-backup-recovery-v1", 32)`; `recoveryPub`.
  - `recoveryProof = HKDF-SHA-256(ikm = entropy, salt = none, info = "webrtc-bun-backup-recovery-proof-v1", 32)`.

All of this is computed in chatcore (web: the wasm core in its worker, with the wasm memory allowed to grow to at least 96 MiB; the app: the native core) so both clients agree byte for byte.

### 3.2 The box

```
box(recipientPub, plaintext, aad, info):
  eph = new X25519 key
  shared = X25519(eph, recipientPub)            -- all-zero shared secret: error invalid
  key = HKDF-SHA-256(ikm = shared, salt = ephPub ‖ recipientPub, info, 32)
  nonce = 12 random bytes
  return base64url( ephPub (32) ‖ nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad) )
```

Backup boxes: `info = "webrtc-bun-backup-box-v1"`, `aad = text16("webrtc-bun-backup-v1") ‖ text16(userId) ‖ bytes8(aikSign) ‖ u32(epoch)`, plaintext `= AccountKey ‖ bytes8(passPub) ‖ bytes8(recoveryPub)`. Opening a box therefore also yields the backup keys.

### 3.3 The record

The server stores one record per account:

```
{ "v": 1, "userId", "aikSign", "epoch",
  "kdf": { "alg": "argon2id", "salt": "<22>", "m", "t", "p" },
  "passHash": "<43>", "recoveryHash": "<43>",      // SHA-256 of passPub / recoveryPub, not the keys
  "pass": "<box>", "recovery": "<box>",
  "passProofHash": "<43>", "recoveryProofHash": "<43>",   // SHA-256 of the proofs (§3.5)
  "signature": "<86>",                              // AIK over the keys bytes
  "updatedAt": ms }
```

**Keys bytes** (signed by the AIK): `text16("webrtc-bun-backup-keys-v2") ‖ text16(userId) ‖ bytes8(aikSign) ‖ u32(epoch) ‖ bytes8(salt) ‖ u32(m) ‖ u32(t) ‖ u32(p) ‖ bytes8(passHash) ‖ bytes8(recoveryHash) ‖ bytes8(passProofHash) ‖ bytes8(recoveryProofHash)`.

Rules every device follows:

- **A device seals only to backup keys it holds locally** (derived itself at setup, from a QR grant, from a rekey, or from opening a box). It never takes `passPub`/`recoveryPub` from the server, which never has them; the server therefore cannot seal a key of its own to the user's passphrase.
- **`epoch` only goes up.** Every change (re-seal after a rotation, new passphrase, new recovery key) is `epoch + 1`. A device stores the highest epoch it has seen and refuses a record or backup keys with a lower one. A device ignores any record signed by a key other than the account's **current** AIK (never a predecessor's).
- `kdf` is versioned: the server and clients accept `m` 65536-1048576, `t` 3-10, `p` 1-4, so the cost can be raised later by a re-seal with a new passphrase.

### 3.4 Setting it up and changing it

On a full device (Settings > Devices > "Account backup"; and offered once after sign-in when the account has none):

1. The user takes the generated passphrase or types their own (twice).
2. The client shows the 24 recovery words once and asks the user to type three of them back (positions chosen at random). Copy writes them to the clipboard and clears it after 60 s; the screen says to store them offline.
3. chatcore `backupCreate { userId, passphrase, accountKey?, now }` -> `{ record (unsigned), words, backupKeys, passProof, recoveryProof }`; the AIK signs the keys bytes; `PUT /api/backup` with the record and the two proofs; the device stores `backupKeys`.

Changes (each `epoch + 1`, each needs the **current passphrase or recovery key**, proved as in §3.5):

- **Change passphrase:** new salt, `passPub`, `pass` box, `passProofHash`; the recovery side is re-sealed under the new epoch with the locally held `recoveryPub`.
- **New recovery key:** new words, `recoveryPub`, `recovery` box, `recoveryProofHash`.
- **Turn off:** `DELETE /api/backup`.

The new backup keys reach the other full devices with the next rekey (§5) or, simpler, on the `backup` frame each full device fetches the record and, if its epoch is newer, asks the user nothing and waits: it seals nothing until it has the new keys (it gets them from a rekey answer, which always carries the current backup keys, or the next time it opens the backup).

### 3.5 The server

The proofs are what lets the server enforce "the passphrase is the final authority" without ever seeing the passphrase: it stores only `SHA-256(proof)`.

| Endpoint | Behaviour |
| --- | --- |
| `PUT /api/backup` | Session bound to a listed, non-revoked device. Body: the record without `updatedAt`, plus `proof` (the current `passProof` or `recoveryProof`, base64url) and, when they change, the new `passProof`/`recoveryProof` (the server checks their hashes against the record). 400 unless every field is canonical (lengths, base64url, `kdf` in range, each box exactly 32 + 12 + len(AccountKey) + 66 + 16 bytes: the plaintext is the AccountKey and two `bytes8` keys of 33 bytes each, 243 bytes for a 22-character user id), `userId` is the session's, `aikSign` equals the published identity, `signature` verifies the keys bytes under it, and `epoch` is the stored epoch + 1 (or 1 for the first record; an existing record with another epoch answers **409** `{ error, epoch }` so the client re-fetches; the first record needs both new proofs). When a record exists, `proof` must hash to its `passProofHash` or `recoveryProofHash`, **except** for a re-seal that keeps both proof hashes and the kdf unchanged and comes right after a succession accepted by the server (§6.2; the server allows one such PUT per accepted succession). 403 on a wrong proof, counted like a failed restore (rate limit below). Answer 200 `{ updatedAt }`, frame `backup { id, epoch }`. |
| `GET /api/backup` | Any session of the account, **including a pending device's** (the restore case). The whole record (the proof hashes too: the restoring device needs them to check the signature over the keys bytes; they give an offline guesser nothing the `pass` box doesn't), or 404. Rate limited per account (10 per hour, 30 per day) **and** per session (5 per hour), counted before the lookup; 429 after, so a stranger's pending session cannot use up the owner's quota. Every read is logged in the account's security events and pushes `backup { id, read: true, deviceId }`; other devices show "Your backup was opened on a new device". |
| `DELETE /api/backup` | Listed device's session and `{ proof }`. 204. |
| `GET /api/devices/<own username>` | The owner's own view gains `backup: { epoch, updatedAt } \| null`, so clients can show backup state without the rate-limited, logged `GET /api/backup`. Not shown to other accounts. |

The server never sees the passphrase, the recovery words, the unlock keys or an AccountKey. Someone with the server's data can still try passphrases offline (Argon2id per guess); that is the accepted cost of a passphrase, and why the default is a generated one.

## 4. Signing in on a new device (restore)

The screen a signed-in browser or app shows when the account has devices and this one is not listed (today's "Link this browser" screen) becomes:

> **Use your account here.** Your messages are end-to-end encrypted. Unlock them on this device with your backup, or link it from a device you already use.
> [Enter your passphrase] [Use your recovery key] [Link from another device] — and, small, "I can't do any of these" (M5 §6 fresh start, unchanged, with its warning).

When the account has no backup the first two are hidden and a line says "Turn on account backup on one of your devices to sign in without it next time."

Restore, after passkey sign-in (session, device `pending`):

1. `GET /api/backup` and the account's published identity (`GET /api/devices/:username`). Check the record's signature over the keys bytes under the published `sign`, and `aikSign` equals it.
2. The user enters the passphrase or the words. chatcore `backupOpen { userId, record, passphrase | words }` derives the unlock secret, opens the matching box (its `aad` names the record's `aikSign` and `epoch`), checks `SHA-256` of the `passPub`/`recoveryPub` inside against `passHash`/`recoveryHash`, and returns `{ accountKey, backupKeys }`. Wrong passphrase: error `auth` ("That passphrase doesn't open your backup.").
3. `importAccountKey { …, published }`, store `backupKeys`. The device is full.
4. It publishes DeviceList version + 1 naming itself (409: re-fetch, re-apply, retry; §6.1), signs its own MLS certificate, uploads KeyPackages and joins its groups by external join exactly as a linked device (M5 §3). There is no bundle: history from before the restore is not available here; the conversation list comes from `GET /api/channels`.
5. Pins: the device starts with no contact pins and pins each contact on first use. Contacts' verification of this account is unaffected (same AIK).

**Trust.** The box can only be made by someone who knows `passPub` or `recoveryPub`, which only the user's devices hold, so a server cannot hand the device a key of its own that the passphrase opens. The device still trusts the server for its contacts' keys (first use), as any fresh device does. The success screen shows the account's safety number and says: "Your contacts don't need to re-verify you. To check this device, compare a contact's safety number with them, or with your other device."

## 5. Rekey: a companion becomes full again

Used after a rotation (§6) and to upgrade pre-M6 companions (§7). The server relays; it is not trusted for which leaf belongs to which device, exactly as recert (M5 §5.2.2), which it replaces for M6 clients. Code-linked devices (§2) are **not** rekeyed this way: they unlock with the passphrase.

1. **Companion** (its pinned account identity is the published one and it does not hold the AIK): chatcore `rekeyRequest { userId, deviceId, platform }` makes an ephemeral X25519 key (kept in the store, `rekey:pending`) and returns `{ eph, leafSigKey, signature }`, where the **MLS leaf signature key** signs the *request bytes*
   `text16("webrtc-bun-rekey-v1") ‖ text16(userId) ‖ text16(deviceId) ‖ text16(platform) ‖ bytes8(eph) ‖ bytes8(leafSigKey) ‖ bytes8(aikSign)` (`aikSign` = the account key it pins now). `PUT /api/devices/rekey { platform, eph, leafSigKey, signature }`: 403 unless the session is bound to a listed device; replaces an earlier request. Frame `rekey { id, deviceId }`.
2. **Any full device** (on the frame, and on start): `GET /api/devices/rekey` (listed device's session) -> `{ requests: [ { deviceId, platform, eph, leafSigKey, signature } ] }`. For each it requires, in order: the device is in the newest list it signed or verified and not revoked, and was not linked by short code (its sealed `meta` says `via: 'code'`, see below); the signature verifies under `leafSigKey` over the request bytes with **its own** current `aikSign`; `mlsLeafKnown { deviceId, leafSigKey, groups }` over all its channels (M5 §5.2.2). Only then: `rekeyAnswer { userId, deviceId, platform, eph, leafSigKey, now }` (chatcore, full core) returns `box(eph, plaintext, aad, "webrtc-bun-rekey-box-v1")` with
   `plaintext = { "v":1, "accountKey": "<base64url>", "cert": "<DeviceCert JSON for that leaf and platform under the current AIK>", "backupKeys": { "epoch", "passPub", "recoveryPub" } | null }` and `aad = text16("webrtc-bun-rekey-v1") ‖ text16(userId) ‖ text16(deviceId) ‖ text16(platform) ‖ bytes8(eph) ‖ bytes8(leafSigKey) ‖ bytes8(aikSign)`. `PUT /api/devices/rekey/:deviceId { box }` (201; 404 if no such request).
3. **Companion** (frame `rekey { answered: true }`, or polling `GET /api/devices/rekey/mine` -> `{ box }` or `{ box: null }`): `rekeyOpen { userId, deviceId, platform, box }` opens it with the pending ephemeral secret, checks the AccountKey against its pinned identity and the cert (names its device, platform and leaf, verifies under the AIK), installs both and the backup keys (only if their epoch is not lower than the one it holds): the core is full. Then `mlsCommit { update: true }` in each group, `DELETE /api/devices/rekey`.

A device in no group that a full device shares cannot be answered (nothing proves its leaf); it waits and asks again on its next start, and the UI offers "Enter your passphrase" instead.

The `via` field lives **inside the sealed `meta`** of the device's list entry (devices.md: `{ label, platform, via? }`), so the list's byte layout does not change: only AIK holders can read or write it, and the AIK signature covers the ciphertext. The full device that links a device by short code seals `via: 'code'` into its meta; absent means QR, restore or pre-M6. The device drops it (re-seals its meta without `via`) in the first list it publishes itself after unlocking with the passphrase.

## 6. Lists, rotation and revocation

### 6.1 Lists

Any full device signs the next DeviceList. The server's next-version-and-prevHash rule (devices.ts) already makes concurrent writers safe: on 409 the client fetches the current list, verifies it, re-applies its own change (add itself, drop a revoked device) and signs again; at most 5 attempts.

### 6.2 Rotation

Every holder of the AIK can sign anything, so **removing a device that holds the AIK means replacing the AIK**. The rotation is M5 succession run by one device on itself:

1. A full core rotates itself with `rotateIdentity { userId, at, key?, record?, signature?, commit? }` (two steps: `commit: false` prepares and returns `{ identity, record, key }` without changing anything; once `PUT /api/devices/succession` was accepted, the same call with that `key`, `record` and `signature` swaps the identity, so a refused or lost request leaves the core on the old key. The prepared rotation is **kept in the core's store** (`rotation:pending`, protected like the identity): the server may have taken the record while the new key existed nowhere else, and an app that dies between the `PUT` and the commit would otherwise leave the account on a key nobody holds. A second prepare is refused (`pending`) until the first is committed or dropped. On start a client asks `rotationPending {}` (`{ identity, record } | null`): if the server publishes that identity it commits with `rotateIdentity { userId }` alone (no key: the stored one) and finishes the rotation (list v1, the re-seal under the server's proof-free allowance, which lives on the server and survives the restart); if the server still publishes the old key it calls `rotationDrop {}`. Following someone else's rotation (`adoptSuccession`) drops it. chatcore: mints the new key, or takes `key`, an AccountKey the web minted in WebCrypto; signs the succession record with the current AIK, or checks the `record`/`signature` the web signed; swaps the identity, keeps the old one as `own-previous` until `at`, keeps pins and MLS state; returns `{ identity, record }`). `successionStart`/`successionComplete` stay for the pre-M6 companion-to-primary transfer. Then `PUT /api/devices/succession { record, signature, proof? }` with the record, `PUT /api/devices/succession { record, signature, proof? }`, adopt it (`successionComplete`), `PUT /api/keys` with the new identity (this moves the inbox to this device, as M5), DeviceList version 1 under the new AIK naming every live device except the removed ones, its own new MLS certificate.
2. If a backup exists: re-seal both boxes with the new AccountKey to the **locally held** backup keys at `epoch + 1`, sign the keys bytes with the new AIK, `PUT /api/backup` (the one proof-free re-seal the server allows after a succession, §3.5). The removed device cannot open the new boxes without the passphrase.
3. Other devices follow the chain (M5 §5.2.1; `adoptSuccession` also works on a full core: it becomes a companion of the new key and keeps the old one in `own-previous`) and rekey (§5), **only if** list v1 under the new key still names them. A device cannot tell from server state whether a removal was the user's own (the rotation itself revokes every device it drops, and revoked rows are not served), so the check is against **this device's own last verified list**: if list v1 drops any device that list named, the device follows but always shows a notice naming who rotated and what was removed — "Your account key was changed from <label>, which removed <labels>. If this wasn't you, take your account back" (§6.4) — until the user dismisses it. A rotation that drops *this* device is not followed (the device shows the same notice and offers restore). With a backup, the server's proof check (§6.3) is what stops a thief from rotating; without one, this notice is the only signal. Contacts follow the succession with their verification kept (M5 §5.3); their notice reads "<name> updated their security key. Verification kept."

**Who may rotate.** The server accepts `PUT /api/devices/succession` only from a session bound to a listed, non-revoked device, and, **when the account has a backup**, only with `proof` (the current `passProof` or `recoveryProof`; same check and rate limit as §3.5; a wrong one is counted in `backup_reads`). The accepted succession allows exactly one proof-free `PUT /api/backup` that keeps the unlock hashes, the proof hashes and the cost and moves to `epoch + 1` under the new AIK. A stolen device therefore cannot rotate the user out unless the thief also knows the passphrase. Without a backup there is no proof to ask for: the first device to rotate wins (the M5 situation), and the device list and settings say "Turn on account backup so a lost device can't lock you out."

When it runs:

- **On revoke, after the user confirms.** Revoking a device from a full device shows "Remove <label> and change your account key?" with the passphrase field (when a backup exists); confirming revokes (`POST /api/devices/:id/revoke`) and rotates. The server no longer refuses to revoke the inbox device (the 409 goes); the rotation moves the inbox to the rotating device. A revoke from a session that is not full (pending, companion) only cuts the device; every full device compares, on start and on the `devices` frame, the server's revoked set with the newest signed list, and when a device listed under the current AIK is revoked it asks the user to finish ("<label> was removed. Change your account key now?"). The server has no `needsRotation` flag; it cannot make a device rotate by itself.
- **For the web upgrade** (§1): same steps, nothing removed, `proof` needed if a backup exists.

Two devices rotating at once: the server accepts the first succession; the second gets 409, fetches the chain and goes through step 3's check.

### 6.3 Removing devices needs the proof

Anyone holding the AIK (a thief with an unlocked full device) could otherwise drop the user's other devices with a signed list, or revoke them. **When the account has a backup**, the server therefore refuses, with 403 (and counts the failure like a wrong restore, 429 over the limit):
- a `PUT /api/devices/list` that drops a device that is listed now, unless the body carries `proof` (§3.5) **and** the publisher's session is bound to a device that is already `listed` (a pending device's session never removes devices, even with the proof);
- a `POST /api/devices/:id/revoke` unless the body is `{ proof }` and the session is a listed device's. Unlinking a device from its own session needs no proof (nobody else loses anything).

The exception is the rotation: the first list under a new key after a succession the server accepted (which already carried the proof) may drop the removed devices without one, once; the backup re-seal that follows has its own single allowance (§3.5). Without a backup there is nothing to prove with and the rules are as before (the UI says to turn the backup on).

### 6.4 Taking the account back

If a stolen device rotated first (no backup existed) or the user sees "changed from <label>" and it wasn't them: with a backup, the user signs in on any device (passkey), restores with the passphrase (§4; the thief's rotation re-sealed the backup to the same backup keys, so the passphrase opens the current AIK), and revokes the stolen device with a rotation (§6.2), which the thief cannot answer because it lacks the proof. The revoke screen offers "Also change your passphrase" for the case where the thief may have seen it.

What a revoked device keeps: the old AIK. With it, it can no longer publish anything (the server takes only the current key and its sessions are gone), and contacts treat its key as a predecessor only until the record's time.

### 6.5 Replacing the identity without a succession

`PUT /api/keys` with a new identity voids the account's lists and sets every device pending, so on an account **with a backup** the server refuses it unless one of these holds (403 otherwise; a wrong `proof` is counted like any wrong proof):
- the newest succession the server accepted hands over **from the identity published now to that one**, and has not been used yet (each record authorizes one change, so after a later change by proof or reset, a revoked device holding an older key cannot put it back with an old record) — the rotation of §6.2;
- the body carries `proof` (§3.5): the user knows the passphrase or recovery key and starts over anyway;
- **a reset that has waited a week** (below).

Both of the last two replace the account key for good, so the server deletes the backup in the same step (it holds the old key). A succession keeps it (the rotation re-seals it). An account without a backup is not asked.

**Delayed reset.** For someone who has lost everything: `POST /api/keys/reset` from any session of the account, a pending passkey session included, creates a request (409 without a backup or with one already open; 429 after three requests in 30 days). The server sends every open stream of the account the frame `reset { id, requestedBy: { deviceId, platform }, at, executeAfter }` (`executeAfter` = `at` + 7 days) and serves the open request as `reset` in the owner's own `GET /api/devices/<me>` (null when none). Listed devices show "Someone asked to reset your account key from <platform> on <date>. If this wasn't you, cancel it." and `DELETE /api/keys/reset` (a listed device's session, no proof; 204; frame `reset { id, cancelled: true }`) cancels it. After `executeAfter`, `PUT /api/keys` with a new identity is accepted from the **requesting session only**; the request ends with it. Clients: the "I can't do any of these" path on an account with a backup says "Your account key will be reset in 7 days unless one of your devices cancels it" and waits (the requester shows the date; it polls the owner view or listens for `reset`).

What this does not cover: someone who lost the passphrase and the recovery key while a thief holds a listed device that keeps cancelling. That needs support, and is accepted.

## 7. Moving existing accounts

- **The app primary** holds the AIK in chatcore: already exportable. It answers rekeys and can set up the backup at once.
- **A web primary** with a non-extractable sign key rotates once (§6.2) the first time it needs to export; until then it signs as before.
- **Existing companions** send a rekey request (§5) on their first start on an M6 client and become full when a full device answers. Until then they work as M5 companions.
- **Pre-M6 clients** keep working: they still see a signed list, certificates and successions. M6 full devices also answer `GET /api/devices/recert` requests (M5 §5.2.2) so a pre-M6 companion recovers after a rotation; the server lets any listed device's session list and answer them, not only the primary's.
- UI: the words "primary" and "companion" disappear from settings. **This** device shows "Can unlock your account" (full) or "Waiting for keys" (companion; with "Enter passphrase" when code-linked). Other devices' key status is not known to anyone but them and is not shown (code-linked devices, whose `meta` says so, may show "Linked by code").

## 8. Commands, endpoints, frames (additions)

### 8.1 chatcore

| Command | Result |
| --- | --- |
| `exportAccountKey { userId }` | base64url AccountKey. Full core only (`companion`). |
| `importAccountKey { userId, key, published? }` | the identity `{ dh, sign }` now held. Checks §1 against the pinned account, or, on a core with no account (restore), against `published` `{ dh, sign }`. |
| `backupCreate { userId, passphrase, accountKey? }` | `{ record (unsigned), words, backupKeys, passProof, recoveryProof }`. `accountKey` required when the AIK is outside the core (web). A custom passphrase under 14 characters (after NFKC) is `invalid`. The caller keeps `backupKeys` with `backupKeysSet` once the server accepted the record. |
| `backupSignKeys { userId, record }` | the AIK signature over the keys bytes (full core). |
| `backupReseal { userId, record, backupKeys?, accountKey?, passphrase?, newRecovery? }` (`backupKeys` defaults to the keys the core holds) | `{ record (unsigned, epoch + 1), backupKeys, words?, passProof?, recoveryProof? }`: re-seal after a rotation (no secrets needed; only to the given local `backupKeys`), change passphrase, or new recovery key. Refuses a record whose signature is not under the **current** own AIK (or, right after a rotation, the immediately preceding one, checked against the succession record this core just made) or whose epoch is below `backupKeys.epoch`. |
| `backupProve { record, passphrase? , words? }` | `{ proof }` for a change, delete or rotation. |
| `backupOpen { userId, record, passphrase?, words? }` | `{ accountKey, backupKeys }`; `auth` on a wrong passphrase or words, `invalid` on bad words. |
| `backupKeys {}` / `backupKeysSet { backupKeys }` | the backup keys this core holds (or null) / remember them, never replacing a higher epoch (returns the keys held). A full device stores them after `backupOpen`, after the server accepted a `backupCreate`/`backupReseal`; `rekeyOpen` stores what the answer carries. |
| `passphraseGenerate` | six BIP-39 words. |
| `rekeyRequest { userId, deviceId, platform }` / `rekeyAnswer { userId, deviceId, platform, eph, leafSigKey, signature, groups, now, backupKeys? }` / `rekeyOpen { userId, deviceId, platform, box }` | §5. `rekeyAnswer` checks the request's `signature` (the leaf key's over the request bytes, naming this core's AIK) and `mlsLeafKnown` over `groups` itself; "the device is in the newest signed list" and the `via` check stay the caller's. `backupKeys` defaults to the keys the core holds. `rekeyOpen` returns `{ identity, backupKeys }`. |

Argon2id from the `argon2` crate, BIP-39 from a vendored English wordlist (no new runtime dependency on the web beyond the existing wasm core).

### 8.2 Server

`PUT|GET|DELETE /api/backup` (§3.5); `PUT|GET|DELETE /api/devices/rekey`, `PUT /api/devices/rekey/:deviceId`, `GET /api/devices/rekey/mine` (§5); `/api/link/lookup` and `/api/link/:id/offer` accept any listed device's session (§2); `PUT /api/devices/succession` requires a listed non-revoked device's session and, with a backup, `proof` (§6.2); `POST /api/devices/:id/revoke` no longer 409s on the inbox device; a device entry's sealed `meta` may carry `via: 'code'` (§5). Migration `user_version` 7: `account_backups`, `backup_reads` (every try to read a backup, per session, and every wrong proof: the rate-limit counter and the account's log of opened backups), `rekey_requests`, `backup_reseal_allowance` (one proof-free re-seal per accepted succession). Frames `backup { id, epoch?, read?, deviceId? }`, `rekey { id, deviceId, answered? }`.

## 9. Who builds what

| Part | Owner |
| --- | --- |
| chatcore §1, §3.1-3.2, §5, §8.1, wasm build, vectors; server §2, §3.5, §5, §6, §8.2; CSP check; unit tests | mls-core |
| Web: wrapped exportable sign key and upgrade rotation, grant fields, backup setup/change/restore screens, rekey (both sides), rotation on revoke with confirmation and the adoption check, device list wording; browser tests | web-m4 |
| App: same; bridge for the new commands; widget and cross-client tests | flutter-m4 |

## 10. Pinned vectors

`crates/chatcore/tests/account_key.rs` pins, for fixed inputs: AccountKey bytes; Argon2id seed, `passSecret`/`passPub`/`passProof` for passphrase `"correct horse battery staple"` and a fixed salt; the 24 words, `recoveryPub` and `recoveryProof` for entropy `00..1f`; a backup box and a rekey box for a fixed ephemeral key and nonce; the keys bytes and their SHA-256; the rekey request bytes. `tests/unit/account-key.test.ts` checks the web's keys bytes and rekey bytes against the same values.
