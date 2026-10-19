# Devices (M1)

Milestone M1 of [the workspace plan](workspace-architecture.md) (§1 device registry, §2 DeviceCert, §3 migration of today's users). It adds a device registry, an account-signed device list, a per-device inbox and numbered schema migrations. Messaging is still one device per account (the device holding the account identity key, AIK). Companion devices that read messages arrive with MLS (M2–M5).

## Device list and certificates

The canonical bytes live in one file, `packages/signaling/public/devices.js`. The browser and the server both load it, and `apps/chat/lib/core/devices.dart` ports it byte for byte. A fixed test vector is pinned in both `tests/unit/devices.test.ts` and `apps/chat/test/devices_test.dart`.

```
DeviceList { v: 1, userId, version, prevHash, devices: [{ deviceId, addedAt, meta }] }   signed by the AIK
DeviceCert { v: 1, userId, deviceId, leafSigKey: '', issuedAt }                          signed by the AIK, one per listed device
```

- **Encoding.** TLS-style: u16-length-prefixed UTF-8 strings, big-endian integers, timestamps as u64 milliseconds. Each structure starts with a label: `webrtc-bun-devicelist-v1` or `webrtc-bun-devicecert-v1`.
- **List rules.** Devices are sorted by id, with no duplicates, and there are 1–16 of them. Version 1 has an empty `prevHash`. Every later version carries the base64url SHA-256 of the previous list's bytes. JSON key order doesn't matter, but the bytes must be canonical.
- **`leafSigKey`.** Empty until M2. From then on it binds the device's MLS leaf key.
- **`meta`.** Holds the device's label and platform (`{ label, platform }`), sealed with AES-256-GCM (12-byte IV ‖ ciphertext). The AAD is `webrtc-bun-devicemeta-v1 ‖ userId ‖ deviceId`, so a sealed value can't be moved to another entry or account. `meta` is empty when the signer can't describe the device.
  - **Key derivation.** The sealing key is HKDF-SHA-256 over the AIK's Ed25519 signature of `webrtc-bun-devicemeta-v1 ‖ userId`. Ed25519 is deterministic (RFC 8032), so every holder of the AIK derives the same key and nobody else can. That signature is never published. Companions receive the key in their link bundle (M5).
  - **What others see.** The server and contacts see only device ids, dates and ciphertext.

## Pinning (clients)

`verifyView` (JS) and `verifyView` (Dart) accept a served list only if all of the following hold:

1. It is canonical and names its owner.
2. The AIK signature verifies under the identity the client pinned for that account. This is the security code, never the server's word.
3. Every device has a valid AIK-signed certificate.
4. It doesn't go back on the stored pin:
   - no older version (`rollback`);
   - no different list at the same version (`equivocation`);
   - version + 1 must name the pinned hash (`fork`);
   - no device that an earlier pinned list dropped may come back (`revoked`; tombstones are kept).

The web client pins in `localStorage['device-pins-v1:<userId>']`. The app pins in SharedPreferences (`device-pin-v1:<userId>:<contactId>`). A new AIK (key change) starts a new pin chain, after the usual security-code review.

## Server

- **`devices`**: `(id, user_id, platform, state, is_primary, cert, created_at, last_seen_at, revoked_at)`.
  - **`state`** is `placeholder` (pre-M1 messaging device), `pending` (signed in, not listed), `listed` or `revoked`.
  - **`platform`** is the session's client kind (`web`, `ios`, …), which sign-in already reveals.
  - **Uniqueness.** At most one live primary per account.
- **`device_lists`** stores the latest list verbatim, with its hash, signature, certificates and the AIK that signed it.
- **Accepting a list.** The server accepts only the exact next version, chained to the stored hash and sent from the primary's session (or version 1 under a new AIK). Devices the list drops are revoked: their sessions end, streams close with 4401, push tokens and inbox rows are removed.
- **`sessions.device_id`** binds each session to one device, only with proof of possession.
  - **Device key.** Each device has its own Ed25519 key (`devices.sig_key`). The browser keeps a non-extractable one in IndexedDB beside its id; the app keeps the seed in the Keychain / Keystore.
  - **Binding.** `POST /api/devices/challenge` returns a single-use challenge for the session. The device signs `webrtc-bun-devicebind-v1 ‖ userId ‖ deviceId ‖ challenge` and sends it to `announce`. A new id registers its key; an existing id binds only with its registered key. Knowing a device id, or holding another session of the account, is never enough to become that device.
  - **Unbindable ids.** Placeholders, revoked devices and listed devices the server never saw announce (no key) can't be bound.
  - **Publishing.** A list is accepted only from a session already bound to the publishing device.
- **`device_inbox`** replaces `mailbox`.
  - **Routing.** Envelopes go to the account's messaging device (the primary). A stream reads its session's own device inbox, and acks delete rows only there.
  - **Unbound sessions** (legacy apps, a session that hasn't announced yet) read nothing once the account has a messaging device. Only while the primary is still a placeholder (migrated, unclaimed) does every session read the placeholder's inbox, as before M1; inactive clients never acknowledge it. Binding or claiming delivers what waits at once.
  - **Ephemeral envelopes** (typing) still go to every open stream of every device.
  - **Limits.** The size, per-sender and 30-day limits are unchanged.
- **Which device is the messaging device?** A placeholder created by the migration or on first need, until one of these happens:
  - a device announces with the published identity (`POST /api/devices/announce { deviceId, identity }`);
  - a bound session uploads keys (`PUT /api/keys`);
  - a signed list names a primary.

  The first two (a "claim") need only what the server already trusted before M1: the session that holds the published identity. A signed list outranks a claim. A claim gives no client a reason to trust anything: that takes a signed list.
- **The `devices` frame** (`{ type: 'devices', id }`) goes to the account and its mutual contacts on every change. Clients re-fetch and re-verify.

## Migration of today's users

The schema is numbered with `PRAGMA user_version` (`packages/signaling/migrations.ts`).

- **Step 1** is the pre-M1 schema, written to be idempotent, so a production database at version 0 adopts numbering unchanged.
- **Step 2** creates the tables above. For each recipient with waiting mail, it creates a placeholder primary device and moves the mail into that device's inbox, keeping ids, order and timestamps. Then it drops `mailbox`.

A newer database than the code is refused. On first load after the upgrade:

- **The active device becomes primary automatically.** It is the browser or app holding the published identity. A signal.js browser publishes list v1. The app and the WASM core claim the inbox by announcing.
- **Inactive browsers stay as before.** They announce as pending and show "Link this browser from your primary device". Linking itself is M5. Until then, "Use this device instead" remains (a key change for contacts).
- **Safety numbers don't change**, because the AIK is today's identity key.

## Not yet (M1 scope notes)

- **App list signing.** The app and the WebAssembly core don't sign device lists yet: the AIK is inside chatcore (M2 adds list signing there). They verify and pin contacts' lists, and claim their inbox by announcing.
- **Companions.** There are no companion devices: a list names only the primary, plus devices a later M5 link adds. The owner can remove pending devices from Settings → Devices (web).
- **Labels on pending devices.** Pending devices have no sealed label (only the primary can seal), so they show their client kind.
