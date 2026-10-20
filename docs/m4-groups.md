# M4: groups and channels (client contract)

Shared contract for the web client (`packages/signaling/public/`) and the Flutter app (`apps/chat/`) for group chats and channels over MLS. Both clients must interoperate exactly. Server endpoints are in [signaling-api.md](signaling-api.md) ("Groups and channels"); the engine is `crates/chatcore` ([API.md](../crates/chatcore/API.md), "Groups over MLS"); the design is [workspace-architecture.md](workspace-architecture.md) §1, §2 and §5; the UX comes from the design notes §4 and §5.

**1:1 chats stay on Double Ratchet** (signal.js on the web, chatcore's 1:1 core in the app) with the Phase 1 payloads, exactly as today. Moving DMs to 2-person MLS groups (`kind: dm`) and the 60-day receive-only window come later. M4 creates only `group_dm`, `private` and `public` channels.

## 1. Words

| Term | Meaning |
| --- | --- |
| Group | `kind: group_dm`: 2–8 other people picked from your contacts, no server-visible name. Shown under **Groups**. |
| Channel | `kind: private` (invite-only, name known to members only) or `kind: public` (anyone can join; the name is the one thing the server sees). Shown under **Channels**. |
| Channel id | The MLS group id: 16 random bytes, base64url without padding (22 characters). |
| Conversation id | **The channel id.** Messages of a group live in the message store under it. DMs keep their 43-character `pairId`, so the two can never collide. |

## 2. Before a device can use groups

1. **Listed device.** The device's session must be bound to a device that the account's signed DeviceList names ([devices.md](devices.md)). Otherwise every group endpoint answers 409 (never announced) or 403 (not listed). The web's experimental WebAssembly core can't sign device lists yet, so groups stay off on it (Settings says so); the standard web core and the app's primary device are listed.
2. **Device certificate.** The device's MLS credential is a chatcore `DeviceCert` for `(userId, deviceId, platform)` signed by the account identity key (AIK). Where the AIK lives in chatcore (the app): `mlsInitDevice`. Where it lives in WebCrypto (the web): `mlsDeviceLeaf`, sign `DeviceCert::tbs` with the AIK, then `mlsSetDeviceCert { cert, aik }` (`aik` is accepted only by a core that has no 1:1 identity of its own). A device whose stored certificate names another user, device or AIK starts over with an empty MLS store (its old groups are gone; other members' admins remove the stale leaf).
3. **KeyPackages.** `GET /api/mls/keypackages`; keep 100 one-time packages and one last-resort package on the server: upload `100 - oneTime` when `oneTime < 20` (and on every `keypackages` frame), and a new last-resort package when `lastResort` is 0. At most 100 per request.

## 3. Pins (who is who)

chatcore accepts a member's certificate only if it verifies under the account key **pinned** for that user (`peer:<userId>` in the core's store; contact id = user id).

- **Contacts.** The pin is the contact's 1:1 pinned identity. The web runs MLS in its own core store (§9) and mirrors the signal.js pin into it with `notePeer`; when the user accepts a changed security code in the 1:1 UI, the mirror follows (`notePeer` + `acceptChange`). A contact whose code changed and isn't reviewed has no usable pin.
- **Everyone else** (people you meet in a group or channel): trust on first use from the server: `GET /api/users/:userId/identity` → `{ userId, username, identity: { dh, sign } }`, then `notePeer(userId, identity)`. This is the same key the delivery service validated the commit with, so client and server agree. A later different key is a security-code change: the group pauses for that person until it is reviewed (never silently re-pinned).
- **When to pin.** Before `mlsJoin` (Welcome) and `mlsJoinExternal`: every user in `GET /api/channels/:id/members`. Before processing a log entry: its `from.userId`, and every member the last `members` fetch listed. If a call still fails with `no pinned account key for user <userId>` (chatcore names the user), pin that user and retry once.
- **Pin problems are local, never poison.** If a commit fails while a pin is missing, blocked or just changed, do not report poison; pause that channel ("Review <name>'s security code to keep reading this channel") and resume after review. Only a failure with every involved pin current is reported (§7).

## 4. Creating, adding, removing, leaving, joining

All commits follow API.md "Commit": build (`mlsCommit`), submit, then `mlsMergeOwn` on 201 and `PUT /api/channels/:id/group-info` with the new epoch's GroupInfo. **409**: `mlsClearOwn`, process the log (§6), rebuild, retry; at most 5 tries with backoff (0.5, 1, 2, 4 s). **No answer** (network): leave the commit pending; while processing the log, an own commit entry is fed to `mlsReceive`, which merges it when its digest is our pending one; when the server's epoch has moved past `mlsPending().epoch` without it, `mlsClearOwn` and rebuild. Before building a commit, process the log up to the server's `seq`.

- **Create.** Roles: `{ v: 1, kind: 'group', admins: [me], joinPolicy }` with `joinPolicy: 'open'` for `public`, `'invite'` otherwise. `mlsCreate`, then `POST /api/channels { id, kind, name? , groupInfo, tree }` (`name` only for `public`: 1–64 letters, digits, spaces, `-`, `_`). Then add the chosen people in one commit, then send `meta` (§5.3).
- **Add** (admins; anyone in a public channel): `POST /api/mls/keypackages/claim { users }` (≤ 16 users per call; repeat for more), `mlsCommit { adds: <every claimed KeyPackage> }`, `POST .../commits { message, welcome, joiners: <their deviceIds> }`. This adds **every listed device** of each person. Users who returned no KeyPackage (`missing`) are reported ("bob hasn't opened the app since groups arrived") and skipped. After a 201, send `meta` again so the new members learn the name and topic. New members see messages from when they joined: they cannot decrypt anything earlier.
- **Remove** (admins): `mlsCommit { removes: [{ userId }] }` removes every device of that person. Removed devices get `kind: 'removed'` when they process it and stop receiving.
- **Leave.** MLS doesn't let a member commit its own removal, so: if you are the only admin and others remain, first commit a roles change that makes the earliest-added other person an admin (`roles` with both of you in `admins`); then send `{ v: 1, type: 'leave', id }`; then `mlsForget` the group, keep it as "You left" in the list, and acknowledge (cursor) anything still delivered for it without processing. An admin device that processes a `leave` from user U commits `removes: [{ userId: U }]` (if several admins race, the 409 loser drops it when U is already gone).
- **Public channel directory.** `GET /api/channels/directory` → `{ channels: [{ id, name, members, joined }] }` (public channels only; `members` = number of people). Join with an external commit: pin the members, `GET .../join-info`, `mlsJoinExternal`, `POST .../join`, `mlsMergeOwn`, `PUT .../group-info`. Then process the log from the returned `seq`.
- **Resync.** On a `gap` (the log was trimmed past this device) or a group this device can no longer load: `mlsForget`, then join externally (allowed for a user already in the channel). History before the rejoin stays as stored.

## 5. Application payloads

Every application message is `mlsEncrypt { plaintext: JSON.stringify(payload) }` → `POST /api/channels/:id/messages`. Payloads are **the Phase 1 payloads exactly** ([phase1-protocol.md](phase1-protocol.md) §1–3, `v: 1`), validated by the same store rules as 1:1 messages (`ChatStore.checkPayload` / `receive` on the web, `payload.dart` / `message_store.dart` in the app), with the additions below. The authenticated sender is the MLS sender (`Processed.sender.userId`), never a field of the payload. chatcore's v2 schema (`mlsValidate`, `payload.rs`) is **not** used in M4.

### 5.1 Used in groups

| Type | Shape | Group rules |
| --- | --- | --- |
| `message` | Phase 1 (`text`, `createdAt`, `expiresAt`, `replyTo?`, `attachment?`, `link?`, `kind: 'action'?`) **+ `mentions?`** | `mentions`: 1–64 distinct user ids (22 characters), only in groups. `kind: 'poll'` is not sent in groups in M4. |
| `react` | Phase 1 | Per **person** (user id) per target, a set of emoji; at most 20 distinct emoji per target. |
| `edit` | Phase 1 | Applied only if the target is a stored incoming message whose sender is this payload's MLS sender. |
| `read` | Phase 1 | Sent through the log (not ephemeral), at most once per 2 s while the conversation is visible and focused, only in groups and private channels of **at most 50 people**, never in public channels, and only when "Send read receipts" is on. The receiver records the reader's user id on its own outgoing messages. |
| `typing` | Phase 1 | Sent **ephemeral**: `POST /api/channels/:id/ephemeral { message }` (§8). Throttle `on: true` to one per 4 s while composing; `on: false` on send/clear/blur. Receivers show "alice is typing", "alice and bob are typing", "3 people are typing" (6 s after each `on`; drop when `at` is > 15 s old). |
| `meta` | `{ v: 1, type: 'meta', id, name, topic, at }` | **New.** `name` ≤ 64 characters (may be `''` for a group: show the members' names), `topic` ≤ 256 characters, `at` ms. Applied only from an admin (`mlsRoles`), latest `at` wins. Sent after creating and after every add. Public channels show the server's name when `name` is `''`. |
| `leave` | `{ v: 1, type: 'leave', id }` | **New.** §4. |

Not used in groups in M4: `receipt` (no per-device delivery receipts: ✓ means the server sequenced it), `burn`, `vote`, `rotate`, `policy`. Receivers discard them in groups (acknowledged, no notice).

### 5.2 Mentions

The text carries `@username` literally (readable everywhere); `mentions` lists the mentioned people's user ids. A receiver highlights `@username` when that username belongs to a listed id (from the channel's member list or the stored sender names), and counts the message as a mention of you when your id is listed. Typing `@` in the composer opens an autocomplete of current members (fuzzy by username, ↑/↓, Enter/Tab inserts `@username `). The sender builds `mentions` from the `@username` tokens still present in the final text that name a current member. Notifications for mentions are decided on the device (architecture decision): nothing about mentions reaches the server.

### 5.3 Group name, topic and members on screen

Names of `group_dm` and `private` channels exist only in `meta`. Members come from `mlsMembers` (authoritative); usernames from `GET /api/channels/:id/members`, refreshed on `channel` frames. A message keeps its sender's username as it was received, so it still reads right after they leave.

## 6. Receiving and order

Per channel, one queue processes everything in `seq` order: `group` frames when `seq` is the next one and `message` is present, otherwise `GET /api/channels/:id/log?after=<local cursor>` pages. For each entry:

1. `from.deviceId` is this device: skip it, except a commit while `mlsPending` is set, which goes to `mlsReceive` (it merges our own commit).
2. Otherwise `mlsReceive { group, message, commit: false }`, then:
   - `application`: parse the payload, store it (§10), then `mlsCommitReceived`. A payload that fails validation is acknowledged and dropped (`mlsCommitReceived` all the same, so the key is spent).
   - `commit`: `mlsCommitReceived`; refresh members; write a system line for joins and removals ("alice added bob", "carol left", "dave joined").
   - `removed`: `mlsCommitReceived`; the channel becomes read-only ("You were removed from #design"); stop processing it.
3. Advance the local cursor to the entry's `seq`, and send `{ type: 'cursor', channel, seq }` after each batch.

Errors: `replay` (already processed, e.g. after a crash between commit and cursor): skip. A pin problem: §3. `poison`: §7. Any other coded error on an application message: drop with a notice, advance. Uncoded (transient) errors: stop; retry on the next frame or in 15 s.

## 7. Frozen channels and poison commits

A commit that `mlsReceive` rejects with `poison <digest>: …` (and whose pins are all current, §3) is reported with `POST /api/channels/:id/poison { seq, digest }`; processing stops. The channel shows a banner "This channel is paused while an admin checks a change." Admins (the `channel` frame `frozen`, or a 423 on send) see "A change to #name was rejected by a member" with **Roll back** (removes the change and its author's device) and **Dismiss** (keeps it). Each signs `"webrtc-bun-mlsresolve-v1\n" + channelId + "\n" + action + "\n" + seq + "\n" + digest` with the **device key** (the key the device registered with `announce`) and posts `POST .../resolve`. After a rollback an admin device gets `remove-needed { deviceId }` and removes that device's leaf with an ordinary commit (`removes: [{ userId, deviceId }]`). A device that already merged the rolled-back commit can't continue: it resyncs (§4). `thawed` resumes processing.

## 8. Server additions in M4

| Endpoint / frame | Behaviour |
| --- | --- |
| `GET /api/channels/directory` | Public channels: `{ channels: [{ id, name, members, joined }] }`, newest first, at most 500. Listed devices only. |
| `GET /api/users/:userId/identity` | `{ userId, username, identity: { dh, sign } }` for any account (ids are 128-bit random, so this enumerates nothing). 404 if unknown or without keys. Rate limited. |
| `POST /api/channels/:id/ephemeral { message }` | An application message (private MLS message, at most 2 KiB) for the current epoch (409 `{ epoch }` otherwise). Not logged, not stored, not pushed: sent once to the open streams of the channel's other member devices as `{ type: 'ephemeral', channel, from: { userId, deviceId }, message, createdAt }`. `202 { delivered }`. 10/s per account. |

Receivers process an `ephemeral` frame with `mlsReceive { commit: true }` only when the channel's queue is idle and the payload is `typing`; anything else, or any error, is dropped silently.

## 9. Web specifics

- The browser runs MLS in its own core store: IndexedDB `webrtc-bun-mls-v1-<userId>` (same sealing as `webrtc-bun-core-v1`, associated data `mls1|<userId>|<row>`), its own Web Lock `chatcore-mls:<userId>` and worker, so the 1:1 core (signal.js by default) is untouched. The AIK stays a non-extractable WebCrypto key: it signs only the device certificate bytes.
- `chatcore-wasm` is built with the `mls` feature (`bun run build:wasm`).

## 10. Message store (both clients)

Same store as 1:1, records keyed by `(conversationId, id)`, with these group fields:

| Field | Where | Meaning |
| --- | --- | --- |
| `from`, `fromName` | incoming group messages | Sender's user id and username at receipt. |
| `mentions` | group messages | As sent. |
| `reactions` | any | 1:1: `{ me, peer }`. Groups: `{ me, <userId>: [...] }`. |
| `readBy` | outgoing group messages | User ids whose `read` named it. "Read by everyone" when it covers every other current member; the info sheet lists who has and hasn't read it. |

Statuses in groups: `queued` (on this device), `sent` (sequenced by the server, one tick), `read` (two accent ticks once everyone read it). Groups keep their newest 500 messages each (older ones are evicted, unlike 1:1 where the 501st incoming message is refused), within the device-wide cap. Unread and mention counts are per conversation on the device. A local `@` badge marks conversations where you were mentioned. Store v2 (100k messages, threads) is later.

## 11. Limits

As the server enforces: group 9 people / 64 devices, private channel 500 / 1,000, public 1,000 / 1,000; application message 64 KiB (payload ≤ 16 KB as in Phase 1); ephemeral 2 KiB; 30 messages/s, 15 commits/s, 3 joins/s per account.
