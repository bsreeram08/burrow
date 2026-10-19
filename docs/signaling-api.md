# Calling API

This is the current development protocol for the Bun service. A separate chat or
identity application can create calling rooms through its trusted backend. No
administrator credentials belong in a participant's browser.

## HTTP

All paths are relative to `PUBLIC_ORIGIN`. Use HTTPS except for loopback
development. Successful and error JSON responses disable caching. Browser
requests with a foreign `Origin` are rejected; CLI requests may omit `Origin`.

| Method and path | Authorization | Result |
| --- | --- | --- |
| `GET /health` | None | `{ "status": "ok" }`; proves HTTP availability only. |
| `POST /rooms` | `Authorization: Bearer ADMIN_TOKEN` | HTTP 201 with `roomId`, `expiresAt` (Unix milliseconds), and two `participants` containing distinct `token` values and a `polite` boolean. |
| `GET /rooms/:roomId/ice` | Participant bearer token for this room | `{ "iceServers": [...], "iceTransportPolicy": "all" or "relay" }`, suitable for `RTCPeerConnection`. |
| `DELETE /rooms/:roomId` | Either participant's bearer token | `{ "status": "ended" }`; removes the room, revokes invitations, and closes both signaling sockets. |

The administrator token cannot substitute for a participant token on room ICE or
deletion endpoints. Invalid/expired credentials return 401, foreign origins 403,
source limits 429, and room capacity exhaustion 503. Deleting an already ended
room returns 401 because its credentials no longer exist.

### Account API (when `DATA_DIR` accounts are enabled)

JSON endpoints under `/api`. The web app authenticates with the session cookie, and every non-GET request needs this app's `Origin`. Native apps send **no** `Origin` and authenticate with `Authorization: Bearer <session.token>`; any bearer request that carries an `Origin` header is refused (403), and a web cookie session cannot be used as a bearer token or the reverse. Native apps name their platform (`client`: `ios`, `android`, `macos`, `windows` or `linux`) when starting a passkey ceremony and get the session in the response body instead of a cookie.

| Method and path | Result |
| --- | --- |
| `GET /api/version` | `{ api: 1, minClient: { ios, android, macos, windows, linux } }`, public; apps below `minClient` should ask to update. |
| `POST /api/register/options` `{ invite, username, client? }` | Passkey creation options and a single-use `flowId`. 400 for a bad/used/expired invite or username (or a native request without `client`), 409 if taken. |
| `POST /api/register/verify` `{ flowId, response }` | Creates the account and consumes the invite. Web: sets the session cookie. Native: `201 { user, session: { token, expiresAt } }`. Native ceremonies also accept the configured Android `android:apk-key-hash:` origins. |
| `POST /api/login/options` `{ client? }` | Usernameless passkey request options and a `flowId`. |
| `POST /api/login/verify` `{ flowId, response }` | A fresh session: cookie for the web, `{ user, session }` for native apps. Must finish on the same kind of client that started. Failures are always `Sign-in failed.` |
| `GET /api/me` · `POST /api/logout[?all=1]` | Current user; sign out this session (or every session). |
| `POST /api/invites` | A new single-use invite `{ code, expiresAt }`, shown once. At most 20 unused per account. |
| `GET /api/contacts` | Mutual contacts (with `online`), incoming requests, and outgoing requests (by typed username, `id: null`). |
| `POST /api/contacts` `{ username }` | Always `202 { status: "requested" }` for any well-formed username; accepts if they already asked you. |
| `POST /api/contacts/:username/accept` · `DELETE /api/contacts/:username` | Accept a request; remove a contact or cancel/decline a request (also ends any live room). |
| `POST /api/conversations/:username/session` `{ kind: "chat" \| "voice" \| "video" }` | Mutual contacts only. Returns `{ roomId, token, online }` for the caller's own slot. Calls always replace the pair's room; chat reuses a live one. 409 if already connected. |
| `POST /api/conversations/:username/decline` `{ roomId }` | Ends a ringing call; the caller's socket closes with code 4002. |
| `PUT /api/keys` `{ identity: { dh, sign }, signedPreKey?: { id, key, signature }, oneTimePreKeys?: [{ id, key }] }` | Publishes this device's public keys (base64url X25519/Ed25519, 64-byte signature). The first upload, and any new identity, needs a signed prekey; a new identity voids old prekeys. Contacts get `keys` on the first upload and on every change. At most 100 one-time prekeys per upload and 200 waiting. Returns `{ oneTimePreKeys, changed }`. |
| `GET /api/keys/count` | `{ oneTimePreKeys, signedPreKeyId, identity }` for this account, to decide when to top up or rotate and whether this device holds the published identity. |
| `POST /api/devices/challenge` | `{ challenge }`: a single-use, two-minute challenge for this session to sign in `announce`. A session holds at most four at a time. |
| `POST /api/devices/announce` `{ deviceId, deviceKey, challenge, signature, identityProof? }` | Binds this session to a device id (22 base64url characters, per account, never reused) with proof of possession. `signature` is the device's Ed25519 signature over `bindBytes(userId, deviceId, challenge)` (`devices.js`). A new id registers `deviceKey`; an existing id is bound only by its registered key, so another session of the account cannot become that device. New devices are `pending`. With `identityProof`, the published identity key's Ed25519 signature over `claimBytes(userId, deviceId, challenge)` (same challenge, a distinct label), this device takes the account's messaging inbox unless a signed list names a primary. Naming the public identity proves nothing. A `PUT /api/keys` that sets a new identity (first or changed) moves the inbox to its bound session's device; re-uploading the unchanged identity claims nothing. `200 { deviceId, state, primary }`; 401 for an unknown, used or expired challenge; 403 when the signature or the identity proof does not verify; 409 for another account's, a revoked or an unbindable id, or a session already bound to another device; 429 beyond 16 devices. See [devices](devices.md). |
| `PUT /api/devices/list` `{ list, signature, certs, deviceId }` | A DeviceList signed by the account identity key, with one AIK-signed certificate per device. Accepted only as the exact next version, chained to the stored hash, from the primary's own session (or version 1 under a new identity key), whose session must already be bound to `deviceId`. The publishing device becomes primary and takes the inbox. Listed devices that the list drops are revoked. `200 { version, revoked }`; 400 malformed; 403 bad signature or certificate, or not the primary; 409 version/chain conflicts or unusable ids. |
| `GET /api/devices/:username` | Your own account or a mutual contact's: `{ userId, identity, list, signature, certs }`. Your own also adds `devices` (`id, platform, state, primary, createdAt, lastSeenAt, current`) and `currentDevice`. |
| `DELETE /api/devices/:deviceId` `{ list?, signature?, certs? }` | The primary removes a pending device, or a listed one with the next signed list without it. A pending device may remove itself. The device's sessions end (streams close with 4401), and its push tokens and inbox go. |
| `GET /api/keys/:username` | Mutual contacts only: `{ userId, identity, signedPreKey, oneTimePreKey }` (`oneTimePreKey` may be `null`). Atomically consumes one one-time prekey; a few per second per pair. |
| `GET /api/keys/:username/identity` | Mutual contacts only: `{ userId, identity }`, consuming nothing. |
| `POST /api/messages` `{ to, envelope }` | Mutual contacts only. `envelope` is base64url, at most 64 KiB decoded, opaque to the server. Stored in the recipient's messaging device's inbox until acknowledged (30-day TTL) and delivered at once if that device is online. `201 { id, createdAt }`; 507 when the recipient's mailbox is full (1,000 / 50 MiB); 429 for the per-sender share (200 / 10 MiB) or the rate limit. |
| `POST /api/messages` `{ to, envelope, ephemeral: true }` | Same contact and envelope rules, but at most 2 KiB decoded (413 otherwise), for typing indicators. Sent at once to every open event stream of the recipient (all devices) as an `envelope` frame with `ephemeral: true`, then forgotten: never stored, never pushed, never replayed, no ack needed (an ack is harmless). `202 { delivered }`, `delivered` being whether any stream took it. `ephemeral` must be `true`, `false` or absent. Own rate limit (10/s per account). |
| `POST /api/push/native` `{ platform: "fcm" \| "apns" \| "apns-voip", token, installId }` | Native sessions only (403 for web). `installId` is a random 16–64 character id the app generates once per install. For `fcm`/`apns`: `202 pending` and the server sends that token a silent push `{ type: "verify", nonce }` (FCM data message; APNs `background` push with `content-available`); `201` if already bound to this session. For `apns-voip`: requires a confirmed `apns` token with the same `installId` in this session (otherwise 409). An unclaimed VoIP token binds at once (`201`); one held by another session answers `202 pending` and the server sends it a VoIP push `{ type: "verify", nonce }` — the app must report it to CallKit and end that call immediately, then confirm the nonce. 400 malformed or rejected by Google/Apple, 404 transport not configured, 429 more than five unconfirmed tokens or too fast. |
| `POST /api/push/native/confirm` `{ platform, token, nonce }` | Activates a pending FCM/APNs registration with the nonce the device received. Single use (a wrong nonce spends it) and valid for two minutes; until then any existing binding of that token stays with its owner. |
| `DELETE /api/push/native` `{ platform, token }` | Removes the token if this account holds it. Tokens are also removed on sign-out, session expiry and invalid-token responses. Messages go to FCM and APNs alerts; calls go to FCM (high priority) and, on a device with a VoIP token, to PushKit instead of an alert. |
| `GET /api/events` (WebSocket; cookie + origin, or bearer without origin) | Stream of `hello` (online contacts), `presence`, `contacts` (refetch), `incoming` `{ from, kind, roomId, token }`, `ended`, `keys` `{ id }` (a contact's identity was set or changed: re-check it), `devices` `{ id }` (that account's device list changed: re-fetch and verify it) and `envelope` `{ id, from: { id, username }, envelope, createdAt, ephemeral? }` in order (ephemeral ones outside the mailbox order and the in-flight count), at most 32 unacknowledged at once. The only client message is `{ "type": "ack", "id" }`, which deletes that envelope if it waits in this stream's device inbox. A stream reads its session's device inbox; an unbound session reads nothing once the account has a messaging device (only while the primary is still a migration placeholder does every session read it, as before M1); anything else closes the stream (1008). Closes with 4401 when the session ends. |

Native apps open `/api/events` with `Authorization: Bearer` and no `Origin`, and room sockets with `Origin` set to the server's public origin (room sockets are authorised by the participant credential). Room sockets for contact rooms close with 4001 when a newer call replaces the room and 4002 when the call is declined.

The default lifetime is one hour, and state is memory-only. Server restart ends
all rooms. Each invitation grants one participant slot; it is not proof of human
identity. The operator's `scripts/create-room.ts` command produces two browser
links with credentials in URL fragments. The browser removes that fragment from
the address bar and retains it only in page memory.

## WebSocket

Connect to `/rooms/:roomId/socket` with the two offered subprotocols:

```js
const socket = new WebSocket(socketURL, ['webrtc', participantToken]);
```

The request's `Origin` must exactly match `PUBLIC_ORIGIN`. The server selects
`webrtc`; it never echoes the credential. Do not log the offered subprotocol
header. Only one active connection is allowed per participant token.

Invitations are single-use. When a socket is accepted, the server replaces that
participant's credential and returns the new token in `welcome`; the token that
opened the socket immediately stops working for the socket, ICE and deletion
endpoints. Clients keep the rotated token in memory for reconnects, ICE refreshes
and hangup. A participant who loses it (for example by reloading the page) needs
a new invitation.

Server events:

| Type | Fields | Meaning |
| --- | --- | --- |
| `welcome` | `polite`, `token` | The participant is authenticated. `token` replaces the presented credential (single-use invitations). The non-polite participant initiates the first offer. |
| `ready` | `sessionId` | Both participants are connected. Create a fresh peer connection for this pairing. |
| `description` | `sessionId`, `description: { type, sdp }` | Offer or answer from the paired participant. |
| `candidate` | `sessionId`, `candidate` | ICE candidate, or `null` for end-of-candidates. |
| `peer-left` | None | The other signaling connection closed. Retire the current peer connection and wait for another `ready`. |
| `error` | `error` | Includes `Stale session`, `Peer unavailable`, and `Delivery failed`. |

Clients send `description` and `candidate` with the **exact `sessionId` from the
latest `ready` event**. Forwarded messages retain that identifier. Each new pairing
gets a fresh random identifier, including reconnects with the rotated participant
token. The server rejects missing/old identifiers, so delayed packets cannot
reach a replacement peer connection. Clients must also ignore incoming messages
from retired pairings and guard asynchronous callbacks from retired peers.

Candidate objects contain `candidate`, `sdpMid`, `sdpMLineIndex`, and optionally
`usernameFragment`. Preserve the username fragment when provided: it identifies
an ICE generation within a pairing. ICE restarts keep the pairing's `sessionId`
but negotiate fresh ICE credentials. Queue candidates arriving before their SDP,
with a finite queue limit. The reference browser uses perfect negotiation to
resolve colliding offers.

`{ "type": "hangup" }` ends the entire room over an active WebSocket. The browser
uses authenticated HTTP `DELETE` instead, allowing room closure even when its
WebSocket is disconnected. Capture stops locally immediately; if HTTP cannot
reach the server, the UI reports that room closure could not be confirmed.

## Recovery and limits

The reference browser retries unexpected signaling loss for about 90 seconds,
refreshing room/ICE authorization before reconnecting. Expired rooms stop retries.
It preserves local mute/camera state while reconnecting and stops all media tracks
when the user ends the call, leaves the page, or recovery is abandoned. Delayed
media-permission results cannot restart capture after cancellation.

ICE failure or a persistent disconnection triggers a bounded number of ICE
restarts. `peer-left` followed by `ready` creates a fresh peer connection rather
than reusing the old pairing. A successful signaling reconnect does not by itself
prove media recovery; inspect connection state and received media statistics.

Messages are capped at 64 KiB, SDP strings at 60,000 characters, and candidate
strings at 4,096 characters. Each socket has a 100-message-per-second budget and
bounded outgoing buffering. Signaling is not persisted or replayed; there are no
delivery receipts or durable messaging guarantees. Chat needs a separate protocol.

TURN credentials remain valid until their timestamp expires even after room
deletion. See [security boundaries](security.md) and [deployment](deployment.md).

## Custom emoji

All require a signed-in session; writes also require this app's Origin.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/emoji` | The workspace pack: `{ emoji: [{ name, url, animated, mine }] }`. `url` is always same-origin `/emoji/<sha256>.<png|gif|webp>`. |
| `POST /api/emoji` `{ name, image }` | Upload. `image` is base64 (optionally a `data:image/…;base64,` URL) of a PNG, GIF or WebP up to 512 KB. Names match `^[a-z0-9_+-]{2,32}$` and are unique. 201, or 400/409/413/429. |
| `POST /api/emoji/import` `{ name, url }` | The server fetches the image from an allowlisted https host (see security.md for the SSRF rules). |
| `DELETE /api/emoji/:name` | Only the person who added it, or `Authorization: Bearer <ADMIN_TOKEN>`. |
| `GET /emoji/<sha256>.<ext>` | The image, with a sandboxing CSP and an immutable cache. |

## Attachments and link previews

All require a signed-in session (cookie, or bearer for native apps); the upload also requires this app's Origin, or no Origin with a bearer token.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/blobs` | Body: the raw ciphertext (`nonce \|\| AES-256-GCM ciphertext \|\| tag`), `Content-Type: application/octet-stream`, exact `Content-Length` of 1 byte to 25 MiB + 28. `201 { id }`, a 128-bit random base64url id (22 characters). 401 signed out, 403 origin, 411 no length, 413 too large, 415 other content type, 429 rate limited (4/s per account) or too many uploads in progress (2 per account, 16 overall), 507 when the account's live blobs would exceed 1 GiB or the server's total would exceed `BLOB_BUDGET_BYTES` (default 20 GiB). The body is streamed to disk and must end exactly at `Content-Length` (400 otherwise, nothing kept). |
| `GET /api/blobs/:id` | The bytes as `application/octet-stream` with `Cache-Control: private, max-age=31536000, immutable`, `nosniff`, a sandboxing CSP and `Content-Disposition: attachment`. Any signed-in account may read any id: the id is the capability and the content is ciphertext. 404 when unknown or expired. Blobs live 30 days from upload (like mailbox envelopes) and are swept from disk (`DATA_DIR/blobs/`); files of deleted accounts and interrupted uploads go in a scan every 10 minutes. |
| `GET /api/unfurl?url=` | Link preview for the **sender**: `{ url, title?, description?, site?, image? }` from `og:` / `twitter:` tags or `<title>`, entity-decoded, single-line, bounded to 200 / 300 / 60 characters; `image` is an absolute https URL (resolved against the final page URL). Reads at most 512 KB of `text/html` or `application/xhtml+xml`. |
| `GET /api/unfurl/image?url=` | The preview image bytes (≤ 2 MB) so the client can downscale them into `thumb`. Only JPEG, PNG, GIF, WebP or AVIF, recognised by their bytes and served as that exact type with a sandboxing CSP, `Content-Disposition: attachment` and `no-store`. SVG and anything else is 415. |

Network rules for both unfurl endpoints: `https:` on port 443 only, no credentials in the URL, at most 2048 characters. The hostname is resolved inside the socket's own DNS lookup and **every** address must be public unicast, so the checked address is the one connected to (no DNS rebinding window); IPv4 refuses private, loopback, link-local (cloud metadata), CGNAT, multicast, reserved, benchmarking and documentation ranges, and IPv6 accepts only `2000::/3` minus Teredo/ORCHID, 6to4 and documentation, which excludes loopback, ULA, link-local, multicast and every IPv4-mapped/compatible/NAT64 form in any notation. IP-literal URLs get the same check. Redirects are followed by hand, at most 3, each target re-checked; connections are never pooled. One 5-second deadline covers the whole exchange. Errors: 400 refused address or URL, 413 too large, 415 wrong type, 502 unreachable / bad status / too many redirects, 504 timeout, 429 rate limited (3/s per account, 4 concurrent per account, 64 overall).

## Message payloads added for commands

Inside the encrypted envelope (and the guest data channel): `{v:1, type:'message', id, text, createdAt, expiresAt}` may add `kind:'action'` (a `/me` line) or `kind:'poll', poll:{question, options}`; `{v:1, type:'vote', id, poll, option}` records a vote (`option` an index, or `null` to clear).
