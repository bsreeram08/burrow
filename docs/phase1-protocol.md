# Phase 1: messaging (protocol and UX contract)

Shared contract for the server, the web client (`packages/signaling/public/`) and the Flutter app (`apps/chat/`). Both clients must interoperate exactly; `bun run test:cross-client` is the arbiter. Source of the UX: the design notes.

All new payloads travel inside the existing end-to-end encrypted envelope (`sendControl` on web, `Messenger` on Flutter). The server never sees any field below except blob ciphertext and unfurl URLs.

## 1. Message payload additions (`{ v: 1, type: 'message', ... }`)

All optional. Unknown fields are ignored by older clients; a message with only an attachment has `text: ''`.

| Field | Shape | Rules |
| --- | --- | --- |
| `replyTo` | `{ id: string, text: string }` | `text` is a preview of the quoted message, ≤ 140 chars. Receiver resolves the quoted author from its own record with that `id`; if absent it shows the preview only. |
| `attachment` | see §3 | At most one per message. `text` may be empty only when `attachment` is present. |
| `link` | `{ url, title?, description?, site?, thumb? }` | `url` is https and appears in `text`. `title` ≤ 200, `description` ≤ 300, `site` ≤ 60 chars, `thumb` a `data:image/jpeg;base64,` ≤ 4 KB. |

Text stays ≤ 4096 UTF-8 bytes. The whole encoded payload must be ≤ 16 KB; stores validate the new fields with these bounds and reject (deterministically, `invalid`) anything else.

Text is rendered as a safe Markdown subset on both clients: `**bold**`, `_italic_`/`*italic*`, `~~strike~~`, `` `code` ``, fenced ``` code blocks ``` (monospace box, no execution, optional language label), `> quote` lines, auto-linked `https://` URLs. Never interpret HTML; the web client builds DOM nodes only (no `innerHTML`).

## 2. Control payloads (mutations, no new row, no delivery receipt)

| Type | Shape | Rules |
| --- | --- | --- |
| `react` | `{ v:1, type:'react', id, target, emoji, on: boolean }` | `emoji` is one emoji grapheme or `:custom_name:` (≤ 40 bytes). Per person per target a set of emoji; `on:false` removes. Max 20 distinct emoji per target. Ignored if `target` unknown. |
| `edit` | `{ v:1, type:'edit', id, target, text, editedAt }` | Only the author may edit: receiver applies only when the stored `target` is `incoming` from that sender. Same text bounds as messages. Last `editedAt` wins; store `editedAt` and show "edited". Link/attachment are not editable. |
| `read` | `{ v:1, type:'read', id, ids: string[] }` | ≤ 100 ids of messages the reader has displayed. Sender marks those outgoing records `read`. Sent when the conversation is visible and focused, batched, at most once per 2 s. Respects a "Send read receipts" setting (default on; off also stops showing others'). |
| `typing` | `{ v:1, type:'typing', id, at, on: boolean }` | Sent **ephemeral** (§4). Sender throttles `on:true` to one per 4 s while the composer has text; sends `on:false` on send/clear/blur. Receiver drops if `at` is > 15 s old, and hides the indicator 6 s after the last `on:true` (we use 6 s since we refresh every 4 s). |

Delivery status gains `read` after `delivered`: ✓ sent, ✓✓ delivered, ✓✓ in accent colour = read.

## 3. Attachments

Payload field:

```
attachment: {
  kind: 'image' | 'video' | 'audio' | 'voice' | 'file',
  blob: string,        // server blob id
  key: string,         // base64url, 32 bytes, AES-256-GCM key, fresh per attachment
  sha256: string,      // base64url SHA-256 of the uploaded ciphertext (nonce||ct||tag)
  mime: string, name: string (≤ 120), size: number (plaintext bytes, ≤ 25 MiB),
  width?, height?,     // image/video
  duration?,           // seconds, audio/voice/video
  waveform?: number[], // voice: ≤ 64 values 0–31
  thumb?: string       // data:image/jpeg;base64, ≤ 4 KB, image/video only (blurry placeholder)
}
```

Encryption: ciphertext = `nonce(12) || AES-256-GCM(key, nonce, plaintext) (incl. 16-byte tag)`, no AAD. Receiver downloads, verifies `sha256` over the ciphertext, then decrypts. Mismatch → show "That file couldn't be read." and do not render.

Downloads are lazy for files and audio (on tap), eager for images/voice under 2 MiB. Decrypted plaintext is cached in memory/on device only.

## 4. Server additions (`packages/signaling/`)

| Endpoint | Behaviour |
| --- | --- |
| `POST /api/blobs` | Signed-in only. Body: raw ciphertext, `Content-Type: application/octet-stream`, ≤ 25 MiB + 28 bytes. Returns `{ id }` (128-bit random, base64url). Stored on disk under the data directory, TTL 30 days (swept like the mailbox). Per-user quota 1 GiB live bytes, rate limited. |
| `GET /api/blobs/:id` | Signed-in only. Returns the bytes, `application/octet-stream`, `Cache-Control: private, max-age=31536000, immutable`. 404 when missing/expired. The id is the capability; content is ciphertext. |
| `GET /api/unfurl?url=` | Signed-in only, rate limited. https on port 443 only. DNS is resolved and **every** resolved address checked at connect time (pinned lookup; reject loopback, private, link-local, CGNAT, multicast, ULA, IPv4-mapped forms, metadata ranges). Redirects followed manually, ≤ 3, each re-checked. 5 s timeout, reads ≤ 512 KB of `text/html`. Returns `{ url, title?, description?, site?, image? }` from OpenGraph/Twitter/`<title>` tags. |
| `GET /api/unfurl/image?url=` | Same network rules; `image/*` only, ≤ 2 MB; returns the bytes so the client can downscale to `thumb`. |
| `POST /api/messages` with `ephemeral: true` | Delivered only to the recipient's live event streams, never stored, no ack expected. Accepted only when the envelope is ≤ 2 KB. Used for `typing`. |

CSP must allow `blob:` for `img-src`, `media-src` so decrypted media render. Link previews are generated by the **sender** only (setting "Generate link previews", default on); receivers never fetch.

## 5. Client UX (both clients)

- **Reply**: hover action / swipe-right on mobile → quote chip above composer with ✕; quoted block inside the bubble (author + 1-line preview), click scrolls to and briefly highlights the original.
- **Reactions**: hover bar with 6 quick reactions (👍 ❤️ 😂 😮 😢 🙏) + "more" opening the emoji picker; double-click a bubble = ❤️ (not on photos: they open). Pills under the bubble with counts; own reaction highlighted; click a pill toggles; long-press/hover a pill lists who.
- **Edit**: own text messages only. ↑ in an empty composer edits the last own message ("Edit Last Message"). Composer shows an "Editing" bar; Esc cancels. Bubble shows "edited".
- **Typing**: "<name> is typing…" with three animated dots under the last message; respects reduced motion.
- **Read receipts** as in §2.
- **Attachments**: attach button, drag & drop onto the chat, paste. Image previews with an upload progress ring; images shown at their aspect ratio (max 320 px wide), blurred `thumb` placeholder while loading, open in a full-window viewer with zoom; video with poster + play; files as a card (icon, name, size, download/open); "Couldn't load. Retry" on failure.
- **Voice messages**: mic button when the composer is empty. Recording bar with live level meter, timer, cancel (✕ / Esc) and send. Bubble: play/pause, waveform scrubber, duration, 1×/1.5×/2× speed. Opus/WebM on web, AAC/m4a on Flutter; both must play the other's (`mime` drives the decoder; web uses `<audio>`, Flutter `just_audio` or an existing dependency).
- **Markdown** per §1, plus a code block style with monospace and horizontal scroll.
- **Link cards**: compact card under the text (thumb, title, site); ✕ in the composer to remove the preview before sending ("Remove link preview").
- **Command palette** (⌘K / Ctrl+K; on mobile a search button): fuzzy search over conversations (jump), actions (New conversation, Settings, Theme…, Toggle density, Search this chat), and recent items first. Arrow keys + Enter, Esc closes.
- **Find in conversation** (⌘F): find bar with next/previous over loaded messages, matches highlighted.
- **Jump to newest** floating button when scrolled up, with unread count.
- **Message grouping**: consecutive messages from the same sender within 5 minutes share one header; only the last has the tail. Date separators ("Today", "Yesterday", weekday, date).
- **Empty and error copy** in a calm, plain voice: say what will appear / what to do next.

## 6. Appearance

Theme families (each with light and dark; "System" follows the OS). Existing themes stay available.

| Family | Mood | Light bg / surface / text / accent | Dark bg / surface / text / accent | Font |
| --- | --- | --- | --- | --- |
| Classic | Off-white by day, charcoal by night, indigo accent | `#FBF8F3` `#F2EDE4` `#1F1B16` `#5B6CF0` | `#121214` `#1C1C20` `#ECEAE6` `#7C8BFF` | System sans |
| Forest | Muted greens, deep green accent | `#F3F6F2` `#E5ECE3` `#18231B` `#2F7A4F` | `#0F1712` `#17221B` `#E3EDE5` `#5FBF86` | System sans |
| Ocean | Pale aqua, teal accent | `#F1F8F8` `#E0EFF0` `#0F2328` `#0F8A9D` | `#0B1A1E` `#12262B` `#E0F1F3` `#3CC6D8` | System sans |
| Dusk | Soft violet, purple accent, a touch of coral | `#F7F3FB` `#ECE4F5` `#221A2B` `#7B4FD6` | `#17121F` `#221A2D` `#EEE6F7` `#B08CFF` (secondary `#FF9A76`) | System sans |
| Rose | Pale pink, crimson accent | `#FDF4F5` `#F8E5E8` `#2A1418` `#C8305A` | `#1C1013` `#2A181D` `#F7E6EA` `#FF6F93` | System sans |
| Paper | Cream and brown, serif text | `#F6F0E4` `#EDE4D2` `#2B2118` `#A44A26` | `#1A1611` `#26201A` `#EFE6D6` `#E07A4F` | Serif (Georgia / New York) |
| Mono | Black, white and grey, monospaced, square avatars | `#FFFFFF` `#F2F2F2` `#111111` `#111111` | `#0A0A0A` `#161616` `#EDEDED` `#EDEDED` | Monospace; square avatars; no name colours |
| Midnight | Pure black for OLED, bright blue accent | — (dark only) | `#000000` `#0E0E10` `#F5F5F7` `#3D7BFF` | System sans |

Own bubbles use the accent at 100% with contrasting text (≥ 4.5:1); others use `surface`. Names are coloured from a per-theme palette of 8 (hash of user id) except Mono.

Also: **text size** (S / M / L / XL, default M), **density** (Comfortable / Compact — the spacing between messages and list rows scales with text size), **chat list style** (Detailed: avatar, time, last message / Compact: one line). Stored per device.
