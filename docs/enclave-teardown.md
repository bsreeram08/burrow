# Enclave teardown: feature inventory for replication

Target: `/Applications/Enclave.app` (`com.skilld.enclave`, v1.0 build 202610190709, Mac Catalyst/SwiftUI, arm64, macOS 26+, Mac App Store/TestFlight internal).
Method: static only. Bundle metadata, `Info.plist`, resource files, and strings from the stripped main binary and its two extensions (Share, Notifications). The binary leaks its Swift source file names (226), type names (~1,400) and UI copy (~735 sentences), which together give a reliable feature map. Nothing was executed; layout, spacing, animation and exact flows are **not** observed here and need a runtime/screenshot pass.

Legend: **[O]** observed directly (string/type/file name/plist). **[I]** inferred from names/copy. Unknowns are listed at the end.

## 1. Stack and architecture

| Piece | Evidence |
| --- | --- |
| UI: SwiftUI + UIKit/AppKit bridges, Mac Catalyst | [O] UIKit plist keys, `Mac*` views (`MacSidebar`, `MacWindowBar`, `MacCommands`, `SettingsWindow`) |
| Modules | [O] `Enclave/` (UI, ~210 files), `EnclaveCore/` (Messenger, MLSEngine, HistorySync, BackupEngine, Library, Moderation, Passphrase), `EnclaveCrypto/` (UniFFI bindings), `EnclaveRelay/` (Account) |
| E2EE: **MLS (RFC 9420)** via Rust `openmls 0.6.0` + `openmls_rust_crypto`, exposed to Swift via UniFFI | [O] `openmls-0.6.0/src/...`, `FfiConverterTypeMlsClient`, `KeyPackageInfo`, `StagedCommit`, `PendingCommit`, "Epoch the group will be in once this commit is merged." |
| Key protection | [O] "Private signing key, AEAD-wrapped under the KEK", "Deriving your keys", `Passphrase`, `PassphraseError`, `BackupWordsSheet`, "Type these words from what you wrote down." → passphrase-derived KEK + recovery words |
| Server: "relay" at `https://relay.useenclave.com` | [O] `EnclaveRelayURL`, `RelayClient`, `RelaySocket`, `OutboxWatcher` |
| Calls: LiveKit (SFU) WebRTC | [O] `LiveKitWebRTC.framework`, `CallEngine`, `CallMachine`, `CallQualityMeter`, CallKit/`INStartCallIntent`, `VoipPush` |
| Animations: Lottie | [O] `Lottie.framework`, `StickerPlayback`, `AnimatedEmoji` |
| Local DB | [I] SQLite-ish store, "The local database is suspended while Enclave is in the background" [O] |
| GIFs: Klipy | [O] `/v1/gifs/klipy/search`, `/trending` |
| Auth: username + passphrase; Google sign-in only for Drive backup + Meet + Calendar | [O] "Sign in on this device with your username and passphrase.", Google URL scheme, `/v3/files`, `/v3/calendars/primary/events` |
| CLI + bots | [O] `EnclaveCLIURL`, "Runs bots on a Linux server or a Mac." |
| Signed self-updates for the DMG build | [O] `EnclaveUpdateKey` (Ed25519-sized), `ReleaseManifest`, `UpdateRequiredView` |

Relay REST surface seen in the binary [O]: `/v1/conversations`, `/v1/keypackages/`, `/v1/connections/people`, `/v1/people/lookup`, `/v1/sessions/current`, `/v1/me/{approvals,connected,device-notifications,ignore-broadcasts,notifications,notifications/settings,notifications/people/,pins/order,profile-key,quiet-hours}`, `/v1/stickers/packs`, `/v1/gifs/klipy/*`. Note the server stores **settings that affect notification delivery** (quiet hours, mutes, device notifications) so it can hold pushes, but "still can't read your messages".

## 2. Identity, accounts, devices

- **Invite-only**: "Enclave is invite-only. You vouch for everyone you invite." Invite links `enclave://` scheme, single use ("It works once."), `PasteInviteSheet`. [O]
- **Onboarding steps** [O]: `WelcomeStep` → `InviteStep` → `SignInStep` → `PassphraseStep` (with typed-words rejection: "Why typed words aren't a passphrase. Each case is a different hint in the UI.") → "Deriving your keys" → "Creating your account" → `VerifyStep` (recovery words) → "All set". Progress is a stepper ("The step-by-step progress bar is so good" appears in demo copy).
- **Multi-device**: `DevicesView`, rename device, "Remove an old device?", `OldDevicesPrompt` ("These haven't opened Enclave in a long while..."), "This device was removed", "Linking this Mac". New devices get history via **HistorySync** from your other devices: "Open Enclave on your other device. Your conversations and their history will appear here." [O]
- **Per-device notification settings** synced server-side (`/v1/me/device-notifications`). [O]
- **Safety numbers / verification**: `SafetyNumber`, "Mark as verified", "Their safety number has changed. Check it with them, then try again." [O]
- **Profile**: name, photo (crop "Drag and pinch to frame it."), E2EE profile key (`/v1/me/profile-key`), aliases/former names (`AliasRow`, `FormerAliasRows`). [O]
- **Status** [O]: free text "What's your status?" plus presets *In a meeting, Commuting, Off sick, On leave, Working remotely, Focusing*; `ClearAfter`; auto "Show when I'm in a meeting" (from Google Calendar → `AutoStatus`, `KnownBusy`).
- **Presence**: "See when they're online" (opt-in). [O]

## 3. Organisations, communities, guests

- Multiple **organisations** per account, org switcher (`MacOrgSwitcher`), "Primary organisation", "Group by organisation" in chat list, org colour swatch/mark. [O]
- **Roles** `OrgRole`, `RoleBadge`; "You can't give a role above your own.", "Only someone above them in the organisation can do that." → hierarchical roles (owner > admin > member) [O/I]
- **Community** = public face of an org with a **handle**; "Publish to Community", community feed posts. [O]
- **Connected communities** (Slack Connect equivalent) [O]: request/accept connection, "Connected both ways", per-side switches (`ConnectionSwitches`: find people, message, share channels, "Show me to connected communities"), ending a connection makes chats read-only, approvals before your people join another community's channel (`ApprovalsSheet`, `ApprovalInbox`).
- **Guests**: "Guests are from other communities. They see only the chats they're added to." Policy "Who can invite guests". [O]
- **Shared channels** across communities with badges ("carry its badge here"). [O]
- **Directory**: `ChannelDirectoryView` "Browse channels", `OrgMembersView`. [O]

## 4. Conversations

Kinds [O]: DM, group ("Pick two or more people to start a group"), channel (public/private, "Convert to Channel"), shared channel, bot DM.

Chat list (`ConversationList`, `MacSidebar`) [O]:
- Two list styles: "Each chat with its picture, the time and the last message." vs dense rows (`DenseEntryRow`, `DenseOrgHeader`).
- **Pins** as a grid of tiles at top (`PinnedGrid`, `MacPinGrid`, reorderable, synced via `/v1/me/pins/order`), "Keep this chat at the top".
- Sidebar shortcuts are configurable: "Which shortcuts show beside the chat list, and in what order." (`SidebarEditSheet`) — entries like Threads, Assigned to me, Mine, Library, Approvals.
- Unread badges, "Clear this chat's unread count", "Count muted chats in the badge", Next/Previous conversation commands.
- Empty states with friendly copy for every list ("Nothing assigned to you", "Nothing is waiting for you.").

Conversation info sheet [O]: photo, name, members, notifications, files, calendar, board, encryption info (`EncryptionSheet`), "Resync this conversation" (rebuild view from delivered messages), report/block.

## 5. Messages and the composer

Transcript (`TranscriptCore`, `TranscriptCollectionMac`) [O]:
- Bubbles grouped by sender with tails/corners (`BubbleCorners`, `BubbleTail`, `BubbleRowLayout`), or flat layout ("Messages in bubbles, grouped by who sent them." is one option).
- Date headers, "Go to a day in this chat" (calendar jump `MonthGrid`, `WeekStrip`), `JumpToNewestButton`, "Couldn't load earlier messages", typing indicator.
- Name colours per person (`NameColors`), mention styling, markdown (`MarkdownBlocks`, `CodeBlockBox`, `CodeLexer` → syntax highlighting).
- Delivery states: sending ring, "Not delivered yet", "Delivered to everyone", "Read by everyone", per-person `ReceiptInfoSheet`.
- Message actions [O]: reply (quote), react (`MacReactionPicker`, heart burst animation), edit ("Edit Last Message" shortcut), forward (single + "Forward Selected" with drag-to-select multi-select), copy, save to Mine, save to channel files, tag, highlight, assign as task, remind, report, "Notify Anyway" (bypass someone's mute/Focus, rate-limited: "You've used Notify Anyway a lot just now.").
- `MessageFocusOverlay`: long-press/focus a message with dimmed backdrop (iMessage-style). [I]
- Imported history from Telegram ("Imported from Telegram"). [O]

Composer (`Composer`, `ComposerTextView`) [O]:
- Rich text with formatting actions, mentions, `/` slash commands (`SlashPicker`, `SlashForm` — forms for structured messages).
- Attach: "Add a photo, file, poll, checklist or event". Drag/drop/paste files.
- Voice messages (record bar with level meter, cancel, waveform playback `VoiceBubble`).
- Expression panel: emoji (with search + recents), **animated emoji**, **sticker packs** (Lottie, browse/search packs), GIFs (Klipy, save to org GIF library "our GIFs").
- Link preview attach/remove; tags for what you're sending.
- Drafts per conversation (`DraftBox`).

Rich message types [O]: poll (multi-answer, voters list, close), **find-a-time poll** ("Tick every time you can make"), checklist (shared, "Others can add items"), event (RSVP Going/Maybe, add to group/my calendar, change/cancel notifications), task (assignee, due date), Google Meet link ("Book a Google Meet"), file cards (PDF, CSV/tables, text, docx/xlsx/numbers via QuickLook), voice, photo/video gallery, sticker, GIF.

Link cards [O]: generic, article (reader view via Readability.js — `reader.js`, `Readability.js` bundled), PDF, GitHub, YouTube (inline player), X/Twitter posts, Instagram posts/reels. All "Opens in Enclave".

## 6. Threads

[O] `ThreadView`, `ThreadsView` ("Threads you start, reply in or are mentioned in show up here, with a dot when there's something new."), follow/unfollow thread, thread summary row in transcript ("N replies" line), "Every message, and replies in threads you're in" notification level.

## 7. Productivity layer (the big differentiator)

- **Mine / Scratchpad**: private per-user space. "Drop photos, files or links here, paste them, or use Add. Right-click one in a chat and choose Save to Mine. Only you see them." Also "Scratchpad in New Window". [O]
- **Pad / canvas**: "Your private canvas", "Open the canvas beside the app", notes with headings/checklists/files/stickers/voice memos ("Add a note, heading, checklist, file, sticker or voice memo"), `PadCanvas`, `PadGrid`, note editor, op-log CRDT-ish (`PadOp`, `PadLogEntry`, `PadFold`). [O]
- **Boards** (Kanban per channel): lanes, cards, drag/drop, "Move Card to Next Lane", "This board is full", "Whose cards to show", archive/undo. [O]
- **Tasks**: assign from a message, "Assigned to me" view, due dates. [O]
- **Calendar** per conversation, events with RSVP, Google Calendar integration that "only manages meetings it creates". [O]
- **Reminders** (`Reminders.swift`). [O]
- **Tags** (personal "My tags" synced across devices + org/admin tags): hierarchy up to 4 levels, colours/icons, tag strip, quick tags, triage view "Tag what has no tags yet, one at a time", swipe to tag. [O]
- **Smart folders**: saved filters over shared items (type, tag, people, org). [O]
- **Library**: everything shared across all chats — photos, videos, files, links, GIFs — with facets/pills, inspector panel, "Links saved to read later, not opened yet" (read-later with unread dot), media drawer per chat. [O]
- **Highlights**: highlight passages in articles/PDFs ("Highlight in yellow", `HighlightsListSheet`). [O]
- **Articles**: long-form posts with cover photo, block editor, drafts, comments, publish to community feed, versions/conflict handling. [O]
- **Community feed** posts with photos/videos, likes (`LikersSheet`), comments. [O]
- **PDF markup + e-signature**: annotate PDFs, draw/store signature on device ("Your signature stays on this Mac"), send marked-up copy. Screenshot markup for feedback. [O]
- **Command Center** (⌘K-style palette): sections, recents, scored fuzzy results, prefixes, "asks" into chats, files search. [O]
- **Search**: in chat ("Find in conversation" find bar), everywhere, by tag, file names, in document. [O]

## 8. Notifications

[O] Levels per kind of conversation (`DefaultLevel`): all new messages / mentions and DMs / never. Per-chat override, mute durations, **pause notifications** (custom pause), **quiet hours** (schedule + time zone, held server-side), "Mentions get through mute", "Break through Focus" (Focus filter per org), "Reactions to my messages", keywords ("Add a word or phrase"), mute/pause a whole community, per-device settings, in-app banners, Notify Anyway. Notification Service Extension decrypts pushes.

## 9. Calls

[O] 1:1 and group via LiveKit, CallKit integration (incoming call UI, "Answered on another device"), call bar while browsing, audio route picker (AirPlay, headphones, car), call quality meter, call rows in transcript, "Couldn't connect. One of you may be on a network that blocks calls."

## 10. Backup and restore

[O] Encrypted backups to Google Drive or file export; frequency (incl. "Only when I tap Back up now"), Wi-Fi only, "How much history", segments/manifest, restore offer card after sign-in, "Files include documents and voice messages. Stickers and link previews aren't backed up."

## 11. Bots and CLI

[O] Org bots with two access levels: **post-only** ("It can post where it's added, but it can't read messages. For alerts, feeds and scripts.") and **reader** ("It can read messages in the conversations it's added to, from when it joins. For reminders, commands and assistants."). Bots are real MLS members on a server via the CLI; `BOT` badge; enrolment command.

## 12. Safety and moderation

[O] Report reasons: spam, harassment/bullying, hate speech, violence, nudity, impersonation ("Pretending to be someone else"), misinformation, illegal, other. Block people ("They won't be able to message or call you directly. You'll still see each other in shared groups and channels."). Report GIFs. "Files policy" — "Allow files to leave Enclave", "The copy you share leaves Enclave's encryption."

## 13. Appearance

[O] Theme families with copy:
- **Classic** "Warm paper by day, ink by night: the Enclave look."
- **Forest** "Soft green-grey and deep forest: calm, like a walk outside."
- **Ocean** "Sea glass and deep teal: cool, clear and bright."
- **Sunset/Dusk-lilac** "Lilac evenings and violet ink, with a little sunset."
- **Rose** "Blush and raspberry: warm, friendly, a bit playful."
- **Paper/Sand** "Old paper and rust, serif throughout: reads like a book."
- **Mono** "Greyscale and monospaced: plain names, square avatars, nothing extra."
- **Midnight/Electric** "True black for OLED, an electric accent and vivid names."
(Names found: classic, dawn, electric, forest, midnight, mono, night, ocean, paper, rose, sand, slate, sunset; exact name↔copy mapping is [I].)
Also: text size, spacing ("The room between messages and between chats in the list. It grows with the text size."), list style, app icon (Classic/Black/White), monochrome avatars, haptics policy, reduced motion gate (`MotionGate`).

## 14. UX patterns worth copying (from the copy itself)

- Plain, human copy everywhere; every error says what happened and what to do ("Ask them to open Enclave, then try again.").
- Every empty state explains what will appear there.
- E2EE reassurance is contextual (permission prompts, photo, status) rather than a banner.
- Destructive confirmations spell out consequences precisely ("It comes off everything it's on. Those items keep their other tags.").
- Self-healing UI states instead of errors: "Getting this chat ready on this device", "Enclave is bringing this chat to this device."
- A full **demo mode** with seeded orgs/people/chats ships in the app (`DemoEnvironment`, demo plists/videos/docs) — useful for onboarding and screenshots.

## Gap against this repo (2026-10-19)

| Area | We have | Enclave has | Gap |
| --- | --- | --- | --- |
| Crypto | X3DH + Double Ratchet, 1:1 (`crates/chatcore`, `public/signal.js`) | MLS (openmls) for every conversation | MLS is planned in `workspace-architecture.md`; prerequisite for groups/channels/multi-device |
| Accounts | Passkeys, single-use invites, mutual contacts | Username + passphrase + recovery words, invite-only | Keep passkeys; add recovery words for key backup |
| Devices | One active device | Linked devices + history sync | Large: needs MLS (device = leaf) |
| Orgs/channels | None | Orgs, roles, channels, directory, connected communities, guests | Large |
| Messages | Text, receipts, unread, timers, burn, polls, reminders, slash commands, custom emoji | + replies, reactions, edits, forward, threads, mentions, markdown/code, attachments, voice, stickers, GIFs, link cards, typing | Medium per feature; most are payload types on top of existing transport |
| Calls | 1:1 WebRTC + TURN | Group calls via LiveKit SFU, CallKit | Group calls need an SFU |
| Productivity | — | Mine, Pad, Boards, Tasks, Calendar, Tags, Smart folders, Library, Articles, Command Center | Large, but independent of crypto once payloads exist |
| Notifications | Web Push, FCM/APNs/VoIP | Levels, mutes, pause, quiet hours, keywords, Focus, Notify Anyway | Medium; server must hold pushes per user settings |
| Backup | Manual encrypted export | Scheduled Drive backups, restore offer | Small-medium |
| Appearance | 7 themes, wallpapers | 8 theme families, text size, spacing, list density, app icon | Small |

Suggested order (each step usable on its own): (1) message-level UX on the existing 1:1 transport — reply, react, edit, typing, attachments, voice, markdown, link cards, Command Center, theme/density settings; (2) MLS core + groups; (3) linked devices + history sync; (4) orgs/channels/threads/roles; (5) group calls (SFU); (6) productivity layer (Mine, tags, library, boards, tasks); (7) connected communities, guests, bots.

## Unknowns (need a runtime pass)

- Visual layout, spacing, typography, motion and exact navigation structure.
- Keyboard shortcut bindings (not recoverable from strings).
- Relay wire protocol details beyond endpoint paths; push payload format.
- Group size limits, MLS ciphersuite chosen, how history sync is encrypted between devices.
