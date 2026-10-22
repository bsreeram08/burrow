# Burrow

A self-hosted, end-to-end encrypted messenger. The server is Bun, with coturn relaying call media. It ships a web client and a Flutter app for iOS, Android and macOS, which interoperate. No hosted communication service is required.

- **Messaging:** one-to-one and group chats, end to end encrypted (MLS for groups), with replies, reactions, edits, read receipts, attachments, voice messages and link previews. See [messaging](docs/phase1-protocol.md) and [groups](docs/m4-groups.md).
- **Devices:** every device on an account holds the account key. Link a new one by QR code, or restore it from an encrypted backup that opens with a passphrase or 24 recovery words. See [devices](docs/devices.md), [linking](docs/m5-linking.md) and [account key and backup](docs/m6-account-key.md).
- **Calls:** one-to-one audio and video calls with a six-digit verification code.

The server holds only encrypted messages and attachments until they are delivered, never their content. See [current status](docs/status.md), [security boundaries](docs/security.md) and the [architecture](docs/workspace-architecture.md).

To integrate calls into your own application, use the [calling API](docs/signaling-api.md). Room creation stays on your trusted backend; each participant receives a separate invitation.

## Try locally

Install Bun 1.4.0 or newer. The signaling runtime uses only built-ins, so it can start without installing the repository's legacy dependencies.

For a single-room demo, run this from the repository root:

```sh
bun --no-env-file run demo
```

Open its two private links in separate browser windows and join. Stop with Ctrl+C. The demo generates its own administrator credential and keeps it out of the links.

To manage several rooms locally, use these commands instead:

```sh
export ADMIN_TOKEN="$(bun --no-env-file -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))')"
export PUBLIC_ORIGIN=http://localhost:3000
bun --no-env-file run start &
CALL_SERVER_PID=$!
curl --fail --retry 10 --retry-delay 1 --retry-connrefused http://localhost:3000/health
bun --no-env-file run room:create
```

Open the two different participant links in separate browser windows, then click **Join call** in each. Allow camera/microphone access. Select **Audio only** before joining to skip the camera. These local links work on this machine; use the HTTPS deployment below for other devices and networks. Keep each participant link private, and never send the administrator token to a participant.

When finished with this local server:

```sh
kill "$CALL_SERVER_PID"
```

`bun --no-env-file run dev` runs the signaling server with automatic restart. Rooms live in memory and disappear on restart. Runtime commands explicitly disable loading the repository's old `.env` file; provide configuration through environment variables.

## Self-host on your server

Follow the [deployment guide](docs/deployment.md) for a Linux Docker Compose setup with HTTPS, private administrator credentials, authenticated TURN, firewall ports, and real-network verification. It generates isolated configuration under `deploy/` and preserves existing configuration. WebRTC media is encrypted, including through TURN, but no system is guaranteed unhackable.

The small standalone Bun STUN implementation is available through `bun --no-env-file run stun`; production deployments use coturn for both STUN and TURN. Bun handles signaling rather than terminating or transcoding media.

## Verify changes

```sh
bun install --frozen-lockfile
bun --no-env-file run typecheck
bun --no-env-file test
```

For browser checks, use Node.js 22 or newer and keep the local server running with the same exported `ADMIN_TOKEN`. Install Chromium once, then run:

```sh
bunx playwright-core install chromium
TEST_ORIGIN=http://localhost:3000 bun --no-env-file run test:browser
```

The browser test creates two isolated browser contexts, checks increasing received audio/video bytes and decoded video, verifies mute/camera controls, and checks hangup and invite revocation. It uses synthetic media. `BROWSER_EXECUTABLE=/absolute/path/to/chromium` selects an existing browser; `TEST_MODE=audio` or `TEST_MODE=video` narrows the run. Set `RELAY_ONLY=true` on the server with valid `TURN_SECRET` and `TURN_URLS`, then set `EXPECT_RELAY=true` when running the test to require relay candidates. `REUSE_BROWSER=true` tests consecutive calls in the same browser. Actual devices on different networks are also required before declaring a deployment ready.

The older Auth0/Redis manager and older STUN experiment remain for reference and are outside the supported runtime; do not use them as production entrypoints.
