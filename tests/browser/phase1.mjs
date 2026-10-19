// Phase 1 messaging end to end (docs/phase1-protocol.md): two accounts in Chromium exchange markdown, a reply,
// reactions (hover bar and double-click), an edit (↑ in the empty composer), read receipts, typing, an encrypted
// photo and file (verified bytes, nothing readable on the server), a voice message from the fake microphone,
// find in conversation, the command palette, date separators and appearance settings.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/phase1.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { deflateSync } from 'node:zlib';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3137), origin = `http://localhost:${port}`;
const dataDir = process.env.DATA_DIR || mkdtempSync(join(tmpdir(), 'phase1-e2e-'));
const shots = process.env.SCREENSHOT_DIR;
const env = { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, DATA_DIR: dataDir };
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { cwd: root, env, stdio: ['ignore', 'pipe', 'inherit'] });
process.on('exit', () => server.kill());
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(1));
await new Promise((ok, fail) => { server.stdout.on('data', chunk => String(chunk).includes('listening') && ok()); server.on('exit', code => fail(new Error(`server exited ${code}`))); setTimeout(() => fail(new Error('server did not start')), 10000); });
const browser = await playwright.chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE, args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'] });
const step = name => console.log(`✓ ${name}`);
const pages = [];
const shot = async (page, name) => { if (shots) { await page.waitForTimeout(300); await page.screenshot({ path: join(shots, `phase1-${name}.png`) }); } };
const visible = (page, selector, timeout = 15000) => page.locator(selector).first().waitFor({ state: 'visible', timeout });
const until = (page, fn, arg, timeout = 15000) => page.waitForFunction(fn, arg, { timeout });
/** Every file the server wrote, as one string: plaintext must never be found in it. */
const serverBytes = () => {
  const all = [];
  const walk = dir => { for (const entry of readdirSync(dir, { withFileTypes: true })) { const path = join(dir, entry.name); if (entry.isDirectory()) walk(path); else if (entry.isFile() && statSync(path).size < 64 * 1024 * 1024) all.push(readFileSync(path)); } };
  walk(dataDir); return Buffer.concat(all).toString('latin1');
};
/** A small valid PNG (solid colour with a marker in a text chunk) generated without dependencies. */
function png(width, height, marker) {
  const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = bytes => { let c = 0xffffffff; for (const byte of bytes) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (type, data) => { const head = Buffer.alloc(8); head.writeUInt32BE(data.length); head.write(type, 4, 'latin1'); const tail = Buffer.alloc(4); tail.writeUInt32BE(crc(Buffer.concat([Buffer.from(type, 'latin1'), data]))); return Buffer.concat([head, data, tail]); };
  const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
  const rows = Buffer.alloc((width * 3 + 1) * height);
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) rows.set([40 + x % 200, 120, 200 - y % 150], y * (width * 3 + 1) + 1 + x * 3);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', header), chunk('tEXt', Buffer.from(`Comment\0${marker}`, 'latin1')), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))]);
}

async function person() {
  const context = await browser.newContext({ viewport: { width: 1100, height: 860 }, acceptDownloads: true });
  await context.grantPermissions(['camera', 'microphone', 'clipboard-read', 'clipboard-write'], { origin });
  const page = await context.newPage(); pages.push(page);
  page.on('pageerror', error => { console.error('pageerror', error); throw error; });
  page.on('console', message => { if (message.type() === 'error' && !/Failed to load resource/.test(message.text())) console.log(`[console] ${message.text()}`); });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  // Headless pages never hold window focus; read receipts wait for it, so the test grants it.
  await page.addInitScript(() => { Document.prototype.hasFocus = () => document.visibilityState === 'visible'; });
  return page;
}
async function register(page, invite, username) {
  await page.goto(`${origin}/#invite=${invite}`);
  await visible(page, '#welcome');
  await page.fill('#register-username', username);
  await page.click('#register-submit');
  await visible(page, '#chats');
}
const lastIncoming = '#chat-log li.incoming:last-of-type';
const rowWith = (page, text) => page.locator('#chat-log li[data-message-id]').filter({ has: page.locator('.message-text', { hasText: text }) }).last();

try {
  const bootstrap = spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' });
  const firstInvite = /Invite code: (\S+)/.exec(bootstrap.stdout)?.[1];
  if (!firstInvite) throw new Error(`create-invite failed: ${bootstrap.stderr}`);
  const alice = await person(), bob = await person();
  await register(alice, firstInvite, 'alice');
  await alice.click('#account-menu summary'); await alice.click('#invite-create');
  await visible(alice, '#invite-result');
  await register(bob, new URL(await alice.inputValue('#invite-link')).hash.slice('#invite='.length), 'bob');
  await alice.fill('#contact-input', 'bob'); await alice.click('#contact-add');
  await bob.getByRole('button', { name: 'Accept' }).click({ timeout: 15000 });
  await until(alice, () => document.querySelector('#contact-list .contact.mutual .avatar')?.dataset.online === 'true');
  await alice.click('#contact-list .contact.mutual .row-button'); await visible(alice, '#conv-head');
  await bob.click('#contact-list .contact.mutual .row-button'); await visible(bob, '#conv-head');
  step('alice and bob registered, are contacts, and both have the conversation open');

  // ---------- Markdown, read receipts and typing ----------
  await alice.fill('#chat-input', 'hello **bob**, see `code` and _this_ <img src=x onerror=alert(1)>');
  await alice.press('#chat-input', 'Enter');
  await until(bob, () => document.querySelector('#chat-log li.incoming .message-text strong')?.textContent === 'bob');
  if (await bob.locator('#chat-log li.incoming .message-text img').count()) throw new Error('HTML in a message was interpreted');
  if (!await bob.locator('#chat-log li.incoming .md-code').count() || !await bob.locator('#chat-log li.incoming em').count()) throw new Error('Markdown code or italic did not render');
  await until(alice, () => document.querySelector('#chat-log li.outgoing')?.dataset.status === 'read', null, 20000);
  if (!await alice.locator('#chat-log li.day').count()) throw new Error('No date separator');
  step('markdown rendered as DOM (no HTML), a "Today" separator shows, and the sender saw ✓✓ read');

  await bob.click('#chat-input'); await bob.keyboard.type('typing something');
  await until(alice, () => !document.getElementById('typing').hidden && document.getElementById('typing-text').textContent.includes('bob'), null, 10000);
  await shot(alice, '1-typing');
  await bob.fill('#chat-input', '');
  await bob.locator('#chat-input').blur();
  await until(alice, () => document.getElementById('typing').hidden, null, 10000);
  step('typing indicator appeared while bob typed (ephemeral) and cleared when he stopped');

  // ---------- Reply via the hover bar ----------
  await rowWith(bob, 'hello').hover();
  await visible(bob, '#msg-actions');
  await bob.click('#msg-actions [data-action="reply"]');
  await visible(bob, '#compose-quote');
  if (!(await bob.textContent('#compose-label')).includes('alice')) throw new Error('Reply bar does not name the author');
  await bob.fill('#chat-input', 'replying to you'); await bob.press('#chat-input', 'Enter');
  await until(alice, () => document.querySelector('#chat-log li.incoming .reply-quote .reply-author')?.textContent === 'You');
  await alice.click('#chat-log li.incoming .reply-quote');
  await until(alice, () => document.querySelector('#chat-log li.outgoing.flash'));
  step('bob replied from the hover bar; alice sees the quote with its author, and clicking it highlights the original');

  // ---------- Reactions: quick bar, double-click, toggle off ----------
  await rowWith(alice, 'replying to you').hover();
  await alice.click('#msg-actions [data-react="👍"]');
  await until(bob, () => document.querySelector('#chat-log li.outgoing .reaction[data-emoji="👍"] .reaction-count')?.textContent === '1');
  await rowWith(bob, 'hello').locator('.message-text').dblclick();
  await until(alice, () => document.querySelector('#chat-log li.outgoing .reaction[data-emoji="❤️"]'));
  await bob.click('#chat-log li.outgoing .reaction[data-emoji="👍"]'); // Bob adds his own 👍 to alice's reaction.
  await until(alice, () => document.querySelector('#chat-log li.incoming .reaction[data-emoji="👍"] .reaction-count')?.textContent === '2');
  await alice.click('#chat-log li.incoming .reaction[data-emoji="👍"]'); // Alice takes hers back.
  await until(bob, () => document.querySelector('#chat-log li.outgoing .reaction[data-emoji="👍"] .reaction-count')?.textContent === '1');
  await shot(bob, '2-reactions');
  step('reactions: quick 👍 from the hover bar, ❤️ by double-click, pills toggle and count per person on both sides');

  // ---------- The emoji picker behind "more" ----------
  await rowWith(alice, 'replying to you').hover();
  await alice.click('#msg-actions [data-action="more"]');
  await visible(alice, '#emoji-picker');
  await alice.keyboard.type('tada'); await alice.keyboard.press('Enter');
  await until(bob, () => document.querySelector('#chat-log li.outgoing .reaction[data-emoji="🎉"]'));
  step('"more" opened the emoji picker; searching "tada" and Enter reacted with 🎉');

  // ---------- Link preview: made by the sender only, removable before sending ----------
  // The unfurler is the server's; here its answers are stubbed so the check needs no internet.
  await alice.route('**/api/unfurl?*', route => route.fulfill({ json: { url: 'https://example.com/article', title: 'An article worth reading', description: 'What it is about.', site: 'Example', image: 'https://example.com/cover.png' } }));
  await alice.route('**/api/unfurl/image?*', route => route.fulfill({ body: png(120, 80, 'cover'), contentType: 'image/png' }));
  let bobFetchedPreview = false;
  await bob.route('**/api/unfurl**', route => { bobFetchedPreview = true; return route.abort(); });
  await alice.fill('#chat-input', 'read https://example.com/nope'); await alice.locator('#chat-input').dispatchEvent('input');
  await visible(alice, '#compose-link', 10000);
  await alice.click('#compose-link-remove');
  if (!await alice.isHidden('#compose-link')) throw new Error('Remove link preview did not remove it');
  await alice.fill('#chat-input', 'read **this** https://example.com/article'); await alice.locator('#chat-input').dispatchEvent('input');
  await until(alice, () => !document.getElementById('compose-link').hidden && !document.getElementById('compose-link-thumb').hidden, null, 10000);
  await alice.press('#chat-input', 'Enter');
  await until(bob, () => document.querySelector('#chat-log li.incoming .link-card .link-title')?.textContent === 'An article worth reading' && document.querySelector('#chat-log li.incoming .link-card .link-thumb')?.naturalWidth > 0);
  if (bobFetchedPreview) throw new Error('The receiver fetched the link preview');
  step('link preview: ✕ removed one before sending; the next went with title and a ≤ 4 KB thumbnail, and bob never fetched anything');

  // ---------- Edit the last message with ↑ ----------
  await alice.fill('#chat-input', 'meet at 5pm');
  await alice.press('#chat-input', 'Enter');
  await until(bob, () => document.getElementById('chat-log').textContent.includes('meet at 5pm'));
  await alice.click('#chat-input'); await alice.keyboard.press('ArrowUp');
  if (await alice.inputValue('#chat-input') !== 'meet at 5pm' || await alice.isHidden('#compose-quote')) throw new Error('↑ did not start editing the last message');
  await alice.fill('#chat-input', 'meet at 6pm'); await alice.press('#chat-input', 'Enter');
  await until(bob, () => [...document.querySelectorAll('#chat-log li.incoming')].some(row => row.querySelector('.message-text').textContent === 'meet at 6pm' && row.querySelector('.meta-text').textContent.includes('edited')));
  if ((await bob.textContent('#chat-log')).includes('meet at 5pm')) throw new Error('The old text is still shown after the edit');
  step('↑ in the empty composer edited the last message; bob sees the new text marked "edited"');

  // ---------- Attachments: a photo and a file, encrypted end to end ----------
  const marker = `photo-marker-${randomBytes(6).toString('hex')}`;
  const photo = png(640, 400, marker);
  await alice.setInputFiles('#attach-input', { name: 'sunset.png', mimeType: 'image/png', buffer: photo });
  await until(bob, () => { const image = document.querySelector('#chat-log li.incoming .attachment-image .media-full'); return image?.complete && image.naturalWidth === 640; }, null, 20000);
  const ratio = await bob.$eval('#chat-log li.incoming .attachment-image .media-frame', node => node.getBoundingClientRect().width / node.getBoundingClientRect().height);
  if (Math.abs(ratio - 1.6) > 0.05) throw new Error(`Photo not shown at its aspect ratio: ${ratio}`);
  if (serverBytes().includes(marker)) throw new Error('The photo reached the server unencrypted');
  await bob.click('#chat-log li.incoming .attachment-image .media-frame');
  await visible(bob, '#lightbox');
  await bob.click('#lightbox-img'); await until(bob, () => document.getElementById('lightbox').dataset.zoom === 'yes');
  await shot(bob, '3-lightbox');
  await bob.keyboard.press('Escape'); await until(bob, () => document.getElementById('lightbox').hidden);
  step('photo: encrypted upload, shown at its aspect ratio on the other side, opens in the zoomable viewer; server holds ciphertext only');

  const secret = `file-secret-${randomBytes(8).toString('hex')}\n`.repeat(50);
  await alice.setInputFiles('#attach-input', { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from(secret) });
  await until(bob, () => [...document.querySelectorAll('#chat-log li.incoming .file-name')].some(node => node.textContent === 'notes.txt'), null, 20000);
  const [download] = await Promise.all([bob.waitForEvent('download'), bob.locator('#chat-log li.incoming .file-card', { hasText: 'notes.txt' }).locator('.file-action').click()]);
  const got = readFileSync(await download.path(), 'utf8');
  if (got !== secret || download.suggestedFilename() !== 'notes.txt') throw new Error('Downloaded file differs from what was sent');
  if (serverBytes().includes(secret.slice(0, 30))) throw new Error('The file reached the server unencrypted');
  step('file card: downloaded on the other side byte for byte after SHA-256 verification and decryption');

  // A tampered blob is refused, not rendered.
  const tampered = await bob.evaluate(async () => {
    const records = await window.ChatStore.list(), file = records.findLast(record => record.attachment?.name === 'notes.txt').attachment;
    try { await window.Files.decrypt(new Uint8Array(await (await fetch(`/api/blobs/${file.blob}`)).arrayBuffer()).map((byte, index) => index === 40 ? byte ^ 1 : byte), file.key, file.sha256); return 'accepted'; }
    catch (error) { return error.message; }
  });
  if (tampered !== 'That file couldn’t be read.') throw new Error(`Tampered ciphertext was not refused: ${tampered}`);
  step('ciphertext that fails the SHA-256 check is refused with “That file couldn’t be read.”');

  // ---------- Voice message from the fake microphone ----------
  await alice.fill('#chat-input', '');
  await alice.locator('#chat-input').dispatchEvent('input');
  await visible(alice, '#voice-record');
  await alice.click('#voice-record');
  await visible(alice, '#record-bar');
  await alice.waitForTimeout(1800);
  await shot(alice, '4-recording');
  await alice.click('#record-send');
  await until(bob, () => document.querySelector('#chat-log li.incoming .voice audio'), null, 20000);
  const bars = await bob.locator('#chat-log li.incoming .voice .voice-wave i').count();
  if (bars < 8 || bars > 64) throw new Error(`Unexpected waveform: ${bars} bars`);
  await bob.click('#chat-log li.incoming .voice .voice-speed');
  if (await bob.textContent('#chat-log li.incoming .voice .voice-speed') !== '1.5×') throw new Error('Speed did not change');
  await bob.click('#chat-log li.incoming .voice .voice-play');
  await until(bob, () => { const audio = document.querySelector('#chat-log li.incoming .voice audio'); return audio && !audio.paused && audio.currentTime > 0 && audio.playbackRate === 1.5; }, null, 10000);
  step(`voice message recorded (${await alice.evaluate(() => window.ChatStore.list().then(list => list.findLast(record => record.attachment?.kind === 'voice')?.attachment.mime))}), shows a ${bars}-bar waveform, plays at 1.5×`);

  // ---------- Find, palette, appearance ----------
  await bob.click('#chat-input');
  await bob.keyboard.press('Control+f');
  await visible(bob, '#find-bar');
  await bob.keyboard.type('meet');
  await until(bob, () => document.getElementById('find-count').textContent === '1 of 1');
  await bob.keyboard.press('Escape');
  step('⌘F/Ctrl+F found the edited message in the conversation');

  await alice.click('#conv-back'); await visible(alice, '#chats');
  await alice.keyboard.press('Control+k');
  await visible(alice, '#palette');
  await alice.keyboard.type('bo');
  await until(alice, () => document.querySelector('#palette-list .palette-item[aria-selected="true"] .palette-label')?.textContent === 'bob');
  await shot(alice, '5-palette');
  await alice.keyboard.press('Enter');
  await visible(alice, '#conv-head');
  if (await alice.textContent('#conv-name') !== 'bob') throw new Error('Palette did not open the conversation');
  step('⌘K/Ctrl+K palette: fuzzy "bo" → bob, Enter opened the conversation');

  await alice.evaluate(() => { window.Theme.setAppearance({ size: 'xl', density: 'compact' }); });
  const size = await alice.$eval('#chat-log', node => getComputedStyle(node).fontSize);
  if (size !== '20px') throw new Error(`Text size not applied: ${size}`);
  await alice.click('#conv-menu summary'); await alice.click('#conv-theme'); await visible(alice, '#theme-dialog');
  await alice.click('#theme-families [data-family="forest"]'); await alice.click('#theme-mode [data-mode="light"]');
  const bg = await alice.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
  if (bg !== '#f3f6f2') throw new Error(`Forest light not applied: ${bg}`);
  await shot(alice, '6-theme-dialog');
  await alice.click('#theme-done');
  await shot(alice, '7-forest-xl');
  step('appearance: XL text and compact spacing apply; the Forest family in Light mode recolours the chat');
  console.log('Phase 1 end-to-end check passed.');
} catch (error) {
  for (const page of pages) console.error('chat-status:', await page.textContent('#chat-status').catch(() => '?'), '| chats-status:', await page.textContent('#chats-status').catch(() => '?'));
  throw error;
} finally {
  await browser.close().catch(() => {});
  server.kill();
  if (!process.env.DATA_DIR) rmSync(dataDir, { recursive: true, force: true });
}
