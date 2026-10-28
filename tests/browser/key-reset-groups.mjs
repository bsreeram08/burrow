// A browser that generated new identity keys (no succession) keeps its groups: it rejoins them under the new key,
// so its chats keep working and a newly linked device of the other person can still join the DM. Before, the
// browser started an empty store and its old leaf (old key) blocked every new device from joining.
// Usage: node tests/browser/key-reset-groups.mjs
// (Was: Linked devices and DMs on MLS end to end (docs/m5-linking.md), in Chromium against the real server:
// a 1:1 chat with history on the Double Ratchet moves to MLS with that history intact; alice links a second browser
// (QR text typed across, the 6-digit codes compared), which then shows her channel and her moved DM. Short-code links,
// the account key moving between devices, backups and revocation are in account-key.mjs.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/linking.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3152), origin = `http://localhost:${port}`;
const dataDir = process.env.DATA_DIR || mkdtempSync(join(tmpdir(), 'key-reset-e2e-'));
const shots = process.env.SCREENSHOT_DIR;
// Each browser its own address (per-source limits); test flags (loopback only) let the chat start on the Double Ratchet.
const env = { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, DATA_DIR: dataDir, TRUST_PROXY: 'true', ALLOW_TEST_FLAGS: '1' };
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { cwd: root, env, stdio: ['ignore', 'pipe', 'inherit'] });
process.on('exit', () => server.kill());
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(1));
await new Promise((ok, fail) => { server.stdout.on('data', chunk => String(chunk).includes('listening') && ok()); server.on('exit', code => fail(new Error(`server exited ${code}`))); setTimeout(() => fail(new Error('server did not start')), 10000); });
const browser = await playwright.chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE });
const step = name => console.log(`✓ ${name}`);
const pages = [];
const TIMEOUT = 30000;
const shot = async (page, name) => { if (shots) { await page.waitForTimeout(300); await page.screenshot({ path: join(shots, `key-reset-${name}.png`) }); } };
const visible = (page, selector, timeout = TIMEOUT) => page.locator(selector).first().waitFor({ state: 'visible', timeout });
const until = (page, fn, arg, timeout = TIMEOUT) => page.waitForFunction(fn, arg, { timeout });

let addresses = 0;
async function person(name, { passkey = true } = {}) {
  const context = await browser.newContext({ viewport: { width: 1000, height: 860 }, extraHTTPHeaders: { 'X-Real-IP': `10.8.0.${++addresses}` } });
  const page = await context.newPage(); pages.push(page); page.label = name;
  page.on('pageerror', error => { console.error(`[${name}] pageerror`, error); throw error; });
  page.on('console', message => { if (message.type() === 'error' && !/Failed to load resource/.test(message.text())) console.log(`[${name} console] ${message.text()}`); });
  if (passkey) {
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  }
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
async function invite(page) {
  await page.click('#account-menu summary'); await page.click('#invite-create');
  await visible(page, '#invite-result');
  const code = new URL(await page.inputValue('#invite-link')).hash.slice('#invite='.length);
  await page.click('#invite-close');
  return code;
}
const message = (page, text) => page.locator('#chat-log li[data-message-id]').filter({ has: page.locator('.message-text', { hasText: text }) }).last();
const sees = (page, text, timeout = TIMEOUT) => message(page, text).waitFor({ state: 'visible', timeout });
async function say(page, text) {
  await page.fill('#chat-input', text);
  await page.press('#chat-input', 'Enter');
  await until(page, async text => (await window.ChatStore.list()).some(record => record.direction === 'outgoing' && record.text === text && record.status !== 'queued'), text);
}
const openDm = async (page, name) => {
  if (await page.locator('#conv-head').isVisible()) await page.click('#conv-back');
  const row = page.locator('#contact-list .contact.mutual').filter({ has: page.locator('strong', { hasText: name }) });
  await row.waitFor({ state: 'visible', timeout: TIMEOUT });
  await row.locator('.row-button').click();
  await visible(page, '#conv-head');
};
const moved = page => page.evaluate(() => Object.keys(JSON.parse(localStorage.getItem(`dm-moved-v1:${window.App.accountId}`) || '{}')).length);

// The DM groups this browser knows (dm-moved-v1 maps a contact to its DM channel), with their local state.
const dmStates = () => Object.values(JSON.parse(localStorage.getItem(`dm-moved-v1:${window.App.accountId}`) || '{}')).map(value => window.Groups.debug(typeof value === 'string' ? value : value?.channel));
const diag = page => page.evaluate(dmStates => ({ moved: localStorage.getItem(`dm-moved-v1:${window.App.accountId}`), dms: new Function(`return (${dmStates})()`)(), chat: document.getElementById('chat-status').textContent, banner: document.getElementById('group-banner-text')?.textContent, key: document.getElementById('key-banner-text')?.textContent }), String(dmStates)).catch(error => error.message);

try {
  const bootstrap = spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' });
  const firstInvite = /Invite code: (\S+)/.exec(bootstrap.stdout)?.[1];
  if (!firstInvite) throw new Error(`create-invite failed: ${bootstrap.stderr}`);
  const alice = await person('alice'), bob = await person('bob');
  // As in linking.mjs: the chat starts on the Double Ratchet, then moves to MLS.
  for (const page of [alice, bob]) await page.addInitScript(() => localStorage.setItem('dm-move-test', 'off'));
  await register(alice, firstInvite, 'alice');
  await register(bob, await invite(alice), 'bob');
  await alice.fill('#contact-input', 'bob'); await alice.click('#contact-add');
  await bob.getByRole('button', { name: 'Accept' }).click({ timeout: TIMEOUT });
  await until(alice, () => window.Groups?.enabled()); await until(bob, () => window.Groups?.enabled());
  await openDm(alice, 'bob'); await openDm(bob, 'alice');
  await say(alice, 'Before the move'); await sees(bob, 'Before the move');
  await say(bob, 'Old encryption reply'); await sees(alice, 'Old encryption reply');
  for (const page of [alice, bob]) await page.evaluate(() => localStorage.removeItem('dm-move-test'));
  await say(alice, 'Hello on MLS'); await sees(bob, 'Hello on MLS');
  await until(alice, () => Object.keys(JSON.parse(localStorage.getItem(`dm-moved-v1:${window.App.accountId}`) || '{}')).length === 1);
  step('alice and bob chat in an MLS DM');

  // ---------- alice's browser generates new identity keys: no succession ----------
  await alice.click('#conv-back');
  await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await alice.locator('#identity-reset').scrollIntoViewIfNeeded(); await alice.click('#identity-reset'); await alice.click('#identity-yes');
  await until(alice, () => /New identity keys are in use/.test(document.getElementById('security-status').textContent));
  await alice.reload(); await visible(alice, '#chats');
  await until(alice, () => window.Groups?.enabled(), undefined, 60000);
  // bob reviews alice's new security code, as the banner asks.
  await openDm(bob, 'alice');
  await visible(bob, '#key-banner-review', 60000);
  await bob.click('#key-banner-review'); await visible(bob, '#safety');
  await bob.click('#safety-accept');
  await until(alice, () => Object.values(JSON.parse(localStorage.getItem(`groups-v1:${window.Groups.instance()}`) || '{}')).some(ch => ch.kind === 'dm' && ch.status === 'active'), undefined, 60000);
  await openDm(alice, 'bob');
  await say(alice, 'After my new keys'); await sees(bob, 'After my new keys', 60000);
  await say(bob, 'Reply to new keys'); await sees(alice, 'Reply to new keys', 60000);
  step('alice\'s browser kept its DM across the new keys: both ways still work');

  // ---------- bob links a second browser: it must be able to join the DM ----------
  const laptop = await person('bob-laptop', { passkey: false });
  await laptop.goto(origin); await visible(laptop, '#welcome');
  await laptop.click('#signin-link'); await visible(laptop, '#link-qr svg');
  const qrText = (await laptop.textContent('#link-code')).replace(/\s+/g, '');
  await bob.click('#conv-back').catch(() => {});
  await bob.click('#account-menu summary'); await bob.click('#account-settings');
  await visible(bob, '#device-link-new'); await bob.click('#device-link-new');
  await visible(bob, '#link-code-input'); await bob.fill('#link-code-input', qrText);
  await bob.click('#link-code-submit'); await visible(bob, '#link-confirm'); await bob.click('#link-match');
  await until(bob, () => /^Linked/.test(document.getElementById('link-status').textContent), undefined, 60000);
  await bob.click('#link-cancel'); await bob.evaluate(() => { document.getElementById('settings').open = false; });
  await visible(laptop, '#chats', 60000);
  await until(laptop, () => window.App?.accountId && localStorage.getItem(`linked-store-v1:${window.App.accountId}`), undefined, 60000);
  await laptop.waitForTimeout(5000);
  await until(laptop, () => Object.values(JSON.parse(localStorage.getItem(`groups-v1:${window.Groups.instance()}`) || '{}')).some(ch => ch.kind === 'dm' && ch.status === 'active'), undefined, 60000);
  await openDm(alice, 'bob'); await say(alice, 'To all of bob\'s devices');
  await openDm(laptop, 'alice'); await sees(laptop, 'To all of bob\'s devices', 60000);
  step('bob\'s newly linked browser joined the DM and gets alice\'s messages');
  console.log('KEY RESET E2E PASSED');
} catch (error) {
  console.error(error);
  for (const page of pages) console.error(`[${page.label}]`, JSON.stringify(await diag(page)));
  process.exitCode = 1;
} finally {
  await browser.close();
  server.kill();
  if (!process.env.DATA_DIR) rmSync(dataDir, { recursive: true, force: true });
}
