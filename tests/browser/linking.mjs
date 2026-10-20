// Linked devices and DMs on MLS end to end (docs/m5-linking.md), in Chromium against the real server:
// a 1:1 chat with history on the Double Ratchet moves to MLS with that history intact; alice links a second browser
// (QR text typed across, the 6-digit codes compared), which then shows her channel and her moved DM; the linked
// browser then takes over as primary under a new account key (contacts follow the signed record); and revoking the
// old one from it signs that out so it receives nothing more.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/linking.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3151), origin = `http://localhost:${port}`;
const dataDir = process.env.DATA_DIR || mkdtempSync(join(tmpdir(), 'linking-e2e-'));
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
const shot = async (page, name) => { if (shots) { await page.waitForTimeout(300); await page.screenshot({ path: join(shots, `linking-${name}.png`) }); } };
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

try {
  const bootstrap = spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' });
  const firstInvite = /Invite code: (\S+)/.exec(bootstrap.stdout)?.[1];
  if (!firstInvite) throw new Error(`create-invite failed: ${bootstrap.stderr}`);
  const alice = await person('alice'), bob = await person('bob');
  // The chat starts on the Double Ratchet (a loopback-only test switch), to have history before it moves.
  for (const page of [alice, bob]) await page.addInitScript(() => localStorage.setItem('dm-move-test', 'off'));
  await register(alice, firstInvite, 'alice');
  await register(bob, await invite(alice), 'bob');
  await alice.fill('#contact-input', 'bob'); await alice.click('#contact-add');
  await bob.getByRole('button', { name: 'Accept' }).click({ timeout: TIMEOUT });
  await until(alice, () => window.Groups?.enabled()); await until(bob, () => window.Groups?.enabled());
  await openDm(alice, 'bob'); await openDm(bob, 'alice');
  await say(alice, 'Before the move, on the old encryption');
  await sees(bob, 'Before the move, on the old encryption');
  await say(bob, 'Old encryption reply');
  await sees(alice, 'Old encryption reply');
  if (await moved(alice) || await moved(bob)) throw new Error('the chat moved while the test switch kept it on the Double Ratchet');
  step('alice and bob chat on the Double Ratchet first');

  // ---------- The chat moves to MLS, history intact ----------
  for (const page of [alice, bob]) await page.evaluate(() => localStorage.removeItem('dm-move-test'));
  await say(alice, 'After the move, over MLS');
  await sees(bob, 'After the move, over MLS');
  await until(alice, () => Object.keys(JSON.parse(localStorage.getItem(`dm-moved-v1:${window.App.accountId}`) || '{}')).length === 1);
  await until(bob, () => Object.keys(JSON.parse(localStorage.getItem(`dm-moved-v1:${window.App.accountId}`) || '{}')).length === 1);
  await sees(bob, 'Messages in this chat now use the new encryption');
  for (const text of ['Before the move, on the old encryption', 'Old encryption reply']) await sees(bob, text);
  await say(bob, 'Reply over MLS');
  await sees(alice, 'Reply over MLS');
  // Typing now only travels over MLS, and it works in the moved chat.
  await bob.fill('#chat-input', 'typing…'); await bob.locator('#chat-input').dispatchEvent('input');
  await until(alice, () => !document.getElementById('typing').hidden && document.getElementById('typing-text').textContent.includes('bob'));
  await bob.fill('#chat-input', ''); await bob.locator('#chat-input').dispatchEvent('input');
  const order = await bob.evaluate(async () => (await window.ChatStore.list()).filter(record => record.conversationId.length === 43).map(record => record.text));
  const expected = ['Before the move, on the old encryption', 'Old encryption reply', 'After the move, over MLS', 'Reply over MLS'];
  if (expected.some((text, index) => order.indexOf(text) < 0 || (index && order.indexOf(text) < order.indexOf(expected[index - 1])))) throw new Error(`history out of order: ${order}`);
  await shot(bob, 'moved');
  step('the chat moved to MLS: a system line, the old messages still there in order, new ones and typing over the DM group');

  // ---------- A group for the linked device to find ----------
  await alice.click('#conv-back');
  await alice.click('#channels-new'); await visible(alice, '#group-new');
  await alice.fill('#group-new-name', 'Team');
  await alice.locator('#group-new-people label', { hasText: 'bob' }).locator('input').check();
  await alice.click('#group-new-create');
  await until(alice, () => document.getElementById('conv-name').textContent.includes('Team'));
  await say(alice, 'Team kickoff');
  step('alice starts the private channel #Team with bob');

  // ---------- Link a second browser ----------
  const laptop = await person('alice-laptop', { passkey: false });
  await laptop.goto(origin);
  await visible(laptop, '#welcome');
  await laptop.click('#signin-link');
  await visible(laptop, '#link-qr svg');
  const qrText = (await laptop.textContent('#link-code')).replace(/\s+/g, '');
  if (!/^wb-link1\.[A-Za-z0-9_-]+$/.test(qrText)) throw new Error(`unexpected QR text: ${qrText}`);
  await shot(laptop, 'qr');
  await alice.click('#conv-back').catch(() => {});
  await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await visible(alice, '#device-link-new');
  await alice.click('#device-link-new');
  await visible(alice, '#link-code-input');
  await alice.fill('#link-code-input', qrText.replace(/(.{4})/g, '$1 ')); // typed in groups: spaces don't matter
  await alice.click('#link-code-submit');
  await visible(alice, '#link-confirm');
  const shownOnPrimary = await alice.textContent('#link-sas');
  await until(laptop, code => document.getElementById('link-status').textContent.includes(code), shownOnPrimary);
  if (!/^\d{3} \d{3}$/.test(shownOnPrimary)) throw new Error(`code format: ${shownOnPrimary}`);
  await shot(alice, 'compare');
  await alice.click('#link-match');
  await until(alice, () => /^Linked/.test(document.getElementById('link-status').textContent), undefined, 60000);
  await alice.click('#link-cancel');
  await alice.evaluate(() => { document.getElementById('settings').open = false; });
  step(`alice links a second browser: its code typed across, both showing ${shownOnPrimary}, the primary signs it in`);

  // The laptop reloads as a linked device: no 1:1 keys, its channel and its moved DM.
  await visible(laptop, '#chats', 60000);
  await until(laptop, () => window.App?.accountId && localStorage.getItem(`linked-store-v1:${window.App.accountId}`));
  const teamRow = laptop.locator('#channel-list li').filter({ has: laptop.locator('strong', { hasText: 'Team' }) });
  await teamRow.waitFor({ state: 'visible', timeout: 60000 });
  await until(laptop, () => [...document.querySelectorAll('#channel-list li')].some(row => row.textContent.includes('Team') && !/Join pending/.test(row.textContent)), undefined, 60000);
  await teamRow.locator('.row-button').click();
  await visible(laptop, '#conv-head');
  await bob.click('#conv-back');
  const bobTeam = bob.locator('#channel-list li').filter({ has: bob.locator('strong', { hasText: 'Team' }) });
  await bobTeam.waitFor({ state: 'visible', timeout: TIMEOUT }); await bobTeam.locator('.row-button').click();
  await visible(bob, '#conv-head');
  await say(bob, 'Welcome, laptop');
  await sees(laptop, 'Welcome, laptop', 60000);
  // Nothing from before its join came over MLS: earlier messages only arrive in the bundle, marked as such.
  const early = await laptop.evaluate(async () => (await window.ChatStore.list()).filter(record => record.text === 'Team kickoff').map(record => Boolean(record.imported)));
  if (early.some(imported => !imported)) throw new Error('a linked device received group messages from before it joined');
  if (early.length && !/from your other device/.test(await message(laptop, 'Team kickoff').locator('.meta-text').textContent())) throw new Error('imported history is not labelled');
  // The moved DM is there too, with the history the primary sent along.
  await openDm(laptop, 'bob');
  await sees(laptop, 'Before the move, on the old encryption');
  await say(laptop, 'Sent from my laptop');
  await openDm(bob, 'alice');
  await sees(bob, 'Sent from my laptop');
  await openDm(alice, 'bob');
  await sees(alice, 'Sent from my laptop');
  await shot(laptop, 'linked');
  step('the linked browser joins #Team by itself (earlier messages only as labelled history from the primary), shows the moved DM with its history, and sends in it');

  // ---------- The laptop takes over as primary (m5 §5) ----------
  const oldIdentity = await alice.evaluate(async () => (await (await fetch('/api/keys/count')).json()).identity);
  await laptop.click('#conv-back').catch(() => {});
  await laptop.click('#account-menu summary'); await laptop.click('#account-settings');
  await laptop.locator('.device-become-primary').click({ timeout: TIMEOUT });
  await visible(laptop, '#link-qr svg');
  const transferText = (await laptop.textContent('#link-code')).replace(/\s+/g, '');
  await alice.click('#conv-back').catch(() => {});
  await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await alice.locator('#device-list .device-promote').click({ timeout: TIMEOUT });
  await visible(alice, '#link-code-input');
  await alice.fill('#link-code-input', transferText);
  await alice.click('#link-code-submit');
  await visible(alice, '#link-confirm');
  const transferCode = await alice.textContent('#link-sas');
  await until(laptop, code => document.getElementById('link-status').textContent.includes(code), transferCode);
  await shot(alice, 'transfer');
  await alice.click('#link-match');
  await until(laptop, () => /now your primary/.test(document.getElementById('link-status').textContent), undefined, 60000);
  await until(alice, () => /now your primary/.test(document.getElementById('link-status').textContent), undefined, 60000);
  // Both reload: the laptop as the primary under a new account key, alice's first browser as a linked device of it.
  await alice.waitForLoadState('load'); await laptop.waitForLoadState('load');
  await visible(alice, '#chats', 60000); await visible(laptop, '#chats', 60000);
  await until(laptop, () => window.App?.accountId && !localStorage.getItem(`linked-store-v1:${window.App.accountId}`));
  await until(alice, () => window.App?.accountId && localStorage.getItem(`linked-store-v1:${window.App.accountId}`));
  const newIdentity = await laptop.evaluate(async () => (await (await fetch('/api/keys/count')).json()).identity);
  if (!newIdentity || newIdentity.sign === oldIdentity.sign) throw new Error('the account key did not move');
  const view = await laptop.evaluate(async () => (await fetch(`/api/devices/alice`)).json());
  if (view.list?.version !== 1 || view.list.devices.length !== 2 || view.succession?.length !== 1 || view.devices.find(row => row.current)?.primary !== true) throw new Error(`unexpected device view after the transfer: ${JSON.stringify({ version: view.list?.version, devices: view.list?.devices.length, succession: view.succession?.length })}`);
  // bob's pin followed the signed record: verification state kept, a soft notice instead of a review.
  await until(bob, async () => (await window.ChatStore.list()).some(record => /alice moved to a new device/.test(record.text || '')), undefined, 60000);
  // Each of alice's devices recertifies in each group: a self-update with its certificate under the new key.
  for (const page of [alice, laptop]) await until(page, () => window.Groups.enabled() && window.Groups.sections().rows.every(row => !window.Groups.debug(row.id).recertify), undefined, 60000);
  await until(bob, async () => { const id = window.Groups.sections().rows[0]?.id; const leaves = id ? await window.Groups.leaves(id) : []; return leaves.length === 3 && leaves.every(leaf => !leaf.stale); }, undefined, 30000);
  const team = async page => { await page.click('#conv-back').catch(() => {}); const row = page.locator('#channel-list li').filter({ has: page.locator('strong', { hasText: 'Team' }) }); await row.waitFor({ state: 'visible', timeout: 60000 }); await row.locator('.row-button').click(); await visible(page, '#conv-head'); };
  await team(laptop); await team(alice); await team(bob);
  await say(laptop, 'The laptop is primary now');
  await sees(bob, 'The laptop is primary now', 60000); await sees(alice, 'The laptop is primary now', 60000);
  await say(alice, 'Still here, linked');
  await sees(bob, 'Still here, linked', 60000); await sees(laptop, 'Still here, linked', 60000);
  await openDm(laptop, 'bob'); await openDm(bob, 'alice');
  await say(laptop, 'DM from the new primary');
  await sees(bob, 'DM from the new primary', 60000);
  await say(bob, 'DM back to both');
  await sees(laptop, 'DM back to both', 60000);
  await openDm(alice, 'bob'); await sees(alice, 'DM back to both', 60000);
  await shot(laptop, 'transferred');
  step(`the laptop becomes primary (both showing ${transferCode}): a new account key with a signed record, list v1 naming both, bob's pin follows with a soft notice, both devices recertify and #Team and the DM keep working both ways`);

  // ---------- Revoke the old primary from the new one ----------
  await laptop.click('#conv-back');
  await laptop.click('#account-menu summary'); await laptop.click('#account-settings');
  const aliceDevice = await alice.evaluate(() => JSON.parse(localStorage.getItem(`linked-store-v1:${window.App.accountId}`)).deviceId);
  const aliceRow = laptop.locator('#device-list .device-row[data-state="listed"]').filter({ hasNot: laptop.locator('small', { hasText: 'This browser' }) });
  await aliceRow.getByRole('button', { name: /^Revoke/ }).click({ timeout: TIMEOUT });
  await until(laptop, () => /revoked/i.test(document.getElementById('devices-status').textContent));
  await laptop.evaluate(() => { document.getElementById('settings').open = false; });
  await visible(alice, '#welcome', 30000); // its session ended
  await say(bob, 'After the old browser was revoked').catch(async () => { await openDm(bob, 'alice'); await say(bob, 'After the old browser was revoked'); });
  await openDm(laptop, 'bob');
  await sees(laptop, 'After the old browser was revoked');
  // Its leaves left both of alice's groups (#Team and the DM): gone from the MLS trees, not just from the server.
  await until(laptop, async device => {
    const bob = (await (await fetch('/api/contacts')).json()).contacts.find(contact => contact.username === 'bob');
    const groups = [window.Groups.dmChannelWith(bob.id), ...window.Groups.sections().rows.map(row => row.id)];
    if (groups.length !== 2 || groups.some(id => !id)) return false;
    for (const id of groups) if ((await window.Groups.leaves(id)).some(leaf => leaf.deviceId === device)) return false;
    return true;
  }, aliceDevice, 30000);
  const leaked = await alice.evaluate(async () => (await window.ChatStore.list()).some(record => record.text === 'After the old browser was revoked'));
  if (leaked) throw new Error('a revoked device still received messages');
  step('the new primary revokes the old browser: it is signed out at once and receives nothing more');

  console.log('LINKING E2E PASSED');
} catch (error) {
  console.error(error);
  for (const page of pages) console.error(`[${page.label}] chat-status:`, await page.textContent('#chat-status').catch(() => '?'), '| chats-status:', await page.textContent('#chats-status').catch(() => '?'), '| link-status:', await page.textContent('#link-status').catch(() => '?'));
  process.exitCode = 1;
} finally {
  await browser.close();
  server.kill();
  if (!process.env.DATA_DIR) rmSync(dataDir, { recursive: true, force: true });
}
