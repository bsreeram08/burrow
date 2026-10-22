// The account key on every device and its encrypted backup (docs/m6-account-key.md), in Chromium against the real
// server: a QR link hands the key over; alice turns on the backup; a short-code link leaves a browser waiting until a
// wrong and then the right passphrase unlocks it; a fresh profile restores the account from the backup alone; and
// removing a device replaces the account key, which the remaining devices follow and get back by rekey while bob's
// verification is kept.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/account-key.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3161), origin = `http://localhost:${port}`;
const dataDir = process.env.DATA_DIR || mkdtempSync(join(tmpdir(), 'account-key-e2e-'));
const shots = process.env.SCREENSHOT_DIR;
const env = { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, DATA_DIR: dataDir, TRUST_PROXY: 'true', ALLOW_TEST_FLAGS: '1' };
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { cwd: root, env, stdio: ['ignore', 'pipe', 'inherit'] });
process.on('exit', () => server.kill());
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(1));
await new Promise((ok, fail) => { server.stdout.on('data', chunk => String(chunk).includes('listening') && ok()); server.on('exit', code => fail(new Error(`server exited ${code}`))); setTimeout(() => fail(new Error('server did not start')), 10000); });
const browser = await playwright.chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE });
const step = name => console.log(`✓ ${name}`);
const pages = [];
const TIMEOUT = 60000;
const shot = async (page, name) => { if (shots) { await page.waitForTimeout(300); await page.screenshot({ path: join(shots, `account-key-${name}.png`) }); } };
const visible = (page, selector, timeout = TIMEOUT) => page.locator(selector).first().waitFor({ state: 'visible', timeout });
const until = (page, fn, arg, timeout = TIMEOUT) => page.waitForFunction(fn, arg, { timeout });

let addresses = 0;
async function person(name, { passkey = true } = {}) {
  const context = await browser.newContext({ viewport: { width: 1000, height: 900 }, extraHTTPHeaders: { 'X-Real-IP': `10.9.0.${++addresses}` } });
  const page = await context.newPage(); pages.push(page); page.label = name;
  page.on('pageerror', error => { console.error(`[${name}] pageerror`, error); throw error; });
  page.on('console', message => { if (message.type() === 'error' && !/Failed to load resource/.test(message.text())) console.log(`[${name} console] ${message.text()}`); });
  if (passkey) {
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    page.authenticator = { cdp, authenticatorId };
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
const sees = (page, text, timeout = TIMEOUT) => message(page, text).waitFor({ state: 'visible', timeout }).catch(async error => {
  // Diagnose, don't retry: where the message is here, and what each group store says.
  console.log('DIAG', page.label, text, JSON.stringify(await page.evaluate(async text => ({ records: (await window.ChatStore.list()).filter(record => record.text === text).map(record => [record.direction, record.status]), rows: window.Groups.sections().rows.map(row => window.Groups.debug(row.id)), enabled: window.Groups.enabled(), chats: document.getElementById('chats-status').textContent, chat: document.getElementById('chat-status').textContent, changes: Object.entries(localStorage).filter(([key]) => key.startsWith('pin-changes-v1')).map(([, value]) => value), banner: document.getElementById('group-banner-text')?.textContent, keyBanner: document.getElementById('key-banner-text')?.textContent }), text).catch(() => '?')));
  throw error;
});
async function say(page, text) {
  await page.fill('#chat-input', text);
  await page.press('#chat-input', 'Enter');
  await until(page, async text => (await window.ChatStore.list()).some(record => record.direction === 'outgoing' && record.text === text && record.status !== 'queued'), text);
}
const settings = async page => { await page.click('#conv-back').catch(() => {}); await page.click('#account-menu summary'); await page.click('#account-settings'); await visible(page, '#device-list'); };
const closeSettings = page => page.evaluate(() => { document.getElementById('settings').open = false; });
const linkedState = page => page.evaluate(() => JSON.parse(localStorage.getItem(`linked-store-v1:${window.App.accountId}`) || 'null'));
// A restored device has no bundle, so it doesn't know a private channel's name (it lives only on devices): `named` false
// opens the account's only channel whatever it is called.
const team = async (page, named = true) => {
  await page.click('#conv-back').catch(() => {});
  const row = named ? page.locator('#channel-list li').filter({ has: page.locator('strong', { hasText: 'Team' }) }) : page.locator('#channel-list li').first();
  await row.waitFor({ state: 'visible', timeout: TIMEOUT });
  await until(page, named => [...document.querySelectorAll('#channel-list li')].some(row => (!named || row.textContent.includes('Team')) && !/Join pending/.test(row.textContent)), named);
  await row.locator('.row-button').click(); await visible(page, '#conv-head');
};
/** Links `page` (signed out) to alice from `from`: by its QR text, or by the 8-character code. */
async function link(page, from, { code = false } = {}) {
  await page.goto(origin); await visible(page, '#welcome');
  await page.click('#signin-link'); await visible(page, '#link-qr svg');
  let typed;
  if (code) {
    await page.click('#link-alt'); await visible(page, '#link-code-input');
    await page.fill('#link-code-input', 'alice'); await page.click('#link-code-submit');
    await until(page, () => !document.getElementById('link-qr-box').hidden && /^[A-Z0-9]{4} [A-Z0-9]{4}$/.test(document.getElementById('link-code').textContent));
    if (!/enter your passphrase afterwards/.test(await page.textContent('#link-hint'))) throw new Error('the short-code screen does not say the passphrase unlocks everything');
    typed = (await page.textContent('#link-code')).replace(/\s+/g, '');
  } else typed = (await page.textContent('#link-code')).replace(/\s+/g, '');
  await settings(from);
  await from.click('#device-link-new'); await visible(from, '#link-code-input');
  await from.fill('#link-code-input', typed); await from.click('#link-code-submit');
  await visible(from, '#link-confirm');
  const sas = await from.textContent('#link-sas');
  await until(page, sas => document.getElementById('link-status').textContent.includes(sas), sas);
  await from.click('#link-match');
  await until(from, () => /^Linked/.test(document.getElementById('link-status').textContent));
  await from.click('#link-cancel'); await closeSettings(from);
  await visible(page, '#chats');
  await until(page, () => window.App?.accountId && localStorage.getItem(`linked-store-v1:${window.App.accountId}`));
  return sas;
}

try {
  const bootstrap = spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' });
  const firstInvite = /Invite code: (\S+)/.exec(bootstrap.stdout)?.[1];
  if (!firstInvite) throw new Error(`create-invite failed: ${bootstrap.stderr}`);
  const alice = await person('alice'), bob = await person('bob');
  await register(alice, firstInvite, 'alice');
  await register(bob, await invite(alice), 'bob');
  await alice.fill('#contact-input', 'bob'); await alice.click('#contact-add');
  await bob.getByRole('button', { name: 'Accept' }).click({ timeout: TIMEOUT });
  await until(alice, () => window.Groups?.enabled()); await until(bob, () => window.Groups?.enabled());
  // A new identity is stored wrapped and exportable (m6 §1): the key can move.
  const exportable = await alice.evaluate(async () => {
    const id = window.App.accountId, db = await new Promise((ok, fail) => { const request = indexedDB.open(`webrtc-bun-signal-v1-${id}`, 1); request.onsuccess = () => ok(request.result); request.onerror = fail; });
    const identity = await new Promise(ok => { const request = db.transaction('kv').objectStore('kv').get('identity'); request.onsuccess = () => ok(request.result); });
    db.close();
    return ArrayBuffer.isView(identity?.sign?.wrapped) && !identity.sign.privateKey;
  });
  if (!exportable) throw new Error('a new identity is not stored wrapped');
  await alice.click('#channels-new'); await visible(alice, '#group-new');
  await alice.fill('#group-new-name', 'Team');
  await alice.locator('#group-new-people label', { hasText: 'bob' }).locator('input').check();
  await alice.click('#group-new-create');
  await until(alice, () => document.getElementById('conv-name').textContent.includes('Team'));
  await say(alice, 'Team kickoff');
  step('alice (with a wrapped, exportable account key) and bob are contacts; alice starts #Team with bob');

  // ---------- A QR link hands the account key over (§2) ----------
  const laptop = await person('alice-laptop', { passkey: false });
  const qrSas = await link(laptop, alice);
  if (!(await linkedState(laptop)).full) throw new Error('a QR-linked browser did not receive the account key');
  await settings(laptop);
  await until(laptop, () => /This browser · Can unlock your account/.test(document.getElementById('device-list').textContent));
  await closeSettings(laptop);
  await team(laptop); await sees(laptop, 'Team kickoff');
  step(`a QR link (both showing ${qrSas}) hands the account key over: the laptop can unlock the account and joins #Team`);

  // ---------- Alice turns on the backup (§3.4) ----------
  await settings(alice);
  await alice.click('#backup-on'); await visible(alice, '#backup');
  await until(alice, () => document.getElementById('backup-passphrase').textContent.split(' ').length === 6);
  const passphrase = (await alice.textContent('#backup-passphrase')).trim();
  await shot(alice, 'passphrase');
  await alice.click('#backup-next');
  await until(alice, () => document.querySelectorAll('#backup-words li').length === 24);
  const words = await alice.$$eval('#backup-words li', items => items.map(item => item.textContent));
  await shot(alice, 'words');
  await alice.click('#backup-next');
  for (const input of await alice.$$('#backup-check input')) {
    const at = Number((await input.getAttribute('id')).split('-').pop());
    await input.fill(words[at]);
  }
  await alice.click('#backup-next');
  await until(alice, () => document.getElementById('backup').hidden && /^On\./.test(document.getElementById('backup-state').textContent));
  await closeSettings(alice);
  step('alice turns on the backup: a generated 6-word passphrase, 24 recovery words shown once and three typed back');

  // ---------- A short-code link leaves the browser waiting; the passphrase unlocks it (§2, §4) ----------
  const desktop = await person('alice-desktop', { passkey: false });
  const codeSas = await link(desktop, alice, { code: true });
  if ((await linkedState(desktop)).full) throw new Error('a short-code link handed the account key over');
  await settings(desktop);
  await until(desktop, () => /This browser · Waiting for keys/.test(document.getElementById('device-list').textContent));
  await desktop.click('#device-list .device-unlock'); await visible(desktop, '#restore');
  await desktop.fill('#restore-input', 'not the passphrase at all'); await desktop.click('#restore-submit');
  await until(desktop, () => /doesn’t open your backup/.test(document.getElementById('restore-status').textContent));
  await shot(desktop, 'wrong-passphrase');
  await desktop.fill('#restore-input', passphrase); await desktop.click('#restore-submit');
  await visible(desktop, '#restore-done');
  const reloadDesktop = desktop.waitForEvent('load', { timeout: TIMEOUT });
  await desktop.click('#restore-close'); await reloadDesktop; await visible(desktop, '#chats');
  if (!(await linkedState(desktop)).full) throw new Error('the passphrase did not unlock the short-code browser');
  await settings(desktop);
  await until(desktop, () => /This browser · Can unlock your account/.test(document.getElementById('device-list').textContent));
  await closeSettings(desktop);
  step(`a short-code link (both showing ${codeSas}) leaves the browser waiting for keys; a wrong passphrase is refused, the right one unlocks it`);

  // ---------- A fresh profile restores the account from the backup alone (§4) ----------
  const phone = await person('alice-phone');
  const { credentials } = await alice.authenticator.cdp.send('WebAuthn.getCredentials', { authenticatorId: alice.authenticator.authenticatorId });
  for (const credential of credentials) await phone.authenticator.cdp.send('WebAuthn.addCredential', { authenticatorId: phone.authenticator.authenticatorId, credential });
  await phone.goto(origin); await visible(phone, '#welcome'); await phone.click('#signin'); await visible(phone, '#chats');
  await visible(phone, '#device-restore-words');
  if (!/Use your account here/.test(await phone.textContent('#device-banner-text'))) throw new Error('the restore screen is missing');
  await shot(phone, 'restore-screen');
  await phone.click('#device-restore-words'); await visible(phone, '#restore');
  // Each word may be given by its first four letters, in any case and spacing.
  await phone.fill('#restore-words', words.map((word, at) => at % 2 ? word.slice(0, 4).toUpperCase() : word).join('   '));
  await phone.click('#restore-submit');
  await visible(phone, '#restore-done');
  if (!/^\d{5}( \d{5}){11}$/.test(await phone.textContent('#restore-safety'))) throw new Error('the restore does not show the account\'s safety number');
  const reloadPhone = phone.waitForEvent('load', { timeout: TIMEOUT });
  await phone.click('#restore-close'); await reloadPhone; await visible(phone, '#chats');
  await until(phone, () => document.getElementById('device-banner').hidden);
  await team(phone, false);
  await team(bob); await say(bob, 'Hello restored phone');
  await sees(phone, 'Hello restored phone');
  step('a fresh profile signs in with the passkey and restores from the 24 words (four-letter prefixes, any case): it joins #Team without another device');

  // ---------- Removing a device replaces the key; the others follow and rekey (§5, §6.2) ----------
  const laptopId = (await linkedState(laptop)).deviceId;
  const oldKey = await alice.evaluate(async () => (await (await fetch('/api/keys/count')).json()).identity.sign);
  await settings(alice);
  await alice.locator(`#device-list .device-row[data-device-id="${laptopId}"] .device-remove`).click();
  await visible(alice, '#keychange');
  if (await alice.locator('#keychange-proof').isHidden()) throw new Error('removing a device that holds the key does not ask for the passphrase');
  await alice.fill('#keychange-pass', 'wrong wrong wrong wrong'); await alice.click('#keychange-yes');
  await until(alice, () => /isn’t your passphrase/.test(document.getElementById('keychange-status').textContent));
  await alice.fill('#keychange-pass', passphrase);
  const reloadAlice = alice.waitForEvent('load', { timeout: TIMEOUT });
  await alice.click('#keychange-yes'); await reloadAlice; await visible(alice, '#chats');
  const newKey = await alice.evaluate(async () => (await (await fetch('/api/keys/count')).json()).identity.sign);
  if (newKey === oldKey) throw new Error('removing the laptop did not replace the account key');
  await visible(laptop, '#welcome'); // its session ended
  // bob's pin follows the signed record with its verification kept.
  await until(bob, async () => (await window.ChatStore.list()).some(record => /alice updated their security key\. Verification kept\./.test(record.text || '')));
  // The desktop and the phone follow the record and get the new key back by rekey (both were in #Team with alice).
  for (const page of [desktop, phone]) await until(page, newKey => { const me = JSON.parse(localStorage.getItem(`linked-store-v1:${window.App.accountId}`) || 'null'); return me?.full && me.identity.sign === newKey; }, newKey, 90000);  await settings(phone);
  await until(phone, () => /This browser · Can unlock your account/.test(document.getElementById('device-list').textContent));
  await closeSettings(phone);
  await team(alice); await say(alice, 'After the new key');
  for (const page of [bob, desktop, phone]) { await team(page, page !== phone).catch(() => {}); await sees(page, 'After the new key'); }
  if (await laptop.evaluate(async () => (await window.ChatStore.list()).some(record => record.text === 'After the new key'))) throw new Error('the removed laptop still received messages');
  // The backup followed the key: the passphrase still opens it, now with the new key inside.
  const record = await phone.evaluate(async () => (await fetch('/api/backup')).json());
  if (record.aikSign !== newKey || record.epoch < 2) throw new Error('the backup was not re-sealed under the new key');
  step('removing the laptop needs the passphrase (a wrong one is refused), replaces the account key and re-seals the backup; bob keeps his verification; the desktop and phone follow and rekey; the laptop gets nothing more');

  // ---------- The inbox device follows a key change made elsewhere, and rekeys (§5, §6.2) ----------
  const desktopId = (await linkedState(desktop)).deviceId;
  await alice.evaluate(() => { window.__sameTab = true; }); // It must follow on the live frames, without a reload.
  await settings(phone);
  await phone.locator(`#device-list .device-row[data-device-id="${desktopId}"] .device-remove`).click();
  await visible(phone, '#keychange'); await phone.fill('#keychange-pass', passphrase);
  const reloadPhone2 = phone.waitForEvent('load', { timeout: TIMEOUT });
  await phone.click('#keychange-yes'); await reloadPhone2; await visible(phone, '#chats');
  const thirdKey = await phone.evaluate(async () => (await (await fetch('/api/keys/count')).json()).identity.sign);
  if (thirdKey === newKey) throw new Error('removing the desktop did not replace the account key');
  await visible(desktop, '#welcome');
  // alice's browser was the inbox device: it follows the record, drops the old key and gets the new one by rekey.
  await until(alice, thirdKey => { const me = JSON.parse(localStorage.getItem(`linked-store-v1:${window.App.accountId}`) || 'null'); return me?.full && me.identity.sign === thirdKey; }, thirdKey, 90000);
  if (!await alice.evaluate(() => window.__sameTab === true)) throw new Error('the inbox browser reloaded to follow the key change');
  // It names who changed the key and what was removed, and stays until dismissed (§6.2 step 3).
  await alice.click('#conv-back').catch(() => {}); await closeSettings(alice);
  await visible(alice, '#keychange-notice');
  if (!/Your account key was changed from .*, which removed .*\. If this wasn’t you, take your account back\./.test(await alice.textContent('#keychange-notice-text'))) throw new Error(`unexpected key-change notice: ${await alice.textContent('#keychange-notice-text')}`);
  await alice.click('#keychange-notice-dismiss');
  if (await alice.locator('#keychange-notice').isVisible()) throw new Error('the key-change notice did not go when dismissed');
  await team(phone, false); await say(phone, 'From the new inbox device');
  for (const page of [bob, alice]) {
    await team(page).catch(() => {});
    await sees(page, 'From the new inbox device').catch(async error => {
      // Diagnose, don't retry: where the message is on each side and what each group store says.
      for (const p of [phone, page]) console.log('DIAG', p.label, JSON.stringify(await p.evaluate(async () => ({ records: (await window.ChatStore.list()).filter(record => /From the new inbox device/.test(record.text || '')).map(record => [record.direction, record.status]), rows: window.Groups.sections().rows.map(row => window.Groups.debug(row.id)), chat: document.getElementById('chat-status').textContent, chats: document.getElementById('chats-status').textContent }))));
      throw error;
    });
  }
  step('the restored phone removes the desktop (a third key); alice\'s browser, the inbox device until then, follows the record on the live frames (no reload), shows who changed the key and what it removed until dismissed, and gets the key back by rekey');

  // ---------- A key change cut short is settled on the next start (§6.2) ----------
  // The phone links a tablet (by QR, so it holds the key), then removing the tablet is cut at PUT /api/devices/succession.
  const tablet = await person('alice-tablet', { passkey: false });
  await link(tablet, phone);
  const tabletId = (await linkedState(tablet)).deviceId;
  const served = page => page.evaluate(async () => (await (await fetch('/api/keys/count')).json()).identity.sign);
  const pendingOf = page => page.evaluate(async () => window.Core.groupStore(window.App.accountId, window.Groups.instance())({ cmd: 'rotationPending' }));
  const holds = page => page.evaluate(async () => {
    const id = window.App.accountId, db = await new Promise((ok, fail) => { const request = indexedDB.open(`webrtc-bun-signal-v1-${id}`, 1); request.onsuccess = () => ok(request.result); request.onerror = fail; });
    const identity = await new Promise(ok => { const request = db.transaction('kv').objectStore('kv').get('identity'); request.onsuccess = () => ok(request.result); });
    db.close();
    return identity?.pub?.sign;
  });
  const reload = async page => { await page.reload(); await visible(page, '#chats'); await until(page, () => window.Groups?.enabled()); };
  const tryRemoval = async (start, route) => {
    await phone.route('**/api/devices/succession', route);
    await start();
    await visible(phone, '#keychange'); await phone.fill('#keychange-pass', passphrase); await phone.click('#keychange-yes');
    await until(phone, () => document.getElementById('keychange-status').textContent && !/Changing/.test(document.getElementById('keychange-status').textContent));
    await phone.unroute('**/api/devices/succession');
  };
  // 1. The server refuses the record: the prepared key is dropped at once, and the old key stays after a reload.
  await settings(phone);
  await tryRemoval(() => phone.locator(`#device-list .device-row[data-device-id="${tabletId}"] .device-remove`).click(), route => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Refused for the test.' }) }));
  if (await pendingOf(phone)) throw new Error('a refused key change was kept');
  await reload(phone);
  if (await served(phone) !== thirdKey || await holds(phone) !== thirdKey || await pendingOf(phone)) throw new Error('a refused key change did not leave the old key in place');
  await visible(tablet, '#welcome'); // the revoke itself went through: only the key change was refused
  // 2. The record never reaches the server: kept as prepared, then dropped on the next start (the server has no record).
  await settings(phone);
  await tryRemoval(() => phone.locator(`#device-finish`).click({ timeout: TIMEOUT }), route => route.abort('connectionreset'));
  if (!await pendingOf(phone)) throw new Error('a key change whose answer never came was not kept for the next start');
  await reload(phone);
  if (await served(phone) !== thirdKey || await holds(phone) !== thirdKey || await pendingOf(phone)) throw new Error('a key change the server never got was not dropped on the next start');
  step('a key change the server refuses is dropped at once; one it never received is kept, then dropped on the next start: the old key stays');
  // 3. The server takes the record but the answer is lost and the tab reloads before the commit: the next start finishes it.
  // Backup reads are rate-limited per session: the epoch comes from the owner view, the record from alice's session.
  const backupEpoch = page => page.evaluate(async () => (await (await fetch('/api/devices/alice')).json()).backup?.epoch);
  const epochBefore = await backupEpoch(phone);
  await settings(phone);
  await tryRemoval(() => phone.locator(`#device-finish`).click({ timeout: TIMEOUT }), async route => { await route.fetch(); await route.abort('connectionreset'); });
  if (!await pendingOf(phone) || await holds(phone) !== thirdKey) throw new Error('the prepared key change was not left for the next start');
  await reload(phone);
  const fourthKey = await served(phone);
  if (fourthKey === thirdKey || await holds(phone) !== fourthKey || await pendingOf(phone)) throw new Error('the next start did not finish the accepted key change');
  const listed = await phone.evaluate(async () => (await (await fetch('/api/devices/alice')).json()).list);
  const aliceId = (await linkedState(alice)).deviceId;
  if (listed.version !== 1 || !listed.devices.some(device => device.deviceId === aliceId) || listed.devices.some(device => device.deviceId === tabletId)) throw new Error('list v1 after the resumed key change does not name the other devices');
  await until(phone, epoch => fetch('/api/devices/alice').then(response => response.json()).then(view => view.backup?.epoch === epoch), epochBefore + 1, 30000).catch(() => {});
  const resealed = await alice.evaluate(async () => (await fetch('/api/backup')).json());
  if (resealed.aikSign !== fourthKey || resealed.epoch !== epochBefore + 1) throw new Error(`the backup was not re-sealed after the resumed key change: ${JSON.stringify({ aik: resealed.aikSign === fourthKey, epoch: resealed.epoch, epochBefore, status: await phone.textContent('#chats-status') })}`);
  await until(alice, fourthKey => { const me = JSON.parse(localStorage.getItem(`linked-store-v1:${window.App.accountId}`) || 'null'); return me?.full && me.identity.sign === fourthKey; }, fourthKey, 90000);
  await team(phone, false); await say(phone, 'After the resumed key change');
  for (const page of [bob, alice]) { await team(page).catch(() => {}); await sees(page, 'After the resumed key change'); }
  step('a key change the server accepted but whose answer was lost is finished on the next start: the new key held here, list v1 naming the others, the backup re-sealed, and alice rekeyed');

  console.log('ACCOUNT KEY E2E PASSED');
} catch (error) {
  console.error(error);
  for (const page of pages) console.error(`[${page.label}] chats-status:`, await page.textContent('#chats-status').catch(() => '?'), '| devices-status:', await page.textContent('#devices-status').catch(() => '?'), '| link-status:', await page.textContent('#link-status').catch(() => '?'), '| restore-status:', await page.textContent('#restore-status').catch(() => '?'), '| keychange-status:', await page.textContent('#keychange-status').catch(() => '?'));
  process.exitCode = 1;
} finally {
  await browser.close();
  server.kill();
  if (!process.env.DATA_DIR) rmSync(dataDir, { recursive: true, force: true });
}
