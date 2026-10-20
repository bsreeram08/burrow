// Groups and channels end to end (docs/m4-groups.md): accounts in Chromium on the standard core, over MLS through the
// real delivery service. A group of three: messages with sender names, reactions with who reacted, an edit, read
// receipts ("Read by everyone"), typing, an encrypted attachment, an @mention with autocomplete and highlighting;
// a fourth member who can't read what came before; a removed member who stops receiving; a public channel found in
// the directory and joined; and a commit that loses a race (409), catches up and is retried.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/groups.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3141), origin = `http://localhost:${port}`;
const dataDir = process.env.DATA_DIR || mkdtempSync(join(tmpdir(), 'groups-e2e-'));
const shots = process.env.SCREENSHOT_DIR;
// Each browser is its own address (as real devices are), so per-source rate limits see four people, not one.
const env = { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, DATA_DIR: dataDir, TRUST_PROXY: 'true' };
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { cwd: root, env, stdio: ['ignore', 'pipe', 'inherit'] });
process.on('exit', () => server.kill());
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(1));
await new Promise((ok, fail) => { server.stdout.on('data', chunk => String(chunk).includes('listening') && ok()); server.on('exit', code => fail(new Error(`server exited ${code}`))); setTimeout(() => fail(new Error('server did not start')), 10000); });
const browser = await playwright.chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE });
const step = name => console.log(`✓ ${name}`);
const pages = [];
const TIMEOUT = 30000; // The machine running this may be busy: MLS work happens in a worker per account.
const shot = async (page, name) => { if (shots) { await page.waitForTimeout(300); await page.screenshot({ path: join(shots, `groups-${name}.png`) }); } };
const visible = (page, selector, timeout = TIMEOUT) => page.locator(selector).first().waitFor({ state: 'visible', timeout });
const until = (page, fn, arg, timeout = TIMEOUT) => page.waitForFunction(fn, arg, { timeout });
const serverBytes = () => {
  const all = [];
  const walk = dir => { for (const entry of readdirSync(dir, { withFileTypes: true })) { const path = join(dir, entry.name); if (entry.isDirectory()) walk(path); else if (entry.isFile() && statSync(path).size < 64 * 1024 * 1024) all.push(readFileSync(path)); } };
  walk(dataDir); return Buffer.concat(all).toString('latin1');
};

let addresses = 0;
async function person(name) {
  const context = await browser.newContext({ viewport: { width: 1100, height: 860 }, extraHTTPHeaders: { 'X-Real-IP': `10.9.0.${++addresses}` } });
  const page = await context.newPage(); pages.push(page); page.label = name;
  page.on('pageerror', error => { console.error(`[${name}] pageerror`, error); throw error; });
  page.on('console', message => { if (message.type() === 'error' && !/Failed to load resource/.test(message.text())) console.log(`[${name} console] ${message.text()}`); });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
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
async function befriend(a, b, username) {
  await a.fill('#contact-input', username); await a.click('#contact-add');
  await b.getByRole('button', { name: 'Accept' }).click({ timeout: TIMEOUT });
  await until(a, name => [...document.querySelectorAll('#contact-list .contact.mutual strong')].some(node => node.textContent === name), username);
}
const groupRow = (page, title) => page.locator('#channel-list li, #group-list li, #pinned-list li').filter({ has: page.locator('strong', { hasText: title }) }).first();
async function openGroup(page, title) {
  if (await page.locator('#conv-head').isVisible()) await page.click('#conv-back');
  await groupRow(page, title).waitFor({ state: 'visible', timeout: TIMEOUT });
  await groupRow(page, title).locator('.row-button').click();
  await visible(page, '#conv-head');
  await until(page, text => document.getElementById('conv-name').textContent.includes(text), title);
}
const message = (page, text) => page.locator('#chat-log li[data-message-id]').filter({ has: page.locator('.message-text', { hasText: text }) }).last();
async function say(page, text) {
  await page.fill('#chat-input', text);
  await page.press('#chat-input', 'Enter');
  // Sent: sequenced by the delivery service (not just saved on this device).
  await until(page, async text => (await window.ChatStore.list()).some(record => record.direction === 'outgoing' && record.text === text && record.status !== 'queued'), text);
}
const sees = (page, text) => message(page, text).waitFor({ state: 'visible', timeout: TIMEOUT });
const ready = page => until(page, () => window.Groups?.enabled(), undefined, 60000);
const groupState = (page, id) => page.evaluate(id => window.Groups.debug(id), id);

try {
  const bootstrap = spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' });
  const firstInvite = /Invite code: (\S+)/.exec(bootstrap.stdout)?.[1];
  if (!firstInvite) throw new Error(`create-invite failed: ${bootstrap.stderr}`);
  const alice = await person('alice'), bob = await person('bob'), carol = await person('carol'), dave = await person('dave');
  await register(alice, firstInvite, 'alice');
  for (const [page, name] of [[bob, 'bob'], [carol, 'carol'], [dave, 'dave']]) await register(page, await invite(alice), name);
  await befriend(alice, bob, 'bob'); await befriend(alice, carol, 'carol'); await befriend(alice, dave, 'dave'); await befriend(bob, carol, 'carol');
  await Promise.all([alice, bob, carol, dave].map(ready));
  step('four accounts, contacts, and groups ready on every device (listed devices, KeyPackages uploaded)');

  // ---------- A group of three ----------
  await alice.click('#groups-new');
  await visible(alice, '#group-new');
  await alice.fill('#group-new-name', 'Weekend plans');
  for (const name of ['bob', 'carol']) await alice.locator('#group-new-people label', { hasText: name }).locator('input').check();
  await alice.click('#group-new-create');
  await until(alice, () => document.getElementById('group-new').hidden && document.getElementById('conv-name').textContent.includes('Weekend plans'));
  const groupId = await alice.evaluate(() => window.Groups.active());
  await openGroup(bob, 'Weekend plans'); await openGroup(carol, 'Weekend plans');
  await shot(alice, 'created');
  step('alice creates a group with bob and carol; it appears under Groups for both, named by the encrypted meta');

  await say(alice, 'Hello **group**');
  await sees(bob, 'Hello group'); await sees(carol, 'Hello group');
  if (await message(bob, 'Hello group').locator('.msg-head').textContent() !== 'alice') throw new Error('sender name missing');
  if (!await message(bob, 'Hello group').locator('strong', { hasText: 'group' }).count()) throw new Error('markdown not rendered');
  await say(bob, 'Hi from bob');
  await sees(alice, 'Hi from bob'); await sees(carol, 'Hi from bob');
  step('messages reach everyone with the sender\'s name and markdown');

  // ---------- Reactions with who reacted ----------
  await message(bob, 'Hello group').hover();
  await bob.click('#msg-actions [data-react="👍"]');
  await carol.locator('#chat-log li').filter({ hasText: 'Hello group' }).last().hover();
  await carol.click('#msg-actions [data-react="👍"]');
  const pill = message(alice, 'Hello group').locator('.reaction[data-emoji="👍"]');
  await pill.waitFor({ state: 'visible', timeout: TIMEOUT });
  await until(alice, () => /bob and carol reacted with 👍|carol and bob reacted with 👍/.test(document.querySelector('#chat-log .reaction[data-emoji="👍"]')?.title || ''));
  if (await pill.locator('.reaction-count').textContent() !== '2') throw new Error('reaction count');
  step('reactions are per person: alice sees "bob and carol reacted with 👍"');

  // ---------- Edit (↑ in the empty composer) ----------
  await bob.click('#chat-input'); await bob.press('#chat-input', 'ArrowUp');
  await until(bob, () => document.getElementById('chat-form').dataset.editing === 'true');
  await bob.fill('#chat-input', 'Hi from bob (edited)'); await bob.press('#chat-input', 'Enter');
  await sees(alice, 'Hi from bob (edited)'); await sees(carol, 'Hi from bob (edited)');
  if (!/edited/.test(await message(carol, 'Hi from bob (edited)').locator('.meta-text').textContent())) throw new Error('edited mark missing');
  step('bob edits his message; everyone sees the new text marked edited');

  // ---------- Read receipts: "Read by everyone" ----------
  await until(alice, () => [...document.querySelectorAll('#chat-log li.outgoing')].some(row => row.textContent.includes('Hello group') && row.dataset.status === 'read'));
  await message(alice, 'Hello group').hover(); await alice.click('#msg-actions [data-action="info"]');
  await visible(alice, '#receipt-info');
  const readers = await alice.locator('#receipt-read li').allTextContents();
  if (!readers.includes('bob') || !readers.includes('carol')) throw new Error(`read by: ${readers}`);
  await alice.click('#receipt-close');
  step('both read alice\'s message: two accent ticks ("Read by everyone"), and the info sheet lists who read it');

  // ---------- Typing ----------
  await carol.fill('#chat-input', 'typing something');
  await carol.locator('#chat-input').dispatchEvent('input');
  await until(alice, () => !document.getElementById('typing').hidden && document.getElementById('typing-text').textContent === 'carol is typing');
  await carol.fill('#chat-input', ''); await carol.locator('#chat-input').dispatchEvent('input');
  await until(alice, () => document.getElementById('typing').hidden);
  step('typing goes over the ephemeral channel: "carol is typing", then gone');

  // ---------- An encrypted attachment ----------
  const marker = `group-file-${randomBytes(6).toString('hex')}`, file = join(dataDir, '..', `${marker}.txt`);
  writeFileSync(file, `secret contents ${marker}`);
  await alice.setInputFiles('#attach-input', file);
  await until(bob, name => [...document.querySelectorAll('#chat-log li.incoming .file-name')].some(node => node.textContent.includes(name)), marker);
  await until(carol, name => [...document.querySelectorAll('#chat-log li.incoming .file-name')].some(node => node.textContent.includes(name)), marker);
  rmSync(file, { force: true });
  if (serverBytes().includes(marker)) throw new Error('attachment plaintext reached the server');
  step('alice sends a file: encrypted blob, key inside the MLS message; nothing readable on the server');

  // ---------- @mention with autocomplete and highlighting ----------
  await alice.click('#conv-back'); await visible(alice, '#chats');
  await carol.fill('#chat-input', 'ping @al');
  await carol.locator('#chat-input').dispatchEvent('input');
  await visible(carol, '#mention-popup');
  if (!(await carol.locator('#mention-popup li').first().textContent()).includes('@alice')) throw new Error('autocomplete');
  await carol.press('#chat-input', 'Enter');
  if (await carol.inputValue('#chat-input') !== 'ping @alice ') throw new Error(`mention not inserted: ${await carol.inputValue('#chat-input')}`);
  await carol.type('#chat-input', 'are you in?');
  await carol.press('#chat-input', 'Enter');
  await until(alice, () => document.querySelector('#group-list .mention-badge')?.textContent === '@');
  await shot(alice, 'sidebar');
  await openGroup(alice, 'Weekend plans');
  await sees(alice, 'are you in?');
  if (!await message(alice, 'are you in?').locator('.mention.mention-me', { hasText: '@alice' }).count()) throw new Error('mention not highlighted');
  if (!await message(bob, 'are you in?').locator('.mention', { hasText: '@alice' }).count()) throw new Error('mention not highlighted for bob');
  await shot(alice, 'mention');
  step('carol mentions alice through autocomplete: an @ badge in alice\'s list, highlighted for her and for bob');

  // ---------- A fourth member can't read what came before ----------
  await alice.click('#conv-menu summary'); await alice.click('#conv-info');
  await visible(alice, '#group-info');
  await alice.locator('#group-info-people label', { hasText: 'dave' }).locator('input').check();
  await alice.click('#group-info-add-button');
  await until(alice, () => /Added/.test(document.getElementById('group-info-status').textContent));
  await alice.click('#group-info-close');
  await openGroup(dave, 'Weekend plans');
  await say(alice, 'Welcome dave');
  await sees(dave, 'Welcome dave');
  const daveSees = await dave.locator('#chat-log li[data-message-id]').allTextContents();
  if (daveSees.some(text => /Hello group|Hi from bob|are you in/.test(text))) throw new Error('a new member read history from before they joined');
  await sees(bob, 'Welcome dave'); await sees(carol, 'Welcome dave');
  step('alice adds dave: he gets every message from then on and nothing from before');

  // ---------- A removed member stops receiving ----------
  await alice.click('#conv-menu summary'); await alice.click('#conv-info');
  await visible(alice, '#group-info');
  await alice.locator('#group-info-members li', { hasText: 'carol' }).getByRole('button', { name: 'Remove carol' }).click();
  await until(alice, () => ![...document.querySelectorAll('#group-info-members strong')].some(node => node.textContent.startsWith('carol')));
  await alice.click('#group-info-close');
  await until(carol, () => !document.getElementById('group-banner').hidden && /removed/.test(document.getElementById('group-banner-text').textContent));
  await say(alice, 'After carol left');
  await sees(bob, 'After carol left'); await sees(dave, 'After carol left');
  await carol.waitForTimeout(3000);
  if (await message(carol, 'After carol left').count()) throw new Error('a removed member still receives');
  if (!await carol.locator('#chat-input').isDisabled()) throw new Error('a removed member can still compose');
  step('alice removes carol: carol sees she was removed and gets nothing more');

  // ---------- A public channel, found in the directory and joined ----------
  await bob.click('#conv-back');
  await bob.click('#channels-new'); await visible(bob, '#group-new');
  await bob.fill('#group-new-name', 'general');
  await bob.locator('#group-new-visibility label', { hasText: 'Public' }).click();
  await bob.click('#group-new-create');
  await until(bob, () => document.getElementById('conv-name').textContent.includes('general'));
  await say(bob, 'First in general');
  await dave.click('#conv-back');
  await dave.click('#channels-browse'); await visible(dave, '#channel-browser');
  const entry = dave.locator('#channel-browser-list li', { hasText: '# general' });
  await entry.waitFor({ state: 'visible', timeout: TIMEOUT });
  await entry.getByRole('button', { name: 'Join general' }).click();
  await until(dave, () => document.getElementById('conv-name').textContent.includes('general'));
  if (await message(dave, 'First in general').count()) throw new Error('joined a channel and read what came before');
  await say(dave, 'dave here');
  await sees(bob, 'dave here');
  step('bob starts the public channel #general; dave finds it in Browse channels, joins (external commit) and talks');

  // ---------- A commit that loses a race: 409, catch up, rebuild, retry ----------
  // Dave adds alice to #general; just before his commit reaches the server, bob's commit (adding carol) lands.
  let raced = false; const answers = [];
  dave.on('response', response => { if (/\/api\/channels\/[^/]+\/commits$/.test(response.url())) answers.push(response.status()); });
  await dave.route('**/api/channels/*/commits', async route => {
    if (!raced) {
      raced = true;
      await bob.click('#conv-menu summary'); await bob.click('#conv-info'); await visible(bob, '#group-info');
      await bob.locator('#group-info-people label', { hasText: 'carol' }).locator('input').check();
      await bob.click('#group-info-add-button');
      await until(bob, () => /Added/.test(document.getElementById('group-info-status').textContent));
      await bob.click('#group-info-close');
    }
    await route.continue();
  });
  await dave.click('#conv-menu summary'); await dave.click('#conv-info'); await visible(dave, '#group-info');
  await dave.locator('#group-info-people label', { hasText: 'alice' }).locator('input').check();
  await dave.click('#group-info-add-button');
  await until(dave, () => /Added/.test(document.getElementById('group-info-status').textContent), undefined, 60000);
  await dave.unroute('**/api/channels/*/commits');
  if (!answers.includes(409) || answers.at(-1) !== 201) throw new Error(`commit answers: ${answers}`);
  await dave.click('#group-info-close');
  await openGroup(alice, 'general'); await openGroup(carol, 'general');
  await say(bob, 'Everyone is here');
  await sees(alice, 'Everyone is here'); await sees(carol, 'Everyone is here'); await sees(dave, 'Everyone is here');
  step(`dave's commit lost the race (answers ${answers.join(', ')}): he caught up, rebuilt it and alice got in; all four read #general`);
  await shot(dave, 'channel');

  // ---------- Leaving, and a reported commit an admin dismisses ----------
  // Dave's app is closed for a while, so the log keeps the next commit (it is trimmed once every device read it).
  const general = await bob.evaluate(() => window.Groups.active());
  await dave.goto('about:blank');
  await alice.click('#conv-menu summary'); await alice.click('#conv-leave');
  await visible(alice, '#group-leave-confirm'); await alice.click('#group-leave-yes');
  await until(alice, () => !document.getElementById('group-banner').hidden && /You left/.test(document.getElementById('group-banner-text').textContent));
  // Bob, the admin, removes her when her request arrives (MLS lets nobody remove themselves).
  await until(bob, id => !window.Groups.debug(id).members.includes('alice'), general);
  await sees(bob, 'alice left');
  step('alice leaves #general: her app asks, bob\'s app (an admin) removes her devices');

  // Carol's device rejects that commit (here: reports it by hand) and the channel freezes until an admin decides.
  const report = await carol.evaluate(async id => {
    const page = await (await fetch(`/api/channels/${id}/log?after=0`)).json();
    const entry = page.entries.filter(item => item.kind === 'commit').at(-1);
    const bytes = Uint8Array.from(atob(entry.message.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
    const response = await fetch(`/api/channels/${id}/poison`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ seq: entry.seq, digest }) });
    return { status: response.status, seq: entry.seq };
  }, general);
  if (report.status !== 202) throw new Error(`report: ${JSON.stringify(report)}`);
  // Bob's device re-checks the reported commit (it made it): it checks out, so only Dismiss is offered.
  await until(bob, () => !document.getElementById('group-dismiss').hidden && /checks out/.test(document.getElementById('group-banner-text').textContent));
  if (!await bob.locator('#group-rollback').isHidden()) throw new Error('Rollback offered for a commit that checks out');
  await shot(bob, 'frozen');
  await bob.fill('#chat-input', 'while frozen'); await bob.press('#chat-input', 'Enter');
  await bob.waitForTimeout(1500);
  if (await message(carol, 'while frozen').count()) throw new Error('a message went out while the channel was frozen');
  await bob.click('#group-dismiss');
  await until(bob, () => document.getElementById('group-banner').hidden);
  await sees(carol, 'while frozen');
  await say(bob, 'Back to normal');
  await sees(carol, 'Back to normal');
  await dave.goto(origin); await ready(dave);
  await openGroup(dave, 'general');
  await sees(dave, 'Back to normal');
  if (await message(alice, 'Back to normal').count()) throw new Error('a member who left still receives');
  step('carol reports the commit: #general freezes, bob\'s device re-checks it ("checks out", no Roll back), he dismisses it, and the queued message goes out');

  // ---------- A commit every member rejects: reported, checked, rolled back, its author's device removed ----------
  // Dave's device sends a commit whose last byte (inside the membership tag) is flipped on the way: the delivery
  // service can't check that tag, so it sequences it; every member's device rejects it as poison and reports it.
  await dave.route('**/api/channels/*/commits', async route => {
    const body = JSON.parse(route.request().postData());
    const bytes = Buffer.from(body.message, 'base64url'); bytes[bytes.length - 1] ^= 1;
    await route.continue({ postData: JSON.stringify({ ...body, message: bytes.toString('base64url') }) });
  });
  await dave.click('#conv-menu summary'); await dave.click('#conv-info'); await visible(dave, '#group-info');
  await dave.locator('#group-info-people label', { hasText: 'alice' }).locator('input').check();
  await dave.click('#group-info-add-button');
  await until(dave, () => /Added/.test(document.getElementById('group-info-status').textContent), undefined, 60000);
  await dave.unroute('**/api/channels/*/commits');
  await dave.click('#group-info-close');
  // Bob's device rejected it too, so (and only so) Roll back is offered.
  await until(bob, () => !document.getElementById('group-rollback').hidden && /rejects it too/.test(document.getElementById('group-banner-text').textContent), undefined, 60000);
  await shot(bob, 'rollback');
  const resolved = bob.waitForRequest(request => request.url().endsWith('/resolve'));
  await bob.click('#group-rollback');
  // The signed rollback names the author bob's own device authenticated: dave's device, not whoever the server says.
  const daveDevice = await dave.evaluate(async () => (await window.DeviceFormat.deviceKey(window.App.accountId)).deviceId);
  const signed = JSON.parse((await resolved).postData());
  if (signed.action !== 'rollback' || signed.author !== daveDevice) throw new Error(`rollback signed for ${signed.author}, dave is ${daveDevice}`);
  await sees(bob, 'You removed dave');
  await until(bob, id => !window.Groups.debug(id).members.includes('dave'), general);
  await until(dave, () => !document.getElementById('group-banner').hidden && /removed/.test(document.getElementById('group-banner-text').textContent));
  await say(bob, 'After the rollback');
  await sees(carol, 'After the rollback').catch(async error => { console.error('carol:', JSON.stringify(await carol.evaluate(id => ({ state: window.Groups.debug(id), banner: document.getElementById('group-banner-text').textContent, status: document.getElementById('chat-status').textContent }), general))); throw error; });
  await dave.waitForTimeout(3000);
  if (await message(dave, 'After the rollback').count()) throw new Error('the rolled-back author still receives');
  step('dave\'s corrupted commit is sequenced, then rejected by bob\'s and carol\'s devices and reported; bob\'s device confirms it fails, rolls it back, removes dave\'s device; the channel goes on without him');


  console.log('GROUPS E2E PASSED');
} catch (error) {
  console.error(error);
  for (const page of pages) console.error(`[${page.label}] chat-status:`, await page.textContent('#chat-status').catch(() => '?'), '| chats-status:', await page.textContent('#chats-status').catch(() => '?'), '| channels-empty:', await page.textContent('#channels-empty').catch(() => '?'));
  process.exitCode = 1;
} finally {
  await browser.close();
  server.kill();
  if (!process.env.DATA_DIR) rmSync(dataDir, { recursive: true, force: true });
}
