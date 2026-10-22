// Cross-client proof: the real web client (account.js + signal.js in Chromium) and the Flutter app's real
// crypto path (RustChatCrypto → crates/chatcore through flutter_rust_bridge, plus the app's Messenger, store,
// API client and events socket) talk through one local server.
//
//   bun tests/cross-client/run.ts
//
// Test-only bootstrap: both accounts and their sessions are created through the in-process server's
// `accounts.testing` helpers on a throwaway DATA_DIR (no passkeys needed); nothing here is reachable in
// production. Steps are synchronised with the Dart side through files in a temp dir.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startSignaling } from '../../packages/signaling/server';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const appDir = join(root, 'apps/chat');
const sync = mkdtempSync(join(tmpdir(), 'cross-client-'));
const dataDir = join(sync, 'server');
const port = Number(process.env.TEST_PORT || 3191), origin = `http://localhost:${port}`;
let failed = false;
const step = (text: string) => console.log(`✓ ${text}`);

const build = spawnSync('cargo', ['build', '--quiet', '--manifest-path', join(appDir, 'rust/Cargo.toml')], { stdio: 'inherit' });
if (build.status !== 0) process.exit(1);
const dylib = join(appDir, 'rust/target/debug', process.platform === 'darwin' ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so');

const app = startSignaling({ adminToken: 'x'.repeat(40), origin, hostname: '127.0.0.1', port, dataDir, allowTestFlags: true });
const testing = app.accounts!.testing;
const webUser = testing.createUser('webuser'), appUser = testing.createUser('appuser'), thirdUser = testing.createUser('thirduser');
const cookie = testing.cookie(webUser.id), bearer = testing.bearer(appUser.id, 'ios');
const call = (path: string, init: RequestInit) => fetch(new URL(path, origin), init).then(async response => { if (!response.ok) throw new Error(`${path} → ${response.status} ${await response.text()}`); });
await call('/api/contacts', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: cookie }, body: JSON.stringify({ username: 'appuser' }) });
await call('/api/contacts/webuser/accept', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: '{}' });
// A third account (a web browser) that the app adds to a group and removes again.
const thirdCookie = testing.cookie(thirdUser.id);
await call('/api/contacts', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: thirdCookie }, body: JSON.stringify({ username: 'appuser' }) });
await call('/api/contacts/thirduser/accept', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: '{}' });
// A fourth account (a web browser), the web account's contact, whose chat moves to MLS after the app is linked.
const fourthUser = testing.createUser('fourthuser'), fourthCookie = testing.cookie(fourthUser.id);
await call('/api/contacts', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: fourthCookie }, body: JSON.stringify({ username: 'webuser' }) });
await call('/api/contacts/fourthuser/accept', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: cookie }, body: '{}' });
step('two accounts (web and app) are mutual contacts, and a third is the app\'s contact');

const signal = (name: string, body = '') => writeFileSync(join(sync, `web-${name}`), body);
async function waitFor(name: string, timeout = 90000) {
    const file = join(sync, `app-${name}`), end = Date.now() + timeout;
    while (!existsSync(file)) { if (Date.now() > end || failed) throw new Error(`app never reached ${name}`); await Bun.sleep(100); }
    return readFileSync(file, 'utf8');
}

const dart = spawn('flutter', ['test', 'test/cross_client_test.dart', '--reporter', 'expanded'], {
    cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, CROSS_BASE: origin, CROSS_TOKEN: bearer, CROSS_ME_ID: appUser.id, CROSS_ME_NAME: 'appuser', CROSS_PEER_ID: webUser.id, CROSS_PEER_NAME: 'webuser', CROSS_THIRD_ID: thirdUser.id, CROSS_THIRD_NAME: 'thirduser', CROSS_FOURTH_ID: fourthUser.id, CROSS_FOURTH_NAME: 'fourthuser', CROSS_DIR: sync, CROSS_DYLIB: dylib },
});
let dartOutput = '';
dart.stdout.on('data', chunk => { dartOutput += chunk; });
dart.stderr.on('data', chunk => { dartOutput += chunk; });
const dartDone = new Promise<number>(resolve => dart.on('exit', code => { if (code) failed = true; resolve(code ?? 1); }));

const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const browser = await playwright.chromium.launch();
async function webPage(as = cookie, move = false) {
    const [name, value] = as.split('=');
    const context = await browser.newContext();
    await context.addCookies([{ name, value, url: origin }]);
    // The web never moves a 1:1 chat to MLS itself here: the app is the first sender (m5 §8).
    if (!move) await context.addInitScript(() => localStorage.setItem('dm-move-test', 'off'));
    const page = await context.newPage();
    page.on('pageerror', (error: Error) => console.log(`  web pageerror: ${error.message}`));
    await page.goto(origin);
    await page.waitForSelector('#chats', { state: 'visible', timeout: 20000 });
    return { context, page };
}
const log = (page: any, text: string) => page.waitForFunction((t: string) => document.getElementById('chat-log').textContent.includes(t), text, { timeout: 45000 });

let code = 1;
try {
    // M1: the app announced its device with the published identity and now holds the account's own inbox.
    const appDevice = await waitFor('ready');
    const primary = testing.db.query("SELECT id, platform, state FROM devices WHERE user_id = ? AND is_primary = 1 AND state != 'revoked'").get(appUser.id) as any;
    if (primary?.id !== appDevice || primary.platform !== 'ios') throw new Error(`the app's device is not the account's messaging device: ${JSON.stringify(primary)}`);
    step('the app registered its device and took the account\'s per-device inbox');
    const { page } = await webPage();
    await page.click('#contact-list .contact.mutual .row-button');
    await page.fill('#chat-input', 'hello from web'); await page.click('#chat-send');
    signal('sent-1');
    await log(page, 'hello from app');
    await waitFor('sent-2');
    step('web → app and app → web messages decrypt (signal.js ↔ Rust core), with encrypted receipts');

    // Phase 1 payloads, both directions (docs/phase1-protocol.md §1–§3).
    const records = (): Promise<any[]> => page.evaluate(async () => {
        const w = window as any;
        return (await w.ChatStore.list()).filter((r: any) => r.conversationId === w.App.conversationId);
    });
    async function webUntil(what: string, check: (list: any[]) => boolean, timeout = 45000) {
        const end = Date.now() + timeout;
        while (!check(await records())) {
            if (Date.now() > end || failed) throw new Error(`web: ${what}\n${JSON.stringify((await records()).map(r => ({ d: r.direction, s: r.status, t: r.editedText ?? r.text, k: r.attachment?.kind, r: r.reactions })))}`);
            await Bun.sleep(150);
        }
        return records();
    }
    // The first row with this text: later replies also contain it, in their quote.
    const row = (text: string) => page.locator('#chat-log li[data-message-id]', { hasText: text }).first();
    async function action(text: string, selector: string) { await row(text).hover(); await page.click(`#msg-actions ${selector}`); }
    const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
    const webSha = (attachment: any): Promise<string> => page.evaluate(async (a: any) => {
        const { blob } = await (window as any).Files.open(a);
        const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
        return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
    }, attachment);

    await waitFor('read-sent');
    await webUntil('read receipt from the app', list => list.some(r => r.text === 'hello from web' && r.status === 'read'));
    step('read receipts both ways (✓✓ in accent)');

    // Web → app: reply, react 👍 and 😂 then take 😂 back, edit, an image and a file, a link preview, typing.
    await action('hello from app', '[data-action="reply"]');
    await page.fill('#chat-input', 'web reply'); await page.click('#chat-send');
    await action('hello from app', '[data-react="👍"]');
    await action('hello from app', '[data-react="😂"]');
    await webUntil('our reactions', list => list.some(r => r.text === 'hello from app' && (r.reactions?.me || []).length === 2));
    await row('hello from app').locator('.reaction[data-emoji="😂"]').click();
    await action('hello from web', '[data-action="edit"]');
    await page.fill('#chat-input', 'hello from web, edited'); await page.click('#chat-send');
    const png = readFileSync(join(root, 'packages/signaling/public/icon-192.png'));
    const file = new Uint8Array(50000).map((_, i) => (i * 17 + 3) % 256);
    await page.setInputFiles('#attach-input', [
        { name: 'web.png', mimeType: 'image/png', buffer: png },
        { name: 'web-notes.bin', mimeType: 'application/octet-stream', buffer: Buffer.from(file) },
    ]);
    await webUntil('both uploads sent', list => list.filter(r => r.attachment && r.status !== 'queued').length === 2, 90000);
    await page.evaluate(async () => {
        const w = window as any;
        await w.ChatStore.put({
            id: crypto.randomUUID(), conversationId: w.App.conversationId, direction: 'outgoing', text: 'see https://example.com/web',
            createdAt: Date.now(), status: 'queued', expiresAt: null, link: { url: 'https://example.com/web', title: 'Web link', site: 'example.com' },
        });
        w.App.onQueued();
    });
    await page.fill('#chat-input', 'typing something');
    signal('web-rich', JSON.stringify({ image: sha(png), file: sha(file) }));
    await waitFor('web-rich-ok');
    await page.fill('#chat-input', '');
    step('web → app: reply, reactions on/off, edit, image + file (byte-identical) and a link preview arrive in the app (1:1 typing is gone: m5 §9)');

    // App → web: the same set.
    const fromApp = JSON.parse(await waitFor('app-rich'));
    const list = await webUntil('rich messages from the app', l =>
        l.some(r => r.text === 'app reply' && r.replyTo?.id === fromApp.target) &&
        l.some(r => r.id === fromApp.target && (r.reactions?.peer || []).join() === '❤️') &&
        l.some(r => r.id === fromApp.ours && r.editedText === 'hello from app, edited' && r.editedAt) &&
        l.some(r => r.direction === 'incoming' && r.attachment?.kind === 'image') && l.some(r => r.direction === 'incoming' && r.attachment?.kind === 'file') &&
        l.some(r => r.link?.url === 'https://example.com/app' && r.link?.title === 'App link'));
    for (const kind of ['image', 'file']) {
        const got = await webSha(list.find(r => r.direction === 'incoming' && r.attachment?.kind === kind).attachment);
        if (got !== fromApp[kind]) throw new Error(`${kind} from the app decrypted to different bytes on the web`);
    }
    // The app's photo decrypts and draws on the web.
    await page.waitForFunction(() => [...document.querySelectorAll('#chat-log img.media-full')].some(i => (i as HTMLImageElement).alt === 'app.png' && (i as HTMLImageElement).naturalWidth === 64), null, { timeout: 20000 });
    signal('app-rich-ok');
    step('app → web: reply, reactions on/off, edit, image + file (byte-identical) and a link preview arrive on the web');

    const appNumber = await waitFor('safety');
    await page.click('#conv-menu summary'); await page.click('#conv-safety');
    await page.waitForSelector('#safety', { state: 'visible' });
    const webNumber = (await page.textContent('#safety-number'))!.trim();
    await page.click('#safety-close');
    signal('safety-checked', webNumber === appNumber.trim() ? 'match' : 'mismatch');
    if (webNumber !== appNumber.trim()) throw new Error(`safety numbers differ: web ${webNumber} vs app ${appNumber}`);
    // By now the web published its signed device list v1, and the app verified it (Dart side, before 'safety').
    if (!testing.db.query('SELECT version FROM device_lists WHERE user_id = ?').get(webUser.id)) throw new Error('the web client never published its device list');
    step('the app verified and pinned the web account\'s signed device list');
    step(`safety numbers match on both clients (${webNumber.slice(0, 11)}…)`);

    await waitFor('reset-1');
    await log(page, 'Secure session reset by appuser'); await log(page, 'after app reset');
    step('a session reset started in the app is applied by the web client; messaging continues');

    await page.click('#conv-menu summary'); await page.click('#conv-rotate');
    await page.waitForSelector('#rotate-confirm', { state: 'visible' }); await page.click('#rotate-yes');
    await log(page, 'Secure session reset by you');
    await page.fill('#chat-input', 'after web reset'); await page.click('#chat-send');
    signal('reset-2');
    await waitFor('reset-2-ok');
    await log(page, 'reply on the new keys');
    step('a session reset started on the web is applied by the app (Rust core); messaging continues');

    // A second browser for the web account has no keys: it stays inactive and must not consume envelopes.
    const second = await webPage();
    await second.page.waitForFunction(() => !document.getElementById('device-banner').hidden, null, { timeout: 20000 });
    signal('second-device');
    await waitFor('sent-3');
    await log(page, 'for the active web device');
    const consumed = await second.page.evaluate(() => document.getElementById('chat-log')?.textContent?.includes('for the active web device') ?? false);
    if (consumed) throw new Error('the inactive device showed a message meant for the active one');
    await second.context.close();
    step('active-device rule: a second, inactive web browser leaves the app\'s message for the active one');

    await page.click('#conv-menu summary'); await page.click('#conv-burn');
    await page.waitForSelector('#burn-confirm', { state: 'visible' }); await page.click('#burn-confirm-yes');
    signal('burned');
    step('burn from the web deletes the conversation in the app');

    // Groups over MLS (docs/m4-groups.md): the web and the app in one group, both ways, plus add/remove.
    const groupsReady = (p: any) => p.waitForFunction(() => (window as any).Groups?.enabled(), null, { timeout: 90000 });
    await waitFor('groups-ready', 120000);
    if (!testing.db.query("SELECT 1 FROM devices WHERE user_id = ? AND state = 'listed'").get(appUser.id)) throw new Error('the app\'s device is not listed');
    // The server accepted the app's signed list (chatcore sign_device_list), with its label sealed like the web's.
    const appList = testing.db.query('SELECT list, aik_sign FROM device_lists WHERE user_id = ?').get(appUser.id) as any;
    const appEntry = JSON.parse(appList?.list ?? '{"devices":[]}').devices.find((entry: any) => entry.deviceId === appDevice);
    if (!appEntry || !/^[A-Za-z0-9_-]{38,}$/.test(appEntry.meta)) throw new Error(`the app's list doesn't name its device with a sealed label: ${appList?.list}`);
    await groupsReady(page);
    step('the server accepted the app\'s signed device list (sealed label, chatcore-signed); KeyPackages uploaded; groups are on in both clients');
    if (await page.locator('#conv-head').isVisible()) await page.click('#conv-back');
    // A private channel: a group needs two other people, and the web and the app are each other's only contact.
    await page.click('#channels-new');
    await page.waitForSelector('#group-new', { state: 'visible' });
    await page.fill('#group-new-name', 'Cross team');
    await page.locator('#group-new-people label', { hasText: 'appuser' }).locator('input').check();
    await page.click('#group-new-create');
    await page.waitForFunction(() => document.getElementById('group-new')!.hidden && document.getElementById('conv-name')!.textContent!.includes('Cross team'), null, { timeout: 90000 })
        .catch(async (error: Error) => { throw new Error(`${error.message}\nweb: ${await page.textContent('#group-new-status')}`); });
    const groupId: string = await page.evaluate(() => (window as any).Groups.active());
    signal('group-created', groupId);
    const groupRecords = (p: any = page): Promise<any[]> => p.evaluate(async (id: string) => (await (window as any).ChatStore.list()).filter((r: any) => r.conversationId === id), groupId);
    async function groupUntil(what: string, check: (list: any[]) => boolean, p: any = page, timeout = 90000) {
        const end = Date.now() + timeout;
        while (!check(await groupRecords(p))) {
            if (Date.now() > end || failed) throw new Error(`web: ${what}\n${JSON.stringify((await groupRecords(p)).map(r => ({ d: r.direction, s: r.status, f: r.fromName, t: r.editedText ?? r.text, k: r.attachment?.kind, r: r.reactions })))}`);
            await Bun.sleep(200);
        }
        return groupRecords(p);
    }
    step('the web creates the private channel "Cross team" with the app (the name travels only in the encrypted meta)');

    // Web → app: an @mention and an image.
    await page.fill('#chat-input', 'hello group from web @appuser and all');
    await page.click('#chat-send');
    await groupUntil('mention sent', list => list.some(r => r.direction === 'outgoing' && r.text.startsWith('hello group from web') && r.status !== 'queued'));
    const groupPng = readFileSync(join(root, 'packages/signaling/public/icon-512.png'));
    await page.setInputFiles('#attach-input', [{ name: 'group.png', mimeType: 'image/png', buffer: groupPng }]);
    await groupUntil('image sent', list => list.some(r => r.direction === 'outgoing' && r.attachment?.kind === 'image' && r.status !== 'queued'));
    signal('group-web-sent', JSON.stringify({ image: sha(groupPng) }));

    // App → web: its reaction on our message, its text, its file.
    const fromAppGroup = JSON.parse(await waitFor('group-app-sent', 120000));
    const groupList = await groupUntil('the app\'s group messages', l =>
        l.some(r => r.id === fromAppGroup.id && r.from === appUser.id && r.fromName === 'appuser') &&
        l.some(r => r.direction === 'incoming' && r.attachment?.kind === 'file') &&
        l.some(r => r.text?.startsWith('hello group from web') && (r.reactions?.[appUser.id] || []).includes('👍')));
    if (await webSha(groupList.find(r => r.direction === 'incoming' && r.attachment?.kind === 'file').attachment) !== fromAppGroup.file) throw new Error('the app\'s group file decrypted to different bytes on the web');
    const appRow = page.locator('#chat-log li[data-message-id]', { hasText: 'hello group from app' }).first();
    await appRow.hover(); await page.click('#msg-actions [data-react="😂"]');
    await groupUntil('our reaction', l => l.some(r => r.id === fromAppGroup.id && (r.reactions?.me || []).includes('😂')));
    signal('group-web-reacted');
    step('in the group both ways: text with @mention, an image and a file (byte-identical), and reactions by person');

    // The app's own private channel: the web joins from the app's Welcome and learns the name from its meta.
    const appGroupId = await waitFor('app-group', 120000);
    await page.waitForFunction((id: string) => (window as any).Groups.debug(id)?.members.includes('appuser'), appGroupId, { timeout: 90000 });
    await page.waitForFunction(() => [...document.querySelectorAll('#channel-list li strong, #pinned-list li strong')].some(node => node.textContent!.includes('App team')), null, { timeout: 90000 });
    signal('app-group-joined');
    step('the app creates the private channel "App team" with the web, which joins from the app\'s Welcome');

    // The app adds a third person and removes them again.
    const { page: thirdPage } = await webPage(thirdCookie);
    await groupsReady(thirdPage);
    // Its KeyPackages are on the server before the app claims one.
    for (const end = Date.now() + 90000; !(testing.db.query('SELECT COUNT(*) AS n FROM mls_key_packages WHERE user_id = ?').get(thirdUser.id) as any)?.n;) {
        if (Date.now() > end) throw new Error('the third account never uploaded KeyPackages');
        await Bun.sleep(200);
    }
    signal('third-ready');
    await waitFor('group-added', 120000);
    const thirdRecords = (): Promise<any[]> => thirdPage.evaluate(async (id: string) => (await (window as any).ChatStore.list()).filter((r: any) => r.conversationId === id), appGroupId);
    for (const end = Date.now() + 90000; !(await thirdRecords()).some(r => r.text === 'welcome third');) {
        if (Date.now() > end || failed) throw new Error(`third: never read "welcome third": ${JSON.stringify((await thirdRecords()).map(r => r.text))}`);
        await Bun.sleep(200);
    }
    await page.waitForFunction((id: string) => (window as any).Groups.debug(id)?.members.includes('thirduser'), appGroupId, { timeout: 90000 });
    signal('group-third-ok');
    await waitFor('group-removed', 120000);
    await page.waitForFunction((id: string) => !(window as any).Groups.debug(id)?.members.includes('thirduser'), appGroupId, { timeout: 90000 });
    signal('group-removal-seen');

    // M5 linking (docs/m5-linking.md §1): a fresh browser becomes a linked device of the app's account.
    const laptopContext = await browser.newContext();
    const laptop = await laptopContext.newPage();
    laptop.on('pageerror', (error: Error) => console.log(`  laptop pageerror: ${error.message}`));
    await laptop.goto(origin);
    await laptop.waitForSelector('#welcome', { state: 'visible', timeout: 20000 });
    await laptop.click('#signin-link');
    await laptop.waitForSelector('#link-qr svg', { state: 'visible', timeout: 30000 });
    signal('web-link-qr', (await laptop.textContent('#link-code'))!.replace(/\s+/g, ''));
    const appCode = await waitFor('app-link-code', 120000);
    await laptop.waitForFunction((code: string) => document.getElementById('link-status')!.textContent!.includes(code), appCode, { timeout: 60000 });
    signal('web-link-code-ok');
    const laptopDevice = await waitFor('app-link-approved', 120000);
    await laptop.waitForSelector('#chats', { state: 'visible', timeout: 90000 });
    const listed = testing.db.query("SELECT state FROM devices WHERE id = ? AND user_id = ?").get(laptopDevice, appUser.id) as any;
    if (listed?.state !== 'listed') throw new Error(`the linked browser is not a listed device of the app's account: ${JSON.stringify(listed)}`);
    // It joins the app's private channel by itself (external join), then reads what comes next.
    const inChannel = () => testing.db.query('SELECT 1 FROM channel_members WHERE channel_id = ? AND device_id = ?').get(appGroupId, laptopDevice);
    for (const end = Date.now() + 120000; !inChannel();) {
        if (Date.now() > end || failed) {
            const state = await laptop.evaluate((id: string) => ({ group: (window as any).Groups?.debug(id), status: document.getElementById('chats-status')?.textContent, enabled: (window as any).Groups?.enabled() }), appGroupId).catch(error => String(error));
            throw new Error(`the linked browser never joined the app's channel: ${JSON.stringify(state)}`);
        }
        await Bun.sleep(300);
    }
    // M6 §2: the QR grant carried the account key, so the browser can unlock the account by itself.
    await laptop.click('#account-menu summary'); await laptop.click('#account-settings');
    await laptop.waitForFunction(() => [...document.querySelectorAll('#device-list .device-row')].some(row => row.textContent!.includes('This browser') && row.textContent!.includes('Can unlock your account')), null, { timeout: 60000 })
        .catch(async (error: Error) => { throw new Error(`${error.message}\nlaptop devices: ${await laptop.textContent('#device-list')}`); });
    await laptop.click('#account-menu summary').catch(() => {});
    step('the app links a fresh browser as a device of its account: QR text across, the same 6 digits on both, list + MLS certificate + sealed grant carrying the account key (the browser can unlock the account); the browser joins the channel by itself');
    signal('laptop-ready');
    await waitFor('app-sent-laptop', 120000);
    const laptopRecords = (): Promise<any[]> => laptop.evaluate(async (id: string) => (await (window as any).ChatStore.list()).filter((r: any) => r.conversationId === id), appGroupId);
    for (const end = Date.now() + 90000; !(await laptopRecords()).some(r => r.text === 'hello laptop');) { if (Date.now() > end || failed) throw new Error(`laptop never read the app's message: ${JSON.stringify((await laptopRecords()).map(r => r.text))}`); await Bun.sleep(300); }
    step('the linked browser reads the app\'s next channel message');
    signal('laptop-read');

    // Revocation (§4): the app revokes it; the browser is signed out, its leaf leaves the channel, and it reads nothing more.
    await waitFor('app-revoked', 150000);
    await laptop.waitForSelector('#welcome', { state: 'visible', timeout: 60000 });
    if (inChannel()) throw new Error('the revoked browser is still in the channel');
    if (testing.db.query("SELECT state FROM devices WHERE id = ?").get(laptopDevice) && (testing.db.query("SELECT state FROM devices WHERE id = ?").get(laptopDevice) as any).state !== 'revoked') throw new Error('the browser is not revoked');
    if ((await laptopRecords().catch(() => [])).some(r => r.text === 'after revoking the laptop')) throw new Error('a revoked device received a message');
    step('the app revokes the browser: signed out at once, its leaf removed from the channel, nothing more delivered');
    signal('revoke-seen');
    await laptopContext.close();

    // m5 §8: the 1:1 chat moves to MLS. The web keeps the Double Ratchet (dm-move-test), so the app is the first sender.
    if (await page.locator('#conv-head').isVisible()) await page.click('#conv-back');
    await page.click('#contact-list .contact.mutual .row-button');
    await page.fill('#chat-input', 'before the move'); await page.click('#chat-send');
    await webUntil('sent before the move', list => list.some(r => r.text === 'before the move' && r.status !== 'queued'));
    signal('dm-before');
    const dmChannel = await waitFor('dm-moved', 150000);
    if ((testing.db.query('SELECT kind FROM channels WHERE id = ?').get(dmChannel) as any)?.kind !== 'dm') throw new Error('the app did not make a DM channel');
    await webUntil('the pointer note and the app message via MLS', list => list.some(r => r.text === 'first via mls') && list.some(r => r.text?.includes('now use the new encryption')), 90000);
    await page.waitForFunction(([key, channel]: string[]) => (localStorage.getItem(key) || '').includes(channel), [`dm-moved-v1:${webUser.id}`, dmChannel], { timeout: 90000 })
        .catch(async (error: Error) => { throw new Error(`${error.message}\nweb never accepted the pointer: ${JSON.stringify(await page.evaluate((id: string) => (window as any).Groups.debug(id), dmChannel))}`); });
    // The app checks the reply came through the DM group (its log is trimmed once everyone has read it).
    await page.fill('#chat-input', 'reply via mls'); await page.click('#chat-send');
    await webUntil('reply sent', list => list.some(r => r.text === 'reply via mls' && r.status !== 'queued'));
    signal('dm-replied');
    await waitFor('dm-typing-ready');
    await page.fill('#chat-input', 'typing in the moved chat');
    await waitFor('dm-ok', 120000);
    await page.fill('#chat-input', '');
    step('a 1:1 chat moves to MLS: the app (first sender) makes the DM group and sends the pointer over the Double Ratchet; the web checks and accepts it; history stays, and replies, read receipts and typing use the group');

    // The app as a linked device of the web account: the web, its primary, takes the app's QR text.
    const linkQr = await waitFor('app-link-qr', 120000);
    if (await page.locator('#conv-head').isVisible()) await page.click('#conv-back');
    await page.click('#account-menu summary'); await page.click('#account-settings');
    await page.click('#device-link-new');
    await page.fill('#link-code-input', linkQr); await page.click('#link-code-submit');
    await page.waitForSelector('#link-match', { state: 'visible', timeout: 90000 })
        .catch(async (error: Error) => { throw new Error(`${error.message}\nweb link status: ${await page.textContent('#link-status')}`); });
    const appSas = await waitFor('app-link-sas', 120000);
    const webSas = (await page.textContent('#link-sas'))!.replace(/\s+/g, '');
    if (webSas !== appSas.replace(/\s+/g, '')) throw new Error(`the codes differ: web ${webSas}, app ${appSas}`);
    await page.click('#link-match');
    await page.waitForFunction(() => document.getElementById('link-status')!.textContent!.startsWith('Linked'), null, { timeout: 90000 });
    step('the web links the app as a device of its account: QR text across, the same 6 digits, list + MLS certificate + sealed grant carrying the account key; the app checks it and its Rust core holds the key');
    await waitFor('app-linked-sent', 180000);
    await page.click('#link-cancel').catch(() => {});
    await page.waitForFunction(() => (window as any).ChatStore.list().then((all: any[]) => all.some(r => r.text === 'from the linked app' && r.direction === 'outgoing')), null, { timeout: 90000 });
    signal('linked-seen');
    step('not the inbox device, the linked app joins the web account\'s channels by itself (named from the bundle) and sends in the moved DM through its group; the web stores it as its own');

    // A chat that moves after the link (production: a QR-linked phone could only queue). The contact's browser moves
    // it; the pointer reaches the web, the inbox device, only. The app joins the DM by its Welcome, reads, and sends.
    await waitFor('app-fourth-queued', 60000);
    const fourth = await webPage(fourthCookie, true);
    await fourth.page.click('#contact-list .contact.mutual .row-button');
    await fourth.page.fill('#chat-input', 'fourth to webuser'); await fourth.page.click('#chat-send');
    const fourthRecords = () => fourth.page.evaluate(() => (window as any).ChatStore.list());
    for (const end = Date.now() + 120000; !(await fourthRecords()).some((r: any) => r.text === 'linked app to fourth' && r.direction === 'incoming');) {
        if (Date.now() > end || failed) throw new Error(`fourth never got the linked app's message: ${JSON.stringify((await fourthRecords()).map((r: any) => ({ d: r.direction, s: r.status, t: r.text })))}`);
        await Bun.sleep(200);
    }
    await page.waitForFunction(() => (window as any).ChatStore.list().then((all: any[]) => all.some(r => r.text === 'linked app to fourth' && r.direction === 'outgoing')), null, { timeout: 90000 });
    await waitFor('app-fourth-read', 90000);
    await fourth.context.close();
    signal('fourth-seen');
    step('a chat the contact moves after the link: the linked app (holding the key, not the inbox) joins the DM by its Welcome, reads it, and its queued 1:1 message reaches the contact; the web stores it as its own');

    // M6 §3-§4: the web turns on account backup; the app, signed in on a new device of that account, restores it.
    const webKey = (testing.db.query('SELECT sign FROM identity_keys WHERE user_id = ?').get(webUser.id) as any)?.sign;
    if (!await page.locator('#backup-on').isVisible()) { await page.click('#account-menu summary'); await page.click('#account-settings'); }
    await page.click('#backup-on', { timeout: 60000 });
    await page.click('#backup-own');
    const passphrase = 'cross client backup passphrase';
    await page.fill('#backup-pass1', passphrase); await page.fill('#backup-pass2', passphrase);
    await page.click('#backup-next');
    await page.waitForFunction(() => document.querySelectorAll('#backup-words li').length === 24, null, { timeout: 90000 })
        .catch(async (error: Error) => { throw new Error(`${error.message}\nweb backup status: ${await page.textContent('#account-backup-status')}`); });
    const words: string[] = await page.$$eval('#backup-words li', items => items.map(item => item.textContent!.trim()));
    await page.click('#backup-next');
    const asked: string[] = await page.$$eval('#backup-check input', inputs => inputs.map(input => input.id));
    for (const id of asked) await page.fill(`#${id}`, words[Number(id.split('-').pop())]!);
    await page.click('#backup-next');
    await page.waitForFunction(() => document.getElementById('backup')!.hidden && document.getElementById('backup-state')!.textContent!.startsWith('On.'), null, { timeout: 90000 })
        .catch(async (error: Error) => { throw new Error(`${error.message}\nweb backup status: ${await page.textContent('#account-backup-status')}`); });
    step('the web turns on account backup: its own passphrase, 24 recovery words shown once, three typed back');
    signal('web-backup-on', JSON.stringify({ passphrase, token: testing.bearer(webUser.id, 'macos') }));
    const restoredDevice = await waitFor('app-restored', 180000);
    const restoredRow = testing.db.query('SELECT state FROM devices WHERE id = ? AND user_id = ?').get(restoredDevice, webUser.id) as any;
    if (restoredRow?.state !== 'listed') throw new Error(`the restored app is not a listed device of the web account: ${JSON.stringify(restoredRow)}`);
    if ((testing.db.query('SELECT sign FROM identity_keys WHERE user_id = ?').get(webUser.id) as any)?.sign !== webKey) throw new Error('the account key changed: contacts would have to re-verify');
    step('the app restores the web\'s backup on a new device: a wrong passphrase opens nothing, the right one gives it the same account key, and it lists itself');
    signal('restore-seen');

    // M6 §6.2-§6.3: the restored app removes the other app device (with the backup proof) and changes the account key;
    // the web follows the signed chain and gets the new key from the app (rekey).
    const rotatedSign = await waitFor('app-rotated', 300000);
    if ((testing.db.query('SELECT sign FROM identity_keys WHERE user_id = ?').get(webUser.id) as any)?.sign !== rotatedSign) throw new Error('the server does not serve the rotated key');
    if (rotatedSign === webKey) throw new Error('the account key did not change');
    const rekeyed = () => page.evaluate(() => [...document.querySelectorAll('#device-list .device-row')].some(row => row.textContent!.includes('This browser') && row.textContent!.includes('Can unlock your account'))).catch(() => false);
    for (const end = Date.now() + 150000; !await rekeyed();) {
        if (Date.now() > end || failed) {
            const seen = await page.evaluate(async (name: string) => {
                const view = await (await fetch(`/api/devices/${name}`, { cache: 'no-store' })).json();
                const pins = JSON.parse(localStorage.getItem(Object.keys(localStorage).find(key => key.startsWith('device-pins-v1:')) || '') || 'null');
                return { identity: view.identity?.sign, listVersion: view.list?.version, listed: view.list?.devices.map((d: any) => d.deviceId), rows: view.devices?.map((r: any) => `${r.id}:${r.state}${r.primary ? '*' : ''}${r.current ? '(me)' : ''}`), succession: view.succession?.length, pinned: pins };
            }, 'webuser').catch(error => String(error));
            throw new Error(`the web was never rekeyed: ${await page.textContent('#device-list').catch(() => '')} / ${await page.textContent('#devices-status').catch(() => '')}\nweb sees: ${JSON.stringify(seen)}`);
        }
        if (!await page.locator('#device-list').isVisible().catch(() => false)) { await page.click('#account-menu summary').catch(() => {}); await page.click('#account-settings').catch(() => {}); }
        await Bun.sleep(1000);
    }
    signal('web-rekeyed');
    await waitFor('removed-checked', 120000);
    step('removing a device that holds the key changes it: the app proves the passphrase, revokes it and rotates (list v1 without it, backup re-sealed); the web follows the chain and the app rekeys it; the removed device can publish nothing');
    await waitFor('done');
    step('the app adds thirduser (who reads from then on) and removes them; the web sees both');
    code = await dartDone;
    if (code !== 0) throw new Error('the app side failed');
    console.log('Cross-client check passed.');
} catch (error) {
    failed = true;
    console.log(`✗ ${(error as Error).message}`);
    dart.kill();
    await dartDone;
    console.log(dartOutput.split('\n').slice(-40).join('\n'));
    code = 1;
} finally {
    await browser.close();
    await app.stop();
    rmSync(sync, { recursive: true, force: true });
}
process.exit(code);
