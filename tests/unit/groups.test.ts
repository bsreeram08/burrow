import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { IDBFactory, IDBKeyRange } from 'fake-indexeddb';

// groups.js (docs/m4-groups.md) against a scripted core and server: the rules the review asked for, which the
// end-to-end test can't provoke (a hostile frame, a lying log, a reported commit that checks out, a stray
// remove-needed, a changed code of someone met in a group).
const read = (name: string) => readFileSync(new URL(`../../packages/signaling/public/${name}`, import.meta.url), 'utf8');
const sources = [read('chat-store.js'), read('groups.js')];
const G = 'g'.repeat(22), ME = 'M'.repeat(22), BOB = 'B'.repeat(22), DEV = 'D'.repeat(22), BOB_DEV = 'E'.repeat(22);
const coded = (code: string | null, message: string) => Object.assign(new Error(message), { code });
const b64 = (text: string) => Buffer.from(text).toString('base64url');
const sha = (text: string) => createHash('sha256').update(text).digest('hex');

type Cmd = { cmd: string; [key: string]: any };
function world(options: { log?: (after: number) => any[]; frozen?: { seq: number; digest: string } } = {}) {
  const calls: Cmd[] = [], requests: { method: string; path: string; body: any }[] = [];
  let peer: any = { identity: { dh: 'dh1', sign: 'sign1' }, verified: false, changed: false, blocked: false };
  const handlers: Record<string, (command: Cmd) => any> = {
    mlsDeviceLeaf: () => 'leaf', mlsSetDeviceCert: () => ({}), mlsKeyPackages: command => Array(command.count).fill('kp'),
    peer: () => peer, notePeer: command => { const changed = peer && (peer.identity.dh !== command.identity.dh || peer.identity.sign !== command.identity.sign); peer = { identity: command.identity, verified: false, changed, blocked: changed }; return peer; },
    acceptChange: () => { peer = { ...peer, blocked: false }; return null; }, setVerified: () => null,
    mlsRoles: () => ({ v: 1, kind: 'group', admins: [ME], joinPolicy: 'invite' }),
    mlsMembers: () => [{ leaf: 0, userId: ME, deviceId: DEV, platform: 'web', admin: true }, { leaf: 1, userId: BOB, deviceId: BOB_DEV, platform: 'web', admin: false }],
    mlsPending: () => null, mlsCommitReceived: () => null, mlsAbortReceived: () => null, mlsForget: () => null,
    mlsCommit: () => ({ groupId: G, commit: b64('commit'), digest: sha('commit'), epoch: 3 }),
    mlsMergeOwn: () => ({ groupId: G, epoch: 4, groupInfo: 'gi', tree: 't' }),
    mlsReceive: () => { throw coded('invalid', 'no script'); },
  };
  const core = async (command: Cmd) => { calls.push(command); const handler = handlers[command.cmd]; if (!handler) throw new Error(`unexpected ${command.cmd}`); return handler(command); };
  const routes: [string, RegExp, (body: any, match: RegExpExecArray) => [number, any]][] = [
    ['GET', /^\/api\/mls\/keypackages$/, () => [200, { oneTime: 100, lastResort: true, low: false, max: 100 }]],
    ['GET', /^\/api\/channels$/, () => [200, { channels: [{ id: G, kind: 'private', name: null, epoch: 3, seq: 0, frozen: false, member: true, cursor: 0, admin: true }] }]],
    ['GET', /^\/api\/channels\/\w+\/members$/, () => [200, { members: [{ userId: ME, username: 'me', deviceId: DEV, admin: true }, { userId: BOB, username: 'bob', deviceId: BOB_DEV, admin: false }] }]],
    ['GET', /^\/api\/mls\/welcomes$/, () => [200, { welcomes: [] }]],
    ['GET', /^\/api\/channels\/\w+\/log\?after=(\d+)$/, (_, match) => [200, { epoch: 3, seq: 9, cursor: 0, entries: options.log?.(Number(match[1])) ?? [], more: false, gap: false }]],
    ['GET', /^\/api\/users\/\w+\/identity$/, () => [200, { userId: BOB, username: 'bob', identity: { dh: 'dh2', sign: 'sign2' } }]],
    ['POST', /^\/api\/channels\/\w+\/resolve$/, body => [200, body.action === 'rollback' ? { resolved: 'rollback', epoch: 3, seq: 4, removeDevice: BOB_DEV } : { resolved: 'dismiss' }]],
    ['POST', /^\/api\/channels\/\w+\/commits$/, () => [201, { epoch: 4, seq: 6, digest: sha('commit') }]],
    ['PUT', /^\/api\/channels\/\w+\/group-info$/, () => [200, {}]],
    ['POST', /^\/api\/channels\/\w+\/cursor$/, () => [200, {}]],
  ];
  async function fetch(path: string, init: any = {}) {
    const method = init.method || 'GET', body = init.body ? JSON.parse(init.body) : undefined;
    requests.push({ method, path, body });
    for (const [verb, pattern, answer] of routes) { const match = pattern.exec(path); if (verb === method && match) { const [status, data] = answer(body, match); return { status, ok: status < 300, json: async () => data }; } }
    return { status: 404, ok: false, json: async () => ({ error: 'Not found' }) };
  }
  const elements = new Map<string, any>();
  const element = () => ({ hidden: true, textContent: '', value: '', disabled: false, dataset: {}, style: { setProperty() {} }, children: [] as any[], onclick: null as any,
    addEventListener() {}, replaceChildren(...nodes: any[]) { this.children = nodes; }, append(...nodes: any[]) { this.children.push(...nodes); }, querySelectorAll: () => [], focus() {}, setAttribute() {}, classList: { add() {}, remove() {}, toggle() {} } });
  const document = { readyState: 'complete', getElementById: (id: string) => elements.get(id) ?? (elements.set(id, element()), elements.get(id)), createElement: element, getElementsByName: () => [] };
  const storage = new Map<string, string>();
  const app = { openConversation() {}, showTyping() {}, chatStatus(text: string) { app.status = text; }, status: '', refreshHistory() {}, setComposable() {}, setPeerName() {}, messagePayload: (record: any) => record, readReceipts: true };
  const context: Record<string, any> = {
    indexedDB: new IDBFactory(), IDBKeyRange, crypto, Blob, TextEncoder, TextDecoder, Uint8Array, Date, atob, btoa, URL, Intl, setTimeout, clearTimeout, Promise, JSON, fetch, document,
    localStorage: { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => storage.set(key, value), removeItem: (key: string) => storage.delete(key) },
    navigator: { locks: { request(_name: string, options: any, callback?: any) { const run = callback ?? options; Promise.resolve().then(() => run({})); return Promise.resolve(); } } },
    WebSocket: { OPEN: 1 }, App: app,
    Core: { supported: () => true, groupStore: () => core },
    DeviceFormat: { deviceKey: async () => ({ deviceId: DEV, sign: async () => 'signature' }), mlsCertBytes: () => new Uint8Array(1), mlsCertJson: () => '{}', b64: (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url') },
  };
  context.window = context;
  for (const source of sources) runInNewContext(source, context);
  const Groups = context.Groups;
  const ctx = { me: { id: ME, username: 'me' }, backend: 'signal', box: { identity: async () => ({ pub: { sign: 'A'.repeat(43) } }), peer: async () => null, notePeer: async () => {} }, signWithIdentity: async () => 'sig',
    contacts: () => [], render() {}, notice() {}, viewing: () => false, looking: () => false, socket: () => null, openGroup() {}, review() {} };
  const el = (id: string) => document.getElementById(id);
  const until = async (check: () => boolean, what: string) => { for (let i = 0; i < 400; i++) { if (check()) return; await Bun.sleep(5); } throw new Error(`timed out: ${what}`); };
  const settle = () => Bun.sleep(60);
  return { Groups, calls, requests, handlers, ctx, el, app, until, settle, setPeer: (value: any) => { peer = value; },
    async start() { Groups.start(ctx); await until(() => Groups.enabled(), 'groups enabled'); await settle(); },
    of: (name: string) => calls.filter(command => command.cmd === name) };
}
const application = (payload: unknown) => ({ pendingId: 'p1', kind: 'application', plaintext: JSON.stringify(payload), sender: { leaf: 1, userId: BOB, deviceId: BOB_DEV, platform: 'web', admin: false }, epoch: 3 });
const typing = { v: 1, type: 'typing', id: crypto.randomUUID(), at: Date.now(), on: true };
const text = { v: 1, type: 'message', id: crypto.randomUUID(), text: 'hi', createdAt: Date.now(), expiresAt: null };
const live = { type: 'ephemeral', channel: G, from: { userId: BOB, deviceId: BOB_DEV }, message: b64('live'), createdAt: Date.now() };

describe('groups.js security rules (docs/m4-groups.md)', () => {
  test('1. a live (ephemeral) frame is staged only, and kept only when it is an application message carrying typing', async () => {
    const w = world();
    await w.start();
    for (const [processed, kept] of [[{ pendingId: 'p1', kind: 'commit', sender: { userId: BOB }, epoch: 4 }, false], [application(text), false], [application(typing), true]] as const) {
      w.calls.length = 0;
      w.handlers.mlsReceive = () => processed;
      w.Groups.frame(live);
      await w.until(() => w.of('mlsAbortReceived').length + w.of('mlsCommitReceived').length > 0, 'decision');
      expect(w.of('mlsReceive')[0]).toMatchObject({ commit: false, expect: 'application' });
      expect(w.of(kept ? 'mlsCommitReceived' : 'mlsAbortReceived')).toEqual([{ cmd: kept ? 'mlsCommitReceived' : 'mlsAbortReceived', pendingId: 'p1' }]);
      expect(w.of(kept ? 'mlsAbortReceived' : 'mlsCommitReceived')).toEqual([]);
    }
  });

  test('2. a log entry whose content is not the kind the log says is aborted and skipped, never committed', async () => {
    const w = world();
    await w.start();
    w.handlers.mlsReceive = () => ({ pendingId: 'p1', kind: 'commit', sender: { leaf: 1, userId: BOB }, epoch: 4, digest: 'd' });
    w.Groups.frame({ type: 'group', channel: G, seq: 1, epoch: 3, kind: 'app', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('m1'), createdAt: Date.now() });
    await w.until(() => w.Groups.debug(G).cursor === 1, 'entry 1 skipped');
    expect(w.of('mlsReceive')[0]).toMatchObject({ commit: false, expect: 'application' });
    w.handlers.mlsReceive = () => ({ ...application(text), pendingId: 'p2' });
    w.Groups.frame({ type: 'group', channel: G, seq: 2, epoch: 3, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('m2'), createdAt: Date.now() });
    await w.until(() => w.Groups.debug(G).cursor === 2, 'entry 2 skipped');
    expect(w.of('mlsAbortReceived').map(command => command.pendingId)).toEqual(['p1', 'p2']);
    expect(w.of('mlsCommitReceived')).toEqual([]);
  });

  const frozenEntry = (message = b64('bad commit')) => ({ seq: 5, epoch: 3, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message, createdAt: Date.now() });
  async function frozenWorld(receive: () => any, entry = frozenEntry()) {
    const w = world({ log: after => after === 4 ? [entry] : [] });
    w.handlers.mlsReceive = receive;
    await w.start();
    w.Groups.open(G);
    w.Groups.frame({ type: 'channel', id: G, change: 'frozen', seq: 5, digest: sha('bad commit') });
    await w.until(() => !/Checking/.test(w.el('group-banner-text').textContent) && !w.el('group-banner').hidden, 'checked');
    return w;
  }

  test('3a. a reported commit that checks out here: only Dismiss, and Rollback is refused; nothing is kept from the check', async () => {
    const w = await frozenWorld(() => ({ pendingId: 'c1', kind: 'commit', sender: { leaf: 1, userId: BOB }, epoch: 4 }));
    expect(w.of('mlsReceive')[0]).toMatchObject({ commit: false, expect: 'commit', message: b64('bad commit') });
    expect(w.of('mlsAbortReceived')).toEqual([{ cmd: 'mlsAbortReceived', pendingId: 'c1' }]);
    expect(w.of('mlsCommitReceived')).toEqual([]);
    expect(w.el('group-banner-text').textContent).toContain('checks out');
    expect([w.el('group-rollback').hidden, w.el('group-dismiss').hidden]).toEqual([true, false]);
    await w.el('group-rollback').onclick(); await w.settle();
    expect(w.requests.filter(request => request.path.endsWith('/resolve'))).toEqual([]);
    await w.el('group-dismiss').onclick(); await w.settle();
    expect(w.requests.filter(request => request.path.endsWith('/resolve')).map(request => request.body.action)).toEqual(['dismiss']);
  });

  test('3b. a reported commit this device rejects too: Rollback is offered; a log entry that does not match the report is not', async () => {
    const fails = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); });
    expect(fails.el('group-banner-text').textContent).toContain('rejects it too');
    expect([fails.el('group-rollback').hidden, fails.el('group-dismiss').hidden]).toEqual([false, false]);
    const mismatch = await frozenWorld(() => { throw coded('poison', 'poison x: y'); }, frozenEntry(b64('another commit')));
    expect(mismatch.of('mlsReceive')).toEqual([]);
    expect(mismatch.el('group-banner-text').textContent).toContain("couldn't check it");
    expect([mismatch.el('group-rollback').hidden, mismatch.el('group-dismiss').hidden]).toEqual([true, false]);
  });

  test('4. remove-needed frames remove nobody; only the device our own signed rollback names is removed', async () => {
    const w = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); });
    w.Groups.frame({ type: 'channel', id: G, change: 'remove-needed', deviceId: 'Z'.repeat(22) });
    await w.settle();
    expect(w.of('mlsCommit')).toEqual([]);
    await w.el('group-rollback').onclick();
    await w.until(() => w.of('mlsCommit').length > 0, 'removal commit');
    expect(w.requests.find(request => request.path.endsWith('/resolve'))!.body).toMatchObject({ action: 'rollback', seq: 5, digest: sha('bad commit'), signature: 'signature' });
    expect(w.of('mlsCommit')[0].removes).toEqual([{ userId: BOB, deviceId: BOB_DEV }]);
  });

  test('5. a changed code of someone met in a group pauses the group and is only accepted from an explicit review', async () => {
    const w = world({ log: after => after === 0 ? [{ seq: 1, epoch: 3, kind: 'app', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('m'), createdAt: Date.now() }] : [] });
    w.handlers.mlsReceive = () => { throw coded('invalid', `no pinned account key for user ${BOB}`); };
    await w.start();
    await w.until(() => w.Groups.debug(G).status === 'paused', 'paused');
    w.Groups.open(G);
    expect(w.el('group-review').hidden).toBe(false);
    expect(w.of('acceptChange')).toEqual([]);
    await w.el('group-review').onclick(); await w.settle();
    expect(w.el('pin-review').hidden).toBe(false);
    expect(w.of('acceptChange')).toEqual([]);
    const [before, after] = [w.el('pin-review-before').textContent, w.el('pin-review-after').textContent];
    expect(before).toMatch(/^(\d{5} ){11}\d{5}$/);
    expect(after).toMatch(/^(\d{5} ){11}\d{5}$/);
    expect(before).not.toBe(after);
    w.el('pin-review-cancel').onclick();
    expect(w.of('acceptChange')).toEqual([]);
    await w.el('group-review').onclick(); await w.settle();
    await w.el('pin-review-verify').onclick(); await w.settle();
    expect(w.of('acceptChange')).toEqual([{ cmd: 'acceptChange', contact: BOB }]);
    expect(w.of('setVerified')).toEqual([{ cmd: 'setVerified', contact: BOB, verified: true }]);
    expect(w.Groups.debug(G).status).not.toBe('paused');
  });
});
