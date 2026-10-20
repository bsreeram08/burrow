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
const PAIR = 'p'.repeat(43), DEV2 = 'F'.repeat(22), G = 'g'.repeat(22), ME = 'M'.repeat(22), BOB = 'B'.repeat(22), DEV = 'D'.repeat(22), BOB_DEV = 'E'.repeat(22);
const coded = (code: string | null, message: string) => Object.assign(new Error(message), { code });
const b64 = (text: string) => Buffer.from(text).toString('base64url');
const sha = (text: string) => createHash('sha256').update(text).digest('hex');

type Cmd = { cmd: string; [key: string]: any };
function world(options: { log?: (after: number) => any[]; contact?: boolean; dmPeer?: any; poison?: number; removeDevice?: string; epoch?: number; channels?: any[]; own?: { listed: string[]; dropped: string[] } | null; tree?: any[] } = {}) {
  const log = { current: options.log };
  const calls: Cmd[] = [], requests: { method: string; path: string; body: any }[] = [];
  let peer: any = { identity: { dh: 'dh1', sign: 'sign1' }, verified: false, changed: false, blocked: false };
  const handlers: Record<string, (command: Cmd) => any> = {
    mlsDeviceLeaf: () => 'leaf', mlsSetDeviceCert: () => ({}), mlsKeyPackages: command => Array(command.count).fill('kp'),
    peer: () => peer, notePeer: command => { const changed = peer && (peer.identity.dh !== command.identity.dh || peer.identity.sign !== command.identity.sign); peer = { identity: command.identity, verified: false, changed, blocked: changed }; return peer; },
    // Like chatcore: with `identity`, only that exact pinned identity is accepted.
    acceptChange: command => { if (command.identity && (command.identity.dh !== peer.identity.dh || command.identity.sign !== peer.identity.sign)) throw coded('mismatch', 'The security code changed again.'); peer = { ...peer, blocked: false }; return null; },
    setVerified: command => { if (command.identity && (command.identity.dh !== peer.identity.dh || command.identity.sign !== peer.identity.sign)) throw coded('mismatch', 'The security code changed again.'); return null; },
    mlsSignResolution: () => 'L'.repeat(86),
    mlsInspectGroup: command => ({ groupId: G, members: options.tree ?? [] }), // chatcore: { groupId, members: [{ leaf, userId, deviceId, platform, admin, stale }] }
    mlsVerifyResolution: command => { if (command.signature !== 'L'.repeat(86) || command.by !== DEV2) throw coded('auth', 'bad resolution signature'); return { userId: ME, deviceId: DEV2 }; },
    mlsCommitAuthor: () => ({ authenticated: true, signedContentInvalid: true, class: 'signed-content', author: { leaf: 1, userId: BOB, deviceId: BOB_DEV, platform: 'web', admin: false } }),
    mlsRoles: () => ({ v: 1, kind: 'group', admins: [ME], joinPolicy: 'invite' }),
    mlsMembers: () => [{ leaf: 0, userId: ME, deviceId: DEV, platform: 'web', admin: true }, { leaf: 1, userId: BOB, deviceId: BOB_DEV, platform: 'web', admin: false }],
    mlsPending: () => null, mlsClearOwn: () => null, mlsView: () => ({ groupId: G, epoch: 3, groupInfo: 'gi', tree: 't' }), mlsCommitReceived: () => null, mlsAbortReceived: () => null, mlsForget: () => null,
    mlsCommit: () => ({ groupId: G, commit: b64('commit'), digest: sha('commit'), epoch: 3 }),
    mlsMergeOwn: () => ({ groupId: G, epoch: 4, groupInfo: 'gi', tree: 't' }),
    mlsReceive: () => { throw coded('invalid', 'no script'); },
  };
  const core = async (command: Cmd) => { calls.push(command); const handler = handlers[command.cmd]; if (!handler) throw new Error(`unexpected ${command.cmd}`); return handler(command); };
  const routes: [string, RegExp, (body: any, match: RegExpExecArray) => [number, any]][] = [
    ['GET', /^\/api\/mls\/keypackages$/, () => [200, { oneTime: 100, lastResort: true, low: false, max: 100 }]],
    ['GET', /^\/api\/channels$/, () => [200, { channels: options.channels ?? [{ id: G, kind: 'private', name: null, epoch: 3, seq: 0, frozen: false, member: true, cursor: 0, admin: true }] }]],
    ['GET', /^\/api\/channels\/[\w-]{22}$/, () => [200, { id: G, kind: 'private', name: null, epoch: options.epoch ?? 3, seq: 5, frozen: false, member: true, cursor: 5, admin: true }]],
    ['GET', /^\/api\/channels\/\w+\/members$/, () => [200, { members: [{ userId: ME, username: 'me', deviceId: DEV, admin: true }, { userId: BOB, username: 'bob', deviceId: BOB_DEV, admin: false }] }]],
    ['GET', /^\/api\/mls\/welcomes$/, () => [200, { welcomes: [] }]],
    ['GET', /^\/api\/channels\/\w+\/log\?after=(\d+)$/, (_, match) => [200, { epoch: 3, seq: 9, cursor: 0, entries: log.current?.(Number(match[1])) ?? [], more: false, gap: false }]],
    ['GET', /^\/api\/users\/\w+\/identity$/, () => [200, { userId: BOB, username: 'bob', identity: { dh: 'dh2', sign: 'sign2' } }]],
    ['POST', /^\/api\/channels\/\w+\/resolve$/, body => [200, body.action === 'rollback' ? { resolved: 'rollback', epoch: 3, seq: 4, removeDevice: options.removeDevice ?? BOB_DEV } : { resolved: 'dismiss' }]],
    ['POST', /^\/api\/channels\/\w+\/commits$/, () => [201, { epoch: 4, seq: 6, digest: sha('commit') }]],
    ['PUT', /^\/api\/channels\/\w+\/group-info$/, () => [200, {}]],
    ['POST', /^\/api\/channels\/\w+\/poison$/, () => options.poison === 429 ? [429, { error: 'Too many reports from this device. Try again later.' }] : options.poison === 409 ? [409, { error: 'That is not the latest sequenced commit.' }] : [202, { frozen: true }]],
    ['POST', /^\/api\/channels\/\w+\/cursor$/, () => [200, {}]],
    ['GET', /^\/api\/channels\/\w+\/join-info$/, () => [200, { epoch: 3, seq: 6, groupInfo: 'gi', tree: 't' }]],
    ['POST', /^\/api\/channels\/\w+\/join$/, () => [201, { epoch: 4, seq: 7, digest: sha('join') }]],
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
  context.Math = Object.assign(Object.create(Math), { random: () => 0 }); // No 0–3 s jitter in tests.
  context.window = context;
  for (const source of sources) runInNewContext(source, context);
  const Groups = context.Groups;
  const dm = { peer: options.dmPeer ?? null };
  const ctx = { me: { id: ME, username: 'me' }, backend: 'signal', box: { identity: async () => ({ pub: { sign: 'A'.repeat(43) } }), peer: async () => dm.peer, notePeer: async () => {} }, signWithIdentity: async () => 'sig',
    contacts: () => options.contact ? [{ id: BOB, username: 'bob', state: 'mutual' }] : [], render() {}, notice() {}, viewing: () => false, looking: () => false, socket: () => null, openGroup() {},
    // Our devices as a verified signed list proves them (account.js); null: nothing verifiable.
    pairIdOf: async () => PAIR, dmChanged() {}, dmIncoming() {}, dmTyping() {},
    verifiedOwnDevices: async () => { const own = options.own === undefined ? { listed: [DEV], dropped: [] } : options.own; return own && { listed: new Set(own.listed), dropped: new Set(own.dropped) }; } };
  const el = (id: string) => document.getElementById(id);
  const until = async (check: () => boolean, what: string) => { for (let i = 0; i < 400; i++) { if (check()) return; await Bun.sleep(5); } throw new Error(`timed out: ${what}`); };
  const settle = () => Bun.sleep(60);
  return { storeList: () => context.ChatStore.list(), log, storage, dm, Groups, calls, requests, handlers, ctx, el, app, until, settle, setPeer: (value: any) => { peer = value; },
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
  async function frozenWorld(receive: () => any, entry = frozenEntry(), options: { removeDevice?: string; author?: () => any; before?: (storage: Map<string, string>) => void } = {}) {
    const w = world({ log: after => after === 4 ? [entry] : [], removeDevice: options.removeDevice });
    options.before?.(w.storage);
    w.handlers.mlsReceive = receive;
    if (options.author) w.handlers.mlsCommitAuthor = options.author;
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
    expect(w.requests.find(request => request.path.endsWith('/resolve'))!.body).toMatchObject({ action: 'rollback', seq: 5, digest: sha('bad commit'), author: BOB_DEV, signature: 'signature' });
    expect(w.of('mlsCommitAuthor')[0]).toMatchObject({ message: b64('bad commit') });
    expect(w.of('mlsCommit')[0].removes).toEqual([{ userId: BOB, deviceId: BOB_DEV }]);
  });

  test('4b. the author is the one this device authenticated: an answer naming another device removes nobody', async () => {
    const w = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); }, frozenEntry(), { removeDevice: 'Z'.repeat(22) });
    await w.el('group-rollback').onclick();
    await w.until(() => /different device/.test(w.app.status), 'refused');
    await w.settle();
    expect(w.of('mlsCommit')).toEqual([]);
  });

  test('4c. a failure outside what the author signed (a tag the server could corrupt) rolls back but removes nobody', async () => {
    for (const author of [() => ({ authenticated: true, signedContentInvalid: false, class: 'tag', author: { leaf: 1, userId: BOB, deviceId: BOB_DEV } }), () => { throw coded('auth', 'commit signature rejected'); }]) {
      const w = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); }, frozenEntry(), { author });
      expect(w.el('group-banner-text').textContent).toContain('nobody is removed');
      expect([w.el('group-rollback').hidden, w.el('group-dismiss').hidden]).toEqual([false, false]);
      await w.el('group-rollback').onclick(); await w.settle();
      expect(w.requests.find(request => request.path.endsWith('/resolve'))!.body).toMatchObject({ action: 'rollback', author: '' });
      expect(w.of('mlsCommit')).toEqual([]);
      // The restored epoch's GroupInfo is published, so the author can rejoin.
      expect(w.requests.some(request => request.method === 'PUT' && request.path.endsWith('/group-info'))).toBe(true);
    }
  });

  test('4d. the author of a rolled-back commit rejoins and makes the same change again; others ignore the notice', async () => {
    const w = world();
    let joined = 0;
    w.handlers.mlsJoinExternal = () => { joined++; return { groupId: G, commit: b64('join'), digest: sha('join'), epoch: 3 }; };
    await w.start();
    w.Groups.open(G);
    // This device removes bob (a commit of its own), and the server later reports that very commit rolled back.
    await w.Groups.removeMember(G, BOB);
    const own = w.requests.filter(request => request.path.endsWith('/commits')).length;
    const signed = { type: 'channel', id: G, change: 'rolled-back', action: 'rollback', author: '', by: DEV2, signature: 'L'.repeat(86) };
    w.Groups.frame({ ...signed, seq: 99, digest: 'f'.repeat(64) }); // not ours
    await w.settle();
    expect(joined).toBe(0);
    w.Groups.frame({ ...signed, seq: 6, digest: sha('commit') });
    await w.until(() => w.requests.filter(request => request.path.endsWith('/commits')).length === own + 1, 'redone');
    expect(joined).toBe(1);
    expect(w.of('mlsForget').length).toBeGreaterThan(0);
    expect(w.of('mlsCommit').at(-1)!.removes).toEqual([{ userId: BOB }]);
    expect(w.of('mlsVerifyResolution')[0]).toMatchObject({ group: G, action: 'rollback', seq: 6, digest: sha('commit'), author: '', by: DEV2 });
  });

  test('6. a rolled-back notice the server could have made up redoes nothing', async () => {
    const cases: [string, Partial<{ notice: any; epoch: number; log: (after: number) => any[]; later: boolean }>][] = [
      ['unsigned', { notice: { signature: 'X'.repeat(86) } }],
      ['signed by a device that is not an admin here', { notice: { by: 'Q'.repeat(22) } }],
      ['the commit is still in the log', { log: after => after === 5 ? [{ seq: 6, epoch: 3, kind: 'commit', from: { userId: ME, deviceId: DEV }, message: b64('commit'), createdAt: 0 }] : [] }],
      ['the channel is not at the pre-commit epoch', { epoch: 4 }],
      ['a later commit was processed since', { later: true, log: after => after < 7 ? [{ seq: 6, epoch: 3, kind: 'commit', from: { userId: ME, deviceId: DEV }, message: b64('commit'), createdAt: 0 }, { seq: 7, epoch: 4, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('later'), createdAt: 0 }].filter(entry => entry.seq > after) : [] }],
    ];
    for (const [what, variant] of cases) {
      const w = world({ epoch: variant.epoch, log: variant.later ? undefined : variant.log });
      let joined = 0;
      w.handlers.mlsJoinExternal = () => { joined++; return { groupId: G, commit: b64('join'), digest: sha('join'), epoch: 3 }; };
      await w.start();
      await w.Groups.removeMember(G, BOB);
      if (variant.later) {
        w.log.current = variant.log;
        w.handlers.mlsReceive = () => ({ pendingId: 'p9', kind: 'commit', sender: { leaf: 1, userId: BOB }, epoch: 5, digest: 'x' });
        w.Groups.frame({ type: 'group', channel: G, seq: 7, epoch: 4, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('later'), createdAt: Date.now() });
        await w.until(() => w.Groups.debug(G).cursor === 7, 'later commit');
      }
      const commits = w.of('mlsCommit').length;
      w.Groups.frame({ type: 'channel', id: G, change: 'rolled-back', action: 'rollback', seq: 6, digest: sha('commit'), author: '', by: DEV2, signature: 'L'.repeat(86), ...variant.notice });
      await Bun.sleep(150);
      expect([what, joined, w.of('mlsCommit').length]).toEqual([what, 0, commits]);
      if (variant.later) expect(w.of('mlsVerifyResolution')).toEqual([]); // forgotten as soon as the group moved past it
    }
  });

  const tagCheck = () => ({ authenticated: true, signedContentInvalid: false, class: 'tag', author: { leaf: 1, userId: BOB, deviceId: BOB_DEV } });
  const instanceKey = `tag-rollbacks-v1:${ME}-${DEV}-${'A'.repeat(12)}`;
  test('7. a tag rollback names nobody but is counted; from the second in a day an admin may remove that device, explicitly', async () => {
    const once = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); }, frozenEntry(), { author: tagCheck });
    expect(once.el('group-remove-author').hidden).toBe(true);
    await once.el('group-rollback').onclick(); await once.settle();
    expect(once.requests.find(request => request.path.endsWith('/resolve'))!.body).toMatchObject({ author: '', leafSignature: 'L'.repeat(86) });
    expect(JSON.parse(once.storage.get(instanceKey)!)[BOB_DEV]).toHaveLength(1);
    expect(once.of('mlsCommit')).toEqual([]);

    const w = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); }, frozenEntry(), { author: tagCheck, before: storage => storage.set(instanceKey, JSON.stringify({ [BOB_DEV]: [Date.now() - 3600000, Date.now() - 60000] })) });
    expect(w.el('group-remove-author').hidden).toBe(false);
    expect(w.el('group-remove-author').textContent).toBe("Remove bob's device");
    w.el('group-remove-author').onclick();
    expect(w.el('group-remove-confirm').hidden).toBe(false);
    expect(w.requests.filter(request => request.path.endsWith('/resolve'))).toEqual([]); // nothing until confirmed
    w.el('group-remove-yes').onclick();
    await w.until(() => w.of('mlsCommit').length > 0, 'removal');
    expect(w.requests.find(request => request.path.endsWith('/resolve'))!.body).toMatchObject({ action: 'rollback', author: BOB_DEV });
    expect(w.of('mlsSignResolution')[0]).toMatchObject({ author: BOB_DEV });
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
    expect(w.of('acceptChange')).toEqual([{ cmd: 'acceptChange', contact: BOB, identity: { dh: 'dh2', sign: 'sign2' } }]);
    expect(w.of('setVerified')).toEqual([{ cmd: 'setVerified', contact: BOB, verified: true, identity: { dh: 'dh2', sign: 'sign2' } }]);
    expect(w.Groups.debug(G).status).not.toBe('paused');
  });

  test('5c. the review accepts only the code it showed: a newer one pending at the tap is re-reviewed, not accepted', async () => {
    const w = world({ log: after => after === 0 ? [{ seq: 1, epoch: 3, kind: 'app', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('m'), createdAt: Date.now() }] : [] });
    w.handlers.mlsReceive = () => { throw coded('invalid', `no pinned account key for user ${BOB}`); };
    await w.start();
    await w.until(() => w.Groups.debug(G).status === 'paused', 'paused');
    w.Groups.open(G);
    await w.el('group-review').onclick(); await w.settle();
    const shown = w.el('pin-review-after').textContent;
    w.setPeer({ identity: { dh: 'dh3', sign: 'sign3' }, verified: false, changed: true, blocked: true }); // changed again behind the sheet
    await w.el('pin-review-accept').onclick(); await w.settle();
    expect(w.of('acceptChange')).toEqual([{ cmd: 'acceptChange', contact: BOB, identity: { dh: 'dh2', sign: 'sign2' } }]);
    expect(w.Groups.debug(G).status).toBe('paused');
    expect(w.el('pin-review').hidden).toBe(false);
    expect(w.el('pin-review-status').textContent).toContain('changed again');
    expect(w.el('pin-review-after').textContent).not.toBe(shown);
  });

  test('5b. a contact whose key differs from the group store\'s is paused too; only an explicit decision accepts it', async () => {
    const entry = { seq: 1, epoch: 3, kind: 'app', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('m'), createdAt: Date.now() };
    const w = world({ contact: true, dmPeer: { identity: { dh: 'dh2', sign: 'sign2' }, verified: false, changed: true, blocked: false }, log: after => after === 0 ? [entry] : [] });
    await w.start();
    await w.until(() => w.Groups.debug(G).status === 'paused', 'paused on the contact');
    expect(w.of('notePeer')).toEqual([{ cmd: 'notePeer', contact: BOB, identity: { dh: 'dh2', sign: 'sign2' } }]);
    expect(w.of('acceptChange')).toEqual([]);
    // Accepting this exact code in the 1:1 safety sheet is the explicit decision; then the group resumes.
    w.handlers.mlsReceive = () => application(text);
    await w.Groups.contactAccepted(BOB);
    expect(w.of('acceptChange')).toEqual([{ cmd: 'acceptChange', contact: BOB, identity: { dh: 'dh2', sign: 'sign2' } }]);
    await w.until(() => w.Groups.debug(G).cursor === 1, 'resumed');
  });

  test('3c. this device\'s own report (202 answers { frozen: true }) keeps the commit it froze on, and offers Rollback', async () => {
    const entry = { seq: 5, epoch: 3, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('bad commit'), createdAt: Date.now() };
    const w = world({ log: after => after <= 4 ? [entry] : [] });
    w.handlers.mlsMembers = () => [{ leaf: 0, userId: ME, deviceId: DEV, platform: 'web', admin: true }, { leaf: 1, userId: BOB, deviceId: BOB_DEV, platform: 'web', admin: false }];
    w.handlers.mlsReceive = () => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); };
    w.setPeer({ identity: { dh: 'dh2', sign: 'sign2' }, verified: false, changed: false, blocked: false }); // the key the server publishes
    await w.start();
    w.Groups.open(G);
    await w.until(() => !w.el('group-rollback').hidden, 'rollback offered');
    expect(w.requests.find(request => request.path.endsWith('/poison'))!.body).toEqual({ seq: 5, digest: sha('bad commit') });
    expect(w.el('group-banner-text').textContent).toContain('rejects it too');
  });

  test('3d. a rate-limited report is retried later: the device neither freezes on its own nor rejoins', async () => {
    const entry = { seq: 5, epoch: 3, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('bad commit'), createdAt: Date.now() };
    const w = world({ log: after => after <= 4 ? [entry] : [], poison: 429 });
    w.handlers.mlsReceive = () => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); };
    w.setPeer({ identity: { dh: 'dh2', sign: 'sign2' }, verified: false, changed: false, blocked: false });
    await w.start();
    await w.until(() => w.requests.some(request => request.path.endsWith('/poison')), 'reported');
    await w.settle();
    expect(w.Groups.debug(G)).toMatchObject({ status: 'active', cursor: 0 }); // still before the commit, to report it again
    expect(w.of('mlsForget')).toEqual([]);
    expect(w.requests.filter(request => request.path.endsWith('/join-info') || request.path.endsWith('/join'))).toEqual([]);
  });

  test('8. a device joins its account\'s channels by external commit only when the tree proves our account is in it (m5 §3)', async () => {
    const H = 'h'.repeat(22), OTHER = 'O'.repeat(22);
    const rows = [{ id: G, kind: 'private', name: null, epoch: 3, seq: 0, frozen: false, member: false, cursor: null, admin: false }, { id: H, kind: 'private', name: null, epoch: 3, seq: 0, frozen: false, member: false, cursor: null, admin: false }];
    const ourLeaf = { userId: ME, deviceId: OTHER, stale: false };
    const cases: [string, any, any[], boolean][] = [
      ['our other listed device is in the tree', { listed: [DEV, OTHER], dropped: [] }, [ourLeaf], true],
      ['the tree has no leaf of ours', { listed: [DEV, OTHER], dropped: [] }, [{ userId: BOB, deviceId: BOB_DEV, stale: false }], false],
      ['our leaf is for a device the verified list does not name', { listed: [DEV], dropped: [] }, [ourLeaf], false],
      ['our leaf is stale', { listed: [DEV, OTHER], dropped: [] }, [{ ...ourLeaf, stale: true }], false],
      ['our device list cannot be verified', null, [ourLeaf], false],
    ];
    for (const [what, own, tree, joins] of cases) {
      const w = world({ channels: rows, own, tree });
      w.handlers.mlsJoinExternal = () => ({ groupId: G, commit: b64('join'), digest: sha('join'), epoch: 3 });
      w.storage.set(`groups-v1:${ME}-${DEV}-${'A'.repeat(12)}`, JSON.stringify({ [H]: { kind: 'private', status: 'left', cursor: 0, members: [], admins: [], unread: 0, lastAt: 0 } }));
      await w.start();
      await Bun.sleep(300);
      expect([what, w.requests.filter(request => request.path.endsWith('/join')).map(request => request.path)]).toEqual([what, joins ? [`/api/channels/${G}/join`] : []]);
      expect(w.Groups.debug(H).status).toBe('left'); // never one we left
    }
  });

  test('9. own leaves go only when a verified signed list dropped them (or the core finds them stale); frames are hints', async () => {
    const GONE = 'Z'.repeat(22), KEPT = 'K'.repeat(22);
    const ours = () => [{ leaf: 0, userId: ME, deviceId: DEV, admin: true }, { leaf: 2, userId: ME, deviceId: GONE, admin: true }, { leaf: 3, userId: ME, deviceId: KEPT, admin: true }];
    // The server's word alone (an unverifiable list) removes nothing.
    const unverified = world({ own: null });
    unverified.handlers.mlsMembers = ours;
    await unverified.start(); await unverified.settle();
    unverified.Groups.frame({ type: 'channel', id: G, change: 'remove-device', deviceId: GONE });
    await Bun.sleep(150);
    expect(unverified.of('mlsCommit')).toEqual([]);
    // A verified list that dropped GONE: it goes at start; KEPT (merely missing, not dropped) stays.
    const w = world({ own: { listed: [DEV], dropped: [GONE] } });
    w.handlers.mlsMembers = ours;
    await w.start();
    await w.until(() => w.of('mlsCommit').length === 1, 'removed at start');
    await w.settle();
    expect(w.of('mlsCommit').map(command => command.removes)).toEqual([[{ userId: ME, deviceId: GONE }]]);
    // A frame for a device the verified list still names (or never dropped) is ignored.
    w.Groups.frame({ type: 'channel', id: G, change: 'remove-device', deviceId: KEPT });
    await Bun.sleep(150);
    expect(w.of('mlsCommit')).toHaveLength(1);
  });

  test('10. a rollback removes the authenticated (user, device) only, never another user\'s leaf claiming the same device id', async () => {
    const EVE = 'V'.repeat(22);
    const evil = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); });
    evil.handlers.mlsMembers = () => [{ leaf: 0, userId: ME, deviceId: DEV, admin: true }, { leaf: 4, userId: EVE, deviceId: BOB_DEV, admin: false }];
    await evil.el('group-rollback').onclick(); await evil.settle(); await Bun.sleep(100);
    expect(evil.of('mlsCommit')).toEqual([]); // bob's leaf is gone; eve's look-alike stays
    const both = await frozenWorld(() => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); });
    both.handlers.mlsMembers = () => [{ leaf: 1, userId: BOB, deviceId: BOB_DEV, admin: false }, { leaf: 4, userId: EVE, deviceId: BOB_DEV, admin: false }];
    await both.el('group-rollback').onclick();
    await both.until(() => both.of('mlsCommit').length === 1, 'removal');
    expect(both.of('mlsCommit')[0].removes).toEqual([{ userId: BOB, deviceId: BOB_DEV }]);
  });

  test('11. a 1:1 chat on MLS lands in its own conversation, as 1:1, only once checked, and only from the two of us (m5 §8)', async () => {
    const EVE = 'V'.repeat(22);
    const rows = [{ id: G, kind: 'dm', name: null, epoch: 3, seq: 0, frozen: false, member: true, cursor: 0, admin: true, peer: { id: BOB, username: 'bob' } }];
    const entry = (seq: number) => ({ type: 'group', channel: G, seq, epoch: 3, kind: 'app', from: { userId: BOB, deviceId: BOB_DEV }, message: b64(`m${seq}`), createdAt: Date.now() });
    const w = world({ channels: rows });
    await w.start();
    expect(w.Groups.sections().rows).toEqual([]); // not a group: shown under its contact
    // A check that fails (not our DM) stores nothing.
    w.handlers.mlsCheckDm = () => { throw coded('invalid', 'not a DM of these two'); };
    w.handlers.mlsReceive = () => application({ ...text, id: crypto.randomUUID(), text: 'unchecked' });
    w.Groups.frame(entry(1));
    await w.until(() => w.Groups.debug(G).cursor === 1, 'processed');
    // Checked: bob's message lands under the pair, incoming, without group fields.
    w.handlers.mlsCheckDm = () => null;
    const hello = { ...text, id: crypto.randomUUID(), text: 'hello over MLS' };
    w.handlers.mlsReceive = () => application(hello);
    w.Groups.frame(entry(2));
    await w.until(() => w.Groups.debug(G).cursor === 2, 'processed');
    // Someone else in the group (never in a real DM) is ignored.
    w.handlers.mlsReceive = () => ({ ...application({ ...text, id: crypto.randomUUID(), text: 'from eve' }), sender: { leaf: 2, userId: EVE, deviceId: 'Q'.repeat(22) } });
    w.Groups.frame(entry(3));
    await w.until(() => w.Groups.debug(G).cursor === 3, 'processed');
    const stored = await w.storeList();
    expect(stored.map((record: any) => [record.conversationId, record.direction, record.text, record.from])).toEqual([[PAIR, 'incoming', 'hello over MLS', undefined]]);
    expect(w.of('mlsCheckDm').length).toBe(2);
  });

  test('3e. a report refused because the commit was rolled back meanwhile reads on; it never rejoins (or retries a 429 report)', async () => {
    const bad = { seq: 5, epoch: 3, kind: 'commit', from: { userId: BOB, deviceId: BOB_DEV }, message: b64('bad commit'), createdAt: Date.now() };
    const w = world({ poison: 409 });
    let rolledBack = false;
    w.log.current = after => (rolledBack ? [] : after <= 4 ? [bad] : []);
    w.handlers.mlsReceive = () => { rolledBack = true; throw coded('poison', `poison ${sha('bad commit')}: bad tag`); };
    w.setPeer({ identity: { dh: 'dh2', sign: 'sign2' }, verified: false, changed: false, blocked: false });
    await w.start();
    await w.until(() => w.requests.some(request => request.path.endsWith('/poison')), 'reported');
    await w.settle();
    expect(w.requests.filter(request => /\/join(-info)?$/.test(request.path))).toEqual([]);
    expect(w.of('mlsForget')).toEqual([]);
    expect(w.Groups.debug(G).status).toBe('active');
    const limited = world({ log: after => after <= 4 ? [bad] : [], poison: 429 });
    limited.handlers.mlsReceive = () => { throw coded('poison', `poison ${sha('bad commit')}: bad tag`); };
    limited.setPeer({ identity: { dh: 'dh2', sign: 'sign2' }, verified: false, changed: false, blocked: false });
    await limited.start();
    await limited.until(() => limited.requests.some(request => request.path.endsWith('/poison')), 'reported');
    await Bun.sleep(400);
    expect(limited.requests.filter(request => request.path.endsWith('/poison'))).toHaveLength(1); // no burst retries of a 429 report
  });
});
