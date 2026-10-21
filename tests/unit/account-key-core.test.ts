import { describe, expect, test } from 'bun:test';
import { Client, clientCore } from './helpers/mls';
import { passphrase, record, vectors } from './helpers/account-key-vectors';

// The account key and its backup through the wasm core, the way the browser calls it (docs/m6-account-key.md): the
// pinned vectors computed independently of chatcore (Python), and the flows. crates/chatcore/tests/account_key.rs
// pins the same values natively; account-key.test.ts checks the web's own byte builders against them.
// Needs the Rust toolchain like the other core-backed tests.
const loaded = clientCore();
if ('skip' in loaded) console.warn(`account-key-core.test.ts skipped: ${loaded.skip}`);
const suite = 'core' in loaded ? describe : describe.skip;
const Core = 'core' in loaded ? loaded.core : (undefined as never);
const published = { dh: vectors.dhPub, sign: vectors.aikSign };
const rejected = (run: () => unknown): any => { try { run(); } catch (error) { return error; } throw new Error('did not throw'); };

suite('the account key and its backup through the wasm core (m6)', () => {
    test('a core restored from the pinned key exports the pinned bytes, and the AIK signs the pinned keys bytes', () => {
        const core = new Client(Core);
        expect(rejected(() => core.call({ cmd: 'importAccountKey', userId: vectors.user, key: vectors.accountKey })).code).toBe('invalid'); // a blank core needs the published identity
        expect(core.call({ cmd: 'importAccountKey', userId: vectors.user, key: vectors.accountKey, published })).toEqual(published);
        expect(core.call({ cmd: 'identity' })).toEqual(published);
        expect(core.call({ cmd: 'exportAccountKey', userId: vectors.user })).toBe(vectors.accountKey);
        // Ed25519 is deterministic: signing the keys bytes reproduces the independently computed signature.
        const { signature, updatedAt, ...unsigned } = record as any;
        expect(core.call({ cmd: 'backupSignKeys', userId: vectors.user, record: unsigned })).toBe(signature);
    });

    test('a record sealed elsewhere opens with the passphrase and with the 24 words (any case, four letters each)', () => {
        const core = new Client(Core);
        const open = (secret: object, over: object = {}) => core.call({ cmd: 'backupOpen', userId: vectors.user, record, published, ...secret, ...over });
        const keys = { epoch: 1, passPub: vectors.passPub, recoveryPub: vectors.recoveryPub };
        expect(open({ passphrase })).toEqual({ accountKey: vectors.accountKey, backupKeys: keys });
        expect(open({ words: vectors.words }).accountKey).toBe(vectors.accountKey);
        expect(open({ words: vectors.words.split(' ').map(word => word.slice(0, 4).toUpperCase()).join('  ') }).accountKey).toBe(vectors.accountKey);
        expect(rejected(() => open({ passphrase: `${passphrase}!` })).message).toMatch(/doesn't open/);
        const swapped = vectors.words.split(' ');
        [swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
        expect(rejected(() => open({ words: swapped.join(' ') })).code).toBe('invalid');
        // The proofs the server holds the hashes of.
        expect(core.call({ cmd: 'backupProve', record, passphrase })).toEqual({ proof: vectors.passProof });
        expect(core.call({ cmd: 'backupProve', record, words: vectors.words })).toEqual({ proof: vectors.recoveryProof });
        // The record is checked first: not the published key, a tampered hash (the signature covers it), a cost out of range.
        expect(rejected(() => open({ passphrase }, { published: { dh: published.dh, sign: 'A'.repeat(43) } })).code).toBe('auth');
        expect(rejected(() => open({ passphrase }, { record: { ...record, passHash: 'A'.repeat(43) } })).code).toBe('auth');
        expect(rejected(() => open({ passphrase }, { record: { ...record, kdf: { ...record.kdf, m: 8 } } })).code).toBe('invalid');
    });

    test('create, sign, change the passphrase and reseal to the keys the device holds, all in the browser core', () => {
        const core = new Client(Core);
        core.call({ cmd: 'importAccountKey', userId: vectors.user, key: vectors.accountKey, published });
        const created = core.call({ cmd: 'backupCreate', userId: vectors.user, passphrase: 'a long enough passphrase' });
        expect(created.words.split(' ')).toHaveLength(24);
        expect(created.record.epoch).toBe(1);
        const signed = { ...created.record, signature: core.call({ cmd: 'backupSignKeys', userId: vectors.user, record: created.record }) };
        const blank = new Client(Core);
        const opened = blank.call({ cmd: 'backupOpen', userId: vectors.user, record: signed, passphrase: 'a long enough passphrase', published });
        expect(opened).toEqual({ accountKey: vectors.accountKey, backupKeys: created.backupKeys });
        expect(blank.call({ cmd: 'backupOpen', userId: vectors.user, record: signed, words: created.words, published }).accountKey).toBe(vectors.accountKey);
        // A web core that keeps its AIK in WebCrypto passes the AccountKey in.
        const web = new Client(Core);
        const made = web.call({ cmd: 'backupCreate', userId: vectors.user, passphrase: 'another long passphrase here', accountKey: vectors.accountKey });
        expect(made.record.aikSign).toBe(vectors.aikSign);
        expect(rejected(() => web.call({ cmd: 'backupCreate', userId: vectors.user, passphrase: 'another long passphrase here' }))).toBeTruthy(); // no key held, none given
        expect(rejected(() => web.call({ cmd: 'backupCreate', userId: vectors.user, passphrase: 'too short', accountKey: vectors.accountKey })).code).toBe('invalid');
        expect(core.call({ cmd: 'passphraseGenerate' }).split(' ')).toHaveLength(6);
        // The device keeps the backup keys; a change seals to them at epoch + 1 and leaves the recovery side alone.
        expect(rejected(() => core.call({ cmd: 'backupReseal', userId: vectors.user, record: signed, passphrase: 'a different passphrase' })).code).toBe('invalid'); // none held yet
        core.call({ cmd: 'backupKeysSet', backupKeys: created.backupKeys });
        const changed = core.call({ cmd: 'backupReseal', userId: vectors.user, record: signed, passphrase: 'a different passphrase' });
        expect(changed.words).toBeNull();
        expect(changed.record.epoch).toBe(2);
        expect(changed.record.recoveryHash).toBe(signed.recoveryHash);
        expect(changed.backupKeys.recoveryPub).toBe(created.backupKeys.recoveryPub);
    });
});
