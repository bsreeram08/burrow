import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import '../../packages/signaling/public/devices.js';

// docs/m5-linking.md §1.3 and §5.1: the bytes a new device's key and the old account key sign. The same SHA-256
// values are pinned in apps/chat/test/link_bytes_test.dart (and crates/chatcore/tests/link.rs, §12).
const F = (globalThis as any).DeviceFormat;
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const b64 = (fill: number) => Buffer.alloc(32, fill).toString('base64url');

describe('link and succession bytes (shared vectors)', () => {
  test('start, claim and succession bytes match the app', () => {
    expect(sha(F.startBytes('a'.repeat(22), 'ios', b64(1)))).toBe('1f9848b5414f7d90cbf8277e3d4730267f72ee8d028ad67fd58a69c33c5d05f7');
    expect(sha(F.linkClaimBytes('L'.repeat(22), 'a'.repeat(22), b64(2)))).toBe('273bab88d9d3840481bfd63b210753922a6c999c2b58fd5c76c54c2d12b57116');
    expect(sha(F.successionBytes({ v: 1, userId: 'user_1', oldSign: b64(3), newSign: b64(4), newDh: b64(5), at: 1700000000000 }))).toBe('ba9d21a694b578849a380ef5cc9db652bec880543922e660c8f2fb2777758b54');
  });
  test('malformed inputs are refused', () => {
    expect(() => F.startBytes('a'.repeat(22), 'toaster', b64(1))).toThrow();
    expect(() => F.linkClaimBytes('short', 'a'.repeat(22), b64(2))).toThrow();
    expect(() => F.successionBytes({ v: 1, userId: 'user_1', oldSign: b64(3), newSign: 'x', newDh: b64(5), at: 1 })).toThrow();
    expect(() => F.successionBytes({ v: 1, userId: 'user_1', oldSign: b64(3), newSign: b64(4), newDh: b64(5), at: 1, extra: 1 })).toThrow();
  });
  test('the label key sent to a linked device opens what the primary sealed', async () => {
    const { privateKey } = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as unknown as CryptoKeyPair;
    const sign = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, new Uint8Array(bytes)));
    const primary = await F.deviceMetaKey('user_1', sign), raw = await F.deviceMetaKeyBytes('user_1', sign);
    expect(raw).toHaveLength(32);
    const sealed = await F.sealMeta(primary, 'user_1', 'd'.repeat(22), { label: 'Chrome on Mac', platform: 'web' });
    expect(await F.openMeta(await F.metaKeyFromBytes(raw), 'user_1', 'd'.repeat(22), sealed)).toEqual({ label: 'Chrome on Mac', platform: 'web' });
  });
  test('a succession chain is followed only from the pinned key to the served one, each record signed by the key before it', async () => {
    const key = async () => { const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as unknown as CryptoKeyPair; return { pair, pub: Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('base64url') }; };
    const [k0, k1, k2] = [await key(), await key(), await key()];
    const record = async (from: any, to: any, at: number, userId = 'user_1') => {
      const body = { v: 1, userId, oldSign: from.pub, newSign: to.pub, newDh: b64(9), at };
      return { ...body, signature: Buffer.from(await crypto.subtle.sign('Ed25519', from.pair.privateKey, new Uint8Array(F.successionBytes(body)))).toString('base64url') };
    };
    const chain = [await record(k0, k1, 1), await record(k1, k2, 2)];
    const served = { sign: k2.pub, dh: b64(9) };
    expect(await F.verifySuccession('user_1', { sign: k0.pub }, served, chain)).toHaveLength(2);
    expect(await F.verifySuccession('user_1', { sign: k1.pub }, served, chain)).toHaveLength(1); // pinned mid-chain
    expect(await F.verifySuccession('user_1', { sign: k2.pub }, { sign: k1.pub, dh: b64(9) }, chain)).toBeNull(); // must end at the served key
    expect(await F.verifySuccession('user_2', { sign: k0.pub }, served, chain)).toBeNull();
    const forged = [chain[0], { ...chain[1], signature: chain[0].signature }];
    expect(await F.verifySuccession('user_1', { sign: k0.pub }, served, forged)).toBeNull();
    const stranger = await key();
    expect(await F.verifySuccession('user_1', { sign: stranger.pub }, served, chain)).toBeNull(); // must start at our pin
  });
});
