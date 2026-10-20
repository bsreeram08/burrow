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
});
