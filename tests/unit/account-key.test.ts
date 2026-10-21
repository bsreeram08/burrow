import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import '../../packages/signaling/public/devices.js';

// docs/m6-account-key.md §1, §3.3, §5: the bytes the web builds itself (the AccountKey it hands the core, the keys bytes
// its account key signs, the rekey request bytes it checks). The same values are pinned in
// crates/chatcore/tests/account_key.rs (§10).
const F = (globalThis as any).DeviceFormat;
const b64 = (bytes: Uint8Array | number[]) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
const USER = 'AAECAwQFBgcICQoLDA0ODw', DEVICE = 'EBESExQVFhcYGRobHB0eHw';
const seed = Uint8Array.from({ length: 32 }, (_, i) => 1 + i), dh = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
const AIK = 'ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';

describe('the account key bytes (shared vectors)', () => {
  test('AccountKey bytes match the core, and are read back strictly', () => {
    const bytes = F.accountKeyBytes(USER, seed, dh);
    expect(b64(bytes)).toBe('ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f');
    expect(bytes.length).toBe(117);
    const parsed = F.parseAccountKey(bytes, USER);
    expect([b64(parsed.signSeed), b64(parsed.dhSecret)]).toEqual([b64(seed), b64(dh)]);
    expect(() => F.parseAccountKey(bytes, 'another_user')).toThrow();
    expect(() => F.parseAccountKey(bytes.slice(0, -1), USER)).toThrow();
    expect(() => F.parseAccountKey(new Uint8Array([...bytes, 0]), USER)).toThrow();
    expect(() => F.accountKeyBytes(USER, seed.slice(1), dh)).toThrow();
  });
  test('the backup keys bytes match the core', () => {
    const hash = (text: string) => b64(sha(unb64(text)));
    const record = {
      v: 1, userId: USER, aikSign: AIK, epoch: 1, kdf: { alg: 'argon2id', salt: b64(Array.from({ length: 16 }, (_, i) => i)), m: 65536, t: 3, p: 1 },
      passHash: hash('PPCKyg-NB-6w8OEHe2_Z30fvNjIIOXRJwaWn4iSDyxY'), recoveryHash: hash('osIiZH2Qf6a3UUY_8wACozHYmpvt3CyQlfpc3Kld6D8'),
      passProofHash: hash('C9g-jJrsploDsMuNH52rbLTMfoDU_9vORpUpp-pGYoM'), recoveryProofHash: hash('8M1ElR7RU5dET5kZDE0Tzvw21P49Sot8f0ZCaK68NwI'),
    };
    const bytes = F.backupKeysBytes(record);
    expect(b64(bytes)).toBe('ABl3ZWJydGMtYnVuLWJhY2t1cC1rZXlzLXYyABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IHm1Vi6P5lT5QHixEuipi6eQH4U65pW-1-DjkQutBJZkAAAAARAAAQIDBAUGBwgJCgsMDQ4PAAEAAAAAAAMAAAABICYpbD9pfRrPdjNuK_69ykgVNlVjfpV3eyCkDN1cs5IxIB4H0DRDgvm5IDnSE5OxVhzbYHSrrjTJb8YyEsimJymOIJqjwGctBYJYymIPtNlv-YKtDqmEg-AzIoDFYH2K5kAXIDLtcn3DUEbtgnKDeZuxeAluFgq5vFrD-upycRd4XWab');
    expect(sha(bytes).toString('hex')).toBe('deccb6a4d30ffe8808cc17a5da29db8cfc47b2665f38bd340d4e1495a861b46c');
    expect(() => F.backupKeysBytes({ ...record, epoch: 0 })).toThrow();
    expect(() => F.backupKeysBytes({ ...record, kdf: { ...record.kdf, alg: 'scrypt' } })).toThrow();
  });
  test('the rekey request bytes match the core', () => {
    const bytes = F.rekeyBytes(USER, DEVICE, 'web', 'HPV5q6RaELodHvBtkfyiqp7QoRUFFWUxVUBdCxjLmmc', '_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg', AIK);
    expect(sha(bytes).toString('hex')).toBe('e3ca3b897fd9bbcc3b6e3a672dd91964c6457673304c1dd18492c2d0d84c5c1e');
    expect(() => F.rekeyBytes(USER, DEVICE, 'toaster', AIK, AIK, AIK)).toThrow();
  });
});
