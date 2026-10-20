import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import '../../packages/signaling/public/qr.js';

// qr.js against an independent encoder (libqrencode's `qrencode`): for every input, one of qr.js's eight masks must
// produce exactly the matrix qrencode produces. That checks the data and error-correction codewords, their
// placement, and the format and version information; the mask qrencode picks may differ (any mask is valid).
const QR = (globalThis as any).QR as { matrix(text: string, mask?: number): boolean[][] };
const hasQrencode = spawnSync('qrencode', ['-V']).status === 0;
const reference = (text: string) => spawnSync('qrencode', ['-t', 'ASCII', '-l', 'M', '-8', '-m', '0', '-o', '-', text], { encoding: 'utf8' }).stdout
  .split('\n').filter(Boolean).map(line => Array.from({ length: line.length / 2 }, (_, i) => line[i * 2] === '#'));

describe('QR codes for device linking', () => {
  const inputs = ['hi', 'https://calls.sreerams.in/#link=abc', 'webrtc-bun-link-v1:' + 'A'.repeat(43) + ':' + 'B'.repeat(22), 'ü→✓ unicode', ...[20, 40, 60, 80, 100, 120, 150, 180, 213].map(n => 'x'.repeat(n - 7) + '0123456'.slice(0, 7))];
  (hasQrencode ? test : test.skip)('matches libqrencode module for module, versions 1–10', () => {
    for (const text of inputs) {
      const expected = reference(text);
      const candidates = Array.from({ length: 8 }, (_, mask) => QR.matrix(text, mask));
      expect([text, candidates.some(candidate => JSON.stringify(candidate) === JSON.stringify(expected))]).toEqual([text, true]);
      expect(QR.matrix(text).length).toBe(expected.length); // the automatic mask keeps the same version
    }
  });
  test('sizes follow the version, and too much text is refused', () => {
    expect(QR.matrix('a').length).toBe(21);
    expect(QR.matrix('a'.repeat(213)).length).toBe(57);
    expect(() => QR.matrix('a'.repeat(214))).toThrow(/Too much/);
  });
});
