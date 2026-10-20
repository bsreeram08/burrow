'use strict';
// QR codes for linking a device (docs/m5-linking.md): byte mode, error correction level M, versions 1–10 (up to 213
// bytes). No dependency: the page's CSP allows only this app's own scripts. Renders SVG built from DOM nodes.
// Checked module for module against libqrencode (tests/unit/qr.test.ts).
(() => {
  const root = typeof window !== 'undefined' ? window : globalThis;
  // Level M: [error-correction codewords per block, [blocks, data codewords per block], ...].
  const BLOCKS = [null,
    [10, [1, 16]], [16, [1, 28]], [26, [1, 44]], [18, [2, 32]], [24, [2, 43]],
    [16, [4, 27]], [18, [4, 31]], [22, [2, 38], [2, 39]], [22, [3, 36], [2, 37]], [26, [4, 43], [1, 44]]];
  const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

  // ---------- Reed–Solomon over GF(256), polynomial 0x11D ----------
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11d; }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const mul = (a, b) => a && b ? EXP[LOG[a] + LOG[b]] : 0;
  function generator(degree) {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) { next[j] ^= poly[j]; next[j + 1] ^= mul(poly[j], EXP[i]); }
      poly = next;
    }
    return poly;
  }
  function remainder(data, degree) {
    const gen = generator(degree), out = [...data, ...new Array(degree).fill(0)];
    for (let i = 0; i < data.length; i++) {
      const factor = out[i];
      if (factor) for (let j = 0; j < gen.length; j++) out[i + j] ^= mul(gen[j], factor);
    }
    return out.slice(data.length);
  }

  // ---------- Data codewords ----------
  const capacity = version => BLOCKS[version].slice(1).reduce((sum, [count, size]) => sum + count * size, 0);
  function codewords(bytes, version) {
    const bits = [], push = (value, length) => { for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
    push(0b0100, 4); push(bytes.length, version < 10 ? 8 : 16);
    for (const byte of bytes) push(byte, 8);
    const total = capacity(version) * 8;
    push(0, Math.min(4, total - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((value, bit) => value << 1 | bit, 0));
    for (let pad = 0; data.length < capacity(version); pad ^= 1) data.push(pad ? 0x11 : 0xec);
    // Split into blocks, add error correction to each, interleave.
    const [ec, ...groups] = BLOCKS[version], blocks = [];
    let at = 0;
    for (const [count, size] of groups) for (let i = 0; i < count; i++) { const block = data.slice(at, at + size); at += size; blocks.push({ data: block, ec: remainder(block, ec) }); }
    const out = [], longest = Math.max(...blocks.map(block => block.data.length));
    for (let i = 0; i < longest; i++) for (const block of blocks) if (i < block.data.length) out.push(block.data[i]);
    for (let i = 0; i < ec; i++) for (const block of blocks) out.push(block.ec[i]);
    return out;
  }

  // ---------- Matrix ----------
  const bch = (value, poly, bits) => { let rem = value << (bits - 1); const top = 31 - Math.clz32(poly); for (let i = 31 - Math.clz32(rem); i >= top; i--) if (rem >>> i & 1) rem ^= poly << (i - top); return value << (bits - 1) | rem; };
  const MASKS = [(r, c) => (r + c) % 2 === 0, r => r % 2 === 0, (r, c) => c % 3 === 0, (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0, (r, c) => (r * c) % 2 + (r * c) % 3 === 0,
    (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0, (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0];

  function base(version) {
    const size = version * 4 + 17, dark = Array.from({ length: size }, () => new Array(size).fill(false)), fixed = Array.from({ length: size }, () => new Array(size).fill(false));
    const set = (r, c, value) => { dark[r][c] = value; fixed[r][c] = true; };
    for (const [row, col] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
        const y = row + r, x = col + c;
        if (y < 0 || x < 0 || y >= size || x >= size) continue;
        const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3));
        set(y, x, r >= 0 && r <= 6 && c >= 0 && c <= 6 && ring !== 2 && ring <= 3);
      }
    }
    for (let i = 8; i < size - 8; i++) { if (!fixed[6][i]) set(6, i, i % 2 === 0); if (!fixed[i][6]) set(i, 6, i % 2 === 0); }
    // Alignment patterns, except the three that would overlap the finders (they may cross the timing patterns).
    const centres = ALIGN[version], last = centres.length - 1;
    centres.forEach((r, i) => centres.forEach((c, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
      for (let y = -2; y <= 2; y++) for (let x = -2; x <= 2; x++) set(r + y, c + x, Math.max(Math.abs(y), Math.abs(x)) !== 1);
    }));
    set(size - 8, 8, true); // The dark module.
    for (let i = 0; i < 9; i++) { if (!fixed[8][i]) set(8, i, false); if (!fixed[i][8]) set(i, 8, false); }
    for (let i = 0; i < 8; i++) { set(8, size - 1 - i, false); if (!fixed[size - 1 - i][8]) set(size - 1 - i, 8, false); }
    if (version >= 7) {
      const info = bch(version, 0x1f25, 13);
      for (let i = 0; i < 18; i++) { const bit = Boolean(info >>> i & 1), a = Math.floor(i / 3), b = size - 11 + i % 3; set(a, b, bit); set(b, a, bit); }
    }
    return { size, dark, fixed };
  }
  function place({ size, dark, fixed }, data) {
    const bits = [];
    for (const byte of data) for (let i = 7; i >= 0; i--) bits.push(Boolean(byte >>> i & 1));
    let at = 0, upward = true;
    for (let right = size - 1; right > 0; right -= 2) {
      if (right === 6) right = 5;
      for (let i = 0; i < size; i++) {
        const row = upward ? size - 1 - i : i;
        for (const col of [right, right - 1]) if (!fixed[row][col]) dark[row][col] = at < bits.length ? bits[at++] : false;
      }
      upward = !upward;
    }
  }
  function withMask({ size, dark, fixed }, mask) {
    const out = dark.map((row, r) => row.map((value, c) => fixed[r][c] ? value : value !== MASKS[mask](r, c)));
    // Format information: level M (00) and the mask, BCH-protected and XOR-masked.
    const format = bch(mask, 0x537, 11) ^ 0x5412;
    for (let i = 0; i < 15; i++) {
      const bit = Boolean(format >>> i & 1);
      if (i < 6) out[i][8] = bit; else if (i < 8) out[i + 1][8] = bit; else out[size - 15 + i][8] = bit;
      if (i < 8) out[8][size - 1 - i] = bit; else if (i < 9) out[8][15 - i] = bit; else out[8][14 - i] = bit;
    }
    return out;
  }
  /** The standard penalty (ISO/IEC 18004 §7.8.3): lower is easier to scan. */
  function penalty(m) {
    const size = m.length;
    let score = 0;
    const runs = line => { let total = 0, run = 1; for (let i = 1; i <= line.length; i++) { if (i < line.length && line[i] === line[i - 1]) run++; else { if (run >= 5) total += run - 2; run = 1; } } return total; };
    const finderLike = line => { let total = 0; const s = line.map(v => v ? 1 : 0).join(''); for (const p of ['10111010000', '00001011101']) for (let i = s.indexOf(p); i !== -1; i = s.indexOf(p, i + 1)) total += 40; return total; };
    for (let i = 0; i < size; i++) { const row = m[i], col = m.map(r => r[i]); score += runs(row) + runs(col) + finderLike(row) + finderLike(col); }
    for (let r = 0; r < size - 1; r++) for (let c = 0; c < size - 1; c++) if (m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c] && m[r][c] === m[r + 1][c + 1]) score += 3;
    const darkCount = m.flat().filter(Boolean).length;
    score += Math.floor(Math.abs(darkCount * 20 - size * size * 10) / (size * size)) * 10;
    return score;
  }

  /**
   * The module matrix (true = dark) for `text` (UTF-8). `mask` forces one of the eight masks (tests); otherwise the
   * one with the lowest penalty is used. Throws if the text needs more than version 10.
   */
  function matrix(text, mask) {
    const bytes = new TextEncoder().encode(text);
    const version = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].find(v => 4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= capacity(v) * 8);
    if (!version) throw new Error('Too much to fit in a QR code.');
    const grid = base(version);
    place(grid, codewords(bytes, version)); // Modules left after the data (remainder bits) stay light.
    if (mask !== undefined) return withMask(grid, mask);
    let best = null;
    for (let candidate = 0; candidate < 8; candidate++) { const m = withMask(grid, candidate), score = penalty(m); if (!best || score < best.score) best = { m, score }; }
    return best.m;
  }

  /** An <svg> of the code with a 4-module quiet zone, drawn as one path (crisp at any size). */
  function svg(text, label) {
    const m = matrix(text), size = m.length + 8, NS = 'http://www.w3.org/2000/svg';
    const node = document.createElementNS(NS, 'svg');
    node.setAttribute('viewBox', `0 0 ${size} ${size}`); node.setAttribute('shape-rendering', 'crispEdges');
    node.setAttribute('role', 'img'); node.setAttribute('aria-label', label || 'QR code');
    const back = document.createElementNS(NS, 'rect'); back.setAttribute('width', String(size)); back.setAttribute('height', String(size)); back.setAttribute('fill', '#fff');
    const path = document.createElementNS(NS, 'path'); let d = '';
    m.forEach((row, r) => row.forEach((on, c) => { if (on) d += `M${c + 4} ${r + 4}h1v1h-1z`; }));
    path.setAttribute('d', d); path.setAttribute('fill', '#000');
    node.append(back, path);
    return node;
  }

  /** Reads a QR code from the camera where the browser can (BarcodeDetector); null where it can't. */
  async function scanner(video) {
    if (typeof root.BarcodeDetector !== 'function' || !(await root.BarcodeDetector.getSupportedFormats?.())?.includes('qr_code')) return null;
    const detector = new root.BarcodeDetector({ formats: ['qr_code'] });
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    video.srcObject = stream; await video.play();
    let stopped = false;
    const stop = () => { stopped = true; for (const track of stream.getTracks()) track.stop(); video.srcObject = null; };
    const next = new Promise((resolve, reject) => {
      const tick = async () => {
        if (stopped) return resolve(null);
        try { const [code] = await detector.detect(video); if (code?.rawValue) { stop(); return resolve(code.rawValue); } } catch (error) { stop(); return reject(error); }
        setTimeout(tick, 250);
      };
      tick();
    });
    return { result: next, stop };
  }

  root.QR = Object.freeze({ matrix, svg, scanner });
})();
