import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/files.js', import.meta.url), 'utf8');
/** files.js with a fake blob server: `blobs` maps an id to the ciphertext it returns. */
function load(blobs: Map<string, Uint8Array>) {
    let fetches = 0, urls = 0;
    const context: any = {
        crypto, Blob, Uint8Array, btoa, atob, performance,
        URL: { createObjectURL: () => `blob:test/${++urls}` },
        fetch: async (path: string) => { fetches++; const bytes = blobs.get(decodeURIComponent(path.split('/').pop()!)); return bytes ? new Response(bytes) : new Response('', { status: 404 }); },
        setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    };
    context.window = context;
    runInNewContext(source, context);
    return { Files: context.Files, get fetches() { return fetches; } };
}
const encoder = new TextEncoder();

describe('encrypted attachments', () => {
    test('round trip: nonce || AES-GCM ciphertext || tag, verified by SHA-256 before decrypting', async () => {
        const { Files } = load(new Map());
        const sealed = await Files.encrypt(encoder.encode('private photo'));
        expect(sealed.ciphertext.length).toBe(12 + 13 + 16);
        expect(sealed.key).toMatch(/^[A-Za-z0-9_-]{43}$/); expect(sealed.sha256).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(new TextDecoder().decode(await Files.decrypt(sealed.ciphertext, sealed.key, sealed.sha256))).toBe('private photo');
        const flipped = sealed.ciphertext.slice(); flipped[20] ^= 1;
        await expect(Files.decrypt(flipped, sealed.key, sealed.sha256)).rejects.toMatchObject({ code: 'integrity' });
    });
    test('a blob id the server reuses never serves cached content another message did not verify', async () => {
        const first = await load(new Map()).Files.encrypt(encoder.encode('alice’s photo'));
        const blobs = new Map([['sameid0123456789abcd', first.ciphertext]]);
        const harness = load(blobs), { Files } = harness;
        const genuine = { kind: 'file', blob: 'sameid0123456789abcd', key: first.key, sha256: first.sha256, mime: 'text/plain', name: 'a.txt', size: 13 };
        const shown = await Files.open(genuine);
        expect(await shown.blob.text()).toBe('alice’s photo');
        // A second message names the same blob id with its own key and hash: it must be fetched and checked again,
        // and fail, instead of reusing the first message's decrypted bytes.
        const other = await Files.encrypt(encoder.encode('something else'));
        const hostile = { ...genuine, key: other.key, sha256: other.sha256 };
        await expect(Files.open(hostile)).rejects.toMatchObject({ code: 'integrity' });
        expect(harness.fetches).toBe(2);
        expect(Files.loaded(genuine)).toBe(true); expect(Files.loaded(hostile)).toBe(false);
        // Our own upload is remembered under its own id and hash only.
        Files.remember({ blob: 'mine00000000000000000', sha256: other.sha256 }, new Blob(['x']));
        expect(Files.loaded({ blob: 'mine00000000000000000', sha256: first.sha256 })).toBe(false);
    });
    test('file names drop characters that hide or reorder the extension', () => {
        const { Files } = load(new Map());
        expect(Files.cleanName('report‮fdp.exe')).toBe('reportfdp.exe');
        expect(Files.cleanName('in⁧voice⁩‍.pdf​')).toBe('invoice.pdf');
        expect(Files.cleanName('‏‎')).toBe('file');
    });
});
