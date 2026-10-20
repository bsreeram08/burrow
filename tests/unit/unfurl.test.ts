import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { httpsTransport, isPublicAddress, safeGet, type Hop, type Lookup, type Transport } from '../../packages/signaling/safe-fetch';
import { decodeEntities, parsePreview, readTags } from '../../packages/signaling/unfurl';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
const PAGE = `<!doctype html><html><head><title>Fallback &amp; title</title>
<!-- <meta property="og:title" content="commented out"> -->
<script>var s = '<meta property="og:title" content="from a script">';</script>
<meta property="og:title" content="Caf&eacute; &quot;Ol&#233;&quot; &#x1F600; &mdash; news">
<meta name=description content='A short description'>
<meta property="og:site_name" content="Example">
<meta property="og:image" content="/images/card.png?a=1&amp;b=2">
</head><body>ignored</body></html>`;
type Page = { status?: number; type?: string; body?: string | Uint8Array; location?: string };
let dataDir: string, app: ReturnType<typeof startSignaling>, dns: Record<string, string[]>, pages: Record<string, Page>, fetched: string[];
// Stands in for the network, but connects the way the real transport does: through the checked lookup.
const transport: Transport = async (url, { resolve }) => {
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (!/^[\d.]+$|:/.test(host)) await resolve(host);
    fetched.push(url.href);
    const page = pages[url.href] ?? { status: 404 };
    const body = typeof page.body === 'string' ? new TextEncoder().encode(page.body) : page.body ?? new Uint8Array();
    const headers: Record<string, string> = { 'content-type': page.type ?? 'text/html; charset=utf-8', ...(page.location ? { location: page.location } : {}) };
    return { status: page.status ?? 200, header: name => headers[name], body: (async function* () { yield body; })(), close() {} } satisfies Hop;
};
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'unfurl-'));
    fetched = [];
    dns = { 'example.com': ['93.184.216.34'], 'cdn.example.com': ['93.184.216.35', '2606:2800:220:1::1'] };
    pages = { 'https://example.com/post': { body: PAGE }, 'https://example.com/images/card.png?a=1&b=2': { type: 'image/png', body: PNG } };
    app = startSignaling({
        adminToken: 'unfurl-test-admin-secret-000000000000000000', origin, port: 0, dataDir, unfurlTransport: transport,
        unfurlResolver: async host => { if (!dns[host]) throw new Error('NXDOMAIN'); return dns[host]!; },
    });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });
const user = (name: string) => { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; };
const unfurl = (cookie: string | undefined, target: string, path = '/api/unfurl') =>
    fetch(new URL(`${path}?url=${encodeURIComponent(target)}`, app.server.url), { headers: cookie ? { Cookie: cookie } : {} });

describe('address classification', () => {
    test('only public unicast addresses pass, whatever the notation', () => {
        const refused = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '100.100.100.200', '0.0.0.0', '224.0.0.1', '255.255.255.255', '192.0.0.192', '198.18.0.1', '192.0.2.1',
            '::', '::1', 'fe80::1', 'fd00::1', 'fd00:ec2::254', 'ff02::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a00:1', '::ffff:169.254.169.254', '::127.0.0.1', '64:ff9b::a00:1', '64:ff9b::7f00:1',
            '2001::1', '2001:db8::1', '2002:7f00:1::1', 'fe80::1%en0', 'localhost', 'not-an-ip', ''];
        for (const address of refused) expect([address, isPublicAddress(address)]).toEqual([address, false]);
        for (const address of ['93.184.216.34', '8.8.8.8', '104.21.1.1', '2606:4700::1111', '2a00:1450:4001:80b::200e', '2001:4860:4860::8888']) expect([address, isPublicAddress(address)]).toEqual([address, true]);
    });
});

describe('deadline', () => {
    test('a redirect hop that would start after the deadline is never started', async () => {
        let hops = 0;
        // Ignores the abort signal, as a slow exchange that finishes just after the deadline would.
        const slow: Transport = async () => { hops++; await Bun.sleep(80); return { status: 302, header: name => name === 'location' ? 'https://example.com/next' : undefined, body: (async function* () {})(), close() {} }; };
        const result = await safeGet('https://example.com/', { accept: '*/*', types: () => true, maxBytes: 10, transport: slow, resolver: async () => ['93.184.216.34'], timeoutMs: 50 });
        expect(result).toEqual({ ok: false, status: 504, error: 'The site took too long to answer.' });
        expect(hops).toBe(1);
    });
});

describe('preview parser', () => {
    test('OpenGraph wins over <title>; comments and scripts are skipped; entities are decoded; the image is resolved', () => {
        expect(parsePreview(PAGE, new URL('https://example.com/post'))).toEqual({
            title: 'Café "Olé" 😀 — news', description: 'A short description', site: 'Example', image: 'https://example.com/images/card.png?a=1&b=2',
        });
    });
    test('falls back to Twitter tags and <title>, bounds lengths and drops non-https images', () => {
        const html = `<title>  Plain\n  title </title><meta name="twitter:description" content="${'x'.repeat(400)}"><meta name="twitter:image" content="http://example.com/a.png"><meta property="og:site_name" content="">`;
        const preview = parsePreview(html, new URL('https://example.com/'));
        expect(preview.title).toBe('Plain title');
        expect(Array.from(preview.description!).length).toBe(300);
        expect(preview.image).toBeUndefined();
        expect(preview.site).toBeUndefined();
        expect(parsePreview('<meta property="og:title" content="Twitter loses"><meta name="twitter:title" content="x">', new URL('https://a.example/')).title).toBe('Twitter loses');
    });
    test('malformed and hostile markup ends quietly and in linear time', () => {
        expect(readTags('<meta property="og:title" content="unterminated').meta.size).toBe(0);
        expect(readTags('<script>never closed <meta property="og:title" content="x">').meta.size).toBe(0);
        const started = performance.now();
        readTags('<script'.repeat(70000)); readTags('<a "'.repeat(100000)); readTags('<!--'.repeat(100000)); readTags('<title>'.repeat(70000));
        expect(performance.now() - started).toBeLessThan(2000);
    });
    test('entities: named, decimal, hex and invalid code points', () => {
        expect(decodeEntities('&lt;b&gt; &amp;amp; &#39;&#x27; &#0; &#xD800; &#1114112; &unknown; &hellip;')).toBe("<b> &amp; '' \ufffd \ufffd \ufffd &unknown; …");
    });
});

describe('GET /api/unfurl', () => {
    test('returns the preview for a signed-in user only', async () => {
        const alice = user('alice');
        expect((await unfurl(undefined, 'https://example.com/post')).status).toBe(401);
        const response = await unfurl(alice.cookie, 'https://example.com/post');
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ url: 'https://example.com/post', title: 'Café "Olé" 😀 — news', description: 'A short description', site: 'Example', image: 'https://example.com/images/card.png?a=1&b=2' });
    });
    test('refuses non-https, other ports, credentials and private, loopback or mapped addresses before connecting', async () => {
        const alice = user('alice');
        for (const target of ['http://example.com/post', 'https://example.com:8443/post', 'https://user:pass@example.com/post', 'ftp://example.com/', 'javascript:alert(1)', 'not a url',
            'https://127.0.0.1/', 'https://2130706433/', 'https://0x7f.1/', 'https://[::1]/', 'https://[::ffff:127.0.0.1]/', 'https://[::ffff:7f00:1]/', 'https://169.254.169.254/latest/meta-data', 'https://10.0.0.1/']) {
            expect([target, (await unfurl(alice.cookie, target)).status]).toEqual([target, 400]);
            await Bun.sleep(350); // three previews a second per user
        }
        expect(fetched).toEqual([]);
    });
    test('refuses hosts whose DNS answers include any non-public address', async () => {
        const alice = user('alice');
        for (const answer of [['10.0.0.5'], ['93.184.216.34', '127.0.0.1'], ['169.254.169.254'], ['::ffff:7f00:1'], ['::ffff:10.0.0.1'], ['fd00:ec2::254'], ['100.100.100.200'], ['64:ff9b::a9fe:a9fe'], []]) {
            dns['example.com'] = answer;
            expect([answer, (await unfurl(alice.cookie, 'https://example.com/post')).status]).toEqual([answer, 400]);
            await Bun.sleep(350);
        }
        expect(fetched).toEqual([]);
    });
    test('follows at most three redirects, re-checking each target', async () => {
        const alice = user('alice');
        dns['internal.example'] = ['10.0.0.5'];
        pages['https://example.com/to-private'] = { status: 302, location: 'https://internal.example/admin' };
        pages['https://example.com/to-literal'] = { status: 301, location: 'https://[::ffff:a9fe:a9fe]/latest/meta-data' };
        pages['https://example.com/to-http'] = { status: 307, location: 'http://example.com/post' };
        pages['https://example.com/to-port'] = { status: 308, location: 'https://example.com:444/post' };
        for (const path of ['to-private', 'to-literal', 'to-http', 'to-port']) { expect([path, (await unfurl(alice.cookie, `https://example.com/${path}`)).status]).toEqual([path, 400]); await Bun.sleep(350); }
        expect(fetched.some(url => url.includes('internal.example') || url.startsWith('http:') || url.includes(':444') || url.includes('[::'))).toBe(false);
        pages['https://example.com/r1'] = { status: 302, location: '/r2' };
        pages['https://example.com/r2'] = { status: 302, location: 'https://cdn.example.com/r3' };
        pages['https://cdn.example.com/r3'] = { status: 303, location: 'https://example.com/post' };
        expect((await (await unfurl(alice.cookie, 'https://example.com/r1')).json() as any).title).toBe('Café "Olé" 😀 — news');
        await Bun.sleep(350);
        pages['https://example.com/post'] = { status: 302, location: 'https://example.com/r1' }; // a fourth redirect
        expect((await unfurl(alice.cookie, 'https://example.com/r1')).status).toBe(502);
    });
    test('only HTML is parsed, and only the first 512 KB of it', async () => {
        const alice = user('alice');
        pages['https://example.com/data'] = { type: 'application/json', body: '{}' };
        expect((await unfurl(alice.cookie, 'https://example.com/data')).status).toBe(415);
        await Bun.sleep(350);
        pages['https://example.com/long'] = { body: `<title>Early</title>${' '.repeat(600 * 1024)}<meta property="og:title" content="Too late">` };
        expect((await (await unfurl(alice.cookie, 'https://example.com/long')).json() as any).title).toBe('Early');
    });
    test('is rate limited per user', async () => {
        const alice = user('alice');
        const statuses = await Promise.all(Array.from({ length: 5 }, () => unfurl(alice.cookie, 'https://example.com/post').then(response => response.status)));
        expect(statuses.filter(status => status === 429).length).toBeGreaterThan(0);
    });
});

describe('GET /api/unfurl/image', () => {
    test('returns a raster image under a sandboxing policy', async () => {
        const alice = user('alice');
        expect((await unfurl(undefined, 'https://example.com/images/card.png?a=1&b=2', '/api/unfurl/image')).status).toBe(401);
        const response = await unfurl(alice.cookie, 'https://example.com/images/card.png?a=1&b=2', '/api/unfurl/image');
        expect(response.status).toBe(200);
        expect(response.headers.get('content-type')).toBe('image/png');
        expect(response.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
        expect(response.headers.get('x-content-type-options')).toBe('nosniff');
        expect(new Uint8Array(await response.arrayBuffer())).toEqual(PNG);
    });
    test('refuses non-images, SVG, bytes that are not an image, oversize images and private addresses', async () => {
        const alice = user('alice');
        pages['https://example.com/page'] = { body: PAGE };
        pages['https://example.com/a.svg'] = { type: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' };
        pages['https://example.com/fake.png'] = { type: 'image/png', body: '<html><script>alert(1)</script>' };
        pages['https://example.com/huge.png'] = { type: 'image/png', body: new Uint8Array([...PNG, ...new Uint8Array(2 * 1024 * 1024)]) };
        const expected: [string, number][] = [['page', 415], ['a.svg', 415], ['fake.png', 415], ['huge.png', 413]];
        for (const [path, status] of expected) { expect([path, (await unfurl(alice.cookie, `https://example.com/${path}`, '/api/unfurl/image')).status]).toEqual([path, status]); await Bun.sleep(350); }
        dns['example.com'] = ['192.168.0.10'];
        expect((await unfurl(alice.cookie, 'https://example.com/images/card.png?a=1&b=2', '/api/unfurl/image')).status).toBe(400);
    });
});

// The real transport under Bun: the hostname exists only in our lookup, so a successful TLS exchange proves the
// socket connected to the address the lookup returned, and the certificate was checked against the hostname.
describe.skipIf(!Bun.which('openssl'))('pinned HTTPS transport', () => {
    let server: ReturnType<typeof Bun.serve>, cert: string, hits = 0;
    beforeAll(async () => {
        const directory = await mkdtemp(join(tmpdir(), 'pinned-'));
        Bun.spawnSync(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'), '-days', '1', '-subj', '/CN=pinned.test', '-addext', 'subjectAltName=DNS:pinned.test']);
        cert = await Bun.file(join(directory, 'cert.pem')).text();
        server = Bun.serve({ hostname: '127.0.0.1', port: 0, tls: { key: await Bun.file(join(directory, 'key.pem')).text(), cert }, fetch: request => { hits++; return new Response(`host ${request.headers.get('host')}`); } });
        await rm(directory, { recursive: true, force: true });
    });
    afterAll(() => server?.stop(true));
    const lookupTo = (address: string | null, seen: string[]): Lookup => (hostname, options, callback) => {
        seen.push(hostname);
        if (!address) { callback(new Error('Address refused'), ''); return; }
        if (options?.all) callback(null, [{ address, family: 4 }]); else callback(null, address, 4);
    };
    const exchange = async (lookup: Lookup, ca?: string) => {
        const hop = await httpsTransport(ca ? { ca } : {})(new URL(`https://pinned.test:${server.port}/`), { lookup, resolve: async () => [], signal: AbortSignal.timeout(3000), accept: '*/*' });
        let text = '';
        for await (const chunk of hop.body) text += Buffer.from(chunk).toString();
        hop.close();
        return { status: hop.status, text };
    };
    test('connects to the looked-up address and verifies the certificate for the hostname', async () => {
        const seen: string[] = [];
        expect(await exchange(lookupTo('127.0.0.1', seen), cert)).toEqual({ status: 200, text: `host pinned.test:${server.port}` });
        expect(seen).toEqual(['pinned.test']);
        await expect(exchange(lookupTo('127.0.0.1', []))).rejects.toThrow(); // untrusted certificate
    });
    test('every request runs the lookup (no pooled socket), and a refused lookup never connects', async () => {
        const seen: string[] = [], before = hits;
        await exchange(lookupTo('127.0.0.1', seen), cert);
        await expect(exchange(lookupTo(null, seen), cert)).rejects.toThrow('Address refused');
        expect(seen).toEqual(['pinned.test', 'pinned.test']);
        expect(hits).toBe(before + 1);
    });
});
