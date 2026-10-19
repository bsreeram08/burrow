import { lookup as dnsLookup } from 'node:dns/promises';
import { request } from 'node:https';
import { isIP } from 'node:net';

// Outbound HTTPS for link previews, safe against SSRF. The address check runs inside the socket's DNS lookup, so
// the address that is checked is the address that is connected to (no rebinding window), and it runs again for
// every redirect. Only https on port 443, no credentials in URLs, bounded time and bytes.
export type Resolver = (host: string) => Promise<string[]>;
type LookupCallback = (error: Error | null, address: string | { address: string; family: number }[], family?: number) => void;
export type Lookup = (hostname: string, options: { all?: boolean }, callback: LookupCallback) => void;
/** One HTTP exchange; the body is streamed so callers can stop at their byte cap. */
export type Hop = { status: number; header(name: string): string | undefined; body: AsyncIterable<Uint8Array>; close(): void };
/** `resolve` is the checked DNS lookup (throws for a refused address); `lookup` is the same, for node:net. */
export type Transport = (url: URL, options: { resolve: Resolver; lookup: Lookup; signal: AbortSignal; accept: string }) => Promise<Hop>;
export type Fetched = { ok: true; url: URL; type: string; charset?: string; bytes: Uint8Array } | { ok: false; status: 400 | 413 | 415 | 502 | 504; error: string };
export const MAX_REDIRECTS = 3, FETCH_TIMEOUT = 5000;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

function publicV4(address: string) {
    const [a, b, c] = address.split('.').map(Number) as [number, number, number];
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 ||
        a === 192 && b === 168 || a === 192 && b === 0 && (c === 0 || c === 2) || a === 192 && b === 88 && c === 99 || a === 198 && (b === 18 || b === 19) ||
        a === 198 && b === 51 && c === 100 || a === 203 && b === 0 && c === 113);
}
/** The first two 16-bit groups of a valid IPv6 address (enough to classify it). */
function v6Prefix(address: string): [number, number] {
    const [head = '', tail] = address.split('::');
    const groups = head ? head.split(':') : [];
    if (groups.length < 2 && tail !== undefined) groups.push(...Array(2).fill('0'));
    return [parseInt(groups[0] ?? '0', 16), parseInt(groups[1] ?? '0', 16)];
}
/**
 * Whether an address is globally routable unicast. IPv4: not private, loopback, link-local (cloud metadata),
 * CGNAT, multicast, reserved, benchmarking or documentation. IPv6: only 2000::/3, which excludes loopback,
 * unspecified, ULA, link-local, multicast and every IPv4-embedding form (mapped, compatible, NAT64); within it the
 * IETF special-purpose block (Teredo, ORCHID), 6to4 and documentation ranges are refused too.
 */
export function isPublicAddress(address: string): boolean {
    if (isIP(address) === 4) return publicV4(address);
    if (isIP(address) !== 6 || address.includes('%')) return false;
    const [first, second] = v6Prefix(address.toLowerCase());
    if ((first & 0xe000) !== 0x2000) return false;
    return !(first === 0x2001 && (second < 0x200 || second === 0xdb8) || first === 0x2002 || first === 0x3fff && second < 0x1000);
}

const defaultResolver: Resolver = async host => (await dnsLookup(host, { all: true, verbatim: true })).map(entry => entry.address);
/** Real network: node:https with the checked lookup. No agent, so no pooled socket can skip the lookup. */
export function httpsTransport(tls: { ca?: string } = {}): Transport {
    return (url, { lookup, signal, accept }) => new Promise<Hop>((resolve, reject) => {
        const req = request({
            hostname: url.hostname, port: url.port || 443, path: `${url.pathname}${url.search}`, method: 'GET', agent: false, lookup, ca: tls.ca,
            headers: { Host: url.host, Accept: accept, 'Accept-Encoding': 'identity', 'User-Agent': 'Mozilla/5.0 (compatible; LinkPreview/1.0)', Connection: 'close' },
        }, response => {
            signal.addEventListener('abort', () => response.destroy(new Error('timeout')), { once: true });
            const value = (name: string) => { const header = response.headers[name]; return Array.isArray(header) ? header[0] : header; };
            resolve({ status: response.statusCode ?? 0, header: value, body: response, close: () => response.destroy() });
        });
        signal.addEventListener('abort', () => req.destroy(new Error('timeout')), { once: true });
        req.on('error', reject);
        req.end();
    });
}

/** Plain https URL on port 443 without credentials; IP literals must be public. */
function target(url: URL) {
    if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return false;
    const host = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
    return Boolean(host) && (!isIP(host) || isPublicAddress(host));
}

/**
 * GET with redirects followed by hand (each one re-checked), one deadline for the whole exchange, a content-type
 * filter and a byte cap. With `truncate`, a longer body is cut at the cap instead of refused.
 */
export async function safeGet(raw: string, options: { accept: string; types: (type: string) => boolean; maxBytes: number; truncate?: boolean; resolver?: Resolver; transport?: Transport; timeoutMs?: number }): Promise<Fetched> {
    let url: URL;
    try { url = new URL(raw); } catch { return { ok: false, status: 400, error: 'That is not a web address.' }; }
    const resolver = options.resolver ?? defaultResolver, transport = options.transport ?? httpsTransport();
    const signal = AbortSignal.timeout(options.timeoutMs ?? FETCH_TIMEOUT);
    let refused = false;
    const resolve: Resolver = async host => {
        const addresses = await resolver(host);
        if (!addresses.length || !addresses.every(isPublicAddress)) { refused = true; throw new Error('Address refused'); }
        return addresses;
    };
    const lookup: Lookup = (hostname, lookupOptions, callback) => {
        resolve(hostname).then(addresses => {
            if (lookupOptions?.all) callback(null, addresses.map(address => ({ address, family: isIP(address) })));
            else callback(null, addresses[0]!, isIP(addresses[0]!));
        }, error => callback(error, ''));
    };
    for (let hop = 0; ; hop++) {
        if (signal.aborted) return { ok: false, status: 504, error: 'The site took too long to answer.' };
        if (!target(url)) return { ok: false, status: 400, error: 'Only public https addresses can be previewed.' };
        let response: Hop;
        try { response = await transport(url, { resolve, lookup, signal, accept: options.accept }); }
        catch {
            if (refused) return { ok: false, status: 400, error: 'Only public https addresses can be previewed.' };
            return signal.aborted ? { ok: false, status: 504, error: 'The site took too long to answer.' } : { ok: false, status: 502, error: 'The site could not be reached.' };
        }
        if (REDIRECTS.has(response.status)) {
            response.close();
            const location = response.header('location');
            if (hop >= MAX_REDIRECTS || !location) return { ok: false, status: 502, error: 'The site redirected too many times.' };
            try { url = new URL(location, url); } catch { return { ok: false, status: 502, error: 'The site redirected to an invalid address.' }; }
            continue;
        }
        if (response.status < 200 || response.status > 299) { response.close(); return { ok: false, status: 502, error: `The site answered HTTP ${response.status}.` }; }
        const [mime = '', ...parameters] = (response.header('content-type') ?? '').split(';').map(part => part.trim());
        const type = mime.toLowerCase();
        if (!options.types(type)) { response.close(); return { ok: false, status: 415, error: 'That address is not the expected kind of content.' }; }
        const declared = Number(response.header('content-length') || 0);
        if (declared > options.maxBytes && !options.truncate) { response.close(); return { ok: false, status: 413, error: 'That content is too large.' }; }
        const chunks: Uint8Array[] = []; let size = 0;
        try {
            for await (const chunk of response.body) {
                const room = options.maxBytes - size;
                if (chunk.byteLength > room) {
                    if (!options.truncate) return { ok: false, status: 413, error: 'That content is too large.' };
                    chunks.push(chunk.subarray(0, room)); size += room; break;
                }
                chunks.push(chunk); size += chunk.byteLength;
            }
        } catch { return signal.aborted ? { ok: false, status: 504, error: 'The site took too long to answer.' } : { ok: false, status: 502, error: 'The site could not be reached.' }; }
        finally { response.close(); }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const charset = parameters.find(part => /^charset=/i.test(part))?.slice(8).replace(/"/g, '').trim();
        return { ok: true, url, type, bytes, ...(charset ? { charset } : {}) };
    }
}
