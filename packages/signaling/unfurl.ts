import { requestLimiter } from './rate-limit';
import { safeGet, type Resolver, type Transport } from './safe-fetch';

// Link previews, generated for the sender only: the server fetches the page (or its preview image) the sender is
// about to share and returns its OpenGraph/Twitter/<title> metadata. Receivers never fetch. Network rules live
// in safe-fetch.ts; this module bounds what is read and what is returned.
export const PAGE_MAX = 512 * 1024, IMAGE_MAX = 2 * 1024 * 1024;
export type Preview = { url: string; title?: string; description?: string; site?: string; image?: string };
type User = { id: string };
const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
// Latin-1 (U+00A0–U+00FF) in code-point order, then the punctuation pages commonly use.
const LATIN1 = 'nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest Agrave Aacute Acirc Atilde Auml Aring AElig Ccedil Egrave Eacute Ecirc Euml Igrave Iacute Icirc Iuml ETH Ntilde Ograve Oacute Ocirc Otilde Ouml times Oslash Ugrave Uacute Ucirc Uuml Yacute THORN szlig agrave aacute acirc atilde auml aring aelig ccedil egrave eacute ecirc euml igrave iacute icirc iuml eth ntilde ograve oacute ocirc otilde ouml divide oslash ugrave uacute ucirc uuml yacute thorn yuml';
const ENTITIES: Record<string, string> = {
    ...Object.fromEntries(LATIN1.split(' ').map((name, index) => [name, String.fromCharCode(0xa0 + index)])),
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", hellip: '\u2026', mdash: '\u2014', ndash: '\u2013', lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201c', rdquo: '\u201d',
    sbquo: '\u201a', bdquo: '\u201e', bull: '\u2022', trade: '\u2122', euro: '\u20ac', thinsp: '\u2009', ensp: '\u2002', emsp: '\u2003', zwj: '\u200d', zwnj: '\u200c',
};

/** Named (common set) and numeric character references; invalid code points become U+FFFD. */
export function decodeEntities(text: string): string {
    return text.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));?/g, (whole, decimal?: string, hex?: string, name?: string) => {
        if (name !== undefined) return ENTITIES[name] ?? (/^(AMP|LT|GT|QUOT)$/.test(name) ? ENTITIES[name.toLowerCase()]! : whole);
        const code = decimal !== undefined ? Number(decimal) : parseInt(hex!, 16);
        return code === 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ? '\ufffd' : String.fromCodePoint(code);
    });
}
/** Decoded, single-line, without control or bidi-override characters, at most `max` code points. */
function clean(value: string | undefined, max: number) {
    if (value === undefined) return undefined;
    const text = decodeEntities(value).replace(/[\u00ad\u200b\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g, '').replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ').replace(/\s+/g, ' ').trim();
    const points = Array.from(text);
    return !text ? undefined : points.length > max ? `${points.slice(0, max - 1).join('').trimEnd()}…` : text;
}
const ATTRIBUTE = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

/**
 * Extracts <meta property|name content> pairs and the first <title> in one linear pass. Comments, <script> and
 * <style> bodies are skipped; markup is never interpreted beyond that.
 */
export function readTags(html: string): { meta: Map<string, string>; title?: string } {
    const meta = new Map<string, string>();
    let title: string | undefined, index = 0;
    const closing = (name: string, from: number) => { const pattern = new RegExp(`</${name}\\s*>`, 'gi'); pattern.lastIndex = from; const match = pattern.exec(html); return match ? { start: match.index, end: pattern.lastIndex } : null; };
    while (index < html.length) {
        const open = html.indexOf('<', index);
        if (open < 0) break;
        if (html.startsWith('<!--', open)) { const end = html.indexOf('-->', open + 4); if (end < 0) break; index = end + 3; continue; }
        const name = /^[a-zA-Z][a-zA-Z0-9-]*/.exec(html.slice(open + 1, open + 33))?.[0]?.toLowerCase();
        if (!name) { index = open + 1; continue; }
        // The tag ends at the first '>' outside quotes.
        let end = open + 1 + name.length, quote = '';
        for (; end < html.length; end++) {
            const char = html[end]!;
            if (quote) { if (char === quote) quote = ''; } else if (char === '"' || char === "'") quote = char; else if (char === '>') break;
        }
        if (end >= html.length) break;
        const body = html.slice(open + 1 + name.length, end);
        index = end + 1;
        if (name === 'meta') {
            const attributes = new Map<string, string>();
            for (const match of body.matchAll(ATTRIBUTE)) { const key = match[1]!.toLowerCase(); if (!attributes.has(key)) attributes.set(key, match[2] ?? match[3] ?? match[4] ?? ''); }
            const key = (attributes.get('property') ?? attributes.get('name'))?.toLowerCase(), content = attributes.get('content');
            if (key && content !== undefined && !meta.has(key) && meta.size < 256) meta.set(key, content.slice(0, 4096));
        } else if (name === 'script' || name === 'style' || name === 'title') {
            const close = closing(name, index);
            if (name === 'title' && title === undefined) title = html.slice(index, close?.start ?? Math.min(html.length, index + 4096)).slice(0, 4096);
            if (!close) break;
            index = close.end;
        }
    }
    return { meta, ...(title !== undefined ? { title } : {}) };
}

/** The preview fields from a page, bounded as the message payload requires; the image only as an https URL. */
export function parsePreview(html: string, url: URL): Omit<Preview, 'url'> {
    const { meta, title } = readTags(html);
    const pick = (...keys: string[]) => keys.map(key => meta.get(key)).find(value => value !== undefined && value.trim() !== '');
    const preview: Omit<Preview, 'url'> = {};
    const fields = {
        title: clean(pick('og:title', 'twitter:title') ?? title, 200),
        description: clean(pick('og:description', 'twitter:description', 'description'), 300),
        site: clean(pick('og:site_name', 'application-name'), 60),
    };
    for (const [key, value] of Object.entries(fields)) if (value) preview[key as keyof typeof fields] = value;
    const raw = pick('og:image:secure_url', 'og:image', 'og:image:url', 'twitter:image', 'twitter:image:src');
    if (raw) {
        try {
            const image = new URL(decodeEntities(raw.trim()), url);
            if (image.protocol === 'https:' && !image.username && !image.password && image.href.length <= 2048) preview.image = image.href;
        } catch {}
    }
    return preview;
}

/** Raster formats a client can downscale, recognised by their bytes (SVG and anything else is refused). */
export function imageType(bytes: Uint8Array): string | null {
    const ascii = (start: number, end: number) => String.fromCharCode(...bytes.subarray(start, end));
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
    if (bytes.length >= 8 && bytes[0] === 0x89 && ascii(1, 8) === 'PNG\r\n\x1a\n') return 'image/png';
    if (bytes.length >= 6 && (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a')) return 'image/gif';
    if (bytes.length >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WEBP') return 'image/webp';
    if (bytes.length >= 12 && ascii(4, 8) === 'ftyp' && ['avif', 'avis'].includes(ascii(8, 12))) return 'image/avif';
    return null;
}

function decode(bytes: Uint8Array, charset?: string) {
    try { return new TextDecoder((charset || 'utf-8') as ConstructorParameters<typeof TextDecoder>[0]).decode(bytes); } catch { return new TextDecoder().decode(bytes); }
}

export function createUnfurl(options: { resolver?: Resolver; transport?: Transport } = {}) {
    const allow = requestLimiter({ perSource: 3, global: 100 });
    // Fetches hold sockets for up to five seconds: bound them per user and overall.
    const inflight = new Map<string, number>();
    let total = 0;
    async function limited<T>(userId: string, work: () => Promise<T>): Promise<T | null> {
        if ((inflight.get(userId) ?? 0) >= 4 || total >= 64) return null;
        inflight.set(userId, (inflight.get(userId) ?? 0) + 1); total++;
        try { return await work(); } finally {
            total--;
            const left = (inflight.get(userId) ?? 1) - 1;
            if (left) inflight.set(userId, left); else inflight.delete(userId);
        }
    }
    async function handle(request: Request, url: URL, user: User | null): Promise<Response> {
        if (request.method !== 'GET' || !['/api/unfurl', '/api/unfurl/image'].includes(url.pathname)) return json({ error: 'Not found' }, 404);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const target = url.searchParams.get('url') ?? '';
        if (!target || target.length > 2048) return json({ error: 'Send the address as ?url=https://…' }, 400);
        if (!allow(user.id)) return json({ error: 'Rate limited' }, 429);
        const network = { resolver: options.resolver, transport: options.transport };
        if (url.pathname === '/api/unfurl') {
            const page = await limited(user.id, () => safeGet(target, { ...network, accept: 'text/html,application/xhtml+xml', types: type => type === 'text/html' || type === 'application/xhtml+xml', maxBytes: PAGE_MAX, truncate: true }));
            if (!page) return json({ error: 'Too many previews at once.' }, 429);
            if (!page.ok) return json({ error: page.error }, page.status);
            return json({ url: new URL(target).href, ...parsePreview(decode(page.bytes, page.charset), page.url) } satisfies Preview);
        }
        const image = await limited(user.id, () => safeGet(target, { ...network, accept: 'image/avif,image/webp,image/png,image/jpeg,image/gif', types: type => type.startsWith('image/'), maxBytes: IMAGE_MAX }));
        if (!image) return json({ error: 'Too many previews at once.' }, 429);
        if (!image.ok) return json({ error: image.error }, image.status);
        const type = imageType(image.bytes);
        if (!type) return json({ error: 'Only JPEG, PNG, GIF, WebP or AVIF images can be previewed.' }, 415);
        // Third-party bytes on this origin: exact sniffed type, never rendered as a document.
        return new Response(image.bytes, { headers: {
            'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Cache-Control': 'no-store',
            'Content-Disposition': 'attachment', 'Cross-Origin-Resource-Policy': 'same-origin', 'Referrer-Policy': 'no-referrer',
        } });
    }
    return { handle };
}
export type Unfurl = ReturnType<typeof createUnfurl>;
