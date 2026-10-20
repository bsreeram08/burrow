import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const load = (file: string, extra: Record<string, unknown> = {}) => {
    const context: any = { URL, ...extra };
    context.window = context;
    runInNewContext(readFileSync(new URL(`../../packages/signaling/public/${file}`, import.meta.url), 'utf8'), context);
    return context;
};
const { Markdown } = load('markdown.js');
const text = (value: string) => ({ type: 'text', text: value });

describe('markdown subset', () => {
    test('inline styles nest; code spans and links are leaves', () => {
        expect(Markdown.parse('**bold _it_** ~~gone~~ `co*de*` *x*')).toEqual([{ type: 'text', children: [
            { type: 'bold', children: [text('bold '), { type: 'italic', children: [text('it')] }] }, text(' '),
            { type: 'strike', children: [text('gone')] }, text(' '), { type: 'code', text: 'co*de*' }, text(' '),
            { type: 'italic', children: [text('x')] },
        ] }]);
    });
    test('words with underscores and lone stars stay text', () => {
        for (const value of ['snake_case_name', 'a * b * c', '2*3*4', 'file_v2_final.txt']) expect(Markdown.parse(value)).toEqual([{ type: 'text', children: [text(value)] }]);
    });
    test('only https URLs link, without trailing punctuation or unbalanced parentheses', () => {
        expect(Markdown.inline('see https://ex.com/a_b_c). and http://plain.example')).toEqual([text('see '), { type: 'link', text: 'https://ex.com/a_b_c' }, text('). and http://plain.example')]);
        expect(Markdown.inline('(https://en.wikipedia.org/wiki/Foo_(bar))')).toEqual([text('('), { type: 'link', text: 'https://en.wikipedia.org/wiki/Foo_(bar)' }, text(')')]);
        expect(Markdown.inline('javascript:alert(1) https://')).toEqual([text('javascript:alert(1) https://')]);
        expect(Markdown.firstUrl('look **https://a.example/x.** now')).toBe('https://a.example/x');
        expect(Markdown.firstUrl('```\nhttps://in.code\n```')).toBeNull();
    });
    test('fenced code keeps its text verbatim with an optional language; an unclosed fence is text', () => {
        expect(Markdown.parse('```js\nlet a = "<b>**x**</b>";\n```\nafter')).toEqual([
            { type: 'code', lang: 'js', text: 'let a = "<b>**x**</b>";' }, { type: 'text', children: [text('after')] }]);
        expect(Markdown.parse('```\nunclosed')).toEqual([{ type: 'text', children: [text('```\nunclosed')] }]);
    });
    test('quote lines group into one block; HTML is never interpreted', () => {
        expect(Markdown.parse('> one **b**\n> two\nplain')).toEqual([
            { type: 'quote', children: [text('one '), { type: 'bold', children: [text('b')] }, text('\ntwo')] },
            { type: 'text', children: [text('plain')] }]);
        expect(Markdown.parse('<img src=x onerror=alert(1)>')).toEqual([{ type: 'text', children: [text('<img src=x onerror=alert(1)>')] }]);
        expect(Markdown.plainText('**hi** _there_ `x`')).toBe('hi there x');
    });
    test('deep nesting is bounded', () => {
        const deep = '**'.repeat(40) + 'x' + '**'.repeat(40);
        expect(() => Markdown.parse(deep)).not.toThrow();
    });
});

describe('command palette ranking', () => {
    const element = () => null;
    const { Palette } = load('palette.js', { document: { getElementById: element, addEventListener() {} }, localStorage: { getItem: () => null, setItem() {} } });
    test('subsequence matches score; word starts and prefixes rank higher; non-matches are dropped', () => {
        expect(Palette.score('xyz', 'Settings')).toBe(0);
        expect(Palette.score('set', 'Settings')).toBeGreaterThan(Palette.score('set', 'Reset session'));
        expect(Palette.score('td', 'Toggle density')).toBeGreaterThan(0);
        const items = ['Settings', 'Theme…', 'Toggle density', 'alice', 'bob'].map(label => ({ id: label, label }));
        expect(Palette.rank(items, 'th', []).map((item: any) => item.id)[0]).toBe('Theme…');
        expect(Palette.rank(items, '', ['bob', 'alice']).map((item: any) => item.id).slice(0, 2)).toEqual(['bob', 'alice']);
    });
});
