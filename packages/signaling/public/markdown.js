'use strict';
// A safe Markdown subset for message text (docs/phase1-protocol.md §1): **bold**, _italic_ / *italic*,
// ~~strike~~, `code`, fenced ``` code blocks ``` with an optional language label, `> quote` lines and
// auto-linked https:// URLs. HTML is never interpreted: parse() returns plain data and render() builds DOM
// nodes (text nodes, a few elements and https links); nothing is ever assigned to innerHTML.
(() => {
  const FENCE = /^```([A-Za-z0-9_+.#-]{0,20})\s*$/;
  // Earliest match wins; on a tie the first pattern in this list does. Code and links are leaves.
  const INLINE = [
    { type: 'code', pattern: /`([^`\n]+)`/ },
    { type: 'link', pattern: /https:\/\/[^\s<>"]+/ },
    { type: 'bold', pattern: /\*\*(?=\S)([\s\S]*?\S)\*\*/ },
    { type: 'strike', pattern: /~~(?=\S)([\s\S]*?\S)~~/ },
    { type: 'italic', pattern: /(?<![\w\\])_(?=[^\s_])([^_\n]*?[^\s_])_(?!\w)/ },
    { type: 'italic', pattern: /(?<![\w*\\])\*(?=[^\s*])([^*\n]*?[^\s*])\*(?![\w*])/ },
  ];
  const MAX_DEPTH = 6;

  /** Trims trailing punctuation a sentence puts after a URL, keeping balanced parentheses. */
  function trimUrl(url) {
    let end = url.length;
    while (end > 0) {
      const last = url[end - 1];
      if ('.,;:!?\'"*_~'.includes(last)) { end--; continue; }
      if (last === ')') {
        const open = (url.slice(0, end).match(/\(/g) || []).length, close = (url.slice(0, end).match(/\)/g) || []).length;
        if (close > open) { end--; continue; }
      }
      break;
    }
    return url.slice(0, end);
  }
  const validUrl = value => { try { const url = new URL(value); return url.protocol === 'https:' && Boolean(url.hostname); } catch { return false; } };

  /** Inline tokens: { type: 'text' | 'code' | 'link', text } or { type: 'bold' | 'italic' | 'strike', children }. */
  function inline(text, depth = 0) {
    const out = [];
    let rest = text;
    while (rest) {
      let best = null;
      if (depth < MAX_DEPTH) for (const rule of INLINE) {
        const match = rule.pattern.exec(rest);
        if (match && (!best || match.index < best.match.index)) best = { rule, match };
      }
      if (!best) { out.push({ type: 'text', text: rest }); break; }
      const { rule, match } = best;
      let length = match[0].length, token;
      if (rule.type === 'link') {
        const url = trimUrl(match[0]);
        length = url.length;
        token = url.length > 'https://'.length && validUrl(url) ? { type: 'link', text: url } : { type: 'text', text: url || match[0] };
        if (!url) length = match[0].length;
      } else if (rule.type === 'code') token = { type: 'code', text: match[1] };
      else token = { type: rule.type, children: inline(match[1], depth + 1) };
      if (match.index) out.push({ type: 'text', text: rest.slice(0, match.index) });
      out.push(token);
      rest = rest.slice(match.index + length);
    }
    // Adjacent text runs merge, so a rejected candidate never splits words into separate nodes.
    return out.reduce((all, token) => {
      const last = all.at(-1);
      if (token.type === 'text' && last?.type === 'text') last.text += token.text; else all.push(token);
      return all;
    }, []);
  }

  /**
   * Blocks: { type: 'code', lang, text } (fenced, verbatim), { type: 'quote', children } for consecutive
   * `>` lines, and { type: 'text', children } for everything else (line breaks kept as text).
   */
  function parse(source) {
    const text = typeof source === 'string' ? source : '', lines = text.split('\n'), blocks = [];
    let plain = [], quote = [];
    const flush = () => {
      if (plain.length) { blocks.push({ type: 'text', children: inline(plain.join('\n')) }); plain = []; }
      if (quote.length) { blocks.push({ type: 'quote', children: inline(quote.join('\n')) }); quote = []; }
    };
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index], fence = FENCE.exec(line);
      if (fence) {
        const close = lines.findIndex((value, at) => at > index && /^```\s*$/.test(value));
        // An unclosed fence is shown as typed: the backticks are text.
        if (close !== -1) {
          flush();
          blocks.push({ type: 'code', lang: fence[1], text: lines.slice(index + 1, close).join('\n') });
          index = close; continue;
        }
      }
      const quoted = /^>\s?(.*)$/.exec(line);
      if (quoted) { if (plain.length) flush(); quote.push(quoted[1]); }
      else { if (quote.length) flush(); plain.push(line); }
    }
    flush();
    return blocks;
  }

  /** Plain text without markers (chat list previews, notifications and find-in-conversation). */
  function plainText(source) {
    const flat = tokens => tokens.map(token => token.children ? flat(token.children) : token.text).join('');
    return parse(source).map(block => block.type === 'code' ? block.text : flat(block.children)).join('\n');
  }

  /**
   * Renders text into an element. `textNodes(text)` turns a plain run into nodes (custom emoji images);
   * by default a text node.
   */
  function render(element, source, textNodes = text => [document.createTextNode(text)]) {
    const nodes = tokens => tokens.flatMap(token => {
      if (token.type === 'text') return textNodes(token.text);
      if (token.type === 'code') { const code = document.createElement('code'); code.className = 'md-code'; code.textContent = token.text; return [code]; }
      if (token.type === 'link') {
        const link = document.createElement('a');
        link.href = token.text; link.textContent = token.text; link.target = '_blank'; link.rel = 'noopener noreferrer nofollow';
        return [link];
      }
      const tag = { bold: 'strong', italic: 'em', strike: 's' }[token.type], node = document.createElement(tag);
      node.append(...nodes(token.children));
      return [node];
    });
    const blocks = parse(source).map(block => {
      if (block.type === 'code') {
        const figure = document.createElement('div'); figure.className = 'md-pre';
        if (block.lang) { const label = document.createElement('span'); label.className = 'md-lang'; label.textContent = block.lang; figure.append(label); }
        const pre = document.createElement('pre'), code = document.createElement('code');
        code.textContent = block.text; pre.append(code); figure.append(pre);
        return figure;
      }
      if (block.type === 'quote') { const quote = document.createElement('blockquote'); quote.className = 'md-quote'; quote.append(...nodes(block.children)); return quote; }
      const span = document.createElement('span'); span.className = 'md-text'; span.append(...nodes(block.children));
      return span;
    });
    element.replaceChildren(...blocks);
  }

  /** The first https URL in text (for link previews), or null. */
  function firstUrl(source) {
    const find = tokens => { for (const token of tokens) { if (token.type === 'link') return token.text; if (token.children) { const found = find(token.children); if (found) return found; } } return null; };
    for (const block of parse(source)) if (block.type !== 'code') { const found = find(block.children); if (found) return found; }
    return null;
  }

  window.Markdown = Object.freeze({ parse, inline, render, plainText, firstUrl });
})();
