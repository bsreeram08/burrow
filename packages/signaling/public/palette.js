'use strict';
// Command palette (⌘K / Ctrl+K, or the search button on phones): fuzzy search over conversations and actions,
// with recently used items first. Other scripts register providers that return items on demand, so the list is
// always current: { id, label, hint?, group, run(), keywords? }. Arrow keys move, Enter runs, Escape closes.
(() => {
  const $ = id => document.getElementById(id);
  const providers = new Set(), RECENT_KEY = 'palette-recent-v1', MAX_RESULTS = 30;
  let items = [], results = [], index = 0, opener = null;

  /**
   * Scores `query` against `text` as a subsequence: 0 for no match; higher for matches at word starts,
   * consecutive runs and an early first letter. Pure, so it is unit tested.
   */
  function score(query, text) {
    const wanted = String(query || '').toLowerCase().replace(/\s+/g, ''), hay = String(text || '').toLowerCase();
    if (!wanted) return 1;
    let total = 0, from = 0, run = 0, first = -1;
    for (const character of wanted) {
      const at = hay.indexOf(character, from);
      if (at === -1) return 0;
      if (first === -1) first = at;
      const wordStart = at === 0 || /[\s@/_.-]/.test(hay[at - 1]);
      run = at === from && from > 0 ? run + 1 : 0;
      total += 1 + (wordStart ? 6 : 0) + run * 3;
      from = at + 1;
    }
    if (hay.startsWith(wanted)) total += 20;
    return total + Math.max(0, 10 - first) - hay.length * 0.01;
  }
  const recent = () => { try { const list = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); return Array.isArray(list) ? list.filter(value => typeof value === 'string').slice(0, 8) : []; } catch { return []; } };
  const remember = id => { try { localStorage.setItem(RECENT_KEY, JSON.stringify([id, ...recent().filter(value => value !== id)].slice(0, 8))); } catch {} };

  /** Ranks items for a query: with no query, recent items first and then the rest in provider order. */
  function rank(list, query, recentIds = []) {
    const order = new Map(recentIds.map((id, position) => [id, position]));
    if (!query.trim()) return [...list].sort((a, b) => (order.has(a.id) ? order.get(a.id) : 99) - (order.has(b.id) ? order.get(b.id) : 99));
    return list.map(item => ({ item, value: Math.max(score(query, item.label), score(query, item.keywords || '') * 0.8) + (order.has(item.id) ? 4 - order.get(item.id) * 0.4 : 0) }))
      .filter(entry => entry.value > 0).sort((a, b) => b.value - a.value).map(entry => entry.item);
  }

  function collect() {
    const all = [];
    for (const provider of providers) { try { for (const item of provider() || []) if (item && typeof item.id === 'string' && typeof item.run === 'function') all.push(item); } catch {} }
    return all;
  }
  function paint() {
    const query = $('palette-input').value;
    results = rank(items, query, recent()).slice(0, MAX_RESULTS);
    index = Math.min(index, Math.max(0, results.length - 1));
    let group = null;
    const rows = [];
    results.forEach((item, position) => {
      if (item.group !== group) { group = item.group; const heading = document.createElement('li'); heading.className = 'palette-group'; heading.setAttribute('role', 'presentation'); heading.textContent = group; rows.push(heading); }
      const row = document.createElement('li');
      row.id = `palette-item-${position}`; row.className = 'palette-item'; row.setAttribute('role', 'option'); row.dataset.index = String(position);
      row.setAttribute('aria-selected', String(position === index));
      const label = document.createElement('span'); label.className = 'palette-label'; label.textContent = item.label;
      row.append(label);
      if (item.hint) { const hint = document.createElement('span'); hint.className = 'palette-hint'; hint.textContent = item.hint; row.append(hint); }
      rows.push(row);
    });
    $('palette-list').replaceChildren(...rows);
    $('palette-empty').hidden = results.length > 0;
    highlight(index);
  }
  function highlight(next) {
    if (!results.length) { $('palette-input').removeAttribute('aria-activedescendant'); return; }
    index = (next + results.length) % results.length;
    for (const row of $('palette-list').querySelectorAll('.palette-item')) row.setAttribute('aria-selected', String(Number(row.dataset.index) === index));
    const active = $(`palette-item-${index}`);
    $('palette-input').setAttribute('aria-activedescendant', active.id); active.scrollIntoView?.({ block: 'nearest' });
  }
  function open() {
    if (!$('palette')) return;
    opener = document.activeElement;
    items = collect(); index = 0;
    $('palette-input').value = '';
    $('palette').hidden = false; paint(); $('palette-input').focus();
  }
  function close(restore = true) {
    $('palette').hidden = true;
    if (restore && opener?.isConnected) opener.focus?.();
    opener = null;
  }
  function choose(position) {
    const item = results[position];
    if (!item) return;
    remember(item.id); close(false);
    try { item.run(); } catch {}
  }

  if ($('palette')) {
    $('palette-input').addEventListener('input', () => { index = 0; paint(); });
    $('palette-input').addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); highlight(index + (event.key === 'ArrowDown' ? 1 : -1)); }
      else if (event.key === 'Enter' && !event.isComposing) { event.preventDefault(); choose(index); }
      else if (event.key === 'Escape') { event.preventDefault(); close(); }
    });
    $('palette-list').addEventListener('mousedown', event => event.preventDefault());
    $('palette-list').addEventListener('click', event => { const row = event.target.closest?.('.palette-item'); if (row) choose(Number(row.dataset.index)); });
    $('palette').addEventListener('click', event => { if (event.target === $('palette')) close(); });
    document.addEventListener('keydown', event => {
      if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        if ($('palette').hidden) open(); else close();
      }
    });
    for (const id of ['chats-search', 'conv-search']) $(id)?.addEventListener('click', open);
  }

  window.Palette = Object.freeze({ register: provider => { providers.add(provider); return () => providers.delete(provider); }, open, close, score, rank });
})();
