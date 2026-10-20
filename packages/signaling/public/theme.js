'use strict';
// Cosmetic themes: preset palettes, a custom accent, and per-chat theme + wallpaper overrides.
// Preferences live in this browser only (localStorage, per account); they never reach the server.
(() => {
  const $ = id => document.getElementById(id);
  const PRESETS = {
    midnight: { name: 'Midnight', scheme: 'dark', bg: '#111820', surface: '#192733', 'surface-2': '#20303c', raised: '#263d4c', line: '#344755', 'line-strong': '#647987', text: '#eef4f9', muted: '#afbfcc', accent: '#a1efce', mine: '#244535', theirs: '#20303c', danger: '#e2606e', 'danger-bg': '#562d35', warn: '#f2c14e', 'warn-bg': '#3d321a', wallpaper: 'none' },
    fsociety: { name: 'fsociety', scheme: 'dark', mono: true, bg: '#040805', surface: '#09110b', 'surface-2': '#0e1a11', raised: '#142418', line: '#1c3322', 'line-strong': '#2f5a39', text: '#c9f7c8', muted: '#7cb487', accent: '#3dff73', mine: '#0f2b17', theirs: '#0c1810', danger: '#ff4d5e', 'danger-bg': '#3a1015', warn: '#e8d44d', 'warn-bg': '#2a260c', wallpaper: 'circuit' },
    light: { name: 'Daylight', scheme: 'light', bg: '#f4f6f8', surface: '#ffffff', 'surface-2': '#eaeff3', raised: '#dfe6ec', line: '#d3dce3', 'line-strong': '#a3b1bc', text: '#13202a', muted: '#52616c', accent: '#0a7a52', mine: '#d4f3e4', theirs: '#ffffff', danger: '#c2334a', 'danger-bg': '#fbe1e5', warn: '#7d5800', 'warn-bg': '#fff1c7', wallpaper: 'dots' },
    amoled: { name: 'AMOLED', scheme: 'dark', bg: '#000000', surface: '#0b0b0b', 'surface-2': '#141414', raised: '#1e1e1e', line: '#262626', 'line-strong': '#454545', text: '#f2f2f2', muted: '#a6a6a6', accent: '#8ab4ff', mine: '#15253f', theirs: '#161616', danger: '#ff6b78', 'danger-bg': '#3b141a', warn: '#ffd166', 'warn-bg': '#2e2510', wallpaper: 'none' },
    dusk: { name: 'Dusk', scheme: 'dark', bg: '#16111e', surface: '#1f1829', 'surface-2': '#292034', raised: '#342a42', line: '#3d3150', 'line-strong': '#6b5b82', text: '#f4eefb', muted: '#c4b7d8', accent: '#f6a8cb', mine: '#4a2944', theirs: '#292034', danger: '#ff6f86', 'danger-bg': '#4a1f2c', warn: '#f7c86b', 'warn-bg': '#3a2c18', wallpaper: 'gradient' },
    ocean: { name: 'Ocean', scheme: 'dark', bg: '#0a1520', surface: '#0f1f2e', 'surface-2': '#14283b', raised: '#1b344d', line: '#233f5a', 'line-strong': '#4b6a89', text: '#eaf3fb', muted: '#a8bfd3', accent: '#6fcbff', mine: '#153a59', theirs: '#14283b', danger: '#ff6b78', 'danger-bg': '#45202a', warn: '#f5c451', 'warn-bg': '#382d14', wallpaper: 'lines' },
  };
  const WALLPAPERS = { none: 'None', dots: 'Dots', grid: 'Grid', lines: 'Lines', gradient: 'Glow', circuit: 'Circuit' };
  const HEX = /^#[0-9a-f]{6}$/i, MAX_CHATS = 300;
  // Theme families (docs/phase1-protocol.md §6): each has a light and a dark variant, and "System" follows the OS.
  // Keys are `<family>-light`, `<family>-dark` and `<family>-system`; the presets above stay available.
  const SANS = 'system-ui, -apple-system, "Segoe UI", sans-serif', SERIF = 'Georgia, "New York", "Iowan Old Style", "Times New Roman", serif', MONO = 'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, monospace';
  const FAMILIES = {
    classic: { name: 'Classic', mood: 'Off-white by day, charcoal by night, with an indigo accent.', light: ['#fbf8f3', '#f2ede4', '#1f1b16', '#5869e9'], dark: ['#121214', '#1c1c20', '#eceae6', '#7c8bff'] },
    forest: { name: 'Forest', mood: 'Muted greens with a deep green accent.', light: ['#f3f6f2', '#e5ece3', '#18231b', '#2f7a4f'], dark: ['#0f1712', '#17221b', '#e3ede5', '#5fbf86'] },
    ocean: { name: 'Ocean', mood: 'Pale aqua with a teal accent.', light: ['#f1f8f8', '#e0eff0', '#0f2328', '#0f8a9d'], dark: ['#0b1a1e', '#12262b', '#e0f1f3', '#3cc6d8'] },
    dusk: { name: 'Dusk', mood: 'Soft violet with a purple accent and a touch of coral.', light: ['#f7f3fb', '#ece4f5', '#221a2b', '#7b4fd6'], dark: ['#17121f', '#221a2d', '#eee6f7', '#b08cff'], secondary: '#ff9a76' },
    rose: { name: 'Rose', mood: 'Pale pink with a crimson accent.', light: ['#fdf4f5', '#f8e5e8', '#2a1418', '#c8305a'], dark: ['#1c1013', '#2a181d', '#f7e6ea', '#ff6f93'] },
    paper: { name: 'Paper', mood: 'Cream and brown, with serif text.', light: ['#f6f0e4', '#ede4d2', '#2b2118', '#a44a26'], dark: ['#1a1611', '#26201a', '#efe6d6', '#e07a4f'], font: SERIF },
    mono: { name: 'Mono', mood: 'Black, white and grey in a monospaced font, with square avatars.', light: ['#ffffff', '#f2f2f2', '#111111', '#111111'], dark: ['#0a0a0a', '#161616', '#ededed', '#ededed'], font: MONO, square: true, plain: true },
    midnight: { name: 'Midnight', mood: 'Pure black for OLED screens, with a bright blue accent.', dark: ['#000000', '#0e0e10', '#f5f5f7', '#3d7bff'], vivid: true },
  };
  // Name colours: 8 per scheme, picked by a hash of the person's id (Mono keeps names plain).
  const NAMES = {
    light: ['#b4232c', '#a1490c', '#7a5c00', '#2d7a1e', '#0b7366', '#1f5fbf', '#6b3fc4', '#a3307e'],
    dark: ['#ff8a8a', '#ffb063', '#f2d45c', '#7fdb8a', '#5fd6c8', '#7fb2ff', '#b79cff', '#f78bd0'],
    vivid: ['#ff5c5c', '#ff9f1c', '#ffe14d', '#3dff8c', '#2ef2e2', '#4d9cff', '#b266ff', '#ff4fd8'],
  };

  // ---------- Color math (WCAG relative luminance and contrast) ----------
  const rgb = hex => [1, 3, 5].map(index => parseInt(hex.slice(index, index + 2), 16));
  const hex = values => '#' + values.map(value => Math.round(Math.min(255, Math.max(0, value))).toString(16).padStart(2, '0')).join('');
  const luminance = color => { const [r, g, b] = rgb(color).map(value => { value /= 255; return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const contrast = (a, b) => { const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const mix = (a, b, amount) => { const [p, q] = [rgb(a), rgb(b)]; return hex(p.map((value, index) => value * amount + q[index] * (1 - amount))); };
  const ink = color => contrast(color, '#ffffff') >= contrast(color, '#0b0f12') ? '#ffffff' : '#0b0f12';

  const best = color => Math.max(contrast(color, '#ffffff'), contrast(color, '#0b0f12'));
  /** The nearest colour to `color` that some text colour can sit on at 4.5:1 (most colours already can). */
  function readable(color) {
    let out = color;
    for (let step = 1; step <= 20 && best(out) < 4.5; step++) out = mix(color, luminance(color) > 0.18 ? '#000000' : '#ffffff', 1 - step * 0.03);
    return out;
  }
  /** `fore` mixed toward `back` as far as it can go while keeping 4.5:1 on every listed background. */
  function quiet(fore, back, grounds, start = 0.62) {
    let amount = start, out = mix(fore, back, amount);
    while (grounds.some(ground => contrast(out, ground) < 4.5) && amount < 1) { amount += 0.04; out = mix(fore, back, Math.min(1, amount)); }
    return out;
  }
  function familyPreset(key, scheme) {
    const family = FAMILIES[key], [bg, surface, text, accent] = family[scheme], light = scheme === 'light';
    return {
      name: family[light ? 'dark' : 'light'] ? `${family.name} ${light ? 'light' : 'dark'}` : family.name, family: key, scheme, font: family.font, square: family.square, plain: family.plain,
      bg, surface, 'surface-2': mix(text, surface, 0.05), raised: mix(text, surface, 0.1), line: mix(text, bg, 0.13), 'line-strong': mix(text, bg, 0.36),
      text, muted: quiet(text, bg, [bg, surface]), accent, mine: accent, theirs: surface,
      danger: light ? '#b3263e' : '#ff6b78', 'danger-bg': light ? '#fbe1e5' : '#45202a', warn: light ? '#7d5800' : '#f5c451', 'warn-bg': light ? '#fff1c7' : '#382d14',
      wallpaper: 'none', names: family.plain ? null : NAMES[family.vivid ? 'vivid' : scheme], secondary: family.secondary,
    };
  }
  for (const key of Object.keys(FAMILIES)) for (const scheme of ['light', 'dark']) if (FAMILIES[key][scheme]) PRESETS[`${key}-${scheme}`] = familyPreset(key, scheme);
  /** `<family>-system` → that family's light or dark variant, following the OS. */
  const prefersDark = () => globalThis.matchMedia?.('(prefers-color-scheme: dark)')?.matches !== false;
  const isSystem = name => typeof name === 'string' && name.endsWith('-system') && Object.hasOwn(FAMILIES, name.slice(0, -7));
  function variant(name) {
    if (!isSystem(name)) return name;
    const family = name.slice(0, -7);
    return FAMILIES[family].light && !prefersDark() ? `${family}-light` : `${family}-dark`;
  }
  const known = name => Object.hasOwn(PRESETS, name) || isSystem(name);

  /** Full token set for a preset, optionally re-tinted around a custom accent while keeping AA text contrast. */
  function tokens(presetName, accent) {
    const preset = PRESETS[variant(presetName)] || PRESETS.midnight, out = { ...preset };
    if (preset.family) {
      // Families: your own bubbles are the accent itself, with text that reads on it.
      out.accent = readable(accent && HEX.test(accent) ? accent : preset.accent); out.mine = out.accent;
      out['accent-ink'] = ink(out.accent); out['mine-text'] = out['accent-ink']; out['theirs-text'] = out.text;
      out['ok-bg'] = mix(out.accent, out.bg, preset.scheme === 'light' ? 0.12 : 0.16); out['ok-line'] = mix(out.accent, out.bg, 0.35);
      out.meta = mix(out['mine-text'], out.mine, 0.74); out['theirs-meta'] = out.muted;
      out['tick-read'] = out['mine-text'];
      out['danger-line'] = mix(out.danger, out.bg, 0.55); out['warn-line'] = mix(out.warn, out.bg, 0.45);
      out['danger-text'] = preset.scheme === 'light' ? out.danger : mix(out.danger, '#ffffff', 0.7);
      return out;
    }
    if (accent && HEX.test(accent)) {
      out.accent = accent;
      // Tint the outgoing bubble toward the accent, backing off until its text keeps 4.5:1 contrast.
      let amount = preset.scheme === 'light' ? 0.24 : 0.34, mine = mix(accent, preset.bg, amount);
      while (contrast(mine, preset.text) < 4.5 && amount > 0.04) { amount -= 0.03; mine = mix(accent, preset.bg, amount); }
      out.mine = mine;
    }
    out['accent-ink'] = ink(out.accent);
    out['ok-bg'] = mix(out.accent, out.bg, preset.scheme === 'light' ? 0.16 : 0.14);
    out['ok-line'] = mix(out.accent, out.bg, 0.35);
    out['mine-text'] = out.text; out['theirs-text'] = out.text;
    out.meta = mix(out.text, out.mine, 0.72); out['theirs-meta'] = mix(out.text, out.theirs, 0.72);
    // Delivered ticks use the accent only where it stands out on the outgoing bubble.
    out['tick-read'] = contrast(out.accent, out.mine) >= 3 ? out.accent : out.text;
    out['danger-line'] = mix(out.danger, out.bg, 0.55);
    out['warn-line'] = mix(out.warn, out.bg, 0.45);
    out['danger-text'] = preset.scheme === 'light' ? out.danger : mix(out.danger, '#ffffff', 0.7);
    return out;
  }

  // ---------- Preferences ----------
  let account = 'guest', prefs = load(), currentChat = null;
  function clean(value) {
    const out = {};
    if (value && known(value.preset)) out.preset = value.preset;
    if (value && HEX.test(value.accent || '')) out.accent = value.accent.toLowerCase();
    if (value && WALLPAPERS[value.wallpaper]) out.wallpaper = value.wallpaper;
    return out;
  }
  function chatKey(id) { return typeof id === 'string' && /^[A-Za-z0-9_:-]{1,80}$/.test(id) && !['__proto__', 'constructor', 'prototype'].includes(id); }
  function load() {
    let raw = {};
    try { raw = JSON.parse(localStorage.getItem(`theme-v1:${account}`) || '{}') || {}; } catch {}
    // A prototype-less map: no conversation id (stored or live) can ever reach Object.prototype.
    const chats = Object.create(null);
    for (const [id, value] of Object.entries(raw.chats && typeof raw.chats === 'object' ? raw.chats : {}).slice(-MAX_CHATS)) if (chatKey(id)) chats[id] = clean(value);
    return { app: clean(raw.app), chats };
  }
  function save() {
    const ids = Object.keys(prefs.chats);
    for (const id of ids.slice(0, Math.max(0, ids.length - MAX_CHATS))) delete prefs.chats[id];
    try { localStorage.setItem(`theme-v1:${account}`, JSON.stringify(prefs)); } catch {}
  }
  function resolved(chatId = currentChat) {
    const app = prefs.app, chat = chatId ? prefs.chats[chatId] || {} : {};
    const preset = chat.preset || app.preset || 'midnight';
    // A chat that picks its own preset starts from that preset's own accent unless it sets one too.
    const accent = chat.accent || (chat.preset ? null : app.accent) || null;
    const wallpaper = chat.wallpaper || app.wallpaper || PRESETS[variant(preset)].wallpaper;
    return { preset, accent, wallpaper };
  }
  const NOT_COLOURS = ['name', 'scheme', 'wallpaper', 'family', 'font', 'secondary'];
  function apply() {
    const { preset, accent, wallpaper } = resolved(), values = tokens(preset, accent), root = document.documentElement;
    for (const [key, value] of Object.entries(values)) if (typeof value === 'string' && !NOT_COLOURS.includes(key)) root.style.setProperty(`--${key}`, value);
    root.style.setProperty('color-scheme', values.scheme);
    root.style.setProperty('--chat-font', values.mono || values.family === 'mono' ? MONO : 'inherit');
    root.style.setProperty('--app-font', values.font || SANS);
    root.style.setProperty('--accent-2', values.secondary || values.accent);
    const names = values.names || Array(8).fill(values.plain ? values.text : values.accent);
    names.forEach((color, index) => root.style.setProperty(`--name-${index}`, color));
    root.dataset.scheme = values.scheme;
    root.dataset.avatars = values.square ? 'square' : 'round';
    $('app').dataset.wallpaper = wallpaper; $('app').dataset.theme = variant(preset);
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', values.bg);
  }
  globalThis.matchMedia?.('(prefers-color-scheme: dark)')?.addEventListener?.('change', () => apply());

  // ---------- Appearance (per device): text size, density and chat list style ----------
  const SIZES = { s: 14, m: 16, l: 18, xl: 20 }, DENSITIES = ['comfortable', 'compact'], LISTS = ['detailed', 'compact'];
  let appearance = loadAppearance();
  function loadAppearance() {
    let raw = {};
    try { raw = JSON.parse(localStorage.getItem('appearance-v1') || '{}') || {}; } catch {}
    return { size: Object.hasOwn(SIZES, raw.size) ? raw.size : 'm', density: DENSITIES.includes(raw.density) ? raw.density : 'comfortable', list: LISTS.includes(raw.list) ? raw.list : 'detailed' };
  }
  function applyAppearance() {
    const root = document.documentElement;
    root.style.setProperty('--chat-size', `${SIZES[appearance.size]}px`);
    // Space between messages and chats scales with the text size.
    root.style.setProperty('--gap', `${Math.round(SIZES[appearance.size] * (appearance.density === 'compact' ? 0.12 : 0.4))}px`);
    root.style.setProperty('--row-pad', `${Math.round(SIZES[appearance.size] * (appearance.density === 'compact' ? 0.4 : 0.75))}px`);
    root.dataset.textSize = appearance.size; root.dataset.density = appearance.density; root.dataset.list = appearance.list;
    for (const [name, value] of [['appearance-size', appearance.size], ['appearance-density', appearance.density], ['appearance-list', appearance.list]]) {
      for (const input of document.querySelectorAll?.(`input[name="${name}"]`) || []) input.checked = input.value === value;
    }
  }
  function setAppearance(change) {
    const next = { ...appearance, ...change };
    if (!Object.hasOwn(SIZES, next.size) || !DENSITIES.includes(next.density) || !LISTS.includes(next.list)) return false;
    appearance = next;
    try { localStorage.setItem('appearance-v1', JSON.stringify(appearance)); } catch {}
    applyAppearance(); return true;
  }
  document.addEventListener('change', event => {
    const input = event.target, key = { 'appearance-size': 'size', 'appearance-density': 'density', 'appearance-list': 'list' }[input?.name];
    if (key && input.checked) setAppearance({ [key]: input.value });
  });

  // ---------- Picker ----------
  let scope = 'app';
  function swatch(name) {
    const button = document.createElement('button'), values = tokens(name);
    button.type = 'button'; button.className = 'swatch'; button.dataset.preset = name;
    button.setAttribute('role', 'radio'); button.setAttribute('aria-label', PRESETS[name].name);
    for (const key of ['bg', 'mine', 'theirs', 'accent', 'line']) button.style.setProperty(`--sw-${key}`, values[key]);
    const preview = document.createElement('span'); preview.className = 'swatch-preview'; preview.setAttribute('aria-hidden', 'true');
    preview.append(...['sw-theirs', 'sw-mine', 'sw-dot'].map(kind => { const part = document.createElement('i'); part.className = kind; return part; }));
    const label = document.createElement('span'); label.textContent = PRESETS[name].name;
    button.append(preview, label);
    button.onclick = () => choose({ preset: name, accent: undefined });
    return button;
  }
  function wallSwatch(name) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'wall-swatch'; button.dataset.wallpaper = name;
    button.setAttribute('role', 'radio'); button.setAttribute('aria-label', WALLPAPERS[name]);
    const label = document.createElement('span'); label.textContent = WALLPAPERS[name]; button.append(label);
    button.onclick = () => choose({ wallpaper: name });
    return button;
  }
  /** One card per family; the System / Light / Dark switch below picks the variant. */
  function familyCard(key) {
    const button = document.createElement('button'), family = FAMILIES[key], values = tokens(family.dark ? `${key}-dark` : `${key}-light`), day = family.light ? tokens(`${key}-light`) : values;
    button.type = 'button'; button.className = 'swatch family'; button.dataset.family = key;
    button.setAttribute('role', 'radio'); button.setAttribute('aria-label', `${family.name}: ${family.mood}`); button.title = family.mood;
    for (const [prefix, set] of [['sw', day], ['sn', values]]) for (const part of ['bg', 'mine', 'theirs', 'accent', 'line']) button.style.setProperty(`--${prefix}-${part}`, set[part]);
    const preview = document.createElement('span'); preview.className = 'swatch-preview split'; preview.setAttribute('aria-hidden', 'true');
    preview.append(...['sw-theirs', 'sw-mine', 'sw-dot', 'sn-half'].map(kind => { const part = document.createElement('i'); part.className = kind; return part; }));
    const label = document.createElement('span'); label.textContent = family.name;
    if (family.font) label.style.setProperty('font-family', family.font);
    button.append(preview, label);
    button.onclick = () => {
      const mode = family.light ? currentMode() : 'dark';
      choose({ preset: `${key}-${mode}`, accent: undefined });
    };
    return button;
  }
  function currentMode() {
    const preset = (scope === 'chat' && currentChat ? prefs.chats[currentChat]?.preset : prefs.app.preset) || '';
    const match = /-(light|dark|system)$/.exec(preset);
    return match ? match[1] : 'system';
  }
  function setMode(mode) {
    const entry = target(), family = /^([a-z]+)-(?:light|dark|system)$/.exec(entry.preset || '')?.[1];
    if (!family || !FAMILIES[family]) { modeChoice = mode; paintPicker(); return; }
    choose({ preset: FAMILIES[family].light ? `${family}-${mode}` : `${family}-dark` });
  }
  let modeChoice = 'system';
  function target() { return scope === 'chat' && chatKey(currentChat) ? (prefs.chats[currentChat] ||= {}) : prefs.app; }
  function choose(change) {
    const entry = target();
    for (const [key, value] of Object.entries(change)) { if (value === undefined) delete entry[key]; else entry[key] = value; }
    save(); apply(); paintPicker();
  }
  function paintPicker() {
    const entry = scope === 'chat' && currentChat ? prefs.chats[currentChat] || {} : prefs.app, effective = resolved();
    const presetChosen = scope === 'chat' ? entry.preset || 'inherit' : effective.preset;
    for (const button of $('theme-presets').children) button.setAttribute('aria-checked', String(button.dataset.preset === presetChosen));
    const chosenFamily = /^([a-z]+)-(?:light|dark|system)$/.exec(presetChosen)?.[1];
    for (const button of $('theme-families')?.children || []) button.setAttribute('aria-checked', String(button.dataset.family === chosenFamily));
    const mode = chosenFamily ? currentMode() : modeChoice;
    for (const button of $('theme-mode')?.children || []) { button.setAttribute('aria-checked', String(button.dataset.mode === mode)); button.disabled = Boolean(chosenFamily && !FAMILIES[chosenFamily].light && button.dataset.mode !== 'dark'); }
    const wallChosen = scope === 'chat' ? entry.wallpaper || 'inherit' : prefs.app.wallpaper || 'inherit';
    for (const button of $('theme-walls').children) button.setAttribute('aria-checked', String(button.dataset.wallpaper === wallChosen));
    $('theme-accent').value = effective.accent || tokens(effective.preset).accent;
    $('theme-accent-reset').hidden = !entry.accent;
    $('theme-title').textContent = scope === 'chat' ? 'Chat theme' : 'App theme';
    $('theme-note').textContent = scope === 'chat' ? 'Only this conversation, on this device.' : 'Every conversation without its own theme, on this device.';
  }
  function inheritButton(kind) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = kind === 'preset' ? 'swatch inherit' : 'wall-swatch inherit';
    button.dataset[kind === 'preset' ? 'preset' : 'wallpaper'] = 'inherit';
    button.setAttribute('role', 'radio');
    const label = document.createElement('span'); label.textContent = kind === 'preset' ? 'Same as app' : 'Theme default'; button.append(label);
    button.onclick = () => choose(kind === 'preset' ? { preset: undefined, accent: undefined } : { wallpaper: undefined });
    return button;
  }
  function open(nextScope) {
    scope = nextScope === 'chat' && currentChat ? 'chat' : 'app';
    $('theme-presets').replaceChildren(...(scope === 'chat' ? [inheritButton('preset')] : []), ...Object.keys(PRESETS).filter(name => !PRESETS[name].family).map(swatch));
    $('theme-families').replaceChildren(...Object.keys(FAMILIES).map(familyCard));
    $('theme-walls').replaceChildren(inheritButton('wallpaper'), ...Object.keys(WALLPAPERS).map(wallSwatch));
    paintPicker();
    $('theme-dialog').hidden = false; $('theme-done').focus();
  }
  $('theme-accent').oninput = () => { if (HEX.test($('theme-accent').value)) choose({ accent: $('theme-accent').value.toLowerCase() }); };
  $('theme-accent-reset').onclick = () => choose({ accent: undefined });
  $('theme-done').onclick = () => { $('theme-dialog').hidden = true; };
  $('theme-dialog').addEventListener('keydown', event => { if (event.key === 'Escape') $('theme-dialog').hidden = true; });

  // ---------- Small icon animations (classes only; CSS decides whether motion is allowed) ----------
  const replay = (element, name) => { if (!element) return; element.classList.remove(name); requestAnimationFrame(() => element.classList.add(name)); };
  document.addEventListener('click', event => {
    const button = event.target.closest?.('#notify-enable, .toggle');
    if (button && (button.id === 'notify-enable' || button.querySelector('#notify-toggle'))) replay($('notify-banner').querySelector('.icon'), 'shake');
  });
  $('disappear').addEventListener('change', () => { replay($('disappear').closest('.timer'), 'sweep'); $('disappear').closest('.timer').dataset.on = String($('disappear').value !== 'off'); });
  $('disappear').closest('.timer').dataset.on = String($('disappear').value !== 'off');

  for (const button of $('theme-mode')?.children || []) button.onclick = () => setMode(button.dataset.mode);
  $('theme-app').onclick = () => open('app');
  $('conv-theme').onclick = () => { $('conv-menu').open = false; open('chat'); };
  $('theme-open').onclick = () => { $('menu').open = false; open('chat'); };

  window.Theme = Object.freeze({
    PRESETS, FAMILIES, WALLPAPERS, tokens, contrast, variant,
    get appearance() { return { ...appearance }; },
    setAppearance,
    toggleDensity() { setAppearance({ density: appearance.density === 'compact' ? 'comfortable' : 'compact' }); return appearance.density; },
    /** A colour index 0–7 for a person (hash of their id); CSS maps it to the theme's name palette. */
    nameIndex(id) { let hash = 0; for (const character of String(id || '')) hash = (hash * 31 + character.codePointAt(0)) >>> 0; return hash % 8; },
    /** Shows a conversation's theme (or the app theme with null). */
    use(chatId) { currentChat = chatId || null; apply(); },
    setAccount(id) { account = id || 'guest'; prefs = load(); apply(); },
    open,
    /** /theme: sets this conversation's preset by key or display name; 'default' returns it to the app theme. */
    setChatPreset(name) {
      const wanted = String(name || '').toLowerCase();
      const key = wanted === 'default' ? 'default' : Object.keys(PRESETS).find(id => id === wanted || PRESETS[id].name.toLowerCase() === wanted && !PRESETS[id].family) ||
        (Object.hasOwn(FAMILIES, wanted) ? `${wanted}-system` : known(wanted) ? wanted : undefined);
      if (!key || !chatKey(currentChat)) return false;
      const entry = prefs.chats[currentChat] ||= {};
      if (key === 'default') { delete entry.preset; delete entry.accent; } else { entry.preset = key; delete entry.accent; }
      save(); apply(); return true;
    },
  });
  currentChat = window.App?.conversationId || null; // A call link opened before this script loaded.
  apply(); applyAppearance();
})();
