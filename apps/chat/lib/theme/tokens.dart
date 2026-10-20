import 'dart:math' as math;

import 'package:flutter/material.dart';

/// The web client's theme presets and color math (theme.js), so both apps
/// look the same and apply the same WCAG contrast rules.
class Preset {
  const Preset({
    required this.key,
    required this.name,
    required this.dark,
    required this.bg,
    required this.surface,
    required this.surface2,
    required this.raised,
    required this.line,
    required this.lineStrong,
    required this.text,
    required this.muted,
    required this.accent,
    required this.mine,
    required this.theirs,
    required this.danger,
    required this.dangerBg,
    required this.warn,
    required this.warnBg,
    required this.wallpaper,
    this.mono = false,
    this.family,
    this.font = ThemeFont.sans,
    this.names = const [],
    this.secondary,
  });
  final String key, name, wallpaper;
  final bool dark, mono;
  final String bg, surface, surface2, raised, line, lineStrong, text, muted, accent, mine, theirs, danger, dangerBg, warn, warnBg;

  /// Set for the theme families (§6): own bubbles are the accent at 100% with contrasting text.
  final String? family;
  final ThemeFont font;

  /// Per-theme palette of 8 name colours; empty means plain names (Mono).
  final List<String> names;
  final String? secondary;
  bool get accentBubbles => family != null;
}

enum ThemeFont { sans, serif, mono }

/// One theme family (docs/phase1-protocol.md §6), each with light and dark (Midnight is dark only).
class ThemeFamily {
  const ThemeFamily({required this.key, required this.name, required this.mood, required this.dark, this.light});
  final String key, name, mood;
  final Preset dark;
  final Preset? light;
  Preset variant(bool wantDark) => wantDark || light == null ? dark : light!;
}

const _namesLight = ['#b4410c', '#8a5a00', '#15803d', '#0f766e', '#1d4ed8', '#7c3aed', '#be185d', '#4d7c0f'];
const _namesDark = ['#fb923c', '#fbbf24', '#4ade80', '#2dd4bf', '#60a5fa', '#a78bfa', '#f472b6', '#a3e635'];
const _namesVivid = ['#ff5c5c', '#ffb02e', '#3ddc84', '#00d1ff', '#5c8fff', '#b36bff', '#ff4fd8', '#c6ff3d'];

/// Derives the full token set from the four colours each family defines.
Preset _variant(String family, String name, bool dark, String bg, String surface, String text, String accent,
    {ThemeFont font = ThemeFont.sans, List<String>? names, String? secondary}) {
  var muted = mix(text, bg, 0.66);
  for (var amount = 0.7; contrast(muted, bg) < 4.5 && amount < 1; amount += 0.04) {
    muted = mix(text, bg, amount);
  }
  return Preset(
    key: '$family-${dark ? 'dark' : 'light'}',
    name: name,
    dark: dark,
    bg: bg,
    surface: surface,
    surface2: mix(text, surface, 0.06),
    raised: mix(text, surface, 0.11),
    line: mix(text, bg, 0.12),
    lineStrong: mix(text, bg, 0.35),
    text: text,
    muted: muted,
    accent: accent,
    mine: accent,
    theirs: surface,
    danger: dark ? '#ff6b78' : '#c2334a',
    dangerBg: dark ? '#3b141a' : '#fbe1e5',
    warn: dark ? '#ffd166' : '#7d5800',
    warnBg: dark ? '#2e2510' : '#fff1c7',
    wallpaper: 'none',
    mono: font == ThemeFont.mono,
    family: family,
    font: font,
    names: names ?? (dark ? _namesDark : _namesLight),
    secondary: secondary,
  );
}

final families = <String, ThemeFamily>{
  for (final f in [
    ThemeFamily(
      key: 'classic',
      name: 'Classic',
      mood: 'Warm paper by day, ink by night.',
      light: _variant('classic', 'Classic', false, '#FBF8F3', '#F2EDE4', '#1F1B16', '#5B6CF0'),
      dark: _variant('classic', 'Classic', true, '#121214', '#1C1C20', '#ECEAE6', '#7C8BFF'),
    ),
    ThemeFamily(
      key: 'forest',
      name: 'Forest',
      mood: 'Soft green-grey and deep forest: calm, like a walk outside.',
      light: _variant('forest', 'Forest', false, '#F3F6F2', '#E5ECE3', '#18231B', '#2F7A4F'),
      dark: _variant('forest', 'Forest', true, '#0F1712', '#17221B', '#E3EDE5', '#5FBF86'),
    ),
    ThemeFamily(
      key: 'ocean',
      name: 'Ocean',
      mood: 'Sea glass and deep teal: cool, clear and bright.',
      light: _variant('ocean', 'Ocean', false, '#F1F8F8', '#E0EFF0', '#0F2328', '#0F8A9D'),
      dark: _variant('ocean', 'Ocean', true, '#0B1A1E', '#12262B', '#E0F1F3', '#3CC6D8'),
    ),
    ThemeFamily(
      key: 'dusk',
      name: 'Dusk',
      mood: 'Lilac evenings and violet ink, with a little sunset.',
      light: _variant('dusk', 'Dusk', false, '#F7F3FB', '#ECE4F5', '#221A2B', '#7B4FD6'),
      dark: _variant('dusk', 'Dusk', true, '#17121F', '#221A2D', '#EEE6F7', '#B08CFF', secondary: '#FF9A76'),
    ),
    ThemeFamily(
      key: 'rose',
      name: 'Rose',
      mood: 'Blush and raspberry: warm, friendly, a bit playful.',
      light: _variant('rose', 'Rose', false, '#FDF4F5', '#F8E5E8', '#2A1418', '#C8305A'),
      dark: _variant('rose', 'Rose', true, '#1C1013', '#2A181D', '#F7E6EA', '#FF6F93'),
    ),
    ThemeFamily(
      key: 'paper',
      name: 'Paper',
      mood: 'Old paper and rust, serif throughout: reads like a book.',
      light: _variant('paper', 'Paper', false, '#F6F0E4', '#EDE4D2', '#2B2118', '#A44A26', font: ThemeFont.serif),
      dark: _variant('paper', 'Paper', true, '#1A1611', '#26201A', '#EFE6D6', '#E07A4F', font: ThemeFont.serif),
    ),
    ThemeFamily(
      key: 'mono',
      name: 'Mono',
      mood: 'Greyscale and monospaced: plain names, square avatars, nothing extra.',
      light: _variant('mono', 'Mono', false, '#FFFFFF', '#F2F2F2', '#111111', '#111111', font: ThemeFont.mono, names: const []),
      dark: _variant('mono', 'Mono', true, '#0A0A0A', '#161616', '#EDEDED', '#EDEDED', font: ThemeFont.mono, names: const []),
    ),
    ThemeFamily(
      key: 'midnight',
      name: 'Midnight',
      mood: 'True black for OLED, an electric accent and vivid names.',
      dark: _variant('midnight', 'Midnight', true, '#000000', '#0E0E10', '#F5F5F7', '#3D7BFF', names: _namesVivid),
    ),
  ])
    f.key: f,
};

/// Every preset by key: the family variants plus the earlier themes, which stay available.
final allPresets = <String, Preset>{
  for (final f in families.values) ...{f.dark.key: f.dark, if (f.light != null) f.light!.key: f.light!},
  ...presets,
};

/// The earlier themes, kept under their stored keys (display names differ from the families).
const presets = <String, Preset>{
  'midnight': Preset(key: 'midnight', name: 'Harbor', dark: true, bg: '#111820', surface: '#192733', surface2: '#20303c', raised: '#263d4c', line: '#344755', lineStrong: '#647987', text: '#eef4f9', muted: '#afbfcc', accent: '#a1efce', mine: '#244535', theirs: '#20303c', danger: '#e2606e', dangerBg: '#562d35', warn: '#f2c14e', warnBg: '#3d321a', wallpaper: 'none'),
  'fsociety': Preset(key: 'fsociety', name: 'fsociety', dark: true, mono: true, bg: '#040805', surface: '#09110b', surface2: '#0e1a11', raised: '#142418', line: '#1c3322', lineStrong: '#2f5a39', text: '#c9f7c8', muted: '#7cb487', accent: '#3dff73', mine: '#0f2b17', theirs: '#0c1810', danger: '#ff4d5e', dangerBg: '#3a1015', warn: '#e8d44d', warnBg: '#2a260c', wallpaper: 'circuit'),
  'light': Preset(key: 'light', name: 'Daylight', dark: false, bg: '#f4f6f8', surface: '#ffffff', surface2: '#eaeff3', raised: '#dfe6ec', line: '#d3dce3', lineStrong: '#a3b1bc', text: '#13202a', muted: '#52616c', accent: '#0a7a52', mine: '#d4f3e4', theirs: '#ffffff', danger: '#c2334a', dangerBg: '#fbe1e5', warn: '#7d5800', warnBg: '#fff1c7', wallpaper: 'dots'),
  'amoled': Preset(key: 'amoled', name: 'AMOLED', dark: true, bg: '#000000', surface: '#0b0b0b', surface2: '#141414', raised: '#1e1e1e', line: '#262626', lineStrong: '#454545', text: '#f2f2f2', muted: '#a6a6a6', accent: '#8ab4ff', mine: '#15253f', theirs: '#161616', danger: '#ff6b78', dangerBg: '#3b141a', warn: '#ffd166', warnBg: '#2e2510', wallpaper: 'none'),
  'dusk': Preset(key: 'dusk', name: 'Twilight', dark: true, bg: '#16111e', surface: '#1f1829', surface2: '#292034', raised: '#342a42', line: '#3d3150', lineStrong: '#6b5b82', text: '#f4eefb', muted: '#c4b7d8', accent: '#f6a8cb', mine: '#4a2944', theirs: '#292034', danger: '#ff6f86', dangerBg: '#4a1f2c', warn: '#f7c86b', warnBg: '#3a2c18', wallpaper: 'gradient'),
  'ocean': Preset(key: 'ocean', name: 'Deep sea', dark: true, bg: '#0a1520', surface: '#0f1f2e', surface2: '#14283b', raised: '#1b344d', line: '#233f5a', lineStrong: '#4b6a89', text: '#eaf3fb', muted: '#a8bfd3', accent: '#6fcbff', mine: '#153a59', theirs: '#14283b', danger: '#ff6b78', dangerBg: '#45202a', warn: '#f5c451', warnBg: '#382d14', wallpaper: 'lines'),
};

const wallpapers = <String, String>{'none': 'None', 'dots': 'Dots', 'grid': 'Grid', 'lines': 'Lines', 'gradient': 'Glow', 'circuit': 'Circuit'};

final _hexPattern = RegExp(r'^#[0-9a-fA-F]{6}$');
bool isHexColor(String? value) => value != null && _hexPattern.hasMatch(value);

List<int> _rgb(String hex) => [1, 3, 5].map((i) => int.parse(hex.substring(i, i + 2), radix: 16)).toList();
String _hex(List<double> values) => '#${values.map((v) => v.round().clamp(0, 255).toRadixString(16).padLeft(2, '0')).join()}';

double luminance(String color) {
  final c = _rgb(color).map((v) {
    final x = v / 255;
    return x <= 0.03928 ? x / 12.92 : math.pow((x + 0.055) / 1.055, 2.4).toDouble();
  }).toList();
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

double contrast(String a, String b) {
  final x = luminance(a), y = luminance(b);
  return (math.max(x, y) + 0.05) / (math.min(x, y) + 0.05);
}

String mix(String a, String b, double amount) {
  final p = _rgb(a), q = _rgb(b);
  return _hex([for (var i = 0; i < 3; i++) p[i] * amount + q[i] * (1 - amount)]);
}

String ink(String color) => contrast(color, '#ffffff') >= contrast(color, '#0b0f12') ? '#ffffff' : '#0b0f12';

Color _c(String hex) => Color(0xFF000000 | int.parse(hex.substring(1), radix: 16));

/// Resolved colors for one preset, optionally re-tinted around a custom accent.
class ChatTokens {
  ChatTokens._(this.preset, Map<String, String> v)
    : bg = _c(v['bg']!),
      surface = _c(v['surface']!),
      surface2 = _c(v['surface2']!),
      raised = _c(v['raised']!),
      line = _c(v['line']!),
      lineStrong = _c(v['lineStrong']!),
      text = _c(v['text']!),
      muted = _c(v['muted']!),
      accent = _c(v['accent']!),
      accentInk = _c(v['accentInk']!),
      mine = _c(v['mine']!),
      mineText = _c(v['mineText']!),
      theirs = _c(v['theirs']!),
      meta = _c(v['meta']!),
      metaTheirs = _c(v['metaTheirs']!),
      tickRead = _c(v['tickRead']!),
      okBg = _c(v['okBg']!),
      okLine = _c(v['okLine']!),
      danger = _c(v['danger']!),
      dangerBg = _c(v['dangerBg']!),
      dangerText = _c(v['dangerText']!),
      warn = _c(v['warn']!),
      warnBg = _c(v['warnBg']!),
      names = [for (final n in preset.names) _c(_readable(n, v['theirs']!, preset.text))],
      hex = v;

  /// A name colour nudged toward the text colour until it reads at 4.5:1 on incoming bubbles.
  static String _readable(String color, String on, String text) {
    var out = color;
    for (var amount = 0.85; contrast(out, on) < 4.5 && amount > 0; amount -= 0.1) {
      out = mix(color, text, amount);
    }
    return contrast(out, on) < 4.5 ? text : out;
  }

  final Preset preset;
  final Map<String, String> hex;
  final Color bg, surface, surface2, raised, line, lineStrong, text, muted, accent, accentInk, mine, mineText, theirs, meta, metaTheirs, tickRead, okBg, okLine, danger, dangerBg, dangerText, warn, warnBg;
  final List<Color> names;
  bool get dark => preset.dark;
  bool get mono => preset.mono;

  /// Square avatars and plain names (Mono).
  bool get square => preset.family == 'mono';

  String? get fontFamily => switch (preset.font) {
    ThemeFont.sans => preset.mono ? 'Menlo' : null,
    ThemeFont.serif => 'Georgia',
    ThemeFont.mono => 'Menlo',
  };
  List<String>? get fontFallback => switch (preset.font) {
    ThemeFont.serif => const ['New York', 'Times New Roman', 'Noto Serif', 'serif'],
    _ when preset.mono || preset.font == ThemeFont.mono => const ['SF Mono', 'Roboto Mono', 'Consolas', 'monospace'],
    _ => null,
  };

  /// A person's name colour (stable hash of their id); the text colour when the theme has none.
  Color nameColor(String userId) {
    if (names.isEmpty) return text;
    var h = 0;
    for (final unit in userId.codeUnits) {
      h = (h * 31 + unit) & 0x7fffffff;
    }
    return names[h % names.length];
  }

  /// Port of theme.js `tokens()`: tint the outgoing bubble toward the accent,
  /// backing off until its text keeps 4.5:1 contrast.
  factory ChatTokens.resolve(String presetKey, [String? accent]) {
    final p = allPresets[presetKey] ?? families['classic']!.dark;
    final v = <String, String>{
      'bg': p.bg, 'surface': p.surface, 'surface2': p.surface2, 'raised': p.raised, 'line': p.line, 'lineStrong': p.lineStrong,
      'text': p.text, 'muted': p.muted, 'accent': p.accent, 'mine': p.mine, 'theirs': p.theirs,
      'danger': p.danger, 'dangerBg': p.dangerBg, 'warn': p.warn, 'warnBg': p.warnBg,
    };
    if (p.accentBubbles) {
      // Families: own bubbles are the accent itself; its text is whichever ink reads at 4.5:1, and the
      // bubble steps toward black or white only when neither does.
      if (isHexColor(accent)) v['accent'] = accent!.toLowerCase();
      // Step the colour toward black (for white text) or white (for dark text), whichever needs less;
      // a tie keeps white text, which reads as the accent best.
      ({String color, int steps}) nudge(String towards, String text) {
        var color = v['accent']!;
        var steps = 0;
        for (var amount = 0.97; contrast(color, text) < 4.5 && amount > 0.3; amount -= 0.03) {
          color = mix(v['accent']!, towards, amount);
          steps++;
        }
        return (color: color, steps: contrast(color, text) < 4.5 ? 999 : steps);
      }

      final light = nudge('#000000', '#ffffff'), dark = nudge('#ffffff', '#0b0f12');
      final mine = light.steps <= dark.steps ? light.color : dark.color;
      // The accent is the bubble: when the spec colour misses 4.5:1 by a hair (Classic light), both move together.
      v['mine'] = mine;
      v['accent'] = mine;
      v['mineText'] = ink(mine);
    } else if (isHexColor(accent)) {
      v['accent'] = accent!.toLowerCase();
      var amount = p.dark ? 0.34 : 0.24;
      var mine = mix(v['accent']!, p.bg, amount);
      while (contrast(mine, p.text) < 4.5 && amount > 0.04) {
        amount -= 0.03;
        mine = mix(v['accent']!, p.bg, amount);
      }
      v['mine'] = mine;
    }
    v['mineText'] ??= p.text;
    v['accentInk'] = ink(v['accent']!);
    v['okBg'] = mix(v['accent']!, p.bg, p.dark ? 0.14 : 0.16);
    v['okLine'] = mix(v['accent']!, p.bg, 0.35);
    v['meta'] = mix(v['mineText']!, v['mine']!, 0.72);
    v['metaTheirs'] = mix(p.text, p.theirs, 0.66);
    v['tickRead'] = contrast(v['accent']!, v['mine']!) >= 3 ? v['accent']! : v['mineText']!;
    v['dangerText'] = p.dark ? mix(p.danger, '#ffffff', 0.7) : p.danger;
    return ChatTokens._(p, v);
  }

  ThemeData material() {
    final scheme = ColorScheme.fromSeed(
      seedColor: accent,
      brightness: dark ? Brightness.dark : Brightness.light,
    ).copyWith(primary: accent, onPrimary: accentInk, surface: bg, onSurface: text, error: danger, outline: lineStrong);
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      fontFamily: fontFamily,
      fontFamilyFallback: fontFallback,
      scaffoldBackgroundColor: bg,
      appBarTheme: AppBarTheme(backgroundColor: bg, foregroundColor: text, elevation: 0, scrolledUnderElevation: 0),
      dividerColor: line,
      bottomSheetTheme: BottomSheetThemeData(backgroundColor: surface2, showDragHandle: true),
      dialogTheme: DialogThemeData(backgroundColor: surface2),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surface,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(24), borderSide: BorderSide(color: lineStrong)),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(24), borderSide: BorderSide(color: lineStrong)),
        hintStyle: TextStyle(color: muted),
      ),
      textTheme: Typography.material2021().englishLike.apply(bodyColor: text, displayColor: text, fontFamily: fontFamily, fontFamilyFallback: fontFallback),
    );
  }
}
