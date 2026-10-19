import 'package:flutter/material.dart' show Brightness;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/theme/theme_prefs.dart';
import 'package:private_chat/theme/tokens.dart';

void main() {
  const accents = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ffffff', '#000000', '#7f7f7f'];

  test('every preset, with and without a custom accent, keeps AA contrast for bubble and button text', () {
    for (final preset in presets.keys) {
      for (final accent in [null, ...accents]) {
        final t = ChatTokens.resolve(preset, accent);
        expect(contrast(t.hex['text']!, t.hex['mine']!), greaterThanOrEqualTo(4.5), reason: '$preset $accent outgoing bubble');
        expect(contrast(t.hex['text']!, t.hex['theirs']!), greaterThanOrEqualTo(4.5), reason: '$preset incoming bubble');
        expect(contrast(t.hex['accentInk']!, t.hex['accent']!), greaterThanOrEqualTo(4.5), reason: '$preset $accent button text');
      }
    }
  });

  test('theme families: own bubbles are the accent with 4.5:1 text, names read on incoming bubbles', () {
    expect(families.keys, ['classic', 'forest', 'ocean', 'dusk', 'rose', 'paper', 'mono', 'midnight']);
    expect(families['midnight']!.light, isNull, reason: 'Midnight is dark only');
    expect(families['classic']!.light!.bg, '#FBF8F3');
    expect(families['midnight']!.dark.bg, '#000000');
    for (final key in allPresets.keys.where((k) => allPresets[k]!.family != null)) {
      for (final accent in [null, ...accents]) {
        final t = ChatTokens.resolve(key, accent);
        expect(contrast(t.hex['mineText']!, t.hex['mine']!), greaterThanOrEqualTo(4.5), reason: '$key $accent own bubble');
        expect(contrast(t.hex['text']!, t.hex['theirs']!), greaterThanOrEqualTo(4.5), reason: '$key incoming bubble');
        expect(contrast(t.hex['accentInk']!, t.hex['accent']!), greaterThanOrEqualTo(4.5), reason: '$key $accent button text');
        expect(contrast(t.hex['muted']!, t.hex['bg']!), greaterThanOrEqualTo(4.5), reason: '$key secondary text');
      }
      final t = ChatTokens.resolve(key);
      if (t.preset.family == 'mono') {
        expect(t.names, isEmpty);
        expect(t.square, isTrue);
        expect(t.nameColor('anyone'), t.text);
      } else {
        expect(t.names, hasLength(8));
        for (final n in t.names) {
          final hex = '#${(n.toARGB32() & 0xFFFFFF).toRadixString(16).padLeft(6, '0')}';
          expect(contrast(hex, t.hex['theirs']!), greaterThanOrEqualTo(4.5), reason: '$key name $hex');
        }
      }
    }
    expect(ChatTokens.resolve('paper-light').fontFamily, 'Georgia');
    expect(ChatTokens.resolve('mono-dark').fontFamily, 'Menlo');
  });

  test('System follows the platform; light/dark force a variant; Classic is the default', () {
    const system = ThemePrefs();
    expect(system.resolve(null, Brightness.light).preset, 'classic-light');
    expect(system.resolve(null, Brightness.dark).preset, 'classic-dark');
    const forest = ThemePrefs(app: ThemeChoice(family: 'forest'), display: Display(mode: AppearanceMode.dark));
    expect(forest.resolve(null, Brightness.light).preset, 'forest-dark');
    const midnight = ThemePrefs(app: ThemeChoice(family: 'midnight'), display: Display(mode: AppearanceMode.light));
    expect(midnight.resolve().preset, 'midnight-dark');
    final display = Display.fromJson(const Display(textSize: TextSize.xl, density: Density.compact, listStyle: ListStyle.compact).toJson());
    expect((display.textSize, display.density, display.listStyle), (TextSize.xl, Density.compact, ListStyle.compact));
    expect(Display.fromJson({'textSize': 'huge'}).textSize, TextSize.m);
    expect(ThemeChoice.fromJson({'family': 'rose', 'preset': 'ocean'}).toJson(), {'family': 'rose'});
  });

  test('color math matches WCAG reference values', () {
    expect(contrast('#000000', '#ffffff'), closeTo(21, 0.01));
    expect(contrast('#777777', '#ffffff'), closeTo(4.48, 0.01));
    expect(mix('#000000', '#ffffff', .5), '#808080');
  });

  test('delivered ticks use the accent only where it stands out on the bubble', () {
    for (final preset in presets.keys) {
      final t = ChatTokens.resolve(preset);
      expect(t.hex['tickRead'] == t.hex['accent'] ? contrast(t.hex['accent']!, t.hex['mine']!) >= 3 : true, isTrue, reason: preset);
    }
  });

  test('a chat theme overrides the app theme with the same precedence as theme.js', () {
    const prefs = ThemePrefs(
      app: ThemeChoice(preset: 'ocean', accent: '#ff8a65'),
      chats: {'chat1': ThemeChoice(preset: 'fsociety'), 'chat2': ThemeChoice(wallpaper: 'grid')},
    );
    expect(prefs.resolve(), (preset: 'ocean', accent: '#ff8a65', wallpaper: 'lines'));
    // Picking its own preset drops the app accent and uses the preset's wallpaper.
    expect(prefs.resolve('chat1'), (preset: 'fsociety', accent: null, wallpaper: 'circuit'));
    expect(prefs.resolve('chat2'), (preset: 'ocean', accent: '#ff8a65', wallpaper: 'grid'));
  });

  test('stored preferences are validated against the fixed lists', () {
    final choice = ThemeChoice.fromJson({'preset': 'evil', 'accent': 'url(x)', 'wallpaper': 'nope'});
    expect(choice.isEmpty, isTrue);
  });
}
