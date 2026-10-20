import 'dart:convert';
import 'dart:ui' show Brightness, PlatformDispatcher;

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'tokens.dart';

/// A theme choice: a family (light/dark by the appearance mode) or one of the earlier presets,
/// an optional custom accent, an optional wallpaper. Picking a family clears the preset and back.
class ThemeChoice {
  const ThemeChoice({this.preset, this.family, this.accent, this.wallpaper});
  final String? preset, family, accent, wallpaper;

  factory ThemeChoice.fromJson(Object? json) {
    if (json is! Map) return const ThemeChoice();
    final preset = json['preset'], family = json['family'], accent = json['accent'], wallpaper = json['wallpaper'];
    final validFamily = families.containsKey(family) ? family as String : null;
    return ThemeChoice(
      preset: validFamily == null && presets.containsKey(preset) ? preset as String : null,
      family: validFamily,
      accent: isHexColor(accent as String?) ? (accent as String).toLowerCase() : null,
      wallpaper: wallpapers.containsKey(wallpaper) ? wallpaper as String : null,
    );
  }

  Map<String, String> toJson() => {'preset': ?preset, 'family': ?family, 'accent': ?accent, 'wallpaper': ?wallpaper};
  bool get isEmpty => preset == null && family == null && accent == null && wallpaper == null;
  bool get hasTheme => preset != null || family != null;
}

enum AppearanceMode { system, light, dark }

enum TextSize {
  s('S', 0.875),
  m('M', 1),
  l('L', 1.125),
  xl('XL', 1.25);

  const TextSize(this.label, this.scale);
  final String label;
  final double scale;
}

enum Density { comfortable, compact }

enum ListStyle { detailed, compact }

/// Display settings for this device (§6): light/dark mode, text size, spacing, chat list style.
class Display {
  const Display({this.mode = AppearanceMode.system, this.textSize = TextSize.m, this.density = Density.comfortable, this.listStyle = ListStyle.detailed});
  final AppearanceMode mode;
  final TextSize textSize;
  final Density density;
  final ListStyle listStyle;

  /// The room between messages and between chats in the list; it grows with the text size.
  double get gap => (density == Density.compact ? 1.0 : 3.0) * textSize.scale;
  double get rowPadding => (density == Density.compact ? 2.0 : 8.0) * textSize.scale;

  Display copyWith({AppearanceMode? mode, TextSize? textSize, Density? density, ListStyle? listStyle}) => Display(
    mode: mode ?? this.mode,
    textSize: textSize ?? this.textSize,
    density: density ?? this.density,
    listStyle: listStyle ?? this.listStyle,
  );

  static T _pick<T extends Enum>(List<T> values, Object? name, T fallback) => values.where((v) => v.name == name).firstOrNull ?? fallback;

  factory Display.fromJson(Object? json) {
    if (json is! Map) return const Display();
    return Display(
      mode: _pick(AppearanceMode.values, json['mode'], AppearanceMode.system),
      textSize: _pick(TextSize.values, json['textSize'], TextSize.m),
      density: _pick(Density.values, json['density'], Density.comfortable),
      listStyle: _pick(ListStyle.values, json['listStyle'], ListStyle.detailed),
    );
  }

  Map<String, String> toJson() => {'mode': mode.name, 'textSize': textSize.name, 'density': density.name, 'listStyle': listStyle.name};
}

/// App-wide and per-chat appearance. Cosmetic and local to this device: it is
/// never sent to the server (same rule as theme.js).
class ThemePrefs {
  const ThemePrefs({this.app = const ThemeChoice(), this.chats = const {}, this.display = const Display()});
  final ThemeChoice app;
  final Map<String, ThemeChoice> chats;
  final Display display;

  static const defaultFamily = 'classic';

  bool _dark(Brightness? platform) => switch (display.mode) {
    AppearanceMode.light => false,
    AppearanceMode.dark => true,
    AppearanceMode.system => (platform ?? PlatformDispatcher.instance.platformBrightness) == Brightness.dark,
  };

  /// Same precedence as theme.js `resolved()`: a chat's own theme wins, then the app's, then Classic.
  ({String preset, String? accent, String wallpaper}) resolve([String? chatId, Brightness? platform]) {
    final chat = chatId == null ? const ThemeChoice() : chats[chatId] ?? const ThemeChoice();
    final source = chat.hasTheme ? chat : app;
    final family = source.family ?? (source.preset == null ? defaultFamily : null);
    final preset = family != null ? families[family]!.variant(_dark(platform)).key : source.preset!;
    final accent = chat.accent ?? (chat.hasTheme ? null : app.accent);
    final wallpaper = chat.wallpaper ?? app.wallpaper ?? allPresets[preset]!.wallpaper;
    return (preset: preset, accent: accent, wallpaper: wallpaper);
  }

  ChatTokens tokens([String? chatId, Brightness? platform]) {
    final r = resolve(chatId, platform);
    return ChatTokens.resolve(r.preset, r.accent);
  }
}

class ThemePrefsNotifier extends Notifier<ThemePrefs> {
  static const _maxChats = 300;
  String _account = 'guest';
  SharedPreferences? _prefs;

  @override
  ThemePrefs build() => const ThemePrefs();

  Future<void> load(String? account) async {
    _account = account ?? 'guest';
    _prefs ??= await SharedPreferences.getInstance();
    try {
      final raw = jsonDecode(_prefs!.getString('theme-v1:$_account') ?? '{}') as Map<String, dynamic>;
      final chats = <String, ThemeChoice>{};
      if (raw['chats'] is Map) {
        for (final entry in (raw['chats'] as Map).entries) {
          if (entry.key is String && RegExp(r'^[A-Za-z0-9_:-]{1,80}$').hasMatch(entry.key as String)) {
            chats[entry.key as String] = ThemeChoice.fromJson(entry.value);
          }
        }
      }
      state = ThemePrefs(app: ThemeChoice.fromJson(raw['app']), chats: chats, display: Display.fromJson(raw['display']));
    } catch (_) {
      state = const ThemePrefs();
    }
  }

  void setApp(ThemeChoice choice) => _save(ThemePrefs(app: choice, chats: state.chats, display: state.display));

  void setDisplay(Display display) => _save(ThemePrefs(app: state.app, chats: state.chats, display: display));

  void toggleDensity() =>
      setDisplay(state.display.copyWith(density: state.display.density == Density.compact ? Density.comfortable : Density.compact));

  void setChat(String chatId, ThemeChoice choice) {
    final chats = Map.of(state.chats)..remove(chatId);
    if (!choice.isEmpty) chats[chatId] = choice;
    while (chats.length > _maxChats) {
      chats.remove(chats.keys.first);
    }
    _save(ThemePrefs(app: state.app, chats: chats, display: state.display));
  }

  void _save(ThemePrefs next) {
    state = next;
    _prefs?.setString(
      'theme-v1:$_account',
      jsonEncode({'app': next.app.toJson(), 'chats': next.chats.map((k, v) => MapEntry(k, v.toJson())), 'display': next.display.toJson()}),
    );
  }
}

final themePrefsProvider = NotifierProvider<ThemePrefsNotifier, ThemePrefs>(ThemePrefsNotifier.new);

/// The OS light/dark setting, kept current by the app (for "System").
class PlatformBrightness extends Notifier<Brightness> {
  @override
  Brightness build() => PlatformDispatcher.instance.platformBrightness;
  void set(Brightness value) => state = value;
}

final platformBrightnessProvider = NotifierProvider<PlatformBrightness, Brightness>(PlatformBrightness.new);
