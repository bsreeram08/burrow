import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../theme/theme_prefs.dart';
import '../theme/tokens.dart';

const _accents = ['#5b6cf0', '#3d7bff', '#0f8a9d', '#2f7a4f', '#7b4fd6', '#c8305a', '#a44a26', '#a1efce', '#f2c14e', '#e2606e'];

/// Appearance for the app, or one conversation's theme when [chatId] is given (§6).
Future<void> showThemePicker(BuildContext context, WidgetRef ref, {String? chatId}) =>
    showModalBottomSheet<void>(context: context, isScrollControlled: true, builder: (_) => ThemePicker(chatId: chatId));

class ThemePicker extends ConsumerWidget {
  const ThemePicker({super.key, this.chatId});
  final String? chatId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final prefs = ref.watch(themePrefsProvider);
    final brightness = ref.watch(platformBrightnessProvider);
    final notifier = ref.read(themePrefsProvider.notifier);
    final entry = chatId == null ? prefs.app : prefs.chats[chatId] ?? const ThemeChoice();
    final effective = prefs.resolve(chatId, brightness);
    final dark = allPresets[effective.preset]?.dark ?? true;
    void choose({Object? preset = _keep, Object? family = _keep, Object? accent = _keep, Object? wallpaper = _keep}) {
      final next = ThemeChoice(
        preset: preset == _keep ? entry.preset : preset as String?,
        family: family == _keep ? entry.family : family as String?,
        accent: accent == _keep ? entry.accent : accent as String?,
        wallpaper: wallpaper == _keep ? entry.wallpaper : wallpaper as String?,
      );
      chatId == null ? notifier.setApp(next) : notifier.setChat(chatId!, next);
    }

    final display = prefs.display;
    final scheme = Theme.of(context).colorScheme;
    final selectedFamily = allPresets[effective.preset]?.family;
    final ownTheme = chatId == null || entry.hasTheme;
    Widget label(String text) => Padding(padding: const EdgeInsets.only(top: 18, bottom: 8), child: Text(text, style: const TextStyle(fontWeight: FontWeight.w700)));

    return SafeArea(
      child: ConstrainedBox(
        constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * .88),
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(chatId == null ? 'Appearance' : 'Chat theme', style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700)),
              Text(chatId == null ? 'Every conversation without its own theme, on this device.' : 'Only this conversation, on this device.'),
              if (chatId == null) ...[
                label('Mode'),
                SegmentedButton<AppearanceMode>(
                  segments: const [
                    ButtonSegment(value: AppearanceMode.system, label: Text('System'), icon: Icon(Icons.brightness_auto_outlined)),
                    ButtonSegment(value: AppearanceMode.light, label: Text('Light'), icon: Icon(Icons.light_mode_outlined)),
                    ButtonSegment(value: AppearanceMode.dark, label: Text('Dark'), icon: Icon(Icons.dark_mode_outlined)),
                  ],
                  selected: {display.mode},
                  onSelectionChanged: (v) => notifier.setDisplay(display.copyWith(mode: v.first)),
                ),
              ],
              label('Theme'),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  if (chatId != null) _Swatch(label: 'Same as app', selected: !entry.hasTheme, onTap: () => choose(preset: null, family: null, accent: null)),
                  for (final f in families.values)
                    _Swatch(
                      key: Key('family-${f.key}'),
                      label: f.name,
                      tooltip: f.mood,
                      tokens: ChatTokens.resolve(f.variant(dark).key),
                      selected: ownTheme && selectedFamily == f.key,
                      onTap: () => choose(family: f.key, preset: null, accent: null),
                    ),
                ],
              ),
              if (selectedFamily != null && ownTheme)
                Padding(padding: const EdgeInsets.only(top: 8), child: Text(families[selectedFamily]!.mood, style: TextStyle(color: scheme.onSurface.withValues(alpha: .7)))),
              label('Earlier themes'),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  for (final p in presets.values)
                    _Swatch(
                      label: p.name,
                      tokens: ChatTokens.resolve(p.key),
                      selected: ownTheme && effective.preset == p.key,
                      onTap: () => choose(preset: p.key, family: null, accent: null),
                    ),
                ],
              ),
              label('Accent'),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  for (final hex in _accents)
                    Semantics(
                      button: true,
                      selected: effective.accent == hex,
                      label: 'Accent $hex',
                      child: InkWell(
                        customBorder: const CircleBorder(),
                        onTap: () => choose(accent: hex),
                        child: Container(
                          width: 34,
                          height: 34,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: Color(0xFF000000 | int.parse(hex.substring(1), radix: 16)),
                            border: Border.all(color: effective.accent == hex ? scheme.onSurface : Colors.transparent, width: 3),
                          ),
                        ),
                      ),
                    ),
                  if (entry.accent != null) TextButton(onPressed: () => choose(accent: null), child: const Text('Reset')),
                ],
              ),
              label('Wallpaper'),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ChoiceChip(label: const Text('Theme default'), selected: entry.wallpaper == null, onSelected: (_) => choose(wallpaper: null)),
                  for (final w in wallpapers.entries)
                    ChoiceChip(label: Text(w.value), selected: entry.wallpaper == w.key, onSelected: (_) => choose(wallpaper: w.key)),
                ],
              ),
              if (chatId == null) ...[
                label('Text size'),
                SegmentedButton<TextSize>(
                  segments: [for (final s in TextSize.values) ButtonSegment(value: s, label: Text(s.label))],
                  selected: {display.textSize},
                  onSelectionChanged: (v) => notifier.setDisplay(display.copyWith(textSize: v.first)),
                ),
                label('Spacing'),
                Text('The room between messages and between chats in the list. It grows with the text size.', style: TextStyle(color: scheme.onSurface.withValues(alpha: .7))),
                const SizedBox(height: 8),
                SegmentedButton<Density>(
                  segments: const [ButtonSegment(value: Density.comfortable, label: Text('Comfortable')), ButtonSegment(value: Density.compact, label: Text('Compact'))],
                  selected: {display.density},
                  onSelectionChanged: (v) => notifier.setDisplay(display.copyWith(density: v.first)),
                ),
                label('Chat list'),
                SegmentedButton<ListStyle>(
                  segments: const [ButtonSegment(value: ListStyle.detailed, label: Text('Detailed')), ButtonSegment(value: ListStyle.compact, label: Text('Compact'))],
                  selected: {display.listStyle},
                  onSelectionChanged: (v) => notifier.setDisplay(display.copyWith(listStyle: v.first)),
                ),
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text(
                    display.listStyle == ListStyle.detailed ? 'Each chat with its picture, the time and the last message.' : 'One line per chat.',
                    style: TextStyle(color: scheme.onSurface.withValues(alpha: .7)),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Align(alignment: Alignment.centerRight, child: FilledButton(onPressed: () => Navigator.pop(context), child: const Text('Done'))),
            ],
          ),
        ),
      ),
    );
  }
}

const _keep = Object();

class _Swatch extends StatelessWidget {
  const _Swatch({super.key, required this.label, required this.selected, required this.onTap, this.tokens, this.tooltip});
  final String label;
  final String? tooltip;
  final bool selected;
  final VoidCallback onTap;
  final ChatTokens? tokens;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final t = tokens;
    final swatch = Semantics(
      button: true,
      selected: selected,
      label: label,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 160),
          width: 96,
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: selected ? scheme.primary : scheme.outline.withValues(alpha: .4), width: selected ? 2.5 : 1),
          ),
          child: Column(
            children: [
              Container(
                height: 54,
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(color: t?.bg ?? scheme.surface, borderRadius: BorderRadius.circular(9)),
                child: t == null
                    ? const Center(child: Icon(Icons.layers_outlined, size: 20))
                    : Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Align(alignment: Alignment.centerLeft, child: _bar(t.theirs, 40)),
                          const SizedBox(height: 5),
                          Align(alignment: Alignment.centerRight, child: _bar(t.mine, 46)),
                          const Spacer(),
                          Align(alignment: Alignment.centerRight, child: CircleAvatar(radius: 4, backgroundColor: t.accent)),
                        ],
                      ),
              ),
              const SizedBox(height: 6),
              Text(
                label,
                style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600, fontFamily: t?.fontFamily, fontFamilyFallback: t?.fontFallback),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
      ),
    );
    return tooltip == null ? swatch : Tooltip(message: tooltip!, child: swatch);
  }

  Widget _bar(Color color, double width) =>
      Container(width: width, height: 10, decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(5)));
}
