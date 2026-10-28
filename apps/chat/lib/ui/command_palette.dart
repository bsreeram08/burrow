import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../text/fuzzy.dart';
import '../theme/theme_prefs.dart';
import 'settings_sheet.dart';
import 'theme_picker.dart';
import 'widgets/common.dart';

/// "Search this chat" for the conversation on screen, if any (set by the conversation screen).
class ChatSearch extends Notifier<({Object owner, VoidCallback run})?> {
  @override
  ({Object owner, VoidCallback run})? build() => null;
  void set(Object owner, VoidCallback run) => state = (owner: owner, run: run);
  void clear(Object owner) {
    if (state?.owner == owner) state = null;
  }
}

final chatSearchProvider = NotifierProvider<ChatSearch, ({Object owner, VoidCallback run})?>(ChatSearch.new);

/// Recently run palette items, newest first (this session).
class PaletteRecents extends Notifier<List<String>> {
  @override
  List<String> build() => const [];
  void used(String id) => state = [id, ...state.where((r) => r != id)].take(8).toList();
}

final paletteRecentsProvider = NotifierProvider<PaletteRecents, List<String>>(PaletteRecents.new);

class PaletteItem {
  const PaletteItem({required this.id, required this.title, required this.icon, required this.run, this.subtitle});
  final String id, title;
  final String? subtitle;
  final IconData icon;
  final void Function(BuildContext context) run;
}

/// Builds the palette's items: conversations (jump) and actions.
List<PaletteItem> paletteItems(WidgetRef ref) {
  final state = ref.read(appProvider);
  final search = ref.read(chatSearchProvider);
  final items = <PaletteItem>[
    for (final c in state.contacts)
      if (c.state == ContactState.mutual && c.id != null)
        PaletteItem(
          id: 'chat:${c.id}',
          title: c.username,
          subtitle: c.online ? 'Conversation · online' : 'Conversation',
          icon: Icons.chat_bubble_outline_rounded,
          run: (context) {
            final router = GoRouter.of(context);
            final inChat = router.routerDelegate.currentConfiguration.uri.path.startsWith('/chat/');
            inChat ? router.pushReplacement('/chat/${c.id}') : router.push('/chat/${c.id}');
          },
        ),
    PaletteItem(
      id: 'new',
      title: 'New conversation',
      subtitle: 'Add a contact by username',
      icon: Icons.person_add_alt_1_outlined,
      run: (context) => showNewConversation(context, ref),
    ),
    PaletteItem(
      id: 'settings',
      title: 'Settings',
      subtitle: 'Read receipts, link previews',
      icon: Icons.settings_outlined,
      run: (context) => showChatSettings(context, ref),
    ),
    PaletteItem(
      id: 'theme',
      title: 'Theme…',
      subtitle: 'Colours, text size, spacing',
      icon: Icons.palette_outlined,
      run: (context) => showThemePicker(context, ref),
    ),
    PaletteItem(
      id: 'density',
      title: 'Toggle density',
      subtitle: ref.read(themePrefsProvider).display.density == Density.compact ? 'Now compact' : 'Now comfortable',
      icon: Icons.density_medium_rounded,
      run: (_) => ref.read(themePrefsProvider.notifier).toggleDensity(),
    ),
    if (search != null) PaletteItem(id: 'find', title: 'Search this chat', icon: Icons.manage_search_rounded, run: (_) => search.run()),
  ];
  return items;
}

/// ⌘K / Ctrl+K, or the search button on phones.
Future<void> showCommandPalette(BuildContext context, WidgetRef ref) async {
  final items = paletteItems(ref);
  final picked = await showDialog<PaletteItem>(
    context: context,
    barrierColor: Colors.black54,
    builder: (_) => _Palette(items: items, recents: ref.read(paletteRecentsProvider)),
  );
  if (picked == null || !context.mounted) return;
  ref.read(paletteRecentsProvider.notifier).used(picked.id);
  picked.run(context);
}

/// Prompts for a username and sends a contact request.
Future<void> showNewConversation(BuildContext context, WidgetRef ref) async {
  final controller = TextEditingController();
  final name = await showDialog<String>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('New conversation'),
      content: TextField(
        controller: controller,
        autofocus: true,
        autocorrect: false,
        decoration: const InputDecoration(hintText: 'Their username'),
        onSubmitted: (v) => Navigator.pop(context, v),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, controller.text), child: const Text('Send request')),
      ],
    ),
  );
  controller.dispose();
  if (name == null || name.trim().isEmpty) return;
  try {
    await ref.read(appProvider.notifier).addContact(name);
  } on ApiException catch (e) {
    if (context.mounted) showSnack(context, e.message);
  }
}

class _Palette extends StatefulWidget {
  const _Palette({required this.items, required this.recents});
  final List<PaletteItem> items;
  final List<String> recents;
  @override
  State<_Palette> createState() => _PaletteState();
}

class _PaletteState extends State<_Palette> {
  final _query = TextEditingController();
  int _selected = 0;

  List<PaletteItem> get _ordered {
    final rank = {for (var i = 0; i < widget.recents.length; i++) widget.recents[i]: i};
    final items = List.of(widget.items)..sort((a, b) => (rank[a.id] ?? 999).compareTo(rank[b.id] ?? 999));
    return fuzzyFilter(_query.text, items, (i) => '${i.title} ${i.subtitle ?? ''}');
  }

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final results = _ordered;
    final scheme = Theme.of(context).colorScheme;
    if (_selected >= results.length) _selected = results.isEmpty ? 0 : results.length - 1;
    // On a phone it sits at the top, inset from the edges and above the keyboard, so it never half-covers the
    // header behind it; wider screens keep it floating in the upper middle.
    final phone = MediaQuery.sizeOf(context).width < 600;
    return SafeArea(
      child: Padding(
        padding: EdgeInsets.fromLTRB(12, 12, 12, 12 + MediaQuery.viewInsetsOf(context).bottom),
        child: Align(
          alignment: phone ? Alignment.topCenter : const Alignment(0, -.5),
          child: Material(
            elevation: 12,
            borderRadius: BorderRadius.circular(16),
            clipBehavior: Clip.antiAlias,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560, maxHeight: 440),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CallbackShortcuts(
                    bindings: {
                      const SingleActivator(LogicalKeyboardKey.arrowDown): () =>
                          setState(() => _selected = results.isEmpty ? 0 : (_selected + 1) % results.length),
                      const SingleActivator(LogicalKeyboardKey.arrowUp): () =>
                          setState(() => _selected = results.isEmpty ? 0 : (_selected - 1 + results.length) % results.length),
                    },
                    child: TextField(
                      key: const Key('palette-input'),
                      controller: _query,
                      autofocus: true,
                      decoration: const InputDecoration(
                        hintText: 'Jump to a chat or run an action',
                        prefixIcon: Icon(Icons.search),
                        border: InputBorder.none,
                        enabledBorder: InputBorder.none,
                        filled: false,
                        contentPadding: EdgeInsets.symmetric(vertical: 16),
                      ),
                      onChanged: (_) => setState(() => _selected = 0),
                      onSubmitted: (_) {
                        if (results.isNotEmpty) Navigator.pop(context, results[_selected]);
                      },
                    ),
                  ),
                  const Divider(height: 1),
                  Flexible(
                    child: results.isEmpty
                        ? const Padding(padding: EdgeInsets.all(24), child: Text('Nothing matches. Try a contact name or an action like "theme".'))
                        : ListView.builder(
                            shrinkWrap: true,
                            padding: const EdgeInsets.symmetric(vertical: 6),
                            itemCount: results.length,
                            itemBuilder: (context, i) {
                              final item = results[i];
                              final recent = widget.recents.contains(item.id) && _query.text.isEmpty;
                              return ListTile(
                                dense: true,
                                selected: i == _selected,
                                selectedTileColor: scheme.primary.withValues(alpha: .12),
                                leading: Icon(item.icon),
                                title: Text(item.title, style: const TextStyle(fontWeight: FontWeight.w600)),
                                subtitle: item.subtitle == null && !recent ? null : Text([if (recent) 'Recent', ?item.subtitle].join(' · ')),
                                onTap: () => Navigator.pop(context, item),
                              );
                            },
                          ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// The app-wide ⌘K / Ctrl+K binding. [navigatorContext] returns a context under the navigator.
class PaletteShortcut extends ConsumerWidget {
  const PaletteShortcut({super.key, required this.child, required this.navigatorContext});
  final Widget child;
  final BuildContext? Function() navigatorContext;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    void open() {
      final nav = navigatorContext();
      if (nav != null && ref.read(appProvider).phase == AuthPhase.signedIn) unawaited(showCommandPalette(nav, ref));
    }

    return CallbackShortcuts(
      bindings: {const SingleActivator(LogicalKeyboardKey.keyK, meta: true): open, const SingleActivator(LogicalKeyboardKey.keyK, control: true): open},
      child: Focus(autofocus: true, child: child),
    );
  }
}
