import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/chat_settings.dart';

/// Settings → Chats: read receipts and link previews, for this account on this device.
Future<void> showChatSettings(BuildContext context, WidgetRef ref) =>
    showModalBottomSheet<void>(context: context, showDragHandle: true, builder: (_) => const _ChatSettingsSheet());

class _ChatSettingsSheet extends ConsumerWidget {
  const _ChatSettingsSheet();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(chatSettingsProvider);
    final notifier = ref.read(chatSettingsProvider.notifier);
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(8, 0, 8, 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(padding: const EdgeInsets.fromLTRB(16, 0, 16, 8), child: Text('Chats', style: Theme.of(context).textTheme.titleLarge)),
            SwitchListTile(
              key: const Key('read-receipts'),
              value: settings.readReceipts,
              onChanged: (v) => notifier.set(settings.copyWith(readReceipts: v)),
              title: const Text('Send read receipts'),
              subtitle: const Text("People see when you've read their messages. Turn it off and you won't see theirs either."),
            ),
            SwitchListTile(
              key: const Key('link-previews'),
              value: settings.linkPreviews,
              onChanged: (v) => notifier.set(settings.copyWith(linkPreviews: v)),
              title: const Text('Generate link previews'),
              subtitle: const Text('When you paste a link, the server fetches its title and picture for you. The person you send it to never fetches anything.'),
            ),
          ],
        ),
      ),
    );
  }
}
