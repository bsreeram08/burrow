import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:share_plus/share_plus.dart';

import '../app/app_controller.dart';
import 'account/backup_screen.dart';
import 'account/copy.dart' show resetBanner;
import '../messaging/linking.dart' show platformLabel;
import '../app/chat_settings.dart';
import '../core/api.dart';
import '../core/pair_id.dart';
import '../messaging/group_messenger.dart' show typingLine;
import '../store/message.dart';
import '../store/message_store.dart' show GroupConversation, GroupKindName, Membership;
import '../theme/theme_prefs.dart';
import 'channel_browser.dart';
import 'command_palette.dart';
import 'devices_screen.dart';
import 'conversation_view.dart' show messagePreview;
import 'new_group_sheet.dart';
import 'security_settings.dart';
import 'settings_sheet.dart';
import 'theme_picker.dart';
import 'widgets/common.dart';

class ChatListScreen extends ConsumerStatefulWidget {
  const ChatListScreen({super.key});
  @override
  ConsumerState<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends ConsumerState<ChatListScreen> {
  final _add = TextEditingController();
  Map<String, ChatMessage> _latest = {};
  StreamSubscription<String?>? _changes;

  @override
  void initState() {
    super.initState();
    final store = ref.read(appProvider.notifier).store;
    _changes = store?.changes.listen((_) => _refresh());
    _refresh();
  }

  Future<void> _refresh() async {
    final store = ref.read(appProvider.notifier).store;
    if (store == null) return;
    final latest = await store.latest();
    if (mounted) setState(() => _latest = latest);
  }

  @override
  void dispose() {
    _changes?.cancel();
    _add.dispose();
    super.dispose();
  }

  Future<void> _guard(Future<void> Function() task) async {
    try {
      await task();
    } on ApiException catch (e) {
      if (mounted) showSnack(context, e.message);
    }
  }

  Future<void> _invite() async {
    final invite = await ref.read(appProvider.notifier).createInvite();
    if (!mounted) return;
    final until = DateTime.fromMillisecondsSinceEpoch(invite.expiresAt);
    await showModalBottomSheet<void>(
      context: context,
      builder: (context) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Invite someone', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text('Works once, until ${until.day}/${until.month}. Share it privately — whoever has it can create an account.'),
            const SizedBox(height: 16),
            SelectableText(invite.link, style: const TextStyle(fontFamily: 'monospace')),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => Clipboard.setData(ClipboardData(text: invite.link)),
                    icon: const Icon(Icons.copy),
                    label: const Text('Copy'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: () => SharePlus.instance.share(ShareParams(text: invite.link)),
                    icon: const Icon(Icons.ios_share),
                    label: const Text('Share'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(appProvider);
    final app = ref.read(appProvider.notifier);
    final me = state.user;
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    ref.listen(appProvider.select((s) => s.notice), (_, notice) {
      if (notice != null) {
        showSnack(context, notice);
        app.dismissNotice();
      }
    });
    return Scaffold(
      appBar: AppBar(
        toolbarHeight: 76,
        titleSpacing: 20,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Chats', style: TextStyle(fontSize: 30, fontWeight: FontWeight.w800)),
            if (me != null) Text('@${me.username}', style: TextStyle(fontSize: 14, color: muted)),
          ],
        ),
        actions: [
          PopupMenuButton<String>(
            key: const Key('new-menu'),
            tooltip: 'New group or channel',
            icon: const Icon(Icons.edit_square),
            onSelected: (value) => switch (value) {
              'group' => showNewGroupSheet(context, ref, kind: GroupKindName.groupDm),
              'private' => showNewGroupSheet(context, ref, kind: GroupKindName.private),
              'public' => showNewGroupSheet(context, ref, kind: GroupKindName.public),
              'browse' => showChannelBrowser(context, ref),
              _ => null,
            },
            itemBuilder: (_) => const [
              PopupMenuItem(key: Key('new-group'), value: 'group', child: ListTile(leading: Icon(Icons.group_add_outlined), title: Text('New group'))),
              PopupMenuItem(key: Key('new-private'), value: 'private', child: ListTile(leading: Icon(Icons.lock_outline), title: Text('New private channel'))),
              PopupMenuItem(key: Key('new-public'), value: 'public', child: ListTile(leading: Icon(Icons.tag), title: Text('New public channel'))),
              PopupMenuItem(key: Key('browse-channels'), value: 'browse', child: ListTile(leading: Icon(Icons.travel_explore), title: Text('Browse channels'))),
            ],
          ),
          IconButton(
            key: const Key('open-palette'),
            tooltip: 'Search chats and actions (⌘K)',
            onPressed: () => showCommandPalette(context, ref),
            icon: const Icon(Icons.search_rounded),
          ),
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_horiz),
            onSelected: (value) => switch (value) {
              'invite' => _guard(_invite),
              'theme' => showThemePicker(context, ref),
              'chats' => showChatSettings(context, ref),
              'security' => showSecuritySettings(context, ref),
              'devices' => showDevices(context),
              'signout' => app.signOut(),
              'signout-all' => app.signOut(everywhere: true),
              _ => null,
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'invite', child: Text('Invite someone')),
              PopupMenuItem(value: 'theme', child: Text('Appearance')),
              PopupMenuItem(value: 'chats', child: Text('Chat settings')),
              PopupMenuItem(value: 'security', child: Text('Security')),
              PopupMenuItem(value: 'devices', child: Text('Devices')),
              PopupMenuItem(value: 'signout', child: Text('Sign out')),
              PopupMenuItem(value: 'signout-all', child: Text('Sign out everywhere')),
            ],
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 32),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 12),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _add,
                    autocorrect: false,
                    textInputAction: TextInputAction.done,
                    decoration: const InputDecoration(hintText: 'Add contact by username', isDense: true),
                    onSubmitted: (_) => _guard(() async {
                      await app.addContact(_add.text);
                      _add.clear();
                    }),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton.tonal(
                  onPressed: () => _guard(() async {
                    await app.addContact(_add.text);
                    _add.clear();
                  }),
                  child: const Text('Add'),
                ),
              ],
            ),
          ),
          // Another device changed the account key and removed devices: until dismissed (M6 §6.2).
          if (state.keyChangeNotice case final text?)
            MaterialBanner(
              key: const Key('key-change-notice'),
              content: Text(text),
              actions: [TextButton(onPressed: () => _guard(app.dismissKeyChangeNotice), child: const Text('Dismiss'))],
            ),
          // Someone asked to reset the account key: any of the user's devices can stop it (M6 §6.5).
          if (state.keyReset case final reset? when !reset.mine)
            MaterialBanner(
              key: const Key('reset-banner'),
              content: Text(resetBanner(platformLabel(reset.platform), reset.at)),
              actions: [
                TextButton(
                  key: const Key('reset-cancel'),
                  onPressed: () => _guard(app.cancelKeyReset),
                  child: const Text('Cancel it'),
                ),
              ],
            ),
          // Offered once after sign-in when the account has no backup (M6 §3.4).
          if (state.offerBackup)
            MaterialBanner(
              key: const Key('offer-backup'),
              content: const Text("Turn on account backup so you can sign in on a new device without your other devices, and a lost device can't lock you out."),
              actions: [
                TextButton(onPressed: app.dismissBackupOffer, child: const Text('Not now')),
                TextButton(
                  key: const Key('offer-backup-yes'),
                  onPressed: () {
                    app.dismissBackupOffer();
                    showAccountBackup(context);
                  },
                  child: const Text('Turn on'),
                ),
              ],
            ),
          if (state.groupsUnavailable != null)
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 8),
              child: Text(state.groupsUnavailable!, key: const Key('groups-unavailable'), style: TextStyle(color: muted, fontSize: 13)),
            ),
          if (state.contacts.isEmpty && state.groups.isEmpty)
            Padding(
              padding: const EdgeInsets.all(32),
              child: Text(
                'Your conversations will appear here. Add someone by their username above, or invite them with a link from the ⋯ menu.',
                textAlign: TextAlign.center,
                style: TextStyle(color: muted),
              ),
            ),
          ..._sections(context, state, me),
        ],
      ),
    );
  }

  /// Pinned, Channels, Groups and Direct messages (design notes §4), newest activity first.
  List<Widget> _sections(BuildContext context, AppState state, User? me) {
    final pins = ref.watch(chatSettingsProvider.select((s) => s.pinned));
    int recent(String id, int fallback) => _latest[id]?.createdAt ?? fallback;
    final groups = [...state.groups]..sort((a, b) => recent(b.id, b.createdAt).compareTo(recent(a.id, a.createdAt)));
    final mutual = [for (final c in state.contacts) if (c.state == ContactState.mutual && c.id != null && me != null) c]
      ..sort((a, b) => recent(pairId(me!.id, b.id!), 0).compareTo(recent(pairId(me.id, a.id!), 0)));
    final pending = [for (final c in state.contacts) if (c.state != ContactState.mutual || c.id == null) c];
    bool pinnedDm(Contact c) => me != null && pins.contains(pairId(me.id, c.id!));
    final pinned = [
      for (final g in groups) if (g.pinned) _groupRow(context, g, state),
      for (final c in mutual) if (pinnedDm(c)) _row(context, c, me, state.unread, state.typing),
    ];
    final channels = [for (final g in groups) if (!g.pinned && g.kind.isChannel) _groupRow(context, g, state)];
    final grouped = [for (final g in groups) if (!g.pinned && !g.kind.isChannel) _groupRow(context, g, state)];
    final direct = [
      for (final c in mutual) if (!pinnedDm(c)) _row(context, c, me, state.unread, state.typing),
      for (final c in pending) _row(context, c, me, state.unread, state.typing),
    ];
    return [
      if (pinned.isNotEmpty) ...[const _SectionHeader('Pinned', key: Key('section-pinned')), ...pinned],
      _SectionHeader(
        'Channels',
        key: const Key('section-channels'),
        action: TextButton(key: const Key('browse'), onPressed: () => showChannelBrowser(context, ref), child: const Text('Browse')),
      ),
      ...channels,
      if (groups.isNotEmpty || grouped.isNotEmpty) ...[
        _SectionHeader(
          'Groups',
          key: const Key('section-groups'),
          action: TextButton(onPressed: () => showNewGroupSheet(context, ref, kind: GroupKindName.groupDm), child: const Text('New')),
        ),
        ...grouped,
      ],
      if (direct.isNotEmpty) ...[const _SectionHeader('Direct messages', key: Key('section-direct')), ...direct],
    ];
  }

  Future<void> _rowMenu(BuildContext context, {required bool pinned, required VoidCallback onPin, GroupConversation? group}) async {
    final choice = await showModalBottomSheet<String>(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: Icon(pinned ? Icons.push_pin_outlined : Icons.push_pin),
              title: Text(pinned ? 'Unpin' : 'Keep this chat at the top'),
              onTap: () => Navigator.pop(context, 'pin'),
            ),
            if (group != null && !group.active)
              ListTile(leading: const Icon(Icons.delete_outline), title: const Text('Delete from this device'), onTap: () => Navigator.pop(context, 'forget')),
          ],
        ),
      ),
    );
    if (choice == 'pin') onPin();
    if (choice == 'forget' && group != null) await ref.read(appProvider.notifier).groups?.forget(group.id);
  }

  Widget _groupRow(BuildContext context, GroupConversation group, AppState state) {
    final app = ref.read(appProvider.notifier);
    final messenger = app.groups;
    final scheme = Theme.of(context).colorScheme;
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final display = ref.watch(themePrefsProvider.select((p) => p.display));
    final tokens = ref.watch(themePrefsProvider).tokens(null, ref.watch(platformBrightnessProvider));
    final name = messenger?.displayName(group) ?? group.name;
    final recent = _latest[group.id];
    final typing = [for (final id in state.groupTyping[group.id] ?? const <String>[]) messenger?.nameOf(id) ?? 'someone'];
    final count = group.unread;
    final String preview;
    if (!group.active) {
      preview = group.membership == Membership.left ? 'You left' : 'You were removed';
    } else if (typing.isNotEmpty) {
      preview = '${typingLine(typing)}…';
    } else if (recent != null) {
      preview = recent.system ? recent.text : '${recent.outgoing ? 'You' : (recent.senderName ?? 'someone')}: ${messagePreview(recent)}';
    } else {
      preview = group.topic.isNotEmpty ? group.topic : (group.kind == GroupKindName.public ? 'Public channel' : 'End-to-end encrypted');
    }
    final previewStyle = TextStyle(
      color: typing.isNotEmpty ? scheme.primary : (count > 0 ? null : muted),
      fontWeight: count > 0 ? FontWeight.w600 : null,
      fontStyle: typing.isNotEmpty || !group.active ? FontStyle.italic : null,
    );
    final time = recent != null ? Text(clock(recent.createdAt), style: TextStyle(fontSize: 12, color: count > 0 ? scheme.primary : muted)) : null;
    final badges = [
      if (group.mentioned) Badge(key: ValueKey('mention-${group.id}'), label: const Text('@'), backgroundColor: scheme.primary, textColor: scheme.onPrimary),
      if (count > 0) Badge(label: Text(count > 99 ? '99+' : '$count'), backgroundColor: scheme.primary, textColor: scheme.onPrimary),
    ];
    final icon = group.kind.isChannel ? (group.kind == GroupKindName.public ? Icons.tag : Icons.lock_outline) : Icons.group_outlined;
    void open() => context.push('/group/${group.id}');
    void pin() => unawaited(messenger?.setPinned(group.id, !group.pinned));
    final leading = Container(
      width: display.listStyle == ListStyle.compact ? 28 : 48,
      height: display.listStyle == ListStyle.compact ? 28 : 48,
      decoration: BoxDecoration(color: tokens.nameColor(group.id).withValues(alpha: .16), borderRadius: BorderRadius.circular(tokens.square ? 8 : 24)),
      child: Icon(icon, color: tokens.nameColor(group.id), size: display.listStyle == ListStyle.compact ? 16 : 24),
    );
    final title = Text(group.kind.isChannel ? name : name, maxLines: 1, overflow: TextOverflow.ellipsis, style: TextStyle(fontWeight: FontWeight.w700, fontSize: display.listStyle == ListStyle.compact ? null : 17, color: group.active ? null : muted));
    if (display.listStyle == ListStyle.compact) {
      return InkWell(
        key: ValueKey('group-${group.id}'),
        onTap: open,
        onLongPress: () => _rowMenu(context, pinned: group.pinned, onPin: pin, group: group),
        child: Padding(
          padding: EdgeInsets.symmetric(horizontal: 16, vertical: 6 + display.rowPadding),
          child: Row(
            children: [
              leading,
              const SizedBox(width: 10),
              Flexible(child: title),
              const SizedBox(width: 10),
              Expanded(child: Text(preview, maxLines: 1, overflow: TextOverflow.ellipsis, style: previewStyle)),
              if (time != null) ...[const SizedBox(width: 8), time],
              for (final b in badges) ...[const SizedBox(width: 6), b],
            ],
          ),
        ),
      );
    }
    return ListTile(
      key: ValueKey('group-${group.id}'),
      contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: display.rowPadding / 2),
      leading: leading,
      title: title,
      subtitle: Text(preview, maxLines: 1, overflow: TextOverflow.ellipsis, style: previewStyle),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          ?time,
          if (badges.isNotEmpty) ...[const SizedBox(height: 4), Row(mainAxisSize: MainAxisSize.min, spacing: 4, children: badges)],
        ],
      ),
      onTap: open,
      onLongPress: () => _rowMenu(context, pinned: group.pinned, onPin: pin, group: group),
    );
  }

  Widget _row(BuildContext context, Contact contact, User? me, Map<String, int> unread, Set<String> typing) {
    final app = ref.read(appProvider.notifier);
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final scheme = Theme.of(context).colorScheme;
    if (contact.state != ContactState.mutual || contact.id == null || me == null) {
      return ListTile(
        leading: Avatar(name: contact.username),
        title: Text(contact.username, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Text(contact.state == ContactState.incoming ? 'Wants to add you' : 'Request sent', style: TextStyle(color: muted)),
        trailing: Wrap(
          spacing: 8,
          children: [
            if (contact.state == ContactState.incoming) FilledButton(onPressed: () => _guard(() => app.acceptContact(contact)), child: const Text('Accept')),
            OutlinedButton(
              onPressed: () => _guard(() => app.removeContact(contact)),
              child: Text(contact.state == ContactState.incoming ? 'Decline' : 'Cancel'),
            ),
          ],
        ),
      );
    }
    final recent = _latest[pairId(me.id, contact.id!)];
    final count = unread[contact.id] ?? 0;
    final display = ref.watch(themePrefsProvider.select((p) => p.display));
    final tokens = ref.watch(themePrefsProvider).tokens(null, ref.watch(platformBrightnessProvider));
    final isTyping = typing.contains(contact.id);
    final preview = isTyping
        ? 'typing…'
        : recent != null
        ? '${recent.outgoing ? 'You: ' : ''}${messagePreview(recent)}'
        : (contact.online ? 'Online' : 'Say hello. Messages are end-to-end encrypted.');
    final previewStyle = TextStyle(
      color: isTyping ? scheme.primary : (count > 0 ? null : muted),
      fontWeight: count > 0 ? FontWeight.w600 : null,
      fontStyle: isTyping ? FontStyle.italic : null,
    );
    final time = recent != null ? Text(clock(recent.createdAt), style: TextStyle(fontSize: 12, color: count > 0 ? scheme.primary : muted)) : null;
    final badge = count > 0 ? Badge(label: Text(count > 99 ? '99+' : '$count'), backgroundColor: scheme.primary, textColor: scheme.onPrimary) : null;
    void open() => context.push('/chat/${contact.id}');
    final conversation = pairId(me.id, contact.id!);
    void pin() {
      final settings = ref.read(chatSettingsProvider);
      final next = {...settings.pinned};
      next.contains(conversation) ? next.remove(conversation) : next.add(conversation);
      ref.read(chatSettingsProvider.notifier).set(settings.copyWith(pinned: next));
    }

    void menu() => _rowMenu(context, pinned: ref.read(chatSettingsProvider).pinned.contains(conversation), onPin: pin);
    if (display.listStyle == ListStyle.compact) {
      return InkWell(
        key: ValueKey(contact.id),
        onTap: open,
        onLongPress: menu,
        child: Padding(
          padding: EdgeInsets.symmetric(horizontal: 16, vertical: 6 + display.rowPadding),
          child: Row(
            children: [
              if (contact.online) ...[const Icon(Icons.circle, size: 8, color: Color(0xFF3CD07A)), const SizedBox(width: 6)],
              Text(contact.username, style: TextStyle(fontWeight: FontWeight.w700, color: tokens.square ? null : tokens.nameColor(contact.id!))),
              const SizedBox(width: 10),
              Expanded(child: Text(preview, maxLines: 1, overflow: TextOverflow.ellipsis, style: previewStyle)),
              if (time != null) ...[const SizedBox(width: 8), time],
              if (badge != null) ...[const SizedBox(width: 8), badge],
            ],
          ),
        ),
      );
    }
    return ListTile(
      key: ValueKey(contact.id),
      contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: display.rowPadding / 2),
      leading: Avatar(name: contact.username, online: contact.online, square: tokens.square, color: tokens.square ? null : tokens.nameColor(contact.id!)),
      title: Text(contact.username, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 17)),
      subtitle: Text(preview, maxLines: 1, overflow: TextOverflow.ellipsis, style: previewStyle),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          ?time,
          if (badge != null) ...[const SizedBox(height: 4), badge],
        ],
      ),
      onTap: open,
      onLongPress: menu,
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title, {super.key, this.action});
  final String title;
  final Widget? action;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.fromLTRB(20, 14, 8, 2),
    child: Row(
      children: [
        Expanded(
          child: Text(
            title.toUpperCase(),
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w800, letterSpacing: .8, color: Theme.of(context).textTheme.bodySmall?.color),
          ),
        ),
        ?action,
      ],
    ),
  );
}
