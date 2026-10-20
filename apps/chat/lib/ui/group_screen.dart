import 'dart:async';
import 'dart:io' show Platform;

import 'package:cross_file/cross_file.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/app_controller.dart';
import '../app/chat_settings.dart';
import '../core/api.dart';
import '../messaging/attachments.dart';
import '../messaging/group_messenger.dart';
import '../messaging/group_sync.dart' show FrozenVerdict;
import '../store/message.dart';
import '../store/message_store.dart' show Frozen, GroupConversation, GroupKindName, Membership;
import '../theme/theme_prefs.dart';
import '../theme/tokens.dart';
import 'command_palette.dart';
import 'conversation_view.dart';
import 'group_info_sheet.dart';
import 'sending.dart';
import 'theme_picker.dart';
import 'widgets/common.dart';
import 'widgets/voice_recorder.dart';

/// A group or channel (docs/m4-groups.md): the shared conversation view in group mode, with the member
/// count or who is typing in the header, the frozen / paused banners, and a read-only footer once this
/// device left or was removed.
class GroupScreen extends ConsumerStatefulWidget {
  const GroupScreen({super.key, required this.groupId});
  final String groupId;
  @override
  ConsumerState<GroupScreen> createState() => _GroupScreenState();
}

class _GroupScreenState extends ConsumerState<GroupScreen> with AttachmentSending {
  List<ChatMessage>? _messages;
  List<GroupPerson> _members = const [];
  bool _admin = false;
  StreamSubscription<String?>? _changes;
  StreamSubscription<String>? _membership;
  late final AppController _app = ref.read(appProvider.notifier);
  late final ChatSearch _search = ref.read(chatSearchProvider.notifier);
  final _view = GlobalKey<ConversationViewState>();
  late final AppLifecycleListener _lifecycle;
  bool _focused = true, _dropping = false;
  Frozen? _verdictFor;
  FrozenVerdict? _verdict;
  final List<ChatMessage> _unreported = [];

  GroupMessenger? get _groups => _app.groups;

  @override
  String get conversationId => widget.groupId;

  @override
  SendAttachment get sendAttachment => (attachment, {replyTo, disappearAfter}) async {
    await _groups!.send(widget.groupId, '', attachment: attachment, replyTo: replyTo, disappearAfter: disappearAfter);
  };

  @override
  void initState() {
    super.initState();
    _app.openGroup(widget.groupId);
    _changes = _app.store?.changes.listen((id) {
      if (id == null || id == widget.groupId) _load();
    });
    _membership = _groups?.sync.membershipChanges.listen((id) {
      if (id == widget.groupId) _loadMembers(refresh: true);
    });
    final lifecycle = WidgetsBinding.instance.lifecycleState;
    _focused = lifecycle == null || lifecycle == AppLifecycleState.resumed;
    _lifecycle = AppLifecycleListener(onStateChange: (state) {
      _focused = state == AppLifecycleState.resumed;
      if (_focused) _displayed(const []);
    });
    WidgetsBinding.instance.addPostFrameCallback((_) => _search.set(this, () => _view.currentState?.openFind()));
    _load();
    _loadMembers(refresh: true);
  }

  Future<void> _load() async {
    final list = await _app.store?.list(widget.groupId) ?? const <ChatMessage>[];
    if (mounted) setState(() => _messages = list);
  }

  Future<void> _loadMembers({bool refresh = false}) async {
    final groups = _groups;
    if (groups == null) return;
    final members = await groups.members(widget.groupId, refresh: refresh);
    final admin = await groups.isAdmin(widget.groupId);
    if (mounted) {
      setState(() {
        _members = members;
        _admin = admin;
      });
    }
  }

  void _displayed(List<ChatMessage> messages) {
    _unreported.addAll(messages);
    if (!_focused || _unreported.isEmpty) return;
    _groups?.displayed(widget.groupId, List.of(_unreported));
    _unreported.clear();
  }

  @override
  void dispose() {
    _changes?.cancel();
    _membership?.cancel();
    _lifecycle.dispose();
    _app.closeGroup();
    unawaited(_groups?.typingChanged(widget.groupId, on: false));
    Future.microtask(() => _search.clear(this));
    super.dispose();
  }

  String _nameOf(String userId) => _groups?.nameOf(userId) ?? userId;

  Future<void> _readBy(ChatMessage m) async {
    final others = [for (final p in _members) if (p.userId != ref.read(appProvider).user?.id) p];
    final read = [for (final p in others) if (m.readBy.contains(p.userId)) p.username];
    final waiting = [for (final p in others) if (!m.readBy.contains(p.userId)) p.username];
    await showModalBottomSheet<void>(
      context: context,
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(waiting.isEmpty && read.isNotEmpty ? 'Read by everyone' : 'Read by', style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              Text(read.isEmpty ? 'Nobody yet.' : read.join(', ')),
              if (waiting.isNotEmpty) ...[
                const SizedBox(height: 12),
                Text('Not yet', style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 4),
                Text(waiting.join(', ')),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget? _banner(GroupConversation group, ChatTokens t, String? pausedFor) {
    Widget bar(String text, {List<Widget> actions = const [], Key? key}) => Material(
      color: t.warnBg,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 10, 8, 10),
        child: Row(
          children: [
            Icon(Icons.pause_circle_outline_rounded, color: t.warn),
            const SizedBox(width: 10),
            Expanded(child: Text(text, key: key, style: TextStyle(color: t.text, fontSize: 14))),
            ...actions,
          ],
        ),
      ),
    );
    final frozen = group.frozen;
    if (frozen != null) {
      if (!_admin) return bar('This channel is paused while an admin checks a change.', key: const Key('frozen-banner'));
      // Rollback only after this admin device checked the reported commit itself and found it bad.
      if (_verdictFor != frozen) {
        _verdictFor = frozen;
        _verdict = null;
        unawaited(_groups?.sync.checkFrozen(widget.groupId).then((v) {
          if (mounted && _verdictFor == frozen) setState(() => _verdict = v);
        }));
      }
      final verdict = _verdict;
      return bar(
        switch (verdict) {
          FrozenVerdict.fails => 'A change to ${_title(group)} was rejected by a member, and this device rejects it too.',
          FrozenVerdict.ok => 'A member reported a change to ${_title(group)}, but it checks out on this device.',
          FrozenVerdict.unknown => "A member reported a change to ${_title(group)}. This device couldn't check it.",
          null => 'A change to ${_title(group)} was reported by a member. Checking it…',
        },
        key: const Key('frozen-banner'),
        actions: [
          if (verdict == FrozenVerdict.fails) TextButton(key: const Key('rollback'), onPressed: () => _resolve(rollback: true), child: const Text('Roll back')),
          if (verdict != null) TextButton(key: const Key('dismiss'), onPressed: () => _resolve(rollback: false), child: const Text('Dismiss')),
        ],
      );
    }
    if (pausedFor != null) {
      return bar(
        "Review ${_nameOf(pausedFor)}'s security code to keep reading this ${group.kind.isChannel ? 'channel' : 'group'}.",
        key: const Key('paused-banner'),
        actions: [TextButton(onPressed: () => showMemberSafety(context, ref, pausedFor, _nameOf(pausedFor)), child: const Text('Review'))],
      );
    }
    return null;
  }

  Future<void> _resolve({required bool rollback}) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(rollback ? 'Roll back this change?' : 'Keep this change?'),
        content: Text(
          rollback
              ? "The change is undone for everyone, and the device that made it is removed from this channel."
              : "The change stays. Devices that rejected it rejoin the channel; they can't read what was sent in between.",
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: Text(rollback ? 'Roll back' : 'Dismiss')),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await _groups!.sync.resolve(widget.groupId, rollback: rollback);
    } catch (e) {
      if (mounted) showSnack(context, e is ApiException ? e.message : (e is StoreException ? e.message : 'Could not resolve: $e'));
    }
  }

  String _title(GroupConversation group) {
    final name = _groups?.displayName(group) ?? group.name;
    return group.kind.isChannel ? '#$name' : name;
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(appProvider);
    final group = _app.groupById(widget.groupId);
    if (group == null) return const Scaffold(body: Center(child: Text('This group is not on this device.')));
    final prefs = ref.watch(themePrefsProvider);
    final brightness = ref.watch(platformBrightnessProvider);
    final tokens = prefs.tokens(widget.groupId, brightness);
    final resolved = prefs.resolve(widget.groupId, brightness);
    final settings = ref.watch(chatSettingsProvider);
    final me = state.user?.id ?? '';
    final typing = [for (final id in state.groupTyping[widget.groupId] ?? const <String>[]) if (id != me) _nameOf(id)];
    final subtitle = typing.isNotEmpty
        ? '${typingLine(typing)}…'
        : !group.active
        ? (group.membership == Membership.left ? 'You left' : 'You were removed')
        : group.topic.isNotEmpty
        ? group.topic
        : (_members.isEmpty ? (group.kind == GroupKindName.public ? 'Public channel' : 'Group') : '${_members.length} ${_members.length == 1 ? 'member' : 'members'}');
    final readOnly = group.active
        ? null
        : group.membership == Membership.left
        ? 'You left this ${group.kind.isChannel ? 'channel' : 'group'}.'
        : 'You were removed from ${_title(group)}.';
    final icon = group.kind.isChannel ? (group.kind == GroupKindName.public ? Icons.tag : Icons.lock_outline) : Icons.group_outlined;
    return Theme(
      data: tokens.material(),
      child: Scaffold(
        appBar: AppBar(
          titleSpacing: 0,
          title: InkWell(
            key: const Key('group-title'),
            onTap: () => showGroupInfo(context, ref, widget.groupId),
            child: Row(
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(color: tokens.nameColor(widget.groupId).withValues(alpha: .16), borderRadius: BorderRadius.circular(tokens.square ? 8 : 20)),
                  child: Icon(icon, color: tokens.nameColor(widget.groupId), size: 22),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(_title(group), maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w700)),
                      Text(subtitle, maxLines: 1, overflow: TextOverflow.ellipsis, style: TextStyle(fontSize: 13, color: typing.isNotEmpty ? tokens.accent : tokens.muted)),
                    ],
                  ),
                ),
              ],
            ),
          ),
          actions: [
            IconButton(tooltip: 'Find in conversation', onPressed: () => _view.currentState?.openFind(), icon: const Icon(Icons.search_rounded)),
            IconButton(key: const Key('group-info'), tooltip: 'Conversation info', onPressed: () => showGroupInfo(context, ref, widget.groupId), icon: const Icon(Icons.info_outline_rounded)),
            PopupMenuButton<String>(
              icon: const Icon(Icons.more_horiz),
              onSelected: (v) => switch (v) {
                'theme' => showThemePicker(context, ref, chatId: widget.groupId),
                'pin' => _groups?.setPinned(widget.groupId, !group.pinned),
                _ => null,
              },
              itemBuilder: (_) => [
                PopupMenuItem(value: 'pin', child: Text(group.pinned ? 'Unpin' : 'Keep this chat at the top')),
                const PopupMenuItem(value: 'theme', child: Text('Chat theme')),
              ],
            ),
          ],
        ),
        body: _messages == null
            ? const SizedBox.shrink()
            : _dropTarget(
                accent: tokens.accent,
                enabled: group.active,
                child: ValueListenableBuilder<List<PendingUpload>>(
                  valueListenable: attachmentService.uploads,
                  builder: (context, uploads, _) => ConversationView(
                    key: _view,
                    tokens: tokens,
                    wallpaper: resolved.wallpaper,
                    messages: _messages!,
                    peerName: _title(group),
                    display: prefs.display,
                    showRead: settings.readReceipts,
                    uploads: [for (final u in uploads) if (u.conversationId == widget.groupId) u],
                    actions: _GroupActions(this),
                    nameOf: _nameOf,
                    members: _members,
                    me: me,
                    typingText: typing.isEmpty ? null : typingLine(typing),
                    banner: _banner(group, tokens, state.pausedGroups[widget.groupId]),
                    readOnly: readOnly,
                    emptyText: group.kind == GroupKindName.public
                        ? 'No messages yet. Anyone can join this channel; new members see messages from when they join.'
                        : 'No messages yet. What you send here is end-to-end encrypted: only the members can read it.',
                    onReadInfo: _readBy,
                    onSend: (draft) async {
                      await _groups!.send(widget.groupId, draft.text, disappearAfter: draft.disappearAfter, replyTo: draft.replyTo, link: draft.link);
                    },
                  ),
                ),
              ),
      ),
    );
  }

  static final _desktop = !kIsWeb && (Platform.isMacOS || Platform.isWindows || Platform.isLinux);

  Widget _dropTarget({required Widget child, required Color accent, required bool enabled}) {
    if (!_desktop || !enabled) return child;
    return DropTarget(
      onDragEntered: (_) => setState(() => _dropping = true),
      onDragExited: (_) => setState(() => _dropping = false),
      onDragDone: (details) {
        setState(() => _dropping = false);
        unawaited(attachFiles(details.files));
      },
      child: Stack(
        children: [
          child,
          if (_dropping)
            Positioned.fill(
              child: IgnorePointer(
                child: Container(
                  margin: const EdgeInsets.all(12),
                  decoration: BoxDecoration(color: accent.withValues(alpha: .08), borderRadius: BorderRadius.circular(16), border: Border.all(color: accent, width: 2)),
                  child: const Center(child: Text('Drop to send, end-to-end encrypted', style: TextStyle(fontWeight: FontWeight.w700))),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _GroupActions extends ConversationActions {
  const _GroupActions(this.s);
  final _GroupScreenState s;

  @override
  Future<void> react(ChatMessage message, String emoji, bool on) async => s._groups!.react(s.widget.groupId, message, emoji, on: on);
  @override
  Future<void> edit(ChatMessage message, String text) async => s._groups!.edit(s.widget.groupId, message, text);
  @override
  Future<List<XFile>> pickFiles({required bool media}) => s.pickFiles(media: media);
  @override
  Future<void> attach(List<XFile> files, {ReplyTo? replyTo, Duration? disappearAfter}) => s.attachFiles(files, replyTo: replyTo, disappearAfter: disappearAfter);
  @override
  Future<void> sendVoice(VoiceNote note, {ReplyTo? replyTo, Duration? disappearAfter}) => s.sendVoiceNote(note, replyTo: replyTo, disappearAfter: disappearAfter);
  @override
  void typing(bool on) => unawaited(s._groups?.typingChanged(s.widget.groupId, on: on));
  @override
  void displayed(List<ChatMessage> messages) => s._displayed(messages);
  @override
  Future<LinkPreview?> unfurl(String url) => s.unfurlLink(url);
  @override
  AttachmentService get attachments => s.attachmentService;
  @override
  bool get canRecord => true;
  @override
  void retryUpload(PendingUpload upload) => s.retryUpload(upload);
  @override
  void removeUpload(PendingUpload upload) => s.removeUpload(upload);
}
