import 'dart:async';
import 'dart:io' show Platform;

import 'package:cross_file/cross_file.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../app/app_controller.dart';
import '../app/chat_settings.dart';
import '../core/api.dart';
import '../crypto/chat_crypto.dart';
import '../messaging/attachments.dart';
import '../messaging/messenger.dart' show companionNotice;
import '../store/message.dart';
import '../theme/theme_prefs.dart';
import 'command_palette.dart';
import 'conversation_view.dart';
import 'safety_sheet.dart';
import 'theme_picker.dart';
import 'widgets/common.dart';
import 'sending.dart';
import 'widgets/voice_recorder.dart';

class ConversationScreen extends ConsumerStatefulWidget {
  const ConversationScreen({super.key, required this.contactId});
  final String contactId;
  @override
  ConsumerState<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends ConsumerState<ConversationScreen> with AttachmentSending {
  List<ChatMessage>? _messages;
  SafetyNumber? _safety;
  StreamSubscription<String?>? _changes;
  late final AppController _app = ref.read(appProvider.notifier);
  late final String _conversationId = _app.messenger!.conversationWith(widget.contactId);
  AttachmentService get _attachments => attachmentService;

  @override
  String get conversationId => _conversationId;

  @override
  SendAttachment get sendAttachment => (attachment, {replyTo, disappearAfter}) async {
    final contact = _contact;
    if (contact == null) return;
    await _app.messenger!.send(contact, '', attachment: attachment, replyTo: replyTo, disappearAfter: disappearAfter);
  };
  late final ChatSearch _search = ref.read(chatSearchProvider.notifier);
  final _view = GlobalKey<ConversationViewState>();
  late final AppLifecycleListener _lifecycle;
  bool _focused = true;
  bool _dropping = false;
  final List<ChatMessage> _unreported = [];
  Future<String>? _reason;

  @override
  void initState() {
    super.initState();
    _app.openConversation(widget.contactId);
    _changes = _app.store?.changes.listen((id) {
      if (id == null || id == _conversationId) _load();
    });
    final lifecycle = WidgetsBinding.instance.lifecycleState;
    _focused = lifecycle == null || lifecycle == AppLifecycleState.resumed;
    _lifecycle = AppLifecycleListener(onStateChange: (state) {
      _focused = state == AppLifecycleState.resumed;
      if (_focused) _displayed(const []);
    });
    WidgetsBinding.instance.addPostFrameCallback((_) => _search.set(this, () => _view.currentState?.openFind()));
    _load();
    _loadSafety();
  }

  Contact? get _contact => _app.contactById(widget.contactId);

  /// Read receipts go only while this conversation is visible and the app focused.
  void _displayed(List<ChatMessage> messages) {
    _unreported.addAll(messages);
    final contact = _contact;
    if (!_focused || contact == null || _unreported.isEmpty) return;
    _app.messenger?.displayed(contact, List.of(_unreported));
    _unreported.clear();
  }

  Future<void> _load() async {
    final list = await _app.store?.list(_conversationId) ?? const <ChatMessage>[];
    if (mounted) setState(() => _messages = list);
  }

  Future<void> _loadSafety() async {
    final state = ref.read(appProvider);
    final contact = _app.contactById(widget.contactId);
    if (contact == null || state.user == null) return;
    final safety = await ref.read(cryptoProvider).safety(state.user!.username, widget.contactId, contact.username);
    if (mounted) setState(() => _safety = safety);
  }

  @override
  void dispose() {
    _changes?.cancel();
    _lifecycle.dispose();
    _app.closeConversation();
    final contact = _contact;
    if (contact != null) unawaited(_app.messenger?.typingChanged(contact, on: false));
    Future.microtask(() => _search.clear(this));
    super.dispose();
  }

  Future<void> _call(Contact contact, String kind) async {
    try {
      await _app.call(contact, kind);
      if (mounted) unawaited(context.push('/call'));
    } on ApiException catch (e) {
      if (mounted) showSnack(context, e.message);
    }
  }

  Future<void> _resetSession(Contact contact) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset the secure session?'),
        content: Text('Both devices drop this chat\'s current keys and start fresh ones. Your security code with ${contact.username} stays the same.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Reset')),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await _app.resetSession(contact);
      if (mounted) showSnack(context, 'Secure session reset. New keys are in use for this chat.');
    } on CryptoException catch (e) {
      if (mounted) showSnack(context, e.code == 'identity-blocked' ? "${contact.username}'s security code changed. Review it before resetting." : 'Could not reset: ${e.message}');
    } catch (e) {
      if (mounted) showSnack(context, 'Could not reset: $e');
    }
  }

  Future<void> _burn(Contact contact) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Burn this conversation with ${contact.username}?'),
        content: const Text("Deletes every message on this device and asks their device to delete its copy. Their device does this when the encrypted request arrives."),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Keep')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Burn'),
          ),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await _app.messenger!.burn(contact);
      if (mounted) showSnack(context, 'Burned on this device.');
    } catch (e) {
      if (mounted) showSnack(context, '$e');
    }
  }

  Future<void> _openSafety(Contact contact) async {
    final state = ref.read(appProvider);
    final crypto = ref.read(cryptoProvider);
    var safety = await crypto.safety(state.user!.username, widget.contactId, contact.username);
    if (safety == null) {
      try {
        await crypto.notePeer(widget.contactId, Identity.fromJson(await ref.read(apiProvider).publishedIdentity(contact.username)));
        safety = await crypto.safety(state.user!.username, widget.contactId, contact.username);
      } on ApiException catch (e) {
        if (mounted) showSnack(context, e.message);
        return;
      }
    }
    // The decision binds to the identity whose code is shown now.
    final shown = (await crypto.peer(widget.contactId))?.identity;
    if (!mounted || safety == null) return;
    final result = await showSafetySheet(context, contact.username, safety);
    if (result != null) {
      try {
        await _app.reviewedKey(widget.contactId, verified: result == SafetyAction.verify, shown: shown);
      } on CryptoException catch (e) {
        if (e.code != 'mismatch') rethrow;
        if (mounted) showSnack(context, "${contact.username}'s security code changed again. Review the new one.");
        await _loadSafety();
        return;
      }
      if (result == SafetyAction.unverify) await crypto.setVerified(widget.contactId, false);
      await _loadSafety();
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(appProvider);
    final prefs = ref.watch(themePrefsProvider);
    final contact = _app.contactById(widget.contactId);
    if (contact == null) return const Scaffold(body: Center(child: Text('Not a contact')));
    final brightness = ref.watch(platformBrightnessProvider);
    final tokens = prefs.tokens(_conversationId, brightness);
    final resolved = prefs.resolve(_conversationId, brightness);
    final blocked = _safety?.blocked ?? false;
    final settings = ref.watch(chatSettingsProvider);
    final typing = state.typing.contains(widget.contactId);
    final keyChanged = state.keyChanged.contains(widget.contactId) || (_safety?.changed ?? false);
    ref.listen(appProvider.select((s) => s.keyChanged.contains(widget.contactId)), (_, _) => _loadSafety());
    return Theme(
      data: tokens.material(),
      child: Scaffold(
        appBar: AppBar(
          titleSpacing: 0,
          title: Row(
            children: [
              Avatar(name: contact.username, online: contact.online, size: 40, square: tokens.square),
              const SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(contact.username, style: const TextStyle(fontWeight: FontWeight.w700)),
                  Text(
                    typing ? 'typing…' : (contact.online ? 'online' : 'offline'),
                    style: TextStyle(fontSize: 13, color: typing ? tokens.accent : tokens.muted),
                  ),
                ],
              ),
            ],
          ),
          actions: [
            IconButton(tooltip: 'Find in conversation', onPressed: () => _view.currentState?.openFind(), icon: const Icon(Icons.search_rounded)),
            IconButton(tooltip: 'Voice call', onPressed: contact.online ? () => _call(contact, 'voice') : null, icon: const Icon(Icons.call_outlined)),
            IconButton(tooltip: 'Video call', onPressed: contact.online ? () => _call(contact, 'video') : null, icon: const Icon(Icons.videocam_outlined)),
            PopupMenuButton<String>(
              icon: const Icon(Icons.more_horiz),
              onSelected: (v) => switch (v) {
                'safety' => _openSafety(contact),
                'theme' => showThemePicker(context, ref, chatId: _conversationId),
                'burn' => _burn(contact),
                'reset' => _resetSession(contact),
                _ => null,
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'safety', child: Text('Security code')),
                PopupMenuItem(value: 'theme', child: Text('Chat theme')),
                PopupMenuItem(value: 'reset', child: Text('Reset secure session')),
                PopupMenuItem(value: 'burn', child: Text('Burn conversation')),
              ],
            ),
          ],
        ),
        body: _messages == null
            ? const SizedBox.shrink()
            : _onPrimaryNotice(
                show: (state.companion || state.inactiveDevice) && !state.movedChats.contains(widget.contactId),
                color: tokens.muted,
                child: _dropTarget(
                accent: tokens.accent,
                child: ValueListenableBuilder<List<PendingUpload>>(
                  valueListenable: _attachments.uploads,
                  builder: (context, uploads, _) => ConversationView(
                    key: _view,
                    tokens: tokens,
                    wallpaper: resolved.wallpaper,
                    messages: _messages!,
                    peerName: contact.username,
                    peerId: widget.contactId,
                    blocked: blocked,
                    keyChanged: keyChanged,
                    flagged: _app.messenger?.flagged ?? const {},
                    onReviewKey: () => _openSafety(contact),
                    display: prefs.display,
                    showRead: settings.readReceipts,
                    typing: typing,
                    uploads: [for (final u in uploads) if (u.conversationId == _conversationId) u],
                    actions: _ScreenActions(this, contact),
                    onSend: (draft) async {
                      await _app.messenger!.send(contact, draft.text, disappearAfter: draft.disappearAfter, replyTo: draft.replyTo, link: draft.link);
                    },
                  ),
                ),
              ),
              ),
      ),
    );
  }

  /// A device other than the inbox device sends here only once the chat moved to MLS (m5 §8, M6 §0).
  Widget _onPrimaryNotice({required bool show, required Color color, required Widget child}) => !show
      ? child
      : Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(12),
              child: FutureBuilder<String>(
                future: _reason ??= switch (_contact) {
                  final contact? => _app.messenger?.companionReason(contact),
                  null => null,
                },
                initialData: companionNotice,
                builder: (context, reason) => Text(reason.data ?? companionNotice, key: const Key('companion-notice'), style: TextStyle(color: color)),
              ),
            ),
            Expanded(child: child),
          ],
        );

  static final _desktop = !kIsWeb && (Platform.isMacOS || Platform.isWindows || Platform.isLinux);

  /// Drag and drop files onto the chat (desktop).
  Widget _dropTarget({required Widget child, required Color accent}) {
    if (!_desktop) return child;
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
                  decoration: BoxDecoration(
                    color: accent.withValues(alpha: .08),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: accent, width: 2),
                  ),
                  child: const Center(child: Text('Drop to send, end-to-end encrypted', style: TextStyle(fontWeight: FontWeight.w700))),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _ScreenActions extends ConversationActions {
  const _ScreenActions(this.s, this.contact);
  final _ConversationScreenState s;
  final Contact contact;

  @override
  Future<void> react(ChatMessage message, String emoji, bool on) async => s._app.messenger!.react(contact, message, emoji, on: on);
  @override
  Future<void> edit(ChatMessage message, String text) async => s._app.messenger!.edit(contact, message, text);
  @override
  Future<List<XFile>> pickFiles({required bool media}) => s.pickFiles(media: media);
  @override
  Future<void> attach(List<XFile> files, {ReplyTo? replyTo, Duration? disappearAfter}) => s.attachFiles(files, replyTo: replyTo, disappearAfter: disappearAfter);
  @override
  Future<void> sendVoice(VoiceNote note, {ReplyTo? replyTo, Duration? disappearAfter}) => s.sendVoiceNote(note, replyTo: replyTo, disappearAfter: disappearAfter);
  @override
  void typing(bool on) => unawaited(s._app.messenger?.typingChanged(s._contact ?? contact, on: on));
  @override
  void displayed(List<ChatMessage> messages) => s._displayed(messages);
  @override
  Future<LinkPreview?> unfurl(String url) => s.unfurlLink(url);
  @override
  AttachmentService get attachments => s._attachments;
  @override
  bool get canRecord => true;
  @override
  void retryUpload(PendingUpload upload) => s.retryUpload(upload);
  @override
  void removeUpload(PendingUpload upload) => s.removeUpload(upload);
}
