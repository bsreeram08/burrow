import 'dart:async';
import 'dart:io' show Platform;

import 'package:cross_file/cross_file.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../messaging/attachments.dart';
import '../messaging/group_messenger.dart' show GroupPerson;
import '../text/fuzzy.dart';
import '../store/message.dart';
import '../text/markdown.dart';
import '../text/timeline.dart';
import '../theme/theme_prefs.dart';
import '../theme/tokens.dart';
import 'widgets/attachment_view.dart';
import 'widgets/bubble.dart';
import 'widgets/common.dart';
import 'widgets/icons.dart';
import 'widgets/reactions.dart';
import 'widgets/voice_recorder.dart';
import 'widgets/wallpaper.dart';

const disappearOptions = <String, Duration?>{'Off': null, '1 hour': Duration(hours: 1), '24 hours': Duration(hours: 24), '7 days': Duration(days: 7)};

/// What the composer sends.
class Draft {
  const Draft({required this.text, this.disappearAfter, this.replyTo, this.link});
  final String text;
  final Duration? disappearAfter;
  final ReplyTo? replyTo;
  final LinkPreview? link;
}

/// Everything the conversation asks of the app besides sending text. The defaults do nothing, so the
/// view renders and is testable on its own.
class ConversationActions {
  const ConversationActions();
  Future<void> react(ChatMessage message, String emoji, bool on) async {}
  Future<void> edit(ChatMessage message, String text) async {}
  Future<List<XFile>> pickFiles({required bool media}) async => const [];
  Future<void> attach(List<XFile> files, {ReplyTo? replyTo, Duration? disappearAfter}) async {}
  Future<void> sendVoice(VoiceNote note, {ReplyTo? replyTo, Duration? disappearAfter}) async {}
  void typing(bool on) {}

  /// These incoming messages are on screen (for read receipts).
  void displayed(List<ChatMessage> messages) {}

  /// A sender-side link preview, or null (previews off, nothing found).
  Future<LinkPreview?> unfurl(String url) async => null;
  AttachmentService? get attachments => null;
  bool get canRecord => false;
  void retryUpload(PendingUpload upload) {}
  void removeUpload(PendingUpload upload) {}
}

/// The conversation body: wallpaper, message list, key-change banner, find bar and
/// composer. Pure view (data in, callbacks out) so it is widget-testable.
class ConversationView extends StatefulWidget {
  const ConversationView({
    super.key,
    required this.tokens,
    required this.wallpaper,
    required this.messages,
    required this.onSend,
    required this.peerName,
    this.peerId = '',
    this.blocked = false,
    this.keyChanged = false,
    this.flagged = const {},
    this.onReviewKey,
    this.status,
    this.display = const Display(),
    this.showRead = true,
    this.typing = false,
    this.uploads = const [],
    this.actions = const ConversationActions(),
    this.nameOf,
    this.members = const [],
    this.me = '',
    this.typingText,
    this.banner,
    this.readOnly,
    this.emptyText,
    this.onReadInfo,
  });

  final ChatTokens tokens;
  final String wallpaper;
  final List<ChatMessage> messages;
  final String peerName, peerId;

  /// The contact's security code changed and has not been accepted: sending pauses.
  final bool blocked;
  final bool keyChanged;
  final Set<String> flagged;
  final Future<void> Function(Draft draft) onSend;
  final VoidCallback? onReviewKey;
  final String? status;
  final Display display;

  /// "Send read receipts" is on: show the peer's reads as well.
  final bool showRead;

  /// The peer is typing.
  final bool typing;
  final List<PendingUpload> uploads;
  final ConversationActions actions;

  /// Groups (docs/m4-groups.md): names a member by user id. Its presence switches the view to group mode:
  /// sender names per message, system rows, per-person reactions, mentions.
  final String Function(String userId)? nameOf;

  /// Groups: current members, for `@` autocomplete.
  final List<GroupPerson> members;

  /// This account's user id (groups: excluded from autocomplete).
  final String me;

  /// Groups: "alice and bob are typing".
  final String? typingText;

  /// Shown above the messages (frozen or paused channel).
  final Widget? banner;

  /// When set, the composer is replaced by this notice ("You left this group").
  final String? readOnly;
  final String? emptyText;

  /// Groups: "Read by" for one of our messages.
  final void Function(ChatMessage message)? onReadInfo;

  bool get group => nameOf != null;

  @override
  State<ConversationView> createState() => ConversationViewState();
}

sealed class _Row {
  const _Row();
}

class _TypingRow extends _Row {
  const _TypingRow();
}

class _UploadRow extends _Row {
  const _UploadRow(this.upload);
  final PendingUpload upload;
}

class _EntryRow extends _Row {
  const _EntryRow(this.entry);
  final TimelineEntry entry;
}

class ConversationViewState extends State<ConversationView> {
  final _input = TextEditingController();
  late final FocusNode _focus = FocusNode(onKeyEvent: _composerKey);
  final _scroll = ScrollController();
  final _findInput = TextEditingController();
  final _findFocus = FocusNode();
  late final Set<String> _initial = widget.messages.map((m) => m.id).toSet();
  final Map<String, GlobalKey> _keys = {};
  final Set<String> _reported = {};
  final List<ChatMessage> _toReport = [];
  String _disappear = 'Off';
  int _sends = 0;

  ChatMessage? _replyTo, _editing;
  LinkPreview? _link;
  String? _linkUrl;
  final Set<String> _dismissedLinks = {};
  Timer? _unfurlTimer;
  bool _recording = false;
  bool _typingSent = false;

  bool _finding = false;
  List<String> _matches = const [];
  int _match = 0;
  String? _highlight;
  Timer? _highlightTimer;

  bool _away = false;
  int _newWhileAway = 0;

  late List<TimelineEntry> _timeline = buildTimeline(widget.messages);

  @override
  void initState() {
    super.initState();
    _scroll.addListener(_onScroll);
    _input.addListener(_onText);
    _focus.addListener(() {
      if (!_focus.hasFocus) _stopTyping();
    });
  }

  @override
  void didUpdateWidget(ConversationView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.messages, widget.messages)) {
      _timeline = buildTimeline(widget.messages);
      if (_away) {
        final known = oldWidget.messages.map((m) => m.id).toSet();
        _newWhileAway += widget.messages.where((m) => !m.outgoing && !known.contains(m.id)).length;
      }
      if (_finding) _runFind(keepPosition: true);
    }
  }

  @override
  void dispose() {
    _stopTyping();
    _unfurlTimer?.cancel();
    _highlightTimer?.cancel();
    _input.dispose();
    _focus.dispose();
    _scroll.dispose();
    _findInput.dispose();
    _findFocus.dispose();
    super.dispose();
  }

  void _onScroll() {
    final away = _scroll.hasClients && _scroll.offset > 320;
    if (away != _away) {
      setState(() {
        _away = away;
        if (!away) _newWhileAway = 0;
      });
    }
  }

  // ---------- Composer ----------
  void _onText() {
    final text = _input.text;
    if (text.trim().isNotEmpty && !widget.blocked) {
      widget.actions.typing(true);
      _typingSent = true;
    } else {
      _stopTyping();
    }
    if (_editing == null) _scheduleUnfurl(text);
    _updateMention();
    setState(() {}); // Send vs mic.
  }

  // ---------- @ mentions (groups) ----------
  List<GroupPerson> _mentionOptions = const [];
  int _mentionIndex = 0;
  int _mentionStart = -1;

  void _updateMention() {
    if (!widget.group) return;
    final caret = _input.selection.baseOffset;
    final before = caret < 0 || caret > _input.text.length ? _input.text : _input.text.substring(0, caret);
    final match = RegExp(r'(^|[^A-Za-z0-9_])@([A-Za-z0-9_]{0,20})$').firstMatch(before);
    if (match == null) {
      _mentionOptions = const [];
      _mentionStart = -1;
      return;
    }
    _mentionStart = match.start + match.group(1)!.length;
    final candidates = [for (final m in widget.members) if (m.userId != widget.me) m];
    _mentionOptions = fuzzyFilter(match.group(2)!, candidates, (m) => m.username).take(6).toList();
    _mentionIndex = _mentionIndex.clamp(0, _mentionOptions.isEmpty ? 0 : _mentionOptions.length - 1);
  }

  void _insertMention(GroupPerson person) {
    if (_mentionStart < 0) return;
    final caret = _input.selection.baseOffset < 0 ? _input.text.length : _input.selection.baseOffset;
    final text = _input.text.replaceRange(_mentionStart, caret, '@${person.username} ');
    final offset = _mentionStart + person.username.length + 2;
    _input.value = TextEditingValue(text: text, selection: TextSelection.collapsed(offset: offset));
    setState(() {
      _mentionOptions = const [];
      _mentionStart = -1;
      _mentionIndex = 0;
    });
    _focus.requestFocus();
  }

  void _stopTyping() {
    if (!_typingSent) return;
    _typingSent = false;
    widget.actions.typing(false);
  }

  void _scheduleUnfurl(String text) {
    final links = findLinks(text);
    final url = links.where((l) => LinkPreview.isHttpsUrl(l) && !_dismissedLinks.contains(l)).firstOrNull;
    if (url == _linkUrl) return;
    _unfurlTimer?.cancel();
    setState(() {
      _linkUrl = url;
      _link = null;
    });
    if (url == null) return;
    _unfurlTimer = Timer(const Duration(milliseconds: 700), () async {
      final preview = await widget.actions.unfurl(url);
      if (mounted && _linkUrl == url && preview != null) setState(() => _link = preview);
    });
  }

  void _removeLink() {
    setState(() {
      if (_linkUrl != null) _dismissedLinks.add(_linkUrl!);
      _link = null;
    });
  }

  ReplyTo? get _replyRef => _replyTo == null ? null : ReplyTo.preview(_replyTo!.id, _replyTo!.body.isNotEmpty ? plainText(_replyTo!.body) : _attachmentLabel(_replyTo!.attachment));

  Duration? get _after => disappearOptions[_disappear];

  Future<void> _send() async {
    final text = _input.text;
    if (widget.blocked) return;
    final editing = _editing;
    if (editing != null) {
      if (text.trim().isEmpty) return;
      _cancelCompose();
      try {
        await widget.actions.edit(editing, text);
      } catch (e) {
        if (mounted) showSnack(context, e.toString());
      }
      return;
    }
    if (text.trim().isEmpty) return;
    final draft = Draft(text: text, disappearAfter: _after, replyTo: _replyRef, link: _link != null && text.contains(_link!.url) ? _link : null);
    // Clear at once and keep the keyboard: typing continues while the message saves.
    _input.clear();
    _focus.requestFocus();
    _stopTyping();
    final reply = _replyTo, link = _link;
    setState(() {
      _sends++;
      _replyTo = null;
      _link = null;
      _linkUrl = null;
      _dismissedLinks.clear();
    });
    _jumpToNewest();
    try {
      await widget.onSend(draft);
    } catch (e) {
      if (_input.text.isEmpty) {
        _input.text = text;
        setState(() {
          _replyTo = reply;
          _link = link;
        });
      }
      if (mounted) showSnack(context, e.toString());
    }
  }

  void _cancelCompose() {
    final wasEditing = _editing != null;
    setState(() {
      _editing = null;
      _replyTo = null;
    });
    if (wasEditing) _input.clear();
  }

  bool _canEdit(ChatMessage m) => m.outgoing && m.attachment == null && m.status != MessageStatus.queued && m.status != MessageStatus.uncertain;

  void startEdit(ChatMessage m) {
    if (!_canEdit(m)) return;
    setState(() {
      _editing = m;
      _replyTo = null;
      _link = null;
      _linkUrl = null;
    });
    _input.text = m.body;
    _input.selection = TextSelection.collapsed(offset: _input.text.length);
    _focus.requestFocus();
  }

  void startReply(ChatMessage m) {
    setState(() {
      _replyTo = m;
      if (_editing != null) {
        _editing = null;
        _input.clear();
      }
    });
    _focus.requestFocus();
  }

  static final _desktop = !kIsWeb && (Platform.isMacOS || Platform.isWindows || Platform.isLinux);

  KeyEventResult _composerKey(FocusNode node, KeyEvent event) {
    if (event is! KeyDownEvent && event is! KeyRepeatEvent) return KeyEventResult.ignored;
    final key = event.logicalKey;
    if (_mentionOptions.isNotEmpty) {
      if (key == LogicalKeyboardKey.arrowDown || key == LogicalKeyboardKey.arrowUp) {
        setState(() => _mentionIndex = (_mentionIndex + (key == LogicalKeyboardKey.arrowDown ? 1 : -1)) % _mentionOptions.length);
        return KeyEventResult.handled;
      }
      if (key == LogicalKeyboardKey.enter || key == LogicalKeyboardKey.tab) {
        _insertMention(_mentionOptions[_mentionIndex]);
        return KeyEventResult.handled;
      }
      if (key == LogicalKeyboardKey.escape) {
        setState(() => _mentionOptions = const []);
        return KeyEventResult.handled;
      }
    }
    if (event is! KeyDownEvent) return KeyEventResult.ignored;
    if (key == LogicalKeyboardKey.escape && (_editing != null || _replyTo != null)) {
      _cancelCompose();
      return KeyEventResult.handled;
    }
    // ↑ in an empty composer edits the last message you sent ("Edit Last Message").
    if (key == LogicalKeyboardKey.arrowUp && _input.text.isEmpty) {
      final last = widget.messages.lastWhere(_canEdit, orElse: () => _none);
      if (!identical(last, _none)) {
        startEdit(last);
        return KeyEventResult.handled;
      }
    }
    if (_desktop && key == LogicalKeyboardKey.enter && !HardwareKeyboard.instance.isShiftPressed) {
      unawaited(_send());
      return KeyEventResult.handled;
    }
    return KeyEventResult.ignored;
  }

  static final _none = ChatMessage(id: '', conversationId: '', direction: Direction.incoming, text: '', createdAt: 0, status: MessageStatus.uncertain);

  Future<void> _attach() async {
    final choice = await showModalBottomSheet<bool>(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(leading: const Icon(Icons.photo_library_outlined), title: const Text('Photo or video'), onTap: () => Navigator.pop(context, true)),
            ListTile(leading: const Icon(Icons.insert_drive_file_outlined), title: const Text('File'), subtitle: const Text('Up to 25 MB, end-to-end encrypted'), onTap: () => Navigator.pop(context, false)),
          ],
        ),
      ),
    );
    if (choice == null) return;
    try {
      final files = await widget.actions.pickFiles(media: choice);
      if (files.isEmpty) return;
      final reply = _replyRef;
      setState(() => _replyTo = null);
      _jumpToNewest();
      await widget.actions.attach(files, replyTo: reply, disappearAfter: _after);
    } catch (e) {
      if (mounted) showSnack(context, e.toString());
    }
  }

  // ---------- Messages ----------
  Future<void> _menu(ChatMessage m) async {
    final sendable = !(m.outgoing && m.status == MessageStatus.queued);
    if (m.system) return;
    final result = await showMessageMenu(context, message: m, tokens: widget.tokens, canEdit: _canEdit(m), canReact: sendable, canInfo: widget.onReadInfo != null && m.outgoing && m.status != MessageStatus.queued);
    if (!mounted || result == null) return;
    switch (result) {
      case String emoji:
        await _react(m, emoji, !m.reactions.of('me').contains(emoji));
      case MessageAction.reply:
        startReply(m);
      case MessageAction.edit:
        startEdit(m);
      case MessageAction.copy:
        await Clipboard.setData(ClipboardData(text: m.body));
        if (mounted) showSnack(context, 'Copied.');
      case MessageAction.info:
        widget.onReadInfo?.call(m);
    }
  }

  Future<void> _react(ChatMessage m, String emoji, bool on) async {
    try {
      await widget.actions.react(m, emoji, on);
    } catch (e) {
      if (mounted) showSnack(context, e.toString());
    }
  }

  void _report(ChatMessage m) {
    if (m.outgoing || m.system || m.status != MessageStatus.delivered || !_reported.add(m.id)) return;
    _toReport.add(m);
    if (_toReport.length == 1) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted || _toReport.isEmpty) return;
        final batch = List.of(_toReport);
        _toReport.clear();
        widget.actions.displayed(batch);
      });
    }
  }

  // ---------- Scrolling, find, jump ----------
  List<_Row> _rows() => [
    if (widget.typing || widget.typingText != null) const _TypingRow(),
    for (final u in widget.uploads.reversed) _UploadRow(u),
    for (final e in _timeline.reversed) _EntryRow(e),
  ];

  void _jumpToNewest() {
    if (!_scroll.hasClients) return;
    if (MediaQuery.disableAnimationsOf(context)) {
      _scroll.jumpTo(0);
    } else {
      unawaited(_scroll.animateTo(0, duration: const Duration(milliseconds: 280), curve: Curves.easeOut));
    }
    setState(() => _newWhileAway = 0);
  }

  /// Scrolls a message into view and highlights it briefly (reply quotes, find).
  Future<void> reveal(String id) async {
    final rows = _rows();
    final index = rows.indexWhere((r) => r is _EntryRow && r.entry.key == id);
    if (index == -1) {
      showSnack(context, "That message isn't on this device anymore.");
      return;
    }
    setState(() {
      _highlight = id;
      _highlightTimer?.cancel();
      _highlightTimer = Timer(const Duration(milliseconds: 1600), () => mounted ? setState(() => _highlight = null) : null);
    });
    for (var attempt = 0; attempt < 40 && mounted && _scroll.hasClients; attempt++) {
      final context = _keys[id]?.currentContext;
      if (context != null && context.mounted) {
        await Scrollable.ensureVisible(context, alignment: .5, duration: MediaQuery.disableAnimationsOf(context) ? Duration.zero : const Duration(milliseconds: 250));
        return;
      }
      // Not built yet: step through the lazy list toward it.
      final position = _scroll.position;
      final estimate = (position.maxScrollExtent + position.viewportDimension) / rows.length * index;
      final target = attempt == 0 ? estimate : position.pixels + position.viewportDimension * .8 * (_builtMax < index ? 1 : -1);
      _scroll.jumpTo(target.clamp(0, position.maxScrollExtent));
      await WidgetsBinding.instance.endOfFrame;
    }
  }

  int _builtMax = 0;

  void openFind() {
    setState(() => _finding = true);
    _findFocus.requestFocus();
    _findInput.selection = TextSelection(baseOffset: 0, extentOffset: _findInput.text.length);
  }

  void _closeFind() {
    setState(() {
      _finding = false;
      _matches = const [];
    });
    _focus.requestFocus();
  }

  void _runFind({bool keepPosition = false}) {
    final q = _findInput.text.trim().toLowerCase();
    final matches = q.isEmpty
        ? const <String>[]
        : [for (final m in widget.messages.reversed) if (plainText(m.body).toLowerCase().contains(q) || (m.attachment?.name.toLowerCase().contains(q) ?? false)) m.id];
    setState(() {
      _matches = matches;
      if (!keepPosition || _match >= matches.length) _match = 0;
    });
    if (!keepPosition && matches.isNotEmpty) unawaited(reveal(matches.first));
  }

  void _step(int delta) {
    if (_matches.isEmpty) return;
    setState(() => _match = (_match + delta) % _matches.length);
    unawaited(reveal(_matches[_match]));
  }

  String? _quotedAuthor(ReplyTo reply) {
    for (final m in widget.messages) {
      if (m.id == reply.id) return m.outgoing ? 'You' : _author(m);
    }
    return null;
  }

  /// Who wrote an incoming message: the peer, or in a group its sender as it was received.
  String _author(ChatMessage m) => !widget.group ? widget.peerName : (m.senderName ?? (m.sender == null ? '' : widget.nameOf!(m.sender!)));

  Set<String> _mentionNames(ChatMessage m) => m.mentions.isEmpty || !widget.group ? const {} : {for (final id in m.mentions) widget.nameOf!(id).toLowerCase()};

  @override
  Widget build(BuildContext context) {
    final t = widget.tokens;
    final rows = _rows();
    final findQuery = _finding ? _findInput.text.trim() : null;
    final empty = widget.messages.isEmpty && widget.uploads.isEmpty;
    return CallbackShortcuts(
      bindings: {
        const SingleActivator(LogicalKeyboardKey.keyF, meta: true): openFind,
        const SingleActivator(LogicalKeyboardKey.keyF, control: true): openFind,
      },
      child: Column(
        children: [
          if (widget.keyChanged || widget.blocked)
            Material(
              color: t.warnBg,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 10, 8, 10),
                child: Row(
                  children: [
                    Icon(Icons.warning_amber_rounded, color: t.warn),
                    const SizedBox(width: 10),
                    Expanded(
                      key: const Key('key-banner'),
                      child: Text(
                        widget.blocked
                            ? "${widget.peerName}'s security code changed. Sending is paused until you review it."
                            : "${widget.peerName}'s security code changed. Compare it again to be sure no one is in the middle.",
                        style: TextStyle(color: t.text, fontSize: 14),
                      ),
                    ),
                    TextButton(onPressed: widget.onReviewKey, child: const Text('Review')),
                  ],
                ),
              ),
            ),
          ?widget.banner,
          if (_finding) _findBar(t),
          Expanded(
            child: Wallpaper(
              kind: widget.wallpaper,
              tokens: t,
              child: Stack(
                children: [
                  if (empty)
                    Center(
                      child: Padding(
                        padding: const EdgeInsets.all(32),
                        child: Text(
                          widget.emptyText ?? 'No messages yet. What you send here is end-to-end encrypted: only you and ${widget.peerName} can read it.',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: t.muted),
                        ),
                      ),
                    )
                  else
                    ListView.builder(
                      controller: _scroll,
                      reverse: true,
                      padding: const EdgeInsets.fromLTRB(12, 12, 12, 8),
                      itemCount: rows.length,
                      // Keyed: status changes update a row in place, new rows animate in.
                      findChildIndexCallback: (key) {
                        final id = (key as ValueKey<String>).value;
                        final index = rows.indexWhere((r) => _rowKey(r) == id);
                        return index < 0 ? null : index;
                      },
                      itemBuilder: (context, i) {
                        if (i > _builtMax) _builtMax = i;
                        return _buildRow(rows[i], t, findQuery);
                      },
                    ),
                  if (_away && !empty)
                    Positioned(
                      right: 16,
                      bottom: 12,
                      child: Badge(
                        isLabelVisible: _newWhileAway > 0,
                        label: Text('$_newWhileAway'),
                        backgroundColor: t.accent,
                        textColor: t.accentInk,
                        child: FloatingActionButton.small(
                          key: const Key('jump-newest'),
                          tooltip: 'Jump to newest',
                          backgroundColor: t.surface2,
                          foregroundColor: t.text,
                          onPressed: _jumpToNewest,
                          child: const Icon(Icons.keyboard_double_arrow_down_rounded),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
          if (widget.status != null && widget.status!.isNotEmpty)
            Padding(padding: const EdgeInsets.fromLTRB(16, 4, 16, 0), child: Text(widget.status!, style: TextStyle(color: t.muted, fontSize: 12))),
          if (widget.readOnly != null)
            Material(
              color: t.surface2,
              child: SafeArea(
                top: false,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(widget.readOnly!, key: const Key('read-only'), textAlign: TextAlign.center, style: TextStyle(color: t.muted)),
                ),
              ),
            )
          else
            _composer(t),
        ],
      ),
    );
  }

  String _rowKey(_Row r) => switch (r) {
    _TypingRow() => 'typing',
    _UploadRow(:final upload) => 'upload-${upload.id}',
    _EntryRow(:final entry) => entry.key,
  };

  Widget _buildRow(_Row row, ChatTokens t, String? findQuery) {
    switch (row) {
      case _TypingRow():
        return KeyedSubtree(
          key: const ValueKey('typing'),
          child: Align(alignment: Alignment.centerLeft, child: TypingIndicator(name: widget.peerName, line: widget.typingText, tokens: t)),
        );
      case _UploadRow(:final upload):
        return KeyedSubtree(
          key: ValueKey('upload-${upload.id}'),
          child: UploadBubble(upload: upload, tokens: t, onRetry: () => widget.actions.retryUpload(upload), onRemove: () => widget.actions.removeUpload(upload)),
        );
      case _EntryRow(entry: DayDivider(:final label, :final key)):
        return KeyedSubtree(key: ValueKey(key), child: DaySeparator(label: label, tokens: t));
      case _EntryRow(entry: MessageEntry(:final message, :final first, :final last)):
        _report(message);
        final m = message;
        if (m.system) {
          return KeyedSubtree(
            key: ValueKey(m.id),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Center(child: Text(m.text, style: TextStyle(color: t.muted, fontSize: 12.5, fontStyle: FontStyle.italic))),
            ),
          );
        }
        return KeyedSubtree(
          key: ValueKey(m.id),
          child: KeyedSubtree(
            key: _keys.putIfAbsent(m.id, GlobalKey.new),
            child: Bubble(
              message: m,
              tokens: t,
              animateIn: !_initial.contains(m.id),
              flagged: widget.flagged.contains(m.id),
              first: first,
              last: last,
              display: widget.display,
              peerName: m.outgoing ? widget.peerName : _author(m),
              peerId: m.sender ?? widget.peerId,
              nameOf: widget.nameOf,
              mentionNames: _mentionNames(m),
              quotedAuthor: m.replyTo == null ? null : _quotedAuthor(m.replyTo!),
              highlighted: _highlight == m.id,
              findQuery: findQuery,
              showRead: widget.showRead,
              attachments: widget.actions.attachments,
              callbacks: BubbleCallbacks(
                onReply: widget.blocked ? null : startReply,
                onReact: widget.blocked ? null : _react,
                onMenu: _menu,
                onQuoteTap: reveal,
              ),
            ),
          ),
        );
    }
  }

  Widget _findBar(ChatTokens t) => Material(
    color: t.surface2,
    child: Padding(
      padding: const EdgeInsets.fromLTRB(12, 6, 4, 6),
      child: Row(
        children: [
          Icon(Icons.search, color: t.muted, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: CallbackShortcuts(
              bindings: {
                const SingleActivator(LogicalKeyboardKey.escape): _closeFind,
                const SingleActivator(LogicalKeyboardKey.enter): () => _step(1),
                const SingleActivator(LogicalKeyboardKey.enter, shift: true): () => _step(-1),
              },
              child: TextField(
                key: const Key('find'),
                controller: _findInput,
                focusNode: _findFocus,
                decoration: const InputDecoration(hintText: 'Find in conversation', isDense: true, border: InputBorder.none, enabledBorder: InputBorder.none, filled: false),
                onChanged: (_) => _runFind(),
              ),
            ),
          ),
          Text(
            _findInput.text.trim().isEmpty ? '' : (_matches.isEmpty ? 'No matches' : '${_match + 1} of ${_matches.length}'),
            style: TextStyle(color: t.muted, fontSize: 13),
          ),
          IconButton(tooltip: 'Previous match (older)', onPressed: _matches.isEmpty ? null : () => _step(1), icon: const Icon(Icons.keyboard_arrow_up_rounded)),
          IconButton(tooltip: 'Next match (newer)', onPressed: _matches.isEmpty ? null : () => _step(-1), icon: const Icon(Icons.keyboard_arrow_down_rounded)),
          IconButton(tooltip: 'Close find', onPressed: _closeFind, icon: const Icon(Icons.close_rounded)),
        ],
      ),
    ),
  );

  Widget _contextBar(ChatTokens t, {required IconData icon, required String title, required String body, required String closeLabel}) => Container(
    padding: const EdgeInsets.fromLTRB(12, 6, 4, 6),
    decoration: BoxDecoration(border: Border(left: BorderSide(color: t.accent, width: 3))),
    child: Row(
      children: [
        Icon(icon, size: 18, color: t.accent),
        const SizedBox(width: 8),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: TextStyle(color: t.accent, fontWeight: FontWeight.w700, fontSize: 13)),
              Text(body, maxLines: 1, overflow: TextOverflow.ellipsis, style: TextStyle(color: t.muted, fontSize: 13)),
            ],
          ),
        ),
        IconButton(tooltip: closeLabel, onPressed: _cancelCompose, icon: Icon(Icons.close_rounded, color: t.muted, size: 20)),
      ],
    ),
  );

  Widget _composer(ChatTokens t) {
    final hasText = _input.text.trim().isNotEmpty;
    final showMic = !hasText && _editing == null && widget.actions.canRecord && !widget.blocked;
    return Material(
      color: t.bg,
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (_editing != null)
                _contextBar(t, icon: Icons.edit_outlined, title: 'Editing', body: plainText(_editing!.body), closeLabel: 'Cancel editing')
              else if (_replyTo != null)
                _contextBar(
                  t,
                  icon: Icons.reply_rounded,
                  title: 'Replying to ${_replyTo!.outgoing ? 'yourself' : _author(_replyTo!)}',
                  body: _replyTo!.body.isNotEmpty ? plainText(_replyTo!.body) : _attachmentLabel(_replyTo!.attachment),
                  closeLabel: 'Cancel reply',
                ),
              if (_mentionOptions.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.fromLTRB(4, 0, 4, 6),
                  child: Material(
                    key: const Key('mention-list'),
                    color: t.surface2,
                    clipBehavior: Clip.antiAlias,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12), side: BorderSide(color: t.line)),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        for (var i = 0; i < _mentionOptions.length; i++)
                        ListTile(
                          key: ValueKey('mention-${_mentionOptions[i].username}'),
                          dense: true,
                          selected: i == _mentionIndex,
                          selectedTileColor: t.okBg,
                          leading: CircleAvatar(radius: 12, backgroundColor: t.nameColor(_mentionOptions[i].userId), child: Text(_mentionOptions[i].username[0].toUpperCase(), style: const TextStyle(fontSize: 12, color: Colors.white))),
                          title: Text('@${_mentionOptions[i].username}', style: TextStyle(color: t.text)),
                          onTap: () => _insertMention(_mentionOptions[i]),
                        ),
                      ],
                    ),
                  ),
                ),
              if (_link != null && _editing == null)
                Padding(
                  padding: const EdgeInsets.fromLTRB(4, 2, 4, 6),
                  child: Align(alignment: Alignment.centerLeft, child: LinkCard(link: _link!, color: t.text, onRemove: _removeLink)),
                ),
              if (_recording)
                VoiceRecorderBar(
                  tokens: t,
                  onCancel: (problem) {
                    setState(() => _recording = false);
                    if (problem != null) showSnack(context, problem);
                  },
                  onSend: (note) async {
                    final reply = _replyRef;
                    setState(() {
                      _recording = false;
                      _replyTo = null;
                    });
                    _jumpToNewest();
                    try {
                      await widget.actions.sendVoice(note, replyTo: reply, disappearAfter: _after);
                    } catch (e) {
                      if (mounted) showSnack(context, e.toString());
                    }
                  },
                )
              else
                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    IconButton(
                      key: const Key('attach'),
                      tooltip: 'Attach a photo, video or file',
                      onPressed: widget.blocked || _editing != null ? null : _attach,
                      icon: Icon(Icons.add_circle_outline_rounded, color: t.muted),
                    ),
                    PopupMenuButton<String>(
                      tooltip: 'Disappearing messages',
                      initialValue: _disappear,
                      onSelected: (v) => setState(() => _disappear = v),
                      itemBuilder: (_) => [for (final k in disappearOptions.keys) PopupMenuItem(value: k, child: Text(k == 'Off' ? 'Keep messages' : 'Disappear after $k'))],
                      child: Padding(
                        padding: const EdgeInsets.all(4),
                        child: CircleAvatar(
                          radius: 19,
                          backgroundColor: _disappear == 'Off' ? t.surface : t.okBg,
                          child: Icon(Icons.timer_outlined, size: 20, color: _disappear == 'Off' ? t.muted : t.accent),
                        ),
                      ),
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: TextField(
                        key: const Key('composer'),
                        controller: _input,
                        focusNode: _focus,
                        minLines: 1,
                        maxLines: 6,
                        maxLength: 4096,
                        buildCounter: (_, {required currentLength, required isFocused, maxLength}) => null,
                        textCapitalization: TextCapitalization.sentences,
                        style: TextStyle(color: t.text, fontSize: 16),
                        decoration: InputDecoration(
                          hintText: widget.blocked ? 'Review the new security code to send' : (_editing != null ? 'Edit message' : 'Message'),
                          isDense: true,
                          contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                        ),
                        onSubmitted: (_) => _send(),
                      ),
                    ),
                    const SizedBox(width: 8),
                    if (showMic)
                      IconButton.filled(
                        key: const Key('record'),
                        tooltip: 'Record a voice message',
                        onPressed: () => setState(() => _recording = true),
                        style: IconButton.styleFrom(backgroundColor: t.surface2, fixedSize: const Size(46, 46)),
                        icon: Icon(Icons.mic_none_rounded, color: t.text),
                      )
                    else
                      Semantics(
                        button: true,
                        label: _editing != null ? 'Save edit' : 'Send message',
                        child: IconButton.filled(
                          key: const Key('send'),
                          onPressed: widget.blocked ? null : _send,
                          style: IconButton.styleFrom(backgroundColor: t.accent, fixedSize: const Size(46, 46)),
                          icon: _editing != null ? Icon(Icons.check_rounded, color: t.accentInk) : SendPlane(sends: _sends, color: t.accentInk),
                        ),
                      ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }
}

String _attachmentLabel(Attachment? a) => switch (a?.kind) {
  'image' => 'Photo',
  'video' => 'Video',
  'voice' => 'Voice message',
  'audio' => 'Audio',
  null => '',
  _ => a!.name,
};

/// A one-line summary of a message for lists and previews.
String messagePreview(ChatMessage m) {
  final a = m.attachment;
  final text = plainText(m.body).replaceAll('\n', ' ');
  if (a == null) return text;
  final label = switch (a.kind) { 'image' => '📷 Photo', 'video' => '🎬 Video', 'voice' => '🎤 Voice message', 'audio' => '🎵 Audio', _ => '📎 ${a.name}' };
  return text.isEmpty ? label : '$label · $text';
}
