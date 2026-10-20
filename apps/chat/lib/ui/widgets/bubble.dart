import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../messaging/attachments.dart';
import '../../store/message.dart';
import '../../text/markdown.dart';
import '../../theme/theme_prefs.dart';
import '../../theme/tokens.dart';
import 'attachment_view.dart';
import 'common.dart';
import 'markdown_text.dart';
import 'reactions.dart';
import 'ticks.dart';

/// What a bubble can ask of the conversation.
class BubbleCallbacks {
  const BubbleCallbacks({this.onReply, this.onReact, this.onMenu, this.onQuoteTap});
  final void Function(ChatMessage)? onReply;
  final void Function(ChatMessage, String emoji, bool on)? onReact;
  final void Function(ChatMessage)? onMenu;
  final void Function(String id)? onQuoteTap;
}

/// One message bubble (docs/phase1-protocol.md §5): quote, attachment, Markdown text, link card,
/// "edited", time, ticks, reactions. Grouped bubbles share a header and only the last has a tail.
/// New rows slide up and fade in once; history is drawn still.
class Bubble extends StatefulWidget {
  const Bubble({
    super.key,
    required this.message,
    required this.tokens,
    this.animateIn = false,
    this.flagged = false,
    this.first = true,
    this.last = true,
    this.display = const Display(),
    this.peerName = '',
    this.peerId = '',
    this.quotedAuthor,
    this.highlighted = false,
    this.findQuery,
    this.showRead = true,
    this.attachments,
    this.callbacks = const BubbleCallbacks(),
  });

  final ChatMessage message;
  final ChatTokens tokens;
  final bool animateIn, flagged, first, last, highlighted, showRead;
  final Display display;
  final String peerName, peerId;

  /// Who wrote the quoted message: "You", the peer's name, or null when it isn't on this device.
  final String? quotedAuthor;
  final String? findQuery;
  final AttachmentService? attachments;
  final BubbleCallbacks callbacks;

  @override
  State<Bubble> createState() => _BubbleState();
}

class _BubbleState extends State<Bubble> with SingleTickerProviderStateMixin {
  late final AnimationController _in = AnimationController(vsync: this, duration: const Duration(milliseconds: 180), value: widget.animateIn ? 0 : 1);
  double _drag = 0;
  bool _hover = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_in.value == 0) {
      if (MediaQuery.disableAnimationsOf(context)) {
        _in.value = 1;
      } else {
        _in.forward();
      }
    }
  }

  @override
  void dispose() {
    _in.dispose();
    super.dispose();
  }

  bool get _sendable => widget.message.status != MessageStatus.queued || !widget.message.outgoing;

  void _endDrag() {
    if (_drag >= 56 && widget.callbacks.onReply != null) {
      HapticFeedback.selectionClick();
      widget.callbacks.onReply!(widget.message);
    }
    setState(() => _drag = 0);
  }

  @override
  Widget build(BuildContext context) {
    final m = widget.message, t = widget.tokens, cb = widget.callbacks;
    final mine = m.outgoing;
    final ink = mine ? t.mineText : t.text;
    final meta = mine ? t.meta : t.metaTheirs;
    final width = MediaQuery.sizeOf(context).width;
    final maxBubble = math.min(width * .78, 560.0);
    final a = m.attachment;
    final media = a != null && a.visual;
    const big = Radius.circular(18), joined = Radius.circular(6), tail = Radius.circular(4);
    final radius = BorderRadius.only(
      topLeft: !mine && !widget.first ? joined : big,
      topRight: mine && !widget.first ? joined : big,
      bottomLeft: mine ? big : (widget.last ? tail : joined),
      bottomRight: mine ? (widget.last ? tail : joined) : big,
    );
    final status = !widget.showRead && m.status == MessageStatus.read ? MessageStatus.delivered : m.status;

    final content = <Widget>[
      if (m.replyTo != null)
        _Quote(
          reply: m.replyTo!,
          author: widget.quotedAuthor,
          color: ink,
          authorColor: mine ? ink : (widget.quotedAuthor == 'You' ? t.accent : t.nameColor(widget.peerId)),
          onTap: cb.onQuoteTap == null ? null : () => cb.onQuoteTap!(m.replyTo!.id),
        ),
      if (a != null)
        Padding(
          padding: EdgeInsets.only(bottom: m.body.isEmpty ? 0 : 6),
          child: AttachmentView(attachment: a, tokens: t, onBubble: ink, service: widget.attachments, maxWidth: math.min(320, maxBubble - 16)),
        ),
      if (m.body.isNotEmpty)
        Align(
          alignment: Alignment.centerLeft,
          widthFactor: 1,
          child: MarkdownText(m.body, tokens: t, color: ink, fontSize: 16, highlight: widget.findQuery, linkColor: mine ? ink : t.accent),
        ),
      if (m.link != null)
        Padding(
          padding: const EdgeInsets.only(top: 6),
          child: LinkCard(link: m.link!, color: ink, onTap: () => openLink(m.link!.url)),
        ),
      const SizedBox(height: 2),
      Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (widget.flagged) ...[Icon(Icons.warning_amber_rounded, size: 13, color: t.warn), const SizedBox(width: 3)],
          if (m.edited) ...[
            Text(
              'edited',
              style: TextStyle(color: meta, fontSize: 11, fontStyle: FontStyle.italic),
            ),
            const SizedBox(width: 5),
          ],
          if (m.expiresAt != null) ...[Icon(Icons.timer_outlined, size: 12, color: meta), const SizedBox(width: 3)],
          Text(clock(m.createdAt), style: TextStyle(color: meta, fontSize: 11)),
          if (mine) ...[const SizedBox(width: 4), Ticks(status: status, color: meta, readColor: t.tickRead)],
        ],
      ),
    ];

    Widget bubble = AnimatedContainer(
      duration: const Duration(milliseconds: 260),
      constraints: BoxConstraints(maxWidth: maxBubble),
      padding: EdgeInsets.fromLTRB(media ? 4 : 12, media ? 4 : 8, media ? 8 : 12, 6),
      decoration: BoxDecoration(
        color: widget.highlighted ? Color.alphaBlend(t.warn.withValues(alpha: .35), mine ? t.mine : t.theirs) : (mine ? t.mine : t.theirs),
        borderRadius: radius,
        boxShadow: t.dark ? null : const [BoxShadow(color: Color(0x1F0F1F2A), blurRadius: 1.5, offset: Offset(0, 1))],
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.end, mainAxisSize: MainAxisSize.min, children: content),
    );

    bubble = GestureDetector(
      onLongPress: cb.onMenu == null ? null : () => cb.onMenu!(m),
      onSecondaryTap: cb.onMenu == null ? null : () => cb.onMenu!(m),
      // Double-tap a text bubble for ❤️; photos open instead.
      onDoubleTap: cb.onReact == null || media || !_sendable ? null : () => cb.onReact!(m, '❤️', !m.reactions.of('me').contains('❤️')),
      child: bubble,
    );

    // Desktop hover actions, shown only while the pointer is over the row.
    final hoverBar = Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (cb.onReact != null && _sendable)
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 2),
            decoration: BoxDecoration(
              color: t.surface2,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: t.line),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final e in quickReactions)
                  Tooltip(
                    message: 'React $e',
                    child: InkResponse(
                      radius: 16,
                      onTap: () => cb.onReact!(m, e, !m.reactions.of('me').contains(e)),
                      child: Padding(
                        padding: const EdgeInsets.all(3),
                        child: Text(e, style: const TextStyle(fontSize: 16)),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        if (cb.onReply != null) _HoverButton(icon: Icons.reply_rounded, label: 'Reply', color: t.muted, onTap: () => cb.onReply!(m)),
        if (cb.onMenu != null) _HoverButton(icon: Icons.more_horiz, label: 'More', color: t.muted, onTap: () => cb.onMenu!(m)),
      ],
    );

    final column = Column(
      crossAxisAlignment: mine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (widget.first && !mine && widget.peerName.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(6, 6, 6, 2),
            child: Text(
              widget.peerName,
              style: TextStyle(color: t.nameColor(widget.peerId), fontSize: 12.5, fontWeight: FontWeight.w700),
            ),
          ),
        bubble,
        if (!m.reactions.isEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 3, left: 4, right: 4),
            child: ReactionPills(
              reactions: m.reactions,
              tokens: t,
              peerName: widget.peerName,
              onToggle: cb.onReact == null ? null : (emoji, on) => cb.onReact!(m, emoji, on),
            ),
          ),
      ],
    );

    // Swipe right to reply (mobile); the reply arrow fades in under the finger.
    final swipe = GestureDetector(
      onHorizontalDragUpdate: cb.onReply == null ? null : (d) => setState(() => _drag = (_drag + d.delta.dx).clamp(0, 80)),
      onHorizontalDragEnd: cb.onReply == null ? null : (_) => _endDrag(),
      onHorizontalDragCancel: cb.onReply == null ? null : () => setState(() => _drag = 0),
      child: Stack(
        alignment: Alignment.centerLeft,
        children: [
          if (_drag > 0)
            Opacity(
              opacity: (_drag / 56).clamp(0, 1),
              child: Icon(Icons.reply_rounded, color: t.muted),
            ),
          Transform.translate(
            offset: Offset(_drag, 0),
            child: Align(alignment: mine ? Alignment.centerRight : Alignment.centerLeft, child: column),
          ),
          // Over the empty side of the row, so it never moves the bubble.
          if (_hover) Positioned(top: 0, left: mine ? 0 : null, right: mine ? null : 0, child: hoverBar),
        ],
      ),
    );

    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: Padding(
        padding: EdgeInsets.only(top: widget.first ? widget.display.gap * 2 : widget.display.gap * .5, bottom: widget.display.gap * .5),
        child: FadeTransition(
          opacity: _in,
          child: SlideTransition(
            position: Tween(begin: const Offset(0, .25), end: Offset.zero).animate(CurvedAnimation(parent: _in, curve: Curves.easeOut)),
            child: swipe,
          ),
        ),
      ),
    );
  }
}

class _HoverButton extends StatelessWidget {
  const _HoverButton({required this.icon, required this.label, required this.color, required this.onTap});
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) =>
      IconButton(tooltip: label, visualDensity: VisualDensity.compact, iconSize: 18, color: color, onPressed: onTap, icon: Icon(icon));
}

class _Quote extends StatelessWidget {
  const _Quote({required this.reply, required this.author, required this.color, required this.authorColor, this.onTap});
  final ReplyTo reply;
  final String? author;
  final Color color, authorColor;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) => Semantics(
    button: onTap != null,
    label: 'Reply to ${author ?? 'a message'}: ${reply.text}',
    child: GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.fromLTRB(8, 4, 8, 4),
        decoration: BoxDecoration(
          color: color.withValues(alpha: .08),
          borderRadius: BorderRadius.circular(8),
          border: Border(left: BorderSide(color: authorColor, width: 3)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            if (author != null)
              Text(
                author!,
                style: TextStyle(color: authorColor, fontWeight: FontWeight.w700, fontSize: 12.5),
              ),
            Text(
              reply.text.isEmpty ? 'Attachment' : plainText(reply.text),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(color: color.withValues(alpha: .8), fontSize: 13.5),
            ),
          ],
        ),
      ),
    ),
  );
}

/// "`name` is typing…" with three dots that pulse; still dots under reduced motion.
class TypingIndicator extends StatefulWidget {
  const TypingIndicator({super.key, required this.name, required this.tokens});
  final String name;
  final ChatTokens tokens;
  @override
  State<TypingIndicator> createState() => _TypingIndicatorState();
}

class _TypingIndicatorState extends State<TypingIndicator> with SingleTickerProviderStateMixin {
  late final AnimationController _dots = AnimationController(vsync: this, duration: const Duration(milliseconds: 1200));

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    MediaQuery.disableAnimationsOf(context) ? _dots.stop() : _dots.repeat();
  }

  @override
  void dispose() {
    _dots.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = widget.tokens;
    return Semantics(
      liveRegion: true,
      label: '${widget.name} is typing',
      child: Padding(
        padding: const EdgeInsets.fromLTRB(6, 6, 6, 2),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
              decoration: BoxDecoration(color: t.theirs, borderRadius: BorderRadius.circular(14)),
              child: AnimatedBuilder(
                animation: _dots,
                builder: (_, _) => Row(
                  mainAxisSize: MainAxisSize.min,
                  spacing: 4,
                  children: [
                    for (var i = 0; i < 3; i++)
                      Opacity(
                        opacity: _dots.isAnimating ? .35 + .65 * math.max(0, math.sin((_dots.value - i * .18) * 2 * math.pi)) : .6,
                        child: CircleAvatar(radius: 3.2, backgroundColor: t.muted),
                      ),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 8),
            Flexible(
              child: Text(
                '${widget.name} is typing…',
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: t.muted, fontSize: 12.5),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// "Today", "Yesterday", … between days.
class DaySeparator extends StatelessWidget {
  const DaySeparator({super.key, required this.label, required this.tokens});
  final String label;
  final ChatTokens tokens;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 10),
    child: Center(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        decoration: BoxDecoration(color: tokens.surface2.withValues(alpha: .92), borderRadius: BorderRadius.circular(12)),
        child: Text(
          label,
          style: TextStyle(color: tokens.muted, fontSize: 12, fontWeight: FontWeight.w600),
        ),
      ),
    ),
  );
}

/// A file on its way up: local preview, progress ring, or Retry / Remove after a failure.
class UploadBubble extends StatelessWidget {
  const UploadBubble({super.key, required this.upload, required this.tokens, this.onRetry, this.onRemove});
  final PendingUpload upload;
  final ChatTokens tokens;
  final VoidCallback? onRetry, onRemove;

  @override
  Widget build(BuildContext context) {
    final t = tokens;
    final image = upload.kind == 'image';
    return Align(
      alignment: Alignment.centerRight,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.all(4),
        constraints: const BoxConstraints(maxWidth: 320),
        decoration: BoxDecoration(color: t.mine, borderRadius: BorderRadius.circular(18)),
        child: ValueListenableBuilder<String?>(
          valueListenable: upload.error,
          builder: (context, error, _) => Stack(
            alignment: Alignment.center,
            children: [
              if (image)
                ClipRRect(
                  borderRadius: BorderRadius.circular(14),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxHeight: 320),
                    child: Opacity(
                      opacity: .7,
                      child: Image.memory(upload.bytes, fit: BoxFit.cover, errorBuilder: (_, _, _) => const SizedBox(width: 200, height: 120)),
                    ),
                  ),
                )
              else
                Padding(
                  padding: const EdgeInsets.fromLTRB(12, 10, 56, 10),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(upload.kind == 'voice' ? Icons.mic_none_rounded : Icons.insert_drive_file_outlined, color: t.mineText),
                      const SizedBox(width: 8),
                      Flexible(
                        child: Text(
                          upload.name,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(color: t.mineText, fontWeight: FontWeight.w600),
                        ),
                      ),
                    ],
                  ),
                ),
              Positioned(
                right: image ? null : 8,
                child: error != null
                    ? Material(
                        color: const Color(0xCC000000),
                        borderRadius: BorderRadius.circular(16),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 6),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text("Couldn't send", style: const TextStyle(color: Colors.white, fontSize: 12.5)),
                              TextButton(onPressed: onRetry, child: const Text('Retry')),
                              IconButton(
                                tooltip: 'Remove',
                                onPressed: onRemove,
                                icon: const Icon(Icons.close, color: Colors.white, size: 18),
                              ),
                            ],
                          ),
                        ),
                      )
                    : ValueListenableBuilder<double>(
                        valueListenable: upload.progress,
                        builder: (_, v, _) => Semantics(
                          label: 'Uploading ${(v * 100).round()}%',
                          child: Container(
                            width: 40,
                            height: 40,
                            padding: const EdgeInsets.all(7),
                            decoration: const BoxDecoration(color: Color(0x88000000), shape: BoxShape.circle),
                            child: CircularProgressIndicator(value: v <= 0 ? null : v, strokeWidth: 3, color: Colors.white),
                          ),
                        ),
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
