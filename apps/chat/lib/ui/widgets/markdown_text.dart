import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../text/markdown.dart';
import '../../theme/tokens.dart';

Future<void> openLink(String url) async {
  final uri = Uri.tryParse(url);
  if (uri == null || uri.scheme != 'https') return;
  await launchUrl(uri, mode: LaunchMode.externalApplication);
}

/// Renders the protocol's Markdown subset as text spans and boxes; never HTML. Matches of
/// [highlight] (find in conversation) get a marker background.
class MarkdownText extends StatefulWidget {
  const MarkdownText(this.text, {super.key, required this.tokens, required this.color, this.fontSize = 16, this.highlight, this.linkColor, this.mentions = const {}});
  final String text;
  final ChatTokens tokens;
  final Color color;
  final Color? linkColor;
  final double fontSize;
  final String? highlight;

  /// Lower-case usernames whose `@username` is a mention (m4-groups §5.2).
  final Set<String> mentions;

  @override
  State<MarkdownText> createState() => _MarkdownTextState();
}

class _MarkdownTextState extends State<MarkdownText> {
  final _recognizers = <TapGestureRecognizer>[];
  List<MdBlock>? _blocks;
  String? _parsed;

  @override
  void dispose() {
    _disposeRecognizers();
    super.dispose();
  }

  void _disposeRecognizers() {
    for (final r in _recognizers) {
      r.dispose();
    }
    _recognizers.clear();
  }

  List<InlineSpan> _spans(List<MdRun> runs, TextStyle base) {
    final t = widget.tokens;
    final out = <InlineSpan>[];
    for (final run in runs) {
      var style = base.copyWith(
        fontWeight: run.bold ? FontWeight.w700 : null,
        fontStyle: run.italic ? FontStyle.italic : null,
        decoration: run.strike ? TextDecoration.lineThrough : null,
      );
      if (run.code) {
        style = style.copyWith(
          fontFamily: 'Menlo',
          fontFamilyFallback: const ['SF Mono', 'Roboto Mono', 'Consolas', 'monospace'],
          fontSize: widget.fontSize * .9,
          backgroundColor: widget.color.withValues(alpha: .12),
        );
      }
      TapGestureRecognizer? tap;
      if (run.link != null) {
        final link = run.link!;
        tap = TapGestureRecognizer()..onTap = () => openLink(link);
        _recognizers.add(tap);
        style = style.copyWith(color: widget.linkColor ?? widget.color, decoration: TextDecoration.underline, decorationColor: (widget.linkColor ?? widget.color).withValues(alpha: .6));
      }
      out.addAll(_highlighted(run.text, style, tap, t));
    }
    return out;
  }

  Iterable<InlineSpan> _highlighted(String text, TextStyle style, TapGestureRecognizer? tap, ChatTokens t) sync* {
    final q = widget.highlight?.trim().toLowerCase() ?? '';
    if (q.isEmpty) {
      if (widget.mentions.isEmpty || tap != null) {
        yield TextSpan(text: text, style: style, recognizer: tap);
        return;
      }
      var from = 0;
      for (final match in _mention.allMatches(text)) {
        if (!widget.mentions.contains(match.group(2)!.toLowerCase())) continue;
        final at = match.start + match.group(1)!.length;
        if (at > from) yield TextSpan(text: text.substring(from, at), style: style);
        yield TextSpan(
          text: text.substring(at, match.end),
          style: style.copyWith(fontWeight: FontWeight.w700, color: widget.linkColor ?? widget.color, backgroundColor: (widget.linkColor ?? widget.color).withValues(alpha: .14)),
        );
        from = match.end;
      }
      if (from < text.length) yield TextSpan(text: text.substring(from), style: style);
      return;
    }
    final lower = text.toLowerCase();
    var from = 0;
    while (true) {
      final at = lower.indexOf(q, from);
      if (at == -1) break;
      if (at > from) yield TextSpan(text: text.substring(from, at), style: style, recognizer: tap);
      yield TextSpan(
        text: text.substring(at, at + q.length),
        style: style.copyWith(backgroundColor: t.warn.withValues(alpha: .45), color: t.dark ? Colors.white : Colors.black),
        recognizer: tap,
      );
      from = at + q.length;
    }
    if (from < text.length) yield TextSpan(text: text.substring(from), style: style, recognizer: tap);
  }

  @override
  Widget build(BuildContext context) {
    if (_parsed != widget.text) {
      _blocks = parseMarkdown(widget.text);
      _parsed = widget.text;
    }
    _disposeRecognizers();
    final t = widget.tokens;
    final base = TextStyle(color: widget.color, fontSize: widget.fontSize, height: 1.35);
    final children = <Widget>[];
    for (final block in _blocks!) {
      children.add(switch (block) {
        MdParagraph(:final runs) => Text.rich(TextSpan(children: _spans(runs, base))),
        MdQuote(:final runs) => Container(
          margin: const EdgeInsets.symmetric(vertical: 2),
          padding: const EdgeInsets.only(left: 10),
          decoration: BoxDecoration(border: Border(left: BorderSide(color: widget.color.withValues(alpha: .45), width: 3))),
          child: Text.rich(TextSpan(children: _spans(runs, base.copyWith(color: widget.color.withValues(alpha: .82))))),
        ),
        MdCode(:final code, :final language) => _CodeBox(code: code, language: language, color: widget.color, fontSize: widget.fontSize, tokens: t),
      });
    }
    if (children.length == 1) return children.single;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, spacing: 4, children: children);
  }
}

final _mention = RegExp(r'(^|[^A-Za-z0-9_])@([A-Za-z0-9_]{3,20})(?![A-Za-z0-9_])');

class _CodeBox extends StatelessWidget {
  const _CodeBox({required this.code, required this.language, required this.color, required this.fontSize, required this.tokens});
  final String code;
  final String? language;
  final Color color;
  final double fontSize;
  final ChatTokens tokens;

  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.symmetric(vertical: 2),
    decoration: BoxDecoration(color: color.withValues(alpha: .08), borderRadius: BorderRadius.circular(8), border: Border.all(color: color.withValues(alpha: .16))),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (language != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(10, 6, 10, 0),
            child: Text(language!, style: TextStyle(color: color.withValues(alpha: .7), fontSize: fontSize * .72, fontWeight: FontWeight.w600)),
          ),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.fromLTRB(10, 6, 10, 8),
          child: SelectableText(
            code,
            style: TextStyle(
              color: color,
              fontSize: fontSize * .86,
              height: 1.4,
              fontFamily: 'Menlo',
              fontFamilyFallback: const ['SF Mono', 'Roboto Mono', 'Consolas', 'monospace'],
            ),
          ),
        ),
      ],
    ),
  );
}
