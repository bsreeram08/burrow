/// The safe Markdown subset both clients render (docs/phase1-protocol.md §1): `**bold**`,
/// `_italic_` / `*italic*`, `~~strike~~`, `` `code` ``, fenced code blocks with an optional language
/// label, `> quote` lines and auto-linked `https://` URLs. Nothing else is interpreted, HTML least of
/// all: the result is plain data that the UI turns into text spans.
library;

sealed class MdBlock {
  const MdBlock();
}

/// Ordinary lines (line breaks kept).
class MdParagraph extends MdBlock {
  const MdParagraph(this.runs);
  final List<MdRun> runs;
}

/// Consecutive `> ` lines.
class MdQuote extends MdBlock {
  const MdQuote(this.runs);
  final List<MdRun> runs;
}

/// A fenced block: shown verbatim in a monospace box, never executed.
class MdCode extends MdBlock {
  const MdCode(this.code, {this.language});
  final String code;
  final String? language;
}

/// A piece of text with its styles. [link] is an https URL when the run is an auto-link.
class MdRun {
  const MdRun(this.text, {this.bold = false, this.italic = false, this.strike = false, this.code = false, this.link});
  final String text;
  final bool bold, italic, strike, code;
  final String? link;

  MdRun _with(String text) => MdRun(text, bold: bold, italic: italic, strike: strike, code: code, link: link);

  @override
  bool operator ==(Object other) =>
      other is MdRun &&
      other.text == text &&
      other.bold == bold &&
      other.italic == italic &&
      other.strike == strike &&
      other.code == code &&
      other.link == link;
  @override
  int get hashCode => Object.hash(text, bold, italic, strike, code, link);
  @override
  String toString() => 'MdRun(${[text, if (bold) 'b', if (italic) 'i', if (strike) 's', if (code) 'c', ?link].join(', ')})';
}

class _Style {
  const _Style({this.bold = false, this.italic = false, this.strike = false});
  final bool bold, italic, strike;
  _Style copy({bool? bold, bool? italic, bool? strike}) => _Style(bold: bold ?? this.bold, italic: italic ?? this.italic, strike: strike ?? this.strike);
}

final _fence = RegExp(r'^\s{0,3}```\s*([A-Za-z0-9_+#.-]{1,20})?\s*$');
final _quote = RegExp(r'^\s{0,3}>\s?');

List<MdBlock> parseMarkdown(String text) {
  final lines = text.replaceAll('\r\n', '\n').split('\n');
  final blocks = <MdBlock>[];
  final paragraph = <String>[], quote = <String>[];
  void flush() {
    if (paragraph.isNotEmpty) blocks.add(MdParagraph(parseInline(paragraph.join('\n'))));
    if (quote.isNotEmpty) blocks.add(MdQuote(parseInline(quote.join('\n'))));
    paragraph.clear();
    quote.clear();
  }

  for (var i = 0; i < lines.length; i++) {
    final line = lines[i];
    final open = _fence.firstMatch(line);
    if (open != null) {
      final close = lines.indexWhere((l) => l.trim() == '```', i + 1);
      if (close != -1) {
        flush();
        blocks.add(MdCode(lines.sublist(i + 1, close).join('\n'), language: open.group(1)));
        i = close;
        continue;
      }
    }
    final q = _quote.firstMatch(line);
    if (q != null) {
      if (paragraph.isNotEmpty) flush();
      quote.add(line.substring(q.end));
    } else {
      if (quote.isNotEmpty) flush();
      paragraph.add(line);
    }
  }
  flush();
  return blocks;
}

final _url = RegExp(r'https://[^\s<>"`]+');
const _trailing = '.,;:!?\'")]}';

/// The URL starting at [start] (which must begin `https://`), without trailing punctuation.
String? _urlAt(String text, int start) {
  final match = _url.matchAsPrefix(text, start);
  if (match == null) return null;
  var url = match.group(0)!;
  while (url.isNotEmpty && _trailing.contains(url[url.length - 1])) {
    // Keep a closing parenthesis that closes one inside the URL (Wikipedia-style links).
    if (url.endsWith(')') && '('.allMatches(url).length >= ')'.allMatches(url).length) break;
    url = url.substring(0, url.length - 1);
  }
  return url.length > 'https://'.length ? url : null;
}

/// Every auto-linked https URL in [text], in order.
List<String> findLinks(String text) => [
  for (final block in parseMarkdown(text))
    if (block is MdParagraph || block is MdQuote)
      for (final run in block is MdParagraph ? block.runs : (block as MdQuote).runs)
        if (run.link != null) run.link!,
];

bool _wordChar(String c) => RegExp(r'[A-Za-z0-9]').hasMatch(c);

List<MdRun> parseInline(String text) {
  final out = <MdRun>[];
  _inline(text, const _Style(), out);
  // Merge neighbours with the same style so the UI gets as few spans as possible.
  final merged = <MdRun>[];
  for (final run in out) {
    final last = merged.isEmpty ? null : merged.last;
    if (last != null && last.bold == run.bold && last.italic == run.italic && last.strike == run.strike && !last.code && !run.code && last.link == null && run.link == null) {
      merged[merged.length - 1] = last._with(last.text + run.text);
    } else {
      merged.add(run);
    }
  }
  return merged;
}

void _inline(String text, _Style style, List<MdRun> out) {
  final plain = StringBuffer();
  void literal() {
    if (plain.isEmpty) return;
    out.add(MdRun(plain.toString(), bold: style.bold, italic: style.italic, strike: style.strike));
    plain.clear();
  }

  var i = 0;
  while (i < text.length) {
    final c = text[i];
    // `code`: verbatim, no styling inside.
    if (c == '`') {
      final end = text.indexOf('`', i + 1);
      if (end > i + 1) {
        literal();
        out.add(MdRun(text.substring(i + 1, end), bold: style.bold, italic: style.italic, strike: style.strike, code: true));
        i = end + 1;
        continue;
      }
    }
    if (text.startsWith('https://', i)) {
      final url = _urlAt(text, i);
      if (url != null) {
        literal();
        out.add(MdRun(url, bold: style.bold, italic: style.italic, strike: style.strike, link: url));
        i += url.length;
        continue;
      }
    }
    final marker = text.startsWith('**', i) ? '**' : (text.startsWith('~~', i) ? '~~' : null);
    if (marker != null) {
      final end = text.indexOf(marker, i + 2);
      if (end > i + 2 && text[i + 2].trim().isNotEmpty && text[end - 1].trim().isNotEmpty) {
        literal();
        _inline(text.substring(i + 2, end), marker == '**' ? style.copy(bold: true) : style.copy(strike: true), out);
        i = end + 2;
        continue;
      }
    }
    if ((c == '*' || c == '_') && !text.startsWith('**', i)) {
      final before = i == 0 ? ' ' : text[i - 1];
      final opens = i + 1 < text.length && text[i + 1].trim().isNotEmpty && (c == '*' || !_wordChar(before));
      if (opens) {
        var end = i + 1;
        while (true) {
          end = text.indexOf(c, end + 1);
          if (end == -1) break;
          final after = end + 1 < text.length ? text[end + 1] : ' ';
          final closes = text[end - 1].trim().isNotEmpty && (c == '*' ? after != '*' : !_wordChar(after));
          if (closes) break;
        }
        if (end > i + 1) {
          literal();
          _inline(text.substring(i + 1, end), style.copy(italic: true), out);
          i = end + 1;
          continue;
        }
      }
    }
    plain.write(c);
    i++;
  }
  literal();
}

/// Text with the markers removed, for one-line previews (chat list, reply quotes, notifications).
String plainText(String text) => parseMarkdown(text)
    .map((b) => switch (b) {
          MdParagraph(:final runs) || MdQuote(:final runs) => runs.map((r) => r.text).join(),
          MdCode(:final code) => code,
        })
    .join('\n');
