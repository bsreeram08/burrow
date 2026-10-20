import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/text/fuzzy.dart';
import 'package:private_chat/text/markdown.dart';
import 'package:private_chat/text/timeline.dart';

void main() {
  group('markdown subset', () {
    List<MdRun> runs(String text) => (parseMarkdown(text).single as MdParagraph).runs;

    test('inline styles', () {
      expect(runs('a **bold** b'), const [MdRun('a '), MdRun('bold', bold: true), MdRun(' b')]);
      expect(runs('_it_ and *it*'), const [MdRun('it', italic: true), MdRun(' and '), MdRun('it', italic: true)]);
      expect(runs('~~gone~~'), const [MdRun('gone', strike: true)]);
      expect(runs('run `a *b* c` now'), const [MdRun('run '), MdRun('a *b* c', code: true), MdRun(' now')]);
      expect(runs('**bold _both_**'), const [MdRun('bold ', bold: true), MdRun('both', bold: true, italic: true)]);
    });

    test('snake_case, lone markers and unclosed markers stay literal', () {
      expect(runs('snake_case_name'), const [MdRun('snake_case_name')]);
      expect(runs('2 * 3 * 4'), const [MdRun('2 * 3 * 4')]);
      expect(runs('**open'), const [MdRun('**open')]);
      expect(runs('a ` b'), const [MdRun('a ` b')]);
    });

    test('https URLs are auto-linked without trailing punctuation; http is not', () {
      expect(runs('see https://example.com/x?y=1.'), const [MdRun('see '), MdRun('https://example.com/x?y=1', link: 'https://example.com/x?y=1'), MdRun('.')]);
      expect(runs('(https://en.wikipedia.org/wiki/A_(b))'), const [
        MdRun('('),
        MdRun('https://en.wikipedia.org/wiki/A_(b)', link: 'https://en.wikipedia.org/wiki/A_(b)'),
        MdRun(')'),
      ]);
      expect(runs('http://plain.example'), const [MdRun('http://plain.example')]);
      expect(findLinks('a https://one.example b **https://two.example**'), ['https://one.example', 'https://two.example']);
    });

    test('blocks: quotes, fenced code with a language label, paragraphs', () {
      final blocks = parseMarkdown('> quoted\n> more\nafter\n```dart\nvoid main() {}\n```\nend');
      expect(blocks, hasLength(4));
      expect((blocks[0] as MdQuote).runs, const [MdRun('quoted\nmore')]);
      expect((blocks[1] as MdParagraph).runs, const [MdRun('after')]);
      expect((blocks[2] as MdCode).code, 'void main() {}');
      expect((blocks[2] as MdCode).language, 'dart');
      expect((blocks[3] as MdParagraph).runs, const [MdRun('end')]);
    });

    test('HTML is just text; an unclosed fence is text', () {
      expect(runs('<b>hi</b><script>x</script>'), const [MdRun('<b>hi</b><script>x</script>')]);
      expect(parseMarkdown('```\nno close').whereType<MdCode>(), isEmpty);
      expect(plainText('**a** _b_ `c`'), 'a b c');
    });
  });

  group('timeline', () {
    final day = DateTime(2026, 10, 19, 12).millisecondsSinceEpoch;
    ChatMessage m(int n, int at, {bool out = false}) => ChatMessage(
      id: '00000000-0000-4000-8000-${n.toString().padLeft(12, '0')}',
      conversationId: 'c' * 43,
      direction: out ? Direction.outgoing : Direction.incoming,
      text: 't$n',
      createdAt: at,
      status: MessageStatus.delivered,
    );

    test('groups by sender within 5 minutes and separates days', () {
      final list = [
        m(1, day - 86400000),
        m(2, day),
        m(3, day + 60000),
        m(4, day + 60000 + groupGapMs + 1),
        m(5, day + 400000, out: true),
      ];
      final rows = buildTimeline(list, now: DateTime(2026, 10, 19, 18));
      expect(rows.map((r) => r is DayDivider ? r.label : (r as MessageEntry).message.text).toList(), ['Yesterday', 't1', 'Today', 't2', 't3', 't4', 't5']);
      final entries = rows.whereType<MessageEntry>().toList();
      expect([for (final e in entries) (e.first, e.last)], [(true, true), (true, false), (false, true), (true, true), (true, true)]);
    });

    test('day labels', () {
      final now = DateTime(2026, 10, 19, 9);
      expect(dayLabel(DateTime(2026, 10, 19), now), 'Today');
      expect(dayLabel(DateTime(2026, 10, 18), now), 'Yesterday');
      expect(dayLabel(DateTime(2026, 10, 15), now), 'Thursday');
      expect(dayLabel(DateTime(2026, 3, 3), now), '3 March');
      expect(dayLabel(DateTime(2025, 12, 31), now), '31 December 2025');
    });
  });

  group('fuzzy', () {
    test('subsequence match, word starts and prefixes rank first', () {
      expect(fuzzyScore('xyz', 'alice'), isNull);
      expect(fuzzyScore('', 'anything'), 0);
      final items = ['Toggle density', 'Theme…', 'alice', 'Search this chat', 'New conversation'];
      expect(fuzzyFilter('th', items, (s) => s).first, 'Theme…');
      expect(fuzzyFilter('srch', items, (s) => s), ['Search this chat']);
      expect(fuzzyFilter('nc', items, (s) => s).first, 'New conversation');
    });
  });
}
