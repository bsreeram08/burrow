import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/theme/tokens.dart';
import 'package:private_chat/ui/conversation_view.dart';
import 'package:private_chat/ui/widgets/attachment_view.dart';

final tokens = ChatTokens.resolve('classic-light');
const conversation = 'dChfd14K4ur8IscmUwp33zHqWJXMk3nspofSVemJzf0';
String uuid(int n) => '00000000-0000-4000-8000-${n.toString().padLeft(12, '0')}';

ChatMessage msg(int n, String text, {bool outgoing = false, int? at, MessageStatus? status, Reactions reactions = const Reactions(), ReplyTo? replyTo}) => ChatMessage(
  id: uuid(n),
  conversationId: conversation,
  direction: outgoing ? Direction.outgoing : Direction.incoming,
  text: text,
  createdAt: at ?? DateTime.now().millisecondsSinceEpoch,
  status: status ?? (outgoing ? MessageStatus.delivered : MessageStatus.delivered),
  reactions: reactions,
  replyTo: replyTo,
);

class _Actions extends ConversationActions {
  final calls = <String>[];
  final shown = <String>[];
  final edits = <(String, String)>[];
  final typingCalls = <bool>[];
  @override
  Future<void> react(ChatMessage message, String emoji, bool on) async => calls.add('react ${message.id} $emoji $on');
  @override
  Future<void> edit(ChatMessage message, String text) async => edits.add((message.id, text));
  @override
  void displayed(List<ChatMessage> messages) => shown.addAll(messages.map((m) => m.id));
  @override
  void typing(bool on) => typingCalls.add(on);
}

Widget host(Widget child) => MaterialApp(theme: tokens.material(), home: Scaffold(body: child));

void main() {
  Widget view(List<ChatMessage> messages, {_Actions? actions, Future<void> Function(Draft)? onSend, bool typing = false}) => host(
    ConversationView(
      tokens: tokens,
      wallpaper: 'none',
      messages: messages,
      peerName: 'alice',
      peerId: 'alice-id',
      typing: typing,
      actions: actions ?? _Actions(),
      onSend: onSend ?? (_) async {},
    ),
  );

  testWidgets('markdown renders as styled spans, never as markup', (tester) async {
    await tester.pumpWidget(view([msg(1, 'a **bold** move and `code`')]));
    final rich = tester.widgetList<RichText>(find.byType(RichText)).firstWhere((r) => r.text.toPlainText().contains('bold'));
    expect(rich.text.toPlainText(), 'a bold move and code');
    final spans = <TextSpan>[];
    rich.text.visitChildren((s) {
      if (s is TextSpan) spans.add(s);
      return true;
    });
    expect(spans.firstWhere((s) => s.text == 'bold').style!.fontWeight, FontWeight.w700);
  });

  testWidgets('date separators and the typing indicator', (tester) async {
    final now = DateTime.now();
    final yesterday = DateTime(now.year, now.month, now.day - 1, 12).millisecondsSinceEpoch;
    await tester.pumpWidget(view([msg(1, 'old', at: yesterday), msg(2, 'new')], typing: true));
    expect(find.text('Yesterday'), findsOneWidget);
    expect(find.text('Today'), findsOneWidget);
    expect(find.text('alice is typing…'), findsOneWidget);
  });

  testWidgets('shown incoming messages are reported once for read receipts', (tester) async {
    final actions = _Actions();
    await tester.pumpWidget(view([msg(1, 'hi'), msg(2, 'mine', outgoing: true), msg(3, 'read already', status: MessageStatus.read)], actions: actions));
    await tester.pump();
    await tester.pumpWidget(view([msg(1, 'hi'), msg(2, 'mine', outgoing: true), msg(3, 'read already', status: MessageStatus.read)], actions: actions));
    await tester.pump();
    expect(actions.shown, [uuid(1)]);
  });

  testWidgets('reply from the long-press menu quotes the message in the draft', (tester) async {
    final drafts = <Draft>[];
    await tester.pumpWidget(view([msg(1, 'lunch at noon?')], onSend: (d) async => drafts.add(d)));
    await tester.longPress(find.text('lunch at noon?'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Reply'));
    await tester.pumpAndSettle();
    expect(find.text('Replying to alice'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('composer')), 'yes');
    await tester.tap(find.byKey(const Key('send')));
    await tester.pump();
    expect(drafts.single.replyTo, ReplyTo(id: uuid(1), text: 'lunch at noon?'));
    expect(find.text('Replying to alice'), findsNothing);
    await tester.pumpAndSettle();
  });

  testWidgets('a quick reaction from the menu, and tapping our pill removes it', (tester) async {
    final actions = _Actions();
    await tester.pumpWidget(view([msg(1, 'party', reactions: const Reactions({'me': ['🎉'], 'peer': ['🎉', '👍']}))], actions: actions));
    expect(find.text('🎉 2'), findsOneWidget);
    await tester.tap(find.text('🎉 2'));
    await tester.longPress(find.text('party'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('😂'));
    await tester.pumpAndSettle();
    expect(actions.calls, ['react ${uuid(1)} 🎉 false', 'react ${uuid(1)} 😂 true']);
  });

  testWidgets('↑ in an empty composer edits the last sent message; Esc cancels', (tester) async {
    final actions = _Actions();
    await tester.pumpWidget(view([msg(1, 'theirs'), msg(2, 'teh plan', outgoing: true, status: MessageStatus.sent)], actions: actions));
    await tester.tap(find.byKey(const Key('composer')));
    await tester.pump();
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
    await tester.pump();
    expect(find.text('Editing'), findsOneWidget);
    expect(tester.widget<TextField>(find.byKey(const Key('composer'))).controller!.text, 'teh plan');
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pump();
    expect(find.text('Editing'), findsNothing);
    expect(tester.widget<TextField>(find.byKey(const Key('composer'))).controller!.text, isEmpty);

    await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
    await tester.pump();
    await tester.enterText(find.byKey(const Key('composer')), 'the plan');
    await tester.tap(find.byKey(const Key('send')));
    await tester.pump();
    expect(actions.edits, [(uuid(2), 'the plan')]);
  });

  testWidgets('typing is reported while the composer has text and stopped on send', (tester) async {
    final actions = _Actions();
    await tester.pumpWidget(view(const [], actions: actions));
    await tester.enterText(find.byKey(const Key('composer')), 'h');
    await tester.enterText(find.byKey(const Key('composer')), 'hi');
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    expect(actions.typingCalls.first, isTrue);
    expect(actions.typingCalls.last, isFalse);
  });

  testWidgets('find in conversation counts matches and highlights them', (tester) async {
    await tester.pumpWidget(view([msg(1, 'the needle'), msg(2, 'hay'), msg(3, 'another needle')]));
    tester.state<ConversationViewState>(find.byType(ConversationView)).openFind();
    await tester.pump();
    await tester.enterText(find.byKey(const Key('find')), 'needle');
    await tester.pumpAndSettle();
    expect(find.text('1 of 2'), findsOneWidget);
    await tester.tap(find.byTooltip('Previous match (older)'));
    await tester.pumpAndSettle();
    expect(find.text('2 of 2'), findsOneWidget);
    await tester.tap(find.byTooltip('Close find'));
    await tester.pump();
    expect(find.byKey(const Key('find')), findsNothing);
  });

  testWidgets('jump to newest appears when scrolled up', (tester) async {
    final base = DateTime.now().millisecondsSinceEpoch - 100000;
    await tester.pumpWidget(view([for (var i = 1; i <= 60; i++) msg(i, 'message $i', at: base + i * 1000)]));
    expect(find.byKey(const Key('jump-newest')), findsNothing);
    await tester.drag(find.byType(ListView), const Offset(0, 1500));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('jump-newest')), findsOneWidget);
    await tester.tap(find.byKey(const Key('jump-newest')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('jump-newest')), findsNothing);
  });

  testWidgets('edited messages say so, and a quoted reply shows its author', (tester) async {
    final edited = msg(2, 'fixed', outgoing: true).copyWith(editedText: 'fixed!', editedAt: 1);
    await tester.pumpWidget(view([msg(1, 'original'), edited, msg(3, 'answer', replyTo: ReplyTo(id: uuid(2), text: 'fixed'))]));
    expect(find.text('edited'), findsOneWidget);
    expect(find.text('You'), findsOneWidget);
  });

  test('Apple players get a fallback for WebM / Opus voice notes; m4a plays everywhere', () {
    for (final mime in ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg; codecs=opus', 'audio/opus']) {
      expect(playableHere(mime, apple: true), isFalse, reason: mime);
      expect(playableHere(mime, apple: false), isTrue, reason: mime);
    }
    expect(playableHere('audio/mp4', apple: true), isTrue);
    expect(playableHere('audio/aac', apple: true), isTrue);
  });

  testWidgets('a web voice note on an Apple device says it can\'t play here and offers to save it', (tester) async {
    final voice = Attachment.fromJson({
      'kind': 'voice', 'blob': 'b' * 22, 'key': 'k' * 43, 'sha256': 's' * 43, 'mime': 'audio/webm;codecs=opus', 'name': 'Voice message.webm', 'size': 900,
      'duration': 2.5, 'waveform': [3, 9, 20],
    });
    await tester.pumpWidget(host(AttachmentView(attachment: voice, tokens: tokens, onBubble: tokens.text)));
    expect(find.text("This voice message can't play here"), findsOneWidget);
    expect(find.byKey(const Key('voice-save')), findsOneWidget);
  }, skip: !(Platform.isMacOS || Platform.isIOS));

  test('desktop delivery reveals the saved file in the file manager and never opens it', () {
    final mac = revealCommand('/Users/me/Downloads/a.pdf', os: 'macos')!;
    expect(mac.executable, '/usr/bin/open');
    expect(mac.arguments, ['-R', '/Users/me/Downloads/a.pdf']);
    final windows = revealCommand(r'C:\Users\me\Downloads\a.pdf', os: 'windows')!;
    expect(windows.executable, 'explorer.exe');
    expect(windows.arguments, ['/select,', r'C:\Users\me\Downloads\a.pdf']);
    expect(revealCommand('/home/me/Downloads/a.pdf', os: 'linux'), isNull, reason: 'Linux opens the folder, not the file');
  });

  testWidgets('a file card shows the cleaned name and its real extension', (tester) async {
    final file = Attachment.fromJson({'kind': 'file', 'blob': 'b' * 22, 'key': 'k' * 43, 'sha256': 's' * 43, 'mime': 'application/pdf', 'name': 'invoice\u202Efdp.exe', 'size': 2048});
    await tester.pumpWidget(host(AttachmentView(attachment: file, tokens: tokens, onBubble: tokens.text)));
    expect(find.text('invoicefdp.exe'), findsOneWidget);
    expect(tester.widget<Text>(find.byKey(const Key('file-meta'))).data, 'EXE · 2 KB');
  });
}
