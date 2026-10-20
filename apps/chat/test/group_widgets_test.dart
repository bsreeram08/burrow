import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/messaging/group_messenger.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/theme/tokens.dart';
import 'package:private_chat/ui/conversation_view.dart';
import 'package:private_chat/ui/widgets/reactions.dart';

/// The conversation view in group mode (docs/m4-groups.md §5): sender names, system rows, @ autocomplete,
/// who reacted, the read-only footer.
final tokens = ChatTokens.resolve('midnight');
final group = 'G' * 22, alice = 'a' * 22, bob = 'b' * 22, me = 'm' * 22;
String uuid(int n) => '00000000-0000-4000-8000-${n.toString().padLeft(12, '0')}';
const names = {'a': 'alice', 'b': 'bob', 'm': 'me', 'c': 'carol'};
String nameOf(String id) => names[id[0]] ?? 'someone';
final members = [
  GroupPerson(userId: alice, username: 'alice', admin: true),
  GroupPerson(userId: bob, username: 'bob', admin: false),
  GroupPerson(userId: 'c' * 22, username: 'carol', admin: false),
  GroupPerson(userId: me, username: 'me', admin: false),
];

ChatMessage incoming(int n, String text, String from, {List<String> mentions = const [], Reactions reactions = const Reactions()}) => ChatMessage(
  id: uuid(n),
  conversationId: group,
  direction: Direction.incoming,
  text: text,
  createdAt: 1700000000000 + n * 1000,
  status: MessageStatus.delivered,
  sender: from,
  senderName: nameOf(from),
  mentions: mentions,
  reactions: reactions,
);

void main() {
  Widget view(List<ChatMessage> messages, {String? readOnly, String? typing, Future<void> Function(Draft)? onSend}) => MaterialApp(
    theme: tokens.material(),
    home: Scaffold(
      body: ConversationView(
        tokens: tokens,
        wallpaper: 'dots',
        messages: messages,
        peerName: 'Design',
        nameOf: nameOf,
        members: members,
        me: me,
        typingText: typing,
        readOnly: readOnly,
        onSend: onSend ?? (_) async {},
      ),
    ),
  );

  testWidgets('each sender is named once per run; system lines sit in the middle', (tester) async {
    final system = ChatMessage(id: uuid(9), conversationId: group, direction: Direction.system, text: 'alice added bob', createdAt: 1700000000500, status: MessageStatus.delivered);
    await tester.pumpWidget(view([system, incoming(1, 'one', alice), incoming(2, 'two', alice), incoming(3, 'three', bob)]));
    await tester.pumpAndSettle();
    expect(find.text('alice added bob'), findsOneWidget);
    expect(find.text('alice'), findsOneWidget, reason: 'two messages in a row from alice share one header');
    expect(find.text('bob'), findsOneWidget);
  });

  testWidgets('typing @ suggests members (never me); Tab or a tap inserts @username', (tester) async {
    final sent = <String>[];
    await tester.pumpWidget(view(const [], onSend: (d) async => sent.add(d.text)));
    await tester.enterText(find.byKey(const Key('composer')), 'hi @b');
    await tester.pump();
    expect(find.byKey(const Key('mention-list')), findsOneWidget);
    expect(find.byKey(const ValueKey('mention-bob')), findsOneWidget);
    expect(find.byKey(const ValueKey('mention-me')), findsNothing);
    await tester.tap(find.byKey(const ValueKey('mention-bob')));
    await tester.pump();
    expect(tester.widget<TextField>(find.byKey(const Key('composer'))).controller!.text, 'hi @bob ');
    expect(find.byKey(const Key('mention-list')), findsNothing);
    // Keyboard: ↓ then Tab picks the second suggestion.
    await tester.enterText(find.byKey(const Key('composer')), '@');
    await tester.pump();
    expect(find.byKey(const Key('mention-list')), findsOneWidget);
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pump();
    expect(tester.widget<TextField>(find.byKey(const Key('composer'))).controller!.text, '@bob ');
  });

  testWidgets('reactions say who reacted; read-only groups have no composer', (tester) async {
    final reactions = const Reactions().toggle(alice, '👍', true)!.toggle('me', '👍', true)!.toggle(bob, '🎉', true)!;
    await tester.pumpWidget(view([incoming(1, 'hello @me', alice, mentions: [me], reactions: reactions)], readOnly: 'You left this group.'));
    await tester.pumpAndSettle();
    final tooltips = tester.widgetList<Tooltip>(find.descendant(of: find.byType(ReactionPills), matching: find.byType(Tooltip))).map((t) => t.message).toList();
    expect(tooltips, ['You, alice', 'bob']);
    expect(find.byKey(const Key('read-only')), findsOneWidget);
    expect(find.byKey(const Key('composer')), findsNothing);
  });

  testWidgets('a group typing line names who is typing', (tester) async {
    await tester.pumpWidget(view([incoming(1, 'x', alice)], typing: typingLine(['alice', 'bob'])));
    await tester.pump();
    expect(find.text('alice and bob are typing…'), findsOneWidget);
  });

  test('mentionsIn keeps members named in the final text, once, never me', () {
    expect(mentionsIn('@bob @carol @bob @me @nobody email@bob.com', members, me: me), [bob, 'c' * 22]);
  });
}
