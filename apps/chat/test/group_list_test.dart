import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/app/app_controller.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:private_chat/ui/chat_list_screen.dart';

/// The chat list (design notes §4, m4-groups §1): Pinned, Channels, Groups and Direct
/// messages, with unread counts and the @ badge.
class _App extends AppController {
  _App(this.initial);
  final AppState initial;
  @override
  AppState build() => initial;
}

void main() {
  GroupConversation group(String c, GroupKindName kind, String name, {int unread = 0, bool mentioned = false, bool pinned = false, Membership membership = Membership.active}) =>
      GroupConversation(id: c * 22, kind: kind, name: name, createdAt: 1, unread: unread, mentioned: mentioned, pinned: pinned, membership: membership);

  testWidgets('sections, badges and left groups', (tester) async {
    tester.view.physicalSize = const Size(900, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    final state = AppState(
      phase: AuthPhase.signedIn,
      user: const User(id: 'mmmmmmmmmmmmmmmmmmmmmm', username: 'me'),
      contacts: const [Contact(id: 'aaaaaaaaaaaaaaaaaaaaaa', username: 'alice', state: ContactState.mutual)],
      groups: [
        group('p', GroupKindName.public, 'general', unread: 3),
        group('q', GroupKindName.private, 'design', unread: 1, mentioned: true),
        group('g', GroupKindName.groupDm, 'Weekend'),
        group('l', GroupKindName.groupDm, 'Old plans', membership: Membership.left),
        group('k', GroupKindName.private, 'Pinned one', pinned: true),
      ],
    );
    await tester.pumpWidget(ProviderScope(overrides: [appProvider.overrideWith(() => _App(state))], child: const MaterialApp(home: ChatListScreen())));
    await tester.pump();
    for (final key in ['section-pinned', 'section-channels', 'section-groups', 'section-direct']) {
      expect(find.byKey(Key(key)), findsOneWidget, reason: key);
    }
    double y(String text) => tester.getTopLeft(find.text(text)).dy;
    expect(y('Pinned one') < y('general'), isTrue, reason: 'pins come first');
    expect(y('general') < y('Weekend') && y('Weekend') < y('alice'), isTrue, reason: 'channels, then groups, then direct messages');
    expect(find.byKey(ValueKey('mention-${'q' * 22}')), findsOneWidget, reason: 'the @ badge where I was mentioned');
    expect(find.text('3'), findsOneWidget);
    expect(find.text('You left'), findsOneWidget);
  });
}
