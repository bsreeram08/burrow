import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/app/app_controller.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/crypto/account_crypto.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/messaging/backup.dart';
import 'package:private_chat/ui/account/backup_screen.dart';
import 'package:private_chat/ui/account/copy.dart';
import 'package:private_chat/ui/account/restore_screen.dart';
import 'package:private_chat/ui/chat_list_screen.dart';
import 'package:private_chat/ui/link/link_device_screen.dart';

import 'support/fake_backup.dart';

const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');

/// The app with its account parts replaced: the backup service talks to an in-memory server.
class TestApp extends AppController {
  TestApp(this.initial, {this.server, this.crypto});
  final AppState initial;
  final FakeBackupServer? server;
  final AccountCrypto? crypto;
  final List<Object?> calls = [];

  @override
  AppState build() => initial;

  @override
  Future<AccountBackup?> accountBackup() async {
    final s = server, c = crypto;
    if (s == null || c == null) return null;
    return AccountBackup(api: s.api(), crypto: c, me: me);
  }

  @override
  Future<void> backupChanged() async => state = state.copyWith(hasBackup: server?.record != null);

  @override
  Future<String> restoreFromBackup(Unlock unlock) async {
    calls.add(unlock.passphrase ?? unlock.words);
    if (unlock.passphrase != 'the right one, of course') throw const CryptoException("That passphrase doesn't open your backup.", code: 'auth');
    state = state.copyWith(needsRestore: false, restoredSafety: '12345 67890');
    return '12345 67890';
  }

  @override
  Future<void> startOver() async => calls.add('start over');

  @override
  Future<void> cancelKeyReset() async {
    calls.add('cancel reset');
    state = state.copyWith(clearKeyReset: true);
  }

  @override
  Future<void> removeAndRotate(String deviceId, {Unlock? unlock, bool alreadyRemoved = false}) async => calls.add((deviceId, unlock?.passphrase));
}

Widget app(TestApp controller, Widget home) => ProviderScope(
  overrides: [appProvider.overrideWith(() => controller), accountCryptoProvider.overrideWithValue(controller.crypto ?? FakeAccountCrypto())],
  child: MaterialApp(home: home),
);

AppState signedIn({bool? hasBackup, bool full = true}) =>
    AppState(phase: AuthPhase.signedIn, user: me, needsRestore: true, hasBackup: hasBackup, fullDevice: full);

void main() {
  setUp(() {});

  group('restore (M6 §4)', () {
    testWidgets('with a backup: passphrase, recovery key, link, and the small way out', (tester) async {
      await tester.pumpWidget(app(TestApp(signedIn(hasBackup: true)), const RestoreScreen()));
      expect(find.text('Use your account here.'), findsOneWidget);
      for (final key in ['restore-passphrase', 'restore-words', 'restore-link', 'restore-fresh']) {
        expect(find.byKey(Key(key)), findsOneWidget, reason: key);
      }
      expect(find.byKey(const Key('restore-no-backup')), findsNothing);
    });

    testWidgets('without a backup: only linking, and the line about turning it on', (tester) async {
      await tester.pumpWidget(app(TestApp(signedIn(hasBackup: false)), const RestoreScreen()));
      expect(find.byKey(const Key('restore-passphrase')), findsNothing);
      expect(find.byKey(const Key('restore-words')), findsNothing);
      expect(find.text('Turn on account backup on one of your devices to sign in without it next time.'), findsOneWidget);
      expect(find.byKey(const Key('restore-link')), findsOneWidget);
    });

    testWidgets("a wrong passphrase says so; the right one shows the safety number and that contacts needn't re-verify", (tester) async {
      final controller = TestApp(signedIn(hasBackup: true));
      await tester.pumpWidget(app(controller, const RestoreScreen()));
      await tester.tap(find.byKey(const Key('restore-passphrase')));
      await tester.pump();
      await tester.enterText(find.byKey(const Key('unlock-input')), 'not it');
      await tester.tap(find.byKey(const Key('unlock-submit')));
      await tester.pump();
      expect(find.text(passphraseDoesntOpen), findsOneWidget);
      await tester.enterText(find.byKey(const Key('unlock-input')), 'the right one, of course');
      await tester.tap(find.byKey(const Key('unlock-submit')));
      await tester.pump();
      expect(find.byKey(const Key('restore-safety')), findsOneWidget);
      expect(find.text(noReverify), findsOneWidget);
      expect(find.text('Safety number: 12345 67890'), findsOneWidget);
      await tester.tap(find.byKey(const Key('restore-done')));
      await tester.pump();
      expect(controller.state.restoredSafety, isNull);
    });

    testWidgets('the recovery key screen warns it is not a wallet seed', (tester) async {
      await tester.pumpWidget(app(TestApp(signedIn(hasBackup: true)), const RestoreScreen()));
      await tester.tap(find.byKey(const Key('restore-words')));
      await tester.pump();
      expect(find.text(walletWarning), findsOneWidget);
    });

    testWidgets('"I can\'t do any of these" starts over only after its warning', (tester) async {
      final controller = TestApp(signedIn(hasBackup: true));
      await tester.pumpWidget(app(controller, const RestoreScreen()));
      await tester.tap(find.byKey(const Key('restore-fresh')));
      await tester.pumpAndSettle();
      expect(find.text('Start over on this device?'), findsOneWidget);
      expect(controller.calls, isEmpty);
      await tester.tap(find.byKey(const Key('restore-fresh-confirm')));
      await tester.pumpAndSettle();
      expect(controller.calls, ['start over']);
    });
  });

  group('backup setup (M6 §3.4)', () {
    testWidgets('the suggested passphrase, 24 words shown once, three typed back, then the upload', (tester) async {
      tester.view.physicalSize = const Size(900, 2400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final server = FakeBackupServer(), account = signingAccount();
      final controller = TestApp(signedIn(hasBackup: false).copyWith(needsRestore: false), server: server, crypto: account.crypto);
      await tester.pumpWidget(app(controller, const AccountBackupScreen()));
      await tester.pump();
      expect(find.byKey(const Key('backup-suggested')), findsOneWidget);
      await tester.tap(find.byKey(const Key('backup-use-suggested')));
      await tester.pump();
      await tester.pump();
      expect(find.byKey(const Key('recovery-words')), findsOneWidget);
      expect(find.text(walletWarning), findsOneWidget);
      expect(server.record, isNull, reason: 'nothing uploaded yet');
      final words = [for (var i = 0; i < 24; i++) (tester.widget<Text>(find.byKey(Key('recovery-word-$i'))).data ?? '').split(' ').last];
      expect(words, hasLength(24));
      await tester.tap(find.byKey(const Key('backup-words-next')));
      await tester.pump();
      final labels = [for (var i = 0; i < 3; i++) tester.widget<TextField>(find.byKey(Key('confirm-word-$i'))).decoration!.labelText!];
      final positions = [for (final l in labels) int.parse(l.split(' ').last) - 1];
      expect(positions, orderedEquals([...positions]..sort()), reason: 'ascending');
      for (var i = 0; i < 3; i++) {
        await tester.enterText(find.byKey(Key('confirm-word-$i')), 'wrong');
      }
      await tester.tap(find.byKey(const Key('confirm-words')));
      await tester.pump();
      expect(find.text(wordMismatch(positions.first + 1)), findsOneWidget);
      expect(server.record, isNull);
      for (var i = 0; i < 3; i++) {
        // The first four letters are enough, any case.
        final w = words[positions[i]];
        await tester.enterText(find.byKey(Key('confirm-word-$i')), i == 0 && w.length >= 4 ? w.substring(0, 4).toUpperCase() : w);
      }
      await tester.tap(find.byKey(const Key('confirm-words')));
      await tester.pump();
      await tester.pump();
      expect(server.record?['epoch'], 1);
      expect(find.byKey(const Key('backup-done')), findsOneWidget);
    });

    testWidgets('an own passphrase must be long enough and typed twice the same', (tester) async {
      final controller = TestApp(signedIn(hasBackup: false).copyWith(needsRestore: false), server: FakeBackupServer(), crypto: signingAccount().crypto);
      await tester.pumpWidget(app(controller, const AccountBackupScreen()));
      await tester.pump();
      await tester.tap(find.byKey(const Key('backup-own')));
      await tester.pump();
      await tester.enterText(find.byKey(const Key('backup-own-1')), 'too short');
      await tester.enterText(find.byKey(const Key('backup-own-2')), 'too short');
      await tester.tap(find.byKey(const Key('backup-own-submit')));
      await tester.pump();
      expect(find.text(tooShort), findsOneWidget);
      await tester.enterText(find.byKey(const Key('backup-own-1')), 'a long enough passphrase');
      await tester.enterText(find.byKey(const Key('backup-own-2')), 'a different passphrase!');
      await tester.tap(find.byKey(const Key('backup-own-submit')));
      await tester.pump();
      expect(find.text(noMatch), findsOneWidget);
    });

    testWidgets('changing it asks for the current passphrase first; a wrong one changes nothing', (tester) async {
      final server = FakeBackupServer(), account = signingAccount();
      final controller = TestApp(signedIn(hasBackup: true).copyWith(needsRestore: false), server: server, crypto: account.crypto);
      final backup = (await controller.accountBackup())!;
      await tester.runAsync(() async => backup.commit(await backup.prepareTurnOn('first passphrase here')));
      await tester.pumpWidget(app(controller, const AccountBackupScreen()));
      await tester.tap(find.byKey(const Key('backup-change-passphrase')));
      await tester.pump();
      await tester.enterText(find.byKey(const Key('backup-new-1')), 'second passphrase here');
      await tester.enterText(find.byKey(const Key('backup-new-2')), 'second passphrase here');
      await tester.tap(find.byKey(const Key('manage-submit')));
      await tester.pump();
      expect(find.text(enterCurrent), findsOneWidget);
      await tester.enterText(find.byKey(const Key('current-secret')), 'not the first one');
      await tester.runAsync(() async {
        await tester.tap(find.byKey(const Key('manage-submit')));
        await Future<void>.delayed(const Duration(milliseconds: 50));
      });
      await tester.pump();
      expect(find.text(notCurrent), findsOneWidget);
      expect(server.record?['epoch'], 1);
      await tester.enterText(find.byKey(const Key('current-secret')), 'first passphrase here');
      await tester.runAsync(() async {
        await tester.tap(find.byKey(const Key('manage-submit')));
        await Future<void>.delayed(const Duration(milliseconds: 50));
      });
      await tester.pump();
      expect(server.record?['epoch'], 2);
      expect(find.byKey(const Key('manage-done')), findsOneWidget);
    });
  });

  group('removing a device (M6 §6.2)', () {
    Widget host(TestApp controller) => app(
      controller,
      Builder(
        builder: (context) => Consumer(builder: (context, ref, _) => TextButton(onPressed: () => confirmRemove(context, ref, 'd' * 22, 'Work laptop'), child: const Text('go'))),
      ),
    );

    testWidgets('on a device with the key and a backup: change the key, with the passphrase', (tester) async {
      final controller = TestApp(signedIn(hasBackup: true).copyWith(needsRestore: false));
      await tester.pumpWidget(host(controller));
      await tester.tap(find.text('go'));
      await tester.pumpAndSettle();
      expect(find.text('Remove Work laptop and change your account key?'), findsOneWidget);
      expect(find.byKey(const Key('remove-change-passphrase')), findsOneWidget);
      await tester.tap(find.byKey(const Key('revoke-confirm')));
      await tester.pumpAndSettle();
      expect(controller.calls, isEmpty, reason: 'not without the passphrase');
      await tester.enterText(find.byKey(const Key('remove-secret')), 'my passphrase');
      await tester.tap(find.byKey(const Key('revoke-confirm')));
      await tester.pumpAndSettle();
      expect(controller.calls, [('d' * 22, 'my passphrase')]);
    });

    testWidgets('on a device without the key and an account without a backup: only removing, nothing to type', (tester) async {
      final controller = TestApp(signedIn(hasBackup: false, full: false).copyWith(needsRestore: false));
      await tester.pumpWidget(host(controller));
      await tester.tap(find.text('go'));
      await tester.pumpAndSettle();
      expect(find.text('Remove Work laptop?'), findsOneWidget);
      expect(find.byKey(const Key('remove-secret')), findsNothing);
      await tester.tap(find.byKey(const Key('revoke-confirm')));
      await tester.pumpAndSettle();
      expect(controller.calls, [('d' * 22, null)]);
    });
  });

  group('removal needs the passphrase and resets wait a week (M6 §6.3, §6.5)', () {
    testWidgets('a device without the key still asks for the passphrase when there is a backup', (tester) async {
      final controller = TestApp(signedIn(hasBackup: true, full: false).copyWith(needsRestore: false));
      await tester.pumpWidget(app(
        controller,
        Builder(builder: (context) => Consumer(builder: (context, ref, _) => TextButton(onPressed: () => confirmRemove(context, ref, 'd' * 22, 'Work laptop'), child: const Text('go')))),
      ));
      await tester.tap(find.text('go'));
      await tester.pumpAndSettle();
      expect(find.text('Remove Work laptop?'), findsOneWidget);
      expect(find.byKey(const Key('remove-secret')), findsOneWidget);
      await tester.tap(find.byKey(const Key('revoke-confirm')));
      await tester.pump();
      expect(find.text(enterCurrent), findsOneWidget);
      expect(controller.calls, isEmpty);
    });

    testWidgets("the device that asked for a reset waits, saying when it goes ahead", (tester) async {
      final reset = (platform: 'macos', at: 1, executeAfter: DateTime(2030, 1, 8).millisecondsSinceEpoch, mine: true);
      await tester.pumpWidget(app(TestApp(signedIn(hasBackup: true).copyWith(keyReset: reset)), const RestoreScreen()));
      expect(find.text(resetWaiting), findsOneWidget);
      expect(find.textContaining('2030-01-08'), findsOneWidget);
      expect(find.byKey(const Key('restore-passphrase')), findsNothing);
    });

    testWidgets("the user's other devices see who asked and can cancel it", (tester) async {
      tester.view.physicalSize = const Size(900, 2000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final reset = (platform: 'web', at: DateTime(2030, 1, 1).millisecondsSinceEpoch, executeAfter: 2, mine: false);
      final controller = TestApp(AppState(phase: AuthPhase.signedIn, user: me, keyReset: reset));
      await tester.pumpWidget(app(controller, const ChatListScreen()));
      await tester.pump();
      expect(find.text(resetBanner('Web browser', reset.at)), findsOneWidget);
      await tester.tap(find.byKey(const Key('reset-cancel')));
      await tester.pump();
      expect(controller.calls, ['cancel reset']);
    });
  });
}
