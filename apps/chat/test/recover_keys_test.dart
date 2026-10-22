import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/app/app_controller.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/account_crypto.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/crypto/link_crypto.dart';
import 'package:private_chat/main.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
const account = Identity(dh: 'account-dh', sign: 'account-sign');

class MemoryTokens implements TokenStore {
  String? token = 'token';
  @override
  Future<String?> read() async => token;
  @override
  Future<void> write(String? value) async => token = value;
}

/// The shell with a locked key database; recovery itself is recorded, not run.
class LockedApp extends AppController {
  int recovered = 0;
  @override
  AppState build() => const AppState(phase: AuthPhase.signedIn, user: me, keysLocked: true);
  @override
  Future<void> restore() async {}
  @override
  Future<void> recoverKeys() async {
    recovered++;
    state = state.copyWith(keysLocked: false);
  }
}

class RecordingCrypto extends FakeChatCrypto {
  RecordingCrypto() : super(me: account);
  final List<String> opened = [], reset = [];
  @override
  Future<void> init(String dbPath) async {
    opened.add(dbPath);
    await super.init(dbPath);
  }

  @override
  Future<void> resetLocal(String dbPath) async {
    reset.add(dbPath);
    await super.resetLocal(dbPath);
  }
}

/// A locked key database (M6 §4): recovery resets the database this install opened and lands on the restore screen;
/// it never makes or uploads a key of its own, and never changes the device list.
void main() {
  sqfliteFfiInit();

  Future<(ProviderContainer, RecordingCrypto, List<String>)> start(Map<String, Object> prefs) async {
    SharedPreferences.setMockInitialValues(prefs);
    final devices = MemoryDevicePrefs();
    final device = await localDevice(devices, me.id);
    final writes = <String>[];
    final crypto = RecordingCrypto()..locked = true;
    final api = Api(
      baseUrl: 'http://127.0.0.1:9',
      clientName: 'android',
      client: MockClient((request) async {
        final path = request.url.path;
        if (request.method != 'GET') writes.add('${request.method} $path');
        final body = switch (path) {
          '/api/me' => {'user': {'id': me.id, 'username': me.username}},
          '/api/keys/count' => {'oneTimePreKeys': 10, 'signedPreKeyId': 1, 'identity': account.toJson()},
          '/api/devices/me' => {
            'userId': me.id,
            'identity': account.toJson(),
            'list': null,
            'devices': [
              {'id': device.deviceId, 'state': 'listed'},
            ],
          },
          '/api/devices/challenge' => {'challenge': 'c'},
          '/api/contacts' => {'contacts': <Object>[]},
          _ => <String, Object>{},
        };
        return http.Response(jsonEncode(body), 200);
      }),
    );
    final container = ProviderContainer(
      overrides: [
        apiProvider.overrideWithValue(api),
        cryptoProvider.overrideWithValue(crypto),
        groupCryptoProvider.overrideWithValue(FakeGroupCrypto(userId: me.id)),
        linkCryptoProvider.overrideWithValue(FakeLinkCrypto()),
        accountCryptoProvider.overrideWithValue(FakeAccountCrypto()),
        tokenStoreProvider.overrideWithValue(MemoryTokens()),
        devicePrefsProvider.overrideWithValue(() async => devices),
        storeOpenerProvider.overrideWithValue((_) => MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath)),
        pushEnabledProvider.overrideWithValue(false),
      ],
    );
    return (container, crypto, writes);
  }

  test('a linked install resets its own database, then restores: no new key, no list, no removals', () async {
    final (container, crypto, writes) = await start({'linked-core-v1:${me.id}': 'keys-link-dddd', 'linked-by-code-v1:${me.id}': true});
    final app = container.read(appProvider.notifier);
    await app.restore();
    expect(container.read(appProvider).keysLocked, isTrue);
    expect(crypto.opened, ['keys-link-dddd']);

    await app.recoverKeys();
    await pumpEventQueue();
    final state = container.read(appProvider);
    expect(crypto.reset, ['keys-link-dddd']);
    expect(crypto.opened.last, 'keys-link-dddd');
    expect((state.keysLocked, state.needsRestore), (false, true));
    expect((await SharedPreferences.getInstance()).getBool('linked-by-code-v1:${me.id}'), isNull);
    // Only binding the session: no key upload, no device list, no removal.
    expect(writes.where((w) => !w.startsWith('POST /api/devices/challenge') && !w.startsWith('POST /api/devices/announce')), isEmpty);
  });

  test('the primary install resets keys-<user>; listed but without the account key, it still restores', () async {
    final (container, crypto, writes) = await start({});
    final app = container.read(appProvider.notifier);
    await app.restore();
    await app.recoverKeys();
    await pumpEventQueue();
    expect(crypto.reset, ['keys-${me.id}']);
    expect(container.read(appProvider).needsRestore, isTrue);
    expect(writes.where((w) => w.contains('/api/keys') || w.contains('/api/devices/list') || w.contains('revoke')), isEmpty);
  });

  testWidgets('Recover on the banner opens its dialog on the router (the banner sits above it) and resets on confirm', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final controller = LockedApp();
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appProvider.overrideWith(() => controller),
          apiProvider.overrideWithValue(Api(baseUrl: 'http://127.0.0.1:9', client: MockClient((_) async => http.Response('{}', 200)), clientName: 'android')),
          pushEnabledProvider.overrideWithValue(false),
        ],
        child: const PrivateChatApp(),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('recover-keys')));
    await tester.pumpAndSettle();
    expect(find.text("Reset this device's keys?"), findsOneWidget);
    await tester.tap(find.text('Not now'));
    await tester.pumpAndSettle();
    expect(controller.recovered, 0);
    await tester.tap(find.byKey(const Key('recover-keys')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('recover-keys-confirm')));
    await tester.pumpAndSettle();
    expect(controller.recovered, 1);
    expect(find.byKey(const Key('recover-keys')), findsNothing);
  });
}
