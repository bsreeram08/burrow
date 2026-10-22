import 'dart:typed_data';
import 'dart:convert';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/account_crypto.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/crypto/link_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/messaging/succession.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// Rekey and following a rotation (docs/m6-account-key.md §5, §6.2 step 3).
void main() {
  sqfliteFfiInit();
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');

  /// A served view of our own list, signed by [key], with labels sealed under [metaKey].
  Map<String, Object?> view(ed.KeyPair key, List<({String id, String platform, String? via})> devices, {Map<String, Object?> extra = const {}, Uint8List? metaKey}) {
    final sealKey = metaKey ?? Uint8List(32);
    final sorted = devices.toList()..sort((a, b) => a.id.compareTo(b.id));
    final list = {
      'v': 1, 'userId': me.id, 'version': 1, 'prevHash': '',
      'devices': [for (final d in sorted) {'deviceId': d.id, 'addedAt': 1, 'meta': sealMeta(sealKey, me.id, d.id, label: 'L', platform: d.platform, via: d.via)}],
    };
    return {
      'list': list,
      'signature': b64(ed.sign(key.privateKey, listBytes(list))),
      'certs': {for (final d in list['devices']! as List) (d as Map)['deviceId']: b64(ed.sign(key.privateKey, certBytes(me.id, d)))},
      ...extra,
    };
  }

  test('a device with the key answers only devices of its verified list, never code-linked ones, with the platform from their label', () async {
    final aik = ed.generateKey();
    final identity = Identity(dh: b64(List.filled(32, 2)), sign: b64(aik.publicKey.bytes));
    final prefs = MemoryDevicePrefs();
    final self = await localDevice(prefs, me.id);
    final a = 'a' * 22, b = 'b' * 22, c = 'c' * 22;
    final answered = <String, String>{};
    final chat = FakeChatCrypto(me: identity);
    final metaKey = deviceMetaKey(await chat.deviceMetaSignature(me.id));
    final client = MockClient((request) async {
      final path = request.url.path;
      if (path == '/api/devices/me') {
        return http.Response(jsonEncode(view(aik, [(id: self.deviceId, platform: 'ios', via: null), (id: a, platform: 'web', via: null), (id: b, platform: 'web', via: 'code')], metaKey: metaKey)), 200);
      }
      if (path == '/api/devices/rekey' && request.method == 'GET') {
        return http.Response(jsonEncode({'requests': [for (final id in [a, b, c, self.deviceId]) {'deviceId': id, 'platform': 'web', 'eph': 'eph-$id', 'leafSigKey': 'leaf-$id', 'signature': 'sig-$id'}]}), 200);
      }
      if (path.startsWith('/api/devices/rekey/')) answered[path.split('/').last] = (jsonDecode(request.body) as Map)['box'] as String;
      return http.Response('{}', 201);
    });
    final api = Api(baseUrl: 'https://calls.example', clientName: 'ios', client: client)..token = 't';
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final messenger = Messenger(api: api, crypto: chat, store: store, me: me, contactById: (_) => null, mutualContacts: () => [], ack: (_) {}, devices: prefs);
    final rekey = Rekey(
      api: api, account: FakeAccountCrypto(held: identity), link: FakeLinkCrypto(identity: identity), store: store, me: me, platform: 'ios',
      device: () async => self, messenger: messenger, updateLeaf: (_) async {},
    );
    expect(await rekey.answer(), 1);
    expect(answered.keys, [a], reason: 'b was linked by code, c is not in our list, and never this device');
    await store.close();
  });

  test('without the key: ask, then open the answer, commit the new leaf in every group, and drop the request', () async {
    final identity = Identity(dh: b64(List.filled(32, 2)), sign: b64(List.filled(32, 3)));
    final prefs = MemoryDevicePrefs();
    final self = await localDevice(prefs, me.id);
    final full = FakeAccountCrypto(held: identity), companion = FakeAccountCrypto();
    Map<String, dynamic>? asked;
    String? box;
    var dropped = false;
    final client = MockClient((request) async {
      final path = request.url.path;
      if (path == '/api/devices/rekey' && request.method == 'PUT') asked = jsonDecode(request.body) as Map<String, dynamic>;
      if (path == '/api/devices/rekey' && request.method == 'DELETE') dropped = true;
      if (path == '/api/devices/rekey/mine') return http.Response(jsonEncode({'box': box}), 200);
      return http.Response('{}', 201);
    });
    final api = Api(baseUrl: 'https://calls.example', clientName: 'ios', client: client)..token = 't';
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    await store.putGroup(GroupConversation(id: 'g' * 22, kind: GroupKindName.private, createdAt: 1));
    final committed = <String>[];
    final link = FakeLinkCrypto()..companion = (userId: me.id, identity: identity, certJson: '{}');
    final rekey = Rekey(
      api: api, account: companion, link: link, store: store, me: me, platform: 'ios', device: () async => self,
      messenger: Messenger(api: api, crypto: FakeChatCrypto(), store: store, me: me, contactById: (_) => null, mutualContacts: () => [], ack: (_) {}, devices: prefs),
      updateLeaf: (id) async => committed.add(id),
    );
    await rekey.ask();
    expect(asked?['eph'], 'eph-${self.deviceId}');
    expect(await rekey.take(), isFalse, reason: 'no answer yet');
    final request = (eph: asked!['eph'] as String, leafSigKey: asked!['leafSigKey'] as String, signature: asked!['signature'] as String);
    box = await full.rekeyAnswer(me.id, deviceId: self.deviceId, platform: 'ios', request: request, groups: const [], now: 1);
    expect(await rekey.take(), isTrue);
    expect(companion.held, identity);
    expect(committed, ['g' * 22]);
    expect(dropped, isTrue);
    await store.close();
  });

  group('following a key change another device made (§6.2 step 3)', () {
    /// Our pin names this device, the rotator and a lost device (labelled "Old phone"); the server serves the new key,
    /// its record, and list v1 naming the rotator, this device unless [namesMe], and the lost one when [keepsLost].
    Future<(Object?, FakeLinkCrypto, OwnSuccession)> follow({bool namesMe = true, bool keepsLost = false, bool listUp = true}) async {
      final oldKey = ed.generateKey(), newKey = ed.generateKey();
      final old = Identity(dh: b64(List.filled(32, 2)), sign: b64(oldKey.publicKey.bytes));
      final next = Identity(dh: b64(List.filled(32, 9)), sign: b64(newKey.publicKey.bytes));
      final prefs = MemoryDevicePrefs();
      final self = await localDevice(prefs, me.id);
      final rotator = 'p' * 22, lost = 'l' * 22;
      prefs.setPin(me.id, me.id, DevicePin(aik: old.sign, version: 3, hash: b64(List.filled(32, 1)), devices: [self.deviceId, rotator, lost], revoked: const [], labels: {lost: 'Old phone'}));
      final record = {'v': 1, 'userId': me.id, 'oldSign': old.sign, 'newSign': next.sign, 'newDh': next.dh, 'at': 5};
      final signature = b64(ed.sign(oldKey.privateKey, successionBytes(me.id, old.sign, next.sign, next.dh, 5)));
      // Before list v1 is up the server still serves the old key's list.
      final served = view(listUp ? newKey : oldKey, [
        (id: rotator, platform: 'macos', via: null),
        if (namesMe) (id: self.deviceId, platform: 'ios', via: null),
        if (keepsLost) (id: lost, platform: 'web', via: null),
      ], extra: {
        'identity': next.toJson(),
        'succession': [{...record, 'signature': signature}],
        // Revoked rows are never served: nothing here says whether the lost device was the user's own removal.
        'devices': [
          {'id': rotator, 'state': 'listed', 'platform': 'macos', 'primary': true},
          {'id': self.deviceId, 'state': 'listed', 'platform': 'ios'},
        ],
      });
      final api = Api(baseUrl: 'https://calls.example', clientName: 'ios', client: MockClient((_) async => http.Response(jsonEncode(served), 200)))..token = 't';
      final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
      final link = FakeLinkCrypto(identity: old);
      final own = OwnSuccession(
        api: api, link: link, groups: FakeGroupCrypto(userId: me.id), store: store, updateLeaf: (_) async {}, me: me, platform: 'ios',
        chat: FakeChatCrypto(me: old), devices: prefs, device: () async => self,
      );
      Object? outcome;
      try {
        outcome = await own.follow();
      } catch (e) {
        outcome = e;
      }
      await store.close();
      return (outcome, link, own);
    }

    test('followed quietly when the new list keeps every device this one knew', () async {
      final (outcome, link, own) = await follow(keepsLost: true);
      expect(outcome, isTrue);
      expect(link.adopted, hasLength(1));
      expect(link.identity, isNull, reason: 'it waits for the new key now');
      expect(own.notice, isNull);
    });

    test('followed, with a notice naming who changed it and what it removed, when it drops a device this one knew', () async {
      final (outcome, link, own) = await follow();
      expect(outcome, isTrue);
      expect(link.adopted, hasLength(1));
      expect(own.notice, 'Your account key was changed from Mac app, which removed Old phone. If this wasn’t you, take your account back.');
    });

    test('not followed when the new list drops this device: the same words, and nothing adopted', () async {
      final (outcome, link, _) = await follow(namesMe: false);
      expect(outcome, isA<RotationRefused>().having((e) => e.message, 'message', 'Your account key was changed from Mac app, which removed this device and Old phone. If this wasn’t you, take your account back.'));
      expect(link.adopted, isEmpty);
    });

    test('nothing yet while the new key\'s list is not up', () async {
      final (outcome, link, _) = await follow(listUp: false);
      expect(outcome, isFalse);
      expect(link.adopted, isEmpty);
    });
  });
}
