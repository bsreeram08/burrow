import 'dart:async';
import 'dart:convert';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/crypto/link_crypto.dart';
import 'package:private_chat/messaging/linking.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/messaging/succession.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// The old primary signs a real (Ed25519) succession record; the fake core holds its key pair.
class _SigningLink extends FakeLinkCrypto {
  _SigningLink(this.pair) : super(identity: Identity(dh: b64(List.filled(32, 5)), sign: b64(pair.publicKey.bytes)));
  final ed.KeyPair pair;
  @override
  Future<String> signSuccession({required String userId, required String publishedSign, required Identity newIdentity, required int at}) async {
    final record = {'v': 1, 'userId': userId, 'oldSign': publishedSign, 'newSign': newIdentity.sign, 'newDh': newIdentity.dh, 'at': at};
    return jsonEncode({...record, 'signature': b64(ed.sign(pair.privateKey, successionBytes(userId, publishedSign, newIdentity.sign, newIdentity.dh, at)))});
  }
}

/// The linked device's core: one key store for 1:1 and link calls, as in chatcore.
class _TakingLink extends FakeLinkCrypto {
  _TakingLink(this.chat);
  final FakeChatCrypto chat;
  @override
  Future<Identity> successionStart() async => Identity(dh: b64(List.filled(32, 7)), sign: b64(List.filled(32, 8)));
  @override
  Future<Identity> successionComplete(String recordJson, String signature) async {
    final r = jsonDecode(recordJson) as Map;
    identity = Identity(dh: r['newDh'] as String, sign: r['newSign'] as String);
    companion = null;
    chat.me = identity!;
    return identity!;
  }
}

/// Primary transfer (docs/m5-linking.md §5.2) between two app devices over a fake relay: nothing is signed
/// before the codes are compared; the new primary publishes the record, its keys and list v1 naming the old
/// primary, and certifies the old primary's leaf; the old primary steps down only once the new key is served.
void main() {
  sqfliteFfiInit();
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
  final p0Device = 'p' * 22, linkId = 'L' * 22, claim = b64(List.filled(32, 3));

  /// The served list, signed (with per-device certificates) by [key].
  Map<String, Object?> signed(ed.KeyPair key, List<String> ids) {
    final list = {'v': 1, 'userId': me.id, 'version': 1, 'prevHash': '', 'devices': [for (final (i, id) in (ids.toList()..sort()).indexed) {'deviceId': id, 'addedAt': i + 1, 'meta': ''}]};
    return {
      'list': list,
      'signature': b64(ed.sign(key.privateKey, listBytes(list))),
      'certs': {for (final d in list['devices']! as List) (d as Map)['deviceId']: b64(ed.sign(key.privateKey, certBytes(me.id, d)))},
    };
  }

  for (final forged in [false, true]) {
  test(forged
      ? "a served list our primary didn't sign stops the take-over before anything is published"
      : 'hand over: request, compare, record, keys, list v1 (only our signed list), demote, step down', () async {
    final aik = ed.generateKey(), other = ed.generateKey();
    final p0Link = _SigningLink(aik);
    final p0Chat = FakeChatCrypto(me: p0Link.identity!);
    final nChat = FakeChatCrypto(me: const Identity(dh: 'unused', sign: 'unused'));
    final nLink = _TakingLink(nChat)..companion = (userId: me.id, identity: p0Link.identity!, certJson: '{}');
    final nGroups = FakeGroupCrypto(userId: me.id), p0Groups = FakeGroupCrypto(userId: me.id, deviceId: p0Device);
    final n2p = <String>[], p2n = <String>[];
    var state = <String, dynamic>{'state': 'waiting'};
    Map<String, dynamic>? succession, published;
    Map<String, dynamic> served = p0Link.identity!.toJson();
    late String nDevice;

    MockClient client(bool isN) => MockClient((request) async {
      final path = request.url.path, method = request.method;
      http.Response ok(Object body, [int status = 200]) => http.Response(jsonEncode(body), status);
      final body = request.body.isEmpty ? const <String, dynamic>{} : jsonDecode(request.body) as Map<String, dynamic>;
      if (path == '/api/link/start') {
        expect(body['purpose'], 'transfer');
        nDevice = body['deviceId'] as String;
        return ok({'linkId': linkId, 'claim': claim, 'expiresAt': 1}, 201);
      }
      if (path == '/api/link/$linkId/offer') {
        state = {'state': 'offered', 'eph': body['eph'], 'offerDeviceId': p0Device};
        return ok({'deviceId': nDevice, 'platform': 'macos', 'purpose': 'transfer', 'mode': 'qr'}, 201);
      }
      if (path == '/api/link/$linkId' && method == 'GET') return ok(state);
      if (path == '/api/link/$linkId/messages' && method == 'POST') {
        (isN ? n2p : p2n).add(body['data'] as String);
        return ok({'seq': (isN ? n2p : p2n).length}, 201);
      }
      if (path == '/api/link/$linkId/messages') {
        final from = isN ? p2n : n2p, after = int.parse(request.url.queryParameters['after'] ?? '0');
        return ok({'messages': [for (var i = after; i < from.length; i++) {'seq': i + 1, 'data': from[i]}]});
      }
      if (path == '/api/devices/me') {
        return ok({
          'userId': me.id,
          'identity': served,
          ...signed(forged ? other : aik, [p0Device, nDevice]),
          // The server also shows a device our list never named: it must not be signed into the new list.
          'devices': [{'id': p0Device, 'state': 'listed', 'platform': 'ios', 'primary': true}, {'id': nDevice, 'state': 'listed', 'platform': 'macos'}, {'id': 'x' * 22, 'state': 'listed', 'platform': 'web'}],
        });
      }
      if (path == '/api/devices/succession') {
        expect(published, isNull, reason: 'the record goes before the keys');
        succession = body;
        return ok({'seq': 1}, 201);
      }
      if (path == '/api/keys' && method == 'PUT') {
        expect(succession, isNotNull, reason: 'keys only after the record');
        served = (body['identity'] as Map).cast<String, dynamic>();
        return ok({});
      }
      if (path == '/api/keys/count') return ok({'oneTimePreKeys': 0, 'signedPreKeyId': null, 'identity': served});
      if (path == '/api/devices/list') {
        published = body;
        return ok({'version': 1});
      }
      return ok({'error': 'nope'}, 404);
    });

    final nApi = Api(baseUrl: 'https://calls.example', client: client(true), clientName: 'macos')..token = 'n';
    final p0Api = Api(baseUrl: 'https://calls.example', client: client(false), clientName: 'ios')..token = 'p';
    final nStore = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final p0Store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final nPrefs = MemoryDevicePrefs();
    final nMessenger = Messenger(api: nApi, crypto: nChat, store: nStore, me: me, contactById: (_) => null, mutualContacts: () => [], ack: (_) {}, devices: nPrefs)..companion = true;
    final p0Messenger = Messenger(api: p0Api, crypto: p0Chat, store: p0Store, me: me, contactById: (_) => null, mutualContacts: () => [], ack: (_) {});
    final p0Ctx = LinkContext(api: p0Api, crypto: p0Chat, link: p0Link, messenger: p0Messenger, store: p0Store, contacts: () => [], wait: (_) async => Future<void>.delayed(const Duration(milliseconds: 5)));

    final take = await TakeOver.start(api: nApi, link: nLink, groups: nGroups, device: await nMessenger.device(), platform: 'macos', wait: (_) => Future<void>.delayed(const Duration(milliseconds: 5)));
    final offered = take.waitOffer();
    final hand = await HandOver.fromQr(p0Ctx, p0Groups, take.qr);
    expect(await offered, hand.code, reason: 'both screens show the same digits');
    final request = await hand.waitRequest();
    expect(request.leafSigKey, await nGroups.deviceLeaf());
    expect(succession, isNull, reason: 'nothing signed before the user confirms');

    if (forged) {
      unawaited(hand.approve(timeout: const Duration(milliseconds: 300)).then((_) {}, onError: (_) {}));
      await expectLater(take.run(nMessenger, platform: 'macos'), throwsA(isA<StoreException>()));
      expect((succession, published, served['sign']), (null, null, p0Link.identity!.sign), reason: 'no record, keys or list');
      expect(nMessenger.companion, isTrue);
      await nStore.close();
      await p0Store.close();
      return;
    }
    await Future.wait([hand.approve(), take.run(nMessenger, platform: 'macos')], eagerError: true);

    // N: record, then keys, then list v1 under the new key naming the old primary; its own leaf re-signed.
    expect((succession!['record'] as Map)['newSign'], request.identity.sign);
    expect(served['sign'], request.identity.sign);
    final list = published!['list'] as Map;
    expect((list['version'], list['prevHash']), (1, ''));
    expect({for (final d in list['devices'] as List) d['deviceId']}, {p0Device, nDevice});
    expect(nGroups.recertified, 1);
    expect(nMessenger.companion, isFalse);
    // P0: a linked device of the new key now, with its leaf certified under it.
    expect(p0Link.identity, isNull);
    expect(p0Link.companion?.identity, request.identity);
    final cert = jsonDecode(p0Link.companion!.certJson) as Map;
    expect((cert['deviceId'], cert['leafSigKey'], cert['aikSign']), (p0Device, await p0Groups.deviceLeaf(), request.identity.sign));
    await nStore.close();
    await p0Store.close();
  });
  }

  test('a linked device follows its account to a new key only along a valid chain, then asks for a certificate', () async {
    final aik = ed.generateKey();
    final old = Identity(dh: b64(List.filled(32, 5)), sign: b64(aik.publicKey.bytes));
    final next = Identity(dh: b64(List.filled(32, 7)), sign: b64(List.filled(32, 8)));
    final record = {'v': 1, 'userId': me.id, 'oldSign': old.sign, 'newSign': next.sign, 'newDh': next.dh, 'at': 5};
    var chain = [{...record, 'signature': b64(ed.sign(aik.privateKey, successionBytes(me.id, old.sign, next.sign, next.dh, 5)))}];
    final asked = <Map<String, dynamic>>[];
    final api = Api(
      baseUrl: 'https://calls.example',
      clientName: 'macos',
      client: MockClient((request) async {
        if (request.url.path == '/api/devices/me') return http.Response(jsonEncode({'identity': next.toJson(), 'succession': chain}), 200);
        if (request.url.path == '/api/devices/recert' && request.method == 'PUT') asked.add(jsonDecode(request.body) as Map<String, dynamic>);
        return http.Response('{}', 201);
      }),
    )..token = 't';
    final link = FakeLinkCrypto()..companion = (userId: me.id, identity: old, certJson: '{}');
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final groups = FakeGroupCrypto(userId: me.id);
    OwnSuccession own() => OwnSuccession(api: api, link: link, groups: groups, store: store, updateLeaf: (_) async {}, me: me, platform: 'macos');

    // A served key with a forged chain moves nothing.
    chain = [{...chain.single, 'signature': b64(List.filled(64, 1))}];
    await expectLater(own().follow(), throwsA(isA<StoreException>()));
    expect(link.adopted, isEmpty);

    chain = [{...record, 'signature': b64(ed.sign(aik.privateKey, successionBytes(me.id, old.sign, next.sign, next.dh, 5)))}];
    expect(await own().follow(), isTrue);
    expect(link.companion?.identity, next);
    expect(asked.single['leafSigKey'], await groups.deviceLeaf());
    expect(await own().follow(), isFalse, reason: 'already there');
    await store.close();
  });

  test('the new primary certifies only a device of its verified list (not itself) whose leaf a group holds, with the platform from its sealed label', () async {
    final aik = ed.generateKey();
    final chat = FakeChatCrypto(me: Identity(dh: b64(List.filled(32, 2)), sign: b64(aik.publicKey.bytes)));
    final prefs = MemoryDevicePrefs();
    final self = await localDevice(prefs, me.id);
    final metaKey = deviceMetaKey(await chat.deviceMetaSignature(me.id));
    final a = 'a' * 22, b = 'b' * 22, c = 'c' * 22;
    final ids = [a, b, self.deviceId]..sort();
    final list = {
      'v': 1, 'userId': me.id, 'version': 1, 'prevHash': '',
      'devices': [for (final id in ids) {'deviceId': id, 'addedAt': 1, 'meta': sealMeta(metaKey, me.id, id, label: 'L', platform: id == a ? 'web' : 'macos')}],
    };
    final view = {
      'identity': chat.me.toJson(),
      'list': list,
      'signature': b64(ed.sign(aik.privateKey, listBytes(list))),
      'certs': {for (final d in list['devices']! as List) (d as Map)['deviceId']: b64(ed.sign(aik.privateKey, certBytes(me.id, d)))},
    };
    final answered = <String, String>{};
    final api = Api(
      baseUrl: 'https://calls.example',
      clientName: 'ios',
      client: MockClient((request) async {
        final path = request.url.path;
        if (path == '/api/devices/me') return http.Response(jsonEncode(view), 200);
        if (path == '/api/devices/recert' && request.method == 'GET') {
          return http.Response(jsonEncode({'requests': [
            for (final id in [a, b, c, self.deviceId]) {'deviceId': id, 'platform': 'ios', 'leafSigKey': 'K' * 43},
          ]}), 200);
        }
        if (path.startsWith('/api/devices/recert/')) answered[path.split('/').last] = (jsonDecode(request.body) as Map)['cert'] as String;
        return http.Response('{}', 201);
      }),
    )..token = 't';
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    // Groups hold the leaf for a, c (not in our list) and this device; not for b.
    final groups = FakeGroupCrypto(userId: me.id)..knownLeaves.addAll(['$a:${'K' * 43}', '$c:${'K' * 43}', '${self.deviceId}:${'K' * 43}']);
    final own = OwnSuccession(
      api: api, link: FakeLinkCrypto(identity: chat.me), groups: groups, store: store, updateLeaf: (_) async {}, me: me, platform: 'ios',
      chat: chat, devices: prefs, device: () async => self,
    );
    expect(await own.answerRecerts(), 1);
    expect(answered.keys, [a], reason: 'b: no group holds that leaf; c: not in our signed list; never this device');
    final cert = jsonDecode(answered[a]!) as Map;
    expect((cert['leafSigKey'], cert['platform']), ('K' * 43, 'web'), reason: "the platform from a's sealed label, not the request");
    await store.close();
  });

  test('recovery: the new key\'s first list names only this device, whatever the server lists', () async {
    Map<String, dynamic>? published;
    final api = Api(
      baseUrl: 'https://calls.example',
      clientName: 'ios',
      client: MockClient((request) async {
        if (request.url.path == '/api/devices/list') published = jsonDecode(request.body) as Map<String, dynamic>;
        if (request.url.path == '/api/devices/me') {
          return http.Response(jsonEncode({'list': {'v': 1, 'userId': me.id, 'version': 9, 'prevHash': '', 'devices': [{'deviceId': 'o' * 22, 'addedAt': 1, 'meta': ''}]}, 'devices': [{'id': 'o' * 22, 'state': 'listed'}]}), 200);
        }
        return http.Response('{}', 200);
      }),
    )..token = 't';
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final messenger = Messenger(api: api, crypto: FakeChatCrypto(), store: store, me: me, contactById: (_) => null, mutualContacts: () => [], ack: (_) {});
    await messenger.publishNewChain(const []);
    final list = published!['list'] as Map;
    expect(list['version'], 1);
    expect([for (final d in list['devices'] as List) d['deviceId']], [(await messenger.device()).deviceId]);
    await store.close();
  });
}
