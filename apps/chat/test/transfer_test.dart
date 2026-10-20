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

  /// Two app devices of one account over a fake relay and server: P0 (the primary) and N (a linked device).
  /// [fail] makes one request of N's fail as a lost connection (a crash at that step).
  Future<_Rig> rig({bool forged = false}) async {
    final r = _Rig();
    final aik = ed.generateKey(), other = ed.generateKey();
    r.p0Link = _SigningLink(aik);
    final p0Chat = FakeChatCrypto(me: r.p0Link.identity!);
    r.nChat = FakeChatCrypto(me: const Identity(dh: 'unused', sign: 'unused'));
    r.nLink = _TakingLink(r.nChat)..companion = (userId: me.id, identity: r.p0Link.identity!, certJson: '{}');
    r.nGroups = FakeGroupCrypto(userId: me.id);
    r.p0Groups = FakeGroupCrypto(userId: me.id, deviceId: p0Device);
    final n2p = <String>[], p2n = <String>[];
    var state = <String, dynamic>{'state': 'waiting'};
    r.served = r.p0Link.identity!.toJson();
    late String nDevice;

    MockClient client(bool isN) => MockClient((request) async {
      final path = request.url.path, method = request.method;
      if (isN && (r.fail?.call(method, path) ?? false)) {
        r.fail = null;
        throw http.ClientException('connection lost');
      }
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
          'identity': r.served,
          ...signed(forged ? other : aik, [p0Device, nDevice]),
          if (r.succession != null) 'succession': [{...(r.succession!['record'] as Map), 'signature': r.succession!['signature']}],
          // The server also shows a device our list never named: it must not be signed into the new list.
          'devices': [{'id': p0Device, 'state': 'listed', 'platform': 'ios', 'primary': true}, {'id': nDevice, 'state': 'listed', 'platform': 'macos'}, {'id': 'x' * 22, 'state': 'listed', 'platform': 'web'}],
        });
      }
      if (path == '/api/devices/succession') {
        expect(r.published, isNull, reason: 'the record goes before the keys');
        r.succession = body;
        r.records++;
        return ok({'seq': 1}, 201);
      }
      if (path == '/api/keys' && method == 'PUT') {
        expect(r.succession, isNotNull, reason: 'keys only after the record');
        r.served = (body['identity'] as Map).cast<String, dynamic>();
        return ok({});
      }
      if (path == '/api/keys/count') return ok({'oneTimePreKeys': 0, 'signedPreKeyId': null, 'identity': r.served});
      if (path == '/api/devices/list') {
        r.published = body;
        r.lists++;
        return ok({'version': 1});
      }
      return ok({'error': 'nope'}, 404);
    });

    r.nApi = Api(baseUrl: 'https://calls.example', client: client(true), clientName: 'macos')..token = 'n';
    final p0Api = Api(baseUrl: 'https://calls.example', client: client(false), clientName: 'ios')..token = 'p';
    r.nStore = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    r.p0Store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    r.nMessenger = r.messenger();
    final p0Messenger = Messenger(api: p0Api, crypto: p0Chat, store: r.p0Store, me: me, contactById: (_) => null, mutualContacts: () => [], ack: (_) {});
    final p0Ctx = LinkContext(api: p0Api, crypto: p0Chat, link: r.p0Link, messenger: p0Messenger, store: r.p0Store, contacts: () => [], wait: (_) async => Future<void>.delayed(const Duration(milliseconds: 5)));
    r.take = await TakeOver.start(api: r.nApi, link: r.nLink, groups: r.nGroups, device: await r.nMessenger.device(), platform: 'macos', wait: (_) => Future<void>.delayed(const Duration(milliseconds: 5)));
    final offered = r.take.waitOffer();
    r.hand = await HandOver.fromQr(p0Ctx, r.p0Groups, r.take.qr, hold: (held) async => r.holds.add(held));
    expect(await offered, r.hand.code, reason: 'both screens show the same digits');
    r.request = await r.hand.waitRequest();
    expect(r.request.leafSigKey, await r.nGroups.deviceLeaf());
    expect(r.succession, isNull, reason: 'nothing signed before the user confirms');
    return r;
  }

  Future<void> expectHandedOver(_Rig r) async {
    // N: record, then keys, then list v1 under the new key naming the old primary (never the server-only device).
    expect((r.succession!['record'] as Map)['newSign'], r.request.identity.sign);
    expect(r.served['sign'], r.request.identity.sign);
    final list = r.published!['list'] as Map;
    expect((list['version'], list['prevHash']), (1, ''));
    expect({for (final d in list['devices'] as List) d['deviceId']}, {p0Device, (await r.nMessenger.device()).deviceId});
    expect(r.nGroups.recertified, 1);
    expect(r.nMessenger.companion, isFalse);
    expect(r.marker, isNull, reason: 'the marker is cleared when done');
    expect(r.holds, [true], reason: 'the old primary stopped group traffic before succession and stepped down held');
    // P0: a linked device of the new key now, with its leaf certified under it.
    expect(r.p0Link.identity, isNull);
    expect(r.p0Link.companion?.identity, r.request.identity);
    final cert = jsonDecode(r.p0Link.companion!.certJson) as Map;
    expect((cert['deviceId'], cert['leafSigKey'], cert['aikSign']), (p0Device, await r.p0Groups.deviceLeaf(), r.request.identity.sign));
    await r.nStore.close();
    await r.p0Store.close();
  }

  test('hand over: request, compare, record, keys, list v1 (only our signed list), demote, step down', () async {
    final r = await rig();
    await Future.wait([r.hand.approve(), r.take.run(r.nMessenger, platform: 'macos', markers: r.markers)], eagerError: true);
    await expectHandedOver(r);
  });

  test("a served list our primary didn't sign stops the take-over before anything is published", () async {
    final r = await rig(forged: true);
    unawaited(r.hand.approve(timeout: const Duration(milliseconds: 300)).then((_) {}, onError: (_) {}));
    await expectLater(r.take.run(r.nMessenger, platform: 'macos', markers: r.markers), throwsA(isA<StoreException>()));
    expect((r.succession, r.published, r.served['sign']), (null, null, r.p0Link.identity!.sign), reason: 'no record, keys or list');
    expect((r.nMessenger.companion, r.marker), (true, null));
    await Future<void>.delayed(const Duration(milliseconds: 400));
    expect(r.holds, [true, false], reason: 'still the primary after a failed hand-over: group traffic resumes');
    await r.nStore.close();
    await r.p0Store.close();
  });

  // A crash (here: the connection lost) at each step after the user confirmed; the next start resumes and finishes,
  // repeating nothing that was done.
  for (final (step, at) in <(String, bool Function(_Rig, String, String))>[
    ('publishing the record', (r, m, p) => m == 'PUT' && p == '/api/devices/succession'),
    ('right after holding the new key', (r, m, p) => p == '/api/keys/count' && r.succession != null),
    ('uploading the keys', (r, m, p) => m == 'PUT' && p == '/api/keys'),
    ('publishing list v1', (r, m, p) => m == 'PUT' && p == '/api/devices/list'),
    ('sending demote', (r, m, p) => m == 'POST' && p.endsWith('/messages') && r.published != null),
  ]) {
    test('a take-over cut short while $step resumes on the next start and completes', () async {
      final r = await rig();
      r.fail = (m, p) => at(r, m, p);
      final stepped = r.hand.approve(timeout: const Duration(seconds: 20));
      await expectLater(r.take.run(r.nMessenger, platform: 'macos', markers: r.markers), throwsA(anything));
      expect(r.marker, isNotNull, reason: 'kept for the resume');
      expect(jsonDecode(r.marker!)['newSign'], r.request.identity.sign, reason: 'bound to the new key');
      // Restart: a new Messenger over the same key store, pins and marker.
      r.nMessenger = r.messenger();
      expect(await TakeOver.resume(api: r.nApi, link: r.nLink, groups: r.nGroups, messenger: r.nMessenger, platform: 'macos', markers: r.markers), isTrue);
      await stepped;
      expect((r.records, r.lists), (1, 1), reason: 'nothing published twice');
      await expectHandedOver(r);
      expect(await TakeOver.resume(api: r.nApi, link: r.nLink, groups: r.nGroups, messenger: r.nMessenger, platform: 'macos', markers: r.markers), isFalse);
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
    String? under = old.sign; // The account key our certificate is under.
    OwnSuccession own() => OwnSuccession(
      api: api, link: link, groups: groups, store: store, updateLeaf: (_) async {}, me: me, platform: 'macos',
      certKey: (read: () async => under, write: (String sign) async => under = sign),
    );

    // A served key with a forged chain moves nothing.
    chain = [{...chain.single, 'signature': b64(List.filled(64, 1))}];
    await expectLater(own().follow(), throwsA(isA<StoreException>()));
    expect(link.adopted, isEmpty);

    chain = [{...record, 'signature': b64(ed.sign(aik.privateKey, successionBytes(me.id, old.sign, next.sign, next.dh, 5)))}];
    expect(await own().follow(), isTrue);
    expect(link.companion?.identity, next);
    expect(asked.single['leafSigKey'], await groups.deviceLeaf());
    expect(await own().follow(), isFalse, reason: 'already there');
    expect(asked, hasLength(2), reason: 'the certificate is still under the old key: asked again (a first ask can be refused)');
    under = next.sign;
    expect(await own().follow(), isFalse);
    expect(asked, hasLength(2), reason: 'certified under the current key: no more asking');
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

class _Rig {
  late _SigningLink p0Link;
  late FakeChatCrypto nChat;
  late _TakingLink nLink;
  late FakeGroupCrypto nGroups, p0Groups;
  late Api nApi;
  late MessageStore nStore, p0Store;
  final MemoryDevicePrefs nPrefs = MemoryDevicePrefs();
  late Messenger nMessenger;
  late TakeOver take;
  late HandOver hand;
  late ({Identity identity, String leafSigKey}) request;
  Map<String, dynamic>? succession, published;
  late Map<String, dynamic> served;
  int records = 0, lists = 0;

  /// The old primary's group processing: stopped (true) from sending `succession`, resumed (false) on failure.
  final List<bool> holds = [];
  bool Function(String method, String path)? fail;
  String? marker;
  late final TakeOverMarkers markers = (read: () async => marker, write: (String? v) async => marker = v);

  Messenger messenger() => Messenger(api: nApi, crypto: nChat, store: nStore, me: const User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me'), contactById: (_) => null, mutualContacts: () => [], ack: (_) {}, devices: nPrefs)
    ..companion = true;
}
