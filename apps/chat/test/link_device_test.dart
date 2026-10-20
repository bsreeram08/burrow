import 'dart:convert';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/crypto/link_crypto.dart';
import 'package:private_chat/messaging/linking.dart';
import 'package:private_chat/store/message.dart';

/// The new device's side of linking (docs/m5-linking.md §1, §1.6, §1.7) against a fake relay, with the primary
/// played by hand: the 6 digits match, the hello names this device and its leaf key, and the grant is checked
/// (account, served list under the QR-authenticated key, certificate) before anything is installed.
void main() {
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
  final linkId = 'L' * 22, claim = b64(List.filled(32, 3));
  final aik = ed.generateKey();
  final identity = Identity(dh: b64(List.filled(32, 9)), sign: b64(aik.publicKey.bytes));

  late LocalDevice device;
  late FakeLinkCrypto newLink, primary;
  late FakeGroupCrypto groups;
  late Map<String, dynamic> state;
  late List<String> n2p, p2n;
  late List<String> posted;
  late Map<String, Object?> servedList;
  late Api api;
  String? mode;
  Map? seenHello;

  /// The primary opens the new device's hello once.
  Future<Map> helloOf() async => seenHello ??= jsonDecode(await primary.open(linkId, n2p.single)) as Map;

  Map<String, Object?> signedView(Map<String, Object?> list) => {
    'userId': me.id,
    'identity': identity.toJson(),
    'list': list,
    'signature': b64(ed.sign(aik.privateKey, listBytes(list))),
    'certs': {for (final d in (list['devices']! as List).cast<Map>()) d['deviceId']: b64(ed.sign(aik.privateKey, certBytes(me.id, d)))},
  };

  setUp(() async {
    device = await localDevice(MemoryDevicePrefs(), '__link__');
    newLink = FakeLinkCrypto();
    primary = FakeLinkCrypto(identity: identity);
    groups = FakeGroupCrypto(userId: me.id);
    state = {'state': 'waiting'};
    n2p = [];
    p2n = [];
    posted = [];
    mode = null;
    seenHello = null;
    servedList = {'v': 1, 'userId': me.id, 'version': 1, 'prevHash': '', 'devices': [{'deviceId': device.deviceId, 'addedAt': 1700000000000, 'meta': ''}]};
    final client = MockClient((request) async {
      final path = request.url.path;
      http.Response ok(Object body, [int status = 200]) => http.Response(jsonEncode(body), status);
      final body = request.body.isEmpty ? const <String, dynamic>{} : jsonDecode(request.body) as Map<String, dynamic>;
      posted.add('${request.method} $path');
      if (path == '/api/link/start') {
        mode = body['mode'] as String;
        expect(verifyBytes(body['deviceKey'] as String, linkStartBytes(device.deviceId, 'macos', device.publicKey), body['signature']), isTrue, reason: 'start bytes signed by the device key');
        return ok({'linkId': linkId, 'claim': claim, 'expiresAt': 1, if (mode == 'code') 'code': 'ABCD2345'}, 201);
      }
      if (path == '/api/link/$linkId' && request.method == 'GET') {
        expect(request.headers['X-Link-Claim'], claim);
        return ok(state);
      }
      if (path == '/api/link/$linkId/commit') return ok({});
      if (path == '/api/link/$linkId/reveal') {
        state['reveal'] = body;
        return ok({});
      }
      if (path == '/api/link/$linkId/messages' && request.method == 'POST') {
        n2p.add(body['data'] as String);
        return ok({'seq': n2p.length}, 201);
      }
      if (path == '/api/link/$linkId/messages') {
        final after = int.parse(request.url.queryParameters['after'] ?? '0');
        return ok({'messages': [for (var i = after; i < p2n.length; i++) {'seq': i + 1, 'data': p2n[i]}]});
      }
      if (path == '/api/link/$linkId/claim') {
        expect(verifyBytes(device.publicKey, linkClaimBytes(linkId, device.deviceId, claim), body['signature']), isTrue, reason: 'claim bytes signed by the device key');
        return ok({'user': {'id': me.id, 'username': me.username}, 'session': {'token': 'linked-token', 'expiresAt': 1}});
      }
      if (path == '/api/me') {
        expect(request.headers['Authorization'], 'Bearer linked-token');
        return ok({'user': {'id': me.id, 'username': me.username}});
      }
      if (path == '/api/devices/me') return ok(signedView(servedList));
      return ok({}, 200);
    });
    api = Api(baseUrl: 'https://calls.example', client: client, clientName: 'macos');
  });

  Future<NewDeviceLink> start({String? username}) =>
      NewDeviceLink.start(api: api, link: newLink, groups: groups, device: device, platform: 'macos', label: 'Mac app', username: username, wait: (_) async {});

  /// The primary: grant (and one bundle chunk) sealed for the new device, after the user tapped Link.
  Future<void> grant({Map<String, Object?>? list, String? certFor}) async {
    final hello = await helloOf();
    final bundle = jsonEncode({
      'v': 1,
      'pins': [const PinExport(contact: 'bbbbbbbbbbbbbbbbbbbbbb', identity: Identity(dh: 'b-dh', sign: 'b-sign'), verified: true).toJson()],
      'channels': [],
      'conversations': [],
    });
    final named = list ?? servedList;
    final cert = await primary.signDeviceCert(userId: me.id, deviceId: certFor ?? hello['deviceId'] as String, platform: 'macos', leafSigKey: hello['leafSigKey'] as String, issuedAt: 1);
    p2n.add(await primary.seal(linkId, jsonEncode({
      'v': 1, 'type': 'grant', 'userId': me.id, 'username': me.username, 'identity': identity.toJson(), 'deviceId': device.deviceId, 'cert': cert,
      'listVersion': named['version'], 'listHash': listHash(listBytes(named)), 'metaKey': b64(List.filled(32, 1)), 'chunks': 1,
    })));
    p2n.add(await primary.seal(linkId, jsonEncode({'v': 1, 'type': 'bundle', 'i': 0, 'of': 1, 'data': b64(utf8.encode(bundle))})));
    state = {'state': 'granted'};
  }

  test('QR: the same 6 digits, a sealed hello naming this device and its leaf, then a checked grant installs the account', () async {
    final link = await start();
    expect(mode, 'qr');
    final accepted = await primary.accept(link.qr!);
    state = {'state': 'offered', 'eph': accepted.eph};
    final code = await link.waitOffer();
    expect(code, accepted.code, reason: 'both screens show the same digits');
    final hello = await helloOf();
    expect((hello['type'], hello['deviceId'], hello['platform'], hello['leafSigKey']), ('hello', device.deviceId, 'macos', await groups.deviceLeaf()));
    await grant();
    final setup = await link.waitGrant();
    expect((setup.user.id, setup.token, setup.identity), (me.id, 'linked-token', identity));
    expect(setup.pin.devices, [device.deviceId]);
    expect(newLink.companion?.userId, me.id, reason: 'companion mode, under the key the primary showed');
    expect(newLink.pins.single.contact, 'bbbbbbbbbbbbbbbbbbbbbb', reason: 'pins imported');
    expect(api.token, 'linked-token');
  });

  test('a served list that is not the one the grant names installs nothing', () async {
    final link = await start();
    final accepted = await primary.accept(link.qr!);
    state = {'state': 'offered', 'eph': accepted.eph};
    await link.waitOffer();
    await grant(list: {...servedList, 'devices': [{'deviceId': device.deviceId, 'addedAt': 1700000000001, 'meta': ''}]});
    await expectLater(link.waitGrant(), throwsA(isA<StoreException>().having((e) => e.message, 'message', contains("doesn't look like your account"))));
    expect(newLink.companion, isNull);
    expect(newLink.pins, isEmpty);
  });

  test('a certificate for another device installs nothing', () async {
    final link = await start();
    final accepted = await primary.accept(link.qr!);
    state = {'state': 'offered', 'eph': accepted.eph};
    await link.waitOffer();
    await grant(certFor: 'x' * 22);
    await expectLater(link.waitGrant(), throwsA(isA<StoreException>()));
    expect(newLink.pins, isEmpty);
  });

  test('code mode: commit first, reveal only after the primary offered, and the same digits', () async {
    final link = await start(username: 'me');
    expect((mode, link.shortCode, link.qr), ('code', 'ABCD2345', null));
    expect(posted, contains('POST /api/link/$linkId/commit'));
    expect(posted.where((p) => p.endsWith('/reveal')), isEmpty);
    final eph = await primary.lookup(linkId, deviceN: device.deviceId, commit: 'commit-$linkId', deviceP: 'p' * 22);
    state = {'state': 'offered', 'eph': eph, 'offerDeviceId': 'p' * 22};
    final code = await link.waitOffer();
    final reveal = state['reveal'] as Map;
    expect(code, await primary.openCommitment(linkId, eph: reveal['eph'] as String, nonce: reveal['nonce'] as String));
  });
}
