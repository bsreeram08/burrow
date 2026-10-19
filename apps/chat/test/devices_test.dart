import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// Device lists (docs/devices.md): the same canonical bytes and checks as public/devices.js, and the
/// Messenger's device registration and contact-list pinning against a fake server.
void main() {
  String id(int n) => String.fromCharCode(97 + n) * 22;
  Map<String, dynamic> listOf(String userId, int version, String prevHash, List<String> ids) => {
    'v': 1,
    'userId': userId,
    'version': version,
    'prevHash': prevHash,
    'devices': [for (final device in [...ids]..sort()) {'deviceId': device, 'addedAt': 1800000000000, 'meta': ''}],
  };
  String sign(ed.KeyPair key, Uint8List bytes) => b64(ed.sign(key.privateKey, bytes));
  String aikOf(ed.KeyPair key) => b64(key.publicKey.bytes);
  Map<String, dynamic> signed(ed.KeyPair key, Map<String, dynamic> list) => {
    'list': list,
    'signature': sign(key, listBytes(list)),
    'certs': {for (final device in list['devices'] as List) device['deviceId']: sign(key, certBytes(list['userId'] as String, device as Map))},
  };
  DeviceCheck check(ed.KeyPair key, Map<String, dynamic> view, {String userId = 'alice', DevicePin? pin, String? aik}) =>
      verifyView(userId: userId, aikSign: aik ?? aikOf(key), list: view['list'], signature: view['signature'], certs: view['certs'], pin: pin);

  group('format', () {
    test('the same canonical bytes as devices.js (the fixed vector in tests/unit/devices.test.ts)', () {
      final list = {
        'v': 1,
        'userId': 'user_1',
        'version': 2,
        'prevHash': 'A' * 43,
        'devices': [
          {'deviceId': 'a' * 22, 'addedAt': 1800000000123, 'meta': b64(List.filled(40, 9))},
          {'deviceId': 'b' * 22, 'addedAt': 7, 'meta': ''},
        ],
      };
      expect(hash.sha256.convert(listBytes(list)).toString(), '31f9b6f38de5a0d6180afcf54233e7272add9dd22c49e86e40fa3a7c48e938e6');
      expect(hash.sha256.convert(certBytes('user_1', (list['devices'] as List).first as Map)).toString(), '5115e92bead7431b81c136519282f62e4a85a21c7907d8c3f97571205dcebcea');
      expect(hash.sha256.convert(bindBytes('user_1', 'a' * 22, 'A' * 43)).toString(), 'e11ceff09f689bbea340eef1c1fcc013f3fff12ff1167b7d44d664fbf5101b18');
    });

    test('non-canonical or malformed lists are refused', () {
      final good = listOf('user_1', 1, '', [id(0), id(1)]);
      final devices = good['devices'] as List;
      final bad = [
        {...good, 'extra': true},
        {...good, 'devices': devices.reversed.toList()},
        {...good, 'devices': [devices[0], devices[0]]},
        {...good, 'version': 2},
        {...good, 'prevHash': 'A' * 43},
        {...good, 'devices': []},
        {...good, 'devices': [{...devices[0] as Map, 'meta': 'too-short'}]},
        {...good, 'devices': [{...devices[0] as Map, 'platform': 'web'}]},
        {...good, 'version': 2, 'prevHash': '${'A' * 42}B'},
        {...good, 'userId': 'no spaces'},
      ];
      for (final list in bad) {
        expect(() => listBytes(list), throwsA(isA<DeviceFormatException>()), reason: jsonEncode(list));
      }
    });
  });

  group('verification and pinning', () {
    final key = ed.generateKey(), other = ed.generateKey();
    final ids = [id(0), id(1)];

    test('signature, owner, injected devices and certificates', () {
      final v1 = signed(key, listOf('alice', 1, '', ids));
      final ok = check(key, v1);
      expect(ok.ok, isTrue);
      expect(ok.count, 2);
      expect(check(key, v1, aik: aikOf(other)).reason, 'signature');
      expect(check(key, v1, userId: 'bob').reason, 'owner');
      // A server-injected device: the list no longer matches the AIK signature.
      expect(check(key, {...v1, 'list': listOf('alice', 1, '', [...ids, id(2)])}).reason, 'signature');
      // A device whose certificate is missing, or signed by a key that is not the pinned AIK.
      expect(check(key, {...v1, 'certs': {ids[0]: (v1['certs'] as Map)[ids[0]]}}).reason, 'certificate');
      final forged = {...v1['certs'] as Map, ids[1]: sign(other, certBytes('alice', {'deviceId': ids[1], 'addedAt': 1800000000000}))};
      expect(check(key, {...v1, 'certs': forged}).reason, 'certificate');
    });

    test('rollback, equivocation, fork and revoked devices are refused against the pin', () {
      final first = check(key, signed(key, listOf('alice', 1, '', ids)));
      final v2 = signed(key, listOf('alice', 2, first.hash!, [ids[0]]));
      final second = check(key, v2, pin: first.pin);
      expect(second.ok, isTrue);
      expect(second.pin!.revoked, [ids[1]]);
      expect(check(key, signed(key, listOf('alice', 1, '', ids)), pin: second.pin).reason, 'rollback');
      expect(check(key, signed(key, listOf('alice', 2, first.hash!, ids)), pin: second.pin).reason, 'equivocation');
      expect(check(key, signed(key, listOf('alice', 3, 'A' * 43, [ids[0]])), pin: second.pin).reason, 'fork');
      expect(check(key, signed(key, listOf('alice', 3, second.hash!, ids)), pin: second.pin).reason, 'revoked');
      // The pin survives storage.
      expect(DevicePin.fromJson(jsonDecode(jsonEncode(second.pin!.toJson())))!.revoked, [ids[1]]);
    });
  });

  group('Messenger', () {
    sqfliteFfiInit();
    const me = User(id: 'me-id', username: 'me');
    const alice = Contact(id: 'alice-id', username: 'alice', state: ContactState.mutual, online: true);
    final aliceKey = ed.generateKey();
    final aliceIdentity = Identity(dh: 'alice-dh', sign: aikOf(aliceKey));
    late List<Map<String, dynamic>> announced;
    late Map<String, dynamic>? serverIdentity;
    late Map<String, dynamic> aliceView;
    late List<String> notices;

    Future<Messenger> start(DevicePrefs prefs) async {
      final client = MockClient((request) async {
        final path = request.url.path;
        if (path == '/api/keys/count') return http.Response(jsonEncode({'oneTimePreKeys': 50, 'signedPreKeyId': 1, 'identity': serverIdentity}), 200);
        if (path == '/api/keys') return http.Response('{}', 200);
        if (path == '/api/devices/challenge') return http.Response(jsonEncode({'challenge': 'A' * 43}), 200);
        if (path == '/api/devices/announce') {
          announced.add(jsonDecode(request.body) as Map<String, dynamic>);
          return http.Response(jsonEncode({'deviceId': announced.last['deviceId'], 'state': 'pending', 'primary': true}), 200);
        }
        if (path == '/api/devices/alice') return http.Response(jsonEncode(aliceView), 200);
        return http.Response('{"error":"nope"}', 404);
      });
      final messenger = Messenger(
        api: Api(baseUrl: 'https://calls.example', client: client, clientName: 'ios')..token = 't0ken',
        crypto: FakeChatCrypto(me: const Identity(dh: 'me-dh', sign: 'me-sign')),
        store: await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath),
        me: me,
        contactById: (id) => id == alice.id ? alice : null,
        mutualContacts: () => [alice],
        ack: (_) {},
        devices: prefs,
      );
      messenger.notices.listen(notices.add);
      return messenger;
    }

    setUp(() {
      announced = [];
      notices = [];
      serverIdentity = {'dh': 'me-dh', 'sign': 'me-sign'};
      aliceView = {'userId': 'alice-id', 'identity': aliceIdentity.toJson(), ...signed(aliceKey, listOf('alice-id', 1, '', [id(0)]))};
    });

    test('the key holder announces its device with the published identity; the id is stable', () async {
      final prefs = MemoryDevicePrefs();
      final messenger = await start(prefs);
      expect(await messenger.checkActive(), isTrue);
      final device = await messenger.device(), body = announced.single;
      expect(body['deviceId'], device.deviceId);
      expect(body['identity'], {'dh': 'me-dh', 'sign': 'me-sign'});
      expect(body['challenge'], 'A' * 43);
      // Proof of possession: the device key signed this session's challenge for this account and device.
      expect(verifyBytes(body['deviceKey'] as String, bindBytes(me.id, device.deviceId, 'A' * 43), body['signature']), isTrue);
      // The same install keeps its id and key.
      final again = await (await start(prefs)).device();
      expect([again.deviceId, again.publicKey], [device.deviceId, device.publicKey]);
    });

    test('a device that does not hold the keys announces without an identity and stays inactive', () async {
      serverIdentity = {'dh': 'other-dh', 'sign': 'other-sign'};
      final messenger = await start(MemoryDevicePrefs());
      expect(await messenger.checkActive(), isFalse);
      expect(announced.single.containsKey('identity'), isFalse);
      expect(announced.single.keys, containsAll(['deviceId', 'deviceKey', 'challenge', 'signature']));
    });

    test("a contact's list is pinned; a rollback or a server-injected device is reported", () async {
      final messenger = await start(MemoryDevicePrefs());
      final v1 = await messenger.verifyContactDevices(alice);
      expect(v1!.ok, isTrue);
      final hash1 = v1.hash!;
      aliceView = {...aliceView, ...signed(aliceKey, listOf('alice-id', 2, hash1, [id(0), id(1)]))};
      expect((await messenger.verifyContactDevices(alice))!.version, 2);
      // The server serves v1 again: a rollback.
      aliceView = {...aliceView, ...signed(aliceKey, listOf('alice-id', 1, '', [id(0)]))};
      expect((await messenger.verifyContactDevices(alice))!.reason, 'rollback');
      // The server adds a device of its own to the current list.
      final injected = signed(aliceKey, listOf('alice-id', 2, hash1, [id(0), id(1)]));
      aliceView = {...aliceView, ...injected, 'list': listOf('alice-id', 2, hash1, [id(0), id(1), id(2)])};
      expect((await messenger.verifyContactDevices(alice))!.reason, 'signature');
      await Future<void>.delayed(Duration.zero); // Notices are delivered asynchronously.
      expect(notices, ["alice's device list failed verification (rollback).", "alice's device list failed verification (signature)."]);
    });

    test('a list is only checked against the pinned security code, never a new one the server serves', () async {
      final messenger = await start(MemoryDevicePrefs());
      expect((await messenger.verifyContactDevices(alice))!.ok, isTrue);
      final impostor = ed.generateKey();
      aliceView = {'userId': 'alice-id', 'identity': {'dh': 'x', 'sign': aikOf(impostor)}, ...signed(impostor, listOf('alice-id', 1, '', [id(3)]))};
      expect((await messenger.verifyContactDevices(alice))!.reason, 'identity');
    });
  });

  test("the 'devices' frame parses", () {
    expect((AccountEvent.parse('{"type":"devices","id":"u1"}')! as DevicesChanged).id, 'u1');
  });
}
