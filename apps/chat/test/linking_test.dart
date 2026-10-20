import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/crypto/link_crypto.dart';
import 'package:private_chat/messaging/linking.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// The primary's side of linking (docs/m5-linking.md §1, §2) against a fake relay: nothing is signed before
/// the hello and the user's tap; then the list names the device, the certificate covers its leaf key, and the
/// grant and bundle arrive sealed and in order.
void main() {
  sqfliteFfiInit();
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
  const bob = Contact(id: 'bbbbbbbbbbbbbbbbbbbbbb', username: 'bob', state: ContactState.mutual);
  final newDevice = 'n' * 22, leaf = b64(List.filled(32, 7));

  late List<Map<String, dynamic>> published, n2p, p2n;
  late bool granted;
  late Api api;
  late FakeChatCrypto chat;
  late Messenger messenger;
  late MessageStore store;
  late FakeLinkCrypto primaryLink, deviceLink;

  setUp(() async {
    published = [];
    n2p = [];
    p2n = [];
    granted = false;
    chat = FakeChatCrypto();
    final client = MockClient((request) async {
      final path = request.url.path;
      http.Response ok(Object body, [int status = 200]) => http.Response(jsonEncode(body), status);
      if (path == '/api/keys/count') return ok({'oneTimePreKeys': 50, 'signedPreKeyId': 1, 'identity': chat.me.toJson()});
      if (path == '/api/devices/me') return ok({'userId': me.id, 'identity': chat.me.toJson(), 'list': null, 'devices': []});
      if (path == '/api/devices/list') {
        published.add(jsonDecode(request.body) as Map<String, dynamic>);
        return ok({'version': 1});
      }
      if (path.endsWith('/offer')) return ok({'deviceId': newDevice, 'platform': 'macos', 'purpose': 'link', 'mode': 'qr'}, 201);
      if (path.endsWith('/messages') && request.method == 'POST') {
        p2n.add({'seq': p2n.length + 1, 'data': (jsonDecode(request.body) as Map)['data']});
        return ok({'seq': p2n.length}, 201);
      }
      if (path.endsWith('/messages')) {
        final after = int.parse(request.url.queryParameters['after'] ?? '0');
        return ok({'messages': n2p.where((m) => (m['seq'] as int) > after).toList()});
      }
      if (path.endsWith('/grant')) {
        if (p2n.isEmpty || published.isEmpty) return ok({'error': 'Send the grant first.'}, 409);
        granted = true;
        return ok({'status': 'granted'});
      }
      return ok({}, 200);
    });
    api = Api(baseUrl: 'https://calls.example', client: client, clientName: 'ios')..token = 't';
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    messenger = Messenger(api: api, crypto: chat, store: store, me: me, contactById: (_) => bob, mutualContacts: () => [bob], ack: (_) {}, devices: MemoryDevicePrefs());
    await messenger.checkActive();
    primaryLink = FakeLinkCrypto(identity: chat.me)..pins.add(const PinExport(contact: 'bbbbbbbbbbbbbbbbbbbbbb', identity: Identity(dh: 'b-dh', sign: 'b-sign'), verified: true));
    deviceLink = FakeLinkCrypto();
    await store.put(ChatMessage(id: '00000000-0000-4000-8000-000000000001', conversationId: messenger.conversationWith(bob.id!), direction: Direction.outgoing, text: 'old history', createdAt: 1, status: MessageStatus.sent));
  });
  tearDown(() => store.close());

  LinkContext ctx() => LinkContext(api: api, crypto: chat, link: primaryLink, messenger: messenger, store: store, contacts: () => [bob], wait: (_) async {});

  Future<void> hello({String? deviceId, bool history = true}) async {
    final sealed = await deviceLink.seal('L' * 22, jsonEncode({'v': 1, 'type': 'hello', 'deviceId': deviceId ?? newDevice, 'platform': 'macos', 'label': 'Mac app', 'leafSigKey': leaf, 'wantsHistory': history}));
    n2p.add({'seq': n2p.length + 1, 'data': sealed});
  }

  test('scan, compare, Link: list, certificate, grant and bundle, in that order', () async {
    final qr = await deviceLink.qr('L' * 22);
    final link = await PrimaryLink.fromQr(ctx(), qr);
    expect(link.code, await deviceLink.complete('L' * 22, 'eph'), reason: 'both screens show the same code');
    await hello();
    final said = await link.waitHello();
    expect((said.label, said.platform, said.wantsHistory), ('Mac app', 'macos', true));
    expect(published, isEmpty, reason: 'nothing signed before the tap');

    await link.approve();
    expect(granted, isTrue);
    final list = published.single['list'] as Map;
    expect([for (final d in list['devices'] as List) d['deviceId']], contains(newDevice));
    final entry = (list['devices'] as List).firstWhere((d) => d['deviceId'] == newDevice) as Map;
    final grant = jsonDecode(await deviceLink.open('L' * 22, p2n[0]['data'] as String)) as Map;
    expect((grant['type'], grant['userId'], grant['deviceId'], grant['listVersion']), ('grant', me.id, newDevice, 1));
    expect(grant['listHash'], listHash(listBytes(list)));
    expect(openMeta(unb64(grant['metaKey'] as String), me.id, newDevice, entry['meta'] as String), {'label': 'Mac app', 'platform': 'macos'});
    final cert = jsonDecode(grant['cert'] as String) as Map;
    expect((cert['deviceId'], cert['leafSigKey']), (newDevice, leaf));
    final data = StringBuffer();
    for (var i = 1; i < p2n.length; i++) {
      final chunk = jsonDecode(await deviceLink.open('L' * 22, p2n[i]['data'] as String)) as Map;
      expect((chunk['type'], chunk['i'], chunk['of']), ('bundle', i - 1, grant['chunks']));
      data.write(utf8.decode(unb64(chunk['data'] as String)));
    }
    final bundle = jsonDecode(data.toString()) as Map;
    expect((bundle['pins'] as List).single['contact'], bob.id);
    final conversation = (bundle['conversations'] as List).single as Map;
    expect(conversation['peer'], bob.id);
    expect((conversation['history'] as List).single['text'], 'old history');
  });

  test("a hello from another device than the one registered links nothing", () async {
    final link = await PrimaryLink.fromQr(ctx(), await deviceLink.qr('L' * 22));
    await hello(deviceId: 'x' * 22);
    await expectLater(link.waitHello(), throwsA(isA<StoreException>()));
    expect(published, isEmpty);
  });

  test('without wantsHistory the bundle carries no messages', () async {
    final link = await PrimaryLink.fromQr(ctx(), await deviceLink.qr('L' * 22));
    await hello(history: false);
    await link.waitHello();
    await link.approve();
    final grant = jsonDecode(await deviceLink.open('L' * 22, p2n[0]['data'] as String)) as Map;
    final bundle = jsonDecode(utf8.decode(unb64((jsonDecode(await deviceLink.open('L' * 22, p2n[1]['data'] as String)) as Map)['data'] as String))) as Map;
    expect(grant['chunks'], 1);
    expect(((bundle['conversations'] as List).single as Map).containsKey('history'), isFalse);
  });
}
