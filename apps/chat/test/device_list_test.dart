import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// The app publishes the account's signed device list (docs/devices.md, account.js syncDevices) so that it
/// is a listed device and may use groups (docs/m4-groups.md §2).
void main() {
  sqfliteFfiInit();
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
  test('the key holder publishes list v1 naming this device, signed record by record', () async {
    final crypto = FakeChatCrypto();
    final published = <Map<String, dynamic>>[];
    var view = <String, dynamic>{'userId': me.id, 'identity': crypto.me.toJson(), 'list': null, 'devices': <Object>[]};
    final client = MockClient((request) async {
      final path = request.url.path;
      if (path == '/api/keys/count') return http.Response(jsonEncode({'oneTimePreKeys': 50, 'signedPreKeyId': 1, 'identity': crypto.me.toJson()}), 200);
      if (path == '/api/devices/me') return http.Response(jsonEncode(view), 200);
      if (path == '/api/devices/list') {
        published.add(jsonDecode(request.body) as Map<String, dynamic>);
        return http.Response(jsonEncode({'version': 1, 'revoked': []}), 200);
      }
      return http.Response('{}', 200);
    });
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final prefs = MemoryDevicePrefs();
    final messenger = Messenger(
      api: Api(baseUrl: 'https://calls.example', client: client, clientName: 'ios')..token = 't',
      crypto: crypto,
      store: store,
      me: me,
      contactById: (_) => null,
      mutualContacts: () => const [],
      ack: (_) {},
      devices: prefs,
    );
    expect(await messenger.checkActive(), isTrue);
    expect(await messenger.syncDevices(), isTrue);
    final device = (await messenger.device()).deviceId;
    final sent = published.single;
    expect(sent['deviceId'], device);
    final list = sent['list'] as Map;
    expect((list['version'], list['prevHash'], (list['devices'] as List).single['deviceId']), (1, '', device));
    // The structured list went to the core to validate and sign; this device's label is sealed in it.
    expect(crypto.signedLists.single, list);
    final meta = (list['devices'] as List).single['meta'] as String;
    expect(openMeta(deviceMetaKey(await crypto.deviceMetaSignature(me.id)), me.id, device, meta), {'label': 'iPhone app', 'platform': 'ios'});

    // Someone else's key published: not the key holder, nothing signed.
    view = {...view, 'identity': {'dh': 'x', 'sign': 'y'}};
    expect(await messenger.syncDevices(), isFalse);
    expect(published, hasLength(1));
    await messenger.dispose();
    await store.close();
  });
}
