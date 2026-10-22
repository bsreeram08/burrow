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
import 'package:private_chat/messaging/backup.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/messaging/succession.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import 'support/fake_backup.dart';

/// Removing a device that holds the account key replaces the key (docs/m6-account-key.md §6.2): with a backup, only
/// with the passphrase's proof; list v1 under the new key names our verified devices except the removed one; the
/// backup is re-sealed to the keys held here without a proof.
void main() {
  sqfliteFfiInit();
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
  final other = 'o' * 22, removed = 'r' * 22, coded = 'c' * 22;

  for (final crash in [null, 'record landed', 'record lost', 'superseded']) {
    test(
      switch (crash) {
        null => 'rotate on remove: proof, record, keys, list v1 without the removed device, backup re-sealed',
        'record landed' => 'a crash after the server took the record: the next start finishes the rotation from the core\'s prepared key',
        'superseded' => 'a crash after the server took the record, which another record then replaced: the next start drops the prepared key',
        _ => 'a crash before the record reached the server: the next start drops the prepared key and keeps the old one',
      },
      () async {
        final aik = ed.generateKey();
        final identity = Identity(dh: b64(List.filled(32, 6)), sign: b64(aik.publicKey.bytes));
        final account = FakeAccountCrypto(held: identity)..sign = (record) => b64(ed.sign(aik.privateKey, backupKeysBytes(record)));
        final backups = FakeBackupServer();
        final prefs = MemoryDevicePrefs();
        final self = (await localDevice(prefs, me.id)).deviceId;
        Map<String, dynamic>? succession, list;
        final ids = [self, other, removed, coded]..sort();
        final chat = FakeChatCrypto(me: identity);
        final metaKey = deviceMetaKey(await chat.deviceMetaSignature(me.id));
        final served = {
          'v': 1,
          'userId': me.id,
          'version': 1,
          'prevHash': '',
          'devices': [
            for (final id in ids) {'deviceId': id, 'addedAt': 1, 'meta': sealMeta(metaKey, me.id, id, label: 'L-$id', platform: 'web', via: id == coded ? 'code' : null)},
          ],
        };
        final client = MockClient((request) async {
          final path = request.url.path;
          if (path == '/api/backup') return backups.handle(request);
          http.Response ok(Object body) => http.Response(jsonEncode(body), 200);
          if (path == '/api/devices/me') {
            return ok({
              'identity': identity.toJson(),
              if (succession != null)
                'succession': [
                  {...(succession!['record'] as Map), 'signature': succession!['signature']},
                ],
              // The newest record, as our own view carries it: it still authorizes its key upload.
              if (succession != null) 'rotation': {'oldSign': identity.sign, 'newSign': (succession!['record'] as Map)['newSign'], 'at': 1, 'state': crash == 'superseded' ? 'superseded' : 'open'},
              'list': served,
              'signature': b64(ed.sign(aik.privateKey, listBytes(served))),
              'certs': {for (final d in served['devices']! as List) (d as Map)['deviceId']: b64(ed.sign(aik.privateKey, certBytes(me.id, d)))},
              'devices': [
                for (final id in ids) {'id': id, 'state': id == removed ? 'revoked' : 'listed', 'platform': 'web'},
              ],
            });
          }
          if (path == '/api/devices/succession') {
            final body = jsonDecode(request.body) as Map<String, dynamic>;
            if (backups.record != null && body['proof'] == null) return http.Response('{"error":"The passphrase or recovery key is needed."}', 403);
            if (crash == 'record lost') throw http.ClientException('connection lost');
            succession = body;
            backups.resealAllowed = true;
            if (crash == 'record landed' || crash == 'superseded') throw http.ClientException('connection lost after the server took it');
            return ok({'seq': 1});
          }
          if (path == '/api/devices/list') {
            list = jsonDecode(request.body) as Map<String, dynamic>;
            return ok({'version': 1});
          }
          return ok({});
        });
        final api = Api(baseUrl: 'https://calls.example', clientName: 'ios', client: client)..token = 't';
        final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
        final messenger = Messenger(
          api: api,
          crypto: chat,
          store: store,
          me: me,
          contactById: (_) => null,
          mutualContacts: () => [],
          ack: (_) {},
          devices: prefs,
        );
        final backup = AccountBackup(api: backups.api(), crypto: account, me: me);
        await backup.commit(await backup.prepareTurnOn('my good long passphrase'));
        final groups = FakeGroupCrypto(userId: me.id);
        final rotation = AccountRotation(api: api, account: account, groups: groups, messenger: messenger, platform: 'ios', backup: backup);

        // Without the passphrase nothing changes.
        await expectLater(rotation.rotate(removed: {removed}), throwsA(anything));
        await expectLater(rotation.rotate(removed: {removed}, unlock: const Unlock.passphrase('wrong passphrase here')), throwsA(anything));
        expect(succession, isNull);
        expect(list, isNull);
        expect(account.rotations, isEmpty);

        if (crash != null) {
          await expectLater(rotation.rotate(removed: {removed}, unlock: const Unlock.passphrase('my good long passphrase')), throwsA(anything));
          expect(account.held, identity, reason: 'the key is not swapped before the server answered');
          expect(account.pending, isNotNull, reason: 'the prepared key is kept in the core');
          // Restart.
          final resumed = await AccountRotation(api: api, account: account, groups: groups, messenger: messenger, platform: 'ios', backup: backup).resume();
          expect(account.pending, isNull);
          if (crash == 'record lost' || crash == 'superseded') {
            expect(resumed, isFalse);
            expect(account.held, identity);
            expect(list, isNull);
            await store.close();
            return;
          }
          expect(resumed, isTrue);
        } else {
          await rotation.rotate(removed: {removed}, unlock: const Unlock.passphrase('my good long passphrase'));
        }
        final record = succession!['record'] as Map;
        expect((record['oldSign'], record['newSign']), (identity.sign, account.rotations.single.sign));
        expect(succession!['proof'], isA<String>());
        final v1 = list!['list'] as Map;
        expect(v1['version'], 1);
        expect({for (final d in v1['devices'] as List) d['deviceId']}, {self, other, coded}, reason: 'the removed device (revoked) is not in the new list');
        // A code-linked device keeps its mark under the new key: it unlocks with the passphrase, never by rekey.
        final codedEntry = (v1['devices'] as List).firstWhere((d) => d['deviceId'] == coded) as Map;
        expect(openMeta(metaKey, me.id, coded, codedEntry['meta'] as String), {'label': 'L-$coded', 'platform': 'web', 'via': 'code'});
        final otherEntry = (v1['devices'] as List).firstWhere((d) => d['deviceId'] == other) as Map;
        expect(openMeta(metaKey, me.id, other, otherEntry['meta'] as String)?.containsKey('via'), isFalse);
        expect(groups.recertified, 1);
        // The backup follows the new key: epoch 2, sealed without a proof (the one allowed right after a succession).
        expect(backups.record?['epoch'], 2);
        expect(backups.puts.last.containsKey('proof'), isFalse);
        await store.close();
      },
    );
  }
}
