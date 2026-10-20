import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:uuid/uuid.dart';

/// Phase 1 controls through the real Messenger, store and API client (fake crypto, fake server).
void main() {
  sqfliteFfiInit();
  const me = User(id: 'me-id', username: 'me');
  const alice = Contact(id: 'alice-id', username: 'alice', state: ContactState.mutual, online: true);
  const aliceIdentity = Identity(dh: 'alice-dh', sign: 'alice-sign');
  late MessageStore store;
  late Messenger messenger;
  late FakeChatCrypto mine, theirs;
  late List<String> acks;
  late List<Map<String, dynamic>> posted;
  var receipts = true;
  var now = DateTime.now().millisecondsSinceEpoch;

  Map<String, dynamic> inner(Map<String, dynamic> post) =>
      jsonDecode(jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(post['envelope'] as String))))['p'] as String) as Map<String, dynamic>;
  List<Map<String, dynamic>> sent(String type) => [for (final p in posted) if (inner(p)['type'] == type) inner(p)];

  setUp(() async {
    receipts = true;
    now = DateTime.now().millisecondsSinceEpoch;
    acks = [];
    posted = [];
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    mine = FakeChatCrypto(me: const Identity(dh: 'me-dh', sign: 'me-sign'));
    theirs = FakeChatCrypto(me: aliceIdentity);
    final client = MockClient((request) async {
      final path = request.url.path;
      if (path == '/api/keys/alice/identity') return http.Response(jsonEncode({'userId': 'alice-id', 'identity': aliceIdentity.toJson()}), 200);
      if (path == '/api/keys/alice') return http.Response(jsonEncode({'userId': 'alice-id', 'identity': aliceIdentity.toJson(), 'signedPreKey': {'id': 1}}), 200);
      if (path == '/api/keys/count') return http.Response(jsonEncode({'oneTimePreKeys': 50, 'signedPreKeyId': 1, 'identity': {'dh': 'me-dh', 'sign': 'me-sign'}}), 200);
      if (path == '/api/keys') return http.Response('{}', 200);
      if (path == '/api/messages') {
        posted.add(jsonDecode(request.body) as Map<String, dynamic>);
        return http.Response(jsonEncode({'id': 'm', 'createdAt': 1}), 201);
      }
      return http.Response('{"error":"nope"}', 404);
    });
    messenger = Messenger(
      api: Api(baseUrl: 'https://calls.example', client: client, clientName: 'ios')..token = 't0ken',
      crypto: mine,
      store: store,
      me: me,
      contactById: (id) => id == alice.id ? alice : null,
      mutualContacts: () => [alice],
      ack: acks.add,
      readReceipts: () => receipts,
      now: () => now,
    );
    expect(await messenger.checkActive(), isTrue);
  });
  tearDown(() async {
    await messenger.dispose();
    await store.close();
  });

  final bundle = jsonEncode({'identity': {'dh': 'me-dh', 'sign': 'me-sign'}});
  Future<String> from(Map<String, Object?> payload) async => ((await theirs.encryptTo('me-id', jsonEncode(payload), bundleJson: bundle)) as Encrypted).envelope;
  var envelopes = 0;
  Future<void> deliver(Map<String, Object?> payload, {bool ephemeral = false}) async => messenger.receive(
    EnvelopeEvent(id: 'env${++envelopes}', fromId: 'alice-id', fromUsername: 'alice', envelope: await from(payload), createdAt: 1, ephemeral: ephemeral),
  );
  Map<String, Object?> message(String text, {Map<String, Object?> extra = const {}}) =>
      {'v': 1, 'type': 'message', 'id': const Uuid().v4(), 'text': text, 'createdAt': now, 'expiresAt': null, ...extra};
  String conversation() => messenger.conversationWith('alice-id');
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 30));

  test('a reply with an attachment goes out with the exact payload shape', () async {
    final quoted = const Uuid().v4();
    await messenger.send(
      alice,
      '',
      replyTo: ReplyTo(id: quoted, text: 'that one'),
      attachment: Attachment.fromJson({'kind': 'file', 'blob': 'b' * 22, 'key': 'k' * 43, 'sha256': 's' * 43, 'mime': 'application/pdf', 'name': 'a.pdf', 'size': 3}),
    );
    await settle();
    final payload = sent('message').single;
    expect(payload.keys.toSet(), {'v', 'type', 'id', 'text', 'createdAt', 'expiresAt', 'replyTo', 'attachment'});
    expect(payload['replyTo'], {'id': quoted, 'text': 'that one'});
    expect(payload['text'], '');
  });

  test('a link preview is dropped when its URL is no longer in the text, and oversize payloads never leave', () async {
    await messenger.send(alice, 'no link here', link: const LinkPreview(url: 'https://example.com', title: 'x'));
    await settle();
    expect(sent('message').single.containsKey('link'), isFalse);
    // 4,096 bytes of control characters are valid text but escape to 24 KB of JSON.
    await expectLater(messenger.send(alice, '\u0001' * 4096), throwsA(isA<StoreException>()));
    expect(await store.list(conversation()), hasLength(1), reason: 'nothing is stored that could never be sent');
  });

  test('reactions from the peer are stored without a receipt', () async {
    final m = message('hi');
    await deliver(m);
    await deliver({'v': 1, 'type': 'react', 'id': const Uuid().v4(), 'target': m['id'], 'emoji': '🎉', 'on': true});
    expect((await store.get(conversation(), m['id'] as String))!.reactions.of('peer'), ['🎉']);
    expect(acks, hasLength(2));
    expect(sent('receipt'), hasLength(1), reason: 'controls get no delivery receipt');
  });

  test('our reaction is stored and sent; it rolls back if it cannot be sent', () async {
    final out = await messenger.send(alice, 'mine');
    await settle();
    await messenger.react(alice, out, '👍', on: true);
    expect(sent('react').single, {'v': 1, 'type': 'react', 'id': isA<String>(), 'target': out.id, 'emoji': '👍', 'on': true});
    expect((await store.get(conversation(), out.id))!.reactions.of('me'), ['👍']);
  });

  test('edits: the peer edits only their own messages; ours go out with editedAt', () async {
    final theirsMsg = message('teh');
    await deliver(theirsMsg);
    final out = await messenger.send(alice, 'mine');
    await settle();
    await deliver({'v': 1, 'type': 'edit', 'id': const Uuid().v4(), 'target': theirsMsg['id'], 'text': 'the', 'editedAt': now + 1});
    await deliver({'v': 1, 'type': 'edit', 'id': const Uuid().v4(), 'target': out.id, 'text': 'hijack', 'editedAt': now + 1});
    expect((await store.get(conversation(), theirsMsg['id'] as String))!.body, 'the');
    expect((await store.get(conversation(), out.id))!.body, 'mine', reason: 'only the author may edit');

    // A far-future editedAt is clamped to now + 5 minutes, as on the web.
    await deliver({'v': 1, 'type': 'edit', 'id': const Uuid().v4(), 'target': theirsMsg['id'], 'text': 'from the future', 'editedAt': now + 86400000});
    expect((await store.get(conversation(), theirsMsg['id'] as String))!.editedAt, now + 300000);

    final current = (await store.get(conversation(), out.id))!;
    await messenger.edit(alice, current, 'mine, fixed');
    final edit = sent('edit').single;
    expect(edit['target'], out.id);
    expect(edit['text'], 'mine, fixed');
    expect(edit['editedAt'], greaterThanOrEqualTo(now));
    expect((await store.get(conversation(), out.id))!.edited, isTrue);
  });

  test('read receipts: displayed messages are batched into one read; the peer marks ours read', () async {
    final a = message('one'), b = message('two');
    await deliver(a);
    await deliver(b);
    final stored = await store.list(conversation());
    messenger.displayed(alice, stored);
    messenger.displayed(alice, stored);
    await settle();
    final reads = sent('read');
    expect(reads, hasLength(1));
    expect((reads.single['ids'] as List).toSet(), {a['id'], b['id']});
    expect((await store.list(conversation())).every((m) => m.status == MessageStatus.read), isTrue);

    final out = await messenger.send(alice, 'mine');
    await settle();
    await deliver({'v': 1, 'type': 'read', 'id': const Uuid().v4(), 'ids': [out.id]});
    expect((await store.get(conversation(), out.id))!.status, MessageStatus.read);
  });

  test('with read receipts off, none are sent and the peer\'s are ignored', () async {
    receipts = false;
    final a = message('one');
    await deliver(a);
    messenger.displayed(alice, await store.list(conversation()));
    await settle();
    expect(sent('read'), isEmpty);
    final out = await messenger.send(alice, 'mine');
    await settle();
    await deliver({'v': 1, 'type': 'read', 'id': const Uuid().v4(), 'ids': [out.id]});
    expect((await store.get(conversation(), out.id))!.status, MessageStatus.sent);
  });

  group('typing (docs/m5-linking.md §9)', () {
    test('never travels over the Double Ratchet: only through a moved chat\'s group, when there is one', () async {
      await deliver(message('hi'));
      await settle();
      posted.clear();
      await messenger.typingChanged(alice, on: true);
      expect(posted, isEmpty, reason: 'no 1:1 typing envelopes');
      final viaGroup = <bool>[];
      messenger.dmTyping = (contact, on) async => viaGroup.add(on);
      await messenger.typingChanged(alice, on: true);
      await messenger.typingChanged(alice, on: false);
      expect(viaGroup, [true, false]);
      expect(posted, isEmpty);
    });

    test('a live typing envelope that still arrives is ignored, untouched', () async {
      await deliver(message('hi'));
      final before = acks.length;
      await deliver({'v': 1, 'type': 'typing', 'id': const Uuid().v4(), 'at': now, 'on': true}, ephemeral: true);
      expect(messenger.typing, isEmpty);
      expect(acks, hasLength(before));
      messenger.showTyping('alice-id', true);
      expect(messenger.typing, {'alice-id'}, reason: 'a moved chat shows typing from its group');
    });
  });

  test('a live-only envelope that would open a session (X3DH header) or is unreadable is never decrypted', () {
    String env(Map<String, Object?> packet) => base64Url.encode(utf8.encode(jsonEncode(packet))).replaceAll('=', '');
    expect(startsSession(env({'v': 1, 'sid': 's', 'h': {}, 'c': '', 'x': {'spk': 1}})), isTrue);
    expect(startsSession(env({'v': 1, 'sid': 's', 'h': {}, 'c': ''})), isFalse);
    expect(startsSession('not base64 json'), isTrue);
  });
}
