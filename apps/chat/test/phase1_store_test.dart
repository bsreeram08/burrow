import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:private_chat/core/pair_id.dart';
import 'package:private_chat/messaging/payload.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:uuid/uuid.dart';

/// Phase 1 parts of the store and the payload checks (docs/phase1-protocol.md §1–§3).
void main() {
  sqfliteFfiInit();
  late MessageStore store;
  var now = 1_700_000_000_000;
  final a = pairId('me', 'alice');
  final key = 'A' * 43, sha = 'B' * 43, blob = 'C' * 22;

  setUp(() async {
    now = 1_700_000_000_000;
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath, now: () => now);
  });
  tearDown(() => store.close());

  Map<String, Object?> attachment([Map<String, Object?> extra = const {}]) => {
    'kind': 'image',
    'blob': blob,
    'key': key,
    'sha256': sha,
    'mime': 'image/jpeg',
    'name': 'photo.jpg',
    'size': 1234,
    'width': 800,
    'height': 600,
    'thumb': 'data:image/jpeg;base64,${base64.encode([1, 2, 3])}',
    ...extra,
  };

  Map<String, Object?> voice([Map<String, Object?> extra = const {}]) =>
      {'kind': 'voice', 'blob': blob, 'key': key, 'sha256': sha, 'mime': 'audio/mp4', 'name': 'voice.m4a', 'size': 10, 'duration': 2, 'waveform': [1, 2], ...extra};

  Map<String, Object?> payload({String? id, String text = 'hi', Map<String, Object?> extra = const {}}) => {
    'id': id ?? const Uuid().v4(),
    'text': text,
    'createdAt': now,
    'expiresAt': null,
    ...extra,
  };

  ChatMessage outgoing({String text = 'mine', MessageStatus status = MessageStatus.sent}) => ChatMessage(
    id: const Uuid().v4(),
    conversationId: a,
    direction: Direction.outgoing,
    text: text,
    createdAt: now,
    status: status,
  );

  Matcher invalid() => throwsA(isA<StoreException>().having((e) => e.code, 'code', 'invalid'));

  group('migration', () {
    test('a version 1 database upgrades in place and keeps every message', () async {
      final dir = await Directory.systemTemp.createTemp('chat-migrate');
      final path = p.join(dir.path, 'messages.db');
      final v1 = await databaseFactoryFfi.openDatabase(
        path,
        options: OpenDatabaseOptions(
          version: 1,
          onCreate: (db, _) async {
            await db.execute('''
              CREATE TABLE messages (
                conversation_id TEXT NOT NULL, id TEXT NOT NULL, direction TEXT NOT NULL, text TEXT NOT NULL,
                created_at INTEGER NOT NULL, status TEXT NOT NULL, expires_at INTEGER,
                PRIMARY KEY (conversation_id, id))''');
            await db.execute('CREATE INDEX messages_by_time ON messages (conversation_id, created_at)');
          },
        ),
      );
      final id = const Uuid().v4();
      await v1.insert('messages', {'conversation_id': a, 'id': id, 'direction': 'incoming', 'text': 'from before', 'created_at': now, 'status': 'delivered', 'expires_at': null});
      await v1.close();

      final upgraded = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
      final kept = (await upgraded.list(a)).single;
      expect(kept.text, 'from before');
      expect(kept.replyTo, isNull);
      expect(kept.reactions.isEmpty, isTrue);
      // The new columns work on the old row.
      expect(await upgraded.react(a, id, who: 'me', emoji: '👍', on: true), isTrue);
      expect((await upgraded.list(a)).single.reactions.of('me'), ['👍']);
      await upgraded.close();
      final reopened = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
      expect((await reopened.list(a)).single.reactions.of('me'), ['👍'], reason: 'upgrading twice is a no-op');
      await reopened.close();
      await dir.delete(recursive: true);
    });
  });

  group('rich messages', () {
    test('reply, attachment and link round-trip through the store', () async {
      final quoted = const Uuid().v4();
      final p = payload(
        text: 'see https://example.com/a',
        extra: {
          'replyTo': {'id': quoted, 'text': 'the original'},
          'attachment': attachment(),
          'link': {'url': 'https://example.com/a', 'title': 'Example', 'site': 'example.com'},
        },
      );
      expect(await store.receive(a, p), ReceiveResult.stored);
      final m = (await store.list(a)).single;
      expect(m.replyTo, ReplyTo(id: quoted, text: 'the original'));
      expect(m.attachment!.toJson(), attachment());
      expect(m.link!.title, 'Example');
      expect(m.toPayload().keys, containsAll(['replyTo', 'attachment', 'link']));
      expect(await store.receive(a, p), ReceiveResult.duplicate);
      await expectLater(store.receive(a, {...p, 'attachment': attachment({'size': 99})}), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'conflict')));
    });

    test('an attachment-only message has empty text; plain messages may not', () async {
      expect(await store.receive(a, payload(text: '', extra: {'attachment': attachment()})), ReceiveResult.stored);
      await expectLater(store.receive(a, payload(text: '')), invalid());
    });

    test('every malformed part is rejected deterministically as invalid', () async {
      final bad = <Map<String, Object?>>[
        payload(extra: {'replyTo': {'id': 'nope', 'text': 'x'}}),
        payload(extra: {'replyTo': {'id': const Uuid().v4(), 'text': 'x' * 141}}),
        payload(extra: {'replyTo': {'id': const Uuid().v4()}}),
        payload(extra: {'attachment': attachment({'kind': 'sticker'})}),
        payload(extra: {'attachment': attachment({'key': 'short'})}),
        payload(extra: {'attachment': attachment({'blob': 'x' * 23})}),
        payload(extra: {'attachment': attachment({'size': 25 * 1024 * 1024 + 1})}),
        payload(extra: {'attachment': attachment({'name': 'n' * 121})}),
        payload(extra: {'attachment': attachment({'name': ''})}),
        payload(extra: {'attachment': attachment({'mime': 'not a mime'})}),
        payload(extra: {'attachment': attachment({'extra': 1})}),
        payload(extra: {'attachment': attachment({'width': null})}),
        payload(extra: {'attachment': attachment({'width': 1.5})}),
        payload(extra: {'attachment': attachment({'thumb': 'data:image/png;base64,AAAA'})}),
        payload(extra: {'attachment': attachment({'thumb': 'data:image/jpeg;base64,${'A' * 5468}'})}),
        payload(extra: {'attachment': {...attachment(), 'kind': 'audio', 'width': 1}}),
        payload(extra: {'attachment': voice({'waveform': [32]})}),
        payload(extra: {'attachment': voice({'waveform': List.filled(65, 1)})}),
        payload(extra: {'attachment': voice({'width': 10})}),
        payload(extra: {'attachment': {...attachment(), 'kind': 'file', 'waveform': [1]}}),
        payload(extra: {'link': {'url': 'https://elsewhere.com'}}),
        payload(text: 'http://example.com', extra: {'link': {'url': 'http://example.com'}}),
        payload(text: 'https://example.com', extra: {'link': {'url': 'https://example.com', 'title': 't' * 201}}),
        payload(text: 'https://example.com', extra: {'link': {'url': 'https://example.com', 'site': 's' * 61}}),
      ];
      for (final p in bad) {
        await expectLater(store.receive(a, p), invalid(), reason: jsonEncode(p));
      }
      expect(await store.list(a), isEmpty);
    });

    test('names lose bidi and zero-width characters on receive, like the web store', () {
      expect(Attachment.fromJson(attachment({'name': 'invoice\u202Efdp.exe'})).name, 'invoicefdp.exe');
      expect(Attachment.fromJson(attachment({'name': '\u200B\u2066'})).name, 'file');
    });

    test('voice attachments carry duration and a 0–31 waveform', () async {
      expect(await store.receive(a, payload(text: '', extra: {'attachment': voice()})), ReceiveResult.stored);
      final webm = Attachment.fromJson({
        'kind': 'voice',
        'blob': blob,
        'key': key,
        'sha256': sha,
        'mime': 'audio/webm;codecs=opus',
        'name': 'voice.webm',
        'size': 2048,
        'duration': 3.4,
        'waveform': [0, 31, 12],
      });
      expect(Attachment.fromJson({...webm.toJson(), 'kind': 'audio'}).waveform, [0, 31, 12], reason: 'audio may carry a waveform too');
      expect(Attachment.fromJson({...attachment(), 'thumb': 'data:image/jpeg;base64,${base64.encode(List.filled(4000, 7))}'}).thumb, isNotNull,
          reason: 'up to 4 KB decoded is accepted, as on the web');
      expect(webm.duration, 3.4);
      expect(webm.audible, isTrue);
    });
  });

  group('reactions', () {
    test('each person has a set; on:false removes; unknown targets are ignored', () async {
      final m = await store.put(outgoing());
      expect(await store.react(a, m.id, who: 'peer', emoji: '❤️', on: true), isTrue);
      expect(await store.react(a, m.id, who: 'peer', emoji: '❤️', on: true), isFalse, reason: 'already set');
      expect(await store.react(a, m.id, who: 'me', emoji: '❤️', on: true), isTrue);
      expect(await store.react(a, m.id, who: 'peer', emoji: ':party_parrot:', on: true), isTrue);
      final r = (await store.get(a, m.id))!.reactions;
      expect(r.summary.first, (emoji: '❤️', count: 2, mine: true));
      expect(await store.react(a, m.id, who: 'peer', emoji: '❤️', on: false), isTrue);
      expect((await store.get(a, m.id))!.reactions.of('peer'), [':party_parrot:']);
      expect(await store.react(a, const Uuid().v4(), who: 'peer', emoji: '👍', on: true), isFalse);
    });

    test('at most 20 distinct emoji per message', () async {
      final m = await store.put(outgoing());
      const emoji = ['😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩', '😘', '😗', '😚', '😙', '😋'];
      for (final e in emoji.take(20)) {
        expect(await store.react(a, m.id, who: 'peer', emoji: e, on: true), isTrue);
      }
      expect(await store.react(a, m.id, who: 'me', emoji: emoji.last, on: true), isFalse);
      expect(await store.react(a, m.id, who: 'me', emoji: emoji.first, on: true), isTrue, reason: 'an existing emoji is not a new distinct one');
    });

    test('emoji validation', () {
      for (final ok in ['👍', '❤️', '👩‍👩‍👧', '1️⃣', '🇮🇳', ':custom_1:', ':+1:', ':thumbs-up:']) {
        expect(isReactionEmoji(ok), isTrue, reason: ok);
      }
      for (final bad in ['', 'a', 'é', '!!', 'ok', '👍👍', ':Bad:', ':x:', '<b>', ' ', ':${'x' * 40}:']) {
        expect(isReactionEmoji(bad), isFalse, reason: bad);
      }
    });
  });

  group('edits', () {
    test('only the author edits, the last editedAt wins, and the original stays a duplicate', () async {
      final p = payload(text: 'teh plan');
      await store.receive(a, p);
      final id = p['id'] as String;
      expect(await store.edit(a, id, text: 'the plan', editedAt: now + 10, author: Direction.incoming), isTrue);
      expect(await store.edit(a, id, text: 'older', editedAt: now + 5, author: Direction.incoming), isFalse);
      expect(await store.edit(a, id, text: 'not yours', editedAt: now + 20, author: Direction.outgoing), isFalse);
      final m = (await store.get(a, id))!;
      expect(m.body, 'the plan');
      expect(m.text, 'teh plan');
      expect(m.edited, isTrue);
      expect(await store.receive(a, p), ReceiveResult.duplicate, reason: 'a redelivered original is not a conflict');
      await expectLater(store.edit(a, id, text: '', editedAt: now + 30, author: Direction.incoming), invalid());
      expect(await store.edit(a, const Uuid().v4(), text: 'x', editedAt: now, author: Direction.incoming), isFalse);
    });

    test('attachments are not editable', () async {
      final p = payload(text: '', extra: {'attachment': attachment()});
      await store.receive(a, p);
      expect(await store.edit(a, p['id'] as String, text: 'caption', editedAt: now + 1, author: Direction.incoming), isFalse);
    });
  });

  group('read status', () {
    test('read follows delivered and is never downgraded; markRead touches one direction only', () async {
      final m = await store.put(outgoing());
      expect(await store.markRead(a, [m.id], direction: Direction.outgoing), [m.id]);
      expect(await store.setStatus(a, m.id, MessageStatus.delivered), isFalse);
      expect((await store.get(a, m.id))!.status, MessageStatus.read);
      final p = payload();
      await store.receive(a, p);
      expect(await store.markRead(a, [p['id'] as String], direction: Direction.outgoing), isEmpty);
      expect(await store.markRead(a, [p['id'] as String], direction: Direction.incoming), [p['id']]);
      // A late re-save of the outgoing record keeps its newer status.
      expect((await store.put(m)).status, MessageStatus.read);
    });
  });

  group('payload shapes', () {
    String json(Map<String, Object?> m) => jsonEncode({'v': 1, 'id': const Uuid().v4(), ...m});
    final target = const Uuid().v4();

    test('controls are accepted only in their exact shape', () {
      final good = [
        {'type': 'react', 'target': target, 'emoji': '👍', 'on': true},
        {'type': 'edit', 'target': target, 'text': 'fixed', 'editedAt': now},
        {'type': 'read', 'ids': [target]},
        {'type': 'typing', 'at': now, 'on': false},
        {'type': 'message', 'text': 'x', 'createdAt': now, 'expiresAt': null, 'replyTo': {'id': target, 'text': 'q'}},
        {'type': 'receipt'},
      ];
      for (final g in good) {
        expect(checkPayload(json(g))['type'], g['type']);
      }
      final bad = [
        {'type': 'react', 'target': target, 'emoji': 'ab', 'on': true},
        {'type': 'react', 'target': target, 'emoji': '👍', 'on': 'yes'},
        {'type': 'react', 'target': target, 'emoji': '👍', 'on': true, 'extra': 1},
        {'type': 'edit', 'target': 'x', 'text': 'fixed', 'editedAt': now},
        {'type': 'edit', 'target': target, 'text': 'x' * 4097, 'editedAt': now},
        {'type': 'read', 'ids': []},
        {'type': 'read', 'ids': List.filled(101, target)},
        {'type': 'read', 'ids': ['nope']},
        {'type': 'typing', 'at': 'now', 'on': true},
        {'type': 'message', 'text': 'x', 'createdAt': now, 'expiresAt': null, 'replyTo': null},
        {'type': 'message', 'text': 'x', 'createdAt': now, 'expiresAt': null, 'kind': 'poll'},
        {'type': 'unknown'},
      ];
      for (final b in bad) {
        expect(() => checkPayload(json(b)), throwsA(isA<PayloadException>()), reason: jsonEncode(b));
      }
    });

    test('the whole payload must fit in 16 KB', () {
      final big = json({'type': 'message', 'text': 'x', 'createdAt': now, 'expiresAt': null, 'pad': 'x' * maxPayloadBytes});
      expect(() => checkPayload(big), throwsA(isA<PayloadException>()));
      expect(() => encodePayload({'v': 1, 'pad': 'x' * maxPayloadBytes}), throwsA(isA<StoreException>()));
    });

    test('toPayload omits absent parts and keeps expiresAt null, like the web client', () {
      final m = outgoing(text: 'plain');
      expect(m.toPayload(), {'v': 1, 'type': 'message', 'id': m.id, 'text': 'plain', 'createdAt': now, 'expiresAt': null});
    });

    test('reply previews are one line, at most 140 characters, whole graphemes', () {
      final r = ReplyTo.preview(target, 'line one\nline two ${'👍' * 200}');
      expect(r.text.startsWith('line one line two'), isTrue);
      expect(r.text.length, lessThanOrEqualTo(140));
      expect(() => ReplyTo.fromJson(r.toJson()), returnsNormally);
    });
  });
}
