import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:private_chat/core/pair_id.dart';
import 'package:private_chat/messaging/payload.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:uuid/uuid.dart';

/// Store schema v3 (docs/m4-groups.md §10) and v4 (m5 §8): the migrations, group conversations, and the group
/// rules for senders, mentions, read-by, system rows and the newest-500 eviction.
void main() {
  sqfliteFfiInit();
  final group = 'G' * 22, alice = 'a' * 22, bob = 'b' * 22;
  final dm = pairId('me', 'alice');
  var now = 1_700_000_000_000;
  late MessageStore store;
  setUp(() async {
    now = 1_700_000_000_000;
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath, now: () => now);
  });
  tearDown(() => store.close());

  Map<String, Object?> payload(String text, {Map<String, Object?> extra = const {}}) =>
      {'v': 1, 'type': 'message', 'id': const Uuid().v4(), 'text': text, 'createdAt': now, 'expiresAt': null, ...extra};

  test('a version 2 database upgrades to v3 in place, keeping messages, reactions and edits', () async {
    final dir = await Directory.systemTemp.createTemp('chat-v3');
    final path = p.join(dir.path, 'messages.db');
    final v2 = await databaseFactoryFfi.openDatabase(
      path,
      options: OpenDatabaseOptions(
        version: 2,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE messages (
              conversation_id TEXT NOT NULL, id TEXT NOT NULL, direction TEXT NOT NULL, text TEXT NOT NULL,
              created_at INTEGER NOT NULL, status TEXT NOT NULL, expires_at INTEGER,
              PRIMARY KEY (conversation_id, id))''');
          for (final column in ['reply_to TEXT', 'attachment TEXT', 'link TEXT', 'edited_text TEXT', 'edited_at INTEGER', 'reactions TEXT']) {
            await db.execute('ALTER TABLE messages ADD COLUMN $column');
          }
        },
      ),
    );
    final id = const Uuid().v4();
    await v2.insert('messages', {
      'conversation_id': dm, 'id': id, 'direction': 'incoming', 'text': 'from v2', 'created_at': now, 'status': 'delivered',
      'edited_text': 'edited in v2', 'edited_at': now + 1, 'reactions': '{"peer":["👍"]}',
    });
    await v2.close();

    final upgraded = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
    final kept = (await upgraded.list(dm)).single;
    expect((kept.text, kept.body), ('from v2', 'edited in v2'));
    expect(kept.reactions.of('peer'), ['👍']);
    expect(kept.sender, isNull);
    expect(kept.mentions, isEmpty);
    expect(kept.readBy, isEmpty);
    // The new parts work on the upgraded database.
    await upgraded.putGroup(GroupConversation(id: group, kind: GroupKindName.groupDm, createdAt: now, name: 'Friends'));
    expect(await upgraded.receive(group, payload('hi'), sender: alice, senderName: 'alice'), ReceiveResult.stored);
    expect((await upgraded.groups()).single.name, 'Friends');
    await upgraded.close();
    final again = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
    expect((await again.list(group)).single.senderName, 'alice', reason: 'reopening is a no-op');
    await again.close();
    await dir.delete(recursive: true);
  });

  test('a version 3 database upgrades to v4: groups keep their state, a DM group remembers its peer and move', () async {
    final dir = await Directory.systemTemp.createTemp('chat-v4');
    final path = p.join(dir.path, 'messages.db');
    // A v3 database: today's schema without the v4 columns.
    await (await MessageStore.open(databaseFactoryFfi, path, now: () => now)).close();
    final v3 = await databaseFactoryFfi.openDatabase(path);
    for (final column in ['moved_at', 'dm_checked_peer', 'peer']) {
      await v3.execute('ALTER TABLE conversations DROP COLUMN $column');
    }
    await v3.execute('DROP TABLE bundle_names');
    await v3.insert('conversations', {...GroupConversation(id: group, kind: GroupKindName.private, createdAt: now, name: 'design', cursor: 4).toRow()}..removeWhere((k, _) => ['peer', 'dm_checked_peer', 'moved_at'].contains(k)));
    await v3.setVersion(3);
    await v3.close();

    final upgraded = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
    final kept = (await upgraded.group(group))!;
    expect((kept.name, kept.cursor, kept.peer, kept.dmChecked, kept.movedAt), ('design', 4, null, false, null));
    final dmGroup = 'D' * 22;
    await upgraded.putGroup(GroupConversation(id: dmGroup, kind: GroupKindName.dm, createdAt: now, peer: alice));
    await upgraded.updateGroup(dmGroup, (g) => g.copyWith(dmCheckedPeer: alice, movedAt: now));
    final moved = (await upgraded.group(dmGroup))!;
    expect((moved.kind, moved.peer, moved.dmChecked, moved.movedAt), (GroupKindName.dm, alice, true, now));
    // A 1:1 chat's move is a system line in that chat.
    await upgraded.note(dm, 'Messages in this chat now use the new encryption.');
    expect((await upgraded.list(dm)).single.system, isTrue);
    await upgraded.close();
    await dir.delete(recursive: true);
  });

  test('a linked device imports its bundle history once: malformed records skipped, queued ones not resent', () async {
    final id = const Uuid().v4(), queued = const Uuid().v4();
    final records = [
      {'id': id, 'conversationId': dm, 'direction': 'incoming', 'text': 'imported', 'createdAt': now, 'status': 'read', 'expiresAt': null, 'reactions': {'me': ['👍']}},
      {'id': queued, 'conversationId': dm, 'direction': 'outgoing', 'text': 'never sent', 'createdAt': now, 'status': 'queued', 'expiresAt': null},
      {'id': 'not-a-uuid', 'conversationId': dm, 'direction': 'incoming', 'text': 'x', 'createdAt': now, 'status': 'read'},
      {'id': const Uuid().v4(), 'conversationId': group, 'direction': 'incoming', 'text': 'from alice', 'createdAt': now, 'status': 'delivered', 'from': alice, 'fromName': 'alice'},
      'junk',
    ];
    expect(await store.importLinked(records), 3);
    expect(await store.importLinked(records), 0, reason: 'already there');
    final list = await store.list(dm);
    expect(list.firstWhere((m) => m.id == id).reactions.of('me'), ['👍']);
    expect(list.firstWhere((m) => m.id == queued).status, MessageStatus.uncertain);
    expect(await store.queued(), isEmpty);
    expect((await store.list(group)).single.sender, alice);
  });

  test('channel names from a link bundle survive a restart and are used once', () async {
    final dir = await Directory.systemTemp.createTemp('chat-names');
    final path = p.join(dir.path, 'messages.db');
    final first = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
    await first.putBundleNames({group: (name: 'Design', topic: 'Pixels')});
    await first.close();
    final again = await MessageStore.open(databaseFactoryFfi, path, now: () => now);
    expect(await again.takeBundleName(group), (name: 'Design', topic: 'Pixels'));
    expect(await again.takeBundleName(group), isNull);
    await again.close();
    await dir.delete(recursive: true);
  });

  test("a DM's peer is bound once and its check counts only for that peer", () async {
    final id = 'D' * 22;
    await store.putGroup(GroupConversation(id: id, kind: GroupKindName.dm, createdAt: now, peer: alice));
    var g = (await store.updateGroup(id, (g) => g.copyWith(peer: bob, dmCheckedPeer: alice)))!;
    expect((g.peer, g.dmChecked), (alice, true), reason: 'never rebound');
    g = (await store.updateGroup(id, (g) => g.copyWith(dmCheckedPeer: bob)))!;
    expect(g.dmChecked, isFalse, reason: 'a check for someone else is no check');
    g = (await store.updateGroup(id, (g) => g.copyWith(dmCheckedPeer: alice)))!;
    g = (await store.updateGroup(id, (g) => g.copyWith(clearDmCheck: true)))!;
    expect((g.peer, g.dmChecked), (alice, false));
  });

  test('group records: create, update atomically, pin, unread, frozen, remove with history', () async {
    await store.putGroup(GroupConversation(id: group, kind: GroupKindName.private, createdAt: now));
    await store.updateGroup(group, (g) => g.copyWith(name: 'design', unread: 2, mentioned: true, pinned: true, cursor: 7, frozen: const Frozen(seq: 7, digest: 'd')));
    var g = (await store.group(group))!;
    expect((g.name, g.unread, g.mentioned, g.pinned, g.cursor, g.frozen?.seq), ('design', 2, true, true, 7, 7));
    g = (await store.updateGroup(group, (g) => g.copyWith(clearFrozen: true, membership: Membership.left)))!;
    expect(g.frozen, isNull);
    expect(g.membership, Membership.left);
    expect(await store.updateGroup('H' * 22, (g) => g), isNull);
    await store.receive(group, payload('x'), sender: alice);
    await store.removeGroup(group);
    expect(await store.group(group), isNull);
    expect(await store.list(group), isEmpty);
    expect(() => store.putGroup(GroupConversation(id: 'bad', kind: GroupKindName.private, createdAt: now)), throwsA(isA<StoreException>()));
  });

  test('incoming group messages name their sender; mentions only in groups', () async {
    await store.receive(group, payload('hey @bob', extra: {'mentions': [bob]}), sender: alice, senderName: 'alice');
    final m = (await store.list(group)).single;
    expect((m.sender, m.senderName), (alice, 'alice'));
    expect(m.mentions, [bob]);
    expect(m.toPayload()['mentions'], [bob]);
    await expectLater(store.receive(group, payload('no sender')), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'invalid')));
    await expectLater(store.receive(dm, payload('dm', extra: {'mentions': [bob]})), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'invalid')));
    for (final bad in [[], ['short'], [bob, bob], List.generate(65, (i) => '${i.toString().padLeft(2, '0')}${'x' * 20}')]) {
      expect(() => checkPayload('{"v":1,"type":"message","id":"${const Uuid().v4()}","text":"t","createdAt":1,"expiresAt":null,"mentions":${bad.map((e) => '"$e"').toList()}}'), throwsA(isA<PayloadException>()));
    }
  });

  test('reactions per member, edits only by their sender, read-by on our own messages', () async {
    final incoming = payload('theirs');
    await store.receive(group, incoming, sender: alice, senderName: 'alice');
    final id = incoming['id']! as String;
    expect(await store.react(group, id, who: bob, emoji: '👍', on: true), isTrue);
    expect(await store.react(group, id, who: 'me', emoji: '👍', on: true), isTrue);
    await expectLater(store.react(group, id, who: 'peer', emoji: '👍', on: true), throwsA(isA<StoreException>()));
    final r = (await store.get(group, id))!.reactions;
    expect(r.others('👍'), [bob]);
    expect((r.summary.single.count, r.summary.single.mine), (2, true));
    expect(await store.edit(group, id, text: 'forged', editedAt: now + 1, author: Direction.incoming, sender: bob), isFalse);
    expect(await store.edit(group, id, text: 'fixed', editedAt: now + 1, author: Direction.incoming, sender: alice), isTrue);
    final mine = await store.put(ChatMessage(id: const Uuid().v4(), conversationId: group, direction: Direction.outgoing, text: 'ours', createdAt: now, status: MessageStatus.sent));
    expect(await store.markReadBy(group, [mine.id, id], alice), [mine.id]);
    expect(await store.markReadBy(group, [mine.id], alice), isEmpty);
    expect((await store.get(group, mine.id))!.readBy, [alice]);
    await expectLater(store.markReadBy(dm, [mine.id], alice), throwsA(isA<StoreException>()));
  });

  test('system lines and the newest-500 eviction', () async {
    await store.note(group, 'alice added bob');
    expect((await store.list(group)).single.system, isTrue);
    for (var i = 0; i < groupKeep + 5; i++) {
      now++;
      await store.receive(group, payload('m$i'), sender: alice);
    }
    final list = await store.list(group);
    expect(list.length, groupKeep);
    expect(list.first.text, 'm5');
    expect(list.last.text, 'm504');
    // 1:1 chats still refuse the 501st incoming message.
    for (var i = 0; i < maxPerConversation; i++) {
      await store.receive(dm, payload('d$i'));
    }
    await expectLater(store.receive(dm, payload('one more')), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'conversation-full')));
  });

  test('meta and leave payload shapes', () {
    String meta(Object name, {Object topic = '', Object at = 1}) => '{"v":1,"type":"meta","id":"${const Uuid().v4()}","name":${name is String ? '"$name"' : name},"topic":"$topic","at":$at}';
    expect(checkPayload(meta('Design'))['type'], 'meta');
    expect(checkPayload(meta(''))['name'], '');
    expect(() => checkPayload(meta('x' * 65)), throwsA(isA<PayloadException>()));
    expect(() => checkPayload(meta('bad\\u0007')), throwsA(isA<PayloadException>()));
    expect(() => checkPayload(meta('ok', topic: 't' * 257)), throwsA(isA<PayloadException>()));
    expect(checkPayload('{"v":1,"type":"leave","id":"${const Uuid().v4()}"}')['type'], 'leave');
    expect(() => checkPayload('{"v":1,"type":"leave","id":"${const Uuid().v4()}","why":"x"}'), throwsA(isA<PayloadException>()));
  });
}
