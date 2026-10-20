import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/messaging/group_messenger.dart';
import 'package:private_chat/messaging/group_sync.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import 'support/fake_ds.dart';

/// Group messaging (docs/m4-groups.md §4–§6, §10) through the real GroupMessenger, GroupSync and store,
/// with fake MLS and an in-memory delivery service: Phase 1 payloads in groups, mentions, per-person
/// reactions, read-by, typing, meta, system lines and leaving.
class Member {
  Member._(this.user, this.messenger, this.store, this.chat);
  final User user;
  final GroupMessenger messenger;
  final MessageStore store;
  final FakeChatCrypto chat;
  String? viewing;

  static Future<Member> start(FakeDs ds, String name, {List<Contact> contacts = const []}) async {
    final user = User(id: '${name}_${'x' * (21 - name.length)}', username: name);
    final device = await localDevice(MemoryDevicePrefs(), user.id);
    final api = ds.client(userId: user.id, username: name, deviceId: device.deviceId);
    final store = await MessageStore.open(databaseFactoryFfi, '${Directory.systemTemp.createTempSync('group-messenger').path}/m.db');
    final chat = FakeChatCrypto();
    late Member member;
    final sync = GroupSync(
      api: api,
      crypto: FakeGroupCrypto(userId: user.id),
      store: store,
      me: user,
      device: () async => device,
      platform: 'ios',
      ensurePinned: (ids) => member.messenger.ensurePinned(ids),
      pinProblem: (ids) => member.messenger.pinProblem(ids),
      backoff: (_) => Duration.zero,
    );
    final messenger = GroupMessenger(api: api, sync: sync, chatCrypto: chat, store: store, me: user, contacts: () => contacts, viewing: () => member.viewing);
    member = Member._(user, messenger, store, chat);
    ds.listen(device.deviceId, (event) => unawaited(messenger.onEvent(event).catchError((_) {})));
    await messenger.start();
    return member;
  }

  Future<List<ChatMessage>> list(String groupId) => store.list(groupId);
}

Future<T> eventually<T>(Future<T> Function() read, bool Function(T value) ok, [String what = 'condition']) async {
  late T value;
  for (var i = 0; i < 300; i++) {
    value = await read();
    if (ok(value)) return value;
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  fail('$what: $value');
}

void main() {
  sqfliteFfiInit();
  late FakeDs ds;
  late Member alice, bob, carol;
  setUp(() async {
    ds = FakeDs();
    alice = await Member.start(ds, 'alice');
    bob = await Member.start(ds, 'bob');
    carol = await Member.start(ds, 'carol');
  });
  tearDown(() async {
    for (final m in [alice, bob, carol]) {
      await m.messenger.dispose();
      await m.store.close();
    }
  });

  Future<String> team() async {
    final group = await alice.messenger.create(GroupKindName.private, name: 'Design', topic: 'Pixels', memberIds: [bob.user.id, carol.user.id]);
    await eventually(() => bob.store.group(group.id), (g) => g?.name == 'Design' && g?.topic == 'Pixels', 'bob learned the name from meta');
    await eventually(() => carol.store.group(group.id), (g) => g?.name == 'Design', 'carol learned the name');
    return group.id;
  }

  test('create: members join, learn the name and topic, and see who added whom', () async {
    final id = await team();
    expect((await alice.store.group(id))!.name, 'Design');
    expect((await alice.messenger.members(id)).map((m) => m.username), ['alice', 'bob', 'carol']);
    expect((await alice.messenger.members(id)).firstWhere((m) => m.username == 'alice').admin, isTrue);
    // The non-contacts were pinned on first use.
    expect(await bob.chat.safety('bob', alice.user.id, 'alice'), isNotNull);
    expect(await bob.chat.safety('bob', carol.user.id, 'carol'), isNotNull);
  });

  test('messages with replies, mentions, reactions per person, edits and read-by', () async {
    final id = await team();
    final hello = await alice.messenger.send(id, 'hello @bob and @nobody');
    expect(hello.mentions, [bob.user.id]);
    final got = await eventually(() => bob.list(id), (l) => l.any((m) => m.id == hello.id));
    final incoming = got.firstWhere((m) => m.id == hello.id);
    expect((incoming.sender, incoming.senderName), (alice.user.id, 'alice'));
    expect(incoming.mentions, [bob.user.id]);
    final bobGroup = (await bob.store.group(id))!;
    expect(bobGroup.unread, 1);
    expect(bobGroup.mentioned, isTrue);
    expect((await carol.store.group(id))!.mentioned, isFalse);
    await eventually(() => alice.list(id), (l) => l.firstWhere((m) => m.id == hello.id).status == MessageStatus.sent);

    // Reply and per-person reactions.
    await bob.messenger.send(id, 'on it', replyTo: ReplyTo.preview(hello.id, hello.text));
    await bob.messenger.react(id, incoming, '👍', on: true);
    final carolsCopy = (await eventually(() => carol.list(id), (l) => l.any((m) => m.id == hello.id))).firstWhere((m) => m.id == hello.id);
    await carol.messenger.react(id, carolsCopy, '👍', on: true);
    await carol.messenger.react(id, carolsCopy, '🎉', on: true);
    final reacted = await eventually(() => alice.store.get(id, hello.id), (m) => m!.reactions.others('👍').length == 2 && m.reactions.of(carol.user.id).contains('🎉'));
    expect(reacted!.reactions.others('👍').toSet(), {bob.user.id, carol.user.id});
    final reply = (await eventually(() => alice.list(id), (l) => l.any((m) => m.text == 'on it'))).firstWhere((m) => m.text == 'on it');
    expect(reply.replyTo?.id, hello.id);

    // Edit: alice's applies; carol can't edit alice's message.
    final sent = (await alice.store.get(id, hello.id))!;
    await alice.messenger.edit(id, sent, 'hello @bob (edited)');
    await eventually(() => bob.store.get(id, hello.id), (m) => m!.body == 'hello @bob (edited)');
    expect(await carol.store.edit(id, hello.id, text: 'forged', editedAt: DateTime.now().millisecondsSinceEpoch + 5, author: Direction.incoming, sender: carol.user.id), isFalse);

    // Read-by: read once everyone else has read it.
    bob.messenger.displayed(id, [incoming]);
    await eventually(() => alice.store.get(id, hello.id), (m) => m!.readBy.contains(bob.user.id));
    expect((await alice.store.get(id, hello.id))!.status, MessageStatus.sent);
    carol.messenger.displayed(id, [carolsCopy]);
    await eventually(() => alice.store.get(id, hello.id), (m) => m!.status == MessageStatus.read, 'read by everyone');
  });

  test('typing is live-only and names who is typing', () async {
    final id = await team();
    final seen = <Map<String, List<String>>>[];
    final sub = bob.messenger.typingChanges.listen(seen.add);
    await alice.messenger.typingChanged(id, on: true);
    await eventually(() async => seen, (s) => s.any((t) => t[id]?.contains(alice.user.id) ?? false), 'bob sees alice typing');
    expect(ds.channels[id]!.log.where((e) => e['kind'] == 'app').length, 1, reason: 'only the meta is in the log');
    await sub.cancel();
    expect(typingLine(['alice']), 'alice is typing');
    expect(typingLine(['alice', 'bob']), 'alice and bob are typing');
    expect(typingLine(['a', 'b', 'c']), '3 people are typing');
  });

  test('leave: an admin removes the leaver, everyone sees "carol left"', () async {
    final id = await team();
    await carol.messenger.leave(id);
    expect((await carol.store.group(id))!.membership, Membership.left);
    await eventually(() => alice.messenger.members(id, refresh: true), (m) => m.length == 2, 'alice removed carol');
    await eventually(() => bob.list(id), (l) => l.any((m) => m.system && m.text == 'carol left'));
    // Carol no longer gets anything; she acknowledged without processing.
    await alice.messenger.send(id, 'after carol');
    await eventually(() => bob.list(id), (l) => l.any((m) => m.text == 'after carol'));
    expect((await carol.list(id)).any((m) => m.text == 'after carol'), isFalse);
  });

  test('the only admin who leaves hands the role to the earliest member first', () async {
    final id = await team();
    await alice.messenger.leave(id);
    await eventually(() => bob.messenger.isAdmin(id, bob.user.id), (admin) => admin, 'bob became an admin');
    await eventually(() => bob.messenger.members(id, refresh: true), (m) => m.map((p) => p.username).toList().join() == 'bobcarol');
  });

  test('meta from a non-admin is ignored; removal writes a system line', () async {
    final id = await team();
    await bob.messenger.sync.send(id, '{"v":1,"type":"meta","id":"00000000-0000-4000-8000-000000000001","name":"Hijacked","topic":"","at":${DateTime.now().millisecondsSinceEpoch + 1000}}');
    await alice.messenger.removeMember(id, bob.user.id);
    await eventually(() => carol.list(id), (l) => l.any((m) => m.system && m.text == 'alice removed bob'));
    expect((await carol.store.group(id))!.name, 'Design');
    await eventually(() => bob.store.group(id), (g) => g!.membership == Membership.removed);
  });

  test('public channels: directory and external join', () async {
    final channel = await alice.messenger.create(GroupKindName.public, name: 'general');
    final listed = await bob.messenger.directory();
    expect(listed.single['name'], 'general');
    await bob.messenger.joinPublic(channel.id);
    await eventually(() => alice.list(channel.id), (l) => l.any((m) => m.system && m.text == 'bob joined'));
    await bob.messenger.send(channel.id, 'hi all');
    await eventually(() => alice.list(channel.id), (l) => l.any((m) => m.text == 'hi all' && m.senderName == 'bob'));
  });
}
