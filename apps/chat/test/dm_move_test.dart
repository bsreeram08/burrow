import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/chat_crypto.dart' show Encrypted, Identity;
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/messaging/group_messenger.dart';
import 'package:private_chat/messaging/group_sync.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:uuid/uuid.dart';

import 'support/fake_ds.dart';

/// A 1:1 chat moving from the Double Ratchet to its DM group (docs/m5-linking.md §8) through the real Messenger,
/// GroupMessenger, GroupSync and store, with fake crypto and an in-memory server.
class Person {
  Person._(this.user, this.messenger, this.groups, this.store, this.mls);
  final User user;
  final Messenger messenger;
  final GroupMessenger groups;
  final MessageStore store;
  final FakeGroupCrypto mls;
  String? viewing;

  Contact get contact => Contact(id: user.id, username: user.username, state: ContactState.mutual, online: true);

  static Future<Person> start(FakeDs ds, String name, {required List<Contact> Function() contacts, String? userId, bool companion = false}) async {
    final user = User(id: userId ?? '${name}_${'x' * (21 - name.length)}', username: name.replaceAll(RegExp(r'\d'), ''));
    final device = await localDevice(MemoryDevicePrefs(), user.id);
    final api = ds.client(userId: user.id, username: user.username, deviceId: device.deviceId);
    final store = await MessageStore.open(databaseFactoryFfi, '${Directory.systemTemp.createTempSync('dm-move').path}/m.db');
    final chat = FakeChatCrypto(me: Identity(dh: 'dh-${user.id}', sign: 'sign-${user.id}'));
    final mls = FakeGroupCrypto(userId: user.id);
    late Person person;
    final messenger = Messenger(
      api: api,
      crypto: chat,
      store: store,
      me: user,
      contactById: (id) => contacts().where((c) => c.id == id).firstOrNull,
      mutualContacts: contacts,
      ack: (_) {},
      viewing: () => person.viewing,
    )
      ..moveChats = false
      ..companion = companion;
    // A linked device's MLS certificate came with its link grant (modelled here by the fake's own).
    if (companion) await mls.initDevice(userId: user.id, deviceId: device.deviceId, platform: 'macos', issuedAt: 1);
    final sync = GroupSync(
      api: api,
      crypto: mls,
      store: store,
      me: user,
      device: () async => device,
      platform: 'ios',
      ensurePinned: (ids, {force = false}) => person.groups.ensurePinned(ids, force: force),
      backoff: (_) => Duration.zero,
      companion: companion,
    );
    final groups = GroupMessenger(api: api, sync: sync, chatCrypto: chat, store: store, me: user, contacts: contacts);
    messenger.groups = groups;
    person = Person._(user, messenger, groups, store, mls);
    ds.listen(device.deviceId, (event) {
      if (event is EnvelopeEvent) {
        unawaited(messenger.receive(event));
      } else {
        unawaited(groups.onEvent(event).catchError((_) {}));
      }
    });
    await messenger.checkActive();
    await groups.start();
    return person;
  }

  Future<List<ChatMessage>> chat(Person other) => store.list(messenger.conversationWith(other.user.id));

  Future<void> close() async {
    await groups.dispose();
    await messenger.dispose();
    await store.close();
  }
}

Future<T> eventually<T>(Future<T> Function() read, bool Function(T value) ok, [String what = 'condition']) async {
  late T value;
  for (var i = 0; i < 400; i++) {
    value = await read();
    if (ok(value)) return value;
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  fail('$what: $value');
}

void main() {
  sqfliteFfiInit();
  late FakeDs ds;
  late Person alice, bob;
  final people = <Person>[];
  setUp(() async {
    ds = FakeDs();
    people.clear();
    late Contact aliceContact, bobContact;
    alice = await Person.start(ds, 'alice', contacts: () => [bobContact]);
    bob = await Person.start(ds, 'bob', contacts: () => [aliceContact]);
    aliceContact = alice.contact;
    bobContact = bob.contact;
    people.addAll([alice, bob]);
  });
  tearDown(() async {
    for (final p in people) {
      await p.close();
    }
  });

  bool has(List<ChatMessage> list, String text, Direction direction) => list.any((m) => m.text == text && m.direction == direction);

  test('the first sender moves the chat: pointer over the Double Ratchet, then everything through the DM group', () async {
    // On the Double Ratchet first.
    await alice.messenger.send(bob.contact, 'over the ratchet');
    await eventually(() => bob.chat(alice), (l) => has(l, 'over the ratchet', Direction.incoming));
    final before = ds.envelopes.length;

    alice.messenger.moveChats = true;
    final moved = await alice.messenger.send(bob.contact, 'first through MLS');
    final dm = await eventually(() => alice.store.groups(), (g) => g.any((x) => x.movedAt != null), 'alice moved the chat');
    final channel = dm.single;
    expect((channel.kind, channel.peer, channel.dmChecked), (GroupKindName.dm, bob.user.id, true));
    await eventually(() => alice.store.get(alice.messenger.conversationWith(bob.user.id), moved.id), (m) => m?.status == MessageStatus.sent);
    // Exactly one more Double Ratchet message: the pointer. The message itself went through the group.
    expect(ds.envelopes.length - before, 1);
    expect(ds.channels[channel.id]!.log.where((e) => e['kind'] == 'app'), hasLength(1));

    // Bob accepted it: joined, checked against the pins, moved; history continues under the pairId.
    await eventually(() => bob.store.group(channel.id), (g) => g?.movedAt != null && g?.dmChecked == true, 'bob accepted the pointer');
    final bobsChat = await eventually(() => bob.chat(alice), (l) => has(l, 'first through MLS', Direction.incoming));
    expect(has(bobsChat, 'over the ratchet', Direction.incoming), isTrue);
    expect(bobsChat.where((m) => m.direction == Direction.system).map((m) => m.text), [dmMovedNote]);
    expect(bob.messenger.unread[alice.user.id], 2);

    // Bob's reply, reaction and read go through the group too, never the ratchet.
    final afterPointer = ds.envelopes.length;
    await bob.messenger.send(alice.contact, 'reply via MLS');
    await eventually(() => alice.chat(bob), (l) => has(l, 'reply via MLS', Direction.incoming));
    final incoming = bobsChat.firstWhere((m) => m.text == 'first through MLS');
    await bob.messenger.react(alice.contact, incoming, '👍', on: true);
    await eventually(() => alice.store.get(alice.messenger.conversationWith(bob.user.id), moved.id), (m) => m!.reactions.of('peer').contains('👍'));
    bob.messenger.displayed(alice.contact, [incoming]);
    await eventually(() => alice.store.get(alice.messenger.conversationWith(bob.user.id), moved.id), (m) => m?.status == MessageStatus.read, 'read via the group');
    expect(ds.envelopes.length, afterPointer, reason: 'nothing more over the Double Ratchet');

    // Typing: live through the group only.
    // Live-only: a hint sent while the channel's queue is busy is dropped by design, so the composer says it again.
    await eventually(() async {
      await bob.messenger.typingChanged(alice.contact, on: false);
      await bob.messenger.typingChanged(alice.contact, on: true);
      await Future<void>.delayed(const Duration(milliseconds: 20));
      return alice.messenger.typing;
    }, (t) => t.contains(bob.user.id), 'typing via the group');
    expect(ds.envelopes.length, afterPointer);
  });

  test('a pointer to a group that is not our DM is ignored and the chat stays on the Double Ratchet', () async {
    // Bob makes an ordinary private channel with alice and points at it as if it were their DM.
    final channel = await bob.groups.create(GroupKindName.private, name: 'not a dm', memberIds: [alice.user.id]);
    await eventually(() => alice.store.group(channel.id), (g) => g != null);
    final pointer = {'v': 1, 'type': 'mls-dm', 'id': const Uuid().v4(), 'channel': channel.id, 'at': DateTime.now().millisecondsSinceEpoch};
    final sealed = await bob.messenger.crypto.encryptTo(alice.user.id, jsonEncode(pointer), bundleJson: jsonEncode({'identity': {'dh': 'dh-${alice.user.id}', 'sign': 'sign-${alice.user.id}'}}));
    await bob.messenger.api.postEnvelope('alice', (sealed as Encrypted).envelope);
    await eventually(() => alice.chat(bob), (l) => l.any((m) => m.text == dmMovedNote));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(await alice.groups.acceptDm(channel.id, bob.user.id), isFalse, reason: 'not a DM group');
    expect(await alice.groups.dmChannelWith(bob.user.id), isNull);
    final before = ds.envelopes.length;
    await alice.messenger.send(bob.contact, 'still on the ratchet');
    await eventually(() async => ds.envelopes.length, (n) => n > before);
  });

  test('before its check, a DM group delivers nothing and shows no typing', () async {
    bob.mls.unpinned.add(alice.user.id); // Bob's core can't chain alice's leaves to a pin: mlsCheckDm fails.
    final channel = await alice.groups.createDm(bob.contact);
    await eventually(() => bob.store.group(channel!), (g) => g != null, 'bob joined from the Welcome');
    expect((await bob.store.group(channel!))!.dmChecked, isFalse);
    await alice.groups.typingChanged(channel, on: true);
    await alice.groups.sendDm(channel, {'v': 1, 'type': 'message', 'id': const Uuid().v4(), 'text': 'unchecked', 'createdAt': DateTime.now().millisecondsSinceEpoch, 'expiresAt': null});
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(bob.messenger.typing, isEmpty);
    expect(await bob.chat(alice), isEmpty);
  });

  test('both sides moving at once: the second create is refused (409) and its local group forgotten', () async {
    final first = await alice.groups.createDm(bob.contact);
    expect(first, isNotNull);
    final second = await bob.groups.createDm(alice.contact);
    expect(second, isNull);
    expect(bob.mls.groups.where((g) => g != first), isEmpty, reason: 'the losing local group is gone');
  });

  test('a DM group whose pointer never went out is pointed at on the next send, not left stuck', () async {
    final channel = await alice.groups.createDm(bob.contact);
    expect(channel, isNotNull);
    alice.messenger.moveChats = true;
    await alice.messenger.send(bob.contact, 'after a lost pointer');
    await eventually(() => bob.store.group(channel!), (g) => g?.movedAt != null, 'bob accepted the late pointer');
    await eventually(() => bob.chat(alice), (l) => has(l, 'after a lost pointer', Direction.incoming));
    expect(ds.channels.values.where((c) => c.kind == 'dm'), hasLength(1));
  });

  test('a moved chat reaches our own other device: our messages are ours, theirs are theirs', () async {
    late Contact bobContact;
    final laptop = await Person.start(ds, 'alice2', contacts: () => [bobContact], userId: alice.user.id);
    bobContact = bob.contact;
    people.add(laptop);
    alice.messenger.moveChats = true;
    await alice.messenger.send(bob.contact, 'from the phone');
    final group = await eventually(() => laptop.store.groups(), (g) => g.any((x) => x.kind == GroupKindName.dm), 'the laptop got the Welcome');
    expect(group.single.peer, bob.user.id);
    await eventually(() => bob.store.group(group.single.id), (g) => g?.movedAt != null);
    await bob.messenger.send(alice.contact, 'to both');
    await alice.messenger.send(bob.contact, 'another from the phone');
    final seen = await eventually(() => laptop.chat(bob), (l) => has(l, 'to both', Direction.incoming) && has(l, 'another from the phone', Direction.outgoing));
    expect(seen.firstWhere((m) => m.text == 'another from the phone').status, MessageStatus.sent);
  });

  test('a linked device (no account keys) sends only once the chat moved, through the DM group', () async {
    late Contact bobContact;
    final laptop = await Person.start(ds, 'alice2', contacts: () => [bobContact], userId: alice.user.id, companion: true);
    bobContact = bob.contact;
    people.add(laptop);
    expect(laptop.messenger.active, isFalse);
    final before = ds.envelopes.length;
    final early = await laptop.messenger.send(bob.contact, 'from the laptop, early');
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect((await laptop.store.get(laptop.messenger.conversationWith(bob.user.id), early.id))!.status, MessageStatus.queued, reason: 'waits for the move');
    expect(ds.envelopes.length, before, reason: 'never over the Double Ratchet');

    alice.messenger.moveChats = true;
    await alice.messenger.send(bob.contact, 'moving');
    final dm = await eventually(() => laptop.groups.dmChannelWith(bob.user.id), (c) => c != null, 'the laptop holds the checked DM group');
    expect(dm, isNotNull);
    await laptop.messenger.flush();
    await eventually(() => bob.chat(alice), (l) => has(l, 'from the laptop, early', Direction.incoming), 'bob got the laptop message');
    await eventually(() => alice.chat(bob), (l) => has(l, 'from the laptop, early', Direction.outgoing), 'the phone stores it as ours');
  });
}
