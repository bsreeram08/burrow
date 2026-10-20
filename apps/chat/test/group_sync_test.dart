import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' show sha256;

import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/fake_group_crypto.dart';
import 'package:private_chat/crypto/group_crypto.dart';
import 'package:private_chat/messaging/group_sync.dart';
import 'package:private_chat/store/message.dart' show StoreException;
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import 'support/fake_ds.dart';

/// The MLS transport (GroupSync) against the fake delivery service: create, add, Welcome, the log in
/// order with cursors, 409 rebuild-and-retry, removal, and the poison-commit protocol.
class Party {
  Party._(this.user, this.sync, this.crypto, this.store, this.delivered);
  final User user;
  final GroupSync sync;
  final FakeGroupCrypto crypto;
  final MessageStore store;
  final List<GroupDelivery> delivered;

  static Future<Party> join(FakeDs ds, String name) async {
    final user = User(id: '${name}_${'x' * (21 - name.length)}', username: name);
    final prefs = MemoryDevicePrefs();
    final device = await localDevice(prefs, user.id);
    final api = ds.client(userId: user.id, username: name, deviceId: device.deviceId);
    // One database per party (in-memory paths are shared single instances).
    final store = await MessageStore.open(databaseFactoryFfi, '${Directory.systemTemp.createTempSync('group-sync').path}/m.db');
    final crypto = FakeGroupCrypto(userId: user.id);
    final delivered = <GroupDelivery>[];
    final sync = GroupSync(
      api: api,
      crypto: crypto,
      store: store,
      me: user,
      device: () async => device,
      platform: 'ios',
      ensurePinned: (_, {force = false}) async => const <String>[],
      backoff: (_) => Duration.zero,
    )..onDelivery = (d) async => delivered.add(d);
    ds.listen(device.deviceId, (event) {
      switch (event) {
        case GroupEvent():
          unawaited(sync.onGroupFrame(event));
        case WelcomeEvent():
          unawaited(sync.onWelcome(event));
        case ChannelEvent():
          unawaited(sync.onChannel(event));
        default:
      }
    });
    await sync.ensureReady();
    return Party._(user, sync, crypto, store, delivered);
  }
}

Future<void> settle() async {
  for (var i = 0; i < 20; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Future<void> until(bool Function() test, [String what = 'condition']) async {
  for (var i = 0; i < 200 && !test(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  expect(test(), isTrue, reason: what);
}

void main() {
  sqfliteFfiInit();
  late FakeDs ds;
  late Party alice, bob;
  setUp(() async {
    ds = FakeDs();
    alice = await Party.join(ds, 'alice');
    bob = await Party.join(ds, 'bob');
  });

  test('KeyPackages are stocked: 100 one-time and a last-resort one', () async {
    final count = await ds.client(userId: bob.user.id, username: 'bob', deviceId: bob.crypto.deviceId).keyPackageCount();
    expect(count['oneTime'], 100);
    expect(count['lastResort'], isTrue);
  });

  test('create, add, Welcome, messages both ways, cursors advance', () async {
    final group = await alice.sync.create(GroupKindName.private, name: 'Team');
    await alice.sync.add(group.id, [bob.user.id]);
    await until(() => bob.crypto.groups.contains(group.id), 'bob joined from the Welcome');
    await until(() => ds.welcomes[bob.crypto.deviceId]?.isEmpty ?? true, 'the Welcome was removed');
    expect((await bob.store.group(group.id))?.kind, GroupKindName.private);
    await alice.sync.send(group.id, '{"n":1}');
    await until(() => bob.delivered.isNotEmpty, 'bob received');
    expect(bob.delivered.single.plaintext, '{"n":1}');
    expect(bob.delivered.single.sender.userId, alice.user.id);
    await bob.sync.send(group.id, '{"n":2}');
    await until(() => alice.delivered.isNotEmpty, 'alice received');
    expect(alice.delivered.single.plaintext, '{"n":2}');
    await settle();
    expect((await alice.store.group(group.id))!.cursor, 3);
    expect((await bob.store.group(group.id))!.cursor, 3);
    expect(ds.channels[group.id]!.members[bob.crypto.deviceId]!.cursor, 3);
  });

  test('a 409 drops the commit, catches up and rebuilds', () async {
    final group = await alice.sync.create(GroupKindName.groupDm);
    ds.conflicts = 2;
    await alice.sync.add(group.id, [bob.user.id]);
    expect(ds.conflicts, 0);
    expect(await alice.crypto.pendingCommit(group.id), isNull);
    await until(() => bob.crypto.groups.contains(group.id));
    expect((await alice.crypto.members(group.id)).map((m) => m.userId).toSet(), {alice.user.id, bob.user.id});
  });

  test('a message sent while the group moved on is rebuilt for the new epoch', () async {
    final group = await alice.sync.create(GroupKindName.private);
    await alice.sync.add(group.id, [bob.user.id]);
    await until(() => bob.crypto.groups.contains(group.id));
    // Alice's next epoch lands on the server before bob processed it: bob's message is refused, then rebuilt.
    final carol = await Party.join(ds, 'carol');
    ds.listeners.remove(bob.crypto.deviceId);
    await alice.sync.add(group.id, [carol.user.id]);
    await bob.sync.send(group.id, '{"late":true}');
    await until(() => alice.delivered.any((d) => d.plaintext == '{"late":true}'));
    await until(() => carol.delivered.any((d) => d.plaintext == '{"late":true}'));
  });

  test('removal: the removed member stops, the others carry on', () async {
    final carol = await Party.join(ds, 'carol');
    final group = await alice.sync.create(GroupKindName.private);
    await alice.sync.add(group.id, [bob.user.id, carol.user.id]);
    await until(() => bob.crypto.groups.contains(group.id) && carol.crypto.groups.contains(group.id));
    await alice.sync.remove(group.id, bob.user.id);
    await until(() => true);
    await settle();
    await until(() => (bob.store.group(group.id) as dynamic) != null);
    var removed = false;
    for (var i = 0; i < 100 && !removed; i++) {
      removed = (await bob.store.group(group.id))!.membership == Membership.removed;
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
    expect(removed, isTrue);
    await alice.sync.send(group.id, '{"after":true}');
    await until(() => carol.delivered.any((d) => d.plaintext == '{"after":true}'));
    expect(bob.delivered.where((d) => d.plaintext == '{"after":true}'), isEmpty);
  });

  test('a commit every member rejects is reported, freezes the channel, and an admin rolls it back', () async {
    final carol = await Party.join(ds, 'carol');
    final group = await alice.sync.create(GroupKindName.private);
    await alice.sync.add(group.id, [bob.user.id, carol.user.id]);
    await until(() => bob.crypto.groups.contains(group.id) && carol.crypto.groups.contains(group.id));
    // Bob (not an admin) sends a commit removing carol: the delivery service can't tell, every member refuses it.
    final api = ds.client(userId: bob.user.id, username: 'bob', deviceId: bob.crypto.deviceId);
    String encode(Object v) => base64Url.encode(utf8.encode(jsonEncode(v))).replaceAll('=', '');
    final me = {'userId': bob.user.id, 'deviceId': bob.crypto.deviceId, 'platform': 'ios'};
    final victim = {'userId': carol.user.id, 'deviceId': carol.crypto.deviceId, 'platform': 'ios'};
    await api.postCommit(group.id, encode({'t': 'commit', 'g': group.id, 'epoch': ds.channels[group.id]!.epoch, 'from': me, 'adds': [], 'removes': [victim], 'n': 999}));
    await until(() => ds.channels[group.id]!.frozen != null, 'reported');
    var frozen = await alice.store.group(group.id);
    for (var i = 0; i < 100 && frozen?.frozen == null; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 5));
      frozen = await alice.store.group(group.id);
    }
    expect(frozen!.frozen, isNotNull);
    final check = await alice.sync.checkFrozen(group.id);
    expect(check.verdict, FrozenVerdict.fails);
    expect(check.check?.cls, 'signed-content');
    expect(check.check?.blame?.deviceId, bob.crypto.deviceId, reason: 'the author, authenticated on alice\'s device');
    await alice.sync.resolve(group.id, rollback: true);
    expect(ds.channels[group.id]!.resolved, ['rollback']);
    // Exactly the authenticated author was removed afterwards.
    expect((await alice.crypto.members(group.id)).any((m) => m.deviceId == bob.crypto.deviceId), isFalse);
    expect((await alice.store.group(group.id))!.frozen, isNull);
    await alice.sync.send(group.id, '{"thawed":true}');
    await until(() => carol.delivered.any((d) => d.plaintext == '{"thawed":true}'));
  });

  test('security rules: a log entry of the wrong kind is skipped; remove-needed frames are ignored', () async {
    final group = await alice.sync.create(GroupKindName.private);
    await alice.sync.add(group.id, [bob.user.id]);
    await until(() => bob.crypto.groups.contains(group.id));
    final notices = <String>[];
    bob.sync.notices.listen(notices.add);
    // An application message the server logs as a commit: refused before it is used, skipped with a notice.
    final message = await alice.crypto.encrypt(group.id, '{"sneaky":true}');
    final channel = ds.channels[group.id]!;
    final seq = channel.append('commit', alice.user.id, alice.crypto.deviceId, message);
    await bob.sync.onGroupFrame(GroupEvent(channel: group.id, seq: seq, epoch: channel.epoch, kind: 'commit', fromUserId: alice.user.id, fromDeviceId: alice.crypto.deviceId, message: message, createdAt: 1));
    expect(bob.delivered, isEmpty);
    expect(notices, isNotEmpty);
    expect((await bob.store.group(group.id))!.cursor, seq, reason: 'skipped, not retried');
    // The server can't make an admin remove someone.
    await alice.sync.onChannel(ChannelEvent(id: group.id, change: 'remove-needed', deviceId: bob.crypto.deviceId));
    await settle();
    expect((await alice.crypto.members(group.id)).any((m) => m.userId == bob.user.id), isTrue);
  });

  test('rollback is signed only when the admin device itself finds the frozen commit bad', () async {
    final group = await alice.sync.create(GroupKindName.private);
    await alice.sync.add(group.id, [bob.user.id]);
    await until(() => bob.crypto.groups.contains(group.id));
    // Someone reports alice's own valid commit: it checks out on alice's device, so only Dismiss is possible.
    await alice.sync.setAdmins(group.id, [alice.user.id, bob.user.id]);
    final channel = ds.channels[group.id]!;
    final last = channel.log.last;
    channel.frozen = {'seq': last['seq'], 'digest': FakeDs.digest(last['message']! as String)};
    await alice.store.updateGroup(group.id, (g) => g.copyWith(frozen: Frozen(seq: last['seq']! as int, digest: FakeDs.digest(last['message']! as String))));
    expect((await alice.sync.checkFrozen(group.id)).verdict, FrozenVerdict.ok);
    await expectLater(alice.sync.resolve(group.id, rollback: true), throwsA(isA<StoreException>()));
    expect(channel.resolved, isEmpty, reason: 'nothing signed');
    await alice.sync.resolve(group.id, rollback: false);
    expect(channel.resolved, ['dismiss']);
  });

  test('resolve bytes v2 name the author (vector shared with channels.ts)', () {
    expect(sha256.convert(resolveBytes('C' * 22, 'rollback', 7, 'd' * 64, 'a' * 22)).toString(), '15911786d65cec6da7b01ae0de4df45929815e2d0073cad52665c981f5710bd3');
  });

  test('a tag-only failure rolls back removing nobody; the author rejoins and makes its change again', () async {
    final carol = await Party.join(ds, 'carol');
    final group = await alice.sync.create(GroupKindName.private);
    await alice.sync.add(group.id, [bob.user.id, carol.user.id]);
    await until(() => bob.crypto.groups.contains(group.id) && carol.crypto.groups.contains(group.id));
    await alice.sync.setAdmins(group.id, [alice.user.id, bob.user.id]);
    await until(() => ds.channels[group.id]!.members.values.every((m) => m.cursor == ds.channels[group.id]!.seq), 'everyone caught up');
    for (var i = 0; i < 50 && !(await bob.crypto.roles(group.id)).isAdmin(bob.user.id); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
    // alice's next commit arrives at bob and carol with a broken tag: they reject it and report it.
    bob.crypto.tagFailFrom = alice.crypto.deviceId;
    carol.crypto.tagFailFrom = alice.crypto.deviceId;
    await alice.sync.setAdmins(group.id, [alice.user.id, bob.user.id, carol.user.id]);
    await until(() => ds.channels[group.id]!.frozen != null, 'reported');
    var frozen = await bob.store.group(group.id);
    for (var i = 0; i < 100 && frozen?.frozen == null; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 5));
      frozen = await bob.store.group(group.id);
    }
    final check = await bob.sync.checkFrozen(group.id);
    expect(check.verdict, FrozenVerdict.fails);
    expect(check.check?.cls, 'tag');
    expect(check.check?.blame, isNull, reason: 'a tag proves nothing about the author');
    bob.crypto.tagFailFrom = null;
    carol.crypto.tagFailFrom = null;
    await bob.sync.resolve(group.id, rollback: true);
    expect(ds.channels[group.id]!.resolved, ['rollback']);
    // Nobody removed; alice rejoined and made her change again.
    for (var i = 0; i < 300 && !(await bob.crypto.roles(group.id)).isAdmin(carol.user.id); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    expect((await bob.crypto.roles(group.id)).isAdmin(carol.user.id), isTrue, reason: 'the change was made again');
    expect({for (final m in await bob.crypto.members(group.id)) m.userId}, {alice.user.id, bob.user.id, carol.user.id});
    expect((await alice.store.list(group.id)).any((m) => m.system && m.text.contains('made again')), isTrue);
  });

  test('only an authenticated member whose signed content is invalid is ever blamed', () {
    const member = GroupMember(leaf: 3, userId: 'u', deviceId: 'd', platform: 'ios', admin: false);
    const joiner = GroupMember(leaf: CommitCheck.externalLeaf, userId: 'u', deviceId: 'd', platform: 'ios', admin: false);
    expect(const CommitCheck(authenticated: true, signedContentInvalid: true, cls: 'signed-content', author: member).blame, member);
    expect(const CommitCheck(authenticated: true, signedContentInvalid: false, cls: 'tag', author: member).blame, isNull);
    expect(const CommitCheck(authenticated: false, signedContentInvalid: true, cls: 'tag', author: member).blame, isNull);
    expect(const CommitCheck(authenticated: true, signedContentInvalid: true, cls: 'signed-content', author: joiner).blame, isNull);
    expect(const CommitCheck(authenticated: true, signedContentInvalid: true, cls: 'signed-content').blame, isNull);
  });
}
