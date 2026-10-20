// RustGroupCrypto against the real MLS engine on the host (the dylib `cargo build` produces in rust/).
// The bridge keeps one process-wide core, so the two accounts take turns: each `init` reopens that
// account's sealed key database, which also proves the group state persists there.
// Skipped when it has not been built: `cargo build --manifest-path rust/Cargo.toml`.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/crypto/group_crypto.dart';
import 'package:private_chat/crypto/rust_chat_crypto.dart';
import 'package:private_chat/crypto/rust_group_crypto.dart';

String id(int seed) => base64Url.encode(List<int>.generate(16, (i) => (seed * 31 + i) % 256)).replaceAll('=', '');

void main() {
  final dylib = File('rust/target/debug/${Platform.isMacOS ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so'}');
  final skip = dylib.existsSync() ? false : 'build rust/ first';
  late Directory dir;
  setUpAll(() => dir = Directory.systemTemp.createTempSync('chatcore-mls-'));
  tearDownAll(() => dir.deleteSync(recursive: true));

  test('two accounts form a group, exchange messages, and a removal takes effect', () async {
    final keys = MemoryStoreKeys();
    final rust = RustChatCrypto(directory: () async => dir.path, storeKeys: keys, externalLibrary: ExternalLibrary.open(dylib.absolute.path));
    const mls = RustGroupCrypto();
    final alice = id(1), bob = id(2), aliceDevice = id(3), bobDevice = id(4), group = id(5);

    await rust.init('bob');
    final bobIdentity = await rust.identity();
    final bobCert = await mls.initDevice(userId: bob, deviceId: bobDevice, platform: 'ios', issuedAt: 1700000000000);
    expect(bobCert.aikSign, bobIdentity.sign);
    // Idempotent: the same leaf on a second call.
    expect((await mls.initDevice(userId: bob, deviceId: bobDevice, platform: 'ios', issuedAt: 1700000000000)).leafSigKey, bobCert.leafSigKey);
    final packages = await mls.keyPackages(2);
    expect(packages, hasLength(2));
    expect(await mls.keyPackages(1, lastResort: true), hasLength(1));

    await rust.init('alice');
    final aliceIdentity = await rust.identity();
    await rust.notePeer(bob, bobIdentity); // The 1:1 pin is what makes bob's certificate acceptable.
    await mls.initDevice(userId: alice, deviceId: aliceDevice, platform: 'macos', issuedAt: 1700000000000);
    final created = await mls.create(group, GroupRoles.group([alice]));
    expect(created.epoch, 0);
    expect((await mls.roles(group)).admins, [alice]);
    final add = await mls.commit(group, adds: [packages.first]);
    expect(add.welcome, isNotNull);
    expect(await mls.pendingCommit(group), isA<PendingGroupCommit>().having((p) => p.digest, 'digest', add.digest));
    final merged = await mls.mergeOwn(group);
    expect(merged.epoch, 1);
    expect(await mls.pendingCommit(group), isNull);
    expect({for (final m in await mls.members(group)) m.userId}, {alice, bob});
    final hello = await mls.encrypt(group, '{"hello":"bob"}');

    await rust.init('bob');
    await rust.notePeer(alice, aliceIdentity);
    final joined = await mls.join(add.welcome!, merged.tree);
    expect(joined.epoch, 1);
    final got = await mls.receive(group, hello);
    expect(got.kind, ProcessedKind.application);
    expect(got.plaintext, '{"hello":"bob"}');
    expect(got.sender.userId, alice);
    await mls.receiveCommit(got.pendingId);
    // Replaying a stored message is refused.
    await expectLater(mls.receive(group, hello), throwsA(isA<CryptoException>()));
    final reply = await mls.encrypt(group, '{"hi":"alice"}');

    await rust.init('alice');
    final back = await mls.receive(group, reply);
    expect((back.plaintext, back.sender.deviceId), ('{"hi":"alice"}', bobDevice));
    await mls.receiveCommit(back.pendingId);
    // A conflict: build, drop, rebuild.
    await mls.commit(group, removes: [GroupRemoval(bob)]);
    await mls.clearOwn(group);
    expect(await mls.pendingCommit(group), isNull);
    final remove = await mls.commit(group, removes: [GroupRemoval(bob)]);
    await mls.mergeOwn(group);
    expect([for (final m in await mls.members(group)) m.userId], [alice]);

    await rust.init('bob');
    final removed = await mls.receive(group, remove.commit);
    expect(removed.kind, ProcessedKind.removed);
    await mls.receiveCommit(removed.pendingId);
    await mls.forget(group);
    await expectLater(mls.view(group), throwsA(isA<CryptoException>()));
  }, skip: skip);

  test('policy refusals carry the invalid code', () async {
    final rust = RustChatCrypto(directory: () async => dir.path, storeKeys: MemoryStoreKeys(), externalLibrary: ExternalLibrary.open(dylib.absolute.path));
    const mls = RustGroupCrypto();
    await rust.init('carol');
    final carol = id(6);
    await mls.initDevice(userId: carol, deviceId: id(7), platform: 'ios', issuedAt: 1700000000000);
    // The creator must be an admin.
    await expectLater(mls.create(id(8), GroupRoles.group([id(9)])), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'invalid')));
    await expectLater(mls.view(id(10)), throwsA(isA<CryptoException>().having((e) => e.code, 'code', isNotNull)));
  }, skip: skip);
}
