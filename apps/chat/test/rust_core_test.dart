// RustChatCrypto against the real Rust core on the host (the dylib `cargo build` produces in rust/).
// Skipped when it has not been built: `cargo build --manifest-path rust/Cargo.toml`.
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/rust_chat_crypto.dart';

String sdp(String byte) => 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:sha-256 ${List.filled(32, byte).join(':')}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n';

void main() {
  final dylib = File('rust/target/debug/${Platform.isMacOS ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so'}');
  final skip = dylib.existsSync() ? false : 'build rust/ first';
  late Directory dir;
  setUpAll(() => dir = Directory.systemTemp.createTempSync('chatcore-dart-'));
  tearDownAll(() => dir.deleteSync(recursive: true));
  RustChatCrypto crypto(StoreKeys keys) => RustChatCrypto(directory: () async => dir.path, storeKeys: keys, externalLibrary: ExternalLibrary.open(dylib.absolute.path));

  test('the core reproduces the verify.js call code vector and keeps its identity across opens', () async {
    final keys = MemoryStoreKeys();
    final core = crypto(keys);
    await core.init('account');
    expect(core.sasCode(sdp('ab'), sdp('CD'), ['1' * 64, '2' * 64]), '996 300');
    expect(core.sasCode(sdp('cd'), sdp('ab'), ['2' * 64, '1' * 64]), '996 300');
    final commitment = core.sasCommit();
    expect(core.sasCheck(commitment.nonce, commitment.hash), isTrue);
    expect(() => core.sasCode('v=0\r\n', sdp('ab'), ['1' * 64, '2' * 64]), throwsA(isA<CryptoException>()));
    final identity = await core.identity();
    final upload = await core.preparePrekeys(DateTime.now(), oneTimeOnServer: 0);
    expect(upload.identity, identity);
    expect(upload.oneTimePreKeys, hasLength(100));
    await core.init('account'); // Reopen: same sealed database, same identity.
    expect(await core.identity(), identity);
  }, skip: skip);

  test('the core proves the identity key for a device claim, and refuses anything that is not one', () async {
    final core = crypto(MemoryStoreKeys());
    await core.init('claims');
    final identity = await core.identity(), challenge = 'B' * 42 + 'A', device = 'd' * 22;
    final proof = await core.proveIdentity('user_1', device, challenge);
    expect(verifyBytes(identity.sign, claimBytes('user_1', device, challenge), proof), isTrue);
    expect(verifyBytes(identity.sign, claimBytes('user_2', device, challenge), proof), isFalse);
    // Never a general signing oracle: a malformed challenge, device or account is refused.
    for (final args in [['user_1', device, 'short'], ['user_1', 'nope', challenge], ['no spaces', device, challenge]]) {
      await expectLater(core.proveIdentity(args[0], args[1], args[2]), throwsA(isA<CryptoException>()));
    }
  }, skip: skip);

  test('the core validates and signs device lists, and seeds the label key, for its own identity only', () async {
    final core = crypto(MemoryStoreKeys());
    await core.init('lists');
    final identity = await core.identity();
    const user = 'uuuuuuuuuuuuuuuuuuuuuu', device = 'dddddddddddddddddddddd';
    final seed = await core.deviceMetaSignature(user);
    expect(verifyBytes(identity.sign, metaSeedBytes(user), seed), isTrue);
    final key = deviceMetaKey(seed);
    final entry = <String, Object?>{'deviceId': device, 'addedAt': 1700000000000, 'meta': sealMeta(key, user, device, label: 'Mac app', platform: 'macos')};
    final list = <String, Object?>{'v': 1, 'userId': user, 'version': 1, 'prevHash': '', 'devices': [entry]};
    final signed = await core.signDeviceList(user, identity.sign, list);
    final check = verifyView(userId: user, aikSign: identity.sign, list: list, signature: signed.signature, certs: signed.certs);
    expect(check.ok, isTrue, reason: check.reason);
    expect(openMeta(key, user, device, entry['meta']! as String), {'label': 'Mac app', 'platform': 'macos'});
    // Refused: another account's list, an identity that isn't this core's, a malformed list.
    await expectLater(core.signDeviceList('vvvvvvvvvvvvvvvvvvvvvv', identity.sign, list), throwsA(isA<CryptoException>()));
    await expectLater(core.signDeviceList(user, 'B' * 43, list), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'mismatch')));
    await expectLater(core.signDeviceList(user, identity.sign, {...list, 'extra': 1}), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'invalid')));
  }, skip: skip);

  Matcher locked() => throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'storage').having((e) => e.keysLocked, 'keysLocked', isTrue));

  test('fails closed instead of starting over: wrong key, missing key, deleted database', () async {
    final keys = MemoryStoreKeys();
    await crypto(keys).init('sealed');
    final identity = await crypto(keys).identity();
    // Wrong store key.
    final wrong = MemoryStoreKeys()..keys['sealed'] = List<int>.filled(32, 9);
    await expectLater(crypto(wrong).init('sealed'), locked());
    // A failed open never leaves the previously opened store usable.
    await expectLater(crypto(keys).identity(), locked());
    // Store key missing (keystore cleared) next to an existing database: refused, and no key is minted.
    final lost = MemoryStoreKeys();
    await expectLater(crypto(lost).init('sealed'), locked());
    expect(lost.keys, isEmpty, reason: 'no new store key over an existing database');
    // Database deleted while the keystore still holds its key: "missing or reset", never a fresh identity.
    for (final suffix in ['', '-wal', '-shm']) {
      final file = File('${dir.path}/sealed.sqlite$suffix');
      if (file.existsSync()) file.deleteSync();
    }
    await expectLater(crypto(keys).init('sealed'), locked());
    // Only the explicit recovery starts over.
    await crypto(keys).resetLocal('sealed');
    await crypto(keys).init('sealed');
    expect(await crypto(keys).identity(), isNot(identity));
  }, skip: skip);
}
