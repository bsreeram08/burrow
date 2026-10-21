// The account key and its backup (docs/m6-account-key.md §1, §3, §4) against the real Rust core on the host.
// Skipped when it has not been built: `cargo build --manifest-path rust/Cargo.toml`.
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/account_crypto.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/rust_chat_crypto.dart';

void main() {
  final dylib = File('rust/target/debug/${Platform.isMacOS ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so'}');
  final skip = dylib.existsSync() ? false : 'build rust/ first';
  late Directory dir;
  setUpAll(() => dir = Directory.systemTemp.createTempSync('chatcore-account-'));
  tearDownAll(() => dir.deleteSync(recursive: true));
  RustChatCrypto core() => RustChatCrypto(directory: () async => dir.path, storeKeys: MemoryStoreKeys(), externalLibrary: ExternalLibrary.open(dylib.absolute.path));
  const userId = 'uuuuuuuuuuuuuuuuuuuuuu', passphrase = 'a long passphrase of mine';
  const account = RustAccountCrypto();

  test("a backup made by one core opens on an empty one with the passphrase or the words, as the account's own key", () async {
    final full = core();
    await full.init('full');
    final identity = await full.identity();
    expect((await account.passphraseGenerate()), hasLength(6));
    await expectLater(account.backupCreate(userId, 'too short'), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'invalid')));
    final sealed = await account.backupCreate(userId, passphrase);
    expect(sealed.words, hasLength(24));
    final record = {...sealed.record, 'signature': await account.backupSignKeys(userId, sealed.record)};
    // The app's keys bytes are the core's: the signature verifies in Dart under the account key.
    expect(verifyBackupRecord(record, userId: userId, aikSign: identity.sign), isTrue);
    expect(proofHash(sealed.passProof!), record['passProofHash']);
    expect(proofHash(await account.backupProve(record, const Unlock.passphrase(passphrase))), record['passProofHash']);
    final key = await account.exportAccountKey(userId);

    // A new device: an empty core, nothing minted.
    final fresh = core();
    await fresh.init('fresh');
    await expectLater(account.backupOpen(userId, record, const Unlock.passphrase('not the passphrase'), published: identity), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'auth')));
    final opened = await account.backupOpen(userId, record, Unlock.words(sealed.words!.join(' ')), published: identity);
    expect(opened.accountKey, key);
    expect(await account.importAccountKey(userId, opened.accountKey, published: identity), identity);
    await account.keepBackupKeys(opened.backupKeys);
    expect((await account.heldBackupKeys())?.epoch, 1);
    expect(await fresh.identity(), identity, reason: 'the same account key, so contacts keep their verification');
  }, skip: skip);

  test('a full core replaces its own key: the record is signed by the old one', () async {
    final full = core();
    await full.init('rotate');
    final before = await full.identity();
    final at = DateTime.now().millisecondsSinceEpoch;
    final rotated = await account.prepareRotation(userId, at: at);
    expect(rotated.record['oldSign'], before.sign);
    expect(rotated.record['newSign'], rotated.identity.sign);
    expect(verifySuccessionChain(userId, before.sign, rotated.identity.sign, [{...rotated.record, 'signature': rotated.signature}]), isTrue);
    expect(await full.identity(), before, reason: 'nothing changes before the server took the record');
    // A restart in between loses nothing: the core keeps the prepared rotation.
    expect((await account.rotationPending())?.identity, rotated.identity);
    await expectLater(account.prepareRotation(userId, at: at), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'pending')));
    expect(await account.commitRotation(userId), rotated.identity);
    expect(await account.rotationPending(), isNull);
    expect(await full.identity(), rotated.identity);
  }, skip: skip);
}
