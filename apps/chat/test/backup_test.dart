import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/account_crypto.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/messaging/backup.dart';
import 'package:private_chat/store/message.dart';

import 'support/fake_backup.dart';

/// The encrypted account key backup (docs/m6-account-key.md §3, §4) through the app's service, against an in-memory
/// server: set up, change (each proving the current passphrase or words), and restore on a new device only from a
/// record the account's published key signed.
void main() {
  const me = User(id: 'uuuuuuuuuuuuuuuuuuuuuu', username: 'me');
  const pass = 'amber canyon delta ember harbor violet';

  Future<(FakeBackupServer, AccountBackup, Identity, List<String>)> withBackup() async {
    final server = FakeBackupServer(), account = signingAccount();
    final backup = AccountBackup(api: server.api(), crypto: account.crypto, me: me);
    final sealed = await backup.prepareTurnOn(pass);
    expect(server.record, isNull, reason: 'nothing leaves the device before the words were typed back');
    await backup.commit(sealed);
    return (server, backup, account.identity, sealed.words!);
  }

  test('turning it on uploads a signed record with both proofs and no proof of an earlier one', () async {
    final (server, backup, identity, words) = await withBackup();
    final put = server.puts.single;
    expect(words, hasLength(24));
    expect((put['epoch'], put['aikSign'], put.containsKey('proof')), (1, identity.sign, false));
    expect(put['passProof'], isA<String>());
    expect(put['recoveryProof'], isA<String>());
    expect(verifyBackupRecord(server.record!, userId: me.id, aikSign: identity.sign), isTrue);
    expect((await backup.crypto.heldBackupKeys())?.epoch, 1);
  });

  test('changes prove the current passphrase or words; a wrong one changes nothing', () async {
    final (server, backup, _, words) = await withBackup();
    await expectLater(backup.changePassphrase(const Unlock.passphrase('not the passphrase at all'), 'a brand new passphrase'), throwsA(isA<CryptoException>()));
    expect(server.record?['epoch'], 1);
    await backup.changePassphrase(const Unlock.passphrase(pass), 'a brand new passphrase');
    expect(server.record?['epoch'], 2);
    expect(server.puts.last['proof'], isA<String>(), reason: 'the change carries the proof');
    final fresh = await backup.prepareNewRecoveryKey(Unlock.words(words.join(' ')));
    await backup.commit(fresh.sealed, proof: fresh.proof);
    expect(server.record?['epoch'], 3);
    expect(fresh.sealed.words, isNot(words));
    await backup.turnOff(const Unlock.passphrase('a brand new passphrase'));
    expect(server.record, isNull);
      });

  test('a new device restores with the passphrase or the words, only from a record the published key signed', () async {
    final (server, _, identity, words) = await withBackup();
    AccountBackup fresh() => AccountBackup(api: server.api(), crypto: FakeAccountCrypto(), me: me);

    await expectLater(fresh().restore(const Unlock.passphrase('wrong passphrase here'), published: identity), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'auth')));
    expect(await fresh().restore(const Unlock.passphrase(pass), published: identity), identity);
    final byWords = fresh();
    expect(await byWords.restore(Unlock.words(words.join(' ')), published: identity), identity);
    expect((await byWords.crypto.heldBackupKeys())?.epoch, 1, reason: 'the backup keys come with it');

    // A key the server publishes that didn't sign the record: nothing is opened.
    final other = Identity(dh: identity.dh, sign: b64(ed.generateKey().publicKey.bytes));
    await expectLater(fresh().restore(const Unlock.passphrase(pass), published: other), throwsA(isA<StoreException>()));
    // A record tampered with after signing (another epoch): refused.
    server.record = {...server.record!, 'epoch': 7};
    await expectLater(fresh().restore(const Unlock.passphrase(pass), published: identity), throwsA(isA<StoreException>()));
  });

  test('backup keys only move forward', () async {
    final (_, backup, _, _) = await withBackup();
    await backup.crypto.keepBackupKeys(const BackupKeys(epoch: 5, passPub: 'p', recoveryPub: 'r'));
    final again = await backup.prepareTurnOn(pass);
    await expectLater(backup.commit(again), throwsA(anything), reason: 'epoch 1 after 5: the server refuses it, and so would the device');
  });

  test('custom passphrases: long enough and not a common one', () {
    expect(AccountBackup.passphraseProblem('short'), contains('14'));
    expect(AccountBackup.passphraseProblem('correct horse battery staple'), contains('common'));
    expect(AccountBackup.passphraseProblem('a much longer passphrase of mine'), isNull);
  });
}
