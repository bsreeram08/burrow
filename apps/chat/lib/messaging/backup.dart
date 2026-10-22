import '../core/api.dart';
import '../core/devices.dart';
import '../crypto/account_crypto.dart';
import '../crypto/chat_crypto.dart';
import '../store/message.dart' show StoreException;


/// The encrypted account key backup (docs/m6-account-key.md §3, §4): set up, change and turn off on a full device,
/// and restore on a new one. The passphrase or recovery key is the final authority: every change proves it to the
/// server, and a device seals only to the backup keys it holds itself (never ones the server hands it).
class AccountBackup {
  AccountBackup({required this.api, required this.crypto, required this.me});

  final Api api;
  final AccountCrypto crypto;
  final User me;

  /// A custom passphrase: at least 14 characters and not a common one (§3.1). Null when it is fine.
  static String? passphraseProblem(String passphrase) {
    final text = passphrase.trim();
    if (text.runes.length < minPassphraseChars) return 'Use at least $minPassphraseChars characters, or the generated passphrase.';
    if (_common.contains(text.toLowerCase())) return 'That passphrase is too common. Choose another.';
    return null;
  }

  /// The account's record, or null when it has no backup.
  Future<Map<String, Object?>?> record() async => (await api.backup())?.cast<String, Object?>();

  /// Turning the backup on, step one (§3.4): seals it here with [passphrase] and new recovery words. Nothing is
  /// uploaded until the user has typed three of the words back ([commit]).
  Future<BackupSealed> prepareTurnOn(String passphrase) => crypto.backupCreate(me.id, passphrase);

  /// New recovery words, step one: proved by the passphrase or the current words; uploaded by [commit].
  Future<({BackupSealed sealed, String proof})> prepareNewRecoveryKey(Unlock current) async {
    final (record, held) = await _current();
    final proof = await crypto.backupProve(record, current);
    return (sealed: await crypto.backupReseal(me.id, record, newRecovery: true), proof: proof);
  }

  /// Signs and uploads a prepared backup ([proof]: none for the first one) and keeps its backup keys.
  Future<void> commit(BackupSealed sealed, {String? proof}) => _upload(sealed, proof: proof);

  /// A new passphrase, proved by the current one or the recovery key.
  Future<void> changePassphrase(Unlock current, String passphrase) async {
    final (record, held) = await _current();
    final proof = await crypto.backupProve(record, current);
    await _upload(await crypto.backupReseal(me.id, record, passphrase: passphrase), proof: proof);
  }

  Future<void> turnOff(Unlock current) async {
    final record = await this.record();
    if (record == null) return;
    await api.deleteBackup(await crypto.backupProve(record, current));
  }

  /// The proof a rotation needs when the account has a backup (§6.2); null when it has none.
  /// Also returns the record it read, for the re-seal after the rotation (each read is rate limited and logged).
  Future<({String proof, Map<String, Object?> record})?> proveForRotation(Unlock? unlock) async {
    final record = await this.record();
    if (record == null) return null;
    if (unlock == null) throw const StoreException('Enter your current passphrase or recovery key.');
    final proof = await crypto.backupProve(record, unlock);
    // Checked here before anything changes: the core replaces its key before the server sees the proof.
    if (proofHash(proof) != record['passProofHash'] && proofHash(proof) != record['recoveryProofHash']) {
      throw const StoreException('That isn’t your passphrase or recovery key.');
    }
    return (proof: proof, record: record);
  }

  /// After this device rotated the account key: re-seal both boxes to the backup keys held here, without a proof
  /// (the one re-seal the server allows right after a succession, §6.2 step 2). Nothing to do without a backup.
  Future<void> resealAfterRotation([Map<String, Object?>? read]) async {
    final record = read ?? await this.record();
    final held = await crypto.heldBackupKeys();
    if (record == null || held == null) return;
    await _upload(await crypto.backupReseal(me.id, record), proof: null);
  }

  /// Restore on a new device (§4): the record must be signed by the account's published key, the passphrase or
  /// words open it, and the key imports only as that identity. Returns the identity now held here.
  Future<Identity> restore(Unlock unlock, {required Identity published}) async {
    final record = await this.record();
    if (record == null) throw const StoreException('Your account has no backup. Link this device from one you already use.');
    if (record['aikSign'] != published.sign || !verifyBackupRecord(record, userId: me.id, aikSign: published.sign)) {
      throw const StoreException("Your backup on the server isn't one your account signed. Nothing was changed.");
    }
    final opened = await crypto.backupOpen(me.id, record, unlock, published: published);
    final identity = await crypto.importAccountKey(me.id, opened.accountKey, published: published);
    await _keep(opened.backupKeys);
    return identity;
  }

  Future<(Map<String, Object?>, BackupKeys)> _current() async {
    final record = await this.record();
    final held = await crypto.heldBackupKeys();
    if (record == null) throw const StoreException('Your account has no backup.');
    if (held == null) throw const StoreException('This device has no backup keys yet. Unlock it with your passphrase first.');
    return (record, held);
  }

  Future<void> _upload(BackupSealed sealed, {required String? proof}) async {
    final signature = await crypto.backupSignKeys(me.id, sealed.record);
    await api.putBackup({...sealed.record, 'signature': signature}, proof: proof, passProof: sealed.passProof, recoveryProof: sealed.recoveryProof);
    await _keep(sealed.backupKeys);
  }

  /// The backup keys live in the core, which refuses a lower epoch than the one it holds (§3.3).
  Future<void> _keep(BackupKeys next) => crypto.keepBackupKeys(next);
}

const minPassphraseChars = 14;

// The web client's list (link.js), compared lowercased: the 14-character minimum already rules out nearly every
// common password. ponytail: no NFKC normalisation in Dart; chatcore normalises before stretching it.
const _common = {
  'passwordpassword',
  'password1234567',
  '12345678901234',
  'qwertyuiopasdf',
  'iloveyouiloveyou',
  'correct horse battery staple',
  'letmeinletmein1',
};
