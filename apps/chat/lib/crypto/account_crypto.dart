/// The account key on every device and its encrypted backup (docs/m6-account-key.md §1, §3, §5): chatcore through
/// flutter_rust_bridge ([RustAccountCrypto]), with [FakeAccountCrypto] modelling the same contract for tests. Records
/// travel as the server's JSON; the AccountKey only as base64url text, never logged or stored by the app itself.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;

import '../core/devices.dart' show proofHash;
import '../src/rust/api.dart' as core;
import 'chat_crypto.dart';

/// What a full device keeps to re-seal the backup (§0): never the passphrase, never the server's word.
class BackupKeys {
  const BackupKeys({required this.epoch, required this.passPub, required this.recoveryPub});
  final int epoch;
  final String passPub;
  final String recoveryPub;

  Map<String, Object?> toJson() => {'epoch': epoch, 'passPub': passPub, 'recoveryPub': recoveryPub};
  static BackupKeys? fromJson(Object? json) {
    if (json is! Map || json['epoch'] is! int || json['passPub'] is! String || json['recoveryPub'] is! String) return null;
    return BackupKeys(epoch: json['epoch'] as int, passPub: json['passPub'] as String, recoveryPub: json['recoveryPub'] as String);
  }
}

/// `backupCreate` / `backupReseal`: the record to sign and upload, the backup keys to keep, and what to show once.
class BackupSealed {
  const BackupSealed({required this.record, required this.backupKeys, this.words, this.passProof, this.recoveryProof});

  /// Unsigned: [AccountCrypto.backupSignKeys] signs it.
  final Map<String, Object?> record;
  final BackupKeys backupKeys;

  /// The 24 recovery words, when a recovery key was made.
  final List<String>? words;

  /// New proofs for the server (only when they changed).
  final String? passProof;
  final String? recoveryProof;
}

/// The unlock secret a change, a delete or a rotation proves (§3.5): exactly one of them.
class Unlock {
  const Unlock.passphrase(String this.passphrase) : words = null;
  const Unlock.words(String this.words) : passphrase = null;
  final String? passphrase;
  final String? words;
}

/// A companion's request for the account key (§5): its ephemeral key, its MLS leaf key, and the leaf's signature.
typedef RekeyRequest = ({String eph, String leafSigKey, String signature});

abstract class AccountCrypto {
  /// Full core only (`companion` otherwise).
  Future<String> exportAccountKey(String userId);

  /// Makes this core full with that account key; checked against the pinned account or, on a restore, against
  /// [published]. Returns the identity now held.
  Future<Identity> importAccountKey(String userId, String key, {Identity? published});

  Future<List<String>> passphraseGenerate();
  Future<BackupSealed> backupCreate(String userId, String passphrase);
  Future<String> backupSignKeys(String userId, Map<String, Object?> record);

  /// Re-seal after a rotation (neither given), change the passphrase ([passphrase]) or make a new recovery key
  /// ([newRecovery]); always only to the backup keys this core holds.
  Future<BackupSealed> backupReseal(String userId, Map<String, Object?> record, {String? passphrase, bool newRecovery = false});
  Future<String> backupProve(Map<String, Object?> record, Unlock unlock);

  /// Opens the backup; with [published] (a restore) the key inside must be that identity's.
  Future<({String accountKey, BackupKeys backupKeys})> backupOpen(String userId, Map<String, Object?> record, Unlock unlock, {Identity? published});

  /// The backup keys this core holds, and keeping newer ones (the core refuses a lower epoch).
  Future<BackupKeys?> heldBackupKeys();
  Future<void> keepBackupKeys(BackupKeys keys);

  /// §6.2, in two steps. [prepareRotation] mints the new key, signs the record with the current one and keeps both in
  /// the core (`rotation:pending`, so a crash loses nothing); [commitRotation], once the server took the record, swaps
  /// the key (the old one stays a predecessor). A second prepare while one waits is refused (`pending`).
  Future<({Identity identity, Map<String, Object?> record, String signature})> prepareRotation(String userId, {required int at});
  Future<Identity> commitRotation(String userId);

  /// A prepared rotation the core still holds (after a restart), and dropping it.
  Future<({Identity identity, Map<String, Object?> record, String signature})?> rotationPending();
  Future<void> rotationDrop();

  /// §5 rekey: a companion asks, a full core answers (checking the device, the request's signature and that a group
  /// holds the leaf), and the companion opens the answer, becoming full. Returns the identity and backup keys.
  Future<RekeyRequest> rekeyRequest(String userId, String deviceId, String platform);
  Future<String> rekeyAnswer(String userId, {required String deviceId, required String platform, required RekeyRequest request, required List<String> groups, required int now});
  Future<({Identity identity, BackupKeys? backupKeys})> rekeyOpen(String userId, {required String deviceId, required String platform, required String box});
}

Map<String, Object?> _json(String text) => (jsonDecode(text) as Map).cast<String, Object?>();
BackupKeys _keys(String text) => BackupKeys.fromJson(jsonDecode(text)) ?? (throw const CryptoException('malformed backup keys', code: 'invalid'));
Identity _id(core.Identity i) => Identity(dh: i.dh, sign: i.sign);
core.Identity _core(Identity i) => core.Identity(dh: i.dh, sign: i.sign);

/// chatcore's M6 commands through flutter_rust_bridge; records and backup keys as the contract's JSON text.
class RustAccountCrypto implements AccountCrypto {
  const RustAccountCrypto();

  Future<T> _call<T>(Future<T> Function() work) async {
    try {
      return await work();
    } on core.CoreError catch (error) {
      throw CryptoException(error.message, code: error.code, keysLocked: error.code == 'storage');
    }
  }

  BackupSealed _sealed(core.BackupResult r) => BackupSealed(
    record: _json(r.recordJson),
    backupKeys: _keys(r.backupKeysJson),
    words: r.words?.split(' '),
    passProof: r.passProof,
    recoveryProof: r.recoveryProof,
  );

  @override
  Future<String> exportAccountKey(String userId) => _call(() => core.exportAccountKey(userId: userId));
  @override
  Future<Identity> importAccountKey(String userId, String key, {Identity? published}) =>
      _call(() async => _id(await core.importAccountKey(userId: userId, key: key, published: published == null ? null : _core(published))));
  @override
  Future<List<String>> passphraseGenerate() => _call(() async => (await core.passphraseGenerate()).split(' '));
  @override
  Future<BackupSealed> backupCreate(String userId, String passphrase) => _call(() async => _sealed(await core.backupCreate(userId: userId, passphrase: passphrase)));
  @override
  Future<String> backupSignKeys(String userId, Map<String, Object?> record) => _call(() => core.backupSignKeys(userId: userId, recordJson: jsonEncode(record)));
  @override
  Future<BackupSealed> backupReseal(String userId, Map<String, Object?> record, {String? passphrase, bool newRecovery = false}) =>
      _call(() async => _sealed(await core.backupReseal(userId: userId, recordJson: jsonEncode(record), passphrase: passphrase, newRecovery: newRecovery)));
  @override
  Future<String> backupProve(Map<String, Object?> record, Unlock unlock) =>
      _call(() => core.backupProve(recordJson: jsonEncode(record), passphrase: unlock.passphrase, words: unlock.words));
  @override
  Future<({String accountKey, BackupKeys backupKeys})> backupOpen(String userId, Map<String, Object?> record, Unlock unlock, {Identity? published}) => _call(() async {
    final o = await core.backupOpen(userId: userId, recordJson: jsonEncode(record), passphrase: unlock.passphrase, words: unlock.words, published: published == null ? null : _core(published));
    return (accountKey: o.accountKey, backupKeys: _keys(o.backupKeysJson));
  });
  @override
  Future<BackupKeys?> heldBackupKeys() => _call(() async {
    final text = await core.backupKeys();
    return text == null ? null : _keys(text);
  });
  @override
  Future<void> keepBackupKeys(BackupKeys keys) => _call(() => core.backupKeysSet(backupKeysJson: jsonEncode(keys.toJson())));
  static ({Map<String, Object?> record, String signature}) _signed(String text) {
    final record = _json(text);
    final signature = record.remove('signature');
    if (signature is! String) throw const CryptoException('the core returned no signed record', code: 'invalid');
    return (record: record, signature: signature);
  }

  @override
  Future<({Identity identity, Map<String, Object?> record, String signature})> prepareRotation(String userId, {required int at}) => _call(() async {
    final out = await core.rotateIdentity(userId: userId, at: BigInt.from(at), commit: false);
    final signed = _signed(out.recordJson);
    return (identity: _id(out.identity), record: signed.record, signature: signed.signature);
  });
  @override
  Future<Identity> commitRotation(String userId) => _call(() async => _id((await core.rotateIdentity(userId: userId, at: BigInt.zero, commit: true)).identity));
  @override
  Future<({Identity identity, Map<String, Object?> record, String signature})?> rotationPending() => _call(() async {
    final p = await core.rotationPending();
    final text = p?.json;
    if (p == null || text == null) return null;
    final signed = _signed(text);
    return (identity: _id(p.identity), record: signed.record, signature: signed.signature);
  });
  @override
  Future<void> rotationDrop() => _call(core.rotationDrop);
  @override
  Future<RekeyRequest> rekeyRequest(String userId, String deviceId, String platform) => _call(() async {
    final r = await core.rekeyRequest(userId: userId, deviceId: deviceId, platform: platform);
    return (eph: r.eph, leafSigKey: r.leafSigKey, signature: r.signature);
  });
  @override
  Future<String> rekeyAnswer(String userId, {required String deviceId, required String platform, required RekeyRequest request, required List<String> groups, required int now}) => _call(
    () => core.rekeyAnswer(userId: userId, deviceId: deviceId, platform: platform, eph: request.eph, leafSigKey: request.leafSigKey, signature: request.signature, groups: groups, nowMs: BigInt.from(now)),
  );
  @override
  Future<({Identity identity, BackupKeys? backupKeys})> rekeyOpen(String userId, {required String deviceId, required String platform, required String box}) => _call(() async {
    final out = await core.rekeyOpen(userId: userId, deviceId: deviceId, platform: platform, boxed: box);
    final keys = out.json;
    return (identity: _id(out.identity), backupKeys: keys == null ? null : _keys(keys));
  });
}

/// Test stand-in. It does NOT encrypt or stretch: unlock keys are hashes of the secrets and boxes are readable JSON.
/// It does model what the app relies on: words open only the recovery side, a wrong secret is `auth`, epochs go
/// up, the proofs match the record's hashes, and a key imports only for the identity it belongs to.
class FakeAccountCrypto implements AccountCrypto {
  FakeAccountCrypto({this.held, this.sign});

  /// The identity this core holds (full), or null (companion or empty).
  Identity? held;

  /// Tests: a real signer for the keys bytes; without one the signature is a placeholder.
  String Function(Map<String, Object?> record)? sign;
  BackupKeys? backupKeys;
  int _words = 0, _rotations = 0;

  static String _h(String text) => base64Url.encode(hash.sha256.convert(utf8.encode(text)).bytes).replaceAll('=', '');
  static String _key(Identity id) => 'ak.${id.sign}.${id.dh}';
  static String _norm(String words) => words.trim().toLowerCase().split(RegExp(r'\s+')).join(' ');

  String _passPub(String passphrase) => _h('pass:$passphrase');
  String _recoveryPub(String words) => _h('recovery:${_norm(words)}');
  String _passProof(String passphrase) => _h('pass-proof:$passphrase');
  String _recoveryProof(String words) => _h('recovery-proof:${_norm(words)}');
  Identity _full() => held ?? (throw const CryptoException('no account key here', code: 'companion'));

  @override
  Future<String> exportAccountKey(String userId) async => _key(_full());

  @override
  Future<Identity> importAccountKey(String userId, String key, {Identity? published}) async {
    final parts = key.split('.');
    if (parts.length != 3 || parts[0] != 'ak') throw const CryptoException('malformed account key', code: 'invalid');
    final identity = Identity(dh: parts[2], sign: parts[1]);
    final expected = published ?? held;
    if (expected != null && expected != identity) throw const CryptoException('that key is not this account', code: 'invalid');
    return held = identity;
  }

  @override
  Future<List<String>> passphraseGenerate() async => ['amber', 'canyon', 'delta', 'ember', 'harbor', 'violet'];

  List<String> _newWords() => [for (var i = 0; i < 24; i++) 'w${++_words}'];

  Map<String, Object?> _box(String pub, String accountKey, BackupKeys keys) => {'to': pub, 'key': accountKey, 'keys': keys.toJson()};

  @override
  Future<BackupSealed> backupCreate(String userId, String passphrase) async {
    if (passphrase.runes.length < 14) throw const CryptoException('too short', code: 'invalid');
    final identity = _full();
    final words = _newWords();
    final keys = BackupKeys(epoch: 1, passPub: _passPub(passphrase), recoveryPub: _recoveryPub(words.join(' ')));
    final record = _record(userId, identity, keys, passProofHash: proofHash(_passProof(passphrase)), recoveryProofHash: proofHash(_recoveryProof(words.join(' '))));
    return BackupSealed(record: record, backupKeys: keys, words: words, passProof: _passProof(passphrase), recoveryProof: _recoveryProof(words.join(' ')));
  }

  Map<String, Object?> _record(String userId, Identity identity, BackupKeys keys, {required String passProofHash, required String recoveryProofHash}) => {
    'v': 1,
    'userId': userId,
    'aikSign': identity.sign,
    'epoch': keys.epoch,
    'kdf': {'alg': 'argon2id', 'salt': 'AAAAAAAAAAAAAAAAAAAAAA', 'm': 65536, 't': 3, 'p': 1},
    'passHash': _h(keys.passPub),
    'recoveryHash': _h(keys.recoveryPub),
    'pass': jsonEncode(_box(keys.passPub, _key(identity), keys)),
    'recovery': jsonEncode(_box(keys.recoveryPub, _key(identity), keys)),
    'passProofHash': passProofHash,
    'recoveryProofHash': recoveryProofHash,
  };

  @override
  Future<String> backupSignKeys(String userId, Map<String, Object?> record) async {
    _full();
    return sign?.call(record) ?? 'A' * 86;
  }

  @override
  Future<BackupSealed> backupReseal(String userId, Map<String, Object?> record, {String? passphrase, bool newRecovery = false}) async {
    final identity = _full();
    final keys = backupKeys ?? (throw const CryptoException('this device holds no backup keys', code: 'invalid'));
    if ((record['epoch'] as int? ?? 0) < keys.epoch) throw const CryptoException('an older backup', code: 'invalid');
    final words = newRecovery ? _newWords() : null;
    final next = BackupKeys(
      epoch: (record['epoch']! as int) + 1,
      passPub: passphrase == null ? keys.passPub : _passPub(passphrase),
      recoveryPub: words == null ? keys.recoveryPub : _recoveryPub(words.join(' ')),
    );
    final passProof = passphrase == null ? null : _passProof(passphrase), recoveryProof = words == null ? null : _recoveryProof(words.join(' '));
    final sealed = _record(userId, identity, next,
        passProofHash: passProof == null ? record['passProofHash']! as String : proofHash(passProof),
        recoveryProofHash: recoveryProof == null ? record['recoveryProofHash']! as String : proofHash(recoveryProof));
    return BackupSealed(record: sealed, backupKeys: next, words: words, passProof: passProof, recoveryProof: recoveryProof);
  }

  @override
  Future<String> backupProve(Map<String, Object?> record, Unlock unlock) async {
    final passphrase = unlock.passphrase, words = unlock.words;
    final proof = passphrase != null ? _passProof(passphrase) : _recoveryProof(words ?? '');
    final expected = passphrase != null ? record['passProofHash'] : record['recoveryProofHash'];
    if (expected != null && proofHash(proof) != expected) throw const CryptoException("That passphrase doesn't open your backup.", code: 'auth');
    return proof;
  }

  @override
  Future<({String accountKey, BackupKeys backupKeys})> backupOpen(String userId, Map<String, Object?> record, Unlock unlock, {Identity? published}) async {
    final passphrase = unlock.passphrase, words = unlock.words;
    if (words != null && words.trim().split(RegExp(r'\s+')).length != 24) throw const CryptoException('Those words are not a recovery key.', code: 'invalid');
    final pub = passphrase != null ? _passPub(passphrase) : _recoveryPub(words ?? '');
    final box = jsonDecode((passphrase != null ? record['pass'] : record['recovery'])! as String) as Map;
    if (box['to'] != pub || _h(pub) != (passphrase != null ? record['passHash'] : record['recoveryHash'])) {
      throw CryptoException(passphrase != null ? "That passphrase doesn't open your backup." : "Those words don't open your backup.", code: 'auth');
    }
    final keys = BackupKeys.fromJson(box['keys']) ?? (throw const CryptoException('malformed box', code: 'invalid'));
    return (accountKey: box['key'] as String, backupKeys: keys);
  }

  @override
  Future<BackupKeys?> heldBackupKeys() async => backupKeys;

  @override
  Future<void> keepBackupKeys(BackupKeys keys) async {
    final held = backupKeys;
    if (held != null && keys.epoch < held.epoch) throw const CryptoException('older backup keys', code: 'invalid');
    backupKeys = keys;
  }

  /// Tests: the identities this core replaced its own with.
  final List<Identity> rotations = [];

  /// Tests: the prepared rotation the core keeps (`rotation:pending`).
  ({Identity identity, Map<String, Object?> record, String signature})? pending;

  @override
  Future<({Identity identity, Map<String, Object?> record, String signature})> prepareRotation(String userId, {required int at}) async {
    final old = _full();
    if (pending != null) throw const CryptoException('a rotation is already prepared', code: 'pending');
    final next = Identity(dh: _h('rot-dh-${++_rotations}'), sign: _h('rot-sign-$_rotations'));
    final prepared = (identity: next, record: <String, Object?>{'v': 1, 'userId': userId, 'oldSign': old.sign, 'newSign': next.sign, 'newDh': next.dh, 'at': at}, signature: 'S' * 86);
    pending = prepared;
    return prepared;
  }

  @override
  Future<Identity> commitRotation(String userId) async {
    _full();
    final p = pending ?? (throw const CryptoException('no rotation is prepared', code: 'invalid'));
    pending = null;
    held = p.identity;
    rotations.add(p.identity);
    return p.identity;
  }

  @override
  Future<({Identity identity, Map<String, Object?> record, String signature})?> rotationPending() async => pending;

  @override
  Future<void> rotationDrop() async => pending = null;

  @override
  Future<RekeyRequest> rekeyRequest(String userId, String deviceId, String platform) async => (eph: 'eph-$deviceId', leafSigKey: 'leaf-$deviceId', signature: 'sig-$deviceId');

  @override
  Future<String> rekeyAnswer(String userId, {required String deviceId, required String platform, required RekeyRequest request, required List<String> groups, required int now}) async =>
      jsonEncode({'for': deviceId, 'eph': request.eph, 'key': _key(_full()), 'keys': backupKeys?.toJson()});

  @override
  Future<({Identity identity, BackupKeys? backupKeys})> rekeyOpen(String userId, {required String deviceId, required String platform, required String box}) async {
    final m = jsonDecode(box) as Map;
    if (m['for'] != deviceId || m['eph'] != 'eph-$deviceId') throw const CryptoException('not for this device', code: 'auth');
    final identity = await importAccountKey(userId, m['key'] as String);
    final keys = BackupKeys.fromJson(m['keys']);
    if (keys != null) await keepBackupKeys(keys);
    return (identity: identity, backupKeys: keys);
  }
}
