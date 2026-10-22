/// Device linking, pin transfer and succession in the core (docs/m5-linking.md §1–§5, §10.1). The real
/// implementation is chatcore through flutter_rust_bridge ([RustLinkCrypto]); [FakeLinkCrypto] models the
/// same contract for tests. A companion core (a linked device, without the account key) refuses 1:1 and
/// account-key calls with [CryptoException] code `companion`.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;

import '../src/rust/api.dart' as core;
import 'chat_crypto.dart';

/// A pin as it travels in a link bundle.
class PinExport {
  const PinExport({required this.contact, required this.identity, required this.verified, this.previous = const []});
  final String contact;
  final Identity identity;
  final bool verified;

  /// Earlier account keys (from accepted successions) and until when they could sign.
  final List<({String sign, int until})> previous;

  Map<String, Object?> toJson() => {
    'contact': contact,
    'identity': identity.toJson(),
    'verified': verified,
    if (previous.isNotEmpty) 'previous': [for (final p in previous) {'sign': p.sign, 'until': p.until}],
  };

  static PinExport fromJson(Object? json) {
    if (json is! Map || json['contact'] is! String || json['identity'] is! Map || json['verified'] is! bool) throw const FormatException('Invalid pin');
    return PinExport(
      contact: json['contact'] as String,
      identity: Identity.fromJson((json['identity'] as Map).cast<String, dynamic>()),
      verified: json['verified'] as bool,
      previous: [for (final p in (json['previous'] as List? ?? const [])) (sign: (p as Map)['sign'] as String, until: p['until'] as int)],
    );
  }
}

abstract class LinkCrypto {
  /// New device (QR): its ephemeral key and link secret for [linkId]; the QR text.
  Future<String> qr(String linkId);

  /// Primary: checks a scanned QR and derives the keys: the ephemeral key to offer and the 6-digit code.
  Future<({String linkId, String eph, String code})> accept(String qr);

  /// New device (QR): the primary's ephemeral key arrived; the code.
  Future<String> complete(String linkId, String eph);

  /// Code mode (§1.7). New device: commits to its ephemeral key; then reveals it once the primary's is in.
  Future<String> commit(String linkId, String deviceId);
  Future<({String eph, String nonce})> reveal(String linkId, String ephP);

  /// Code mode. Primary: remembers the commitment, returns its ephemeral key; then checks the reveal (the code).
  Future<String> lookup(String linkId, {required String deviceN, required String commit, required String deviceP});
  Future<String> openCommitment(String linkId, {required String eph, required String nonce});

  /// Code mode. New device: derives the keys from the primary's key; the code.
  Future<String> completeCode(String linkId, {required String ephP, required String deviceP});

  /// The sealed channel of one link (direction follows this core's role; counters in the store).
  Future<String> seal(String linkId, String plaintext);
  Future<String> open(String linkId, String data);
  Future<void> end(String linkId);

  /// Primary: the MLS certificate (JSON text) for a linked device's leaf key; only for a device in the last
  /// list this core signed.
  Future<String> signDeviceCert({required String userId, required String deviceId, required String platform, required String leafSigKey, required int issuedAt});

  Future<List<PinExport>> exportPins();

  /// Creates pins only where none exist; returns how many.
  Future<int> importPins(List<PinExport> pins);

  /// New device: installs the grant (the account's public identity and this device's certificate) and enters
  /// companion mode. Returns what the installed certificate names.
  Future<({String userId, String deviceId, String leafSigKey})> companionSetup({required String userId, required Identity identity, required String certJson});

  /// The account a companion core is linked to; null on a primary (or a core not set up yet).
  Future<({String userId, Identity identity})?> account();

  /// Succession (§5): the new primary mints its identity, then completes with the old primary's record.
  Future<Identity> successionStart();
  Future<Identity> successionComplete(String recordJson, String signature);

  /// The old primary: the signed record (JSON with `signature`) for [newIdentity].
  Future<String> signSuccession({required String userId, required String publishedSign, required Identity newIdentity, required int at});

  /// The old primary steps down to a companion of the account under [newIdentity].
  Future<void> retireIdentity({required String userId, required Identity newIdentity, required int at});

  /// A companion follows one succession record of its own account (from its pinned account key), installing
  /// [certJson] (its leaf under the new key) first when given. Returns the account's new identity.
  Future<Identity> adoptSuccession({required String userId, required Map<String, Object?> record, required String signature, String? certJson});
}

class RustLinkCrypto implements LinkCrypto {
  const RustLinkCrypto();

  BigInt get _now => BigInt.from(DateTime.now().millisecondsSinceEpoch);

  Future<T> _call<T>(Future<T> Function() work) async {
    try {
      return await work();
    } on core.CoreError catch (error) {
      throw CryptoException(error.message, code: error.code, keysLocked: error.code == 'storage');
    }
  }

  @override
  Future<String> qr(String linkId) => _call(() => core.linkQr(linkId: linkId, nowMs: _now));

  @override
  Future<({String linkId, String eph, String code})> accept(String qr) => _call(() async {
    final a = await core.linkAccept(qr: qr, nowMs: _now);
    return (linkId: a.linkId, eph: a.eph, code: a.code);
  });

  @override
  Future<String> complete(String linkId, String eph) => _call(() => core.linkComplete(linkId: linkId, eph: eph, nowMs: _now));

  @override
  Future<String> commit(String linkId, String deviceId) => _call(() => core.linkCommit(linkId: linkId, deviceId: deviceId, nowMs: _now));

  @override
  Future<({String eph, String nonce})> reveal(String linkId, String ephP) => _call(() async {
    final r = await core.linkReveal(linkId: linkId, ephP: ephP, nowMs: _now);
    return (eph: r.eph, nonce: r.nonce);
  });

  @override
  Future<String> lookup(String linkId, {required String deviceN, required String commit, required String deviceP}) =>
      _call(() => core.linkLookup(linkId: linkId, deviceN: deviceN, commit: commit, deviceP: deviceP, nowMs: _now));

  @override
  Future<String> openCommitment(String linkId, {required String eph, required String nonce}) =>
      _call(() => core.linkOpenCommitment(linkId: linkId, ephN: eph, nonce: nonce, nowMs: _now));

  @override
  Future<String> completeCode(String linkId, {required String ephP, required String deviceP}) =>
      _call(() => core.linkCompleteCode(linkId: linkId, ephP: ephP, deviceP: deviceP, nowMs: _now));

  @override
  Future<String> seal(String linkId, String plaintext) => _call(() => core.linkSeal(linkId: linkId, plaintext: plaintext, nowMs: _now));

  @override
  Future<String> open(String linkId, String data) => _call(() => core.linkOpen(linkId: linkId, data: data, nowMs: _now));

  @override
  Future<void> end(String linkId) => _call(() => core.linkEnd(linkId: linkId));

  @override
  Future<String> signDeviceCert({required String userId, required String deviceId, required String platform, required String leafSigKey, required int issuedAt}) =>
      _call(() => core.signDeviceCert(userId: userId, deviceId: deviceId, platform: platform, leafSigKey: leafSigKey, issuedAt: BigInt.from(issuedAt), nowMs: _now));

  @override
  Future<List<PinExport>> exportPins() => _call(() async => [
    for (final p in await core.exportPins())
      PinExport(
        contact: p.contact,
        identity: Identity(dh: p.identity.dh, sign: p.identity.sign),
        verified: p.verified,
        previous: [for (final k in p.previous) (sign: k.sign, until: k.until.toInt())],
      ),
  ]);

  @override
  Future<int> importPins(List<PinExport> pins) => _call(() => core.importPins(
    pins: [
      for (final p in pins)
        core.PinExport(
          contact: p.contact,
          identity: core.Identity(dh: p.identity.dh, sign: p.identity.sign),
          verified: p.verified,
          previous: [for (final k in p.previous) core.PreviousKey(sign: k.sign, until: BigInt.from(k.until))],
        ),
    ],
  ));

  @override
  Future<({String userId, String deviceId, String leafSigKey})> companionSetup({required String userId, required Identity identity, required String certJson}) => _call(() async {
    final cert = await core.companionSetup(userId: userId, identity: core.Identity(dh: identity.dh, sign: identity.sign), certJson: certJson);
    return (userId: cert.userId, deviceId: cert.deviceId, leafSigKey: cert.leafSigKey);
  });

  @override
  Future<({String userId, Identity identity})?> account() => _call(() async {
    final a = await core.account();
    return a == null ? null : (userId: a.userId, identity: Identity(dh: a.identity.dh, sign: a.identity.sign));
  });

  @override
  Future<Identity> adoptSuccession({required String userId, required Map<String, Object?> record, required String signature, String? certJson}) => _call(() async {
    final i = await core.adoptSuccession(userId: userId, recordJson: jsonEncode(record), signature: signature, certJson: certJson);
    return Identity(dh: i.dh, sign: i.sign);
  });

  @override
  Future<Identity> successionStart() => _call(() async {
    final i = await core.successionStart();
    return Identity(dh: i.dh, sign: i.sign);
  });

  @override
  Future<Identity> successionComplete(String recordJson, String signature) => _call(() async {
    final i = await core.successionComplete(recordJson: recordJson, signature: signature);
    return Identity(dh: i.dh, sign: i.sign);
  });

  @override
  Future<String> signSuccession({required String userId, required String publishedSign, required Identity newIdentity, required int at}) =>
      _call(() => core.signSuccession(userId: userId, publishedSign: publishedSign, newSign: newIdentity.sign, newDh: newIdentity.dh, at: BigInt.from(at)));

  @override
  Future<void> retireIdentity({required String userId, required Identity newIdentity, required int at}) =>
      _call(() => core.retireIdentity(userId: userId, newIdentity: core.Identity(dh: newIdentity.dh, sign: newIdentity.sign), at: BigInt.from(at)));
}

/// Test stand-in: no real key exchange. Both ends of a link agree on keys only if they saw the same QR (or the
/// same commitment), which is what the app's flows depend on; sealed messages carry a direction and counter
/// and are refused out of order, as the core does.
class FakeLinkCrypto implements LinkCrypto {
  FakeLinkCrypto({this.identity});

  /// The account key this fake holds (a primary); null for a new device or a companion.
  Identity? identity;
  final Map<String, ({String role, String secret, int sent, int received})> _links = {};
  final List<PinExport> pins = [];
  ({String userId, Identity identity, String certJson})? companion;
  final List<String> signedCerts = [];

  static String _code(String material) {
    final b = hash.sha256.convert(utf8.encode(material)).bytes;
    final n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) % 1000000;
    final s = n.toString().padLeft(6, '0');
    return '${s.substring(0, 3)} ${s.substring(3)}';
  }

  @override
  Future<String> qr(String linkId) async {
    final secret = 'secret-$linkId';
    _links[linkId] = (role: 'n', secret: secret, sent: 0, received: 0);
    return 'wb-link1.${base64Url.encode(utf8.encode(jsonEncode({'linkId': linkId, 'secret': secret}))).replaceAll('=', '')}';
  }

  @override
  Future<({String linkId, String eph, String code})> accept(String qr) async {
    if (identity == null && companion != null) throw const CryptoException('a linked device cannot link others', code: 'companion');
    if (!qr.startsWith('wb-link1.')) throw const CryptoException('not a link code', code: 'invalid');
    final m = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(qr.substring(9))))) as Map;
    final linkId = m['linkId'] as String, secret = m['secret'] as String;
    _links[linkId] = (role: 'p', secret: secret, sent: 0, received: 0);
    return (linkId: linkId, eph: 'eph-p-$linkId', code: _code(secret));
  }

  @override
  Future<String> complete(String linkId, String eph) async => _code(_links[linkId]!.secret);

  @override
  Future<String> commit(String linkId, String deviceId) async {
    _links[linkId] = (role: 'n', secret: 'committed-$linkId-$deviceId', sent: 0, received: 0);
    return 'commit-$linkId';
  }

  @override
  Future<({String eph, String nonce})> reveal(String linkId, String ephP) async => (eph: 'eph-n-$linkId', nonce: _links[linkId]!.secret);

  @override
  Future<String> lookup(String linkId, {required String deviceN, required String commit, required String deviceP}) async {
    _links[linkId] = (role: 'p', secret: '', sent: 0, received: 0);
    return 'eph-p-$linkId';
  }

  @override
  Future<String> openCommitment(String linkId, {required String eph, required String nonce}) async {
    _links[linkId] = (role: 'p', secret: nonce, sent: 0, received: 0);
    return _code(nonce);
  }

  @override
  Future<String> completeCode(String linkId, {required String ephP, required String deviceP}) async => _code(_links[linkId]!.secret);

  @override
  Future<String> seal(String linkId, String plaintext) async {
    final l = _links[linkId] ?? (throw const CryptoException('no such link', code: 'unknown-link'));
    _links[linkId] = (role: l.role, secret: l.secret, sent: l.sent + 1, received: l.received);
    return base64Url.encode(utf8.encode(jsonEncode({'from': l.role, 'n': l.sent, 'k': l.secret, 'p': plaintext}))).replaceAll('=', '');
  }

  @override
  Future<String> open(String linkId, String data) async {
    final l = _links[linkId] ?? (throw const CryptoException('no such link', code: 'unknown-link'));
    final m = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(data)))) as Map;
    if (m['from'] == l.role || m['k'] != l.secret) throw const CryptoException('not sealed for this end of the link', code: 'auth');
    if (m['n'] != l.received) throw const CryptoException('out of order', code: 'replay');
    _links[linkId] = (role: l.role, secret: l.secret, sent: l.sent, received: l.received + 1);
    return m['p'] as String;
  }

  @override
  Future<void> end(String linkId) async => _links.remove(linkId);

  @override
  Future<String> signDeviceCert({required String userId, required String deviceId, required String platform, required String leafSigKey, required int issuedAt}) async {
    final cert = jsonEncode({'v': 1, 'userId': userId, 'deviceId': deviceId, 'platform': platform, 'leafSigKey': leafSigKey, 'aikSign': identity?.sign, 'issuedAt': issuedAt, 'sig': 'fake'});
    signedCerts.add(cert);
    return cert;
  }

  @override
  Future<List<PinExport>> exportPins() async => List.of(pins);

  @override
  Future<int> importPins(List<PinExport> incoming) async {
    var created = 0;
    for (final p in incoming) {
      if (pins.any((q) => q.contact == p.contact)) continue;
      pins.add(p);
      created++;
    }
    return created;
  }

  @override
  Future<({String userId, String deviceId, String leafSigKey})> companionSetup({required String userId, required Identity identity, required String certJson}) async {
    final cert = jsonDecode(certJson) as Map;
    if (cert['aikSign'] != identity.sign || cert['userId'] != userId) throw const CryptoException('certificate does not verify', code: 'invalid');
    companion = (userId: userId, identity: identity, certJson: certJson);
    return (userId: cert['userId'] as String, deviceId: cert['deviceId'] as String, leafSigKey: cert['leafSigKey'] as String);
  }

  @override
  Future<({String userId, Identity identity})?> account() async {
    final c = companion;
    return c == null ? null : (userId: c.userId, identity: c.identity);
  }

  Identity? _minted;

  /// Tests: records this companion followed.
  final List<Map<String, Object?>> adopted = [];

  @override
  Future<Identity> adoptSuccession({required String userId, required Map<String, Object?> record, required String signature, String? certJson}) async {
    // A companion follows from its pinned account key; a full core (M6) from its own, and becomes a companion.
    final from = companion?.identity ?? identity ?? (throw const CryptoException('no account here', code: 'invalid'));
    if (record['userId'] != userId || record['oldSign'] != from.sign) throw const CryptoException('the record does not continue from the pin', code: 'invalid');
    final next = Identity(dh: record['newDh']! as String, sign: record['newSign']! as String);
    adopted.add(record);
    companion = (userId: userId, identity: next, certJson: certJson ?? companion?.certJson ?? '');
    identity = null;
    return next;
  }

  @override
  Future<Identity> successionStart() async => _minted = Identity(dh: 'new-dh-${DateTime.now().microsecondsSinceEpoch}', sign: 'new-sign');

  @override
  Future<Identity> successionComplete(String recordJson, String signature) async {
    final minted = _minted ?? (throw const CryptoException('no succession started', code: 'invalid'));
    identity = minted;
    companion = null;
    return minted;
  }

  @override
  Future<String> signSuccession({required String userId, required String publishedSign, required Identity newIdentity, required int at}) async {
    if (identity?.sign != publishedSign) throw const CryptoException('not the published identity', code: 'mismatch');
    return jsonEncode({'v': 1, 'userId': userId, 'oldSign': publishedSign, 'newSign': newIdentity.sign, 'newDh': newIdentity.dh, 'at': at, 'signature': 'fake'});
  }

  @override
  Future<void> retireIdentity({required String userId, required Identity newIdentity, required int at}) async {
    identity = null;
    companion = (userId: userId, identity: newIdentity, certJson: '');
  }
}
