/// Device lists and device certificates (docs/workspace-architecture.md §1, §2, §3; docs/devices.md).
///
/// A port of the web client's `public/devices.js`: the same canonical bytes, the same checks, the same
/// pin. A DeviceList names every device of an account and is signed with the account identity key (AIK),
/// the Ed25519 half of the identity whose safety number contacts verify; every listed device also has an
/// AIK-signed certificate. A contact's device is trusted only if a list signed by the pinned AIK names it,
/// never because the server says so.
///
/// The app verifies and pins lists, and the device holding the AIK publishes the account's list: chatcore
/// validates and signs it (`ChatCrypto.signDeviceList`), and labels are sealed with [sealMeta] under the key
/// derived from chatcore's `deviceMetaSignature`, exactly as devices.js does.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/export.dart' show AEADParameters, AESEngine, GCMBlockCipher, KeyParameter;

const maxDevices = 16;
const _maxVersion = 2147483647;
const _metaLabel = 'webrtc-bun-devicemeta-v1';
const devicePlatforms = {'web', 'ios', 'android', 'macos', 'windows', 'linux'};
const _metaMaxLabel = 64;
const _listLabel = 'webrtc-bun-devicelist-v1', _certLabel = 'webrtc-bun-devicecert-v1', _bindLabel = 'webrtc-bun-devicebind-v1', _claimLabel = 'webrtc-bun-deviceclaim-v1';
final _userId = RegExp(r'^[A-Za-z0-9_-]{1,64}$');
final _deviceId = RegExp(r'^[A-Za-z0-9_-]{22}$');
final _hash = RegExp(r'^[A-Za-z0-9_-]{43}$');
final _key = RegExp(r'^[A-Za-z0-9_-]{43}$');
final _sig = RegExp(r'^[A-Za-z0-9_-]{86}$');
final _meta = RegExp(r'^[A-Za-z0-9_-]{38,683}$');

class DeviceFormatException implements Exception {
  const DeviceFormatException(this.message);
  final String message;
  @override
  String toString() => message;
}

Never _fail(String message) => throw DeviceFormatException(message);

String b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// Strict base64url: no padding, and the text must round-trip (no stray trailing bits).
Uint8List unb64(String text) {
  final Uint8List bytes;
  try {
    bytes = base64Url.decode(text + '=' * ((4 - text.length % 4) % 4));
  } on FormatException {
    _fail('Invalid base64');
  }
  if (b64(bytes) != text) _fail('Non-canonical base64');
  return bytes;
}

/// A fresh random device id: 16 bytes, base64url (22 characters), like the web client's.
String newDeviceId([Random? random]) {
  final source = random ?? Random.secure();
  return b64(List<int>.generate(16, (_) => source.nextInt(256)));
}

/// TLS-style writer: u16-length-prefixed strings, big-endian integers.
class _Writer {
  final _out = BytesBuilder();
  void u8(int value) => _out.addByte(value & 255);
  void u16(int value) => _out.add([value >> 8 & 255, value & 255]);
  void u32(int value) => _out.add([value >> 24 & 255, value >> 16 & 255, value >> 8 & 255, value & 255]);
  // Millisecond timestamps exceed 32 bits: high and low words, as devices.js does.
  void u64(int value) {
    u32(value ~/ 4294967296);
    u32(value % 4294967296);
  }

  void bytes8(List<int> value) {
    if (value.length > 255) _fail('Field too long');
    u8(value.length);
    _out.add(value);
  }

  void bytes16(List<int> value) {
    if (value.length > 65535) _fail('Field too long');
    u16(value.length);
    _out.add(value);
  }

  void text16(String value) => bytes16(utf8.encode(value));
  Uint8List done() => _out.toBytes();
}

bool _exact(Object? value, List<String> keys) =>
    value is Map && value.length == keys.length && keys.every(value.containsKey);
bool _timestamp(Object? value) => value is int && value >= 0 && value <= 9007199254740991;

/// Strict schema check: exact keys, canonical encodings, devices sorted by id with no duplicates.
Map<String, dynamic> validateList(Object? list) {
  if (!_exact(list, const ['v', 'userId', 'version', 'prevHash', 'devices'])) _fail('Device list has unexpected fields');
  final m = (list as Map).cast<String, dynamic>();
  final userId = m['userId'], version = m['version'], prevHash = m['prevHash'], devices = m['devices'];
  if (m['v'] != 1 || userId is! String || !_userId.hasMatch(userId)) _fail('Invalid device list owner');
  if (version is! int || version < 1 || version > _maxVersion) _fail('Invalid device list version');
  if (version == 1 ? prevHash != '' : prevHash is! String || !_hash.hasMatch(prevHash)) _fail('Invalid previous-list hash');
  if (devices is! List || devices.isEmpty || devices.length > maxDevices) _fail('A device list names 1–$maxDevices devices');
  var previous = '';
  for (final device in devices) {
    if (!_exact(device, const ['deviceId', 'addedAt', 'meta'])) _fail('Device entry has unexpected fields');
    final id = device['deviceId'], meta = device['meta'];
    if (id is! String || !_deviceId.hasMatch(id)) _fail('Invalid device id');
    if (!_timestamp(device['addedAt'])) _fail('Invalid device timestamp');
    if (meta != '' && !(meta is String && _meta.hasMatch(meta))) _fail('Invalid device metadata');
    // Byte order of the ASCII ids, as JavaScript compares strings.
    if (id.compareTo(previous) <= 0) _fail('Devices must be sorted by id without duplicates');
    previous = id;
  }
  if (prevHash is String && prevHash.isNotEmpty) unb64(prevHash);
  return m;
}

/// The canonical bytes the AIK signs for a list (devices.js `listBytes`).
Uint8List listBytes(Object? list) {
  final m = validateList(list);
  final prevHash = m['prevHash'] as String;
  final out = _Writer()
    ..text16(_listLabel)
    ..text16(m['userId'] as String)
    ..u32(m['version'] as int)
    ..bytes8(prevHash.isEmpty ? const [] : unb64(prevHash));
  final devices = m['devices'] as List;
  out.u16(devices.length);
  for (final device in devices) {
    final meta = device['meta'] as String;
    out
      ..text16(device['deviceId'] as String)
      ..u64(device['addedAt'] as int)
      ..bytes16(meta.isEmpty ? const [] : unb64(meta));
  }
  return out.done();
}

/// The canonical bytes of the certificate a list implies for one of its devices (M1: no leaf key yet).
Uint8List certBytes(String userId, Map device) {
  final id = device['deviceId'], issuedAt = device['addedAt'];
  if (!_userId.hasMatch(userId) || id is! String || !_deviceId.hasMatch(id)) _fail('Invalid device certificate subject');
  if (!_timestamp(issuedAt)) _fail('Invalid certificate timestamp');
  return (_Writer()
        ..text16(_certLabel)
        ..text16(userId)
        ..text16(id)
        ..bytes8(const [])
        ..u64(issuedAt as int))
      .done();
}

bool verifyBytes(String aikSign, Uint8List bytes, Object? signature) {
  if (!_key.hasMatch(aikSign) || signature is! String || !_sig.hasMatch(signature)) return false;
  try {
    return ed.verify(ed.PublicKey(unb64(aikSign)), bytes, unb64(signature));
  } catch (_) {
    return false;
  }
}

String listHash(Uint8List bytes) => b64(hash.sha256.convert(bytes).bytes);

/// The highest verified list of one account: version, hash, the devices it names, and every device a
/// pinned list later dropped (tombstones: they never come back under this key).
class DevicePin {
  const DevicePin({required this.aik, required this.version, required this.hash, required this.devices, required this.revoked, this.labels = const {}});
  final String aik;
  final int version;
  final String hash;
  final List<String> devices;
  final List<String> revoked;

  /// Our own account's pin only: the labels this device could read in its lists (device id → label), so it can name a
  /// device a later list dropped (M6 §6.2).
  final Map<String, String> labels;

  DevicePin withLabels(Map<String, String> next) => DevicePin(aik: aik, version: version, hash: hash, devices: devices, revoked: revoked, labels: next);

  Map<String, dynamic> toJson() => {'aik': aik, 'version': version, 'hash': hash, 'devices': devices, 'revoked': revoked, if (labels.isNotEmpty) 'labels': labels};
  static DevicePin? fromJson(Object? json) {
    if (json is! Map) return null;
    try {
      return DevicePin(
        aik: json['aik'] as String,
        version: json['version'] as int,
        hash: json['hash'] as String,
        devices: (json['devices'] as List? ?? const []).cast<String>(),
        revoked: (json['revoked'] as List? ?? const []).cast<String>(),
        labels: (json['labels'] as Map? ?? const {}).cast<String, String>(),
      );
    } catch (_) {
      return null;
    }
  }
}

/// The outcome of [verifyView]. [reason] uses devices.js's vocabulary: none, owner, signature,
/// certificate, rollback, equivocation, fork, revoked, malformed.
class DeviceCheck {
  const DeviceCheck.ok({required String this.hash, required DevicePin this.pin, required this.version, required this.count}) : reason = null;
  const DeviceCheck.failed(String this.reason) : hash = null, pin = null, version = 0, count = 0;
  final String? reason;
  final String? hash;
  final DevicePin? pin;
  final int version;
  final int count;
  bool get ok => reason == null;
}

/// A list (as served) is trusted only if: it is well formed and canonical, names its owner, carries a valid
/// AIK signature, every device has a valid AIK-signed certificate, and it does not go back on the pin: not
/// an older version, not a different list at the pinned version, the next version chains to the pinned
/// hash, and no device the pinned history removed comes back.
DeviceCheck verifyView({
  required String userId,
  required String aikSign,
  required Object? list,
  required Object? signature,
  required Object? certs,
  DevicePin? pin,
}) {
  try {
    if (list == null) return const DeviceCheck.failed('none');
    if (list is! Map || list['userId'] != userId) return const DeviceCheck.failed('owner');
    final bytes = listBytes(list);
    if (!verifyBytes(aikSign, bytes, signature)) return const DeviceCheck.failed('signature');
    final devices = (list['devices'] as List).cast<Map>();
    for (final device in devices) {
      final cert = certs is Map ? certs[device['deviceId']] : null;
      if (!verifyBytes(aikSign, certBytes(userId, device), cert)) return const DeviceCheck.failed('certificate');
    }
    final digest = listHash(bytes), version = list['version'] as int;
    final ids = [for (final device in devices) device['deviceId'] as String];
    final same = pin != null && pin.aik == aikSign;
    if (same) {
      if (version < pin.version) return const DeviceCheck.failed('rollback');
      if (version == pin.version && digest != pin.hash) return const DeviceCheck.failed('equivocation');
      if (version == pin.version + 1 && list['prevHash'] != pin.hash) return const DeviceCheck.failed('fork');
      if (ids.any(pin.revoked.contains)) return const DeviceCheck.failed('revoked');
    }
    final revoked = same ? {...pin.revoked, ...pin.devices.where((id) => !ids.contains(id))}.toList() : <String>[];
    final kept = revoked.length > 256 ? revoked.sublist(revoked.length - 256) : revoked;
    return DeviceCheck.ok(
      hash: digest,
      pin: DevicePin(aik: aikSign, version: version, hash: digest, devices: ids, revoked: kept),
      version: version,
      count: ids.length,
    );
  } catch (_) {
    return const DeviceCheck.failed('malformed');
  }
}

/// What a device signs with its own key to bind a session to its id (devices.js `bindBytes`): the
/// server's single-use challenge for this session, the account and the device.
Uint8List bindBytes(String userId, String deviceId, String challenge) {
  if (!_userId.hasMatch(userId) || !_deviceId.hasMatch(deviceId)) _fail('Invalid device binding');
  if (!_hash.hasMatch(challenge)) _fail('Invalid device challenge');
  return (_Writer()
        ..text16(_bindLabel)
        ..text16(userId)
        ..text16(deviceId)
        ..bytes8(unb64(challenge)))
      .done();
}

/// What the account identity key signs to claim the account's messaging inbox (devices.js `claimBytes`).
/// The app never signs these itself: chatcore's `prove_identity` builds and signs them inside the core.
Uint8List claimBytes(String userId, String deviceId, String challenge) {
  if (!_userId.hasMatch(userId) || !_deviceId.hasMatch(deviceId)) _fail('Invalid identity claim');
  if (!_hash.hasMatch(challenge)) _fail('Invalid device challenge');
  return (_Writer()
        ..text16(_claimLabel)
        ..text16(userId)
        ..text16(deviceId)
        ..bytes8(unb64(challenge)))
      .done();
}

/// This app's device on one account: its id and its own Ed25519 device key, which proves to the server
/// that a session is this device (never just knowing the id).
class LocalDevice {
  LocalDevice._(this.deviceId, this._key);
  final String deviceId;
  final ed.PrivateKey _key;
  String get publicKey => b64(ed.public(_key).bytes);
  String sign(Uint8List bytes) => b64(ed.sign(_key, bytes));
}

/// Device ids and keys (secure storage in the app) and contacts' pinned device lists (SharedPreferences).
abstract class DevicePrefs {
  /// `{"deviceId": ..., "seed": ...}` for this account on this install, or null.
  Future<String?> readDevice(String userId);
  Future<void> writeDevice(String userId, String value);
  DevicePin? pin(String userId, String contactId);
  void setPin(String userId, String contactId, DevicePin pin);
}

class MemoryDevicePrefs implements DevicePrefs {
  final Map<String, String> devices = {};
  final Map<String, DevicePin> pins = {};
  @override
  Future<String?> readDevice(String userId) async => devices[userId];
  @override
  Future<void> writeDevice(String userId, String value) async => devices[userId] = value;
  @override
  DevicePin? pin(String userId, String contactId) => pins['$userId:$contactId'];
  @override
  void setPin(String userId, String contactId, DevicePin pin) => pins['$userId:$contactId'] = pin;
}

/// This install's device for an account, created on first use. The id and key live and die together:
/// an install that lost either starts as a new device.
Future<LocalDevice> localDevice(DevicePrefs prefs, String userId, [Random? random]) async {
  try {
    final stored = jsonDecode(await prefs.readDevice(userId) ?? 'null');
    if (stored is Map && stored['deviceId'] is String && _deviceId.hasMatch(stored['deviceId'] as String) && stored['seed'] is String) {
      final seed = unb64(stored['seed'] as String);
      if (seed.length == 32) return LocalDevice._(stored['deviceId'] as String, ed.newKeyFromSeed(seed));
    }
  } catch (_) {}
  final source = random ?? Random.secure();
  final seed = Uint8List.fromList(List<int>.generate(32, (_) => source.nextInt(256)));
  final id = newDeviceId(source);
  await prefs.writeDevice(userId, jsonEncode({'deviceId': id, 'seed': b64(seed)}));
  return LocalDevice._(id, ed.newKeyFromSeed(seed));
}

// ---------- Sealed device metadata (devices.js deviceMetaKey / sealMeta / openMeta) ----------
/// The AES-256-GCM key that seals list labels: HKDF-SHA-256 over the AIK's signature of the devicemeta label
/// and the user id ([seed], from chatcore `deviceMetaSignature`), zero salt, info = the label.
Uint8List deviceMetaKey(String seed) {
  final ikm = unb64(seed);
  final prk = hash.Hmac(hash.sha256, List.filled(32, 0)).convert(ikm).bytes;
  return Uint8List.fromList(hash.Hmac(hash.sha256, prk).convert([...utf8.encode(_metaLabel), 1]).bytes);
}

/// What the identity key signs to seed [deviceMetaKey] (devices.js deviceMetaKey; chatcore meta_bytes).
Uint8List metaSeedBytes(String userId) {
  if (!_userId.hasMatch(userId)) _fail('Invalid user id');
  return (_Writer()
        ..text16(_metaLabel)
        ..text16(userId))
      .done();
}

Uint8List _metaAad(String userId, String deviceId) => (_Writer()
      ..text16(_metaLabel)
      ..text16(userId)
      ..text16(deviceId))
    .done();

/// Seals `{label, platform}` for one list entry (12-byte IV ‖ ciphertext ‖ tag, base64url); the AAD binds it
/// to that account and device.
/// [via]: `'code'` for a device linked by short code (docs/m6-account-key.md §5), sealed with its label.
String sealMeta(Uint8List key, String userId, String deviceId, {required String label, required String platform, String? via, Uint8List? iv}) {
  if (!devicePlatforms.contains(platform)) _fail('Invalid device platform');
  if (via != null && via != 'code') _fail('Invalid device meta');
  final short = label.length > _metaMaxLabel ? label.substring(0, _metaMaxLabel) : label;
  final plain = Uint8List.fromList(utf8.encode(jsonEncode({'label': short, 'platform': platform, 'via': ?via})));
  final nonce = iv ?? Uint8List.fromList(List<int>.generate(12, (_) => Random.secure().nextInt(256)));
  final gcm = GCMBlockCipher(AESEngine())..init(true, AEADParameters(KeyParameter(key), 128, nonce, _metaAad(userId, deviceId)));
  return b64([...nonce, ...gcm.process(plain)]);
}

/// The entry's `{label, platform}`, or null when it is empty, not ours, or tampered with.
Map<String, String>? openMeta(Uint8List key, String userId, String deviceId, String meta) {
  if (meta.isEmpty) return null;
  try {
    final bytes = unb64(meta);
    final gcm = GCMBlockCipher(AESEngine())..init(false, AEADParameters(KeyParameter(key), 128, Uint8List.sublistView(bytes, 0, 12), _metaAad(userId, deviceId)));
    final value = jsonDecode(utf8.decode(gcm.process(Uint8List.sublistView(bytes, 12))));
    final via = value is Map ? value['via'] : null;
    if (value is Map && value.length == (via == null ? 2 : 3) && (via == null || via == 'code') && value['label'] is String && devicePlatforms.contains(value['platform'])) {
      return {'label': value['label'] as String, 'platform': value['platform'] as String, 'via': ?via as String?};
    }
  } catch (_) {}
  return null;
}

// ---------- Linking and succession (docs/m5-linking.md §1.3, §5.1) ----------
const _linkStartLabel = 'webrtc-bun-linkstart-v1', _linkClaimLabel = 'webrtc-bun-linkclaim-v1', _successionLabel = 'webrtc-bun-succession-v1';

/// What a new device's key signs to start a link: `text16(label) ‖ text16(deviceId) ‖ text16(platform) ‖
/// bytes8(deviceKey raw 32)`.
Uint8List linkStartBytes(String deviceId, String platform, String deviceKey) {
  if (!_deviceId.hasMatch(deviceId) || !devicePlatforms.contains(platform) || !_key.hasMatch(deviceKey)) _fail('Invalid link start');
  return (_Writer()
        ..text16(_linkStartLabel)
        ..text16(deviceId)
        ..text16(platform)
        ..bytes8(unb64(deviceKey)))
      .done();
}

/// What a new device's key signs to claim its session: `text16(label) ‖ text16(linkId) ‖ text16(deviceId) ‖
/// bytes8(claim raw 32)`.
Uint8List linkClaimBytes(String linkId, String deviceId, String claim) {
  if (!_deviceId.hasMatch(linkId) || !_deviceId.hasMatch(deviceId) || !_hash.hasMatch(claim)) _fail('Invalid link claim');
  return (_Writer()
        ..text16(_linkClaimLabel)
        ..text16(linkId)
        ..text16(deviceId)
        ..bytes8(unb64(claim)))
      .done();
}

/// What the old account key signs to hand the account to a new one (a succession record).
Uint8List successionBytes(String userId, String oldSign, String newSign, String newDh, int at) {
  if (!_userId.hasMatch(userId) || !_key.hasMatch(oldSign) || !_key.hasMatch(newSign) || !_key.hasMatch(newDh) || at < 0) _fail('Invalid succession record');
  return (_Writer()
        ..text16(_successionLabel)
        ..text16(userId)
        ..bytes8(unb64(oldSign))
        ..bytes8(unb64(newSign))
        ..bytes8(unb64(newDh))
        ..u64(at))
      .done();
}

/// A succession chain as served (`succession`, oldest first) checked from [pinnedSign]: each record verifies
/// under the previous key and names the next, and the chain ends at [servedSign]. Records the user id.
bool verifySuccessionChain(String userId, String pinnedSign, String servedSign, List<Map<String, dynamic>> records) {
  var key = pinnedSign;
  if (records.isEmpty || records.length > 8) return false;
  try {
    for (final r in records) {
      if (r['v'] != 1 || r['userId'] != userId || r['oldSign'] != key) return false;
      final bytes = successionBytes(userId, r['oldSign'] as String, r['newSign'] as String, r['newDh'] as String, r['at'] as int);
      if (!verifyBytes(key, bytes, r['signature'])) return false;
      key = r['newSign'] as String;
    }
  } catch (_) {
    return false;
  }
  return key == servedSign;
}

// ---------- The account key backup record (docs/m6-account-key.md §3.3) ----------
const _backupKeysLabel = 'webrtc-bun-backup-keys-v2';

/// The bytes the account key signs for a backup record: everything in it except the boxes.
Uint8List backupKeysBytes(Map<String, Object?> record) {
  final kdf = record['kdf'];
  if (kdf is! Map || record['userId'] is! String || record['epoch'] is! int) _fail('Invalid backup record');
  final out = _Writer()
    ..text16(_backupKeysLabel)
    ..text16(record['userId']! as String)
    ..bytes8(unb64(record['aikSign']! as String))
    ..u32(record['epoch']! as int)
    ..bytes8(unb64(kdf['salt']! as String))
    ..u32(kdf['m']! as int)
    ..u32(kdf['t']! as int)
    ..u32(kdf['p']! as int);
  for (final field in ['passHash', 'recoveryHash', 'passProofHash', 'recoveryProofHash']) {
    out.bytes8(unb64(record[field]! as String));
  }
  return out.done();
}

/// What the server keeps of a passphrase or recovery proof: SHA-256 of its raw bytes (§3.5).
String proofHash(String proof) => b64(hash.sha256.convert(unb64(proof)).bytes);

/// A served backup record is usable only if the account's current key signed it (§3.3, §4 step 1).
bool verifyBackupRecord(Map<String, Object?> record, {required String userId, required String aikSign}) {
  try {
    return record['v'] == 1 && record['userId'] == userId && record['aikSign'] == aikSign && verifyBytes(aikSign, backupKeysBytes(record), record['signature']);
  } catch (_) {
    return false;
  }
}
