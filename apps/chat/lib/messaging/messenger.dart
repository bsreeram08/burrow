import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../core/devices.dart';
import '../core/events.dart';
import '../core/pair_id.dart';
import '../crypto/chat_crypto.dart';
import '../store/disposition.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import 'group_messenger.dart';
import 'group_sync.dart' show OwnDeviceList;
import 'payload.dart';

/// Read receipts: at most one `read` per contact per 2 s.
const readIntervalMs = 2000;

/// Typing: `on:true` at most every 4 s; a received one older than 15 s is dropped; shown for 6 s.
const typingThrottleMs = 4000;
const typingFreshMs = 15000;
const typingHideMs = 6000;

/// A 1:1 chat's move to MLS (m5 §8): the first sender tries at most once per contact in this time, and a
/// receiver waits this long for the pointer's group.
const dmMoveRetryMs = 600000;

/// Why a linked device can't send in a chat that is still on the Double Ratchet.
const companionNotice = 'Messages in this chat go through your other device until it moves to the new encryption.';

/// The system line both sides show where a 1:1 chat moved.
const dmMovedNote = 'Messages in this chat now use the new encryption.';

/// End-to-end encrypted contact messaging over the server mailbox. Port of the
/// web client's account.js receive/send path: decrypt, validate, store, then
/// acknowledge and commit the ratchet; encrypted delivery receipts; burn; and a
/// queue that sends oldest first and pauses on a changed security code.
/// Per-account rotation settings on this device (web: localStorage `rotation-*`).
abstract class RotationPrefs {
  int get mine;
  set mine(int value);
  int peer(String contactId);
  void setPeer(String contactId, int value);
  String? told(String contactId);
  void setTold(String contactId, String value);
  void clearTold();
}

class MemoryRotationPrefs implements RotationPrefs {
  @override
  int mine = 0;
  final Map<String, int> peers = {};
  final Map<String, String> _told = {};
  @override
  int peer(String contactId) => peers[contactId] ?? 0;
  @override
  void setPeer(String contactId, int value) => peers[contactId] = value;
  @override
  String? told(String contactId) => _told[contactId];
  @override
  void setTold(String contactId, String value) => _told[contactId] = value;
  @override
  void clearTold() => _told.clear();
}

/// One of this account's devices (Settings → Devices).
class OwnDevice {
  const OwnDevice({required this.id, required this.platform, required this.state, required this.primary, required this.current, this.label, this.lastSeenAt, this.viaCode = false});
  final String id;
  final String platform;

  /// From the sealed list entry, when this device can open it.
  final String? label;

  /// pending, listed, revoked or placeholder.
  final String state;
  final bool primary;
  final bool current;
  final int? lastSeenAt;

  /// Linked by short code (its sealed meta says `via: 'code'`, M6 §5), when this device can read the meta.
  final bool viaCode;
}

class Messenger {
  Messenger({
    required this.api,
    required this.crypto,
    required this.store,
    required this.me,
    required this.contactById,
    required this.mutualContacts,
    required this.ack,
    this.viewing,
    RotationPrefs? rotation,
    DevicePrefs? devices,
    bool Function()? readReceipts,
    int Function()? now,
  }) : rotation = rotation ?? MemoryRotationPrefs(),
       devices = devices ?? MemoryDevicePrefs(),
       readReceipts = readReceipts ?? (() => true),
       _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  /// "Send read receipts" (default on). Off: none are sent and others' are not shown.
  final bool Function() readReceipts;
  final int Function() _now;

  /// Chat key rotation settings (account.js `rotation-*`).
  final RotationPrefs rotation;

  /// This device's id and contacts' pinned device lists (account.js `device-id-v1`, `device-pins-v1`).
  final DevicePrefs devices;

  final Api api;
  final ChatCrypto crypto;
  final MessageStore store;
  final User me;
  final Contact? Function(String id) contactById;
  final List<Contact> Function() mutualContacts;
  final void Function(String envelopeId) ack;

  /// The contact id currently on screen, if any (no unread count for it).
  final String? Function()? viewing;

  final _notices = StreamController<String>.broadcast();
  final _unread = StreamController<Map<String, int>>.broadcast();
  final _identity = StreamController<String>.broadcast();
  final _typing = StreamController<Set<String>>.broadcast();
  final Map<String, int> unread = {};
  final Map<String, int> _attempts = {};
  final Set<String> flagged = {};
  Future<void> _inbound = Future.value();
  bool _flushing = false, _flushAgain = false, _disposed = false;
  Timer? _retryTimer;

  Stream<String> get notices => _notices.stream;
  Stream<Map<String, int>> get unreadChanges => _unread.stream;

  /// A contact's security code changed (contact id).
  Stream<String> get identityChanges => _identity.stream;

  /// Contact ids currently typing to us.
  Stream<Set<String>> get typingChanges => _typing.stream;
  Set<String> get typing => _typingTimers.keys.toSet();

  String conversationWith(String contactId) => pairId(me.id, contactId);

  // ---------- Keys and the active device ----------
  /// Whether this device holds the account's published identity. Only the active device
  /// uploads keys, sends envelopes, and processes or acknowledges incoming envelopes:
  /// they belong to the active device, and acknowledging them here would delete them.
  bool active = false;

  /// This device holds the account's published key (docs/m6-account-key.md §0): it signs lists and certificates,
  /// whether or not it is the inbox device ([active]).
  bool full = false;

  /// The key database refused to work mid-session (tampered, reset, identity missing): stop processing and
  /// acknowledging until the user recovers. Envelopes stay on the server.
  bool keysLocked = false;
  final _lockedChanges = StreamController<bool>.broadcast();
  Stream<bool> get lockedChanges => _lockedChanges.stream;
  final _activeChanges = StreamController<bool>.broadcast();
  Stream<bool> get activeChanges => _activeChanges.stream;

  /// A resumed take-over found the server already serving this device's key (m5 §5.2).
  void markActive() => _setActive(true);

  void _setActive(bool value) {
    if (active == value) return;
    active = value;
    _activeChanges.add(value);
  }

  /// This install's device for the account (docs/devices.md): its id and device key, created on first use.
  Future<LocalDevice> device() => _device ??= localDevice(devices, me.id);
  Future<LocalDevice>? _device;

  /// Binds this session to our device, signing the server's challenge with the device key. With [claim]
  /// (only when our identity is the published one) the identity key also proves it holds the account keys
  /// for the same challenge, and the device takes the account's messaging inbox.
  /// Best effort: a server without devices still delivers as before.
  Future<void> _announce({bool claim = false}) async {
    try {
      final local = await device(), challenge = await api.deviceChallenge();
      await api.announceDevice(
        local.deviceId,
        deviceKey: local.publicKey,
        challenge: challenge,
        signature: local.sign(bindBytes(me.id, local.deviceId, challenge)),
        identityProof: claim ? await crypto.proveIdentity(me.id, local.deviceId, challenge) : null,
      );
    } catch (_) {}
  }

  /// Binds this session to our device with the device key only (no account key needed): a device signing in on an
  /// account can then publish the list naming itself after a restore (M6 §4).
  Future<void> bindSession() => _announce();

  /// Compares the server's published identity with ours before uploading anything.
  /// Re-run on sign-in, on reconnect and on a `keys` event for our own id.
  Future<bool> checkActive() async {
    if (companion) {
      // A linked device never holds the account's keys: nothing to compare or upload.
      _setActive(false);
      return false;
    }
    final count = await api.keyCount();
    final mine = await crypto.identity();
    final published = count.identity == null ? null : Identity.fromJson(count.identity!);
    full = published == null || published == mine;
    if (published != null && published != mine) {
      // Another device holds the keys: this one is a pending device of the account.
      await _announce();
      _setActive(false);
      return false;
    }
    // Every full device holds the account key (docs/m6-account-key.md §0); only the inbox device runs the 1:1
    // Double Ratchet. Another full device leaves the inbox where it is and sends only in chats that moved to MLS.
    if (published != null && !await _holdsInbox()) {
      await _announce();
      _setActive(false);
      unawaited(flush());
      return false;
    }
    // Before the first upload there is nothing to prove: the upload of the new identity claims the inbox.
    await _announce(claim: published != null);
    final upload = await crypto.preparePrekeys(DateTime.now(), oneTimeOnServer: published == null ? 0 : count.oneTimePreKeys);
    final spkId = upload.signedPreKey['id'];
    if (published == null || upload.oneTimePreKeys != null || upload.rotated || count.signedPreKeyId != spkId) await api.uploadKeys(upload.toJson());
    _setActive(true);
    unawaited(flush());
    return true;
  }

  /// Pins our own verified list with the labels this device can read in it (others kept from the previous pin, also
  /// for devices the list dropped, within the pin's bounds), so a later key change can name what it removed (M6 §6.2).
  Future<void> _pinOwn(DevicePin pin, Object? list) async {
    final previous = devices.pin(me.id, me.id)?.labels ?? const <String, String>{};
    Uint8List? key;
    try {
      key = deviceMetaKey(await crypto.deviceMetaSignature(me.id));
    } catch (_) {
      // Without the account key: the labels pinned before.
    }
    final labels = <String, String>{};
    for (final d in ((list as Map?)?['devices'] as List? ?? const []).cast<Map>()) {
      final id = d['deviceId'] as String, metaKey = key;
      final label = (metaKey == null ? null : openMeta(metaKey, me.id, id, d['meta'] as String? ?? ''))?['label'] ?? previous[id];
      if (label != null) labels[id] = label;
    }
    for (final id in [...pin.devices, ...pin.revoked]) {
      final label = previous[id];
      if (label != null) labels.putIfAbsent(id, () => label);
    }
    devices.setPin(me.id, me.id, pin.withLabels(labels));
  }

  /// This device is the account's inbox device (the server's `primary` row), or the account has none yet.
  Future<bool> _holdsInbox() async {
    final id = (await device()).deviceId;
    final List<Map> rows;
    try {
      rows = ((await api.devices(me.username))['devices'] as List? ?? const []).cast<Map>();
    } on ApiException {
      return true; // A server without the device registry: one device holds everything, as before.
    }
    final inbox = rows.where((r) => r['primary'] == true && r['state'] != 'revoked').firstOrNull;
    return inbox == null || inbox['id'] == id;
  }

  /// On the identity-key holder (account.js `syncDevices`): verify the served list against our own key and
  /// pin, and publish the next version if this device is missing from it or isn't its primary. The list
  /// names this device and every listed device the server still has; meta is empty (the app doesn't seal
  /// labels). Returns whether this device is now listed. One at a time.
  Future<bool> syncDevices() {
    final run = _syncing.then((_) => _syncDevicesNow(), onError: (_) => _syncDevicesNow());
    _syncing = run;
    return run;
  }
  Future<Object?> _syncing = Future.value(false);

  /// Why the served list was not accepted, if it wasn't.
  String? deviceWarning;

  Future<bool> _syncDevicesNow() async {
    if ((!active && !full) || keysLocked || _disposed) return false;
    final id = (await device()).deviceId, own = await crypto.identity();
    final view = await api.devices(me.username);
    final served = view['identity'];
    if (served is! Map || served['sign'] != own.sign || served['dh'] != own.dh) return false; // Not the key holder.
    final pin = devices.pin(me.id, me.id);
    Map<String, dynamic>? base;
    String? baseHash;
    if (view['list'] != null) {
      final check = verifyView(userId: me.id, aikSign: own.sign, list: view['list'], signature: view['signature'], certs: view['certs'], pin: pin);
      if (!check.ok) {
        deviceWarning = 'The device list on the server is not one this device signed (${check.reason}). It was not changed.';
        _notices.add(deviceWarning!);
        return false;
      }
      await _pinOwn(check.pin!, view['list']);
      base = (view['list'] as Map).cast<String, dynamic>();
      baseHash = check.hash;
      final rows = (view['devices'] as List? ?? const []).cast<Map>();
      final mine = rows.where((r) => r['id'] == id).firstOrNull;
      final listed = (base['devices'] as List).any((d) => (d as Map)['deviceId'] == id);
      // Listed is enough for a full device that isn't the inbox device; the inbox device also checks it is the one
      // the server routes 1:1 messages to.
      if (listed && (!active || (view['currentDevice'] == id && mine?['primary'] == true))) {
        deviceWarning = null;
        return true;
      }
    }
    await _publishNext(view, base, baseHash, own);
    deviceWarning = null;
    return true;
  }

  /// The identity-key holder publishes the next list: this device, every device the current list names that
  /// the server still calls listed, and [add] (a device being linked). Returns the version and hash.
  Future<({int version, String hash})> publishNextList({Map<String, Object?>? add}) {
    final run = _syncing.then((_) => _publishNextNow(add), onError: (_) => _publishNextNow(add));
    _syncing = run;
    return run;
  }

  /// The first list under a new account key (a primary transfer, m5 §5.2 step 4): version 1 naming this device
  /// and [keep], every other live device (labels sealed under the new key).
  Future<({int version, String hash})> publishNewChain(List<Map<String, Object?>> keep) {
    Future<({int version, String hash})> now() async => _publishNext(const {}, null, null, await crypto.identity(), add: keep);
    final run = _syncing.then((_) => now(), onError: (_) => now());
    _syncing = run;
    return run;
  }

  Future<({int version, String hash})> _publishNextNow(Map<String, Object?>? add) async {
    final own = await crypto.identity();
    final view = await api.devices(me.username);
    Map<String, dynamic>? base;
    String? baseHash;
    if (view['list'] != null) {
      final check = verifyView(userId: me.id, aikSign: own.sign, list: view['list'], signature: view['signature'], certs: view['certs'], pin: devices.pin(me.id, me.id));
      if (!check.ok) throw CryptoException('The device list on the server is not one this device signed (${check.reason}).');
      await _pinOwn(check.pin!, view['list']);
      base = (view['list'] as Map).cast<String, dynamic>();
      baseHash = check.hash;
    }
    return _publishNext(view, base, baseHash, own, add: [?add]);
  }

  Future<({int version, String hash})> _publishNext(Map<String, dynamic> view, Map<String, dynamic>? base, String? baseHash, Identity own, {List<Map<String, Object?>> add = const []}) async {
    final id = (await device()).deviceId;
    final rows = (view['devices'] as List? ?? const []).cast<Map>();
    final keep = [
      for (final d in (base?['devices'] as List? ?? const []).cast<Map>())
        if (d['deviceId'] != id && !add.any((a) => a['deviceId'] == d['deviceId']) && rows.any((r) => r['id'] == d['deviceId'] && r['state'] == 'listed')) Map<String, dynamic>.from(d),
    ];
    final metaKey = deviceMetaKey(await crypto.deviceMetaSignature(me.id));
    var self = (base?['devices'] as List? ?? const []).cast<Map>().where((d) => d['deviceId'] == id).map(Map<String, dynamic>.from).firstOrNull ??
        {
          'deviceId': id,
          'addedAt': _now(),
          // Label and platform, sealed under the account's device-meta key like the web does.
          'meta': sealMeta(metaKey, me.id, id, label: _deviceLabel(api.client), platform: api.client),
        };
    // Linked by code and now holding the key (it unlocked with the passphrase): its own list drops `via` (M6 §5).
    final described = openMeta(metaKey, me.id, id, self['meta'] as String? ?? '');
    if (described?['via'] != null) {
      self = {...self, 'meta': sealMeta(metaKey, me.id, id, label: described?['label'] ?? _deviceLabel(api.client), platform: described?['platform'] ?? api.client)};
    }
    final entries = [...keep, self, ...add]..sort((a, b) => (a['deviceId']! as String).compareTo(b['deviceId']! as String));
    final version = ((base?['version'] as int?) ?? 0) + 1;
    final list = <String, Object?>{'v': 1, 'userId': me.id, 'version': version, 'prevHash': baseHash ?? '', 'devices': entries};
    final head = view['list'] is Map && view['signature'] is String
        ? (list: (view['list'] as Map).cast<String, Object?>(), signature: view['signature'] as String)
        : null;
    final sig = await crypto.signDeviceList(me.id, own.sign, list, head: head);
    final signed = {'list': list, 'signature': sig.signature, 'certs': sig.certs};
    await api.publishDeviceList(signed, id);
    final after = verifyView(userId: me.id, aikSign: own.sign, list: list, signature: signed['signature'], certs: sig.certs, pin: devices.pin(me.id, me.id));
    if (after.ok) await _pinOwn(after.pin!, list);
    return (version: version, hash: listHash(listBytes(list)));
  }

  /// This account's served device list, verified under our account key (this core's identity, or the
  /// account key pinned for us on a linked device) and against our own pin, which it moves forward. Null when
  /// it can't be verified. Tombstones (`dropped`) are only devices an earlier pinned list named and a later one
  /// dropped: proven absent, never just missing.
  Future<OwnDeviceList?> verifiedOwnDevices() async {
    try {
      final view = await api.devices(me.username);
      final pin = devices.pin(me.id, me.id);
      String? aik;
      try {
        aik = (await crypto.identity()).sign;
      } catch (_) {
        aik = pin?.aik;
      }
      if (aik == null || view['list'] == null) return null;
      final check = verifyView(userId: me.id, aikSign: aik, list: view['list'], signature: view['signature'], certs: view['certs'], pin: pin);
      if (!check.ok) return null;
      await _pinOwn(check.pin!, view['list']);
      return OwnDeviceList(listed: {...check.pin!.devices}, dropped: {...check.pin!.revoked});
    } catch (_) {
      return null;
    }
  }

  /// This account's devices as the server lists them, labelled from the sealed list where this device can open
  /// it (the identity-key holder derives the label key), else by client kind.
  Future<List<OwnDevice>> ownDevices() async {
    final view = await api.devices(me.username);
    final list = view['list'] is Map ? (view['list'] as Map).cast<String, dynamic>() : null;
    final own = await crypto.identity();
    final served = view['identity'];
    final holder = !companion && served is Map && served['sign'] == own.sign && served['dh'] == own.dh;
    final key = holder ? deviceMetaKey(await crypto.deviceMetaSignature(me.id)) : null;
    return [
      for (final row in (view['devices'] as List? ?? const []).cast<Map>())
        () {
          final id = row['id'] as String;
          final entry = (list?['devices'] as List? ?? const []).cast<Map>().where((d) => d['deviceId'] == id).firstOrNull;
          final meta = key != null && entry != null ? openMeta(key, me.id, id, entry['meta'] as String? ?? '') : null;
          return OwnDevice(
            id: id,
            platform: meta?['platform'] ?? row['platform'] as String? ?? 'unknown',
            label: meta?['label'],
            state: row['state'] as String? ?? 'pending',
            primary: row['primary'] == true,
            current: row['current'] == true,
            lastSeenAt: row['lastSeenAt'] as int?,
            viaCode: meta?['via'] == 'code',
          );
        }(),
    ];
  }

  /// Signs a device out for good and, if it was listed, publishes the next list without it (primary only).
  Future<void> removeOwnDevice(OwnDevice device) async {
    var signed = const <String, dynamic>{};
    if (device.state == 'listed') {
      final own = await crypto.identity();
      final view = await api.devices(me.username);
      final current = (view['list']! as Map).cast<String, Object?>();
      final check = verifyView(userId: me.id, aikSign: own.sign, list: current, signature: view['signature'], certs: view['certs'], pin: devices.pin(me.id, me.id));
      if (!check.ok) throw CryptoException('The device list on the server is not one this device signed (${check.reason}).');
      final list = <String, Object?>{
        'v': 1,
        'userId': me.id,
        'version': (current['version']! as int) + 1,
        'prevHash': check.hash!,
        'devices': [for (final d in (current['devices']! as List).cast<Map>()) if (d['deviceId'] != device.id) Map<String, Object?>.from(d)],
      };
      final sig = await crypto.signDeviceList(me.id, own.sign, list, head: (list: current, signature: view['signature'] as String));
      signed = {'list': list, 'signature': sig.signature, 'certs': sig.certs};
    }
    await api.removeDevice(device.id, signed);
    if (signed.isNotEmpty) {
      final own = await crypto.identity();
      final after = verifyView(userId: me.id, aikSign: own.sign, list: signed['list'], signature: signed['signature'], certs: signed['certs'], pin: devices.pin(me.id, me.id));
      if (after.ok) await _pinOwn(after.pin!, signed['list']);
    }
  }

  static String _deviceLabel(String platform) =>
      const {'ios': 'iPhone app', 'android': 'Android app', 'macos': 'Mac app', 'windows': 'Windows app', 'linux': 'Linux app'}[platform] ?? 'App';

  /// Only on the user's tap: publish this device's identity, signed prekey and 100 fresh
  /// one-time prekeys. This device becomes active; contacts see a security-code change.
  Future<void> takeOver() async {
    // A bound session: the new identity's upload moves the account's inbox to this device.
    await _announce();
    final upload = await crypto.preparePrekeys(DateTime.now(), oneTimeOnServer: 0);
    await api.uploadKeys(upload.toJson());
    _setActive(true);
    unawaited(flush());
  }

  // ---------- Receiving ----------
  /// Envelopes are processed strictly in order, one at a time.
  Future<void> receive(EnvelopeEvent event) => _inbound = _inbound.then((_) => _receive(event)).catchError((_) {});

  Future<void> _receive(EnvelopeEvent event) async {
    // Inactive: neither process nor acknowledge; the active device will. Locked keys: neither, until recovery.
    if (!active || keysLocked) return;
    if (event.ephemeral) return _receiveEphemeral(event);
    final conversationId = conversationWith(event.fromId);
    String? failureCode;
    var failed = false;
    String? receipt;
    var burned = false, rotated = false;
    String? pointer;
    try {
      Identity? published;
      final decrypted = await crypto.decryptFrom(event.fromId, event.envelope);
      if (decrypted.identity != null) {
        // Defence in depth only: the pinned identity inside the crypto core is the trust boundary.
        try {
          published = Identity.fromJson(await api.publishedIdentity(event.fromUsername));
        } on ApiException catch (error) {
          throw CryptoException(error.message, code: error.status == 403 ? 'mismatch' : 'storage');
        }
        if (published != decrypted.identity) throw const CryptoException('Identity mismatch', code: 'mismatch');
      }
      final Map<String, Object?> payload;
      try {
        payload = checkPayload(decrypted.plaintextJson);
        if (payload['type'] == 'message' && payload.containsKey('mentions')) throw const PayloadException();
      } on PayloadException {
        throw const CryptoException('Invalid message', code: 'invalid');
      }
      final safety = await crypto.safety(me.username, event.fromId, event.fromUsername);
      final untrusted = decrypted.identityChanged || (safety?.blocked ?? false);
      if (decrypted.identityChanged) _identity.add(event.fromId);
      // An unaccepted new identity may deliver (flagged) messages, but may not burn history, fake receipts,
      // react, edit or mark anything read.
      if (!untrusted || payload['type'] == 'message') {
        switch (payload['type']) {
          case 'rotate':
            // The core keeps only the peer's new session, in the same write as the ratchet (commit below).
            rotated = true;
          case 'policy':
            _rememberPeerRotation(event.fromId, payload['rotateEveryMs'] as int);
          case 'receipt':
            await store.setStatus(conversationId, payload['id'] as String, MessageStatus.delivered);
          case 'burn':
            await store.removeConversation(conversationId);
            burned = true;
          case 'react':
            await store.react(conversationId, payload['target'] as String, who: 'peer', emoji: payload['emoji'] as String, on: payload['on'] as bool);
          case 'edit':
            // Only the author edits: the target must be a message we received from this sender.
            // A future editedAt is clamped (as on the web) so one edit can't outrank every later one.
            final editedAt = math.min(payload['editedAt'] as int, _now() + clockSkewMs);
            await store.edit(conversationId, payload['target'] as String, text: payload['text'] as String, editedAt: editedAt, author: Direction.incoming);
          case 'read':
            if (readReceipts()) await store.markRead(conversationId, (payload['ids'] as List).cast<String>(), direction: Direction.outgoing);
          case 'typing':
            break; // Typing travels only as an ephemeral envelope; a stored one is stale.
          case 'meta' || 'leave':
            break; // Group payloads mean nothing in a 1:1 chat.
          case 'mls-dm':
            // Over the pinned session only (an untrusted sender never gets here); the group is checked next.
            await store.note(conversationId, dmMovedNote);
            pointer = payload['channel']! as String;
          default:
            if (await store.receive(conversationId, payload) == ReceiveResult.stored) {
              if (untrusted) flagged.add((payload['id'] as String).toLowerCase());
              if (viewing?.call() != event.fromId) unread[event.fromId] = (unread[event.fromId] ?? 0) + 1;
              receipt = payload['id'] as String;
              _setTyping(event.fromId, false);
            }
        }
      }
      await crypto.commit(decrypted.commitId, rotate: rotated);
      _confirmed.add(event.fromId);
    } on CryptoException catch (error) {
      if (error.keysLocked) {
        // Never count or acknowledge this: the message is fine, our key database isn't.
        keysLocked = true;
        _lockedChanges.add(true);
        return;
      }
      failed = true;
      failureCode = error.code;
    } on StoreException catch (error) {
      failed = true;
      failureCode = error.code ?? 'storage';
    } catch (_) {
      failed = true;
    }
    final tries = (_attempts[event.id] ?? 0) + 1;
    final outcome = inboundDisposition(hasError: failed, code: failureCode, attempts: tries);
    if (!outcome.ack) {
      _attempts[event.id] = tries;
      _notices.add('Could not save an incoming message yet. Retrying…');
      return;
    }
    _attempts.remove(event.id);
    ack(event.id);
    final notice = noticeText(outcome.notice, event.fromUsername);
    if (notice != null) _notices.add(notice);
    if (rotated && !failed) {
      _notices.add('🔄 Secure session reset by ${event.fromUsername}');
      final contact = contactById(event.fromId);
      // Our policy rides on the new session, which also lets the peer drop its old chains.
      if (contact != null) unawaited(_tellPolicy(contact).catchError((_) {}));
    }
    if (burned) {
      unread.remove(event.fromId);
      _notices.add('${event.fromUsername} burned your conversation. It was deleted on this device.');
    }
    _unread.add(Map.of(unread));
    final contact = contactById(event.fromId);
    if (receipt != null && contact != null) {
      unawaited(_sendControl(contact, {'v': 1, 'type': 'receipt', 'id': receipt}).catchError((_) {}));
    }
    if (pointer != null && !failed && contact != null) unawaited(_acceptPointer(contact, pointer).catchError((_) {}));
  }

  /// 1:1 typing no longer travels over the Double Ratchet (docs/m5-linking.md §9): live-only envelopes that
  /// still arrive are ignored, untouched (never decrypted, never acknowledged).
  Future<void> _receiveEphemeral(EnvelopeEvent event) async {}

  void markRead(String contactId) {
    if (unread.remove(contactId) != null) _unread.add(Map.of(unread));
  }

  // ---------- Sending ----------
  /// Stores a new outgoing message as queued and starts delivery. A link preview is kept only while its
  /// URL is still in the text; the whole payload must fit the 16 KB envelope budget.
  Future<ChatMessage> send(
    Contact contact,
    String text, {
    Duration? disappearAfter,
    ReplyTo? replyTo,
    Attachment? attachment,
    LinkPreview? link,
    String? id,
  }) async {
    final now = _now();
    final candidate = validate(
      ChatMessage(
        id: id ?? const Uuid().v4(),
        conversationId: conversationWith(contact.id!),
        direction: Direction.outgoing,
        text: text,
        createdAt: now,
        status: MessageStatus.queued,
        expiresAt: disappearAfter == null ? null : now + disappearAfter.inMilliseconds,
        replyTo: replyTo,
        attachment: attachment,
        link: link != null && text.contains(link.url) ? link : null,
      ),
    );
    encodePayload(candidate.toPayload());
    final message = await store.put(candidate);
    unawaited(flush());
    return message;
  }

  /// A linked device sends only in chats that moved to MLS; the active device sends in all of them.
  Future<void> _requireSendable(Contact contact) async {
    if (keysLocked || (!active && await _dmChannel(contact.id!) == null)) throw const CryptoException(companionNotice);
  }

  /// Adds or removes our reaction: stored here at once, then sent. Reverted if it can't be sent.
  Future<void> react(Contact contact, ChatMessage target, String emoji, {required bool on}) async {
    await _requireSendable(contact);
    final conversationId = conversationWith(contact.id!);
    if (!await store.react(conversationId, target.id, who: 'me', emoji: emoji, on: on)) return;
    try {
      await _sendToContact(contact, {'v': 1, 'type': 'react', 'id': const Uuid().v4(), 'target': target.id, 'emoji': emoji, 'on': on});
    } catch (_) {
      await store.react(conversationId, target.id, who: 'me', emoji: emoji, on: !on);
      rethrow;
    }
  }

  /// Edits one of our sent text messages. Queued messages can't be edited yet (the peer doesn't have them).
  Future<void> edit(Contact contact, ChatMessage target, String text) async {
    await _requireSendable(contact);
    if (!target.outgoing || target.attachment != null || target.status == MessageStatus.queued) {
      throw const StoreException('Only your own sent text messages can be edited.');
    }
    if (!validText(text, hasAttachment: false)) throw const StoreException('A message can be up to 4,096 bytes and not empty.');
    final editedAt = math.max(_now(), (target.editedAt ?? 0) + 1);
    final payload = {'v': 1, 'type': 'edit', 'id': const Uuid().v4(), 'target': target.id, 'text': text, 'editedAt': editedAt};
    encodePayload(payload);
    await _sendToContact(contact, payload);
    await store.edit(conversationWith(contact.id!), target.id, text: text, editedAt: editedAt, author: Direction.outgoing);
  }

  // ---------- Read receipts ----------
  final Map<String, Set<String>> _toRead = {};
  final Map<String, int> _lastReadSent = {};
  final Map<String, Timer> _readTimers = {};

  /// The conversation with [contact] is visible and focused and shows these incoming messages.
  /// Batched: at most one `read` per 2 s per contact, ≤ 100 ids each. With receipts off, they are
  /// marked read here and nothing is sent.
  void displayed(Contact contact, Iterable<ChatMessage> messages) {
    final ids = [for (final m in messages) if (!m.outgoing && m.status == MessageStatus.delivered) m.id];
    if (ids.isEmpty || _disposed) return;
    (_toRead[contact.id!] ??= {}).addAll(ids);
    _scheduleRead(contact);
  }

  void _scheduleRead(Contact contact) {
    final id = contact.id!;
    if (_readTimers[id]?.isActive ?? false) return;
    final wait = math.max(0, readIntervalMs - (_now() - (_lastReadSent[id] ?? 0)));
    _readTimers[id] = Timer(Duration(milliseconds: wait), () => unawaited(_sendRead(contact)));
  }

  Future<void> _sendRead(Contact contact) async {
    final id = contact.id!;
    final pending = _toRead[id];
    if (pending == null || pending.isEmpty || _disposed) return;
    final batch = pending.take(maxReadIds).toList();
    pending.removeAll(batch);
    _lastReadSent[id] = _now();
    final conversationId = conversationWith(id);
    try {
      final changed = await store.markRead(conversationId, batch, direction: Direction.incoming);
      if (changed.isNotEmpty && readReceipts() && (active || await _dmChannel(id) != null) && !keysLocked) {
        await _sendToContact(contact, {'v': 1, 'type': 'read', 'id': const Uuid().v4(), 'ids': changed});
      }
    } catch (_) {
      // A receipt is a courtesy: never retry into a loop. The messages stay marked here.
    }
    if (pending.isNotEmpty) _scheduleRead(contact);
  }

  // ---------- Typing ----------
  final Map<String, Timer> _typingTimers = {};

  /// Contacts we have received from on the current session.
  final Set<String> _confirmed = {};

  void _setTyping(String contactId, bool on) {
    final had = _typingTimers.remove(contactId);
    had?.cancel();
    if (on) _typingTimers[contactId] = Timer(const Duration(milliseconds: typingHideMs), () => _setTyping(contactId, false));
    if ((had != null) != on || on) {
      if (!_typing.isClosed) _typing.add(typing);
    }
  }

  /// The composer has text ([on]) or was sent, cleared or left. Typing goes only through the chat's MLS group
  /// once the 1:1 chat has moved there ([dmTyping]); a chat still on the Double Ratchet shows no typing (m5 §9).
  Future<void> typingChanged(Contact contact, {required bool on}) async {
    if (_disposed) return;
    await dmTyping?.call(contact, on);
  }

  /// Sends typing through a moved chat's DM group, when there is one (set by the app).
  Future<void> Function(Contact contact, bool on)? dmTyping;

  /// A typing hint for a 1:1 chat that arrived through its DM group.
  void showTyping(String contactId, bool on) => _setTyping(contactId, on);

  Future<void> _sendControl(Contact contact, Map<String, Object?> payload) async {
    final json = encodePayload(payload);
    var result = await crypto.encryptTo(contact.id!, json);
    if (result is NeedsBundle) result = await crypto.encryptTo(contact.id!, json, bundleJson: await api.bundleJson(contact.username));
    switch (result) {
      case Encrypted(:final envelope):
        await api.postEnvelope(contact.username, envelope);
      case IdentityBlocked():
        throw const CryptoException('Security code changed. Review it before sending.', code: 'identity-blocked');
      case NeedsBundle():
        throw const CryptoException('Could not start an encrypted session.');
    }
  }

  // ---------- 1:1 chats on MLS (docs/m5-linking.md §8) ----------
  GroupMessenger? _groups;

  /// Groups on this device, the transport of 1:1 chats that moved to MLS. Set by the app once groups start.
  GroupMessenger? get groups => _groups;
  set groups(GroupMessenger? value) {
    _groups = value;
    if (value == null) return;
    value.dmIncoming = (peer) {
      if (viewing?.call() == peer) return;
      unread[peer] = (unread[peer] ?? 0) + 1;
      if (!_unread.isClosed) _unread.add(Map.of(unread));
    };
    value.dmTyping = _setTyping;
    value.sync.onDmJoined = (channel) {
      final wake = _pointerWake.remove(channel);
      if (wake != null && !wake.isCompleted) wake.complete();
    };
    dmTyping = (contact, on) async {
      final channel = await value.dmChannelWith(contact.id!);
      if (channel != null) await value.typingChanged(channel, on: on);
    };
  }

  /// Off: 1:1 chats stay on the Double Ratchet (tests of the 1:1 protocol itself).
  bool moveChats = true;

  /// A linked device (m5 §0): no account keys here, so no 1:1 sessions. It reads and sends only chats that
  /// moved to MLS; the rest stay on the primary.
  bool companion = false;

  Future<String?> _dmChannel(String contactId) async => await _groups?.dmChannelWith(contactId);

  /// Every payload to a contact: through the DM group once the chat moved, otherwise the 1:1 session.
  Future<void> _sendToContact(Contact contact, Map<String, Object?> payload) async {
    final groups = _groups, channel = await _dmChannel(contact.id!);
    if (groups != null && channel != null) return groups.sendDm(channel, payload);
    await _sendControl(contact, payload);
  }

  final Map<String, int> _moveTried = {};

  /// §8.2: the first sender moves the chat when both of us have a device that can. The pointer is the last
  /// Double Ratchet message of this chat.
  Future<void> _maybeMove(Contact contact) async {
    final groups = _groups, id = contact.id!;
    if (!moveChats || groups == null || !groups.ready || !active || keysLocked) return;
    final tried = _moveTried[id];
    if (tried != null && _now() - tried < dmMoveRetryMs) return;
    if (await groups.dmChannelWith(id) != null) return;
    _moveTried[id] = _now();
    final capability = await api.mlsCapability(contact.username);
    if ((capability['devices'] as int? ?? 0) < 1) return; // They can't yet.
    final existing = capability['channel'];
    String? channel;
    if (existing is String) {
      // A DM group this device already holds and checked, whose pointer never went out (ours, or theirs still in
      // flight): point at it. One we don't hold yet: wait for their pointer.
      if (!await groups.acceptDm(existing, id)) return;
      channel = existing;
    } else {
      channel = await groups.createDm(contact);
    }
    if (channel == null) return;
    await _sendControl(contact, {'v': 1, 'type': 'mls-dm', 'id': const Uuid().v4(), 'channel': channel, 'at': _now()});
    await groups.markMoved(channel);
    await store.note(conversationWith(id), dmMovedNote);
  }

  final Map<String, Completer<void>> _pointerWake = {};

  /// §8.3: their pointer moves the chat only when the server calls the channel our DM, this device is in it,
  /// and the core checks the group is exactly the DM of us two, chained to the pinned keys. The Welcome may
  /// come later: tried again when it arrives, otherwise with backoff, for 10 minutes. Anything else: ignored.
  Future<void> _acceptPointer(Contact contact, String channel) async {
    final deadline = _now() + dmMoveRetryMs;
    for (var wait = 1000; !_disposed && _now() < deadline; wait = math.min(wait * 2, 15000)) {
      final groups = _groups;
      if (groups != null) {
        Map<String, dynamic>? info;
        try {
          info = await api.channel(channel);
        } catch (_) {}
        final peer = info?['peer'];
        if (info != null && (info['kind'] != 'dm' || peer is! Map || peer['id'] != contact.id)) return; // Not our DM.
        if (info?['member'] == true && await groups.acceptDm(channel, contact.id!)) {
          await groups.markMoved(channel);
          return;
        }
      }
      final wake = _pointerWake[channel] = Completer<void>();
      await wake.future.timeout(Duration(milliseconds: wait), onTimeout: () {});
      _pointerWake.remove(channel);
    }
  }

  /// Sends every queued message, oldest first, keeping each contact's order.
  Future<void> flush() async {
    // Messages stay queued here until this device can send them: the inbox device over the Double Ratchet, any other
    // device only once the chat moved to MLS (skipped per contact below).
    if (keysLocked || _disposed) return;
    if (_flushing) {
      _flushAgain = true;
      return;
    }
    _flushing = true;
    _flushAgain = false;
    _retryTimer?.cancel();
    var retryLater = false;
    try {
      final queued = await store.queued();
      for (final contact in mutualContacts()) {
        final conversationId = conversationWith(contact.id!);
        final mine = queued.where((m) => m.conversationId == conversationId).toList();
        if (mine.isEmpty) continue;
        await _maybeMove(contact).catchError((_) {});
        final channel = await _dmChannel(contact.id!);
        if (channel == null && !active) continue;
        var prepared = channel != null;
        for (final record in mine) {
          try {
            if (!prepared) {
              await _rotateIfDue(contact);
              await _tellPolicy(contact);
              prepared = true;
            }
            final groups = _groups;
            if (channel != null && groups != null) {
              await groups.sendDm(channel, record.toPayload());
            } else {
              await _sendControl(contact, record.toPayload());
            }
            await store.setStatus(conversationId, record.id, MessageStatus.sent);
          } catch (error) {
            if (error is CryptoException && error.code == 'identity-blocked') {
              _identity.add(contact.id!);
            } else {
              retryLater = true;
            }
            break; // Keep this contact's order; try the next contact.
          }
        }
      }
    } catch (_) {
      retryLater = true; // Storage unavailable: try again later, never lose the queue.
    } finally {
      _flushing = false;
      if (_disposed) {
        // Signed out: nothing more to send from this session.
      } else if (_flushAgain) {
        unawaited(flush());
      } else if (retryLater) {
        _retryTimer = Timer(const Duration(seconds: 15), flush);
      }
    }
  }

  /// Deletes the conversation here and asks the contact's device to do the same.
  Future<void> burn(Contact contact) async {
    if (!active) throw const CryptoException('Encrypted messaging for this account is active on another device or browser.');
    await _sendControl(contact, {'v': 1, 'type': 'burn', 'id': const Uuid().v4()});
    await store.removeConversation(conversationWith(contact.id!));
    unread.remove(contact.id);
    _unread.add(Map.of(unread));
  }

  // ---------- Chat key rotation ----------
  // Sessions (ratchets) rotate; identities do not rotate on a timer — that would make security-code
  // changes routine and teach people to ignore them. Each side picks an interval; a chat uses the shorter.
  final Map<String, List<int>> _policyChanges = {};

  /// A contact's interval: only known choices, and at most ten changes a minute from any contact.
  void _rememberPeerRotation(String contactId, int value) {
    if (!rotationChoices.contains(value) || rotation.peer(contactId) == value) return;
    final now = DateTime.now().millisecondsSinceEpoch;
    final changes = (_policyChanges[contactId] ?? []).where((t) => now - t < 60000).toList();
    if (changes.length >= 10) return;
    _policyChanges[contactId] = [...changes, now];
    rotation.setPeer(contactId, value);
  }

  int effectiveRotation(String contactId) => rotationInterval(rotation.mine, rotation.peer(contactId));

  /// Starts fresh session keys with a new handshake; the security code is untouched.
  Future<void> resetSession(Contact contact, {String reason = 'manual'}) async {
    if (!active) throw const CryptoException('Encrypted messaging for this account is active on another device or browser.');
    await crypto.rotate(contact.id!);
    _confirmed.remove(contact.id);
    await _sendControl(contact, {'v': 1, 'type': 'rotate', 'id': const Uuid().v4(), 'reason': reason});
    _notices.add(reason == 'manual' ? '🔄 Secure session reset by you' : '🔄 Keys rotated on schedule');
    await _tellPolicy(contact);
  }

  Future<void> _rotateIfDue(Contact contact) async {
    final interval = effectiveRotation(contact.id!);
    if (interval == 0) return;
    final info = await crypto.sessionInfo(contact.id!);
    if (info != null && DateTime.now().millisecondsSinceEpoch - info.startedAt >= interval) {
      await resetSession(contact, reason: 'scheduled');
    }
  }

  /// Tells a contact our interval once per session, and again whenever it changes.
  Future<void> _tellPolicy(Contact contact, {bool force = false}) async {
    final mine = rotation.mine;
    final info = await crypto.sessionInfo(contact.id!);
    if (!force && info != null && rotation.told(contact.id!) == '$mine|${info.sid}') return;
    await _sendControl(contact, {'v': 1, 'type': 'policy', 'id': const Uuid().v4(), 'rotateEveryMs': mine});
    final after = await crypto.sessionInfo(contact.id!);
    rotation.setTold(contact.id!, '$mine|${after?.sid}');
  }

  /// Settings → Security: this device's interval (0 = off); contacts with a session hear about it.
  Future<void> setMyRotation(int value) async {
    if (!rotationChoices.contains(value)) return;
    rotation.mine = value;
    if (!active) return;
    for (final contact in mutualContacts()) {
      if (await crypto.sessionInfo(contact.id!) != null) unawaited(_tellPolicy(contact, force: true).catchError((_) {}));
    }
  }

  /// Settings → Security: new identity keys for this device (explicit only). Contacts see a code change.
  // ---------- Contacts' device lists ----------
  /// The last check of each contact's device list (contact id → result).
  final Map<String, DeviceCheck> deviceChecks = {};

  /// Verifies a contact's served device list against the identity pinned for them (never the server's
  /// word) and advances the pin. A failure is reported once as a notice; nothing is trusted from it.
  Future<DeviceCheck?> verifyContactDevices(Contact contact) async {
    final id = contact.id;
    if (id == null) return null;
    final view = await api.devices(contact.username);
    final served = view['identity'];
    if (served is! Map<String, dynamic>) return null;
    await followIdentity(contact, Identity.fromJson(served), view['succession']);
    final safety = await crypto.safety(me.username, id, contact.username);
    if (safety == null || safety.blocked) return deviceChecks[id] = const DeviceCheck.failed('identity');
    final check = verifyView(
      userId: id,
      aikSign: served['sign'] as String,
      list: view['list'],
      signature: view['signature'],
      certs: view['certs'],
      pin: devices.pin(me.id, id),
    );
    final previous = deviceChecks[id];
    deviceChecks[id] = check;
    if (check.ok) {
      devices.setPin(me.id, id, check.pin!);
    } else if (check.reason != 'none' && previous?.reason != check.reason) {
      _notices.add("${contact.username}'s device list failed verification (${check.reason}).");
    }
    return check;
  }

  /// A contact's served identity (m5 §5.3): when it differs from the pin and a signed succession chain from
  /// the pinned key reaches it, the pin moves with verification kept and a soft notice; otherwise recording it
  /// flags a security-code change for review, so nothing is ever trusted silently. Returns true on a succession.
  /// One per contact at a time: a refresh and a succession never interleave their pin writes.
  Future<bool> followIdentity(Contact contact, Identity served, Object? succession) {
    final id = contact.id!;
    final run = (_identityChecks[id] ?? Future<void>.value()).then((_) => _followIdentityNow(contact, served, succession));
    _identityChecks[id] = run.then((_) {}, onError: (_) {});
    return run;
  }

  final Map<String, Future<void>> _identityChecks = {};

  Future<bool> _followIdentityNow(Contact contact, Identity served, Object? succession) async {
    final id = contact.id!;
    final pinned = await crypto.peer(id);
    // Only from a code the user accepted: a pin still waiting for review may already be the server's own key.
    if (pinned != null && pinned.identity != served && !pinned.blocked && !pinned.changed && succession is List && succession.isNotEmpty) {
      try {
        final moved = await crypto.acceptSuccession(id, [for (final r in succession) (r as Map).cast<String, dynamic>()]);
        if (moved.identity == served) {
          keyMoved(contact, served);
          return true;
        }
      } on CryptoException {
        // Not a valid chain from our pin: the usual security-code review below.
      }
    }
    await crypto.notePeer(id, served);
    return false;
  }

  /// A contact's pin moved along their signed chain, here or in the group pins (whichever saw it first):
  /// told once per new key.
  void keyMoved(Contact contact, Identity now) {
    final id = contact.id!;
    if (_movedTo[id] == now.sign) return;
    _movedTo[id] = now.sign;
    _notices.add('${contact.username} updated their security key. Verification kept.');
    _confirmed.remove(id);
  }

  final Map<String, String> _movedTo = {};

  Future<void> regenerateIdentity() async {
    await crypto.resetIdentity();
    _confirmed.clear();
    rotation.clearTold();
    await takeOver();
  }

  Future<void> dispose() async {
    _disposed = true;
    _retryTimer?.cancel();
    for (final t in [..._readTimers.values, ..._typingTimers.values]) {
      t.cancel();
    }
    await _typing.close();
    await _notices.close();
    await _unread.close();
    await _identity.close();
    await _activeChanges.close();
    await _lockedChanges.close();
  }
}

/// True when an envelope carries an X3DH header (or can't be read): it would open a new session.
bool startsSession(String envelope) {
  try {
    final packet = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(envelope))));
    return packet is! Map || packet.containsKey('x');
  } catch (_) {
    return true;
  }
}
