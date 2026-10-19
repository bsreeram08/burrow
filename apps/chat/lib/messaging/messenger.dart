import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../core/devices.dart';
import '../core/events.dart';
import '../core/pair_id.dart';
import '../crypto/chat_crypto.dart';
import '../store/disposition.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import 'payload.dart';

/// Read receipts: at most one `read` per contact per 2 s.
const readIntervalMs = 2000;

/// Typing: `on:true` at most every 4 s; a received one older than 15 s is dropped; shown for 6 s.
const typingThrottleMs = 4000;
const typingFreshMs = 15000;
const typingHideMs = 6000;

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

  /// The key database refused to work mid-session (tampered, reset, identity missing): stop processing and
  /// acknowledging until the user recovers. Envelopes stay on the server.
  bool keysLocked = false;
  final _lockedChanges = StreamController<bool>.broadcast();
  Stream<bool> get lockedChanges => _lockedChanges.stream;
  final _activeChanges = StreamController<bool>.broadcast();
  Stream<bool> get activeChanges => _activeChanges.stream;

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

  /// Compares the server's published identity with ours before uploading anything.
  /// Re-run on sign-in, on reconnect and on a `keys` event for our own id.
  Future<bool> checkActive() async {
    final count = await api.keyCount();
    final mine = await crypto.identity();
    final published = count.identity == null ? null : Identity.fromJson(count.identity!);
    if (published != null && published != mine) {
      // Another device holds the keys: this one is a pending device of the account.
      await _announce();
      _setActive(false);
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
  }

  /// Live-only envelopes carry typing and nothing else. They are never acknowledged (the server keeps
  /// nothing to delete) and any failure is dropped silently: a lost typing hint is harmless.
  Future<void> _receiveEphemeral(EnvelopeEvent event) async {
    // Live-only envelopes may only continue an existing session: an X3DH initial message would claim a prekey
    // slot outside the stored path, so it is dropped before decrypting.
    if (startsSession(event.envelope)) return;
    try {
      final decrypted = await crypto.decryptFrom(event.fromId, event.envelope);
      // A new identity never arrives on a live-only envelope; a session must already exist.
      if (decrypted.identity != null || decrypted.identityChanged) {
        await crypto.abort(decrypted.commitId);
        return;
      }
      Map<String, Object?>? payload;
      try {
        payload = checkPayload(decrypted.plaintextJson);
      } on PayloadException {
        payload = null;
      }
      final safety = await crypto.safety(me.username, event.fromId, event.fromUsername);
      if (payload == null || payload['type'] != 'typing' || (safety?.blocked ?? false)) {
        await crypto.abort(decrypted.commitId); // Discarded unsaved, like the web client.
        return;
      }
      await crypto.commit(decrypted.commitId, rotate: false);
      final on = payload['on'] as bool, at = payload['at'] as int;
      if (on && (_now() - at).abs() > typingFreshMs) return;
      _setTyping(event.fromId, on);
    } on CryptoException catch (error) {
      if (error.keysLocked) {
        keysLocked = true;
        _lockedChanges.add(true);
      }
    } catch (_) {}
  }

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

  void _requireActive() {
    if (!active || keysLocked) throw const CryptoException('Encrypted messaging for this account is active on another device or browser.');
  }

  /// Adds or removes our reaction: stored here at once, then sent. Reverted if it can't be sent.
  Future<void> react(Contact contact, ChatMessage target, String emoji, {required bool on}) async {
    _requireActive();
    final conversationId = conversationWith(contact.id!);
    if (!await store.react(conversationId, target.id, who: 'me', emoji: emoji, on: on)) return;
    try {
      await _sendControl(contact, {'v': 1, 'type': 'react', 'id': const Uuid().v4(), 'target': target.id, 'emoji': emoji, 'on': on});
    } catch (_) {
      await store.react(conversationId, target.id, who: 'me', emoji: emoji, on: !on);
      rethrow;
    }
  }

  /// Edits one of our sent text messages. Queued messages can't be edited yet (the peer doesn't have them).
  Future<void> edit(Contact contact, ChatMessage target, String text) async {
    _requireActive();
    if (!target.outgoing || target.attachment != null || target.status == MessageStatus.queued) {
      throw const StoreException('Only your own sent text messages can be edited.');
    }
    if (!validText(text, hasAttachment: false)) throw const StoreException('A message can be up to 4,096 bytes and not empty.');
    final editedAt = math.max(_now(), (target.editedAt ?? 0) + 1);
    final payload = {'v': 1, 'type': 'edit', 'id': const Uuid().v4(), 'target': target.id, 'text': text, 'editedAt': editedAt};
    encodePayload(payload);
    await _sendControl(contact, payload);
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
      if (changed.isNotEmpty && readReceipts() && active && !keysLocked) {
        await _sendControl(contact, {'v': 1, 'type': 'read', 'id': const Uuid().v4(), 'ids': changed});
      }
    } catch (_) {
      // A receipt is a courtesy: never retry into a loop. The messages stay marked here.
    }
    if (pending.isNotEmpty) _scheduleRead(contact);
  }

  // ---------- Typing ----------
  final Map<String, Timer> _typingTimers = {};
  final Map<String, int> _typingSentAt = {};
  final Set<String> _typingOn = {};

  /// Contacts we have received from on the current session: their side holds it, so a live-only
  /// envelope can never be a session's first message (X3DH initial messages are claimed once).
  final Set<String> _confirmed = {};

  void _setTyping(String contactId, bool on) {
    final had = _typingTimers.remove(contactId);
    had?.cancel();
    if (on) _typingTimers[contactId] = Timer(const Duration(milliseconds: typingHideMs), () => _setTyping(contactId, false));
    if ((had != null) != on || on) {
      if (!_typing.isClosed) _typing.add(typing);
    }
  }

  /// The composer has text ([on]) or was sent, cleared or left. `on:true` is throttled to one per 4 s;
  /// `on:false` goes only after an `on:true`. Live-only, so sent only while the contact is online and an
  /// established session exists (each dropped envelope still advances the sending chain).
  Future<void> typingChanged(Contact contact, {required bool on}) async {
    final id = contact.id!;
    if (!active || keysLocked || _disposed) return;
    final now = _now();
    if (on) {
      if (now - (_typingSentAt[id] ?? 0) < typingThrottleMs) return;
    } else if (!_typingOn.contains(id)) {
      return;
    }
    if (!contact.online || !_confirmed.contains(id) || await crypto.sessionInfo(id) == null) return;
    final safety = await crypto.safety(me.username, id, contact.username);
    if (safety?.blocked ?? false) return;
    on ? _typingSentAt[id] = now : _typingSentAt.remove(id);
    on ? _typingOn.add(id) : _typingOn.remove(id);
    try {
      final result = await crypto.encryptTo(id, encodePayload({'v': 1, 'type': 'typing', 'id': const Uuid().v4(), 'at': now, 'on': on}));
      if (result is Encrypted) await api.postEnvelope(contact.username, result.envelope, ephemeral: true);
    } catch (_) {}
  }

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

  /// Sends every queued message, oldest first, keeping each contact's order.
  Future<void> flush() async {
    if (!active || keysLocked || _disposed) return; // Messages stay queued here until this device is usable.
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
        var prepared = false;
        for (final record in queued.where((m) => m.conversationId == conversationId)) {
          try {
            if (!prepared) {
              await _rotateIfDue(contact);
              await _tellPolicy(contact);
              prepared = true;
            }
            await _sendControl(contact, record.toPayload());
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
    // Recording the served identity flags it if it is not the pinned one, so a list is only ever checked
    // against the security code the user knows.
    await crypto.notePeer(id, Identity.fromJson(served));
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
