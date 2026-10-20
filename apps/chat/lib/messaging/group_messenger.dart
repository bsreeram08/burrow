import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import 'package:crypto/crypto.dart' show sha256;
import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../core/events.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/group_crypto.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import 'group_sync.dart';
import 'messenger.dart' show readIntervalMs, typingFreshMs, typingHideMs, typingThrottleMs;
import 'payload.dart';

/// Read receipts go only in groups and private channels of at most this many people (m4-groups §5.1).
const maxReceiptGroup = 50;

/// A member as shown: the MLS member (authoritative) with the username the server knows.
class GroupPerson {
  const GroupPerson({required this.userId, required this.username, required this.admin});
  final String userId;
  final String username;
  final bool admin;
}

/// A security-code fingerprint of one identity, to compare a changed code (m4-groups §3): SHA-256 of
/// `dh|sign`, as 12 groups of 5 digits (bytes 2i and 2i+1 as a big-endian number, zero-padded).
String identityFingerprint(Identity identity) {
  final bytes = sha256.convert(utf8.encode('${identity.dh}|${identity.sign}')).bytes;
  return [for (var i = 0; i < 12; i++) (bytes[2 * i] * 256 + bytes[2 * i + 1]).toString().padLeft(5, '0')].join(' ');
}

/// Who is typing in a group, for the header and the list: "alice is typing", "alice and bob are typing",
/// "3 people are typing".
String typingLine(List<String> names) => switch (names.length) {
  0 => '',
  1 => '${names.single} is typing',
  2 => '${names[0]} and ${names[1]} are typing',
  _ => '${names.length} people are typing',
};

/// The user ids an outgoing text mentions: `@username` tokens still in the final text that name a current
/// member (m4-groups §5.2). Never me.
List<String> mentionsIn(String text, Iterable<GroupPerson> members, {required String me}) {
  final byName = {for (final m in members) m.username.toLowerCase(): m.userId};
  final out = <String>[];
  for (final match in RegExp(r'(^|[^A-Za-z0-9_])@([a-z0-9_]{3,20})(?![A-Za-z0-9_])').allMatches(text)) {
    final id = byName[match.group(2)!.toLowerCase()];
    if (id != null && id != me && !out.contains(id) && out.length < maxMentions) out.add(id);
  }
  return out;
}

/// Groups and channels (docs/m4-groups.md): the payload layer over [GroupSync]. Phase 1 payloads inside
/// MLS, plus `mentions`, `meta` and `leave`; per-person reactions, read-by, typing; system lines for joins
/// and removals; unread and mention counts; the outgoing queue. 1:1 chats stay on [Messenger].
class GroupMessenger {
  GroupMessenger({
    required this.api,
    required this.sync,
    required this.chatCrypto,
    required this.store,
    required this.me,
    required this.contacts,
    this.viewing,
    bool Function()? readReceipts,
    int Function()? now,
  }) : readReceipts = readReceipts ?? (() => true),
       _now = now ?? (() => DateTime.now().millisecondsSinceEpoch) {
    sync.onDelivery = _deliver;
    sync.onMembership = _membership;
  }

  final Api api;
  final GroupSync sync;
  final ChatCrypto chatCrypto;
  final MessageStore store;
  final User me;

  /// The account's contacts (for names and their 1:1 pins).
  final List<Contact> Function() contacts;

  /// The group on screen, if any (no unread count for it).
  final String? Function()? viewing;
  final bool Function() readReceipts;
  final int Function() _now;

  GroupCrypto get crypto => sync.crypto;

  /// Groups are usable on this device (it is listed and has its group identity).
  bool ready = false;

  /// Why groups are off on this device, when they are.
  String? unavailable;

  final _notices = StreamController<String>.broadcast();
  Stream<String> get notices => _notices.stream;
  void _notice(String text) {
    if (!_notices.isClosed) _notices.add(text);
  }

  // ---------- Names and pins ----------
  /// Usernames by user id: contacts, channel member lists and senders seen.
  final Map<String, String> names = {};

  String nameOf(String userId) {
    if (userId == me.id) return me.username;
    for (final c in contacts()) {
      if (c.id == userId) return c.username;
    }
    return names[userId] ?? 'someone';
  }

  Contact? _contact(String userId) {
    for (final c in contacts()) {
      if (c.id == userId && c.state == ContactState.mutual) return c;
    }
    return null;
  }

  /// Changed codes of people known only from groups, kept until the user reviews them: what was pinned
  /// before and what is published now (m4-groups §3). The core's pin already holds the new key, blocked.
  final Map<String, ({Identity before, Identity after})> pinChanges = {};

  /// §3: contacts are pinned through their 1:1 identity (their published identity on first contact; a change
  /// goes through the 1:1 review). Anyone else is pinned on first use from `GET /api/users/:id/identity`; with
  /// [force] their published key is checked again and a different one is recorded as a change awaiting review,
  /// never accepted. Returns the users without a usable pin.
  Future<List<String>> ensurePinned(Iterable<String> userIds, {bool force = false}) async {
    final problems = <String>[];
    for (final id in userIds.toSet()) {
      if (id == me.id) continue;
      try {
        var pinned = await chatCrypto.peer(id);
        if (pinned != null && !force) {
          if (pinned.blocked) problems.add(id);
          continue;
        }
        final contact = _contact(id);
        Map<String, dynamic>? published;
        if (contact != null) {
          published = await api.publishedIdentity(contact.username);
        } else {
          final user = await api.userIdentity(id);
          if (user['userId'] == id) {
            if (user['username'] is String) names[id] = user['username'] as String;
            published = (user['identity'] as Map).cast<String, dynamic>();
          }
        }
        if (published != null) {
          final identity = Identity.fromJson(published);
          if (pinned != null && pinned.identity != identity && contact == null) {
            pinChanges[id] = (before: pinChanges[id]?.before ?? pinned.identity, after: identity);
          }
          // First sight: trust on first use. A different key: recorded as a change, which blocks until reviewed.
          if (pinned == null || pinned.identity != identity) await chatCrypto.notePeer(id, identity);
          pinned = await chatCrypto.peer(id);
        }
        if (pinned == null || pinned.blocked) problems.add(id);
      } catch (_) {
        if (await chatCrypto.peer(id).catchError((_) => null) == null) problems.add(id);
      }
    }
    return problems;
  }

  /// The user reviewed a group member's changed code: accept exactly [shown] (and optionally mark it
  /// verified), then resume. If the pin changed again meanwhile, the core refuses with `mismatch`; the newer
  /// key is recorded for the next review and nothing is accepted.
  Future<void> acceptChangedCode(String userId, Identity shown, {bool verified = false}) async {
    try {
      verified ? await chatCrypto.setVerifiedFor(userId, true, shown) : await chatCrypto.acceptChangeFor(userId, shown);
    } on CryptoException catch (error) {
      if (error.code == 'mismatch') {
        final now = await chatCrypto.peer(userId);
        final before = pinChanges[userId]?.before;
        if (now != null && before != null) pinChanges[userId] = (before: before, after: now.identity);
      }
      rethrow;
    }
    pinChanges.remove(userId);
    await sync.resume(userId);
  }

  // ---------- Members ----------
  final Map<String, List<GroupPerson>> _members = {};

  /// Current members (one entry per person), from MLS, named from the server's member list.
  Future<List<GroupPerson>> members(String groupId, {bool refresh = false}) async {
    if (!refresh && _members[groupId] != null) return _members[groupId]!;
    List<GroupMember> mls;
    try {
      mls = await crypto.members(groupId);
    } catch (_) {
      return _members[groupId] ?? const [];
    }
    try {
      for (final m in await api.channelMembers(groupId)) {
        names[m['userId'] as String] = m['username'] as String;
      }
    } catch (_) {}
    final seen = <String>{};
    final people = [
      for (final m in mls)
        if (seen.add(m.userId)) GroupPerson(userId: m.userId, username: nameOf(m.userId), admin: m.admin),
    ]..sort((a, b) => a.username.compareTo(b.username));
    return _members[groupId] = people;
  }

  /// The members last loaded, without waiting (the list and headers).
  List<GroupPerson>? cachedMembers(String groupId) => _members[groupId];

  /// What a group is called on screen: its name, else the other members' names (§5.3).
  String displayName(GroupConversation group) {
    if (group.name.isNotEmpty) return group.name;
    final others = [for (final m in _members[group.id] ?? const <GroupPerson>[]) if (m.userId != me.id) m.username];
    if (others.isEmpty) return group.kind.isChannel ? 'Unnamed channel' : 'New group';
    return others.length <= 3 ? others.join(', ') : '${others.take(3).join(', ')} +${others.length - 3}';
  }

  Future<bool> isAdmin(String groupId, [String? userId]) async {
    try {
      return (await crypto.roles(groupId)).isAdmin(userId ?? me.id);
    } catch (_) {
      return false;
    }
  }

  // ---------- Start ----------
  /// After sign-in: group identity and KeyPackages, waiting Welcomes, and every channel's log.
  Future<void> start() async {
    try {
      await sync.ensureReady();
      ready = true;
      unavailable = null;
    } on ApiException catch (error) {
      ready = false;
      // Not a listed device: say what to do. Anything else (offline, a server without groups) stays quiet and
      // is retried on the next reconnect.
      if (error.status != 403 && error.status != 409) rethrow;
      unavailable = 'Groups need this device in your signed device list. Open the app on your primary device.';
      return;
    }
    await sync.fetchWelcomes();
    await sync.refresh();
    for (final g in await store.groups()) {
      if (g.active) unawaited(members(g.id, refresh: true));
    }
    unawaited(flush());
  }

  // ---------- Creating and membership ----------
  /// Creates a group or channel with [memberIds], then tells everyone its name and topic (`meta`).
  Future<GroupConversation> create(GroupKindName kind, {required String name, String topic = '', List<String> memberIds = const []}) async {
    if (!ready) throw StoreException(unavailable ?? 'Groups are not available on this device yet.');
    final group = await sync.create(kind, name: name.trim());
    await store.note(group.id, kind == GroupKindName.groupDm ? 'You started this group.' : 'You created this ${kind == GroupKindName.public ? 'public' : 'private'} channel.');
    final missing = memberIds.isEmpty ? <String>{} : await sync.add(group.id, memberIds);
    await _sendMeta(group.id, name.trim(), topic.trim());
    _reportMissing(missing);
    await members(group.id, refresh: true);
    return (await store.group(group.id))!;
  }

  Future<void> addMembers(String groupId, List<String> userIds) async {
    final missing = await sync.add(groupId, userIds);
    final added = [for (final u in userIds) if (!missing.contains(u)) nameOf(u)];
    if (added.isNotEmpty) await store.note(groupId, 'You added ${added.join(', ')}');
    final group = await store.group(groupId);
    // New members learn the name and topic from a fresh meta.
    if (group != null && await isAdmin(groupId)) await _sendMeta(groupId, group.name, group.topic);
    _reportMissing(missing);
    await members(groupId, refresh: true);
  }

  void _reportMissing(Set<String> missing) {
    if (missing.isEmpty) return;
    final who = missing.map(nameOf).join(', ');
    _notice("$who ${missing.length == 1 ? "hasn't" : "haven't"} opened the app since groups arrived, so ${missing.length == 1 ? 'they were' : 'they were'} not added.");
  }

  Future<void> removeMember(String groupId, String userId) async {
    await sync.remove(groupId, userId);
    await store.note(groupId, 'You removed ${nameOf(userId)}');
    await members(groupId, refresh: true);
  }

  Future<void> makeAdmin(String groupId, String userId) async {
    final roles = await crypto.roles(groupId);
    if (roles.isAdmin(userId)) return;
    await sync.setAdmins(groupId, [...roles.admins, userId]);
    await members(groupId, refresh: true);
  }

  Future<void> leave(String groupId) async {
    await sync.leave(groupId, leavePayload: encodePayload({'v': 1, 'type': 'leave', 'id': const Uuid().v4()}));
    _members.remove(groupId);
    await store.note(groupId, 'You left');
  }

  /// Admins: the name (may be empty for a group) and topic everyone sees.
  Future<void> setMeta(String groupId, {required String name, required String topic}) async {
    if (!await isAdmin(groupId)) throw const StoreException('Only admins can change the name and topic.');
    await _sendMeta(groupId, name.trim(), topic.trim());
  }

  Future<void> _sendMeta(String groupId, String name, String topic) async {
    final at = math.max(_now(), ((await store.group(groupId))?.metaAt ?? 0) + 1);
    final payload = {'v': 1, 'type': 'meta', 'id': const Uuid().v4(), 'name': name, 'topic': topic, 'at': at};
    checkPayload(jsonEncode(payload));
    await sync.send(groupId, encodePayload(payload));
    await store.updateGroup(groupId, (g) => g.copyWith(name: name.isEmpty && g.kind == GroupKindName.public ? g.name : name, topic: topic, metaAt: at));
  }

  Future<List<Map<String, dynamic>>> directory() => api.channelDirectory();

  Future<GroupConversation> joinPublic(String channelId) async {
    if (!ready) throw StoreException(unavailable ?? 'Groups are not available on this device yet.');
    final group = await sync.joinPublic(channelId);
    await members(channelId, refresh: true);
    return group;
  }

  // ---------- Sending ----------
  /// Stores a new outgoing message as queued and starts delivery. Mentions come from `@username` tokens.
  Future<ChatMessage> send(String groupId, String text, {Duration? disappearAfter, ReplyTo? replyTo, Attachment? attachment, LinkPreview? link, String? id}) async {
    final now = _now();
    final candidate = validate(
      ChatMessage(
        id: id ?? const Uuid().v4(),
        conversationId: groupId,
        direction: Direction.outgoing,
        text: text,
        createdAt: now,
        status: MessageStatus.queued,
        expiresAt: disappearAfter == null ? null : now + disappearAfter.inMilliseconds,
        replyTo: replyTo,
        attachment: attachment,
        link: link != null && text.contains(link.url) ? link : null,
        mentions: mentionsIn(text, await members(groupId), me: me.id),
      ),
    );
    encodePayload(candidate.toPayload());
    final message = await store.put(candidate);
    unawaited(flush());
    return message;
  }

  bool _flushing = false, _flushAgain = false, _disposed = false;
  Timer? _retry;

  /// Sends every queued group message, oldest first, keeping each group's order.
  Future<void> flush() async {
    if (!ready || _disposed) return;
    if (_flushing) {
      _flushAgain = true;
      return;
    }
    _flushing = true;
    _flushAgain = false;
    _retry?.cancel();
    var retryLater = false;
    try {
      final queued = (await store.queued()).where((m) => m.inGroup);
      final byGroup = <String, List<ChatMessage>>{};
      for (final m in queued) {
        (byGroup[m.conversationId] ??= []).add(m);
      }
      for (final entry in byGroup.entries) {
        final group = await store.group(entry.key);
        if (group == null || !group.active || group.frozen != null) continue;
        for (final record in entry.value) {
          try {
            await sync.send(entry.key, encodePayload(record.toPayload()));
            await store.setStatus(entry.key, record.id, MessageStatus.sent);
          } catch (_) {
            retryLater = true;
            break; // Keep this group's order.
          }
        }
      }
    } catch (_) {
      retryLater = true;
    } finally {
      _flushing = false;
      if (_disposed) {
        // Signed out.
      } else if (_flushAgain) {
        unawaited(flush());
      } else if (retryLater) {
        _retry = Timer(const Duration(seconds: 15), flush);
      }
    }
  }

  Future<void> _control(String groupId, Map<String, Object?> payload) => sync.send(groupId, encodePayload(payload));

  /// Adds or removes our reaction: stored at once, reverted if it can't be sent.
  Future<void> react(String groupId, ChatMessage target, String emoji, {required bool on}) async {
    if (!await store.react(groupId, target.id, who: 'me', emoji: emoji, on: on)) return;
    try {
      await _control(groupId, {'v': 1, 'type': 'react', 'id': const Uuid().v4(), 'target': target.id, 'emoji': emoji, 'on': on});
    } catch (_) {
      await store.react(groupId, target.id, who: 'me', emoji: emoji, on: !on);
      rethrow;
    }
  }

  Future<void> edit(String groupId, ChatMessage target, String text) async {
    if (!target.outgoing || target.attachment != null || target.status == MessageStatus.queued) {
      throw const StoreException('Only your own sent text messages can be edited.');
    }
    if (!validText(text, hasAttachment: false)) throw const StoreException('A message can be up to 4,096 bytes and not empty.');
    final editedAt = math.max(_now(), (target.editedAt ?? 0) + 1);
    final payload = {'v': 1, 'type': 'edit', 'id': const Uuid().v4(), 'target': target.id, 'text': text, 'editedAt': editedAt};
    encodePayload(payload);
    await _control(groupId, payload);
    await store.edit(groupId, target.id, text: text, editedAt: editedAt, author: Direction.outgoing);
  }

  // ---------- Read receipts ----------
  final Map<String, Set<String>> _toRead = {};
  final Map<String, int> _lastReadSent = {};
  final Map<String, Timer> _readTimers = {};

  /// The group is visible and focused and shows these incoming messages. Marked read here; a `read` goes
  /// at most every 2 s, only in groups and private channels of at most 50 people, and only with receipts on.
  void displayed(String groupId, Iterable<ChatMessage> messages) {
    final ids = [for (final m in messages) if (m.direction == Direction.incoming && m.status == MessageStatus.delivered) m.id];
    if (ids.isEmpty || _disposed) return;
    (_toRead[groupId] ??= {}).addAll(ids);
    if (_readTimers[groupId]?.isActive ?? false) return;
    final wait = math.max(0, readIntervalMs - (_now() - (_lastReadSent[groupId] ?? 0)));
    _readTimers[groupId] = Timer(Duration(milliseconds: wait), () => unawaited(_sendRead(groupId)));
  }

  Future<void> _sendRead(String groupId) async {
    final pending = _toRead[groupId];
    if (pending == null || pending.isEmpty || _disposed) return;
    final batch = pending.take(maxReadIds).toList();
    pending.removeAll(batch);
    _lastReadSent[groupId] = _now();
    try {
      final changed = await store.markRead(groupId, batch, direction: Direction.incoming);
      final group = await store.group(groupId);
      if (changed.isNotEmpty && readReceipts() && group != null && group.active && group.kind != GroupKindName.public && (await members(groupId)).length <= maxReceiptGroup) {
        await _control(groupId, {'v': 1, 'type': 'read', 'id': const Uuid().v4(), 'ids': changed});
      }
    } catch (_) {
      // A courtesy: never retried into a loop.
    }
    if (pending.isNotEmpty) displayed(groupId, const []);
  }

  /// Our message is `read` once everyone else currently in the group has read it.
  Future<void> _settleRead(String groupId, Iterable<String> ids) async {
    final others = {for (final m in await members(groupId)) if (m.userId != me.id) m.userId};
    if (others.isEmpty) return;
    for (final id in ids) {
      final m = await store.get(groupId, id);
      if (m != null && m.outgoing && others.every(m.readBy.contains)) await store.setStatus(groupId, id, MessageStatus.read);
    }
  }

  // ---------- Typing ----------
  final Map<String, Map<String, Timer>> _typing = {};
  final _typingChanges = StreamController<Map<String, List<String>>>.broadcast();

  /// Group id → user ids typing there now.
  Stream<Map<String, List<String>>> get typingChanges => _typingChanges.stream;
  Map<String, List<String>> get typing => {for (final e in _typing.entries) if (e.value.isNotEmpty) e.key: e.value.keys.toList()};

  void _setTyping(String groupId, String userId, bool on) {
    final timers = _typing.putIfAbsent(groupId, () => {});
    timers.remove(userId)?.cancel();
    if (on) timers[userId] = Timer(const Duration(milliseconds: typingHideMs), () => _setTyping(groupId, userId, false));
    if (!_typingChanges.isClosed) _typingChanges.add(typing);
  }

  final Map<String, int> _typingSentAt = {};
  final Set<String> _typingOn = {};

  /// The composer has text ([on]) or was sent, cleared or left: live-only, throttled to one `on` per 4 s.
  Future<void> typingChanged(String groupId, {required bool on}) async {
    if (!ready || _disposed) return;
    final now = _now();
    if (on) {
      if (now - (_typingSentAt[groupId] ?? 0) < typingThrottleMs) return;
      _typingSentAt[groupId] = now;
      _typingOn.add(groupId);
    } else {
      if (!_typingOn.remove(groupId)) return;
      _typingSentAt.remove(groupId);
    }
    await sync.sendEphemeral(groupId, encodePayload({'v': 1, 'type': 'typing', 'id': const Uuid().v4(), 'at': now, 'on': on}));
  }

  // ---------- Receiving ----------
  final Map<String, Set<String>> _leaving = {};

  Future<void> _deliver(GroupDelivery delivery) async {
    final group = delivery.group, sender = delivery.sender.userId;
    Map<String, Object?> payload;
    try {
      payload = checkPayload(delivery.plaintext);
    } on PayloadException {
      throw const StoreException('Invalid message', code: 'invalid');
    }
    final type = payload['type'];
    if (delivery.live) {
      // Live-only frames carry typing and nothing else.
      if (type != 'typing') throw const StoreException('Not a typing payload', code: 'invalid');
      final on = payload['on']! as bool, at = payload['at']! as int;
      if (on && (_now() - at).abs() > typingFreshMs) return;
      _setTyping(group.id, sender, on);
      return;
    }
    switch (type) {
      case 'message':
        if (payload['kind'] != null) throw const StoreException('Not used in groups', code: 'invalid');
        if (names[sender] == null && _contact(sender) == null) await members(group.id, refresh: true);
        final senderName = names[sender] ?? _contact(sender)?.username;
        final result = await store.receive(group.id, payload, sender: sender, senderName: senderName != null && usernamePattern.hasMatch(senderName) ? senderName : null);
        if (result == ReceiveResult.stored) {
          _setTyping(group.id, sender, false);
          if (viewing?.call() != group.id) {
            final mentioned = (payload['mentions'] as List?)?.contains(me.id) ?? false;
            await store.updateGroup(group.id, (g) => g.copyWith(unread: g.unread + 1, mentioned: g.mentioned || mentioned));
          }
        }
      case 'react':
        await store.react(group.id, payload['target']! as String, who: sender, emoji: payload['emoji']! as String, on: payload['on']! as bool);
      case 'edit':
        final editedAt = math.min(payload['editedAt']! as int, _now() + clockSkewMs);
        await store.edit(group.id, payload['target']! as String, text: payload['text']! as String, editedAt: editedAt, author: Direction.incoming, sender: sender);
      case 'read':
        if (!readReceipts()) return;
        final changed = await store.markReadBy(group.id, (payload['ids']! as List).cast<String>(), sender);
        await _settleRead(group.id, changed);
      case 'meta':
        // Only an admin names a group; the latest `at` wins.
        if (!delivery.sender.admin && !await isAdmin(group.id, sender)) return;
        final at = payload['at']! as int, name = payload['name']! as String, topic = payload['topic']! as String;
        await store.updateGroup(group.id, (g) => at <= g.metaAt ? g : g.copyWith(name: name.isEmpty && g.kind == GroupKindName.public ? g.name : name, topic: topic, metaAt: at));
      case 'leave':
        (_leaving[group.id] ??= {}).add(sender);
        // An admin's device turns "remove me" into a commit, after this entry is done.
        if (await isAdmin(group.id)) {
          unawaited(Future<void>.delayed(Duration.zero, () => sync.remove(group.id, sender)).catchError((_) {}));
        }
      default:
        // receipt, burn, vote, rotate, policy, a stored typing: not used in groups. Dropped quietly.
        return;
    }
  }

  Future<void> _membership(MembershipChange change) async {
    final group = change.group, by = change.sender.userId;
    try {
      for (final m in await api.channelMembers(group.id)) {
        names[m['userId'] as String] = m['username'] as String;
      }
    } catch (_) {}
    for (final user in change.added) {
      await store.note(group.id, user == by ? '${nameOf(user)} joined' : '${nameOf(by)} added ${nameOf(user)}', at: change.createdAt);
    }
    for (final user in change.removed) {
      final left = _leaving[group.id]?.remove(user) ?? false;
      await store.note(group.id, left || user == by ? '${nameOf(user)} left' : '${nameOf(by)} removed ${nameOf(user)}', at: change.createdAt);
    }
    await members(group.id, refresh: true);
  }

  // ---------- Events ----------
  Future<void> onEvent(AccountEvent event) async {
    switch (event) {
      case GroupEvent():
        await sync.onGroupFrame(event);
      case WelcomeEvent():
        if (ready) await sync.onWelcome(event);
      case ChannelEvent():
        await sync.onChannel(event);
        _members.remove(event.id);
      case GroupEphemeral():
        await sync.onEphemeral(event);
      case KeyPackagesLow():
        if (ready) await sync.topUpKeyPackages();
      default:
    }
  }

  /// Opening a group clears its unread and mention marks.
  Future<void> markRead(String groupId) => store.updateGroup(groupId, (g) => g.unread == 0 && !g.mentioned ? g : g.copyWith(unread: 0, mentioned: false));

  Future<void> setPinned(String groupId, bool pinned) => store.updateGroup(groupId, (g) => g.copyWith(pinned: pinned));

  /// Forget a group this device left or was removed from (its history too).
  Future<void> forget(String groupId) async {
    try {
      await crypto.forget(groupId);
    } catch (_) {}
    await store.removeGroup(groupId);
  }

  Future<void> dispose() async {
    _disposed = true;
    _retry?.cancel();
    for (final t in [..._readTimers.values, for (final m in _typing.values) ...m.values]) {
      t.cancel();
    }
    await _notices.close();
    await _typingChanges.close();
    await sync.dispose();
  }
}
