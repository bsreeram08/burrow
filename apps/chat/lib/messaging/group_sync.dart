import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/api.dart';
import '../core/devices.dart';
import '../core/events.dart';
import '../crypto/group_crypto.dart';
import '../store/message.dart';
import '../store/message_store.dart';

/// KeyPackages: keep 100 one-time ones on the server, top up below 20 (docs/m4-groups.md §2).
const keyPackageTarget = 100;
const keyPackageLow = 20;

/// Conflicts (409) rebuild and retry: at most 5 tries, backing off 0.5, 1, 2, 4 s (§4).
const commitAttempts = 5;
Duration commitBackoff(int attempt) => Duration(milliseconds: 500 * (1 << attempt));

/// At most this many users per KeyPackage claim (§4).
const claimBatch = 16;

/// A transient failure stops a channel's queue; it is retried on the next frame or after this.
const retryAfter = Duration(seconds: 15);

/// What an admin device signs to resolve a frozen channel (channels.ts `resolveBytes`, v2): it names the
/// commit's author as this device authenticated it.
Uint8List resolveBytes(String channelId, String action, int seq, String digest, String author) =>
    Uint8List.fromList(utf8.encode('webrtc-bun-mlsresolve-v2\n$channelId\n$action\n$seq\n$digest\n$author'));

/// SHA-256 (hex) of a base64url MLS message: the delivery service's and the engine's commit digest.
String messageDigest(String message) => sha256.convert(base64Url.decode(base64Url.normalize(message))).toString();

final _unpinned = RegExp(r'no pinned account key for user ([A-Za-z0-9_-]+)');

/// One log entry as the server sends it (a `group` frame or a `/log` page entry).
class LogEntry {
  const LogEntry({required this.seq, required this.epoch, required this.kind, required this.fromUser, required this.fromDevice, required this.message, required this.createdAt});
  final int seq;
  final int epoch;

  /// `commit` or `app`.
  final String kind;
  final String fromUser;
  final String fromDevice;
  final String message;
  final int createdAt;

  factory LogEntry.fromJson(Map<String, dynamic> json) => LogEntry(
    seq: json['seq'] as int,
    epoch: json['epoch'] as int,
    kind: json['kind'] as String,
    fromUser: (json['from'] as Map)['userId'] as String,
    fromDevice: (json['from'] as Map)['deviceId'] as String,
    message: json['message'] as String,
    createdAt: json['createdAt'] as int,
  );
}

/// This account's verified device list: the devices it names, and the ones an earlier pinned list named and
/// a later one dropped (the pin's tombstones: proven absent).
class OwnDeviceList {
  const OwnDeviceList({required this.listed, required this.dropped});
  final Set<String> listed;
  final Set<String> dropped;
}

/// Where an admin device keeps its tag-only rollbacks per author device (timestamps, ms).
abstract class TagRollbackLog {
  Map<String, List<int>> read();
  void write(Map<String, List<int>> value);
}

class MemoryTagRollbackLog implements TagRollbackLog {
  Map<String, List<int>> _value = {};
  @override
  Map<String, List<int>> read() => {for (final e in _value.entries) e.key: List.of(e.value)};
  @override
  void write(Map<String, List<int>> value) => _value = value;
}

/// An admin device's own verdict on the commit a channel is frozen on.
enum FrozenVerdict { fails, ok, unknown }

/// [checkFrozen]'s result: the verdict, and the core's check of the commit (who signed it, which class of failure).
class FrozenCheck {
  const FrozenCheck(this.verdict, {this.check, this.escalation = false});
  final FrozenVerdict verdict;

  /// A failing `tag` commit by an authenticated author device whose changes this admin already rolled back at
  /// least twice in 24 h: the admin may choose (never automatically) to roll it back *and* remove that device.
  final bool escalation;

  /// The core's verdict on the commit (author and failure class), when it could be checked here.
  final CommitCheck? check;
}

/// A decrypted application message, handed to the payload layer to validate and store.
class GroupDelivery {
  const GroupDelivery({required this.group, required this.sender, required this.plaintext, required this.seq, required this.createdAt, this.live = false});
  final GroupConversation group;
  final GroupMember sender;
  final String plaintext;
  final int seq;
  final int createdAt;

  /// An `ephemeral` frame (typing): never logged, nothing to store.
  final bool live;
}

/// A commit that changed the group, as this device merged it.
class MembershipChange {
  const MembershipChange({required this.group, required this.sender, required this.added, required this.removed, required this.createdAt});
  final GroupConversation group;
  final GroupMember sender;

  /// User ids that gained their first device in the group, and those that lost their last one.
  final Set<String> added;
  final Set<String> removed;
  final int createdAt;
}

/// The payload layer's verdict on an application message that could not be stored. A coded
/// [StoreException] or [CryptoException] is permanent (the entry is skipped with a notice); anything else
/// is retried later and the cursor stays.
typedef DeliveryHandler = Future<void> Function(GroupDelivery delivery);

/// The MLS transport for groups and channels (docs/m4-groups.md §2–§8): this device's group identity and
/// KeyPackages, creating groups, commits with the 409 rebuild-and-retry loop, Welcomes, each channel's log
/// processed strictly in order with a persisted cursor, external joins (public channels, resync after a
/// gap), leaving, live-only typing, pins (TOFU for non-contacts; a pin problem pauses, never poisons), and
/// the poison-commit protocol. Payloads are not its business: plaintext goes to [onDelivery].
class GroupSync {
  GroupSync({
    required this.api,
    required this.crypto,
    required this.store,
    required this.me,
    required this.device,
    required this.platform,
    required this.ensurePinned,
    this.verifiedOwnDevices,
    this.companion = false,
    TagRollbackLog? tagLog,
    this.sendCursor,
    this.onDelivery,
    this.onMembership,
    this.ackWelcome,
    int Function()? now,
    Duration Function(int attempt)? backoff,
  }) : tagLog = tagLog ?? MemoryTagRollbackLog(),
       _now = now ?? (() => DateTime.now().millisecondsSinceEpoch),
       _backoff = backoff ?? commitBackoff;

  final Api api;
  final GroupCrypto crypto;
  final MessageStore store;
  final User me;
  final Future<LocalDevice> Function() device;
  final String platform;

  /// Pins every listed user that has no pin yet (contacts: their 1:1 identity; anyone else: trust on first
  /// use from `GET /api/users/:id/identity`); with `force`, also checks the published key again, recording a
  /// change for review (never accepting it). Returns the users without a usable pin (missing, or a changed
  /// code awaiting review). The engine refuses certificates of unpinned users.
  final Future<List<String>> Function(Iterable<String> userIds, {bool force}) ensurePinned;

  /// The `cursor` frame on the events socket (falls back to `POST .../cursor`).
  final void Function(String channel, int seq)? sendCursor;
  final void Function(String welcomeId)? ackWelcome;

  /// This admin device's record of tag-only rollbacks per author device (kept on the device).
  final TagRollbackLog tagLog;

  /// This account's own signed device list, verified under our account key against our pin (and moving it
  /// forward): the devices it names, and the ones a pinned list dropped. Null when it can't be verified; then
  /// no own leaf is removed and no channel is auto-joined (m5 §3, §4).
  final Future<OwnDeviceList?> Function()? verifiedOwnDevices;

  /// A linked device (m5 §1): its MLS certificate came with the link grant, signed by the primary; it never
  /// makes one itself.
  final bool companion;

  /// The random 0–3 s wait before acting on our own revoked leaves, so devices don't all commit at once.
  Duration Function() removalJitter = () => Duration(milliseconds: math.Random().nextInt(3000));
  DeliveryHandler? onDelivery;
  Future<void> Function(MembershipChange change)? onMembership;

  /// This device joined a 1:1 chat's DM group (m5 §8.3): a pointer waiting for it can be tried now.
  void Function(String groupId)? onDmJoined;
  final int Function() _now;
  final Duration Function(int attempt) _backoff;

  final _notices = StreamController<String>.broadcast();
  Stream<String> get notices => _notices.stream;

  /// The key database refused to work: stop until recovery (like [Messenger.keysLocked]).
  bool keysLocked = false;
  bool _disposed = false;
  final Map<String, Future<void>> _chains = {};
  final Map<String, int> _busy = {};
  final Map<String, Timer> _retries = {};
  Future<void>? _ready;

  /// Channels paused because a member's security code needs review (group id → that user's id).
  final Map<String, String> paused = {};
  final _pausedChanges = StreamController<Map<String, String>>.broadcast();
  Stream<Map<String, String>> get pausedChanges => _pausedChanges.stream;

  final _membershipChanges = StreamController<String>.broadcast();

  /// A group's members, roles or this device's membership changed.
  Stream<String> get membershipChanges => _membershipChanges.stream;

  void _notice(String text) {
    if (!_notices.isClosed) _notices.add(text);
  }

  void _changed(String groupId) {
    if (!_membershipChanges.isClosed) _membershipChanges.add(groupId);
  }

  /// Runs [work] after everything already queued for [groupId]: one channel's log, commits and sends
  /// never interleave.
  Future<T> _serial<T>(String groupId, Future<T> Function() work) {
    final previous = _chains[groupId] ?? Future.value();
    _busy[groupId] = (_busy[groupId] ?? 0) + 1;
    final run = previous.then((_) => work());
    _chains[groupId] = run.then((_) {}, onError: (_) {}).whenComplete(() {
      final left = (_busy[groupId] ?? 1) - 1;
      left <= 0 ? _busy.remove(groupId) : _busy[groupId] = left;
    });
    return run;
  }

  // ---------- This device ----------
  /// Creates this device's group identity (once) and keeps KeyPackages stocked. Needs a listed device.
  Future<void> ensureReady() => _ready ??= _setUp().catchError((Object error) {
    _ready = null;
    throw error;
  });

  Future<void> _setUp() async {
    final local = await device();
    if (!companion) await crypto.initDevice(userId: me.id, deviceId: local.deviceId, platform: platform, issuedAt: _now());
    await topUpKeyPackages();
  }

  /// Uploads `100 - oneTime` when fewer than 20 are left, and a last-resort package when there is none.
  Future<void> topUpKeyPackages() async {
    final count = await api.keyPackageCount();
    final oneTime = count['oneTime'] as int? ?? 0;
    final hasLastResort = count['lastResort'] == true || (count['lastResort'] is int && (count['lastResort'] as int) > 0);
    if (oneTime >= keyPackageLow && hasLastResort) return;
    await api.uploadKeyPackages(
      oneTime: oneTime < keyPackageLow ? await crypto.keyPackages(keyPackageTarget - oneTime) : null,
      lastResort: hasLastResort ? null : (await crypto.keyPackages(1, lastResort: true)).single,
    );
  }

  // ---------- Creating and changing groups ----------
  static String newGroupId([math.Random? random]) {
    final source = random ?? math.Random.secure();
    return base64Url.encode(List<int>.generate(16, (_) => source.nextInt(256))).replaceAll('=', '');
  }

  /// Creates a group on this device and registers it with the delivery service ([name] is the public
  /// channel's server-visible name; group and private names travel only in `meta`).
  Future<GroupConversation> create(GroupKindName kind, {String name = ''}) async {
    await ensureReady();
    final id = newGroupId();
    final roles = GroupRoles.group([me.id], joinPolicy: kind == GroupKindName.public ? JoinPolicy.open : JoinPolicy.invite);
    final view = await crypto.create(id, roles);
    try {
      await api.createChannel(id: id, kind: kind.wire, groupInfo: view.groupInfo, tree: view.tree, name: kind == GroupKindName.public ? name : null);
    } catch (_) {
      await crypto.forget(id);
      rethrow;
    }
    unawaited(_publishGroupInfo(id, view));
    return store.putGroup(GroupConversation(id: id, kind: kind, name: name, createdAt: _now()));
  }

  /// m5 §8.2: the first sender moves a 1:1 chat to a DM group of the two of us, with every listed device of
  /// both. Returns the group id, or null when the other side already made one (409: they are the first sender;
  /// wait for their pointer).
  Future<String?> createDm(String peerId, String peerUsername) async {
    await ensureReady();
    final id = newGroupId();
    final users = [me.id, peerId]..sort();
    final view = await crypto.create(id, GroupRoles(kind: GroupKind.dm, admins: users, joinPolicy: JoinPolicy.invite, dm: users));
    try {
      await api.createChannel(id: id, kind: GroupKindName.dm.wire, groupInfo: view.groupInfo, tree: view.tree, peer: peerUsername);
    } catch (error) {
      await crypto.forget(id);
      if (error is ApiException && error.status == 409) return null;
      rethrow;
    }
    unawaited(_publishGroupInfo(id, view));
    await store.putGroup(GroupConversation(id: id, kind: GroupKindName.dm, createdAt: _now(), peer: peerId));
    await add(id, [peerId, me.id]);
    await checkDm(id);
    return id;
  }

  /// m5 §8.3: whether this DM group is exactly ours with its peer, chained to the pinned keys; remembered.
  Future<bool> checkDm(String groupId) => _serial(groupId, () => checkDmNow(groupId));

  /// [checkDm] from inside the channel's queue (a delivery).
  Future<bool> checkDmNow(String groupId) async {
    final group = await store.group(groupId);
    final peer = group?.peer;
    if (group == null || !group.active || group.kind != GroupKindName.dm || peer == null) return false;
    if (group.dmChecked) return true;
    try {
      await crypto.checkDm(groupId, peer);
    } on CryptoException catch (error) {
      if (error.keysLocked) rethrow;
      return false;
    }
    await store.updateGroup(groupId, (g) => g.peer == peer ? g.copyWith(dmCheckedPeer: peer) : g);
    return true;
  }

  /// Adds every listed device of [userIds] in one commit (KeyPackages claimed 16 users at a time). Returns
  /// the users who have no device that can join yet (`missing`), who are skipped.
  Future<Set<String>> add(String groupId, List<String> userIds) => _serial(groupId, () async {
    await ensurePinned(userIds);
    var packages = <Map<String, dynamic>>[];
    final missing = <String>{};
    Future<void> claim() async {
      packages = [];
      missing.clear();
      for (var i = 0; i < userIds.length; i += claimBatch) {
        final claimed = await api.claimKeyPackages(userIds.sublist(i, math.min(i + claimBatch, userIds.length)));
        packages.addAll((claimed['keyPackages'] as List).cast<Map<String, dynamic>>());
        for (final m in (claimed['missing'] as List? ?? const []).cast<Map<String, dynamic>>()) {
          missing.add(m['userId'] as String);
        }
      }
      missing.removeAll({for (final p in packages) p['userId']});
      // Our own other devices may be added too (a DM, m5 §8.2), never this one.
      final local = await device();
      packages.removeWhere((p) => p['userId'] == me.id && p['deviceId'] == local.deviceId);
    }

    await claim();
    if (packages.isEmpty) return {...userIds};
    await _commit(
      groupId,
      () => crypto.commit(groupId, adds: [for (final p in packages) p['keyPackage'] as String]),
      joiners: () => [for (final p in packages) p['deviceId'] as String],
      // A one-time KeyPackage is spent by the claim: a rebuild claims fresh ones.
      rebuild: claim,
      redo: () async => redoAdd != null ? await redoAdd!(groupId, userIds) : await add(groupId, userIds),
    );
    return {...missing, ...userIds.where((u) => !packages.any((p) => p['userId'] == u))};
  });

  /// Removes every device of [userId] (or one device).
  Future<void> remove(String groupId, String userId, {String? deviceId}) => _serial(groupId, () async {
    if (!(await crypto.members(groupId)).any((m) => m.userId == userId && (deviceId == null || m.deviceId == deviceId))) return;
    await _commit(groupId, () => crypto.commit(groupId, removes: [GroupRemoval(userId, deviceId)]), redo: () => remove(groupId, userId, deviceId: deviceId));
  });

  /// Commits this device's own leaf again (its new certificate, m5 §5.2.2), so the group stops seeing it as
  /// Previous.
  Future<void> updateLeaf(String groupId) => _serial(groupId, () => _commit(groupId, () => crypto.commit(groupId, update: true), redo: () => updateLeaf(groupId)));

  /// Changes the group's admins (admins only).
  Future<void> setAdmins(String groupId, List<String> admins) => _serial(groupId, () async {
    final roles = await crypto.roles(groupId);
    await _commit(groupId, () => crypto.commit(groupId, roles: roles.withAdmins(admins)), redo: () => setAdmins(groupId, admins));
  });

  /// Submits a commit and settles it (§4): accepted → merge and publish the GroupInfo; 409 → drop it, catch
  /// up on the log and rebuild; no answer → leave it pending and let the log decide.
  /// Our last sequenced commit per group, with how to make the same change again ([redo]) if an admin rolls it
  /// back (m4-groups §7: the author redoes it).
  final Map<String, ({int seq, String digest, int epoch, Future<void> Function()? redo})> _lastOwn = {};

  /// Redoes a rolled-back add through the payload layer's normal add path (pins, fresh KeyPackages, `meta`).
  Future<void> Function(String groupId, List<String> userIds)? redoAdd;

  Future<void> _commit(String groupId, Future<GroupCommit> Function() build, {List<String> Function()? joiners, Future<void> Function()? rebuild, Future<void> Function()? redo}) async {
    await _catchUpNow(groupId);
    for (var attempt = 0; ; attempt++) {
      final out = await build();
      Map<String, dynamic> accepted;
      try {
        accepted = await api.postCommit(groupId, out.commit, welcome: out.welcome, joiners: out.welcome == null ? null : joiners?.call());
      } on ApiException catch (error) {
        await crypto.clearOwn(groupId);
        if (_identityConflict(error)) rethrow;
        if (error.status == 409 && attempt + 1 < commitAttempts) {
          await Future<void>.delayed(_backoff(attempt));
          await _catchUpNow(groupId);
          await rebuild?.call();
          continue;
        }
        if (error.status == 423) await _markFrozen(groupId, error.body['frozen']);
        rethrow;
      } catch (_) {
        // Unknown outcome (timeout, connection lost): the log says whether it was sequenced. Our own entry
        // merges it; if the group moved past its epoch without it, drop it and rebuild.
        await _catchUpNow(groupId);
        if (await crypto.pendingCommit(groupId) == null) return;
        await crypto.clearOwn(groupId);
        if (attempt + 1 >= commitAttempts) rethrow;
        await rebuild?.call();
        continue;
      }
      final view = await crypto.mergeOwn(groupId);
      unawaited(_publishGroupInfo(groupId, view));
      final seq = accepted['seq'] as int?;
      if (seq != null) _lastOwn[groupId] = (seq: seq, digest: accepted['digest'] as String? ?? messageDigest(out.commit), epoch: out.epoch, redo: redo);
      await _advanceTo(groupId, seq, onlyIfNext: true);
      _changed(groupId);
      return;
    }
  }

  /// Joiners (new devices of members, public channel members) need the current epoch's GroupInfo: retry a
  /// failed upload a few times (1, 2, 4, 8 s). A 409 means the group already moved on: the next committer
  /// publishes that epoch's.
  Future<void> _publishGroupInfo(String groupId, GroupView view) async {
    for (var attempt = 0; attempt < 5 && !_disposed; attempt++) {
      try {
        await api.putGroupInfo(groupId, view.epoch, view.groupInfo);
        return;
      } on ApiException catch (error) {
        if (error.status == 409 || error.status == 404 || error.status == 403) return;
      } catch (_) {}
      await Future<void>.delayed(Duration(seconds: 1 << attempt));
    }
  }

  /// Our own entry right after the cursor needs no processing (it was merged, or is our own message).
  Future<void> _advanceTo(String groupId, int? seq, {bool onlyIfNext = false}) async {
    if (seq == null) return;
    final updated = await store.updateGroup(groupId, (g) => (!onlyIfNext || g.cursor + 1 == seq) && seq > g.cursor ? g.copyWith(cursor: seq) : g);
    if (updated != null && updated.cursor == seq) _reportCursor(groupId, seq);
  }

  void _reportCursor(String groupId, int seq) {
    final send = sendCursor;
    if (send != null) {
      send(groupId, seq);
    } else {
      unawaited(api.setCursor(groupId, seq).catchError((_) {}));
    }
  }

  // ---------- Leaving ----------
  /// §4 Leave: hand over the admin role if this is the only admin, say `leave` (an admin's device removes
  /// us), forget the group, and keep it as "You left".
  Future<void> leave(String groupId, {required String leavePayload}) => _serial(groupId, () async {
    await _catchUpNow(groupId);
    final members = await crypto.members(groupId);
    final roles = await crypto.roles(groupId);
    final others = members.where((m) => m.userId != me.id).toList()..sort((a, b) => a.leaf.compareTo(b.leaf));
    if (others.isNotEmpty && roles.admins.every((a) => a == me.id)) {
      final heir = others.first.userId;
      await _commit(groupId, () => crypto.commit(groupId, roles: roles.withAdmins([...roles.admins, heir])));
    }
    if (others.isNotEmpty) await _sendNow(groupId, leavePayload);
    await crypto.forget(groupId);
    await store.updateGroup(groupId, (g) => g.copyWith(membership: Membership.left));
    _changed(groupId);
  });

  // ---------- Sending ----------
  /// Encrypts [plaintext] for the group's current epoch and posts it; a 409 (the group moved on) catches
  /// up and re-encrypts. Returns the log seq.
  Future<int> send(String groupId, String plaintext) => _serial(groupId, () => _sendNow(groupId, plaintext));

  Future<int> _sendNow(String groupId, String plaintext) async {
    for (var attempt = 0; ; attempt++) {
      final message = await crypto.encrypt(groupId, plaintext);
      try {
        final result = await api.postGroupMessage(groupId, message);
        final seq = result['seq'] as int;
        await _advanceTo(groupId, seq, onlyIfNext: true);
        return seq;
      } on ApiException catch (error) {
        if (error.status == 409 && attempt + 1 < commitAttempts) {
          await _catchUpNow(groupId);
          continue;
        }
        if (error.status == 423) await _markFrozen(groupId, error.body['frozen']);
        rethrow;
      }
    }
  }

  /// A live-only message (typing) for the current epoch; dropped on any problem.
  Future<void> sendEphemeral(String groupId, String plaintext) async {
    if ((_busy[groupId] ?? 0) > 0) return; // Never race the queue for an epoch.
    try {
      final message = await crypto.encrypt(groupId, plaintext);
      await api.postEphemeral(groupId, message);
    } catch (_) {}
  }

  /// An `ephemeral` frame: processed only while the channel's queue is idle; anything wrong is dropped.
  Future<void> onEphemeral(GroupEphemeral event) async {
    if ((_busy[event.channel] ?? 0) > 0 || keysLocked) return;
    final group = await store.group(event.channel);
    final local = await device();
    if (group == null || !group.active || event.fromDeviceId == local.deviceId) return;
    try {
      final processed = await crypto.receive(event.channel, event.message, expect: ProcessedKind.application);
      if (processed.kind != ProcessedKind.application || processed.plaintext == null) {
        await crypto.receiveAbort(processed.pendingId);
        return;
      }
      // Committed only when the payload layer took it as typing; anything else is aborted (never stored).
      final deliver = onDelivery;
      try {
        if (deliver == null) throw StateError('no payload layer');
        // Only typing travels live: any other application payload is aborted here, never delivered.
        final payload = jsonDecode(processed.plaintext!);
        if (payload is! Map || payload['type'] != 'typing') throw const FormatException('not typing');
        await deliver(GroupDelivery(group: group, sender: processed.sender, plaintext: processed.plaintext!, seq: 0, createdAt: event.createdAt, live: true));
      } catch (_) {
        await crypto.receiveAbort(processed.pendingId);
        return;
      }
      await crypto.receiveCommit(processed.pendingId);
    } catch (_) {}
  }

  // ---------- Receiving ----------
  /// A `group` frame: the next entry, processed in order; a gap or a large entry reads the log instead.
  Future<void> onGroupFrame(GroupEvent event) => _serial(event.channel, () async {
    final group = await store.group(event.channel);
    if (group == null || event.seq <= group.cursor) return;
    if (group.membership == Membership.left) {
      // Acknowledged without processing: this device left.
      await _advanceTo(event.channel, event.seq);
      return;
    }
    if (!group.active) return;
    final message = event.message;
    // A large entry, a gap, or a channel we think is frozen (a missed `thawed`): read the log.
    if (message == null || event.seq != group.cursor + 1 || group.frozen != null) return _catchUpNow(event.channel);
    await _process(group, LogEntry(seq: event.seq, epoch: event.epoch, kind: event.kind, fromUser: event.fromUserId, fromDevice: event.fromDeviceId, message: message, createdAt: event.createdAt));
  });

  /// Reads the channel's log from this device's cursor and processes every entry.
  Future<void> catchUp(String groupId) => _serial(groupId, () => _catchUpNow(groupId));

  void _retryLater(String groupId, {Duration after = retryAfter}) {
    if (_disposed) return;
    _retries[groupId]?.cancel();
    _retries[groupId] = Timer(after, () => unawaited(catchUp(groupId).catchError((_) {})));
  }

  Future<void> _catchUpNow(String groupId) async {
    for (var page = 0; page < 200; page++) {
      final group = await store.group(groupId);
      if (group == null || !group.active || keysLocked || _disposed || paused.containsKey(groupId)) return;
      final Map<String, dynamic> log;
      try {
        log = await api.groupLog(groupId, after: group.cursor);
      } on ApiException catch (error) {
        // The server no longer counts this device in the group: it was removed (the removing commit is
        // never delivered to the removed device).
        if (error.status == 404) {
          await store.updateGroup(groupId, (g) => g.active ? g.copyWith(membership: Membership.removed) : g);
          _changed(groupId);
          return;
        }
        rethrow;
      }
      if (log['frozen'] != null) {
        await _markFrozen(groupId, log['frozen']);
      } else if (group.frozen != null) {
        // Thawed while we weren't listening (nothing is sequenced while frozen).
        await store.updateGroup(groupId, (g) => g.copyWith(clearFrozen: true));
      }
      final serverSeq = log['seq'] as int? ?? 0;
      if (log['gap'] == true || serverSeq < group.cursor) {
        // Trimmed past us, or we merged a commit that was rolled back: our copy can't continue.
        await _resync(groupId);
        return;
      }
      final entries = (log['entries'] as List).cast<Map<String, dynamic>>();
      for (final raw in entries) {
        final current = await store.group(groupId);
        if (current == null || !current.active) return;
        if (!await _process(current, LogEntry.fromJson(raw))) return;
      }
      if (log['more'] != true || entries.isEmpty) return;
    }
  }

  /// Processes one entry (§6). Returns false when processing must stop here (retry later, paused, ended).
  Future<bool> _process(GroupConversation group, LogEntry entry, {bool repinned = false}) async {
    if (entry.seq <= group.cursor) return true;
    final local = await device();
    if (entry.fromUser == me.id && entry.fromDevice == local.deviceId) {
      // Never our own application messages; our own commit only while one is pending (the answer was lost).
      if (entry.kind == 'commit' && await crypto.pendingCommit(group.id) != null) {
        try {
          final own = await crypto.receive(group.id, entry.message, expect: ProcessedKind.commit);
          await crypto.receiveCommit(own.pendingId);
          unawaited(_publishGroupInfo(group.id, await crypto.view(group.id)));
          _changed(group.id);
        } on CryptoException {
          // Not ours after all (another pending commit): the epoch moved without it.
          await crypto.clearOwn(group.id);
        }
      }
      await _advanceTo(group.id, entry.seq);
      return true;
    }
    final involved = <String>{entry.fromUser};
    if (entry.kind == 'commit') {
      // A commit may add people: pin everyone the server lists before checking their certificates.
      try {
        involved.addAll({for (final m in await api.channelMembers(group.id)) m['userId'] as String});
      } catch (_) {}
    }
    // A sender whose key is blocked or changed pauses the channel before anything is received.
    final unpinned = await ensurePinned(involved.where((u) => u != me.id));
    if (unpinned.contains(entry.fromUser)) {
      _pause(group.id, entry.fromUser);
      return false;
    }
    final before = entry.kind == 'commit' ? await crypto.members(group.id) : const <GroupMember>[];
    GroupProcessed processed;
    try {
      processed = await crypto.receive(group.id, entry.message, expect: entry.kind == 'commit' ? ProcessedKind.commit : ProcessedKind.application);
    } on CryptoException catch (error) {
      if (error.keysLocked) {
        keysLocked = true;
        return false;
      }
      final missing = _unpinned.firstMatch(error.message)?.group(1);
      if (missing != null) {
        final problems = await ensurePinned([missing], force: true);
        if (problems.isEmpty && !repinned) return _process(group, entry, repinned: true);
        _pause(group.id, problems.isEmpty ? missing : problems.first);
        return false;
      }
      // Pin problems are local, never poison: before reporting, check every involved key is still the
      // published one; a change waits for review and pauses the channel.
      if (error.code == 'poison' || (entry.kind == 'commit' && error.code == 'invalid')) {
        final problems = await ensurePinned(involved.where((u) => u != me.id), force: true);
        if (problems.isNotEmpty) {
          _pause(group.id, problems.first);
          return false;
        }
      }
      if (error.code == 'poison') {
        await _reportPoison(group, entry);
        return false;
      }
      if (error.code == null) {
        _retryLater(group.id);
        return false; // Transient: the cursor stays.
      }
      // Permanent for this entry (malformed, auth, replay, a stale epoch): skip it.
      if (error.code != 'replay') _notice('A message in ${_label(group)} could not be decrypted and was skipped.');
      await _advanceTo(group.id, entry.seq);
      return true;
    }
    // The entry's kind (as the delivery service logged it) must be what the message turned out to be.
    final expected = entry.kind == 'app' ? processed.kind == ProcessedKind.application : processed.kind != ProcessedKind.application;
    if (!expected) {
      await crypto.receiveAbort(processed.pendingId);
      _notice('A message in ${_label(group)} was not what the server said it was, and was skipped.');
      await _advanceTo(group.id, entry.seq);
      return true;
    }
    switch (processed.kind) {
      case ProcessedKind.application:
        try {
          final text = processed.plaintext;
          if (text != null) await onDelivery?.call(GroupDelivery(group: group, sender: processed.sender, plaintext: text, seq: entry.seq, createdAt: entry.createdAt));
        } on StoreException catch (error) {
          if (error.code == null) return _abort(group.id, processed.pendingId);
        } on CryptoException catch (error) {
          if (error.code == null) return _abort(group.id, processed.pendingId);
        } catch (_) {
          return _abort(group.id, processed.pendingId);
        }
        // A payload that failed validation is acknowledged and dropped all the same: the key is spent.
        await crypto.receiveCommit(processed.pendingId);
      case ProcessedKind.commit || ProcessedKind.own:
        await crypto.receiveCommit(processed.pendingId);
        // The group moved on past our last commit: a later rollback notice can't concern it any more.
        if ((_lastOwn[group.id]?.seq ?? entry.seq) < entry.seq) _lastOwn.remove(group.id);
        final after = await crypto.members(group.id);
        final had = {for (final m in before) m.userId}, has = {for (final m in after) m.userId};
        _changed(group.id);
        await onMembership?.call(MembershipChange(group: group, sender: processed.sender, added: has.difference(had), removed: had.difference(has), createdAt: entry.createdAt));
      case ProcessedKind.removed:
        await crypto.receiveCommit(processed.pendingId);
        await store.updateGroup(group.id, (g) => g.copyWith(membership: Membership.removed, cursor: entry.seq));
        _notice('You were removed from ${_label(group)}.');
        _changed(group.id);
        return false;
    }
    await _advanceTo(group.id, entry.seq);
    return true;
  }

  Future<bool> _abort(String groupId, String pendingId) async {
    await crypto.receiveAbort(pendingId);
    _retryLater(groupId);
    return false;
  }

  void _pause(String groupId, String userId) {
    paused[groupId] = userId;
    if (!_pausedChanges.isClosed) _pausedChanges.add(Map.of(paused));
  }

  /// After a security-code review: resume the channels it paused.
  Future<void> resume([String? userId]) async {
    final groups = [for (final e in paused.entries) if (userId == null || e.value == userId) e.key];
    for (final g in groups) {
      paused.remove(g);
    }
    if (!_pausedChanges.isClosed) _pausedChanges.add(Map.of(paused));
    for (final g in groups) {
      unawaited(catchUp(g).catchError((_) {}));
    }
  }

  String _label(GroupConversation group) => group.name.isEmpty ? 'a group' : (group.kind.isChannel ? '#${group.name}' : group.name);

  // ---------- Welcomes and joins ----------
  /// A Welcome for this device: pin the members, join, record the group, then acknowledge it.
  Future<void> onWelcome(WelcomeEvent event) => _serial(event.channel, () async {
    final known = await store.group(event.channel);
    if (known != null && known.active && await _holds(event.channel)) {
      _dropWelcome(event.id);
      return;
    }
    var welcome = event.welcome, tree = event.tree;
    if (welcome == null || tree == null) {
      final full = await api.welcome(event.id);
      welcome = full['welcome'] as String;
      tree = full['tree'] as String;
    }
    await ensureReady();
    final users = <String>{event.from};
    try {
      users.addAll({for (final m in await api.channelMembers(event.channel)) m['userId'] as String});
    } catch (_) {}
    await ensurePinned(users.where((u) => u != me.id));
    try {
      await crypto.join(welcome, tree);
    } on CryptoException catch (error) {
      if (error.keysLocked || error.code == null) rethrow;
      final missing = _unpinned.firstMatch(error.message)?.group(1);
      if (missing == null) {
        // A Welcome this device can't accept (a bad certificate, a blocked pin): decline it, say so.
        _notice('An invitation to a group could not be verified and was declined.');
        _dropWelcome(event.id);
        return;
      }
      await ensurePinned([missing]);
      await crypto.join(welcome, tree);
    }
    final info = await _channelInfo(event.channel);
    await store.putGroup(
      (known ?? GroupConversation(id: event.channel, kind: info.kind, createdAt: _now(), name: info.name ?? ''))
          .copyWith(membership: Membership.active, cursor: event.seq, kind: info.kind, name: info.name ?? known?.name, peer: info.peer, clearDmCheck: _otherPeer(known, info.peer), clearFrozen: true),
    );
    _dropWelcome(event.id);
    _changed(event.channel);
    await _catchUpNow(event.channel);
    if (info.kind == GroupKindName.dm) {
      // A linked device never sees the pointer: the checked DM group it was added to as our device is the proof.
      if (companion && await checkDmNow(event.channel)) await store.updateGroup(event.channel, (g) => g.copyWith(movedAt: g.movedAt ?? _now()));
      onDmJoined?.call(event.channel);
    }
  });

  void _dropWelcome(String id) {
    ackWelcome?.call(id);
    unawaited(api.deleteWelcome(id).catchError((_) {}));
  }

  /// Welcomes that waited while this device was offline.
  Future<void> fetchWelcomes() async {
    for (final w in await api.welcomes()) {
      try {
        await onWelcome(WelcomeEvent(
          id: w['id'] as String,
          channel: w['channel'] as String,
          from: w['from'] as String,
          epoch: w['epoch'] as int,
          seq: w['seq'] as int,
          welcome: null,
          tree: null,
          createdAt: w['createdAt'] as int,
        ));
      } catch (_) {}
    }
  }

  /// A server row naming another peer than the one a DM is bound to: the peer stays, its check is dropped.
  static bool _otherPeer(GroupConversation? known, String? named) => known?.peer != null && named != null && named != known?.peer;

  /// The server's view of a channel; a DM channel names its other person (`peer: {id, username}`).
  Future<({GroupKindName kind, String? name, String? peer})> _channelInfo(String id) async {
    try {
      final info = await api.channel(id);
      final peer = info['peer'];
      return (kind: GroupKindName.fromWire(info['kind'] as String), name: info['name'] as String?, peer: peer is Map ? peer['id'] as String? : null);
    } catch (_) {
      return (kind: GroupKindName.private, name: null, peer: null);
    }
  }

  /// Joins a public channel from the directory (an external commit), then reads the log from there.
  Future<GroupConversation> joinPublic(String channelId) => _serial(channelId, () async {
    await ensureReady();
    await _externalJoin(channelId);
    await _catchUpNow(channelId);
    return (await store.group(channelId))!;
  });

  /// After a log gap or a broken local copy: drop the local group and join it again externally with the
  /// same leaf. History stays as stored; what was trimmed is gone.
  Future<void> _resync(String groupId) async {
    await crypto.forget(groupId);
    await _externalJoin(groupId);
    _notice('This device rejoined a group after missing part of its history.');
  }

  /// With [checked] (a join-info the caller already inspected), exactly that GroupInfo is joined, once: a retry
  /// must inspect again.
  Future<void> _externalJoin(String groupId, {Map<String, dynamic>? checked}) async {
    for (var attempt = 0; ; attempt++) {
      final Map<String, dynamic> info;
      try {
        info = checked ?? await api.joinInfo(groupId);
      } on ApiException catch (error) {
        // Between epochs (e.g. right after a rollback, before the admin uploads the restored GroupInfo): wait
        // for a member to publish it, 0.5, 1, 2, 4 s.
        if (error.status == 409 && attempt + 1 < commitAttempts) {
          await Future<void>.delayed(commitBackoff(attempt));
          continue;
        }
        rethrow;
      }
      try {
        await ensurePinned({for (final m in await api.channelMembers(groupId)) m['userId'] as String}.where((u) => u != me.id));
      } catch (_) {}
      final out = await crypto.joinExternal(info['groupInfo'] as String, info['tree'] as String, group: groupId);
      Map<String, dynamic> accepted;
      try {
        accepted = await api.joinChannel(groupId, out.commit);
      } on ApiException catch (error) {
        await crypto.clearOwn(groupId);
        await crypto.forget(groupId).catchError((_) {});
        if (_identityConflict(error)) rethrow;
        if (error.status == 409 && checked == null && attempt + 1 < commitAttempts) {
          await Future<void>.delayed(_backoff(attempt));
          continue;
        }
        rethrow;
      }
      final view = await crypto.mergeOwn(groupId);
      unawaited(_publishGroupInfo(groupId, view));
      final channel = await _channelInfo(groupId);
      final existing = await store.group(groupId);
      final seq = accepted['seq'] as int;
      // Names from a link bundle (m5 §3 step 3) for a first join; later `meta` overrides them.
      final named = existing == null ? await store.takeBundleName(groupId) : null;
      await store.putGroup(
        (existing ?? GroupConversation(id: groupId, kind: channel.kind, createdAt: _now(), name: channel.name ?? named?.name ?? '', topic: named?.topic ?? '', peer: channel.peer))
            .copyWith(membership: Membership.active, cursor: seq, clearDmCheck: _otherPeer(existing, channel.peer), clearFrozen: true),
      );
      _reportCursor(groupId, seq);
      _changed(groupId);
      return;
    }
  }

  /// Every channel the server says this account is in: catches up the ones this device belongs to
  /// (after sign-in and reconnects).
  Future<void> refresh() async {
    final channels = await api.channels();
    for (final c in channels) {
      final id = c['id'] as String;
      final local = await store.group(id);
      if (local == null) continue;
      if (c['member'] != true) {
        if (local.active) await store.updateGroup(id, (g) => g.copyWith(membership: Membership.removed));
        continue;
      }
      await store.updateGroup(id, (g) {
        var next = c['kind'] == 'public' && c['name'] is String && g.name.isEmpty ? g.copyWith(name: c['name'] as String) : g;
        if (c['frozen'] != true && g.frozen != null) next = next.copyWith(clearFrozen: true);
        return next;
      });
      unawaited(catchUp(id).catchError((_) {}));
    }
  }

  // ---------- Channel changes and poison commits (§7) ----------
  Future<void> onChannel(ChannelEvent event) async {
    switch (event.change) {
      case 'frozen':
        if (event.seq != null && event.digest != null) await _markFrozen(event.id, {'seq': event.seq, 'digest': event.digest});
      case 'rolled-back':
        // Our commit was rolled back: our copy merged a commit the group no longer has. Rejoin, then make the
        // same change again, but only on an admin's resolution that verifies against our own copy of the group,
        // and only once the log confirms the commit is gone.
        final own = _lastOwn[event.id];
        if (own == null || own.seq != event.seq || own.digest != event.digest) return;
        if (!await _verifiedRollback(event, own.seq, own.digest, own.epoch)) return;
        _lastOwn.remove(event.id);
        // A rollback that names this device removes it: nothing to redo.
        if (event.author == (await device()).deviceId) {
          _notice('An admin undid a change you made and removed this device from the group.');
          return;
        }
        try {
          await _serial(event.id, () async {
            await crypto.forget(event.id);
            await _externalJoin(event.id);
          });
        } catch (_) {
          _notice("A change you made was undone, and this device couldn't rejoin the group to make it again.");
          return;
        }
        final redo = own.redo;
        if (redo != null) {
          await redo();
          await store.note(event.id, 'Your change was undone and redone.');
        }
      case 'thawed':
        await store.updateGroup(event.id, (g) => g.copyWith(clearFrozen: true));
        unawaited(catchUp(event.id).catchError((_) {}));
      case 'remove-needed':
        // Ignored: the server can't choose whom we remove. Only the device named in our own signed rollback's
        // answer is removed (see [resolve]).
      case 'left':
        // Confirmed by the log: a removed device can no longer read it.
        unawaited(catchUp(event.id).catchError((_) {}));
      case 'remove-device':
        // A hint only: we remove our own leaf only if our verified list dropped that device.
        unawaited(removeDroppedOwnLeaves(groupId: event.id).catchError((_) => 0));
      case 'gap':
        unawaited(_serial(event.id, () => _resync(event.id)).catchError((_) {}));
      case 'joined' || 'invited' || 'updated':
        final local = await store.group(event.id);
        if (local != null) {
          // Back in after a rollback: this device's copy of the group never left it.
          if (local.membership == Membership.removed && await _holds(event.id)) {
            await store.updateGroup(event.id, (g) => g.copyWith(membership: Membership.active));
          }
          unawaited(catchUp(event.id).catchError((_) {}));
        }
        _changed(event.id);
    }
  }

  /// m4-groups §7: an admin of our own copy signed it with its leaf key, the channel is back at the commit's
  /// pre-commit epoch, and the log holds no commit with that digest.
  Future<bool> _verifiedRollback(ChannelEvent event, int seq, String digest, int epoch) async {
    final by = event.by, byUser = event.byUser, signature = event.signature, author = event.author;
    if (event.action != 'rollback' || by == null || byUser == null || signature == null || author == null) return false;
    try {
      // The signer is matched as (user, device), never by device id alone.
      final signer = await crypto.verifyResolution(event.id, action: 'rollback', seq: seq, digest: digest, author: author, by: by, byUser: byUser, signature: signature);
      if (signer != byUser) throw const CryptoException('the resolution was signed by another user', code: 'invalid');
    } catch (_) {
      _notice('A rollback notice for a group could not be verified and was ignored.');
      return false;
    }
    try {
      if ((await api.channel(event.id))['epoch'] != epoch) return false;
      final log = await api.groupLog(event.id, after: seq - 1);
      return !(log['entries'] as List).cast<Map<String, dynamic>>().any((e) => e['kind'] == 'commit' && messageDigest(e['message'] as String) == digest);
    } catch (_) {
      return false;
    }
  }

  // ---------- Repeated tag-only rollbacks (m4-groups §7) ----------
  static const _tagWindow = 24 * 60 * 60 * 1000;

  /// This admin device's tag-only rollbacks per author device in the last 24 h.
  List<int> tagRollbacks(String deviceId) => [for (final at in tagLog.read()[deviceId] ?? const <int>[]) if (_now() - at < _tagWindow) at];

  void _recordTagRollback(String deviceId) {
    final all = tagLog.read();
    final next = [...tagRollbacks(deviceId), _now()];
    all[deviceId] = next.length > 20 ? next.sublist(next.length - 20) : next;
    tagLog.write(all);
  }

  // ---------- Our own devices' leaves (m5 §3, §4) ----------
  /// Removes our own leaves for devices a verified signed list dropped (the pin's tombstones), and leaves the
  /// core marks stale. A device that is merely missing, or an unverifiable list, removes nothing. Matches
  /// (userId, deviceId). Treats "no such member" and conflicts as done.
  Future<int> removeDroppedOwnLeaves({String? groupId}) async {
    final own = verifiedOwnDevices == null ? null : await verifiedOwnDevices!();
    final local = await device();
    var removed = 0;
    final groups = groupId == null ? await store.groups() : [?await store.group(groupId)];
    for (final group in groups) {
      if (!group.active) continue;
      List<GroupMember> members;
      try {
        members = await crypto.members(group.id);
      } catch (_) {
        continue;
      }
      final targets = [
        for (final m in members)
          if (m.userId == me.id && m.deviceId != local.deviceId && (m.stale || (own?.dropped.contains(m.deviceId) ?? false))) m,
      ];
      for (final m in targets) {
        await Future<void>.delayed(removalJitter());
        try {
          await remove(group.id, me.id, deviceId: m.deviceId);
          removed++;
        } on CryptoException catch (e) {
          // "No such member": another device of ours already did it. Anything else is retried next time.
          if (!e.message.contains('no such member')) _notice("Couldn't remove a revoked device from ${_label(group)} yet: ${e.message}");
        } on ApiException catch (e) {
          if (e.status != 409) _notice("Couldn't remove a revoked device from ${_label(group)} yet: ${e.message}");
        }
      }
    }
    if (removed > 0) _notice('Removed a revoked device of yours from $removed ${removed == 1 ? 'group' : 'groups'}.');
    return removed;
  }

  /// Joins, by external commit, channels the server lists for this account that this device isn't in yet, but
  /// only where the served tree (checked by the core, [GroupCrypto.inspectGroup]) holds a current leaf of ours
  /// for another device our verified list names. Never one this device left; at most about 3 per second.
  Future<int> joinOwnChannels({int attempts = 5}) async {
    final own = verifiedOwnDevices == null ? null : await verifiedOwnDevices!();
    if (own == null) return 0;
    final local = await device();
    var joined = 0;
    var pending = [for (final c in await api.channels()) if (c['member'] != true) c];
    for (var attempt = 0; attempt < attempts && pending.isNotEmpty; attempt++) {
      if (attempt > 0) await Future<void>.delayed(_backoff(attempt - 1) * 4);
      final failed = <Map<String, dynamic>>[];
      for (final c in pending) {
        final id = c['id'] as String;
        final known = await store.group(id);
        if (known?.membership == Membership.left) continue;
        try {
          // One join-info, inspected and then joined as is (409 "between epochs" is retried, not "not ours").
          final info = await _joinInfo(id);
          final inspected = await crypto.inspectGroup(info['groupInfo'] as String, info['tree'] as String);
          // The served GroupInfo must be for this very channel.
          if (inspected.groupId != id) continue;
          final ours = inspected.members.any((m) => m.userId == me.id && !m.stale && m.deviceId != local.deviceId && own.listed.contains(m.deviceId));
          if (!ours) continue;
          await _serial(id, () async {
            await ensureReady();
            await _externalJoin(id, checked: info);
            await _catchUpNow(id);
          });
          // A moved 1:1 chat (m5 §3 step 5): usable here once it checks out as the DM of the two of us.
          // Our account moved it; this device never sees the pointer.
          if (c['kind'] == GroupKindName.dm.wire && await checkDm(id)) await store.updateGroup(id, (g) => g.copyWith(movedAt: g.movedAt ?? _now()));
          joinErrors.remove(id);
          joined++;
          await Future<void>.delayed(const Duration(milliseconds: 350));
        } catch (error) {
          // Fail closed: an unchecked or failed join is retried with backoff, then on the next start.
          joinErrors[id] = '$error';
          failed.add(c);
        }
      }
      pending = failed;
    }
    return joined;
  }

  Future<Map<String, dynamic>> _joinInfo(String id) async {
    for (var attempt = 0; ; attempt++) {
      try {
        return await api.joinInfo(id);
      } on ApiException catch (error) {
        if (error.status != 409 || attempt + 1 >= commitAttempts) rethrow;
        await Future<void>.delayed(commitBackoff(attempt));
      }
    }
  }

  /// A commit or join refused because a member's identity key doesn't match the server's record (409 `code:
  /// 'identity'`): not a race. It needs a security-code review, so it is reported once and never retried.
  bool _identityConflict(ApiException error) {
    if (error.status != 409 || error.body['code'] != 'identity') return false;
    _notice("A member's security code changed. Review it before changing this group.");
    return true;
  }

  /// Why joining one of our own channels last failed (channel id → error), for diagnostics.
  final Map<String, String> joinErrors = {};


  /// Whether this device's MLS state still has a leaf in the group.
  Future<bool> _holds(String groupId) async {
    try {
      final local = await device();
      return (await crypto.members(groupId)).any((m) => m.deviceId == local.deviceId);
    } catch (_) {
      return false;
    }
  }

  Future<void> _markFrozen(String groupId, Object? frozen) async {
    if (frozen is! Map) return;
    final state = Frozen.fromJson(frozen);
    await store.updateGroup(groupId, (g) => g.frozen == state ? g : g.copyWith(frozen: state));
  }

  Future<void> _reportPoison(GroupConversation group, LogEntry entry) async {
    final digest = messageDigest(entry.message);
    try {
      await api.reportPoison(group.id, entry.seq, digest);
    } on ApiException catch (error) {
      if (error.body['frozen'] is Map) {
        await _markFrozen(group.id, error.body['frozen']);
      } else if (error.status == 409 || error.status == 403) {
        // Refused (not the latest commit, or not ours to report): this copy can't continue; rejoin.
        await _resync(group.id);
      } else {
        // Rate limited or a server error: stop before the commit and try again later.
        _retryLater(group.id, after: const Duration(seconds: 30));
      }
      return;
    } catch (_) {
      _retryLater(group.id, after: const Duration(seconds: 30));
      return;
    }
    _reported.add(digest);
    await _markFrozen(group.id, {'seq': entry.seq, 'digest': digest});
    _notice('A change to ${_label(group)} was rejected by this device. It is paused while an admin checks it.');
  }

  /// Digests of commits this device reported as poison.
  final Set<String> _reported = {};

  /// An admin device's own check of the commit a channel is frozen on (m4-groups §7), before it may offer
  /// Rollback. The logged entry at the reported seq must be a commit whose bytes hash to the reported digest.
  /// The core then checks it against this device's own tree ([GroupCrypto.commitAuthor]): who signed it, and
  /// whether the failure is in what they signed (`signed-content`, which blames them) or only in a tag (`tag`,
  /// which a server could cause in transit and blames nobody). [FrozenVerdict.fails]: this device reported it,
  /// or a trial receive rejects it as poison. [FrozenVerdict.ok]: we built it, already merged it, or the trial
  /// accepts it (then aborted). Anything else is unknown.
  Future<FrozenCheck> checkFrozen(String groupId) => _serial(groupId, () => _checkFrozenNow(groupId));

  Future<FrozenCheck> _checkFrozenNow(String groupId) async {
    final group = await store.group(groupId);
    final frozen = group?.frozen;
    if (group == null || frozen == null) return const FrozenCheck(FrozenVerdict.unknown);
    LogEntry? entry;
    try {
      final log = await api.groupLog(groupId, after: frozen.seq - 1);
      final raw = (log['entries'] as List).cast<Map<String, dynamic>>().where((e) => e['seq'] == frozen.seq).firstOrNull;
      if (raw != null) entry = LogEntry.fromJson(raw);
    } catch (_) {}
    if (entry == null || entry.kind != 'commit' || messageDigest(entry.message) != frozen.digest) return const FrozenCheck(FrozenVerdict.unknown);
    if ((entry.fromUser == me.id && entry.fromDevice == (await device()).deviceId) || group.cursor >= frozen.seq) return const FrozenCheck(FrozenVerdict.ok);
    CommitCheck? check;
    try {
      check = await crypto.commitAuthor(groupId, entry.message);
    } catch (_) {}
    FrozenCheck failing() {
      final author = check?.author;
      final escalation = check != null && check.authenticated && check.cls == 'tag' && author != null && tagRollbacks(author.deviceId).length >= 2;
      return FrozenCheck(FrozenVerdict.fails, check: check, escalation: escalation);
    }

    if (_reported.contains(frozen.digest)) return failing();
    try {
      final trial = await crypto.receive(groupId, entry.message, expect: ProcessedKind.commit);
      await crypto.receiveAbort(trial.pendingId);
      return FrozenCheck(FrozenVerdict.ok, check: check);
    } on CryptoException catch (error) {
      return error.code == 'poison' ? failing() : FrozenCheck(FrozenVerdict.unknown, check: check);
    } catch (_) {
      return FrozenCheck(FrozenVerdict.unknown, check: check);
    }
  }

  /// An admin's decision on a frozen channel, signed with this device's key over the v2 bytes. Rollback is
  /// signed only when this device's own check says the commit fails. A `signed-content` rollback names the
  /// author this device authenticated and then removes exactly that device (nobody if the server's answer names
  /// another); a `tag` rollback, and every dismissal, name nobody and remove nobody. After a rollback this device
  /// uploads the restored epoch's GroupInfo so devices can rejoin.
  /// [removeAuthor]: the admin explicitly chose to remove the author of a repeated tag-only failure
  /// ([FrozenCheck.escalation]); refused otherwise.
  Future<void> resolve(String groupId, {required bool rollback, bool removeAuthor = false}) async {
    GroupMember? culprit;
    await _serial(groupId, () async {
      final group = await store.group(groupId);
      final frozen = group?.frozen;
      if (group == null || frozen == null) return;
      final check = await _checkFrozenNow(groupId);
      if (rollback && check.verdict != FrozenVerdict.fails) {
        throw const StoreException('This device could not confirm that change is bad, so it can only be dismissed.');
      }
      if (removeAuthor && (!rollback || !check.escalation)) throw const StoreException("Removing that device isn't offered for this change.");
      final blamed = rollback ? (check.check?.blame ?? (removeAuthor ? check.check?.author : null)) : null;
      final author = blamed?.deviceId ?? '';
      final action = rollback ? 'rollback' : 'dismiss';
      final local = await device();
      // A rollback is also signed with this device's MLS leaf key, so every member can check it came from an
      // admin of its own copy of the group before acting on the server's `rolled-back`.
      final leafSignature = rollback ? await crypto.signResolution(groupId, action: action, seq: frozen.seq, digest: frozen.digest, author: author) : null;
      final answer = await api.resolveChannel(
        groupId,
        action: action,
        seq: frozen.seq,
        digest: frozen.digest,
        author: author,
        signature: local.sign(resolveBytes(groupId, action, frozen.seq, frozen.digest, author)),
        leafSignature: leafSignature,
      );
  
      await store.updateGroup(groupId, (g) => g.copyWith(clearFrozen: true));
      final tagAuthor = check.check?.author;
      if (rollback && blamed == null && check.check?.cls == 'tag' && check.check?.authenticated == true && tagAuthor != null) _recordTagRollback(tagAuthor.deviceId);
      if (rollback) {
        // This device never merged the rejected commit, so its view is the restored epoch.
        try {
          await _publishGroupInfo(groupId, await crypto.view(groupId));
        } catch (_) {}
        if (blamed != null) {
          if (answer['removeDevice'] == blamed.deviceId) {
            culprit = blamed;
          } else {
            _notice('The server named a different device to remove than the one this device identified, so nobody was removed.');
          }
        }
      }
      // Kept, but this device rejected it: its copy can't follow the group any more, so it rejoins.
      if (!rollback && group.cursor < frozen.seq) await _resync(groupId);
      await _catchUpNow(groupId);
    });
    // A signed-content rollback: the author is still a leaf; remove exactly that device.
    final gone = culprit;
    if (gone != null) await remove(groupId, gone.userId, deviceId: gone.deviceId);
  }

  Future<void> dispose() async {
    _disposed = true;
    for (final t in _retries.values) {
      t.cancel();
    }
    await _notices.close();
    await _membershipChanges.close();
    await _pausedChanges.close();
  }
}
