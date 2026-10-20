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

/// KeyPackages: keep 100 one-time ones on the server, top up below 20 (architecture §2).
const keyPackageTarget = 100;
const keyPackageLow = 20;

/// Conflicts (409) rebuild and retry at most this many times, with backoff.
const commitAttempts = 5;

/// What an admin device signs to resolve a frozen channel (channels.ts `resolveBytes`).
Uint8List resolveBytes(String channelId, String action, int seq, String digest) =>
    Uint8List.fromList(utf8.encode('webrtc-bun-mlsresolve-v1\n$channelId\n$action\n$seq\n$digest'));

/// SHA-256 (hex) of a base64url MLS message: the delivery service's and the engine's commit digest.
String messageDigest(String message) => sha256.convert(base64Url.decode(base64Url.normalize(message))).toString();

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

/// A decrypted application message, handed to the payload layer to validate and store.
class GroupDelivery {
  const GroupDelivery({required this.group, required this.sender, required this.plaintext, required this.seq, required this.createdAt});
  final GroupConversation group;
  final GroupMember sender;
  final String plaintext;
  final int seq;
  final int createdAt;
}

/// The payload layer's verdict on an application message that could not be stored. A coded
/// [StoreException] or [CryptoException] is permanent (the entry is skipped with a notice); anything else
/// is retried later and the cursor stays.
typedef DeliveryHandler = Future<void> Function(GroupDelivery delivery);

/// The MLS transport for groups and channels: this device's group identity and KeyPackages, creating
/// groups, commits with the 409 rebuild-and-retry loop, Welcomes, processing each channel's log strictly
/// in order with a persisted cursor, external joins (public channels, resync after a gap), and the
/// poison-commit protocol (report, frozen state, admin rollback or dismiss). Payloads are not its
/// business: application plaintext goes to [onDelivery].
class GroupSync {
  GroupSync({
    required this.api,
    required this.crypto,
    required this.store,
    required this.me,
    required this.device,
    required this.platform,
    required this.ensurePinned,
    this.sendCursor,
    this.onDelivery,
    this.ackWelcome,
    int Function()? now,
    Duration Function(int attempt)? backoff,
  }) : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch),
       _backoff = backoff ?? ((attempt) => Duration(milliseconds: 200 * (1 << attempt) + math.Random().nextInt(200)));

  final Api api;
  final GroupCrypto crypto;
  final MessageStore store;
  final User me;
  final Future<LocalDevice> Function() device;
  final String platform;

  /// Makes sure every listed user has a pinned account key in the core (mutual contacts: their published,
  /// verified identity). The engine refuses certificates of unpinned users.
  final Future<void> Function(Iterable<String> userIds) ensurePinned;

  /// The `cursor` frame on the events socket (falls back to `POST .../cursor`).
  final void Function(String channel, int seq)? sendCursor;
  final void Function(String welcomeId)? ackWelcome;
  DeliveryHandler? onDelivery;
  final int Function() _now;
  final Duration Function(int attempt) _backoff;

  final _notices = StreamController<String>.broadcast();
  Stream<String> get notices => _notices.stream;

  /// The key database refused to work: stop until recovery (like [Messenger.keysLocked]).
  bool keysLocked = false;
  bool _disposed = false;
  final Map<String, Future<void>> _chains = {};
  bool _ready = false;

  void _notice(String text) {
    if (!_notices.isClosed) _notices.add(text);
  }

  /// Runs [work] after everything already queued for [groupId]: one channel's log, commits and sends
  /// never interleave.
  Future<T> _serial<T>(String groupId, Future<T> Function() work) {
    final previous = _chains[groupId] ?? Future.value();
    final run = previous.then((_) => work());
    _chains[groupId] = run.then((_) {}, onError: (_) {});
    return run;
  }

  // ---------- This device ----------
  /// Creates this device's group identity (once) and keeps KeyPackages stocked. Needs a listed device.
  Future<void> ensureReady() async {
    if (_ready) return;
    final local = await device();
    await crypto.initDevice(userId: me.id, deviceId: local.deviceId, platform: platform, issuedAt: _now());
    await topUpKeyPackages();
    _ready = true;
  }

  Future<void> topUpKeyPackages() async {
    final count = await api.keyPackageCount();
    final oneTime = count['oneTime'] as int? ?? 0;
    final hasLastResort = count['lastResort'] == true;
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

  /// Creates a group on this device, registers it with the delivery service, then adds [members] (user ids).
  Future<GroupConversation> create(GroupKindName kind, {String name = '', String? publicName, List<String> members = const [], String? dmPeer}) async {
    await ensureReady();
    final id = newGroupId();
    final roles = kind == GroupKindName.public ? GroupRoles.group([me.id], joinPolicy: JoinPolicy.open) : GroupRoles.group([me.id]);
    final view = await crypto.create(id, roles);
    try {
      await api.createChannel(id: id, kind: kind.wire, groupInfo: view.groupInfo, tree: view.tree, name: kind == GroupKindName.public ? publicName ?? name : null, peer: dmPeer);
    } catch (_) {
      await crypto.forget(id);
      rethrow;
    }
    final record = await store.putGroup(GroupConversation(id: id, kind: kind, name: name, createdAt: _now()));
    if (members.isNotEmpty) await add(id, members);
    return record;
  }

  /// Adds every listed device of [userIds] (KeyPackages claimed from the server).
  Future<void> add(String groupId, List<String> userIds) => _serial(groupId, () async {
    await ensurePinned(userIds);
    final claimed = await api.claimKeyPackages(userIds);
    final packages = (claimed['keyPackages'] as List).cast<Map<String, dynamic>>();
    if (packages.isEmpty) throw const StoreException("They have no device that can join groups yet. Ask them to open the app, then try again.");
    await _commit(
      groupId,
      () => crypto.commit(groupId, adds: [for (final p in packages) p['keyPackage'] as String]),
      joiners: [for (final p in packages) p['deviceId'] as String],
      // A claimed one-time KeyPackage is spent once: a rebuild claims fresh ones.
      reclaim: () async {
        final again = ((await api.claimKeyPackages(userIds))['keyPackages'] as List).cast<Map<String, dynamic>>();
        packages
          ..clear()
          ..addAll(again);
      },
    );
  });

  /// Removes every device of [userId] (or one device).
  Future<void> remove(String groupId, String userId, {String? deviceId}) =>
      _serial(groupId, () => _commit(groupId, () => crypto.commit(groupId, removes: [GroupRemoval(userId, deviceId)])));

  /// Changes the group's admins (admins only).
  Future<void> setAdmins(String groupId, List<String> admins) => _serial(groupId, () async {
    final roles = await crypto.roles(groupId);
    await _commit(groupId, () => crypto.commit(groupId, roles: roles.withAdmins(admins)));
  });

  /// Submits a commit and settles it: accepted → merge and publish the GroupInfo; 409 → drop it, catch up
  /// on the log and rebuild (at most [commitAttempts] times); no answer → look for it in the log.
  Future<void> _commit(String groupId, Future<GroupCommit> Function() build, {List<String>? joiners, Future<void> Function()? reclaim}) async {
    await _catchUpNow(groupId);
    for (var attempt = 0; ; attempt++) {
      final out = await build();
      Map<String, dynamic> accepted;
      try {
        accepted = await api.postCommit(groupId, out.commit, welcome: out.welcome, joiners: out.welcome == null ? null : joiners);
      } on ApiException catch (error) {
        await crypto.clearOwn(groupId);
        if (error.status == 409 && attempt + 1 < commitAttempts) {
          await Future<void>.delayed(_backoff(attempt));
          await _catchUpNow(groupId);
          await reclaim?.call();
          continue;
        }
        if (error.status == 423) await _markFrozen(groupId, error.body['frozen']);
        rethrow;
      } catch (_) {
        // Unknown outcome (timeout, connection lost): the log says whether it was sequenced.
        await _catchUpNow(groupId);
        if (await crypto.pendingCommit(groupId) == null) return; // Found in the log and merged as our own.
        await crypto.clearOwn(groupId);
        if (attempt + 1 >= commitAttempts) rethrow;
        continue;
      }
      final view = await crypto.mergeOwn(groupId);
      unawaited(_publishGroupInfo(groupId, view));
      await _advanceTo(groupId, accepted['seq'] as int?, onlyIfNext: true);
      return;
    }
  }

  Future<void> _publishGroupInfo(String groupId, GroupView view) async {
    try {
      await api.putGroupInfo(groupId, view.epoch, view.groupInfo);
    } catch (_) {
      // Best effort: the next committer publishes it; joiners wait for a current one.
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

  // ---------- Sending ----------
  /// Encrypts [plaintext] for the group's current epoch and posts it; a 409 (the group moved on) catches
  /// up and re-encrypts. Returns the log seq.
  Future<int> send(String groupId, String plaintext) => _serial(groupId, () async {
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
  });

  // ---------- Receiving ----------
  /// A `group` frame: the next entry, processed in order; a gap or a large entry reads the log instead.
  Future<void> onGroupFrame(GroupEvent event) => _serial(event.channel, () async {
    final group = await store.group(event.channel);
    if (group == null || !group.active || event.seq <= group.cursor) return;
    final message = event.message;
    if (message == null || event.seq != group.cursor + 1) return _catchUpNow(event.channel);
    await _process(group, LogEntry(seq: event.seq, epoch: event.epoch, kind: event.kind, fromUser: event.fromUserId, fromDevice: event.fromDeviceId, message: message, createdAt: event.createdAt));
  });

  /// Reads the channel's log from this device's cursor and processes every entry.
  Future<void> catchUp(String groupId) => _serial(groupId, () => _catchUpNow(groupId));

  Future<void> _catchUpNow(String groupId) async {
    for (var page = 0; page < 200; page++) {
      final group = await store.group(groupId);
      if (group == null || !group.active || keysLocked || _disposed) return;
      final Map<String, dynamic> log;
      try {
        log = await api.groupLog(groupId, after: group.cursor);
      } on ApiException catch (error) {
        // The server no longer counts this device in the group: it was removed (the removing commit is
        // never delivered to the removed device).
        if (error.status == 404 || (error.status == 403 && error.body['frozen'] == null)) {
          await store.updateGroup(groupId, (g) => g.copyWith(membership: Membership.removed));
          _membershipChanges.add(groupId);
          return;
        }
        rethrow;
      }
      if (log['frozen'] != null) await _markFrozen(groupId, log['frozen']);
      if (log['gap'] == true) {
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

  /// Processes one entry. Returns false when processing must stop here (retry later, or the group ended).
  Future<bool> _process(GroupConversation group, LogEntry entry) async {
    if (entry.seq <= group.cursor) return true;
    final local = await device();
    if (entry.fromDevice == local.deviceId) {
      // Never our own application messages; our own commit only if it is still pending here (the answer was lost).
      final pending = entry.kind == 'commit' ? await crypto.pendingCommit(group.id) : null;
      if (pending != null && pending.digest == messageDigest(entry.message)) {
        final own = await crypto.receive(group.id, entry.message);
        await crypto.receiveCommit(own.pendingId);
        final view = await crypto.view(group.id);
        unawaited(_publishGroupInfo(group.id, view));
      }
      await _advanceTo(group.id, entry.seq);
      return true;
    }
    if (entry.kind == 'commit') {
      // A commit may add people: pin everyone the server lists before checking their certificates.
      try {
        final members = await api.channelMembers(group.id);
        await ensurePinned({for (final m in members) m['userId'] as String});
      } catch (_) {}
    }
    GroupProcessed processed;
    try {
      processed = await crypto.receive(group.id, entry.message);
    } on CryptoException catch (error) {
      if (error.keysLocked) {
        keysLocked = true;
        return false;
      }
      if (error.code == 'poison') {
        await _reportPoison(group, entry, error.message);
        return false;
      }
      if (error.code == null) return false; // Transient: retry later, the cursor stays.
      // Permanent for this entry (malformed, auth, replay, a stale epoch): skip it.
      if (error.code != 'replay') _notice('A message in ${_label(group)} could not be decrypted and was skipped.');
      await _advanceTo(group.id, entry.seq);
      return true;
    }
    switch (processed.kind) {
      case ProcessedKind.application:
        try {
          final text = processed.plaintext;
          if (text != null) {
            await onDelivery?.call(GroupDelivery(group: group, sender: processed.sender, plaintext: text, seq: entry.seq, createdAt: entry.createdAt));
          }
        } on StoreException catch (error) {
          if (error.code == null) {
            await crypto.receiveAbort(processed.pendingId);
            return false;
          }
          if (error.code != 'replay') _notice('A message in ${_label(group)} was invalid and was skipped.');
        } on CryptoException catch (error) {
          if (error.code == null) {
            await crypto.receiveAbort(processed.pendingId);
            return false;
          }
        } catch (_) {
          await crypto.receiveAbort(processed.pendingId);
          return false;
        }
        await crypto.receiveCommit(processed.pendingId);
      case ProcessedKind.commit || ProcessedKind.own:
        await crypto.receiveCommit(processed.pendingId);
        _membershipChanges.add(group.id);
      case ProcessedKind.removed:
        await crypto.receiveCommit(processed.pendingId);
        await store.updateGroup(group.id, (g) => g.copyWith(membership: Membership.removed, cursor: entry.seq));
        _notice('You were removed from ${_label(group)}.');
        _membershipChanges.add(group.id);
        return false;
    }
    await _advanceTo(group.id, entry.seq);
    return true;
  }

  final _membershipChanges = StreamController<String>.broadcast();

  /// A group's members or roles changed (a commit was merged here).
  Stream<String> get membershipChanges => _membershipChanges.stream;

  String _label(GroupConversation group) => group.name.isEmpty ? 'a group' : group.name;

  // ---------- Welcomes and joins ----------
  /// A Welcome for this device: join, record the group, then acknowledge it.
  Future<void> onWelcome(WelcomeEvent event) => _serial(event.channel, () async {
    if (await store.group(event.channel) case final known? when known.active) {
      ackWelcome?.call(event.id);
      return;
    }
    var welcome = event.welcome, tree = event.tree;
    if (welcome == null || tree == null) {
      final full = await api.welcome(event.id);
      welcome = full['welcome'] as String;
      tree = full['tree'] as String;
    }
    await ensureReady();
    try {
      final members = await api.channelMembers(event.channel);
      await ensurePinned({event.from, for (final m in members) m['userId'] as String});
    } catch (_) {}
    try {
      await crypto.join(welcome, tree);
    } on CryptoException catch (error) {
      if (error.keysLocked || error.code == null) rethrow;
      // A Welcome this device can't accept (an unpinned member, a bad certificate): drop it, say so.
      _notice('An invitation to a group could not be verified and was declined.');
      ackWelcome?.call(event.id);
      unawaited(api.deleteWelcome(event.id).catchError((_) {}));
      return;
    }
    final info = await _channelInfo(event.channel);
    final existing = await store.group(event.channel);
    await store.putGroup(
      (existing ?? GroupConversation(id: event.channel, kind: info.kind, createdAt: _now(), name: info.name ?? ''))
          .copyWith(membership: Membership.active, cursor: event.seq, kind: info.kind, name: info.name ?? existing?.name),
    );
    ackWelcome?.call(event.id);
    unawaited(api.deleteWelcome(event.id).catchError((_) {}));
    _membershipChanges.add(event.channel);
    await _catchUpNow(event.channel);
  });

  /// Welcomes that waited while this device was offline (the socket also replays them).
  Future<void> fetchWelcomes() async {
    for (final w in await api.welcomes()) {
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
    }
  }

  Future<({GroupKindName kind, String? name})> _channelInfo(String id) async {
    try {
      final info = await api.channel(id);
      return (kind: GroupKindName.fromWire(info['kind'] as String), name: info['name'] as String?);
    } catch (_) {
      return (kind: GroupKindName.private, name: null);
    }
  }

  /// Joins a public channel (an external commit), or rejoins one this device fell out of.
  Future<GroupConversation> joinPublic(String channelId, {String? name}) => _serial(channelId, () async {
    await ensureReady();
    await _externalJoin(channelId);
    return (await store.group(channelId))!;
  });

  /// After a log gap (trimmed past this device) or a broken local copy: drop the local group and join it
  /// again externally with the same leaf. History stays; what was trimmed is gone.
  Future<void> _resync(String groupId) async {
    await crypto.forget(groupId);
    await _externalJoin(groupId);
    _notice('This device rejoined a group after missing part of its history.');
  }

  Future<void> _externalJoin(String groupId) async {
    for (var attempt = 0; ; attempt++) {
      final info = await api.joinInfo(groupId);
      try {
        final members = await api.channelMembers(groupId);
        await ensurePinned({for (final m in members) m['userId'] as String});
      } catch (_) {}
      final out = await crypto.joinExternal(info['groupInfo'] as String, info['tree'] as String);
      Map<String, dynamic> accepted;
      try {
        accepted = await api.joinChannel(groupId, out.commit);
      } on ApiException catch (error) {
        await crypto.clearOwn(groupId);
        await crypto.forget(groupId).catchError((_) {});
        if (error.status == 409 && attempt + 1 < commitAttempts) {
          await Future<void>.delayed(_backoff(attempt));
          continue;
        }
        rethrow;
      }
      final view = await crypto.mergeOwn(groupId);
      unawaited(_publishGroupInfo(groupId, view));
      final channel = await _channelInfo(groupId);
      final existing = await store.group(groupId);
      await store.putGroup(
        (existing ?? GroupConversation(id: groupId, kind: channel.kind, createdAt: _now(), name: channel.name ?? ''))
            .copyWith(membership: Membership.active, cursor: accepted['seq'] as int, clearFrozen: true),
      );
      _reportCursor(groupId, accepted['seq'] as int);
      _membershipChanges.add(groupId);
      return;
    }
  }

  /// Every channel the server says this account is in: records the ones this device belongs to and
  /// catches each one up (after sign-in and reconnects).
  Future<void> refresh() async {
    final channels = await api.channels();
    for (final c in channels) {
      final id = c['id'] as String;
      final local = await store.group(id);
      if (local == null || c['member'] != true) continue;
      await store.updateGroup(id, (g) {
        var next = c['kind'] == 'public' && c['name'] is String ? g.copyWith(name: c['name'] as String) : g;
        if (c['frozen'] != true && g.frozen != null) next = next.copyWith(clearFrozen: true);
        return next;
      });
      if (c['frozen'] == true && local.frozen == null) {
        try {
          final log = await api.groupLog(id, after: local.cursor);
          if (log['frozen'] != null) await _markFrozen(id, log['frozen']);
        } catch (_) {}
      }
      unawaited(catchUp(id).catchError((_) {}));
    }
  }

  // ---------- Channel changes and poison commits ----------
  Future<void> onChannel(ChannelEvent event) async {
    switch (event.change) {
      case 'frozen':
        if (event.seq != null && event.digest != null) await _markFrozen(event.id, {'seq': event.seq, 'digest': event.digest});
      case 'thawed':
        await store.updateGroup(event.id, (g) => g.copyWith(clearFrozen: true));
        unawaited(catchUp(event.id).catchError((_) {}));
      case 'remove-needed':
        // Admins remove a rolled-back commit's author with an ordinary commit.
        final deviceId = event.deviceId;
        if (deviceId == null) return;
        try {
          final member = (await crypto.members(event.id)).where((m) => m.deviceId == deviceId).firstOrNull;
          if (member != null && (await crypto.roles(event.id)).isAdmin(me.id)) await remove(event.id, member.userId, deviceId: deviceId);
        } catch (_) {}
      case 'left':
        // Confirmed by the log: a removed device can no longer read it.
        unawaited(catchUp(event.id).catchError((_) {}));
      case 'gap':
        unawaited(_serial(event.id, () => _resync(event.id)).catchError((_) {}));
      case 'joined' || 'invited' || 'updated':
        final local = await store.group(event.id);
        if (local != null) {
          // Back in after a rollback: this device's copy of the group never left it.
          if (!local.active && local.membership == Membership.removed && await _holds(event.id)) {
            await store.updateGroup(event.id, (g) => g.copyWith(membership: Membership.active));
          }
          unawaited(catchUp(event.id).catchError((_) {}));
        }
        _membershipChanges.add(event.id);
    }
  }

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

  Future<void> _reportPoison(GroupConversation group, LogEntry entry, String reason) async {
    final digest = messageDigest(entry.message);
    try {
      await api.reportPoison(group.id, entry.seq, digest);
    } on ApiException catch (error) {
      if (error.body['frozen'] is Map) await _markFrozen(group.id, error.body['frozen']);
      return;
    } catch (_) {
      return;
    }
    await _markFrozen(group.id, {'seq': entry.seq, 'digest': digest});
    _notice('A change to ${_label(group)} was rejected by this device. The group is paused until an admin resolves it.');
  }

  /// An admin's decision on a frozen channel: `rollback` (undo the commit and remove its author) or
  /// `dismiss` (keep it). Signed with this device's key.
  Future<void> resolve(String groupId, {required bool rollback}) => _serial(groupId, () async {
    final group = await store.group(groupId);
    final frozen = group?.frozen;
    if (frozen == null) return;
    final action = rollback ? 'rollback' : 'dismiss';
    final local = await device();
    await api.resolveChannel(groupId, action: action, seq: frozen.seq, digest: frozen.digest, signature: local.sign(resolveBytes(groupId, action, frozen.seq, frozen.digest)));
    await store.updateGroup(groupId, (g) => g.copyWith(clearFrozen: true));
    if (!rollback) {
      // Kept: if this device rejected it, its copy can't follow the group any more; rejoin.
      if (group!.cursor < frozen.seq) await _resync(groupId);
    }
    await _catchUpNow(groupId);
  });

  Future<void> dispose() async {
    _disposed = true;
    await _notices.close();
    await _membershipChanges.close();
  }
}
