import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'group_crypto.dart';

/// Test and demo stand-in for the MLS engine. It does NOT encrypt: commits, Welcomes, GroupInfos and
/// messages are base64url JSON that carry the whole (tiny) group state. It does model what the app relies
/// on: epochs (a message or commit for another epoch is refused), one pending commit per group, two-phase
/// receive, replay refusal, `own` when our pending commit comes back, `removed`, and the roles rules for
/// who may add or remove whom.
class FakeGroupCrypto implements GroupCrypto {
  FakeGroupCrypto({required this.userId, this.deviceId = '', this.platform = 'ios'});

  final String userId;
  String deviceId;
  String platform;
  bool _device = false;
  final Map<String, _Group> _groups = {};
  final Map<String, Map<String, Object?>> _pendingCommits = {};
  final Map<String, ({String groupId, _Group next, String id})> _pendingReceives = {};
  int _counter = 0;

  /// Tests: groups this device holds.
  Set<String> get groups => _groups.keys.toSet();

  static String _encode(Object value) => base64Url.encode(utf8.encode(jsonEncode(value))).replaceAll('=', '');
  static Map<String, Object?> _decode(String text) {
    try {
      return (jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(text)))) as Map).cast<String, Object?>();
    } catch (_) {
      throw const CryptoException('malformed MLS message', code: 'malformed');
    }
  }

  /// SHA-256 (hex) of the message bytes, like the engine's commit digest.
  static String _digest(String text) => sha256.convert(base64Url.decode(base64Url.normalize(text))).toString();

  _Group _group(String groupId) => _groups[groupId] ?? (throw const CryptoException('unknown group', code: 'unknown-group'));

  void _requireDevice() {
    if (!_device) throw const CryptoException('device not initialized', code: 'invalid');
  }

  Map<String, Object?> get _me => {'userId': userId, 'deviceId': deviceId, 'platform': platform};

  @override
  Future<GroupDevice> initDevice({required String userId, required String deviceId, required String platform, required int issuedAt}) async {
    if (userId != this.userId) throw const CryptoException('device certificate for another account', code: 'invalid');
    if (!_device) {
      this.deviceId = deviceId;
      this.platform = platform;
      _device = true;
    }
    return GroupDevice(userId: userId, deviceId: this.deviceId, platform: this.platform, leafSigKey: 'leaf-${this.deviceId}', aikSign: 'aik-$userId', issuedAt: issuedAt);
  }

  @override
  Future<List<String>> keyPackages(int count, {bool lastResort = false}) async {
    _requireDevice();
    if (count < 1 || count > 100) throw const CryptoException('1-100 KeyPackages', code: 'invalid');
    return [for (var i = 0; i < (lastResort ? 1 : count); i++) _encode({..._me, 'kp': ++_counter, 'lastResort': lastResort})];
  }

  @override
  Future<GroupView> create(String groupId, GroupRoles roles) async {
    _requireDevice();
    if (_groups.containsKey(groupId)) throw const CryptoException('group exists', code: 'invalid');
    if (!roles.admins.contains(userId) && !(roles.dm?.contains(userId) ?? false)) throw const CryptoException('the creator must be an admin', code: 'invalid');
    _groups[groupId] = _Group(groupId, 0, roles, [Map.of(_me)]);
    return view(groupId);
  }

  @override
  Future<GroupView> view(String groupId) async {
    final g = _group(groupId);
    final info = _encode(g.toJson());
    return GroupView(groupId: groupId, epoch: g.epoch, groupInfo: info, tree: _encode({'tree': g.groupId, 'epoch': g.epoch}));
  }

  @override
  Future<GroupCommit> commit(String groupId, {List<String> adds = const [], List<GroupRemoval> removes = const [], GroupRoles? roles, bool update = false}) async {
    final g = _group(groupId);
    if (_pendingCommits.containsKey(groupId)) throw const CryptoException('a commit is already pending', code: 'invalid');
    final added = [for (final kp in adds) _decode(kp)..remove('kp')..remove('lastResort')];
    final removed = <Map<String, Object?>>[];
    for (final r in removes) {
      final matches = g.members.where((m) => m['userId'] == r.userId && (r.deviceId == null || m['deviceId'] == r.deviceId)).toList();
      if (matches.isEmpty) throw const CryptoException('no such member', code: 'invalid');
      removed.addAll(matches);
    }
    final next = g.apply(_me, added, removed, roles);
    if (next == null) throw const CryptoException('not allowed by the group roles', code: 'invalid');
    final body = {'t': 'commit', 'g': groupId, 'epoch': g.epoch, 'from': _me, 'adds': added, 'removes': removed, 'roles': ?(roles == null ? null : _rolesJson(roles)), 'n': ++_counter};
    final text = _encode(body);
    _pendingCommits[groupId] = {'text': text, 'body': body};
    final welcome = added.isEmpty ? null : _encode({'t': 'welcome', 'group': next.toJson()});
    return GroupCommit(groupId: groupId, commit: text, welcome: welcome, digest: _digest(text), epoch: g.epoch);
  }

  @override
  Future<GroupView> mergeOwn(String groupId) async {
    final pending = _pendingCommits.remove(groupId) ?? (throw const CryptoException('no pending commit', code: 'invalid'));
    final body = pending['body']! as Map<String, Object?>;
    final g = _group(groupId);
    if (body['external'] == true) {
      _groups[groupId] = _Group.fromJson(body['group']! as Map<String, Object?>);
    } else {
      _groups[groupId] = g.apply(_me, _list(body['adds']), _list(body['removes']), body['roles'] == null ? null : _rolesFrom(body['roles']))!;
    }
    return view(groupId);
  }

  @override
  Future<void> clearOwn(String groupId) async {
    final pending = _pendingCommits.remove(groupId);
    // An external join that never landed leaves nothing behind.
    if (pending != null && (pending['body']! as Map)['external'] == true) _groups.remove(groupId);
  }

  @override
  Future<PendingGroupCommit?> pendingCommit(String groupId) async {
    final pending = _pendingCommits[groupId];
    if (pending == null) return null;
    final body = pending['body']! as Map<String, Object?>;
    return PendingGroupCommit(digest: _digest(pending['text']! as String), epoch: body['epoch']! as int);
  }

  @override
  Future<GroupView> join(String welcome, String tree) async {
    _requireDevice();
    final w = _decode(welcome);
    if (w['t'] != 'welcome') throw const CryptoException('not a Welcome', code: 'malformed');
    final g = _Group.fromJson((w['group']! as Map).cast<String, Object?>());
    if (!g.members.any((m) => m['deviceId'] == deviceId)) throw const CryptoException('this Welcome is for another device', code: 'invalid');
    _groups[g.groupId] = g;
    return view(g.groupId);
  }

  @override
  Future<GroupCommit> joinExternal(String groupInfo, String tree) async {
    _requireDevice();
    final g = _Group.fromJson(_decode(groupInfo));
    final inGroup = g.members.any((m) => m['userId'] == userId);
    if (!inGroup && g.roles.joinPolicy != JoinPolicy.open) throw const CryptoException('an invite-only group', code: 'invalid');
    final members = [for (final m in g.members) if (m['deviceId'] != deviceId) m, Map.of(_me)];
    final next = _Group(g.groupId, g.epoch + 1, g.roles, members);
    final body = {'t': 'commit', 'g': g.groupId, 'epoch': g.epoch, 'from': _me, 'external': true, 'group': next.toJson(), 'n': ++_counter};
    final text = _encode(body);
    _groups[g.groupId] = g;
    _pendingCommits[g.groupId] = {'text': text, 'body': body};
    return GroupCommit(groupId: g.groupId, commit: text, digest: _digest(text), epoch: g.epoch);
  }

  @override
  Future<void> forget(String groupId) async {
    _groups.remove(groupId);
    _pendingCommits.remove(groupId);
  }

  @override
  Future<String> encrypt(String groupId, String plaintext) async {
    final g = _group(groupId);
    if (utf8.encode(plaintext).length > 60 * 1024) throw const CryptoException('message too large', code: 'invalid');
    return _encode({'t': 'app', 'g': groupId, 'epoch': g.epoch, 'from': _me, 'plaintext': plaintext, 'n': ++_counter});
  }

  @override
  Future<GroupProcessed> receive(String groupId, String message, {ProcessedKind? expect}) async {
    final g = _group(groupId);
    final body = _decode(message);
    if (expect != null && (expect == ProcessedKind.application) != (body['t'] == 'app')) throw const CryptoException('not the expected kind of message', code: 'malformed');
    if (body['g'] != groupId) throw const CryptoException('wrong group', code: 'malformed');
    final from = (body['from']! as Map).cast<String, Object?>();
    final pendingId = 'p${++_counter}';
    GroupMember sender(_Group group) => GroupMember(
      leaf: 0,
      userId: from['userId']! as String,
      deviceId: from['deviceId']! as String,
      platform: from['platform']! as String,
      admin: group.roles.isAdmin(from['userId']! as String),
    );
    if (body['t'] == 'app') {
      final epoch = body['epoch']! as int;
      if (epoch > g.epoch || epoch < g.epoch - 2) throw const CryptoException('message from another epoch', code: 'malformed');
      final key = _digest(message);
      if (g.seen.contains(key)) throw const CryptoException('replay', code: 'replay');
      _pendingReceives[pendingId] = (groupId: groupId, next: g.copy()..seen.add(key), id: key);
      return GroupProcessed(pendingId: pendingId, kind: ProcessedKind.application, plaintext: body['plaintext'] as String?, sender: sender(g), epoch: g.epoch);
    }
    if (body['t'] != 'commit') throw const CryptoException('not an MLS message', code: 'malformed');
    if (body['epoch'] != g.epoch) throw const CryptoException('commit for another epoch', code: 'malformed');
    final own = _pendingCommits[groupId];
    if (own != null && own['text'] == message) {
      await mergeOwn(groupId);
      _pendingReceives[pendingId] = (groupId: groupId, next: _group(groupId), id: '');
      return GroupProcessed(pendingId: pendingId, kind: ProcessedKind.own, sender: sender(_group(groupId)), epoch: _group(groupId).epoch, digest: _digest(message));
    }
    final _Group? next;
    if (body['external'] == true) {
      final proposed = _Group.fromJson((body['group']! as Map).cast<String, Object?>());
      final allowed = g.members.any((m) => m['userId'] == from['userId']) || g.roles.joinPolicy == JoinPolicy.open;
      next = allowed && proposed.epoch == g.epoch + 1 ? proposed : null;
    } else {
      next = g.apply(from, _list(body['adds']), _list(body['removes']), body['roles'] == null ? null : _rolesFrom(body['roles']));
    }
    if (next == null) throw CryptoException('poison ${_digest(message)}: not allowed by the group roles', code: 'poison');
    final gone = !next.members.any((m) => m['deviceId'] == deviceId);
    _pendingReceives[pendingId] = (groupId: groupId, next: next, id: '');
    return GroupProcessed(
      pendingId: pendingId,
      kind: gone ? ProcessedKind.removed : ProcessedKind.commit,
      sender: sender(g),
      epoch: next.epoch,
      digest: _digest(message),
    );
  }

  @override
  Future<void> receiveCommit(String pendingId) async {
    final pending = _pendingReceives.remove(pendingId) ?? (throw const CryptoException('no such pending message', code: 'invalid'));
    _groups[pending.groupId] = pending.next;
  }

  @override
  Future<void> receiveAbort(String pendingId) async => _pendingReceives.remove(pendingId);

  @override
  Future<List<GroupMember>> members(String groupId) async {
    final g = _group(groupId);
    var leaf = 0;
    return [
      for (final m in g.members)
        GroupMember(leaf: leaf++, userId: m['userId']! as String, deviceId: m['deviceId']! as String, platform: m['platform']! as String, admin: g.roles.isAdmin(m['userId']! as String)),
    ];
  }

  @override
  Future<GroupRoles> roles(String groupId) async => _group(groupId).roles;
}

List<Map<String, Object?>> _list(Object? value) => [for (final m in (value as List? ?? const [])) (m as Map).cast<String, Object?>()];

Map<String, Object?> _rolesJson(GroupRoles r) => {'kind': r.kind.name, 'admins': r.admins, 'joinPolicy': r.joinPolicy.name, 'dm': ?r.dm};
GroupRoles _rolesFrom(Object? value) {
  final m = (value! as Map).cast<String, Object?>();
  return GroupRoles(
    kind: GroupKind.values.byName(m['kind']! as String),
    admins: (m['admins']! as List).cast<String>(),
    joinPolicy: JoinPolicy.values.byName(m['joinPolicy']! as String),
    dm: (m['dm'] as List?)?.cast<String>(),
  );
}

class _Group {
  _Group(this.groupId, this.epoch, this.roles, this.members, [Set<String>? seen]) : seen = seen ?? {};
  final String groupId;
  final int epoch;
  final GroupRoles roles;
  final List<Map<String, Object?>> members;
  final Set<String> seen;

  _Group copy() => _Group(groupId, epoch, roles, [for (final m in members) Map.of(m)], Set.of(seen));

  /// The policy check every member runs (API.md "Policy"), or null when the commit is not allowed.
  _Group? apply(Map<String, Object?> by, List<Map<String, Object?>> adds, List<Map<String, Object?>> removes, GroupRoles? nextRoles) {
    final committer = by['userId']! as String;
    final users = {for (final m in members) m['userId']};
    final admin = roles.isAdmin(committer);
    for (final a in adds) {
      if (!users.contains(a['userId']) && a['userId'] != committer && !(admin || roles.joinPolicy == JoinPolicy.open)) return null;
      if (roles.kind == GroupKind.dm && !(roles.dm?.contains(a['userId']) ?? false)) return null;
    }
    for (final r in removes) {
      if (r['userId'] != committer && (!admin || roles.kind == GroupKind.dm)) return null;
    }
    if (nextRoles != null && (!admin || nextRoles.kind != roles.kind)) return null;
    final gone = {for (final r in removes) r['deviceId']};
    return _Group(groupId, epoch + 1, nextRoles ?? roles, [for (final m in members) if (!gone.contains(m['deviceId'])) m, ...adds], Set.of(seen));
  }

  Map<String, Object?> toJson() => {'groupId': groupId, 'epoch': epoch, 'roles': _rolesJson(roles), 'members': members};
  factory _Group.fromJson(Map<String, Object?> json) =>
      _Group(json['groupId']! as String, json['epoch']! as int, _rolesFrom(json['roles']), _list(json['members']));
}
