import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/events.dart';

/// An in-memory delivery service for tests (the shapes of docs/signaling-api.md "Groups and channels"),
/// speaking to FakeGroupCrypto's messages: it sequences per channel with the epoch check (409), keeps the
/// log, the member mirror, cursors, Welcomes and KeyPackages, freezes on a poison report, and pushes
/// `group` / `welcome` / `channel` frames to each device's listener.
class FakeDs {
  final Map<String, _Channel> channels = {};
  final Map<String, List<({String kp, bool lastResort})>> keyPackages = {};
  final Map<String, ({String userId, String username})> devices = {};
  final Map<String, List<Map<String, Object?>>> welcomes = {};
  final Map<String, void Function(AccountEvent)> listeners = {};
  final Map<String, Set<String>> contacts = {};
  int _ids = 0;

  /// Tests: the next N answers to `commits` are 409s (a concurrent commit won).
  int conflicts = 0;

  /// A client for one device of one user.
  Api client({required String userId, required String username, required String deviceId}) {
    devices[deviceId] = (userId: userId, username: username);
    return Api(baseUrl: 'https://ds.example', clientName: 'ios', client: MockClient((request) async => _handle(request, userId, deviceId)))..token = 'token-$deviceId';
  }

  void listen(String deviceId, void Function(AccountEvent) onEvent) => listeners[deviceId] = onEvent;

  static Map<String, Object?> _mls(String text) => (jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(text)))) as Map).cast<String, Object?>();
  static String digest(String text) => sha256.convert(base64Url.decode(base64Url.normalize(text))).toString();

  http.Response _json(Object body, [int status = 200]) => http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});
  http.Response _error(String message, int status, [Map<String, Object?> extra = const {}]) => _json({'error': message, ...extra}, status);

  void _push(String deviceId, AccountEvent event) {
    final listener = listeners[deviceId];
    if (listener != null) scheduleMicrotask(() => listener(event));
  }

  void _notifyUser(String userId, AccountEvent event) {
    for (final entry in devices.entries) {
      if (entry.value.userId == userId) _push(entry.key, event);
    }
  }

  Future<http.Response> _handle(http.Request request, String userId, String deviceId) async {
    final path = request.url.path, method = request.method;
    final body = request.body.isEmpty ? <String, Object?>{} : (jsonDecode(request.body) as Map).cast<String, Object?>();
    if (path == '/api/mls/keypackages' && method == 'PUT') {
      final list = keyPackages.putIfAbsent(deviceId, () => []);
      for (final kp in (body['keyPackages'] as List? ?? const []).cast<String>()) {
        list.add((kp: kp, lastResort: false));
      }
      if (body['lastResort'] is String) {
        list
          ..removeWhere((e) => e.lastResort)
          ..add((kp: body['lastResort']! as String, lastResort: true));
      }
      return _json(_count(deviceId), 201);
    }
    if (path == '/api/mls/keypackages' && method == 'GET') return _json(_count(deviceId));
    if (path == '/api/mls/keypackages/claim') {
      final out = <Map<String, Object?>>[], missing = <Map<String, Object?>>[];
      for (final user in (body['users']! as List).cast<String>()) {
        for (final device in devices.entries.where((d) => d.value.userId == user && d.key != deviceId)) {
          final list = keyPackages[device.key] ?? [];
          final oneTime = list.where((e) => !e.lastResort).firstOrNull;
          final pick = oneTime ?? list.where((e) => e.lastResort).firstOrNull;
          if (pick == null) {
            missing.add({'userId': user, 'deviceId': device.key});
            continue;
          }
          if (!pick.lastResort) list.remove(pick);
          out.add({'userId': user, 'deviceId': device.key, 'keyPackage': pick.kp, 'lastResort': pick.lastResort});
        }
      }
      return _json({'keyPackages': out, 'missing': missing});
    }
    if (path == '/api/mls/welcomes' && method == 'GET') {
      return _json({'welcomes': [for (final w in welcomes[deviceId] ?? const <Map<String, Object?>>[]) {...w}..remove('welcome')..remove('tree')]});
    }
    final welcomeMatch = RegExp(r'^/api/mls/welcomes/(.+)$').firstMatch(path);
    if (welcomeMatch != null) {
      final list = welcomes[deviceId] ?? [];
      final w = list.where((w) => w['id'] == welcomeMatch[1]).firstOrNull;
      if (w == null) return _error('No such Welcome.', 404);
      if (method == 'DELETE') {
        list.remove(w);
        return _json({'status': 'removed'});
      }
      return _json(w);
    }
    if (path == '/api/channels' && method == 'POST') {
      final id = body['id']! as String;
      if (channels.containsKey(id)) return _error('That channel id is taken.', 409);
      final info = _mls(body['groupInfo']! as String);
      channels[id] = _Channel(id, body['kind']! as String, body['name'] as String?, info['epoch']! as int)
        ..members[deviceId] = _Member(userId, 0, 0, admin: true)
        ..groupInfo = body['groupInfo'] as String;
      return _json({'id': id, 'epoch': 0, 'seq': 0}, 201);
    }
    if (path == '/api/channels' && method == 'GET') {
      return _json({'channels': [for (final c in channels.values) if (c.members.values.any((m) => m.userId == userId)) c.describe(userId, deviceId)]});
    }
    if (path == '/api/channels/directory' && method == 'GET') {
      return _json({'channels': [for (final c in channels.values) if (c.kind == 'public') {'id': c.id, 'name': c.name, 'members': c.users.length, 'member': c.users.contains(userId)}]});
    }
    final match = RegExp(r'^/api/channels/([A-Za-z0-9_-]{22})(?:/([a-z-]+))?$').firstMatch(path);
    if (match == null) return _error('Not found', 404);
    final channel = channels[match[1]];
    final action = match[2];
    if (channel == null) return _error('No such channel.', 404);
    final member = channel.members[deviceId];
    switch ((action, method)) {
      case (null, 'GET'):
        return _json(channel.describe(userId, deviceId));
      case ('members', 'GET'):
        return _json({
          'members': [for (final e in channel.members.entries) {'userId': e.value.userId, 'username': devices[e.key]?.username ?? '', 'deviceId': e.key, 'admin': e.value.admin}],
        });
      case ('messages', 'POST'):
        if (member == null) return _error('No such channel.', 404);
        if (channel.frozen != null) return _error('frozen', 423, {'frozen': channel.frozen});
        final message = body['message']! as String;
        if (_mls(message)['epoch'] != channel.epoch) return _error('The group moved on.', 409, {'epoch': channel.epoch, 'seq': channel.seq});
        final seq = channel.append('app', userId, deviceId, message);
        _fanOut(channel, seq);
        return _json({'epoch': channel.epoch, 'seq': seq, 'digest': digest(message)}, 201);
      case ('commits', 'POST') || ('join', 'POST'):
        final external = action == 'join';
        if (!external && member == null) return _error('No such channel.', 404);
        if (external && !(channel.kind == 'public' || channel.users.contains(userId))) return _error('No such channel.', 404);
        if (channel.frozen != null) return _error('frozen', 423, {'frozen': channel.frozen});
        final message = body['message']! as String;
        final commit = _mls(message);
        if (conflicts > 0 && !external) {
          conflicts--;
          return _error('The group moved on.', 409, {'epoch': channel.epoch, 'seq': channel.seq});
        }
        if (commit['epoch'] != channel.epoch) return _error('The group moved on.', 409, {'epoch': channel.epoch, 'seq': channel.seq});
        final seq = channel.append('commit', userId, deviceId, message);
        channel.epoch++;
        final before = channel.users;
        channel.previous = {for (final e in channel.members.entries) e.key: _Member(e.value.userId, e.value.cursor, e.value.joined, admin: e.value.admin)};
        // Mirror: the fake's commit names its adds/removes (or the external join's whole group).
        if (commit['external'] == true) {
          channel.members[deviceId] = _Member(userId, seq, seq, admin: false);
        } else {
          for (final r in (commit['removes'] as List).cast<Map>()) {
            channel.members.remove(r['deviceId']);
          }
          for (final a in (commit['adds'] as List).cast<Map>()) {
            channel.members[a['deviceId'] as String] = _Member(a['userId'] as String, seq, seq, admin: false);
          }
          final roles = commit['roles'] as Map?;
          if (roles != null) {
            for (final m in channel.members.values) {
              m.admin = (roles['admins'] as List).contains(m.userId);
            }
          }
        }
        final welcome = body['welcome'] as String?;
        if (welcome != null) {
          for (final joiner in (body['joiners']! as List).cast<String>()) {
            final id = 'W${(++_ids).toString().padLeft(21, '0')}';
            final w = {'id': id, 'channel': channel.id, 'from': userId, 'epoch': channel.epoch, 'seq': seq, 'welcome': welcome, 'tree': 'tree', 'createdAt': 1};
            welcomes.putIfAbsent(joiner, () => []).add(w);
            _push(joiner, WelcomeEvent(id: id, channel: channel.id, from: userId, epoch: channel.epoch, seq: seq, welcome: welcome, tree: 'tree', createdAt: 1));
          }
        }
        for (final gone in before.difference(channel.users)) {
          _notifyUser(gone, ChannelEvent(id: channel.id, change: 'left'));
        }
        _fanOut(channel, seq);
        return _json({'epoch': channel.epoch, 'seq': seq, 'digest': digest(message)}, 201);
      case ('join-info', 'GET'):
        if (channel.groupInfo == null || channel.groupInfoEpoch != channel.epoch) return _error('between epochs', 409, {'epoch': channel.epoch});
        return _json({'epoch': channel.epoch, 'seq': channel.seq, 'groupInfo': channel.groupInfo, 'tree': 'tree'});
      case ('group-info', 'PUT'):
        if (body['epoch'] != channel.epoch) return _error('another epoch', 409, {'epoch': channel.epoch});
        channel.groupInfo = body['groupInfo'] as String;
        channel.groupInfoEpoch = channel.epoch;
        return _json({'epoch': channel.epoch});
      case ('log', 'GET'):
        if (member == null) return _error('No such channel.', 404);
        final after = int.tryParse(request.url.queryParameters['after'] ?? '') ?? member.cursor;
        final from = after > member.joined ? after : member.joined;
        final entries = channel.log.where((e) => (e['seq']! as int) > from).take(50).toList();
        return _json({'epoch': channel.epoch, 'seq': channel.seq, 'cursor': member.cursor, 'entries': entries, 'more': false, 'gap': false, 'frozen': ?channel.frozen});
      case ('cursor', 'POST'):
        if (member == null) return _error('No such channel.', 404);
        member.cursor = body['seq']! as int;
        return _json({'cursor': member.cursor});
      case ('poison', 'POST'):
        if (member == null) return _error('No such channel.', 404);
        channel.frozen = {'seq': body['seq'], 'digest': body['digest']};
        for (final admin in channel.members.values.where((m) => m.admin).map((m) => m.userId).toSet()) {
          _notifyUser(admin, ChannelEvent(id: channel.id, change: 'frozen', seq: body['seq'] as int, digest: body['digest'] as String));
        }
        return _json({'frozen': true}, 202);
      case ('resolve', 'POST'):
        if (member == null || !member.admin) return _error('Only an admin device resolves a frozen channel.', 403);
        if (channel.frozen == null) return _error('not frozen', 409);
        channel.resolved.add(body['action']! as String);
        channel.frozen = null;
        if (body['action'] == 'rollback') {
          channel.log.removeWhere((e) => e['seq'] == body['seq']);
          channel.seq--;
          channel.epoch--;
          final restored = channel.previous ?? const {};
          final back = {for (final m in restored.values) m.userId}.difference(channel.users);
          channel.members
            ..clear()
            ..addAll(restored);
          for (final u in back) {
            _notifyUser(u, ChannelEvent(id: channel.id, change: 'joined'));
          }
        }
        for (final u in channel.users) {
          _notifyUser(u, ChannelEvent(id: channel.id, change: 'thawed'));
        }
        return _json({'resolved': body['action']});
    }
    return _error('Not found', 404);
  }

  Map<String, Object?> _count(String deviceId) {
    final list = keyPackages[deviceId] ?? const [];
    final oneTime = list.where((e) => !e.lastResort).length;
    return {'oneTime': oneTime, 'lastResort': list.any((e) => e.lastResort), 'low': oneTime < 20, 'max': 100};
  }

  void _fanOut(_Channel channel, int seq) {
    final entry = channel.log.lastWhere((e) => e['seq'] == seq);
    final from = entry['from']! as Map;
    for (final device in channel.members.keys) {
      if (device == from['deviceId']) continue;
      _push(
        device,
        GroupEvent(
          channel: channel.id,
          seq: seq,
          epoch: entry['epoch']! as int,
          kind: entry['kind']! as String,
          fromUserId: from['userId']! as String,
          fromDeviceId: from['deviceId']! as String,
          message: entry['message']! as String,
          createdAt: entry['createdAt']! as int,
        ),
      );
    }
  }
}

class _Member {
  _Member(this.userId, this.cursor, this.joined, {required this.admin});
  final String userId;
  int cursor;
  final int joined;
  bool admin;
}

class _Channel {
  _Channel(this.id, this.kind, this.name, this.epoch);
  final String id;
  final String kind;
  final String? name;
  int epoch;
  int seq = 0;
  String? groupInfo;
  int? groupInfoEpoch = 0;
  Map<String, Object?>? frozen;
  Map<String, _Member>? previous;
  final List<String> resolved = [];
  final Map<String, _Member> members = {};
  final List<Map<String, Object?>> log = [];

  Set<String> get users => {for (final m in members.values) m.userId};

  int append(String kind, String userId, String deviceId, String message) {
    seq++;
    log.add({'seq': seq, 'epoch': epoch, 'kind': kind, 'from': {'userId': userId, 'deviceId': deviceId}, 'message': message, 'createdAt': 1_700_000_000_000 + seq});
    return seq;
  }

  Map<String, Object?> describe(String userId, String deviceId) => {
    'id': id,
    'kind': kind,
    'name': name,
    'epoch': epoch,
    'seq': seq,
    'frozen': frozen != null,
    'member': members.containsKey(deviceId),
    'cursor': members[deviceId]?.cursor,
    'admin': members.values.any((m) => m.userId == userId && m.admin),
  };
}
