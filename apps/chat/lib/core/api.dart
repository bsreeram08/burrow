import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'dart:io' show Platform;

import 'package:http/http.dart' as http;

/// Server base URL. Override with `--dart-define=BASE_URL=http://10.0.2.2:3000`.
const defaultBaseUrl = String.fromEnvironment('BASE_URL', defaultValue: 'https://calls.sreerams.in');

class User {
  const User({required this.id, required this.username});
  final String id;
  final String username;
  factory User.fromJson(Map<String, dynamic> json) => User(id: json['id'] as String, username: json['username'] as String);
}

enum ContactState { mutual, incoming, outgoing }

class Contact {
  const Contact({required this.id, required this.username, required this.state, this.online = false});
  final String? id;
  final String username;
  final ContactState state;
  final bool online;

  Contact copyWith({bool? online}) => Contact(id: id, username: username, state: state, online: online ?? this.online);

  factory Contact.fromJson(Map<String, dynamic> json) => Contact(
    id: json['id'] as String?,
    username: json['username'] as String,
    state: ContactState.values.byName(json['state'] as String),
    online: json['online'] as bool? ?? false,
  );
}

class ApiException implements Exception {
  const ApiException(this.message, this.status, [this.body = const {}]);
  final String message;
  final int status;

  /// The error response's JSON (e.g. a 409's `{epoch, seq}`, a 423's `frozen`).
  final Map<String, dynamic> body;
  @override
  String toString() => message;
}

/// The native client name the server expects in passkey ceremonies.
String nativeClient() => Platform.isIOS
    ? 'ios'
    : Platform.isAndroid
    ? 'android'
    : Platform.isMacOS
    ? 'macos'
    : Platform.isWindows
    ? 'windows'
    : 'linux';

/// The account API (`/api/*`). Native clients authenticate with a bearer
/// session token and must send NO Origin header (a bearer request with an
/// Origin is rejected). The token comes from the passkey `verify` response
/// (`{user, session: {token, expiresAt}}`) when the ceremony declares its
/// native `client`; native never receives a cookie.
class Api {
  Api({String baseUrl = defaultBaseUrl, http.Client? client, String? clientName})
    : base = Uri.parse(baseUrl),
      _client = client ?? http.Client(),
      _clientName = clientName; // ignore: prefer_initializing_formals

  final Uri base;
  final http.Client _client;
  final String? _clientName;
  String? token;

  /// HTTP status of the most recent [call] (e.g. 201 bound vs 202 pending push verification).
  int lastStatus = 0;
  String get client => _clientName ?? nativeClient();

  Uri uri(String path) => base.resolve(path);

  /// A 429 means the server did nothing: wait and try again a few times (0.5, 1, 2 s) before giving up.
  Future<Map<String, dynamic>> call(String path, {String method = 'GET', Object? body}) async {
    for (var attempt = 0; ; attempt++) {
      try {
        return await _callOnce(path, method: method, body: body);
      } on ApiException catch (error) {
        if (error.status != 429 || attempt >= 3) rethrow;
        await Future<void>.delayed(Duration(milliseconds: 500 * (1 << attempt)));
      }
    }
  }

  Future<Map<String, dynamic>> _callOnce(String path, {required String method, Object? body}) async {
    final request = http.Request(method, uri(path))..headers['Accept'] = 'application/json';
    if (token != null) request.headers['Authorization'] = 'Bearer $token';
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    final response = await http.Response.fromStream(await _client.send(request).timeout(const Duration(seconds: 15)));
    lastStatus = response.statusCode;
    Map<String, dynamic> data = const {};
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) data = decoded;
    } catch (_) {}
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ApiException(data['error'] as String? ?? 'Something went wrong. Try again.', response.statusCode, data);
    }
    return data;
  }

  // ---- Passkeys ----
  Future<({String flowId, Map<String, dynamic> options})> loginOptions() async {
    final data = await call('/api/login/options', method: 'POST', body: {'client': client});
    return (flowId: data['flowId'] as String, options: data['options'] as Map<String, dynamic>);
  }

  Future<({User user, String token})> loginVerify(String flowId, Map<String, dynamic> response) async =>
      _session(await call('/api/login/verify', method: 'POST', body: {'flowId': flowId, 'response': response, 'client': client}));

  ({User user, String token}) _session(Map<String, dynamic> data) =>
      (user: User.fromJson(data['user'] as Map<String, dynamic>), token: (data['session'] as Map<String, dynamic>)['token'] as String);

  Future<({String flowId, Map<String, dynamic> options})> registerOptions(String invite, String username) async {
    final data = await call('/api/register/options', method: 'POST', body: {'invite': invite, 'username': username, 'client': client});
    return (flowId: data['flowId'] as String, options: data['options'] as Map<String, dynamic>);
  }

  Future<({User user, String token})> registerVerify(String flowId, Map<String, dynamic> response) async =>
      _session(await call('/api/register/verify', method: 'POST', body: {'flowId': flowId, 'response': response, 'client': client}));

  Future<User> me() async => User.fromJson((await call('/api/me'))['user'] as Map<String, dynamic>);
  Future<void> logout({bool everywhere = false}) => call(everywhere ? '/api/logout?all=1' : '/api/logout', method: 'POST', body: const {});

  // ---- Contacts and invites ----
  Future<List<Contact>> contacts() async =>
      ((await call('/api/contacts'))['contacts'] as List).cast<Map<String, dynamic>>().map(Contact.fromJson).toList();
  Future<void> requestContact(String username) => call('/api/contacts', method: 'POST', body: {'username': username});
  Future<void> acceptContact(String username) => call('/api/contacts/$username/accept', method: 'POST', body: const {});
  Future<void> removeContact(String username) => call('/api/contacts/$username', method: 'DELETE');
  Future<({String code, int expiresAt})> createInvite() async {
    final data = await call('/api/invites', method: 'POST', body: const {});
    return (code: data['code'] as String, expiresAt: data['expiresAt'] as int);
  }

  // ---- Keys and mailbox ----
  /// [identity] is the account's currently published identity (null before the first upload).
  Future<({int oneTimePreKeys, int? signedPreKeyId, Map<String, dynamic>? identity})> keyCount() async {
    final data = await call('/api/keys/count');
    return (
      oneTimePreKeys: data['oneTimePreKeys'] as int,
      signedPreKeyId: data['signedPreKeyId'] as int?,
      identity: data['identity'] as Map<String, dynamic>?,
    );
  }

  Future<void> uploadKeys(Map<String, dynamic> upload) => call('/api/keys', method: 'PUT', body: upload);

  // ---- Devices (docs/devices.md) ----
  /// A single-use challenge for this session, to sign with the device key in [announceDevice].
  Future<String> deviceChallenge() async => (await call('/api/devices/challenge', method: 'POST', body: const {}))['challenge'] as String;

  /// Binds this session to [deviceId], proving possession of its device key ([signature] over
  /// `bindBytes(userId, deviceId, challenge)`; [deviceKey] registers a new device). With [identityProof]
  /// (the published identity key's signature over the claim bytes for the same challenge) the device takes
  /// the account's messaging inbox, unless a signed device list names another primary. Returns the
  /// server's `{deviceId, state, primary}`.
  Future<Map<String, dynamic>> announceDevice(
    String deviceId, {
    required String deviceKey,
    required String challenge,
    required String signature,
    String? identityProof,
  }) => call(
    '/api/devices/announce',
    method: 'POST',
    body: {'deviceId': deviceId, 'deviceKey': deviceKey, 'challenge': challenge, 'signature': signature, 'identityProof': ?identityProof},
  );

  // ---- Linking, revocation, succession, DM capability (docs/m5-linking.md §10.2) ----
  /// Starts a link (no session needed for `link`; a listed device's own session for `transfer`). Code mode
  /// names the account ([username]) and answers with the 8-character code too: `{linkId, claim, expiresAt, code?}`.
  Future<Map<String, dynamic>> linkStart({
    required String purpose,
    required String deviceId,
    required String deviceKey,
    required String platform,
    required String signature,
    String mode = 'qr',
    String? username,
  }) => call(
    '/api/link/start',
    method: 'POST',
    body: {'purpose': purpose, 'mode': mode, 'username': ?username, 'deviceId': deviceId, 'deviceKey': deviceKey, 'platform': platform, 'signature': signature},
  );

  /// Code mode, new device: its commitment to the ephemeral key it will reveal later.
  Future<void> linkCommit(String linkId, String commit, {required String claim}) async {
    await _linkCall('/api/link/$linkId/commit', method: 'POST', body: {'commit': commit}, claim: claim);
  }

  /// Code mode, new device: opens the commitment once the primary's key is in.
  Future<void> linkReveal(String linkId, {required String eph, required String nonce, required String claim}) async {
    await _linkCall('/api/link/$linkId/reveal', method: 'POST', body: {'eph': eph, 'nonce': nonce}, claim: claim);
  }

  /// Code mode, primary: `{linkId, deviceId, platform, commit, expiresAt}` for a typed code (404 for anything wrong).
  Future<Map<String, dynamic>> linkLookup(String code) => call('/api/link/lookup', method: 'POST', body: {'code': code});

  /// The primary offers its ephemeral key: `{deviceId, platform, purpose, mode}`.
  Future<Map<String, dynamic>> linkOffer(String linkId, String eph) => call('/api/link/$linkId/offer', method: 'POST', body: {'eph': eph});

  /// `{state, purpose, mode, platform, expiresAt}` plus, for the new device ([claim]), `eph` and `offerDeviceId`
  /// once offered; for the primary, `deviceId`, `commit?`, `reveal?`.
  Future<Map<String, dynamic>> linkState(String linkId, {String? claim}) => _linkCall('/api/link/$linkId', claim: claim);

  /// Posts one sealed message in this side's own direction; returns its seq.
  Future<int> linkSend(String linkId, String data, {String? claim}) async =>
      (await _linkCall('/api/link/$linkId/messages', method: 'POST', body: {'data': data}, claim: claim))['seq'] as int;

  /// The other side's sealed messages after [after] (exclusive), in order.
  Future<List<({int seq, String data})>> linkMessages(String linkId, {int after = 0, String? claim}) async {
    final data = await _linkCall('/api/link/$linkId/messages?after=$after', claim: claim);
    return [for (final m in (data['messages'] as List? ?? const []).cast<Map>()) (seq: m['seq'] as int, data: m['data'] as String)];
  }

  /// The primary: the list naming the new device is published and the grant sent.
  Future<void> linkGrant(String linkId) async {
    await call('/api/link/$linkId/grant', method: 'POST', body: const {});
  }

  /// The new device claims its session (no session yet): `{user, session: {token, expiresAt}}`.
  Future<({User user, String token})> linkClaim(String linkId, {required String claim, required String signature}) async =>
      _session(await _linkCall('/api/link/$linkId/claim', method: 'POST', body: {'claim': claim, 'signature': signature}));

  Future<void> linkCancel(String linkId, {String? claim}) async {
    await _linkCall('/api/link/$linkId', method: 'DELETE', claim: claim);
  }

  Future<Map<String, dynamic>> _linkCall(String path, {String method = 'GET', Object? body, String? claim}) async {
    if (claim == null) return call(path, method: method, body: body);
    final request = http.Request(method, uri(path))
      ..headers['Accept'] = 'application/json'
      ..headers['X-Link-Claim'] = claim;
    if (token != null) request.headers['Authorization'] = 'Bearer $token';
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    final response = await http.Response.fromStream(await _client.send(request).timeout(const Duration(seconds: 15)));
    lastStatus = response.statusCode;
    Map<String, dynamic> data = const {};
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) data = decoded;
    } catch (_) {}
    if (response.statusCode < 200 || response.statusCode >= 300) throw ApiException(data['error'] as String? ?? 'Something went wrong. Try again.', response.statusCode, data);
    return data;
  }

  /// Cuts one of the account's devices off at once (any session of the account; not the primary).
  Future<List<String>> revokeDevice(String deviceId) async =>
      ((await call('/api/devices/$deviceId/revoke', method: 'POST', body: const {}))['revoked'] as List? ?? const []).cast<String>();

  Future<void> publishSuccession(Map<String, dynamic> record, String signature) async {
    await call('/api/devices/succession', method: 'PUT', body: {'record': record, 'signature': signature});
  }

  // Companion certificates under a new primary's key (m5 §5.2.2).
  /// Companion: asks the primary to certify this leaf under the account's current key.
  Future<void> askRecert({required String platform, required String leafSigKey}) async {
    await call('/api/devices/recert', method: 'PUT', body: {'platform': platform, 'leafSigKey': leafSigKey});
  }

  /// Primary: listed devices waiting for a certificate, `[{deviceId, platform, leafSigKey}]`.
  Future<List<Map<String, dynamic>>> recertRequests() async => ((await call('/api/devices/recert'))['requests'] as List? ?? const []).cast<Map<String, dynamic>>();

  /// Primary: the certificate (DeviceCert JSON) answering one request.
  Future<void> answerRecert(String deviceId, String cert) async {
    await call('/api/devices/recert/$deviceId', method: 'PUT', body: {'cert': cert});
  }

  /// Companion: its answer, or null until there is one (404 if it never asked).
  Future<String?> myRecert() async => (await call('/api/devices/recert/mine'))['cert'] as String?;

  Future<void> dropRecert() async {
    await call('/api/devices/recert', method: 'DELETE');
  }

  /// `{userId, devices, channel}`: the contact's MLS-capable devices and our DM channel with them, if any.
  Future<Map<String, dynamic>> mlsCapability(String username) => call('/api/mls/capability/$username');

  /// Removes one of our devices: a pending one (or ourselves), or a listed one with the next signed list
  /// without it (`{list, signature, certs}`) from the primary.
  Future<void> removeDevice(String deviceId, [Map<String, dynamic> signed = const {}]) async {
    await call('/api/devices/$deviceId', method: 'DELETE', body: signed);
  }

  /// A contact's (or our own) served device list: `{userId, identity, list, signature, certs}`.
  Future<Map<String, dynamic>> devices(String username) => call('/api/devices/$username');
  Future<String> bundleJson(String username) async => jsonEncode(await call('/api/keys/$username'));
  Future<Map<String, dynamic>> publishedIdentity(String username) async =>
      (await call('/api/keys/$username/identity'))['identity'] as Map<String, dynamic>;
  /// [ephemeral]: delivered only to the recipient's open connections, never stored (typing).
  Future<void> postEnvelope(String username, String envelope, {bool ephemeral = false}) =>
      call('/api/messages', method: 'POST', body: {'to': username, 'envelope': envelope, if (ephemeral) 'ephemeral': true});

  /// Publishes the next signed device list (docs/devices.md): `{list, signature, certs}` from this primary device.
  Future<Map<String, dynamic>> publishDeviceList(Map<String, dynamic> signed, String deviceId) =>
      call('/api/devices/list', method: 'PUT', body: {...signed, 'deviceId': deviceId});

  // ---- Groups and channels: the MLS delivery service (docs/signaling-api.md "Groups and channels") ----
  /// Uploads one-time KeyPackages and/or the last-resort one. `{oneTime, lastResort, low}`.
  Future<Map<String, dynamic>> uploadKeyPackages({List<String>? oneTime, String? lastResort}) =>
      call('/api/mls/keypackages', method: 'PUT', body: {'keyPackages': ?oneTime, 'lastResort': ?lastResort});

  /// `{oneTime, lastResort, low, max}` for this device.
  Future<Map<String, dynamic>> keyPackageCount() => call('/api/mls/keypackages');

  /// One KeyPackage per listed device of each user: `{keyPackages: [{userId, deviceId, keyPackage, lastResort}], missing}`.
  Future<Map<String, dynamic>> claimKeyPackages(List<String> userIds) =>
      call('/api/mls/keypackages/claim', method: 'POST', body: {'users': userIds});

  /// Registers a group this device just created. [kind]: public, private, group_dm, dm or self.
  Future<Map<String, dynamic>> createChannel({
    required String id,
    required String kind,
    required String groupInfo,
    required String tree,
    String? name,
    String? peer,
  }) => call('/api/channels', method: 'POST', body: {'id': id, 'kind': kind, 'groupInfo': groupInfo, 'tree': tree, 'name': ?name, 'peer': ?peer});

  /// The caller's channels: `[{id, kind, name, epoch, seq, frozen, member, cursor, admin}]`.
  Future<List<Map<String, dynamic>>> channels() async => ((await call('/api/channels'))['channels'] as List).cast<Map<String, dynamic>>();
  Future<Map<String, dynamic>> channel(String id) => call('/api/channels/$id');

  /// Member devices: `[{userId, username, deviceId, admin}]`.
  Future<List<Map<String, dynamic>>> channelMembers(String id) async =>
      ((await call('/api/channels/$id/members'))['members'] as List).cast<Map<String, dynamic>>();

  /// An application message. `{epoch, seq, digest}`; 409 `{epoch, seq}` when built for another epoch.
  Future<Map<String, dynamic>> postGroupMessage(String id, String message) => call('/api/channels/$id/messages', method: 'POST', body: {'message': message});

  /// A commit, with the Welcome and the added devices' ids when it adds any. 409 on another epoch, 423 frozen.
  Future<Map<String, dynamic>> postCommit(String id, String message, {String? welcome, List<String>? joiners}) =>
      call('/api/channels/$id/commits', method: 'POST', body: {'message': message, 'welcome': ?welcome, 'joiners': ?joiners});

  /// Public channels: `[{id, name, members, joined}]`, newest first.
  Future<List<Map<String, dynamic>>> channelDirectory() async => ((await call('/api/channels/directory'))['channels'] as List).cast<Map<String, dynamic>>();

  /// Any account's published identity, for a trust-on-first-use pin of a group member who isn't a contact.
  Future<Map<String, dynamic>> userIdentity(String userId) => call('/api/users/$userId/identity');

  /// A live-only application message (typing), at most 2 KiB, for the current epoch.
  Future<Map<String, dynamic>> postEphemeral(String id, String message) => call('/api/channels/$id/ephemeral', method: 'POST', body: {'message': message});

  /// An external commit: a public channel, a new device of a member, or a resync.
  Future<Map<String, dynamic>> joinChannel(String id, String message) => call('/api/channels/$id/join', method: 'POST', body: {'message': message});

  /// `{epoch, seq, groupInfo, tree}` for an external join (409 between epochs).
  Future<Map<String, dynamic>> joinInfo(String id) => call('/api/channels/$id/join-info');
  Future<void> putGroupInfo(String id, int epoch, String groupInfo) async {
    await call('/api/channels/$id/group-info', method: 'PUT', body: {'epoch': epoch, 'groupInfo': groupInfo});
  }

  /// Log entries after [after] (default: this device's cursor): `{epoch, seq, cursor, entries, more, gap, frozen?}`.
  Future<Map<String, dynamic>> groupLog(String id, {int? after}) => call('/api/channels/$id/log${after == null ? '' : '?after=$after'}');
  Future<void> setCursor(String id, int seq) async {
    await call('/api/channels/$id/cursor', method: 'POST', body: {'seq': seq});
  }

  /// This device's Welcome inbox (metadata), one Welcome with its tree, and removal after storing it.
  Future<List<Map<String, dynamic>>> welcomes() async => ((await call('/api/mls/welcomes'))['welcomes'] as List).cast<Map<String, dynamic>>();
  Future<Map<String, dynamic>> welcome(String id) => call('/api/mls/welcomes/$id');
  Future<void> deleteWelcome(String id) async {
    await call('/api/mls/welcomes/$id', method: 'DELETE');
  }

  /// Reports that this device rejected the latest sequenced commit: the channel freezes.
  Future<void> reportPoison(String id, int seq, String digest) async {
    await call('/api/channels/$id/poison', method: 'POST', body: {'seq': seq, 'digest': digest});
  }

  /// An admin device resolves a frozen channel; [signature] is its device key over [resolveBytes].
  /// A rollback also carries [leafSignature], the resolution signed with this device's MLS leaf key, which the
  /// server passes on to members in `rolled-back`.
  Future<Map<String, dynamic>> resolveChannel(String id, {required String action, required int seq, required String digest, required String author, required String signature, String? leafSignature}) =>
      call('/api/channels/$id/resolve', method: 'POST', body: {'action': action, 'seq': seq, 'digest': digest, 'author': author, 'signature': signature, 'leafSignature': ?leafSignature});

  // ---- Encrypted blobs and link previews ----
  Map<String, String> get _auth => {if (token != null) 'Authorization': 'Bearer $token'};

  ApiException _blobError(int status, List<int> body) {
    String? message;
    try {
      final decoded = jsonDecode(utf8.decode(body));
      if (decoded is Map && decoded['error'] is String) message = decoded['error'] as String;
    } catch (_) {}
    return ApiException(
      message ??
          switch (status) {
            404 => 'That file is no longer on the server. Files are kept for 30 days.',
            413 => 'That file is too large. Files can be up to 25 MB.',
            429 => 'Too many files at once. Wait a moment, then try again.',
            _ => "Couldn't reach the server. Check your connection and try again.",
          },
      status,
    );
  }

  /// Uploads ciphertext, reporting progress in bytes handed to the connection. Returns the blob id.
  Future<String> uploadBlob(List<int> ciphertext, {void Function(int sent, int total)? onProgress}) async {
    final request = http.StreamedRequest('POST', uri('/api/blobs'))
      ..headers.addAll({..._auth, 'Content-Type': 'application/octet-stream', 'Accept': 'application/json'})
      ..contentLength = ciphertext.length;
    final response = _client.send(request).timeout(const Duration(minutes: 5));
    response.ignore(); // Observed below; this only keeps an early failure from surfacing as unhandled.
    const chunk = 64 * 1024;
    for (var offset = 0; offset < ciphertext.length; offset += chunk) {
      final end = offset + chunk < ciphertext.length ? offset + chunk : ciphertext.length;
      request.sink.add(ciphertext.sublist(offset, end));
      onProgress?.call(end, ciphertext.length);
      await Future<void>.delayed(Duration.zero);
    }
    unawaited(request.sink.close());
    final streamed = await response;
    final body = await streamed.stream.toBytes();
    if (streamed.statusCode < 200 || streamed.statusCode >= 300) throw _blobError(streamed.statusCode, body);
    final decoded = jsonDecode(utf8.decode(body));
    final id = decoded is Map ? decoded['id'] : null;
    if (id is! String) throw ApiException('The server gave an unexpected answer.', streamed.statusCode);
    return id;
  }

  /// Downloads up to [maxBytes] of a blob, reporting progress against Content-Length when known.
  Future<Uint8List> downloadBlob(String id, {required int maxBytes, void Function(int received, int? total)? onProgress}) =>
      _download(uri('/api/blobs/${Uri.encodeComponent(id)}'), maxBytes: maxBytes, onProgress: onProgress, timeout: const Duration(minutes: 5));

  Future<Uint8List> _download(Uri url, {required int maxBytes, void Function(int, int?)? onProgress, required Duration timeout}) async {
    final request = http.Request('GET', url)..headers.addAll(_auth);
    final streamed = await _client.send(request).timeout(const Duration(seconds: 30));
    if (streamed.statusCode != 200) throw _blobError(streamed.statusCode, await streamed.stream.toBytes());
    final total = streamed.contentLength;
    if (total != null && total > maxBytes) throw ApiException('That file is larger than expected.', 413);
    final out = BytesBuilder(copy: false);
    await for (final part in streamed.stream.timeout(timeout)) {
      out.add(part);
      if (out.length > maxBytes) throw ApiException('That file is larger than expected.', 413);
      onProgress?.call(out.length, total);
    }
    return out.takeBytes();
  }

  /// The server fetches the page (sender side only): `{url, title?, description?, site?, image?}`.
  Future<Map<String, dynamic>> unfurl(String url) => call('/api/unfurl?url=${Uri.encodeQueryComponent(url)}');

  /// The preview image's bytes (image/* only, at most 2 MB), to downscale into a thumb here.
  Future<Uint8List> unfurlImage(String url) =>
      _download(uri('/api/unfurl/image?url=${Uri.encodeQueryComponent(url)}'), maxBytes: 2 * 1024 * 1024, timeout: const Duration(seconds: 15));

  // ---- Calls ----
  Future<({String roomId, String token})> session(String username, String kind) async {
    final data = await call('/api/conversations/$username/session', method: 'POST', body: {'kind': kind});
    return (roomId: data['roomId'] as String, token: data['token'] as String);
  }

  Future<void> decline(String username, String roomId) =>
      call('/api/conversations/$username/decline', method: 'POST', body: {'roomId': roomId});

  /// Room ICE uses the room participant credential (not the account session) and,
  /// like the room socket, the server's own Origin.
  Future<Map<String, dynamic>> ice(String roomId, String roomToken) async {
    final response = await _client.get(uri('/rooms/$roomId/ice'), headers: {'Authorization': 'Bearer $roomToken', 'Origin': base.origin});
    if (response.statusCode != 200) throw ApiException('Call ended or credentials expired.', response.statusCode);
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  // ---- Push (proof of possession) ----
  /// Step 1: the server answers with a silent `{type: verify, nonce}` push to [pushToken].
  /// Returns the HTTP status: for `apns-voip`, 201 bound directly and 202 means a
  /// VoIP `verify` push is on its way and must be confirmed.
  Future<int> registerPush(String platform, String pushToken, String installId) async {
    await call('/api/push/native', method: 'POST', body: {'platform': platform, 'token': pushToken, 'installId': installId});
    return lastStatus;
  }

  /// Step 2, within 2 minutes of the verify push.
  Future<void> confirmPush(String platform, String pushToken, String nonce) =>
      call('/api/push/native/confirm', method: 'POST', body: {'platform': platform, 'token': pushToken, 'nonce': nonce});

  /// `{api, minClient: {...}}`: show "update required" when this build is older.
  Future<Map<String, dynamic>> version() => call('/api/version');
}
