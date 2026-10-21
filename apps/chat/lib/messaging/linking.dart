import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import '../core/api.dart';
import '../core/devices.dart';
import '../crypto/account_crypto.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/group_crypto.dart' show GroupCrypto;
import '../crypto/link_crypto.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import 'messenger.dart';

/// Bundle limits (docs/m5-linking.md §2): history of at most 20 conversations, 200 messages each; at most 16
/// chunks; each chunk's slice small enough that its sealed message stays well under 48 KiB of plaintext.
const bundleConversations = 20, bundleMessages = 200, bundleChunks = 16, bundleSlice = 32 * 1024;

/// What the new device said about itself (the sealed `hello`, §1.4).
class LinkHello {
  const LinkHello({required this.deviceId, required this.platform, required this.label, required this.leafSigKey, required this.wantsHistory});
  final String deviceId;
  final String platform;
  final String label;
  final String leafSigKey;
  final bool wantsHistory;

  static final _key = RegExp(r'^[A-Za-z0-9_-]{43}$'), _id = RegExp(r'^[A-Za-z0-9_-]{22}$');

  static LinkHello parse(String json) {
    final m = jsonDecode(json);
    const keys = {'v', 'type', 'deviceId', 'platform', 'label', 'leafSigKey', 'wantsHistory'};
    if (m is! Map || m.length != keys.length || !m.keys.every(keys.contains) || m['v'] != 1 || m['type'] != 'hello') throw const FormatException('Not a hello');
    final deviceId = m['deviceId'], platform = m['platform'], label = m['label'], leaf = m['leafSigKey'], history = m['wantsHistory'];
    if (deviceId is! String || !_id.hasMatch(deviceId) || platform is! String || !devicePlatforms.contains(platform)) throw const FormatException('Invalid hello');
    if (label is! String || label.runes.length > 64 || leaf is! String || !_key.hasMatch(leaf) || history is! bool) throw const FormatException('Invalid hello');
    return LinkHello(deviceId: deviceId, platform: platform, label: label, leafSigKey: leaf, wantsHistory: history);
  }
}

/// This device is the primary linking a new device (docs/m5-linking.md §1): it took the new device's QR or
/// its short code, both screens show the same 6 digits, and only after the user taps Link does it sign
/// anything: the next device list naming the device, its MLS certificate, the grant and the bundle.
class PrimaryLink {
  PrimaryLink._(this._ctx, {required this.linkId, required this.deviceId, required this.platform, required this.code, this.viaCode = false});

  /// Linked by the 8-character code: the 6 digits alone authenticate the exchange, so the account key is not
  /// handed over (docs/m6-account-key.md §2); the device unlocks with the passphrase later.
  final bool viaCode;

  final LinkContext _ctx;
  final String linkId;

  /// The new device, as the server registered it at `link/start`.
  final String deviceId;
  final String platform;

  /// "123 456": compare with the new device's screen.
  final String code;
  LinkHello? hello;
  int _read = 0;
  bool _done = false;

  /// From a scanned (or pasted) QR text.
  static Future<PrimaryLink> fromQr(LinkContext ctx, String qr) async {
    final accepted = await ctx.link.accept(qr.replaceAll(RegExp(r'\s'), ''));
    try {
      final offered = await ctx.api.linkOffer(accepted.linkId, accepted.eph);
      return PrimaryLink._(ctx, linkId: accepted.linkId, deviceId: offered['deviceId'] as String, platform: offered['platform'] as String, code: accepted.code);
    } catch (_) {
      await ctx.link.end(accepted.linkId);
      rethrow;
    }
  }

  /// From the 8-character code the new device shows (§1.7): look it up, offer, then wait for the reveal.
  static Future<PrimaryLink> fromCode(LinkContext ctx, String typed, {Duration timeout = const Duration(minutes: 5)}) async {
    final found = await ctx.api.linkLookup(typed.toUpperCase().replaceAll(RegExp(r'[\s-]'), ''));
    final linkId = found['linkId'] as String, deviceN = found['deviceId'] as String;
    final me = (await ctx.device()).deviceId;
    try {
      final eph = await ctx.link.lookup(linkId, deviceN: deviceN, commit: found['commit'] as String, deviceP: me);
      final offered = await ctx.api.linkOffer(linkId, eph);
      final end = DateTime.now().add(timeout);
      while (true) {
        final state = await ctx.api.linkState(linkId);
        final reveal = state['reveal'];
        if (reveal is Map) {
          final code = await ctx.link.openCommitment(linkId, eph: reveal['eph'] as String, nonce: reveal['nonce'] as String);
          return PrimaryLink._(ctx, linkId: linkId, deviceId: offered['deviceId'] as String, platform: offered['platform'] as String, code: code, viaCode: true);
        }
        if (DateTime.now().isAfter(end)) throw const StoreException('The other device did not answer. Start again on it.');
        await ctx.wait(const Duration(milliseconds: 600));
      }
    } catch (_) {
      await ctx.link.end(linkId);
      unawaited(ctx.api.linkCancel(linkId).catchError((_) {}));
      rethrow;
    }
  }

  /// Waits for the new device's sealed hello (label, platform, leaf key) and checks it names the device the
  /// server registered.
  Future<LinkHello> waitHello({Duration timeout = const Duration(minutes: 5)}) async {
    final end = DateTime.now().add(timeout);
    while (hello == null) {
      for (final m in await _ctx.api.linkMessages(linkId, after: _read)) {
        _read = m.seq;
        final parsed = LinkHello.parse(await _ctx.link.open(linkId, m.data));
        if (parsed.deviceId != deviceId || parsed.platform != platform) throw const StoreException("That device didn't introduce itself as the one that asked to link. Nothing was linked.");
        hello = parsed;
        break;
      }
      if (hello != null) break;
      if (DateTime.now().isAfter(end)) throw const StoreException('The other device did not answer. Start again on it.');
      await _ctx.wait(const Duration(milliseconds: 600));
    }
    return hello!;
  }

  /// The user compared the codes and tapped Link: publish the list naming the device, sign its MLS
  /// certificate, then send the grant and the bundle and tell the server.
  Future<void> approve() async {
    final h = hello ?? (throw StateError('No hello yet'));
    if (_done) return;
    final me = _ctx.messenger.me;
    final metaKey = deviceMetaKey(await _ctx.crypto.deviceMetaSignature(me.id));
    final now = _ctx.now();
    // A short-code link says so in the sealed meta (M6 §5): no rekey for it; it unlocks with the passphrase.
    final entry = <String, Object?>{
      'deviceId': h.deviceId,
      'addedAt': now,
      'meta': sealMeta(metaKey, me.id, h.deviceId, label: h.label.isEmpty ? platformLabel(h.platform) : h.label, platform: h.platform, via: viaCode ? 'code' : null),
    };
    final published = await _ctx.messenger.publishNextList(add: entry);
    final cert = await _ctx.link.signDeviceCert(userId: me.id, deviceId: h.deviceId, platform: h.platform, leafSigKey: h.leafSigKey, issuedAt: now);
    final identity = await _ctx.crypto.identity();
    final chunks = _chunks(jsonEncode(await _ctx.bundle(wantsHistory: h.wantsHistory)));
    final grant = <String, Object?>{
      'v': 1,
      'type': 'grant',
      'userId': me.id,
      'username': me.username,
      'identity': identity.toJson(),
      'deviceId': h.deviceId,
      'cert': cert,
      'listVersion': published.version,
      'listHash': published.hash,
      'metaKey': b64(metaKey),
      'chunks': chunks.length,
    };
    // A QR link hands the account key over, sealed, after both screens showed the same digits (M6 §2).
    final account = _ctx.account;
    if (!viaCode && account != null) {
      grant['accountKey'] = await account.exportAccountKey(me.id);
      grant['backupKeys'] = (await _ctx.backupKeys?.call())?.toJson();
    }
    await _ctx.api.linkSend(linkId, await _ctx.link.seal(linkId, jsonEncode(grant)));
    for (var i = 0; i < chunks.length; i++) {
      await _ctx.api.linkSend(linkId, await _ctx.link.seal(linkId, jsonEncode({'v': 1, 'type': 'bundle', 'i': i, 'of': chunks.length, 'data': b64(utf8.encode(chunks[i]))})));
    }
    await _ctx.api.linkGrant(linkId);
    _done = true;
    await _ctx.link.end(linkId);
  }

  /// Codes didn't match, or the user changed their mind: nothing was signed.
  Future<void> cancel() async {
    await _ctx.link.end(linkId);
    try {
      await _ctx.api.linkCancel(linkId);
    } catch (_) {}
  }

  static List<String> _chunks(String bundle) {
    final out = <String>[];
    for (var i = 0; i < bundle.length; i += bundleSlice) {
      out.add(bundle.substring(i, math.min(i + bundleSlice, bundle.length)));
    }
    if (out.length > bundleChunks) throw const StoreException('There is too much to send to the new device at once.');
    return out;
  }
}

/// What a new device learned from a checked grant (§1.6): its session, the account, and what to install.
class LinkedSetup {
  const LinkedSetup({required this.user, required this.token, required this.identity, required this.pin, required this.metaKey, required this.bundle, this.full = false, this.backupKeys});

  /// The grant carried the account key and this device now holds it (QR links, M6 §2).
  final bool full;

  /// The backup keys the grant carried, to keep.
  final BackupKeys? backupKeys;
  final User user;
  final String token;

  /// The account's public identity, from the QR-authenticated primary (never from the server).
  final Identity identity;

  /// Our own account's list as it verified under [identity]: the pin to keep.
  final DevicePin pin;

  /// The device-label key (§1.4 `metaKey`).
  final String metaKey;

  /// The bundle (§2): pins, channel names, conversations and their history.
  final Map<String, Object?> bundle;
}

/// This device joins an account as a linked device (docs/m5-linking.md §1, §1.6, §1.7): it shows a QR (or an
/// 8-character code for one account), both screens show the same 6 digits, the primary signs it in, and it
/// checks the grant before trusting any of it. Its core must be fresh (no identity of its own).
class NewDeviceLink {
  NewDeviceLink._(this._api, this._link, this._groups, this._device, this._wait, this._account, {required this.linkId, required this.claim, required this.platform, required this.label, this.qr, this.shortCode});

  final AccountCrypto? _account;

  final Api _api;
  final LinkCrypto _link;
  final GroupCrypto _groups;
  final LocalDevice _device;
  final Future<void> Function(Duration) _wait;
  final String linkId;
  final String claim;
  final String platform;
  final String label;

  /// What to show: the QR text, or (code mode) the 8-character code to type on the primary.
  final String? qr;
  final String? shortCode;

  /// "123 456", once the primary offered its key.
  String? code;
  String? _leaf;

  String get deviceId => _device.deviceId;

  static Future<NewDeviceLink> start({
    required Api api,
    required LinkCrypto link,
    required GroupCrypto groups,
    required LocalDevice device,
    required String platform,
    required String label,
    String? username,
    AccountCrypto? account,
    Future<void> Function(Duration)? wait,
  }) async {
    final started = await api.linkStart(
      purpose: 'link',
      mode: username == null ? 'qr' : 'code',
      username: username,
      deviceId: device.deviceId,
      deviceKey: device.publicKey,
      platform: platform,
      signature: device.sign(linkStartBytes(device.deviceId, platform, device.publicKey)),
    );
    final linkId = started['linkId'] as String, claim = started['claim'] as String;
    try {
      String? qr;
      if (username == null) {
        qr = await link.qr(linkId);
      } else {
        await api.linkCommit(linkId, await link.commit(linkId, device.deviceId), claim: claim);
      }
      return NewDeviceLink._(api, link, groups, device, wait ?? ((d) => Future<void>.delayed(d)), account,
          linkId: linkId, claim: claim, platform: platform, label: label, qr: qr, shortCode: username == null ? null : started['code'] as String?);
    } catch (_) {
      await link.end(linkId).catchError((_) {});
      unawaited(api.linkCancel(linkId, claim: claim).catchError((_) {}));
      rethrow;
    }
  }

  Future<Map<String, dynamic>> _until(bool Function(Map<String, dynamic> state) ok, Duration timeout) async {
    final end = DateTime.now().add(timeout);
    while (true) {
      final state = await _api.linkState(linkId, claim: claim);
      if (state['state'] == 'expired') throw const StoreException('The link expired. Start again on both devices.');
      if (ok(state)) return state;
      if (DateTime.now().isAfter(end)) throw const StoreException('The link expired. Start again on both devices.');
      await _wait(const Duration(milliseconds: 1500));
    }
  }

  /// Waits for the primary's key, derives the 6 digits, and introduces this device (sealed) so the primary can
  /// show its name next to them.
  Future<String> waitOffer({Duration timeout = const Duration(minutes: 10)}) async {
    final offered = await _until((s) => (s['state'] == 'offered' || s['state'] == 'granted') && s['eph'] is String, timeout);
    final eph = offered['eph'] as String;
    final String digits;
    if (shortCode == null) {
      digits = await _link.complete(linkId, eph);
    } else {
      final revealed = await _link.reveal(linkId, eph);
      await _api.linkReveal(linkId, eph: revealed.eph, nonce: revealed.nonce, claim: claim);
      digits = await _link.completeCode(linkId, ephP: eph, deviceP: offered['offerDeviceId'] as String);
    }
    code = digits;
    final leaf = _leaf = await _groups.deviceLeaf();
    final hello = {'v': 1, 'type': 'hello', 'deviceId': deviceId, 'platform': platform, 'label': label, 'leafSigKey': leaf, 'wantsHistory': true};
    await _api.linkSend(linkId, await _link.seal(linkId, jsonEncode(hello)), claim: claim);
    return digits;
  }

  /// After the user tapped Link on the primary: take the session, read the grant and the bundle, and check
  /// them (§1.6) before installing the account in the core and importing the pins.
  Future<LinkedSetup> waitGrant({Duration timeout = const Duration(minutes: 10)}) async {
    final leaf = _leaf ?? (throw StateError('waitOffer first'));
    await _until((s) => s['state'] == 'granted', timeout);
    final claimed = await _api.linkClaim(linkId, claim: claim, signature: _device.sign(linkClaimBytes(linkId, deviceId, claim)));
    _api.token = claimed.token;
    Map<String, dynamic>? grant;
    final chunks = <String>[];
    var after = 0;
    final end = DateTime.now().add(timeout);
    while (grant == null || chunks.length < (grant['chunks'] as int)) {
      for (final m in await _api.linkMessages(linkId, after: after, claim: claim)) {
        after = m.seq;
        final value = jsonDecode(await _link.open(linkId, m.data));
        if (value is! Map || value['v'] != 1) throw const StoreException('The other device sent something unexpected.');
        if (grant == null) {
          if (value['type'] != 'grant' || value['chunks'] is! int || (value['chunks'] as int) > bundleChunks) throw const StoreException('The other device sent something unexpected.');
          grant = value.cast<String, dynamic>();
        } else if (value['type'] == 'bundle' && value['i'] == chunks.length && value['of'] == grant['chunks'] && value['data'] is String) {
          chunks.add(utf8.decode(unb64(value['data'] as String)));
        } else {
          throw const StoreException('The other device sent something unexpected.');
        }
      }
      if (grant != null && chunks.length >= (grant['chunks'] as int)) break;
      if (DateTime.now().isAfter(end)) throw const StoreException('The link expired. Start again on both devices.');
      await _wait(const Duration(milliseconds: 1000));
    }
    Map<String, Object?> bundle = const {};
    try {
      if (chunks.isNotEmpty) bundle = (jsonDecode(chunks.join()) as Map).cast<String, Object?>();
    } catch (_) {
      throw const StoreException('The other device sent something unexpected.');
    }
    const wrong = StoreException("This doesn't look like your account. Nothing was set up.");
    final user = claimed.user, me = await _api.me();
    final identityJson = grant['identity'];
    if (grant['deviceId'] != deviceId || grant['userId'] != user.id || grant['username'] != user.username || me.id != user.id || me.username != user.username) throw wrong;
    if (identityJson is! Map || grant['cert'] is! String || grant['metaKey'] is! String) throw wrong;
    final identity = Identity.fromJson(identityJson.cast<String, dynamic>());
    // The list the server serves must be the one the grant names, signed by the account key the primary showed.
    final view = await _api.devices(user.username);
    final check = verifyView(userId: user.id, aikSign: identity.sign, list: view['list'], signature: view['signature'], certs: view['certs']);
    final pin = check.pin;
    if (pin == null || check.version != grant['listVersion'] || check.hash != grant['listHash'] || !pin.devices.contains(deviceId)) throw wrong;
    // The certificate must name this device and its leaf key and verify under that account key (the core checks).
    final cert = await _link.companionSetup(userId: user.id, identity: identity, certJson: grant['cert'] as String);
    if (cert.deviceId != deviceId || cert.leafSigKey != leaf || cert.userId != user.id) throw wrong;
    final pins = <PinExport>[];
    for (final p in (bundle['pins'] as List? ?? const [])) {
      try {
        pins.add(PinExport.fromJson(p));
      } on FormatException {
        // A malformed pin is skipped; that contact goes through the usual first-contact check.
      }
    }
    if (pins.isNotEmpty) await _link.importPins(pins).catchError((_) => 0);
    // A QR grant carries the account key (M6 §2): this device becomes full, checked against the identity it pinned.
    BackupKeys? backupKeys;
    final accountKey = grant['accountKey'];
    if (accountKey is String && shortCode == null) {
      final account = _account ?? (throw wrong);
      if (await account.importAccountKey(user.id, accountKey) != identity) throw wrong;
      backupKeys = BackupKeys.fromJson(grant['backupKeys']);
    }
    await _link.end(linkId).catchError((_) {});
    return LinkedSetup(user: user, token: claimed.token, identity: identity, pin: pin, metaKey: grant['metaKey'] as String, bundle: bundle, full: accountKey is String && shortCode == null, backupKeys: backupKeys);
  }

  /// The user left the link screen before it finished: nothing was installed.
  Future<void> cancel() async {
    await _link.end(linkId).catchError((_) {});
    try {
      await _api.linkCancel(linkId, claim: claim);
    } catch (_) {}
  }
}

/// A checked link bundle on the new device (m5 §2, §3): history as received, and channel names for when this
/// device joins those channels.
Future<void> installLinkBundle(Map<String, Object?> bundle, MessageStore store) async {
  final names = <String, ({String name, String topic})>{};
  for (final c in (bundle['channels'] as List? ?? const []).take(500)) {
    if (c is! Map || c['id'] is! String || !groupIdPattern.hasMatch(c['id'] as String)) continue;
    final name = c['name'] is String ? c['name'] as String : '', topic = c['topic'] is String ? c['topic'] as String : '';
    names[c['id'] as String] = (name: String.fromCharCodes(name.runes.take(64)), topic: String.fromCharCodes(topic.runes.take(256)));
  }
  await store.putBundleNames(names);
  final records = [
    for (final c in (bundle['conversations'] as List? ?? const []).take(bundleConversations))
      if (c is Map && c['history'] is List) ...(c['history'] as List).reversed.take(bundleMessages).toList().reversed,
  ];
  if (records.isNotEmpty) await store.importLinked(records);
}

/// What a device is called when it has no label of its own.
String platformLabel(String platform) =>
    const {'web': 'Web browser', 'ios': 'iPhone app', 'android': 'Android app', 'macos': 'Mac app', 'windows': 'Windows app', 'linux': 'Linux app'}[platform] ?? 'Device';

/// What a link needs from the rest of the app.
class LinkContext {
  LinkContext({
    required this.api,
    required this.crypto,
    required this.link,
    required this.messenger,
    required this.store,
    required this.contacts,
    this.account,
    this.backupKeys,
    int Function()? now,
    Future<void> Function(Duration)? wait,
  }) : now = now ?? (() => DateTime.now().millisecondsSinceEpoch),
       wait = wait ?? ((d) => Future<void>.delayed(d));

  final Api api;
  final ChatCrypto crypto;
  final LinkCrypto link;
  final Messenger messenger;
  final MessageStore store;
  final List<Contact> Function() contacts;

  /// The account key export and the backup keys held here, for a QR grant (M6 §2).
  final AccountCrypto? account;
  final Future<BackupKeys?> Function()? backupKeys;
  final int Function() now;
  final Future<void> Function(Duration) wait;

  Future<LocalDevice> device() => messenger.device();

  /// The bundle (§2): pins (never a changed, unreviewed one), channel names and topics, 1:1 conversations
  /// and, if asked, their newest history. Never a secret key, ratchet or epoch secret.
  Future<Map<String, Object?>> bundle({required bool wantsHistory}) async {
    final me = messenger.me;
    final pins = await link.exportPins();
    final channels = [
      for (final g in await store.groups())
        if (g.active) {'id': g.id, 'kind': g.kind.wire, 'name': g.name.isEmpty ? null : g.name, 'topic': g.topic.isEmpty ? null : g.topic},
    ];
    final conversations = <Map<String, Object?>>[];
    var budget = bundleChunks * bundleSlice - 64 * 1024; // room for pins and channels
    for (final contact in contacts().where((c) => c.state == ContactState.mutual && c.id != null).take(bundleConversations)) {
      final id = messenger.conversationWith(contact.id!);
      final entry = <String, Object?>{'id': id, 'peer': contact.id};
      if (wantsHistory) {
        final all = (await store.list(id)).where((m) => !m.system).toList();
        final recent = all.length > bundleMessages ? all.sublist(all.length - bundleMessages) : all;
        final records = [for (final m in recent) exportRecord(m, me.id)];
        final size = utf8.encode(jsonEncode(records)).length;
        if (records.isNotEmpty && size <= budget) {
          entry['history'] = records;
          budget -= size;
        }
      }
      conversations.add(entry);
    }
    return {'v': 1, 'pins': [for (final p in pins) p.toJson()], 'channels': channels, 'conversations': conversations, 'settings': const <String, Object?>{}};
  }
}

/// A stored message in the shape both clients' stores use (chat-store.js records).
Map<String, Object?> exportRecord(ChatMessage m, String me) => {
  'id': m.id,
  'conversationId': m.conversationId,
  'direction': m.direction.name,
  'text': m.text,
  'createdAt': m.createdAt,
  'status': m.status.name,
  'expiresAt': m.expiresAt,
  if (m.replyTo != null) 'replyTo': m.replyTo!.toJson(),
  if (m.attachment != null) 'attachment': m.attachment!.toJson(),
  if (m.link != null) 'link': m.link!.toJson(),
  if (m.editedText != null) 'editedText': m.editedText,
  if (m.editedAt != null) 'editedAt': m.editedAt,
  if (!m.reactions.isEmpty) 'reactions': m.reactions.toJson(),
  if (m.sender != null) 'from': m.sender,
  if (m.senderName != null) 'fromName': m.senderName,
  if (m.mentions.isNotEmpty) 'mentions': m.mentions,
};
