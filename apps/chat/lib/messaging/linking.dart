import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import '../core/api.dart';
import '../core/devices.dart';
import '../crypto/chat_crypto.dart';
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
  PrimaryLink._(this._ctx, {required this.linkId, required this.deviceId, required this.platform, required this.code});

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
          return PrimaryLink._(ctx, linkId: linkId, deviceId: offered['deviceId'] as String, platform: offered['platform'] as String, code: code);
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
    final entry = <String, Object?>{'deviceId': h.deviceId, 'addedAt': now, 'meta': sealMeta(metaKey, me.id, h.deviceId, label: h.label.isEmpty ? _platformLabel(h.platform) : h.label, platform: h.platform)};
    final published = await _ctx.messenger.publishNextList(add: entry);
    final cert = await _ctx.link.signDeviceCert(userId: me.id, deviceId: h.deviceId, platform: h.platform, leafSigKey: h.leafSigKey, issuedAt: now);
    final identity = await _ctx.crypto.identity();
    final chunks = _chunks(jsonEncode(await _ctx.bundle(wantsHistory: h.wantsHistory)));
    final grant = {
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

String _platformLabel(String platform) =>
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
