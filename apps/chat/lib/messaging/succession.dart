import 'dart:async';
import 'dart:convert';

import '../core/api.dart';
import '../core/devices.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/group_crypto.dart';
import '../crypto/link_crypto.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import 'group_sync.dart';
import 'linking.dart';
import 'messenger.dart';

/// Primary transfer (docs/m5-linking.md §5): the account key never moves. The device taking over mints a new one,
/// the old primary signs a succession record over to it, and contacts and groups follow the signed chain.

const _unexpected = StoreException('The other device sent something unexpected. Nothing changed.');

/// Reads one link's sealed messages from the other side, in order.
class _Inbox {
  _Inbox(this.api, this.link, this.linkId, {this.claim, required this.wait});
  final Api api;
  final LinkCrypto link;
  final String linkId;
  final String? claim;
  final Future<void> Function(Duration) wait;
  int _after = 0;
  final List<Map<String, dynamic>> _queue = [];

  /// The next message, which must have exactly [keys] and this `type`.
  Future<Map<String, dynamic>> next(String type, Set<String> keys, {Duration timeout = const Duration(minutes: 10)}) async {
    final end = DateTime.now().add(timeout);
    while (_queue.isEmpty) {
      for (final m in await api.linkMessages(linkId, after: _after, claim: claim)) {
        _after = m.seq;
        final value = jsonDecode(await link.open(linkId, m.data));
        if (value is! Map) throw _unexpected;
        _queue.add(value.cast<String, dynamic>());
      }
      if (_queue.isNotEmpty) break;
      if (DateTime.now().isAfter(end)) throw const StoreException('The other device did not answer. Start again on both devices.');
      await wait(const Duration(milliseconds: 1000));
    }
    final value = _queue.removeAt(0);
    if (value['v'] != 1 || value['type'] != type || value.length != keys.length || !keys.every(value.containsKey)) throw _unexpected;
    return value;
  }
}

final _key = RegExp(r'^[A-Za-z0-9_-]{43}$');

/// This device is the primary and hands the account over to another device of it (m5 §5.2, P0). Nothing is
/// signed before the user compares the codes and confirms; this device deletes its account key only once the
/// server serves the new one and the new primary sent `demote` (its certificate under the new key).
class HandOver {
  HandOver._(this._ctx, this._groups, this._inbox, {required this.linkId, required this.deviceId, required this.platform, required this.code});

  final LinkContext _ctx;
  final GroupCrypto _groups;
  final _Inbox _inbox;
  final String linkId;

  /// The device taking over, as the server registered it.
  final String deviceId;
  final String platform;
  final String code;
  ({Identity identity, String leafSigKey})? request;

  static Future<HandOver> fromQr(LinkContext ctx, GroupCrypto groups, String qr) async {
    final accepted = await ctx.link.accept(qr.replaceAll(RegExp(r'\s'), ''));
    try {
      final offered = await ctx.api.linkOffer(accepted.linkId, accepted.eph);
      if (offered['purpose'] != 'transfer') throw const StoreException('That code is for linking a new device. Use "Link a device" instead.');
      return HandOver._(ctx, groups, _Inbox(ctx.api, ctx.link, accepted.linkId, wait: ctx.wait),
          linkId: accepted.linkId, deviceId: offered['deviceId'] as String, platform: offered['platform'] as String, code: accepted.code);
    } catch (_) {
      await ctx.link.end(accepted.linkId);
      unawaited(ctx.api.linkCancel(accepted.linkId).catchError((_) {}));
      rethrow;
    }
  }

  /// The other device's new account key and its leaf key (`succession-request`).
  Future<({Identity identity, String leafSigKey})> waitRequest({Duration timeout = const Duration(minutes: 5)}) async {
    final m = await _inbox.next('succession-request', const {'v', 'type', 'newSign', 'newDh', 'leafSigKey'}, timeout: timeout);
    if (![m['newSign'], m['newDh'], m['leafSigKey']].every((k) => k is String && _key.hasMatch(k))) throw _unexpected;
    return request = (identity: Identity(dh: m['newDh'] as String, sign: m['newSign'] as String), leafSigKey: m['leafSigKey'] as String);
  }

  /// The user confirmed: sign the account over, wait for the new primary to take over, then step down to a linked
  /// device of the new key (keeping this device's key, leaf and groups).
  Future<void> approve({Duration timeout = const Duration(minutes: 5)}) async {
    final r = request ?? (throw StateError('No request yet'));
    final me = _ctx.messenger.me, own = await _ctx.crypto.identity();
    final signed = (jsonDecode(await _ctx.link.signSuccession(userId: me.id, publishedSign: own.sign, newIdentity: r.identity, at: _ctx.now())) as Map).cast<String, Object?>();
    final signature = signed.remove('signature')! as String;
    await _ctx.api.linkSend(linkId, await _ctx.link.seal(linkId, jsonEncode({'v': 1, 'type': 'succession', 'record': signed, 'signature': signature, 'leafSigKey': await _groups.deviceLeaf()})));
    final demote = await _inbox.next('demote', const {'v', 'type', 'identity', 'cert', 'metaKey'}, timeout: timeout);
    final identity = demote['identity'];
    if (identity is! Map || identity['sign'] != r.identity.sign || identity['dh'] != r.identity.dh || demote['cert'] is! String) throw const StoreException('The new primary sent something unexpected.');
    final served = (await _ctx.api.keyCount()).identity;
    if (served?['sign'] != r.identity.sign || served?['dh'] != r.identity.dh) throw const StoreException("The new primary hasn't taken over yet. Nothing changed here.");
    await _ctx.link.retireIdentity(userId: me.id, newIdentity: r.identity, at: signed['at']! as int);
    await _ctx.link.companionSetup(userId: me.id, identity: r.identity, certJson: demote['cert']! as String);
    await _ctx.link.end(linkId);
  }

  Future<void> cancel() async {
    await _ctx.link.end(linkId);
    try {
      await _ctx.api.linkCancel(linkId);
    } catch (_) {}
  }
}

/// This linked device takes over as the account's primary (m5 §5.2, N): it shows a code to the primary, mints
/// a new account key, and only after the primary signed the account over publishes the record, its keys and
/// the first list under the new key, then certifies the old primary's leaf (`demote`).
class TakeOver {
  TakeOver._(this._api, this._link, this._groups, this._inbox, {required this.linkId, required this.claim, required this.qr});

  final Api _api;
  final LinkCrypto _link;
  final GroupCrypto _groups;
  final _Inbox _inbox;
  final String linkId;
  final String claim;
  final String qr;
  String? code;
  Identity? _minted;
  String? _primary;

  static Future<TakeOver> start({required Api api, required LinkCrypto link, required GroupCrypto groups, required LocalDevice device, required String platform, Future<void> Function(Duration)? wait}) async {
    final started = await api.linkStart(
      purpose: 'transfer',
      deviceId: device.deviceId,
      deviceKey: device.publicKey,
      platform: platform,
      signature: device.sign(linkStartBytes(device.deviceId, platform, device.publicKey)),
    );
    final linkId = started['linkId'] as String, claim = started['claim'] as String;
    try {
      final qr = await link.qr(linkId);
      return TakeOver._(api, link, groups, _Inbox(api, link, linkId, claim: claim, wait: wait ?? ((d) => Future<void>.delayed(d))), linkId: linkId, claim: claim, qr: qr);
    } catch (_) {
      await link.end(linkId).catchError((_) {});
      unawaited(api.linkCancel(linkId, claim: claim).catchError((_) {}));
      rethrow;
    }
  }

  /// Waits for the primary's offer, derives the code, mints the new account key and asks for the account.
  Future<String> waitOffer({Duration timeout = const Duration(minutes: 10)}) async {
    final end = DateTime.now().add(timeout);
    Map<String, dynamic> state;
    while (true) {
      state = await _api.linkState(linkId, claim: claim);
      if (state['state'] == 'offered' && state['eph'] is String) break;
      if (state['state'] == 'expired' || DateTime.now().isAfter(end)) throw const StoreException('The link expired. Start again on both devices.');
      await _inbox.wait(const Duration(milliseconds: 1500));
    }
    final digits = await _link.complete(linkId, state['eph'] as String);
    code = digits;
    _primary = state['offerDeviceId'] as String?;
    final minted = _minted = await _link.successionStart();
    await _api.linkSend(linkId, await _link.seal(linkId, jsonEncode({'v': 1, 'type': 'succession-request', 'newSign': minted.sign, 'newDh': minted.dh, 'leafSigKey': await _groups.deviceLeaf()})), claim: claim);
    return digits;
  }

  /// After the primary confirmed: check the record, publish it, hold the new key, publish keys and list v1, then
  /// certify the old primary's leaf under the new key and tell it to step down.
  Future<void> run(Messenger messenger, {required String platform, Duration timeout = const Duration(minutes: 10)}) async {
    final minted = _minted ?? (throw StateError('waitOffer first'));
    final m = await _inbox.next('succession', const {'v', 'type', 'record', 'signature', 'leafSigKey'}, timeout: timeout);
    final record = m['record'], signature = m['signature'], primaryLeaf = m['leafSigKey'];
    final me = messenger.me, account = await _link.account();
    if (record is! Map || signature is! String || primaryLeaf is! String || !_key.hasMatch(primaryLeaf) || account == null) throw _unexpected;
    final r = record.cast<String, dynamic>();
    if (r['newSign'] != minted.sign || r['newDh'] != minted.dh || !verifySuccessionChain(me.id, account.identity.sign, minted.sign, [{...r, 'signature': signature}])) {
      throw const StoreException('Your primary device sent something unexpected. Nothing changed.');
    }
    final view = await _api.devices(me.username);
    final rows = (view['devices'] as List? ?? const []).cast<Map>();
    final primary = rows.where((row) => row['id'] == _primary && row['state'] == 'listed').firstOrNull;
    if (primary == null) throw const StoreException("Your primary device isn't in your device list. Nothing changed.");
    await _api.publishSuccession(r, signature);
    await _link.successionComplete(jsonEncode(r), signature);
    // From here this device holds the account key: 1:1 messaging, the device list, certificates.
    messenger.companion = false;
    await messenger.takeOver();
    final self = (await messenger.device()).deviceId;
    final metaKey = deviceMetaKey(await messenger.crypto.deviceMetaSignature(me.id));
    final keep = <Map<String, Object?>>[
      for (final d in ((view['list'] as Map?)?['devices'] as List? ?? const []).cast<Map>())
        if (d['deviceId'] != self && rows.any((row) => row['id'] == d['deviceId'] && row['state'] == 'listed'))
          () {
            final platformOf = rows.firstWhere((row) => row['id'] == d['deviceId'])['platform'] as String? ?? 'web';
            return {'deviceId': d['deviceId'], 'addedAt': d['addedAt'], 'meta': sealMeta(metaKey, me.id, d['deviceId'] as String, label: platformLabel(platformOf), platform: platformOf)};
          }(),
    ];
    await messenger.publishNewChain(keep);
    final now = DateTime.now().millisecondsSinceEpoch;
    await _groups.recertify(platform: platform, issuedAt: now);
    final cert = await _link.signDeviceCert(userId: me.id, deviceId: primary['id'] as String, platform: primary['platform'] as String, leafSigKey: primaryLeaf, issuedAt: now);
    await _api.linkSend(linkId, await _link.seal(linkId, jsonEncode({'v': 1, 'type': 'demote', 'identity': minted.toJson(), 'cert': cert, 'metaKey': b64(metaKey)})), claim: claim);
    await _link.end(linkId);
  }

  Future<void> cancel() async {
    await _link.end(linkId).catchError((_) {});
    try {
      await _api.linkCancel(linkId, claim: claim);
    } catch (_) {}
  }
}

/// After a transfer (m5 §5.2 step 6, §5.2.2): a linked device follows its account to the new key along the
/// signed chain and asks for its leaf to be certified under it; the new primary certifies only (device, leaf)
/// pairs its own groups already hold.
class OwnSuccession {
  OwnSuccession({required this.api, required this.link, required this.groups, required this.store, required this.updateLeaf, required this.me, required this.platform, int Function()? now})
    : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final Api api;
  final LinkCrypto link;
  final GroupCrypto groups;
  final MessageStore store;

  /// Commits this device's leaf again in one group ([GroupSync.updateLeaf]).
  final Future<void> Function(String groupId) updateLeaf;
  final User me;
  final String platform;
  final int Function() _now;

  /// Linked device: the served account key moved on from our pin. Follows a valid chain (never the server's word
  /// alone) and asks for a certificate under the new key. Returns whether it moved; throws when the key changed
  /// without a valid chain.
  Future<bool> follow() async {
    final account = await link.account();
    if (account == null) return false;
    final view = await api.devices(me.username);
    final served = view['identity'];
    if (served is! Map || (served['sign'] == account.identity.sign && served['dh'] == account.identity.dh)) return false;
    final all = [for (final r in (view['succession'] as List? ?? const [])) (r as Map).cast<String, dynamic>()];
    final from = all.indexWhere((r) => r['oldSign'] == account.identity.sign);
    final path = from < 0 ? const <Map<String, dynamic>>[] : all.sublist(from);
    if (path.isEmpty || path.last['newDh'] != served['dh'] || !verifySuccessionChain(me.id, account.identity.sign, served['sign'] as String, path)) {
      throw const StoreException('Your account key changed without a record from your previous primary. Link this device again.');
    }
    for (final r in path) {
      final record = Map<String, Object?>.of(r)..remove('signature');
      await link.adoptSuccession(userId: me.id, record: record, signature: r['signature'] as String);
    }
    await api.askRecert(platform: platform, leafSigKey: await groups.deviceLeaf());
    return true;
  }

  /// Linked device: installs the new primary's answer, if there is one yet, and commits the new leaf in every
  /// group so it stops being Previous.
  Future<bool> takeRecert() async {
    final account = await link.account();
    if (account == null) return false;
    String? cert;
    try {
      cert = await api.myRecert();
    } on ApiException catch (error) {
      if (error.status == 404) return false; // Never asked (or already done).
      rethrow;
    }
    if (cert == null) return false;
    await link.companionSetup(userId: me.id, identity: account.identity, certJson: cert);
    for (final g in await store.groups()) {
      if (g.active) await updateLeaf(g.id).catchError((_) {});
    }
    await api.dropRecert();
    return true;
  }

  /// New primary: certifies each waiting linked device whose (device, leaf key) a group here already holds.
  /// Returns how many.
  Future<int> answerRecerts() async {
    final requests = await api.recertRequests();
    if (requests.isEmpty) return 0;
    final channels = [for (final g in await store.groups()) if (g.active) g.id];
    var answered = 0;
    for (final r in requests) {
      final deviceId = r['deviceId'] as String, leaf = r['leafSigKey'] as String, platform = r['platform'] as String;
      if (!await groups.leafKnown(deviceId, leaf, channels).catchError((_) => false)) continue; // Asked again later.
      final cert = await link.signDeviceCert(userId: me.id, deviceId: deviceId, platform: platform, leafSigKey: leaf, issuedAt: _now());
      await api.answerRecert(deviceId, cert);
      answered++;
    }
    return answered;
  }
}
