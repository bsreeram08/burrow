import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../core/api.dart';
import '../core/devices.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/group_crypto.dart';
import '../crypto/account_crypto.dart';
import '../crypto/link_crypto.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import 'backup.dart';
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

/// Our own account's list as served, verified under [aikSign] and moving forward from our [pin]: each device with
/// its `addedAt` and, when [metaKey] opens it, its sealed label (`{label, platform}`). Null when it doesn't verify.
/// Only these devices are ever carried into a new key's list or certified (never the server's raw device rows).
List<({String deviceId, int addedAt, Map<String, String>? described})>? verifiedOwnList(
  Map<String, dynamic> view, {
  required String userId,
  required String aikSign,
  DevicePin? pin,
  Uint8List? metaKey,
}) {
  final check = verifyView(userId: userId, aikSign: aikSign, list: view['list'], signature: view['signature'], certs: view['certs'], pin: pin);
  if (!check.ok) return null;
  return [
    for (final d in ((view['list']! as Map)['devices']! as List).cast<Map>())
      (
        deviceId: d['deviceId'] as String,
        addedAt: d['addedAt'] as int,
        described: metaKey == null ? null : openMeta(metaKey, userId, d['deviceId'] as String, d['meta'] as String? ?? ''),
      ),
  ];
}

/// This device is the primary and hands the account over to another device of it (m5 §5.2, P0). Nothing is
/// signed before the user compares the codes and confirms; this device deletes its account key only once the
/// server serves the new one and the new primary sent `demote` (its certificate under the new key).
class HandOver {
  HandOver._(this._ctx, this._groups, this._inbox, this._hold, {required this.linkId, required this.deviceId, required this.platform, required this.code});

  final LinkContext _ctx;
  final GroupCrypto _groups;
  final _Inbox _inbox;

  /// Stops (true) or resumes (false) group processing here: from sending `succession` until this device has
  /// stepped down, the new primary's recertify commits are under a key this core doesn't pin yet, and would be
  /// rejected as poison.
  final Future<void> Function(bool held)? _hold;
  final String linkId;

  /// The device taking over, as the server registered it.
  final String deviceId;
  final String platform;
  final String code;
  ({Identity identity, String leafSigKey})? request;

  static Future<HandOver> fromQr(LinkContext ctx, GroupCrypto groups, String qr, {Future<void> Function(bool held)? hold}) async {
    final accepted = await ctx.link.accept(qr.replaceAll(RegExp(r'\s'), ''));
    try {
      final offered = await ctx.api.linkOffer(accepted.linkId, accepted.eph);
      if (offered['purpose'] != 'transfer') throw const StoreException('That code is for linking a new device. Use "Link a device" instead.');
      return HandOver._(ctx, groups, _Inbox(ctx.api, ctx.link, accepted.linkId, wait: ctx.wait), hold,
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
  /// device of the new key (keeping this device's key, leaf and groups). Returns the new device-label key.
  Future<String> approve({Duration timeout = const Duration(minutes: 5)}) async {
    final r = request ?? (throw StateError('No request yet'));
    final me = _ctx.messenger.me, own = await _ctx.crypto.identity();
    final signed = (jsonDecode(await _ctx.link.signSuccession(userId: me.id, publishedSign: own.sign, newIdentity: r.identity, at: _ctx.now())) as Map).cast<String, Object?>();
    final signature = signed.remove('signature')! as String;
    await _hold?.call(true);
    try {
      return await _stepDown(r, signed, signature, timeout);
    } catch (_) {
      await _hold?.call(false); // Still the primary: carry on with the groups.
      rethrow;
    }
  }

  Future<String> _stepDown(({Identity identity, String leafSigKey}) r, Map<String, Object?> signed, String signature, Duration timeout) async {
    final me = _ctx.messenger.me;
    await _ctx.api.linkSend(linkId, await _ctx.link.seal(linkId, jsonEncode({'v': 1, 'type': 'succession', 'record': signed, 'signature': signature, 'leafSigKey': await _groups.deviceLeaf()})));
    final demote = await _inbox.next('demote', const {'v', 'type', 'identity', 'cert', 'metaKey'}, timeout: timeout);
    final identity = demote['identity'];
    if (identity is! Map || identity['sign'] != r.identity.sign || identity['dh'] != r.identity.dh || demote['cert'] is! String || demote['metaKey'] is! String || !_key.hasMatch(demote['metaKey'] as String)) throw const StoreException('The new primary sent something unexpected.');
    final served = (await _ctx.api.keyCount()).identity;
    if (served?['sign'] != r.identity.sign || served?['dh'] != r.identity.dh) throw const StoreException("The new primary hasn't taken over yet. Nothing changed here.");
    await _ctx.link.retireIdentity(userId: me.id, newIdentity: r.identity, at: signed['at']! as int);
    await _ctx.link.companionSetup(userId: me.id, identity: r.identity, certJson: demote['cert']! as String);
    await _ctx.link.end(linkId);
    return demote['metaKey']! as String;
  }

  Future<void> cancel() async {
    await _ctx.link.end(linkId);
    try {
      await _ctx.api.linkCancel(linkId);
    } catch (_) {}
  }
}

/// Where a confirmed take-over stands (JSON), persisted per account so it survives a crash.
typedef TakeOverMarkers = ({Future<String?> Function() read, Future<void> Function(String? value) write});

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
  /// [oldMetaKey]: the account's device-label key from the link grant, to carry labels over (else platform names).
  Future<void> run(Messenger messenger, {required String platform, required TakeOverMarkers markers, Uint8List? oldMetaKey, Duration timeout = const Duration(minutes: 10)}) async {
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
    // Only devices our own signed list names (verified under the account key we pinned, from our pin) carry over.
    final owned = verifiedOwnList(view, userId: me.id, aikSign: account.identity.sign, pin: messenger.devices.pin(me.id, me.id), metaKey: oldMetaKey);
    if (owned == null) throw const StoreException("The device list on the server isn't one your primary signed. Nothing changed.");
    bool listed(String id) => rows.any((row) => row['id'] == id && row['state'] == 'listed');
    final p0 = owned.where((d) => d.deviceId == _primary && listed(d.deviceId)).firstOrNull;
    if (p0 == null) throw const StoreException("Your primary device isn't in your device list. Nothing changed.");
    String platformOf(({String deviceId, int addedAt, Map<String, String>? described}) d) =>
        d.described?['platform'] ?? rows.firstWhere((row) => row['id'] == d.deviceId)['platform'] as String? ?? 'web';
    final self = (await messenger.device()).deviceId;
    // The point of no return is the record's publication: from here every step is persisted and resumable.
    final marker = <String, Object?>{
      'v': 1,
      'userId': me.id,
      'newSign': minted.sign,
      'newDh': minted.dh,
      'record': r,
      'signature': signature,
      'linkId': linkId,
      'claim': claim,
      'primary': {'deviceId': p0.deviceId, 'platform': platformOf(p0), 'leafSigKey': primaryLeaf},
      'keep': [
        for (final d in owned)
          if (d.deviceId != self && listed(d.deviceId)) {'deviceId': d.deviceId, 'addedAt': d.addedAt, 'label': d.described?['label'] ?? platformLabel(platformOf(d)), 'platform': platformOf(d), 'via': ?d.described?['via']},
      ],
      'step': 'publish',
    };
    await markers.write(jsonEncode(marker));
    await finish(marker, api: _api, link: _link, groups: _groups, messenger: messenger, platform: platform, markers: markers);
  }

  /// A take-over cut short after it was confirmed (a crash, a lost connection): resumes it if the persisted marker
  /// is for this account and its key, else drops it. Returns whether one was finished.
  static Future<bool> resume({required Api api, required LinkCrypto link, required GroupCrypto groups, required Messenger messenger, required String platform, required TakeOverMarkers markers}) async {
    final raw = await markers.read();
    if (raw == null) return false;
    Map<String, dynamic> marker;
    try {
      marker = (jsonDecode(raw) as Map).cast<String, dynamic>();
    } catch (_) {
      await markers.write(null);
      return false;
    }
    if (marker['v'] != 1 || marker['userId'] != messenger.me.id || marker['newSign'] is! String) {
      await markers.write(null);
      return false;
    }
    await finish(marker, api: api, link: link, groups: groups, messenger: messenger, platform: platform, markers: markers);
    return true;
  }

  /// The remaining steps, each skipped when already done, so a resume repeats nothing: the record, the key held
  /// here, the keys served, list v1 under the new key (only while no pin exists for it), our leaf re-signed, then
  /// the old primary's certificate (`demote`). Clears the marker at the end.
  static Future<void> finish(
    Map<String, Object?> start, {
    required Api api,
    required LinkCrypto link,
    required GroupCrypto groups,
    required Messenger messenger,
    required String platform,
    required TakeOverMarkers markers,
  }) async {
    var marker = start;
    final me = messenger.me, newSign = marker['newSign']! as String;
    final record = (marker['record']! as Map).cast<String, dynamic>(), signature = marker['signature']! as String;
    final view = await api.devices(me.username);
    if (!(view['succession'] as List? ?? const []).any((x) => x is Map && x['newSign'] == newSign)) {
      try {
        await api.publishSuccession(record, signature);
      } on ApiException catch (error) {
        // Refused (not a lost connection): nothing moved, so there is nothing to resume.
        if (error.status >= 400 && error.status < 500) await markers.write(null);
        rethrow;
      }
    }
    if (await link.account() != null) await link.successionComplete(jsonEncode(record), signature);
    // The marker is bound to the key this core now holds; another key means it isn't ours to finish.
    if ((await messenger.crypto.identity()).sign != newSign) {
      await markers.write(null);
      throw const StoreException('This device holds another account key than the take-over it was finishing. Nothing more was changed.');
    }
    // From here this device holds the account key: 1:1 messaging, the device list, certificates.
    messenger.companion = false;
    if ((await api.keyCount()).identity?['sign'] != newSign) {
      await messenger.takeOver();
    } else {
      messenger.markActive();
    }
    // List v1 is honoured only while no pin exists for the new key (and not already published by this marker).
    if (marker['step'] == 'publish' && messenger.devices.pin(me.id, me.id)?.aik != newSign) {
      final served = await api.devices(me.username);
      final check = verifyView(userId: me.id, aikSign: newSign, list: served['list'], signature: served['signature'], certs: served['certs']);
      if (check.ok) {
        messenger.devices.setPin(me.id, me.id, check.pin!); // Published before the cut: pin it.
      } else {
        final metaKey = deviceMetaKey(await messenger.crypto.deviceMetaSignature(me.id));
        await messenger.publishNewChain([
          for (final d in (marker['keep'] as List? ?? const []).cast<Map>())
            // A code-linked device stays marked under the new key: it unlocks with the passphrase, never by rekey (§5).
            {'deviceId': d['deviceId'], 'addedAt': d['addedAt'], 'meta': sealMeta(metaKey, me.id, d['deviceId'] as String, label: d['label'] as String, platform: d['platform'] as String, via: d['via'] as String?)},
        ]);
      }
    }
    if (marker['step'] == 'publish') {
      marker = {...marker, 'step': 'listed'};
      await markers.write(jsonEncode(marker));
    }
    if (marker['step'] != 'demoted') {
      final now = DateTime.now().millisecondsSinceEpoch;
      if (marker['step'] != 'recertified') {
        await groups.recertify(platform: platform, issuedAt: now);
        marker = {...marker, 'step': 'recertified'};
        await markers.write(jsonEncode(marker));
      }
      final linkId = marker['linkId']! as String;
      // Sealed once and kept: a resend after a lost connection is the same message (the link's counters move on
      // every seal, so sealing again would leave a gap the old primary refuses).
      var sealed = marker['demote'] as String?;
      if (sealed == null) {
        final p0 = (marker['primary']! as Map).cast<String, dynamic>();
        final cert = await link.signDeviceCert(userId: me.id, deviceId: p0['deviceId'] as String, platform: p0['platform'] as String, leafSigKey: p0['leafSigKey'] as String, issuedAt: now);
        final metaKey = deviceMetaKey(await messenger.crypto.deviceMetaSignature(me.id));
        final demote = {'v': 1, 'type': 'demote', 'identity': {'dh': marker['newDh'], 'sign': newSign}, 'cert': cert, 'metaKey': b64(metaKey)};
        sealed = await link.seal(linkId, jsonEncode(demote));
        marker = {...marker, 'demote': sealed};
        await markers.write(jsonEncode(marker));
      }
      try {
        await api.linkSend(linkId, sealed, claim: marker['claim'] as String?);
      } on ApiException catch (error) {
        // The link is gone (expired while this device was away): the old primary sees the served key and follows
        // the chain as a linked device; its leaf gets a certificate through the recert relay. A lost connection
        // (not an answer) is retried on the next start instead.
        if (error.status < 400 || error.status >= 500) rethrow;
      }
      await markers.write(jsonEncode({...marker, 'step': 'demoted'}));
      await link.end(linkId).catchError((_) {});
    }
    await markers.write(null);
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
  OwnSuccession({
    required this.api,
    required this.link,
    required this.groups,
    required this.store,
    required this.updateLeaf,
    required this.me,
    required this.platform,
    this.chat,
    this.devices,
    this.device,
    this.certKey,
    int Function()? now,
  })
    : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final Api api;
  final LinkCrypto link;
  final GroupCrypto groups;
  final MessageStore store;

  /// Commits this device's leaf again in one group ([GroupSync.updateLeaf]).
  final Future<void> Function(String groupId) updateLeaf;
  final User me;
  final String platform;

  /// The primary's account key, pins and own device: what a recert answer is checked against.
  final ChatCrypto? chat;
  final DevicePrefs? devices;
  final Future<LocalDevice> Function()? device;

  /// The account key this linked device's MLS certificate is under (persisted): it asks for a certificate again
  /// until that is the account's current key (a first request is refused while the new list isn't up yet).
  final ({Future<String?> Function() read, Future<void> Function(String sign) write})? certKey;
  final int Function() _now;

  /// Linked device: the served account key moved on from our pin. Follows a valid chain (never the server's word
  /// alone) and asks for a certificate under the new key. Returns whether it moved; throws when the key changed
  /// without a valid chain.
  Future<bool> follow() async {
    final account = await link.account();
    // A device with the key follows a rotation another device made (M6 §6.2 step 3); it pins its own key.
    final chat = this.chat;
    final pinned = account?.identity ?? (chat == null ? null : await chat.identity());
    if (pinned == null) return false;
    final view = await api.devices(me.username);
    final served = view['identity'];
    if (served is! Map || (served['sign'] == pinned.sign && served['dh'] == pinned.dh)) {
      // Already following the current key; a certificate still under an older one is asked for again.
      final under = await certKey?.read();
      if (account != null && under != null && under != pinned.sign) await api.askRecert(platform: platform, leafSigKey: await groups.deviceLeaf());
      return false;
    }
    final all = [for (final r in (view['succession'] as List? ?? const [])) (r as Map).cast<String, dynamic>()];
    final from = all.indexWhere((r) => r['oldSign'] == pinned.sign);
    final path = from < 0 ? const <Map<String, dynamic>>[] : all.sublist(from);
    if (path.isEmpty || path.last['newDh'] != served['dh'] || !verifySuccessionChain(me.id, pinned.sign, served['sign'] as String, path)) {
      throw const StoreException('Your account key changed without a record from your previous device. Link this device again.');
    }
    notice = null;
    if (account == null) {
      final adopt = await _checkAdoption(view, served['sign'] as String);
      if (!adopt) return false; // The new key's list isn't up yet: the next devices event tries again.
    }
    for (final r in path) {
      final record = Map<String, Object?>.of(r)..remove('signature');
      await link.adoptSuccession(userId: me.id, record: record, signature: r['signature'] as String);
    }
    await api.askRecert(platform: platform, leafSigKey: await groups.deviceLeaf());
    return true;
  }

  /// After a [follow] that adopted a key change which removed devices: the notice to show until dismissed.
  String? notice;

  /// §6.2 step 3: a device holding the key adopts another device's key change whenever the new key's list still names
  /// it. The server can't say whether a removal was the user's own (revoked rows aren't served), so the check is
  /// against this device's own last verified list: if the new list drops any device that named, it follows but sets
  /// [notice] (who changed the key, what it removed). A change that drops this device is refused, with the same words.
  /// Returns false while the new key's list isn't up yet.
  Future<bool> _checkAdoption(Map<String, dynamic> view, String newSign) async {
    final self = (await device?.call())?.deviceId, rows = (view['devices'] as List? ?? const []).cast<Map>();
    final check = verifyView(userId: me.id, aikSign: newSign, list: view['list'], signature: view['signature'], certs: view['certs']);
    final newIds = check.pin?.devices;
    if (!check.ok || newIds == null) return false;
    final pin = devices?.pin(me.id, me.id);
    final rotator = rows.where((r) => r['primary'] == true).firstOrNull;
    final from = platformLabel(rotator?['platform'] as String? ?? 'web');
    String name(String id) => pin?.labels[id] ?? 'a device';
    if (self == null || !newIds.contains(self)) throw RotationRefused(from, ['this device', for (final id in pin?.devices ?? const <String>[]) if (id != self && !newIds.contains(id)) name(id)]);
    final dropped = [for (final id in pin?.devices ?? const <String>[]) if (id != self && !newIds.contains(id)) name(id)];
    if (dropped.isNotEmpty) notice = RotationRefused(from, dropped).message;
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
    await certKey?.write(account.identity.sign);
    for (final g in await store.groups()) {
      if (g.active) await updateLeaf(g.id).catchError((_) {});
    }
    await api.dropRecert();
    return true;
  }

  /// New primary: certifies a waiting linked device only if our verified own list names it, it isn't this device,
  /// and a group here already holds exactly that leaf as a current one; the platform comes from the device's sealed
  /// label in our list, never from the request. Returns how many.
  Future<int> answerRecerts() async {
    final chat = this.chat, devices = this.devices, device = this.device;
    if (chat == null || devices == null || device == null) return 0;
    final requests = await api.recertRequests();
    if (requests.isEmpty) return 0;
    final own = await chat.identity(), self = (await device()).deviceId;
    final owned = verifiedOwnList(
      await api.devices(me.username),
      userId: me.id,
      aikSign: own.sign,
      pin: devices.pin(me.id, me.id),
      metaKey: deviceMetaKey(await chat.deviceMetaSignature(me.id)),
    );
    if (owned == null) return 0;
    final channels = [for (final g in await store.groups()) if (g.active) g.id];
    var answered = 0;
    for (final r in requests) {
      final deviceId = r['deviceId'] as String, leaf = r['leafSigKey'] as String;
      final platform = owned.where((d) => d.deviceId == deviceId && deviceId != self).firstOrNull?.described?['platform'];
      if (platform == null) continue;
      if (!await groups.leafKnown(deviceId, leaf, channels).catchError((_) => false)) continue; // Asked again later.
      final cert = await link.signDeviceCert(userId: me.id, deviceId: deviceId, platform: platform, leafSigKey: leaf, issuedAt: _now());
      await api.answerRecert(deviceId, cert);
      answered++;
    }
    return answered;
  }
}

/// A full device replaces the account key itself (docs/m6-account-key.md §6.2): every holder of the key can sign
/// anything, so removing a device that holds it means a new key. The M5 succession, run by this device on itself:
/// record (with the backup proof when there is a backup), the new key held, keys uploaded (the inbox moves here),
/// list v1 naming every live device of our verified list except [removed], our leaf re-signed, and the backup
/// re-sealed to the backup keys held here.
class AccountRotation {
  AccountRotation({required this.api, required this.account, required this.groups, required this.messenger, required this.platform, this.backup, int Function()? now})
    : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final Api api;
  final AccountCrypto account;
  final GroupCrypto groups;
  final Messenger messenger;
  final String platform;
  final AccountBackup? backup;
  final int Function() _now;

  /// [proven]: the proof (and the record it was checked against) when the caller already has it.
  Future<void> rotate({Set<String> removed = const {}, Unlock? unlock, ({String proof, Map<String, Object?> record})? proven}) async {
    final me = messenger.me;
    // Asked first: without the passphrase (when there is a backup) nothing changes.
    final checked = proven ?? await backup?.proveForRotation(unlock);
    final view = await api.devices(me.username);
    final live = await _live(view, removed);
    // The new key and the record signed by the old one, kept in the core; nothing changes until the server took it.
    final rotated = await account.prepareRotation(me.id, at: _now());
    try {
      await api.publishSuccession(rotated.record, rotated.signature, proof: checked?.proof);
    } on ApiException catch (error) {
      // Refused (a wrong proof, or another device rotated first): the prepared key goes; a lost connection keeps it
      // for [resume].
      if (error.status >= 400 && error.status < 500) await account.rotationDrop();
      rethrow;
    }
    await _complete(view, live, record: checked?.record);
  }

  /// On start: a rotation this core prepared before a crash. If the server took its record, it is finished (the key
  /// held, keys, list v1, our leaf, the re-seal, each only if still missing); otherwise it is dropped. Returns whether
  /// one was finished.
  Future<bool> resume() async {
    final pending = await account.rotationPending();
    if (pending == null) return false;
    final view = await api.devices(messenger.me.username);
    final served = view['identity'], rotation = view['rotation'];
    // The server's word on its newest record (our own view's `rotation`): finish only a key it publishes, or a record
    // of ours that still authorizes its key upload ('open'). Anything else never landed or was superseded.
    final accepted = (served is Map && served['sign'] == pending.identity.sign) ||
        (rotation is Map && rotation['newSign'] == pending.identity.sign && rotation['state'] == 'open');
    if (!accepted) {
      await account.rotationDrop();
      return false;
    }
    // List v1 may have gone out before the crash; otherwise the removed devices were revoked before the record went
    // out, so the live ones are the listed ones.
    final done = verifyView(userId: messenger.me.id, aikSign: pending.identity.sign, list: view['list'], signature: view['signature'], certs: view['certs']).ok;
    await _complete(view, done ? const [] : await _live(view, const {}));
    return true;
  }

  /// Our verified devices (under the key held now) that stay: listed on the server, not removed, not this one.
  Future<List<({String deviceId, int addedAt, Map<String, String>? described})>> _live(Map<String, dynamic> view, Set<String> removed) async {
    final me = messenger.me, own = await messenger.crypto.identity();
    final rows = (view['devices'] as List? ?? const []).cast<Map>();
    final owned = verifiedOwnList(view, userId: me.id, aikSign: own.sign, pin: messenger.devices.pin(me.id, me.id), metaKey: deviceMetaKey(await messenger.crypto.deviceMetaSignature(me.id)));
    if (owned == null) throw const StoreException("The device list on the server isn't one your account signed. Nothing changed.");
    final self = (await messenger.device()).deviceId;
    return [
      for (final d in owned)
        if (d.deviceId != self && !removed.contains(d.deviceId) && rows.any((r) => r['id'] == d.deviceId && r['state'] == 'listed')) d,
    ];
  }

  Future<void> _complete(Map<String, dynamic> view, List<({String deviceId, int addedAt, Map<String, String>? described})> live, {Map<String, Object?>? record}) async {
    final me = messenger.me;
    final rows = (view['devices'] as List? ?? const []).cast<Map>();
    final next = await account.commitRotation(me.id);
    await messenger.takeOver(); // Keys under the new key (the server takes them after the succession).
    final served = await api.devices(me.username);
    final listed = verifyView(userId: me.id, aikSign: next.sign, list: served['list'], signature: served['signature'], certs: served['certs']);
    if (!listed.ok) {
      final metaKey = deviceMetaKey(await messenger.crypto.deviceMetaSignature(me.id));
      await messenger.publishNewChain([
        for (final d in live)
          () {
            final platformOf = d.described?['platform'] ?? rows.where((r) => r['id'] == d.deviceId).firstOrNull?['platform'] as String? ?? 'web';
            // A code-linked device stays marked under the new key: it unlocks with the passphrase, never by rekey (§5).
            return <String, Object?>{
              'deviceId': d.deviceId,
              'addedAt': d.addedAt,
              'meta': sealMeta(metaKey, me.id, d.deviceId, label: d.described?['label'] ?? platformLabel(platformOf), platform: platformOf, via: d.described?['via']),
            };
          }(),
      ]);
    } else if (listed.pin case final pin?) {
      messenger.devices.setPin(me.id, me.id, pin); // List v1 went out before the crash: keep it.
    }
    await groups.recertify(platform: platform, issuedAt: _now());
    await backup?.resealAfterRotation(record);
  }
}

/// Rekey (docs/m6-account-key.md §5): a listed device without the account key (after following a rotation, or a
/// pre-M6 linked device) asks; a device with the key answers only for a device of its verified list that wasn't
/// linked by code, with the platform from that device's sealed label, and only if the core finds the request signed
/// by a leaf one of its groups holds. The server relays and proves nothing.
class Rekey {
  Rekey({required this.api, required this.account, required this.link, required this.store, required this.me, required this.platform, required this.device, required this.messenger, required this.updateLeaf, int Function()? now})
    : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final Api api;
  final AccountCrypto account;
  final LinkCrypto link;
  final MessageStore store;
  final User me;
  final String platform;
  final Future<LocalDevice> Function() device;
  final Messenger messenger;
  final Future<void> Function(String groupId) updateLeaf;
  final int Function() _now;

  /// Why requests were last left unanswered (device id → reason), for diagnostics.
  final Map<String, String> skipped = {};

  /// Without the key: ask (once per start; a new request replaces the old one on the server).
  Future<void> ask() async {
    if (await link.account() == null) return; // Already full.
    final id = (await device()).deviceId;
    final r = await account.rekeyRequest(me.id, id, platform);
    await api.askRekey(platform: platform, eph: r.eph, leafSigKey: r.leafSigKey, signature: r.signature);
  }

  /// Without the key: installs the answer if there is one. Returns whether this device is now full.
  Future<bool> take() async {
    if (await link.account() == null) return false;
    final mine = await api.myRekey();
    final box = mine.box;
    if (box == null) return false;
    await account.rekeyOpen(me.id, deviceId: (await device()).deviceId, platform: platform, box: box);
    for (final g in await store.groups()) {
      if (g.active) await updateLeaf(g.id).catchError((_) {});
    }
    await api.dropRekey();
    return true;
  }

  /// With the key: answers every waiting request that passes. Returns how many.
  Future<int> answer() async {
    final requests = await api.rekeyRequests();
    if (requests.isEmpty) return 0;
    final own = await messenger.crypto.identity(), self = (await device()).deviceId;
    final owned = verifiedOwnList(
      await api.devices(me.username),
      userId: me.id,
      aikSign: own.sign,
      pin: messenger.devices.pin(me.id, me.id),
      metaKey: deviceMetaKey(await messenger.crypto.deviceMetaSignature(me.id)),
    );
    if (owned == null) return 0;
    final channels = [for (final g in await store.groups()) if (g.active) g.id];
    var answered = 0;
    for (final r in requests) {
      final deviceId = r['deviceId'] as String;
      final described = owned.where((d) => d.deviceId == deviceId && deviceId != self).firstOrNull?.described;
      final platform = described?['platform'];
      // Not ours, this device, unreadable, or linked by code (that one unlocks with the passphrase): no answer.
      if (platform == null || described?['via'] == 'code') {
        skipped[deviceId] = platform == null ? 'not in our list (or unreadable)' : 'linked by code';
        continue;
      }
      try {
        final box = await account.rekeyAnswer(
          me.id,
          deviceId: deviceId,
          platform: platform,
          request: (eph: r['eph'] as String, leafSigKey: r['leafSigKey'] as String, signature: r['signature'] as String),
          groups: channels,
          now: _now(),
        );
        await api.answerRekey(deviceId, box);
        answered++;
      } on CryptoException catch (error) {
        // Not signed by a leaf our groups hold (or not for our key): it asks again later.
        skipped[deviceId] = error.message;
      }
    }
    return answered;
  }
}

/// Another device changed the account key in a way this device won't adopt silently (M6 §6.2 step 3).
class RotationRefused implements Exception {
  const RotationRefused(this.label, [this.removed = const []]);
  final String label;

  /// What the change removed: device labels, "this device" first when it was this one.
  final List<String> removed;

  String get message => removed.isEmpty
      ? 'Your account key was changed from $label. If this wasn’t you, take your account back.'
      : 'Your account key was changed from $label, which removed ${_and(removed)}. If this wasn’t you, take your account back.';
  @override
  String toString() => message;
}

String _and(List<String> items) => items.length == 1 ? items.single : '${items.sublist(0, items.length - 1).join(', ')} and ${items.last}';
