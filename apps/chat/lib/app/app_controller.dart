import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:passkeys/authenticator.dart';
import 'package:passkeys/types.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';

import '../calls/call_controller.dart';
import '../core/api.dart';
import '../core/devices.dart';
import '../core/events.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/group_crypto.dart';
import '../crypto/link_crypto.dart';
import '../crypto/rust_chat_crypto.dart';
import '../crypto/rust_group_crypto.dart';
import '../messaging/attachments.dart';
import '../messaging/group_messenger.dart';
import '../messaging/group_sync.dart';
import '../messaging/linking.dart';
import '../messaging/messenger.dart';
import '../messaging/succession.dart';
import '../store/message.dart' show StoreException;
import '../store/message_store.dart';
import '../theme/theme_prefs.dart';
import 'chat_settings.dart';

/// Riverpod: providers make every dependency (API, crypto, storage, passkeys)
/// overridable in tests without a DI framework, and Notifier state rebuilds
/// only the widgets that watch it.

/// Passkey ceremonies, behind an interface so tests and screenshots need no OS prompt.
abstract class PasskeyClient {
  Future<Map<String, dynamic>> register(Map<String, dynamic> options);
  Future<Map<String, dynamic>> authenticate(Map<String, dynamic> options);
}

class PlatformPasskeys implements PasskeyClient {
  final _authenticator = PasskeyAuthenticator();
  @override
  Future<Map<String, dynamic>> register(Map<String, dynamic> options) async =>
      (await _authenticator.register(RegisterRequestType.fromJson(options))).toJson();
  @override
  Future<Map<String, dynamic>> authenticate(Map<String, dynamic> options) async =>
      (await _authenticator.authenticate(AuthenticateRequestType.fromJson(options, preferImmediatelyAvailableCredentials: false))).toJson();
}

/// Bearer token storage (Keychain / Android Keystore).
abstract class TokenStore {
  Future<String?> read();
  Future<void> write(String? token);
}

class SecureTokenStore implements TokenStore {
  static const _key = 'session-token-v1';
  final _storage = const FlutterSecureStorage();
  @override
  Future<String?> read() => _storage.read(key: _key);
  @override
  Future<void> write(String? token) => token == null ? _storage.delete(key: _key) : _storage.write(key: _key, value: token);
}

final apiProvider = Provider<Api>((ref) => Api());

/// Encrypted file upload, download and the decrypted cache (one per app; it follows the signed-in token).
final attachmentsProvider = Provider<AttachmentService>((ref) => AttachmentService(ref.read(apiProvider)));

/// Off in tests and the screenshot demo (no OS permission prompts, no Firebase).
final pushEnabledProvider = Provider<bool>((ref) => true);
final passkeysProvider = Provider<PasskeyClient>((ref) => PlatformPasskeys());
final tokenStoreProvider = Provider<TokenStore>((ref) => SecureTokenStore());

/// The Rust core (crates/chatcore) through flutter_rust_bridge. Tests and the demo override this
/// with FakeChatCrypto.
final cryptoProvider = Provider<ChatCrypto>((ref) => RustChatCrypto());

/// Linking, pin transfer and succession in the same Rust core. Tests override this with FakeLinkCrypto.
final linkCryptoProvider = Provider<LinkCrypto>((ref) => const RustLinkCrypto());

/// Groups over MLS: the same Rust core (its group engine). Tests and the demo override this with FakeGroupCrypto.
final groupCryptoProvider = Provider<GroupCrypto>((ref) => const RustGroupCrypto());

/// Rotation settings for an account on this device (account.js `rotation-*` keys in localStorage).
final rotationPrefsProvider = Provider<Future<RotationPrefs> Function(String userId)>((ref) => (userId) async {
  final prefs = await SharedPreferences.getInstance();
  return SharedRotationPrefs(prefs, userId);
});

class SharedRotationPrefs implements RotationPrefs {
  SharedRotationPrefs(this._prefs, this._user);
  final SharedPreferences _prefs;
  final String _user;
  String get _mineKey => 'rotation-v1:$_user';
  String _peerKey(String id) => 'rotation-peer-v1:$_user:$id';
  String _toldKey(String id) => 'rotation-told-v1:$_user:$id';
  @override
  int get mine => _prefs.getInt(_mineKey) ?? 0;
  @override
  set mine(int value) => _prefs.setInt(_mineKey, value);
  @override
  int peer(String contactId) => _prefs.getInt(_peerKey(contactId)) ?? 0;
  @override
  void setPeer(String contactId, int value) => _prefs.setInt(_peerKey(contactId), value);
  @override
  String? told(String contactId) => _prefs.getString(_toldKey(contactId));
  @override
  void setTold(String contactId, String value) => _prefs.setString(_toldKey(contactId), value);
  @override
  void clearTold() {
    for (final key in _prefs.getKeys().where((k) => k.startsWith('rotation-told-v1:$_user:')).toList()) {
      _prefs.remove(key);
    }
  }
}

/// An admin device's tag-only rollbacks per author device, kept on this device (m4-groups §7).
class SharedTagRollbackLog implements TagRollbackLog {
  SharedTagRollbackLog(this._prefs, this._user);
  final SharedPreferences _prefs;
  final String _user;
  String get _key => 'tag-rollbacks-v1:$_user';
  @override
  Map<String, List<int>> read() {
    try {
      final raw = jsonDecode(_prefs.getString(_key) ?? '{}');
      return {for (final e in (raw as Map).entries) e.key as String: [for (final t in e.value as List) t as int]};
    } catch (_) {
      return {};
    }
  }

  @override
  void write(Map<String, List<int>> value) => _prefs.setString(_key, jsonEncode(value));
}

/// This install's device id and key per account, and contacts' pinned device lists (account.js `device-pins-v1`).
final devicePrefsProvider = Provider<Future<DevicePrefs> Function()>((ref) => () async => SharedDevicePrefs(await SharedPreferences.getInstance()));

class SharedDevicePrefs implements DevicePrefs {
  SharedDevicePrefs(this._prefs);
  final SharedPreferences _prefs;
  // The device key seed sits in the Keychain / Android Keystore, like the session token.
  static const _secure = FlutterSecureStorage();
  @override
  Future<String?> readDevice(String userId) => _secure.read(key: 'device-key-v1:$userId');
  @override
  Future<void> writeDevice(String userId, String value) => _secure.write(key: 'device-key-v1:$userId', value: value);
  @override
  DevicePin? pin(String userId, String contactId) {
    final raw = _prefs.getString('device-pin-v1:$userId:$contactId');
    try {
      return raw == null ? null : DevicePin.fromJson(jsonDecode(raw));
    } catch (_) {
      return null;
    }
  }

  @override
  void setPin(String userId, String contactId, DevicePin pin) => _prefs.setString('device-pin-v1:$userId:$contactId', jsonEncode(pin.toJson()));
}

/// Opens the per-account message database.
final storeOpenerProvider = Provider<Future<MessageStore> Function(String userId)>((ref) => (userId) async {
  final dir = await getApplicationSupportDirectory();
  return MessageStore.open(databaseFactory, p.join(dir.path, 'messages-$userId.db'));
});

enum AuthPhase { loading, signedOut, signedIn }

@immutable
class IncomingCall {
  const IncomingCall({required this.contact, required this.kind, required this.roomId, required this.token});
  final Contact contact;
  final String kind;
  final String roomId;
  final String token;
}

@immutable
class AppState {
  const AppState({
    this.phase = AuthPhase.loading,
    this.user,
    this.contacts = const [],
    this.unread = const {},
    this.notice,
    this.incoming,
    this.call,
    this.keyChanged = const {},
    this.inactiveDevice = false,
    this.keysLocked = false,
    this.typing = const {},
    this.groups = const [],
    this.groupTyping = const {},
    this.pausedGroups = const {},
    this.groupsUnavailable,
    this.companion = false,
    this.movedChats = const {},
  });
  final AuthPhase phase;
  final User? user;
  final List<Contact> contacts;
  final Map<String, int> unread;
  final String? notice;
  final IncomingCall? incoming;
  final CallController? call;

  /// Contacts whose security code changed and has not been reviewed.
  final Set<String> keyChanged;

  /// Encrypted messaging for this account is active on another device or browser.
  final bool inactiveDevice;

  /// This device's key database can't be unlocked: messaging is stopped until the user recovers.
  final bool keysLocked;

  /// Contacts typing to us right now.
  final Set<String> typing;

  /// Group conversations on this device (docs/m4-groups.md), with unread and mention marks.
  final List<GroupConversation> groups;

  /// Group id → user ids typing there.
  final Map<String, List<String>> groupTyping;

  /// Groups paused until a member's security code is reviewed (group id → user id).
  final Map<String, String> pausedGroups;

  /// Why groups are off on this device, if they are.
  final String? groupsUnavailable;

  /// This install is a linked device of the account (m5 §0): 1:1 chats stay on the primary until they move.
  final bool companion;

  /// Contacts whose 1:1 chat moved to MLS here (m5 §8).
  final Set<String> movedChats;

  AppState copyWith({
    AuthPhase? phase,
    User? user,
    List<Contact>? contacts,
    Map<String, int>? unread,
    String? notice,
    bool clearNotice = false,
    IncomingCall? incoming,
    bool clearIncoming = false,
    CallController? call,
    bool clearCall = false,
    Set<String>? keyChanged,
    bool? inactiveDevice,
    bool? keysLocked,
    Set<String>? typing,
    List<GroupConversation>? groups,
    Map<String, List<String>>? groupTyping,
    Map<String, String>? pausedGroups,
    String? groupsUnavailable,
    bool clearGroupsUnavailable = false,
    bool? companion,
    Set<String>? movedChats,
  }) => AppState(
    phase: phase ?? this.phase,
    user: user ?? this.user,
    contacts: contacts ?? this.contacts,
    unread: unread ?? this.unread,
    notice: clearNotice ? null : notice ?? this.notice,
    incoming: clearIncoming ? null : incoming ?? this.incoming,
    call: clearCall ? null : call ?? this.call,
    keyChanged: keyChanged ?? this.keyChanged,
    inactiveDevice: inactiveDevice ?? this.inactiveDevice,
    keysLocked: keysLocked ?? this.keysLocked,
    typing: typing ?? this.typing,
    groups: groups ?? this.groups,
    groupTyping: groupTyping ?? this.groupTyping,
    pausedGroups: pausedGroups ?? this.pausedGroups,
    groupsUnavailable: clearGroupsUnavailable ? null : groupsUnavailable ?? this.groupsUnavailable,
    companion: companion ?? this.companion,
    movedChats: movedChats ?? this.movedChats,
  );
}

class AppController extends Notifier<AppState> {
  Api get _api => ref.read(apiProvider);
  ChatCrypto get _crypto => ref.read(cryptoProvider);
  EventsClient? _events;
  Messenger? messenger;
  GroupMessenger? groups;
  MessageStore? store;
  String? viewingGroup;
  final _linkEvents = StreamController<LinkEvent>.broadcast();

  /// `link` frames for this account (hello, offer, grant, message).
  Stream<LinkEvent> get linkEvents => _linkEvents.stream;
  final _subscriptions = <StreamSubscription<Object?>>[];
  String? viewingContact;
  Timer? _missTimer;

  @override
  AppState build() {
    ref.onDispose(_teardown);
    return const AppState();
  }

  /// Restores a saved session, if any.
  Future<void> restore() async {
    final token = await ref.read(tokenStoreProvider).read();
    if (token == null) {
      state = state.copyWith(phase: AuthPhase.signedOut);
      return;
    }
    _api.token = token;
    try {
      await _signedIn(await _api.me(), token);
    } on ApiException catch (error) {
      if (error.status == 401) await ref.read(tokenStoreProvider).write(null);
      state = state.copyWith(phase: AuthPhase.signedOut, notice: error.status == 401 ? 'Your session ended. Sign in again.' : null);
    } catch (_) {
      state = state.copyWith(phase: AuthPhase.signedOut, notice: 'Could not reach the server. Check your connection.');
    }
  }

  Future<void> signIn() async {
    final flow = await _api.loginOptions();
    final response = await ref.read(passkeysProvider).authenticate(flow.options);
    final result = await _api.loginVerify(flow.flowId, response);
    await _signedIn(result.user, result.token);
  }

  Future<void> register(String invite, String username) async {
    final flow = await _api.registerOptions(invite.trim(), username.trim().toLowerCase());
    final response = await ref.read(passkeysProvider).register(flow.options);
    final result = await _api.registerVerify(flow.flowId, response);
    await _signedIn(result.user, result.token);
  }

  /// The device-key slot of an install that is linking and doesn't know its account yet.
  static const _linkOwner = '__link__';

  /// Welcome → "Link to my account" (m5 §1): this install shows a QR (or, with [username], an 8-character code
  /// for that account). Its key database is a fresh one under a link-scoped name, kept for the account once
  /// linked; the device key too.
  Future<NewDeviceLink> startLink({String? username}) async {
    final device = await localDevice(await ref.read(devicePrefsProvider)(), _linkOwner);
    await _crypto.init('keys-link-${device.deviceId}');
    return NewDeviceLink.start(
      api: _api,
      link: ref.read(linkCryptoProvider),
      groups: ref.read(groupCryptoProvider),
      device: device,
      platform: _api.client,
      label: platformLabel(_api.client),
      username: username?.trim().toLowerCase(),
    );
  }

  /// The primary granted the link: check it, keep the core and device key for the account, sign in as a
  /// linked device, and install the bundle's history and channel names.
  Future<void> finishLink(NewDeviceLink link) async {
    final setup = await link.waitGrant();
    final prefs = await ref.read(devicePrefsProvider)();
    final key = await prefs.readDevice(_linkOwner);
    if (key != null) await prefs.writeDevice(setup.user.id, key);
    await prefs.writeDevice(_linkOwner, 'null'); // The next link starts with a new device.
    prefs.setPin(setup.user.id, setup.user.id, setup.pin);
    await (await SharedPreferences.getInstance()).setString('linked-core-v1:${setup.user.id}', 'keys-link-${link.deviceId}');
    await _signedIn(setup.user, setup.token, linked: setup.bundle);
  }

  Future<void> _signedIn(User user, String token, {Map<String, Object?>? linked}) async {
    _api.token = token;
    await ref.read(tokenStoreProvider).write(token);
    await ref.read(themePrefsProvider.notifier).load(user.id);
    await ref.read(chatSettingsProvider.notifier).load(user.id);
    final dbStore = await ref.read(storeOpenerProvider)(user.id);
    store = dbStore;
    var companion = false;
    try {
      // A linked install keeps the key database it linked with.
      await _crypto.init((await SharedPreferences.getInstance()).getString('linked-core-v1:${user.id}') ?? 'keys-${user.id}');
      companion = await ref.read(linkCryptoProvider).account() != null;
    } on CryptoException catch (error) {
      if (!error.keysLocked) rethrow;
      // Signed in, but encrypted messaging stays off until the user chooses recovery. Never reset silently.
      state = state.copyWith(phase: AuthPhase.signedIn, user: user, keysLocked: true, clearNotice: true);
      await loadContacts();
      return;
    }
    final events = EventsClient(url: _api.base.replace(scheme: _api.base.scheme == 'https' ? 'wss' : 'ws', path: '/api/events'), token: token);
    _events = events;
    final m = Messenger(
      api: _api,
      crypto: _crypto,
      store: dbStore,
      me: user,
      contactById: contactById,
      mutualContacts: () => state.contacts.where((c) => c.state == ContactState.mutual && c.id != null).toList(),
      ack: events.ack,
      viewing: () => viewingContact,
      rotation: await ref.read(rotationPrefsProvider)(user.id),
      devices: await ref.read(devicePrefsProvider)(),
      readReceipts: () => ref.read(chatSettingsProvider).readReceipts,
    )..companion = companion;
    messenger = m;
    final sync = GroupSync(
      api: _api,
      crypto: ref.read(groupCryptoProvider),
      store: dbStore,
      me: user,
      device: m.device,
      platform: _api.client,
      ensurePinned: (ids, {force = false}) async => await groups?.ensurePinned(ids, force: force) ?? const <String>[],
      verifiedOwnDevices: m.verifiedOwnDevices,
      companion: companion,
      tagLog: SharedTagRollbackLog(await SharedPreferences.getInstance(), user.id),
      sendCursor: (channel, seq) => events.connected ? events.cursor(channel, seq) : unawaited(_api.setCursor(channel, seq).catchError((_) {})),
      ackWelcome: events.ack,
    );
    final g = GroupMessenger(
      api: _api,
      sync: sync,
      chatCrypto: _crypto,
      store: dbStore,
      me: user,
      contacts: () => state.contacts,
      viewing: () => viewingGroup,
      readReceipts: () => ref.read(chatSettingsProvider).readReceipts,
    );
    groups = g;
    // Moved 1:1 chats travel through their DM groups (m5 §8).
    m.groups = g;
    _subscriptions
      ..add(sync.notices.listen((text) => state = state.copyWith(notice: text)))
      ..add(g.notices.listen((text) => state = state.copyWith(notice: text)))
      ..add(dbStore.groupChanges.listen((_) => unawaited(_loadGroups())))
      ..add(sync.membershipChanges.listen((_) => unawaited(_loadGroups())))
      ..add(g.typingChanges.listen((typing) => state = state.copyWith(groupTyping: typing)))
      ..add(sync.pausedChanges.listen((paused) => state = state.copyWith(pausedGroups: paused)));
    _subscriptions
      ..add(events.events.listen(_onEvent))
      ..add(m.notices.listen((text) => state = state.copyWith(notice: text)))
      ..add(m.unreadChanges.listen((unread) => state = state.copyWith(unread: unread)))
      ..add(m.identityChanges.listen((id) => state = state.copyWith(keyChanged: {...state.keyChanged, id})))
      ..add(m.activeChanges.listen((active) => state = state.copyWith(inactiveDevice: !active)))
      ..add(m.lockedChanges.listen((locked) => state = state.copyWith(keysLocked: locked)))
      ..add(m.typingChanges.listen((typing) => state = state.copyWith(typing: typing)));
    if (linked != null) await installLinkBundle(linked, dbStore, sync);
    state = state.copyWith(phase: AuthPhase.signedIn, user: user, companion: companion, clearNotice: true);
    await _loadGroups();
    unawaited(_checkActive());
    await loadContacts();
    unawaited(events.connect());
    // Pin each contact's signed device list now, so a later rollback or injected device is caught.
    for (final contact in state.contacts.where((c) => c.state == ContactState.mutual && c.id != null)) {
      unawaited(m.verifyContactDevices(contact).catchError((_) => null));
    }
  }

  Future<void> _loadGroups() async {
    final s = store;
    if (s == null) return;
    try {
      // A 1:1 chat's DM group shows as that chat, never as a group.
      final all = await s.groups();
      state = state.copyWith(
        groups: [for (final g in all) if (g.kind != GroupKindName.dm) g],
        movedChats: {for (final g in all) if (g.kind == GroupKindName.dm && g.active && g.dmChecked && g.movedAt != null) ?g.peer},
      );
    } catch (_) {}
  }

  GroupConversation? groupById(String id) {
    for (final g in state.groups) {
      if (g.id == id) return g;
    }
    return null;
  }

  /// Groups after the device is the account's active one: group identity, Welcomes, every log.
  Future<void> _startGroups() async {
    final g = groups;
    if (g == null) return;
    try {
      await g.start();
    } catch (_) {
      // Offline or a server without groups: tried again on the next reconnect.
    }
    state = g.unavailable == null ? state.copyWith(clearGroupsUnavailable: true) : state.copyWith(groupsUnavailable: g.unavailable);
    await _loadGroups();
  }

  // ---------- Primary transfer (m5 §5) ----------
  /// Reopens the account on this device after a transfer changed what its core holds (primary ↔ linked).
  Future<void> _reopen() async {
    final user = state.user, token = _api.token;
    if (user == null || token == null) return;
    await _teardown();
    await _signedIn(user, token);
  }

  /// This primary takes the QR text of the device taking over.
  Future<HandOver> handOver(String qr) async {
    final ctx = linkContext() ?? (throw StateError('Not signed in'));
    return HandOver.fromQr(ctx, ref.read(groupCryptoProvider), qr);
  }

  /// The user confirmed on this primary: sign the account over, then continue here as a linked device.
  Future<void> finishHandOver(HandOver h) async {
    await h.approve();
    await _reopen();
  }

  /// This linked device asks to become the primary: it shows a code for the primary to scan.
  Future<TakeOver> startTakeOver() async {
    final m = messenger ?? (throw StateError('Not signed in'));
    return TakeOver.start(api: _api, link: ref.read(linkCryptoProvider), groups: ref.read(groupCryptoProvider), device: await m.device(), platform: _api.client);
  }

  /// The primary confirmed: take the account over, then continue here as its primary.
  Future<void> finishTakeOver(TakeOver t) async {
    final m = messenger ?? (throw StateError('Not signed in'));
    await t.run(m, platform: _api.client);
    await _reopen();
    unawaited(_ownSuccession()?.answerRecerts().catchError((_) => 0));
  }

  /// Linked devices following the account to a new key, and the primary certifying their leaves (§5.2.2).
  OwnSuccession? _ownSuccession() {
    final m = messenger, s = store, g = groups, user = state.user;
    if (m == null || s == null || g == null || user == null) return null;
    return OwnSuccession(api: _api, link: ref.read(linkCryptoProvider), groups: ref.read(groupCryptoProvider), store: s, updateLeaf: g.sync.updateLeaf, me: user, platform: _api.client);
  }

  Future<void> _followSuccession() async {
    final own = _ownSuccession();
    if (own == null) return;
    try {
      if (await own.follow()) state = state.copyWith(notice: 'Your account moved to a new primary device.');
      await own.takeRecert();
    } on StoreException catch (error) {
      state = state.copyWith(notice: error.message);
    } catch (_) {
      // Offline: tried again on the next devices event or start.
    }
  }

  /// What linking a device needs (this device as the primary).
  LinkContext? linkContext() {
    final m = messenger, s = store;
    if (m == null || s == null) return null;
    return LinkContext(api: _api, crypto: _crypto, link: ref.read(linkCryptoProvider), messenger: m, store: s, contacts: () => state.contacts);
  }

  void openGroup(String id) {
    viewingGroup = id;
    unawaited(groups?.markRead(id));
  }

  void closeGroup() => viewingGroup = null;

  Contact? contactById(String id) {
    for (final c in state.contacts) {
      if (c.id == id) return c;
    }
    return null;
  }

  Future<void> loadContacts() async {
    try {
      final online = {for (final c in state.contacts) if (c.online && c.id != null) c.id!};
      final contacts = await _api.contacts();
      state = state.copyWith(contacts: [for (final c in contacts) c.online || online.contains(c.id) ? c.copyWith(online: true) : c]);
      unawaited(messenger?.flush());
    } on ApiException catch (error) {
      if (error.status == 401) await signOut(silent: true);
    } catch (_) {}
  }

  /// Feeds an account event as if it came from the server (tests and the screenshot demo).
  void handleEvent(AccountEvent event) => _onEvent(event);

  void _onEvent(AccountEvent event) {
    switch (event) {
      case Hello(:final online):
        state = state.copyWith(contacts: [for (final c in state.contacts) c.copyWith(online: online.contains(c.id))]);
        unawaited(_checkActive());
        // A reconnect: Welcomes and logs that waited (frames resume from the cursors).
        if (groups?.ready ?? false) unawaited(groups!.sync.fetchWelcomes().then((_) => groups?.sync.refresh()).catchError((_) {}));
      case Presence(:final id, :final online):
        state = state.copyWith(contacts: [for (final c in state.contacts) c.id == id ? c.copyWith(online: online) : c]);
      case ContactsChanged():
        unawaited(loadContacts());
      case KeysChanged(:final id):
        // Our own id: another device may have taken over this account's encryption.
        unawaited(id == state.user?.id ? _checkActive() : _checkIdentity(id));
      case DevicesChanged(:final id):
        // A contact's list: verify it against their pinned security code. Ours: check it still names this device.
        final contact = contactById(id);
        if (id == state.user?.id && (messenger?.companion ?? false)) {
          // A linked device: our account may have moved to a new primary (m5 §5.2 step 6).
          unawaited(_followSuccession());
          unawaited(groups?.sync.removeDroppedOwnLeaves().catchError((_) => 0));
        } else if (id == state.user?.id) {
          // After a revocation the primary publishes the list without the revoked device (m5 §4).
          unawaited(messenger?.syncDevices().catchError((_) => false));
          if (event.needsList) unawaited(messenger?.publishNextList().then((_) => null, onError: (_) => null));
          unawaited(groups?.sync.removeDroppedOwnLeaves().catchError((_) => 0));
        } else if (contact != null) {
          unawaited(messenger?.verifyContactDevices(contact).catchError((_) => null));
        }
      case EnvelopeEvent():
        unawaited(messenger?.receive(event));
      case RecertEvent():
        // A linked device's certificate under the new key was answered, or (on the primary) one is waiting.
        if (messenger?.companion ?? false) {
          unawaited(_followSuccession());
        } else {
          unawaited(_ownSuccession()?.answerRecerts().catchError((_) => 0));
        }
      case LinkEvent():
        // Screens running a link (the primary's side) wait on these instead of polling.
        if (!_linkEvents.isClosed) _linkEvents.add(event);
      case GroupEvent() || WelcomeEvent() || ChannelEvent() || KeyPackagesLow() || GroupEphemeral():
        unawaited(groups?.onEvent(event).catchError((_) {}));
      case Incoming():
        _incoming(event);
      case Ended(:final roomId):
        final ring = state.incoming;
        if (ring?.roomId == roomId) {
          state = state.copyWith(clearIncoming: true, notice: 'Missed ${ring!.kind} call from ${ring.contact.username}');
        }
      case SignedOutEvent():
        unawaited(signOut(silent: true, message: 'Your session ended. Sign in again.'));
    }
  }

  Future<void> _checkActive() async {
    if (messenger?.companion ?? false) {
      // A linked device: groups (and moved chats) only; the account's keys are on the primary.
      if (!(groups?.ready ?? true)) await _startGroups();
      await _followSuccession();
      return;
    }
    try {
      final active = await messenger?.checkActive();
      if (active != null) state = state.copyWith(inactiveDevice: !active);
      if (active == true) {
        // Groups need this device in the account's signed device list (docs/m4-groups.md §2).
        try {
          await messenger?.syncDevices();
        } catch (_) {}
        if (!(groups?.ready ?? true)) await _startGroups();
        unawaited(_ownSuccession()?.answerRecerts().catchError((_) => 0));
      }
    } catch (e) {
      state = state.copyWith(notice: 'Could not check encryption keys: $e');
    }
  }

  /// Conversation ⋯ → Reset secure session.
  Future<void> resetSession(Contact contact) async => messenger!.resetSession(contact);

  /// Settings → Security: this device's rotation interval (ms, 0 = off).
  Future<void> setRotation(int value) async => messenger?.setMyRotation(value);

  /// Settings → Security: new identity keys (explicit; contacts see a security-code change).
  Future<void> regenerateIdentity() async {
    await messenger?.regenerateIdentity();
    state = state.copyWith(inactiveDevice: false);
  }

  /// Recovery, only from the user's confirmed tap: delete this device's unusable key database and start a
  /// new identity here (contacts see a security-code change). Message history on this device stays.
  Future<void> recoverKeys() async {
    final user = state.user;
    final token = _api.token;
    if (user == null || token == null) return;
    await _crypto.resetLocal('keys-${user.id}');
    await _teardown();
    state = state.copyWith(keysLocked: false);
    await _signedIn(user, token);
    await messenger?.takeOver();
  }

  /// "Use this device instead" (recovery without a primary, m5 §6): only ever from the user's confirmed tap. This
  /// device's key becomes the account's (contacts see the code change) and the first list under it names only
  /// this device: no device of the old key is trusted again.
  Future<void> useThisDevice() async {
    final m = messenger;
    if (m == null) return;
    await m.takeOver();
    await m.publishNewChain(const []);
    state = state.copyWith(inactiveDevice: false);
    await _checkActive();
  }

  Future<void> _checkIdentity(String contactId) async {
    final contact = contactById(contactId);
    if (contact == null) return;
    try {
      // The devices view also serves any succession chain, so a moved account keeps its verification.
      final view = await _api.devices(contact.username);
      final served = view['identity'];
      if (served is! Map<String, dynamic>) return;
      await messenger?.followIdentity(contact, Identity.fromJson(served), view['succession']);
      final safety = await _crypto.safety(state.user!.username, contactId, contact.username);
      if (safety != null && (safety.changed || safety.blocked)) state = state.copyWith(keyChanged: {...state.keyChanged, contactId});
      unawaited(messenger?.flush());
    } catch (_) {}
  }

  // ---------- Calls ----------
  void _incoming(Incoming event) {
    // Contact chats use the encrypted mailbox; only calls ring.
    if (event.kind == 'chat') return;
    final contact = contactById(event.fromId) ?? Contact(id: event.fromId, username: event.fromUsername, state: ContactState.mutual, online: true);
    state = state.copyWith(incoming: IncomingCall(contact: contact, kind: event.kind, roomId: event.roomId, token: event.token));
    _events?.ringing(event.roomId);
    _missTimer?.cancel();
    _missTimer = Timer(const Duration(seconds: 45), () {
      if (state.incoming?.roomId == event.roomId) {
        state = state.copyWith(clearIncoming: true, notice: 'Missed ${event.kind} call from ${contact.username}');
      }
    });
  }

  /// Nothing captures media until this runs from an Accept tap.
  Future<CallController?> accept({required bool audioOnly}) async {
    final ring = state.incoming;
    if (ring == null) return null;
    _missTimer?.cancel();
    state = state.copyWith(clearIncoming: true);
    return _startCall(ring.contact, ring.kind, ring.roomId, ring.token, audioOnly: audioOnly);
  }

  Future<void> decline() async {
    final ring = state.incoming;
    _missTimer?.cancel();
    state = state.copyWith(clearIncoming: true);
    if (ring != null) {
      try {
        await _api.decline(ring.contact.username, ring.roomId);
      } catch (_) {}
    }
  }

  Future<CallController?> call(Contact contact, String kind) async {
    final session = await _api.session(contact.username, kind);
    return _startCall(contact, kind, session.roomId, session.token);
  }

  Future<CallController> _startCall(Contact contact, String kind, String roomId, String token, {bool audioOnly = false}) async {
    await state.call?.end('Switched to a new call.');
    final controller = CallController(api: _api, crypto: _crypto, peerName: contact.username);
    state = state.copyWith(call: controller);
    unawaited(controller.start(roomId: roomId, token: token, kind: kind, audioOnly: audioOnly));
    return controller;
  }

  void callFinished() {
    state.call?.dispose();
    state = state.copyWith(clearCall: true);
  }

  // ---------- Contacts, invites, safety ----------
  Future<void> addContact(String username) async {
    await _api.requestContact(username.trim().toLowerCase());
    state = state.copyWith(notice: 'Request sent to @${username.trim().toLowerCase()}. They appear in your chats once they accept.');
    await loadContacts();
  }

  Future<void> acceptContact(Contact c) async {
    await _api.acceptContact(c.username);
    await loadContacts();
  }

  Future<void> removeContact(Contact c) async {
    await _api.removeContact(c.username);
    await loadContacts();
  }

  Future<({String link, int expiresAt})> createInvite() async {
    final invite = await _api.createInvite();
    return (link: _api.base.replace(fragment: 'invite=${invite.code}').toString(), expiresAt: invite.expiresAt);
  }

  /// [shown]: the identity whose code the sheet showed. The decision applies only to that identity; if the
  /// pin changed again meanwhile the core refuses (`mismatch`) and nothing is accepted.
  Future<void> reviewedKey(String contactId, {required bool verified, Identity? shown}) async {
    if (shown != null) {
      verified ? await _crypto.setVerifiedFor(contactId, true, shown) : await _crypto.acceptChangeFor(contactId, shown);
    } else if (verified) {
      await _crypto.setVerified(contactId, true);
    } else {
      await _crypto.acceptChange(contactId);
    }
    state = state.copyWith(keyChanged: {...state.keyChanged}..remove(contactId));
    unawaited(messenger?.flush());
    // Channels paused for this person's security code carry on.
    unawaited(groups?.sync.resume(contactId));
  }

  void dismissNotice() => state = state.copyWith(clearNotice: true);

  void openConversation(String contactId) {
    viewingContact = contactId;
    messenger?.markRead(contactId);
  }

  void closeConversation() => viewingContact = null;

  // ---------- Sign out ----------
  Future<void> signOut({bool everywhere = false, bool silent = false, String? message}) async {
    if (!silent) {
      try {
        await _api.logout(everywhere: everywhere);
      } catch (_) {}
    }
    await _teardown();
    await ref.read(attachmentsProvider).clearDisk();
    await ref.read(tokenStoreProvider).write(null);
    _api.token = null;
    state = AppState(phase: AuthPhase.signedOut, notice: message ?? (everywhere ? 'Signed out on every device.' : 'Signed out.'));
  }

  Future<void> _teardown() async {
    _missTimer?.cancel();
    for (final s in _subscriptions) {
      await s.cancel();
    }
    _subscriptions.clear();
    await _events?.close();
    _events = null;
    await state.call?.end('Signed out.');
    await messenger?.dispose();
    messenger = null;
    await groups?.dispose();
    groups = null;
    await store?.close();
    store = null;
  }
}

final appProvider = NotifierProvider<AppController, AppState>(AppController.new);
