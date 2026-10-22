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
import '../crypto/account_crypto.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/group_crypto.dart';
import '../crypto/link_crypto.dart';
import '../crypto/rust_chat_crypto.dart';
import '../crypto/rust_group_crypto.dart';
import '../messaging/attachments.dart';
import '../messaging/backup.dart';
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

/// The account key export/import and its encrypted backup (docs/m6-account-key.md).
final accountCryptoProvider = Provider<AccountCrypto>((ref) => const RustAccountCrypto());

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

/// An open reset of the account key (docs/m6-account-key.md §6.5).
typedef KeyReset = ({String platform, int at, int executeAfter, bool mine});

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
    this.needsRestore = false,
    this.hasBackup,
    this.backupUpdatedAt,
    this.fullDevice = false,
    this.offerBackup = false,
    this.removedListed,
    this.restoredSafety,
    this.keyReset,
    this.keyChangeNotice,
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

  /// Signed in on a device the account doesn't list yet (docs/m6-account-key.md §4): show "Use your account here".
  final bool needsRestore;

  /// Whether the account has an encrypted key backup (null: not known yet).
  final bool? hasBackup;

  /// When the backup last changed (its `updatedAt`).
  final int? backupUpdatedAt;

  /// This device holds the account key ("Can unlock your account").
  final bool fullDevice;

  /// Offer to turn the backup on, once after sign-in, when the account has none.
  final bool offerBackup;

  /// A device our signed list still names that the server says was revoked (another device cut it off): ask the
  /// user to change the account key (§6.2). Its id and label.
  final ({String id, String label})? removedListed;

  /// Just restored from the backup: the account's safety number, shown once with "your contacts don't need to
  /// re-verify you" (§4).
  final String? restoredSafety;

  /// An open request to reset the account key (M6 §6.5): from which platform, when, when it may run, and whether this
  /// device asked for it.
  final KeyReset? keyReset;

  /// Another device changed the account key and removed devices (or this one): shown until dismissed.
  final String? keyChangeNotice;

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
    bool? needsRestore,
    bool? hasBackup,
    int? backupUpdatedAt,
    bool? fullDevice,
    bool? offerBackup,
    ({String id, String label})? removedListed,
    bool clearRemovedListed = false,
    String? restoredSafety,
    bool clearRestoredSafety = false,
    KeyReset? keyReset,
    bool clearKeyReset = false,
    String? keyChangeNotice,
    bool clearKeyChangeNotice = false,
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
    needsRestore: needsRestore ?? this.needsRestore,
    hasBackup: hasBackup ?? this.hasBackup,
    backupUpdatedAt: backupUpdatedAt ?? this.backupUpdatedAt,
    fullDevice: fullDevice ?? this.fullDevice,
    offerBackup: offerBackup ?? this.offerBackup,
    removedListed: clearRemovedListed ? null : removedListed ?? this.removedListed,
    restoredSafety: clearRestoredSafety ? null : restoredSafety ?? this.restoredSafety,
    keyReset: clearKeyReset ? null : keyReset ?? this.keyReset,
    keyChangeNotice: clearKeyChangeNotice ? null : keyChangeNotice ?? this.keyChangeNotice,
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
      account: ref.read(accountCryptoProvider),
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
    await (await SharedPreferences.getInstance()).setString('device-meta-key-v1:${setup.user.id}', setup.metaKey);
    await (await _certKey(setup.user.id)).write(setup.identity.sign); // The grant's certificate is under this key.
    await (await SharedPreferences.getInstance()).setString('linked-core-v1:${setup.user.id}', 'keys-link-${link.deviceId}');
    // A short-code link carries no key and is never rekeyed: it unlocks with the passphrase (M6 §2, §5).
    await (await SharedPreferences.getInstance()).setBool('linked-by-code-v1:${setup.user.id}', link.shortCode != null && !setup.full);
    final keys = setup.backupKeys;
    if (keys != null) await ref.read(accountCryptoProvider).keepBackupKeys(keys); // In the core, like every full device's.
    await _signedIn(setup.user, setup.token, linked: setup.bundle);
  }

  /// The key database [_signedIn] opened (a linked install keeps the one it linked with).
  String? _corePath;

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
      await _crypto.init(_corePath = (await SharedPreferences.getInstance()).getString('linked-core-v1:${user.id}') ?? 'keys-${user.id}');
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
    sync.followIdentity = _followAuthor;
    g.onKeyMoved = (id, now) {
      final contact = contactById(id);
      if (contact != null) m.keyMoved(contact, now);
    };
    _certKeyCached = await _certKey(user.id);
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
    if (linked != null) await installLinkBundle(linked, dbStore);
    state = state.copyWith(
      phase: AuthPhase.signedIn,
      user: user,
      companion: companion,
      needsRestore: false,
      keyChangeNotice: (await SharedPreferences.getInstance()).getString('key-change-notice-v1:${user.id}'),
      clearNotice: true,
    );
    await _loadGroups();
    final checked = _checkActive();
    await loadContacts();
    unawaited(events.connect());
    // Pin each contact's signed device list now, so a later rollback or injected device is caught. Not on a device
    // waiting to restore: its key database must stay empty until the account key is imported (§4).
    unawaited(checked.then((_) {
      if (state.needsRestore) return;
      for (final contact in state.contacts.where((c) => c.state == ContactState.mutual && c.id != null)) {
        unawaited(m.verifyContactDevices(contact).catchError((_) => null));
      }
    }));
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

  // M6 devices don't transfer (docs/m6-account-key.md §2): a take-over begun under M5 still finishes on start.
  Future<TakeOverMarkers> _takeOverMarkers(String userId) async {
    final prefs = await SharedPreferences.getInstance(), key = 'takeover-v1:$userId';
    return (read: () async => prefs.getString(key), write: (String? v) async => v == null ? await prefs.remove(key) : await prefs.setString(key, v));
  }

  /// A take-over cut short after it was confirmed resumes on the next start (m5 §5.2).
  Future<bool> _resumeTakeOver() async {
    final m = messenger;
    if (m == null) return false;
    try {
      final done = await TakeOver.resume(api: _api, link: ref.read(linkCryptoProvider), groups: ref.read(groupCryptoProvider), messenger: m, platform: _api.client, markers: await _takeOverMarkers(m.me.id));
      if (done) state = state.copyWith(notice: 'This device finished taking over your account.');
      return done;
    } on StoreException catch (error) {
      state = state.copyWith(notice: error.message);
    } catch (_) {
      // Offline: tried again on the next start.
    }
    return false;
  }

  /// After a succession this device's leaf carries a certificate under the new key: commit it in every group until
  /// no group sees it as Previous (which blocks adding people, m5 §7), a bounded number of tries each.
  Future<void> _recommitLeaves() async {
    final g = groups, s = store;
    if (g == null || s == null) return;
    var left = 0;
    for (final c in await s.groups()) {
      if (c.active && !await g.sync.recommitLeaf(c.id)) left++;
    }
    if (left > 0) state = state.copyWith(notice: "$left ${left == 1 ? 'group still sees' : 'groups still see'} this device's old key. It tries again on the next start.");
  }

  /// Linked devices following the account to a new key, and the primary certifying their leaves (§5.2.2).
  OwnSuccession? _ownSuccession() {
    final m = messenger, s = store, g = groups, user = state.user;
    if (m == null || s == null || g == null || user == null) return null;
    return OwnSuccession(
      api: _api,
      link: ref.read(linkCryptoProvider),
      groups: ref.read(groupCryptoProvider),
      store: s,
      updateLeaf: g.sync.updateLeaf,
      me: user,
      platform: _api.client,
      chat: _crypto,
      devices: m.devices,
      device: m.device,
      certKey: _certKeyCached,
    );
  }

  /// The account key this device's MLS certificate is under, persisted per account (§5.2.2).
  ({Future<String?> Function() read, Future<void> Function(String sign) write})? _certKeyCached;
  Future<({Future<String?> Function() read, Future<void> Function(String sign) write})> _certKey(String userId) async {
    final prefs = await SharedPreferences.getInstance(), key = 'cert-key-v1:$userId';
    return (read: () async => prefs.getString(key), write: (String sign) async => prefs.setString(key, sign).then((_) {}));
  }

  /// The author of a commit about to be reported as poison may have moved to a new account key (m5 §5.2): ours
  /// follows our own chain, a contact's is checked again. True when a pin moved.
  Future<bool> _followAuthor(String userId) async {
    if (userId == state.user?.id) return messenger?.companion ?? false ? await _ownSuccession()?.follow() ?? false : false;
    final before = (await _crypto.peer(userId))?.identity;
    await _checkIdentity(userId);
    // Someone met only in groups: the group pins follow their chain (a forced pass may already have moved it).
    if (contactById(userId) == null) await groups?.ensurePinned([userId], force: true);
    return (groups?.followed.remove(userId) ?? false) || (await _crypto.peer(userId))?.identity != before;
  }

  /// Follows the account to a new key along its signed chain. Returns whether it moved.
  Future<bool> _followSuccession() async {
    final own = _ownSuccession();
    if (own == null) return false;
    try {
      final moved = await own.follow();
      final notice = own.notice;
      if (notice != null) {
        await _keepKeyChangeNotice(notice);
      } else if (moved) {
        state = state.copyWith(notice: 'Your account has a new key. Your contacts keep their verification.');
      }
      await own.takeRecert();
      return moved;
    } on StoreException catch (error) {
      state = state.copyWith(notice: error.message);
    } on RotationRefused catch (refused) {
      // This device was removed by someone else's key change: not followed; restore takes the account back (§6.4).
      await _keepKeyChangeNotice(refused.message);
    } catch (_) {
      // Offline: tried again on the next devices event or start.
    }
    return false;
  }

  /// What linking a device needs (this device as the primary).
  LinkContext? linkContext() {
    final m = messenger, s = store;
    if (m == null || s == null) return null;
    return LinkContext(
      api: _api,
      crypto: _crypto,
      link: ref.read(linkCryptoProvider),
      messenger: m,
      store: s,
      contacts: () => state.contacts,
      account: ref.read(accountCryptoProvider),
      backupKeys: ref.read(accountCryptoProvider).heldBackupKeys,
    );
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
      case BackupEvent(:final read, :final deviceId):
        if (read) {
          _backupOpenedElsewhere(deviceId);
        } else {
          unawaited(backupChanged());
        }
      case ResetEvent(:final cancelled, :final deviceId, :final platform, :final at, :final executeAfter):
        if (cancelled || at == null || executeAfter == null) {
          state = state.copyWith(clearKeyReset: true);
        } else {
          unawaited(messenger?.device().then((d) {
            state = state.copyWith(keyReset: (platform: platform ?? 'web', at: at, executeAfter: executeAfter, mine: d.deviceId == deviceId));
          }));
        }
      case RekeyEvent(:final answered):
        if (answered) {
          unawaited(_takeRekey());
        } else if (messenger?.full ?? false) {
          unawaited(_rekey()?.answer().catchError((_) => 0));
        }
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
    if (await _resumeTakeOver()) {
      await _reopen();
      await _recommitLeaves();
      return;
    }
    if (messenger?.companion ?? false) {
      // Without the account key: groups (and moved chats) only. It asks a device with the key for it (M6 §5),
      // unless it was linked by code (that one unlocks with the passphrase).
      if (!(groups?.ready ?? true)) await _startGroups();
      await _followSuccession();
      if (!await _linkedByCode()) {
        if (!await _takeRekey()) unawaited(_rekey()?.ask().catchError((_) {}));
      }
      return;
    }
    if (await _needsRestore()) return;
    // A key change this device prepared before a crash (M6 §6.2): finished if the server took it, else dropped. First,
    // before the key comparison below would take the new published key for someone else's.
    if (await _resumeRotation()) {
      await _reopen();
      await _recommitLeaves();
      return;
    }
    try {
      final m = messenger;
      final active = await m?.checkActive();
      if (active != null) state = state.copyWith(inactiveDevice: !active, fullDevice: m?.full ?? false);
      // The key this device holds is no longer the published one: another device rotated it (M6 §6.2). Follow it
      // (if it passes the adoption check) and ask for the new key.
      if (active == false && !(m?.full ?? true) && await _followSuccession()) {
        await _reopen();
        return;
      }
      if (active == true || (m?.full ?? false)) {
        // Groups need this device in the account's signed device list (docs/m4-groups.md §2).
        try {
          await messenger?.syncDevices();
        } catch (_) {}
        if (!(groups?.ready ?? true)) await _startGroups();
        unawaited(_ownSuccession()?.answerRecerts().catchError((_) => 0));
        unawaited(_checkBackup());
        unawaited(checkRemovedDevices());
        unawaited(_rekey()?.answer().catchError((_) => 0));
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

  /// Recovery, only from the user's confirmed tap: delete this device's unusable key database (the one it opened).
  /// The device is then one without the account key (M6 §4): the restore screen unlocks it again (backup, a link, or
  /// the explicit reset). Nothing here makes a key or touches the other devices. Message history on this device stays.
  Future<void> recoverKeys() async {
    final user = state.user;
    final token = _api.token;
    if (user == null || token == null) return;
    await _crypto.resetLocal(_corePath ?? 'keys-${user.id}');
    // A code-linked device's core is gone with it: it restores like any device without the key.
    await (await SharedPreferences.getInstance()).remove('linked-by-code-v1:${user.id}');
    await _teardown();
    state = state.copyWith(keysLocked: false);
    await _signedIn(user, token);
  }

  // ---------- The account key and its backup (docs/m6-account-key.md) ----------
  /// The backup service for this account, once signed in.
  Future<AccountBackup?> accountBackup() async {
    final user = state.user;
    if (user == null) return null;
    return AccountBackup(api: _api, crypto: ref.read(accountCryptoProvider), me: user);
  }

  /// §4: signed in on a device the account doesn't list, while it has a published key: the restore screen, and
  /// nothing that would mint or upload a key of this device's own.
  Future<bool> _needsRestore() async {
    final m = messenger, user = state.user;
    if (m == null || user == null || m.companion) return false;
    try {
      final published = (await _api.keyCount()).identity;
      if (published == null) return false; // A new account: this device makes the key.
      final id = (await m.device()).deviceId;
      final view = await _api.devices(user.username);
      final rows = (view['devices'] as List? ?? const []).cast<Map>();
      final listed = rows.any((r) => r['id'] == id && r['state'] == 'listed');
      if (listed && await _holdsAccountKey(Identity.fromJson(published), view['succession'])) return false;
      final backup = await _backupState();
      await m.bindSession(); // A pending device of the account, so it may list itself after the restore.
      state = state.copyWith(needsRestore: true, hasBackup: backup.has);
      // Its own reset has waited its week: this same session may now replace the account key (§6.5).
      final reset = state.keyReset;
      if (reset != null && reset.mine && DateTime.now().millisecondsSinceEpoch >= reset.executeAfter) {
        unawaited(_startOverNow().catchError((Object e) => state = state.copyWith(notice: 'Couldn’t reset the account key: $e')));
      }
      return true;
    } catch (_) {
      return false; // Offline: the next reconnect checks again.
    }
  }

  /// A listed full device holds the published key, or one it was rotated from (another device changed it: followed
  /// later in [_checkActive]). Anything else is a fresh key database, e.g. after [recoverKeys]: it holds no account key.
  Future<bool> _holdsAccountKey(Identity published, Object? succession) async {
    final mine = await _crypto.identity();
    if (mine == published) return true;
    return succession is List && succession.any((r) => r is Map && r['oldSign'] == mine.sign);
  }

  /// "Enter your passphrase" / "Use your recovery key" on the restore screen (§4): open the backup, hold the account
  /// key, publish the list naming this device, then start as a full device. Returns the account's safety number.
  Future<String> restoreFromBackup(Unlock unlock) async {
    final m = messenger, backup = await accountBackup();
    if (m == null || backup == null) throw StateError('Not signed in');
    final published = (await _api.keyCount()).identity;
    if (published == null) throw const StoreException("Your account has no key yet. Nothing to restore.");
    final identity = await backup.restore(unlock, published: Identity.fromJson(published));
    await m.publishNextList();
    final safety = identityFingerprint(identity);
    state = state.copyWith(needsRestore: false, restoredSafety: safety);
    await _reopen();
    return safety;
  }

  void dismissRestored() => state = state.copyWith(clearRestoredSafety: true);

  /// "I can't do any of these" (M5 §6, after its warning): new keys here; contacts see the code change. With a
  /// backup the server waits a week first, so any of the user's devices can cancel it (§6.5).
  Future<void> startOver() async {
    if (state.hasBackup ?? false) {
      final reset = await _api.requestKeyReset();
      state = state.copyWith(keyReset: (platform: _api.client, at: reset['at'] as int, executeAfter: reset['executeAfter'] as int, mine: true));
      return;
    }
    await _startOverNow();
  }

  Future<void> _startOverNow() async {
    state = state.copyWith(needsRestore: false, clearKeyReset: true);
    await useThisDevice();
  }

  /// A code-linked device unlocks itself with the passphrase (§2): the same backup, against its pinned account.
  Future<void> unlockWithBackup(Unlock unlock) async {
    final user = state.user, backup = await accountBackup();
    if (user == null || backup == null) return;
    final account = await ref.read(linkCryptoProvider).account();
    if (account == null) return; // Already full.
    await backup.restore(unlock, published: account.identity);
    await messenger?.publishNextList(); // Its own first list: its meta no longer says "linked by code".
    await (await SharedPreferences.getInstance()).remove('linked-by-code-v1:${user.id}');
    await _reopen();
  }

  Rekey? _rekey() {
    final m = messenger, s = store, g = groups, user = state.user;
    if (m == null || s == null || g == null || user == null) return null;
    return Rekey(
      api: _api,
      account: ref.read(accountCryptoProvider),
      link: ref.read(linkCryptoProvider),
      store: s,
      me: user,
      platform: _api.client,
      device: m.device,
      messenger: m,
      updateLeaf: g.sync.updateLeaf,
    );
  }

  /// A rekey answer is in: this device holds the account key now; reopen as a full device.
  Future<bool> _takeRekey() async {
    try {
      if (await _rekey()?.take() ?? false) {
        await _reopen();
        return true;
      }
    } catch (_) {
      // Not yet, or not for us: it asks again on the next start.
    }
    return false;
  }

  Future<bool> _linkedByCode() async {
    final user = state.user;
    return user != null && ((await SharedPreferences.getInstance()).getBool('linked-by-code-v1:${user.id}') ?? false);
  }

  /// Whether the account has a backup; offered once after sign-in on a full device when it has none.
  Future<void> _checkBackup() async {
    final user = state.user;
    if (user == null) return;
    try {
      final backup = await _backupState();
      final prefs = await SharedPreferences.getInstance(), key = 'backup-offered-v1:${user.id}';
      final offer = !backup.has && !(prefs.getBool(key) ?? false);
      if (offer) await prefs.setBool(key, true);
      state = state.copyWith(hasBackup: backup.has, offerBackup: offer, backupUpdatedAt: backup.updatedAt);
    } catch (_) {}
  }

  void dismissBackupOffer() => state = state.copyWith(offerBackup: false);

  /// A backup read (§3.5): our own devices read it to change it; a device our verified list didn't name at the time
  /// of the read is signing in. Judged from the frame and the list this device had pinned, never a later lookup.
  void _backupOpenedElsewhere(String? deviceId) {
    final m = messenger, user = state.user;
    if (m == null || user == null) return;
    final known = m.devices.pin(user.id, user.id)?.devices ?? const <String>[];
    if (deviceId != null && known.contains(deviceId)) return;
    state = state.copyWith(notice: 'Your backup was opened on a new device');
  }

  /// Refreshes [AppState.hasBackup] after a change on the backup screens.
  Future<void> backupChanged() async {
    try {
      final backup = await _backupState();
      state = state.copyWith(hasBackup: backup.has, backupUpdatedAt: backup.updatedAt);
    } catch (_) {}
  }

  /// Whether the account has a backup, from our own device view (`backup: {epoch, updatedAt} | null`): never the
  /// rate-limited, logged `GET /api/backup`, which only a restore or a change reads.
  Future<({bool has, int? updatedAt})> _backupState() async {
    final user = state.user ?? (throw StateError('Not signed in'));
    final view = await _api.devices(user.username);
    final backup = view['backup'], reset = view['reset'];
    final self = (await messenger?.device())?.deviceId;
    state = reset is Map && reset['requestedBy'] is Map
        ? state.copyWith(
            keyReset: (
              platform: (reset['requestedBy'] as Map)['platform'] as String? ?? 'web',
              at: reset['at'] as int,
              executeAfter: reset['executeAfter'] as int,
              mine: (reset['requestedBy'] as Map)['deviceId'] == self,
            ),
          )
        : state.copyWith(clearKeyReset: true);
    return backup is Map ? (has: true, updatedAt: backup['updatedAt'] as int?) : (has: false, updatedAt: null);
  }

  /// A listed device cancels someone's reset of the account key (M6 §6.5).
  Future<void> cancelKeyReset() async {
    await _api.cancelKeyReset();
    state = state.copyWith(clearKeyReset: true);
  }

  /// §6.2: a device our newest signed list names that the server says was revoked (cut off from a device that
  /// couldn't rotate): the user is asked to change the account key. The server can't make us rotate by itself.
  Future<void> checkRemovedDevices() async {
    final m = messenger, user = state.user;
    if (m == null || user == null || !m.full) return;
    try {
      final view = await _api.devices(user.username);
      final own = await _crypto.identity();
      final owned = verifiedOwnList(view, userId: user.id, aikSign: own.sign, pin: m.devices.pin(user.id, user.id), metaKey: deviceMetaKey(await _crypto.deviceMetaSignature(user.id)));
      final rows = (view['devices'] as List? ?? const []).cast<Map>();
      final gone = owned?.where((d) => rows.any((r) => r['id'] == d.deviceId && r['state'] == 'revoked')).firstOrNull;
      state = gone == null
          ? state.copyWith(clearRemovedListed: true)
          : state.copyWith(removedListed: (id: gone.deviceId, label: gone.described?['label'] ?? platformLabel(gone.described?['platform'] ?? 'web')));
    } catch (_) {}
  }

  /// Revoke from a full device (§6.2): "Remove <label> and change your account key?". Revokes, then replaces the
  /// account key (with the backup proof when there is a backup) so the removed device's copy is worthless.
  Future<void> removeAndRotate(String deviceId, {Unlock? unlock, bool alreadyRemoved = false}) async {
    final m = messenger, g = groups;
    if (m == null || g == null) throw StateError('Not signed in');
    // With a backup, removing a device needs the passphrase's proof (§6.3), checked here before anything changes.
    final backup = (state.hasBackup ?? false) ? await accountBackup() : null;
    final proven = await backup?.proveForRotation(unlock);
    if (!m.full) {
      // Not holding the key: only cut the device off; a device with the key finishes the job (§6.2).
      await _api.revokeDevice(deviceId, proof: proven?.proof);
      return;
    }
    if (!alreadyRemoved) {
      try {
        await _api.revokeDevice(deviceId, proof: proven?.proof);
      } on ApiException catch (error) {
        if (error.status != 404) rethrow; // Already revoked: finish the rotation.
      }
    }
    await AccountRotation(api: _api, account: ref.read(accountCryptoProvider), groups: ref.read(groupCryptoProvider), messenger: m, platform: _api.client, backup: backup)
        .rotate(removed: {deviceId}, proven: proven);
    state = state.copyWith(clearRemovedListed: true);
    await _reopen();
    await _recommitLeaves();
  }

  /// "Your account key was changed from …, which removed …" stays until the user dismisses it (M6 §6.2 step 3).
  Future<void> _keepKeyChangeNotice(String text) async {
    final user = state.user;
    if (user != null) await (await SharedPreferences.getInstance()).setString('key-change-notice-v1:${user.id}', text);
    state = state.copyWith(keyChangeNotice: text);
  }

  Future<void> dismissKeyChangeNotice() async {
    final user = state.user;
    if (user != null) await (await SharedPreferences.getInstance()).remove('key-change-notice-v1:${user.id}');
    state = state.copyWith(clearKeyChangeNotice: true);
  }

  Future<bool> _resumeRotation() async {
    final m = messenger;
    if (m == null || m.companion) return false;
    try {
      return await AccountRotation(
        api: _api,
        account: ref.read(accountCryptoProvider),
        groups: ref.read(groupCryptoProvider),
        messenger: m,
        platform: _api.client,
        backup: await accountBackup(),
      ).resume();
    } catch (_) {
      return false; // Offline: tried again on the next start.
    }
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
    if (contact == null || state.needsRestore) return;
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
  /// The user's decision binds to exactly the identity whose code was shown: if another key was pinned
  /// meanwhile, the core refuses (`mismatch`) and that one goes to review.
  Future<void> reviewedKey(String contactId, {required bool verified, required Identity? shown}) async {
    if (shown == null) return; // Nothing pinned yet: nothing to accept.
    verified ? await _crypto.setVerifiedFor(contactId, true, shown) : await _crypto.acceptChangeFor(contactId, shown);
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
