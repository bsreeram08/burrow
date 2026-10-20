import '../src/rust/api.dart' as core;
import 'group_crypto.dart';

/// The real MLS engine: `crates/chatcore` through flutter_rust_bridge. It shares the process-wide core
/// that [RustChatCrypto.init] opened, so group state is sealed in the same key database as the 1:1
/// sessions and fails closed the same way. Open the account with [RustChatCrypto.init] first.
class RustGroupCrypto implements GroupCrypto {
  const RustGroupCrypto();

  Future<T> _call<T>(Future<T> Function() work) async {
    try {
      return await work();
    } on core.CoreError catch (error) {
      throw CryptoException(error.message, code: error.code, keysLocked: error.code == 'storage');
    }
  }

  static core.MlsRoles _roles(GroupRoles roles) => core.MlsRoles(
    kind: roles.kind == GroupKind.dm ? core.MlsKind.dm : core.MlsKind.group,
    admins: roles.admins,
    joinPolicy: roles.joinPolicy == JoinPolicy.open ? core.MlsJoinPolicy.open : core.MlsJoinPolicy.invite,
    dm: roles.dm,
  );

  static GroupRoles _fromRoles(core.MlsRoles roles) => GroupRoles(
    kind: roles.kind == core.MlsKind.dm ? GroupKind.dm : GroupKind.group,
    admins: roles.admins,
    joinPolicy: roles.joinPolicy == core.MlsJoinPolicy.open ? JoinPolicy.open : JoinPolicy.invite,
    dm: roles.dm,
  );

  static GroupView _view(core.MlsGroupView v) => GroupView(groupId: v.groupId, epoch: v.epoch.toInt(), groupInfo: v.groupInfo, tree: v.tree);
  static GroupCommit _commit(core.MlsOutgoing o) =>
      GroupCommit(groupId: o.groupId, commit: o.commit, welcome: o.welcome, digest: o.digest, epoch: o.epoch.toInt());
  static GroupMember _member(core.MlsMember m) =>
      GroupMember(leaf: m.leaf, userId: m.userId, deviceId: m.deviceId, platform: m.platform, admin: m.admin);

  @override
  Future<GroupDevice> initDevice({required String userId, required String deviceId, required String platform, required int issuedAt}) => _call(() async {
    final cert = await core.mlsInitDevice(userId: userId, deviceId: deviceId, platform: platform, issuedAtMs: BigInt.from(issuedAt));
    return GroupDevice(
      userId: cert.userId,
      deviceId: cert.deviceId,
      platform: cert.platform,
      leafSigKey: cert.leafSigKey,
      aikSign: cert.aikSign,
      issuedAt: cert.issuedAt.toInt(),
    );
  });

  @override
  Future<List<String>> keyPackages(int count, {bool lastResort = false}) => _call(() => core.mlsKeyPackages(count: count, lastResort: lastResort));

  @override
  Future<GroupView> create(String groupId, GroupRoles roles) => _call(() async => _view(await core.mlsCreateGroup(groupId: groupId, roles: _roles(roles))));

  @override
  Future<GroupCommit> commit(String groupId, {List<String> adds = const [], List<GroupRemoval> removes = const [], GroupRoles? roles, bool update = false}) =>
      _call(() async => _commit(await core.mlsCommit(
        groupId: groupId,
        adds: adds,
        removes: [for (final r in removes) core.MlsRemoval(userId: r.userId, deviceId: r.deviceId)],
        roles: roles == null ? null : _roles(roles),
        update: update,
      )));

  @override
  Future<GroupView> mergeOwn(String groupId) => _call(() async => _view(await core.mlsMergeOwn(groupId: groupId)));

  @override
  Future<void> clearOwn(String groupId) => _call(() => core.mlsClearOwn(groupId: groupId));

  @override
  Future<PendingGroupCommit?> pendingCommit(String groupId) => _call(() async {
    final pending = await core.mlsPendingCommit(groupId: groupId);
    return pending == null ? null : PendingGroupCommit(digest: pending.digest, epoch: pending.epoch.toInt());
  });

  @override
  Future<GroupView> join(String welcome, String tree) => _call(() async => _view(await core.mlsJoin(welcome: welcome, tree: tree)));

  @override
  Future<GroupCommit> joinExternal(String groupInfo, String tree) => _call(() async => _commit(await core.mlsJoinExternal(groupInfo: groupInfo, tree: tree)));

  @override
  Future<void> forget(String groupId) => _call(() => core.mlsForgetGroup(groupId: groupId));

  @override
  Future<String> encrypt(String groupId, String plaintext) => _call(() => core.mlsEncrypt(groupId: groupId, plaintext: plaintext));

  @override
  Future<GroupProcessed> receive(String groupId, String message, {ProcessedKind? expect}) => _call(() async {
    final p = await core.mlsReceive(
      groupId: groupId,
      message: message,
      expect: switch (expect) {
        ProcessedKind.application => core.MlsExpect.application,
        ProcessedKind.commit || ProcessedKind.own || ProcessedKind.removed => core.MlsExpect.commit,
        null => null,
      },
    );
    return GroupProcessed(
      pendingId: p.pendingId,
      kind: ProcessedKind.values.byName(p.kind),
      plaintext: p.plaintext,
      sender: _member(p.sender),
      epoch: p.epoch.toInt(),
      digest: p.digest,
    );
  });

  @override
  Future<CommitCheck> commitAuthor(String groupId, String message) => _call(() async {
    final c = await core.mlsCommitAuthor(groupId: groupId, message: message);
    final author = c.author;
    return CommitCheck(authenticated: c.authenticated, signedContentInvalid: c.signedContentInvalid, cls: c.class_, author: author == null ? null : _member(author));
  });

  @override
  Future<String> signResolution(String groupId, {required String action, required int seq, required String digest, required String author}) =>
      _call(() => core.mlsSignResolution(groupId: groupId, action: action, seq: BigInt.from(seq), digest: digest, author: author));

  @override
  Future<String> verifyResolution(String groupId, {required String action, required int seq, required String digest, required String author, required String by, required String signature}) =>
      _call(() async => (await core.mlsVerifyResolution(groupId: groupId, action: action, seq: BigInt.from(seq), digest: digest, author: author, by: by, signature: signature)).userId);

  @override
  Future<void> receiveCommit(String pendingId) => _call(() => core.mlsReceiveCommit(pendingId: pendingId));

  @override
  Future<void> receiveAbort(String pendingId) => _call(() => core.mlsReceiveAbort(pendingId: pendingId));

  @override
  Future<List<GroupMember>> members(String groupId) => _call(() async => [for (final m in await core.mlsMembers(groupId: groupId)) _member(m)]);

  @override
  Future<GroupRoles> roles(String groupId) => _call(() async => _fromRoles(await core.mlsRoles(groupId: groupId)));

  @override
  Future<GroupView> view(String groupId) => _call(() async => _view(await core.mlsGroupView(groupId: groupId)));
}
