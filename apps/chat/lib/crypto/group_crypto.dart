/// The MLS (RFC 9420) boundary for groups and channels: `crates/chatcore`'s group engine
/// (API.md "Groups over MLS") through flutter_rust_bridge. Like [ChatCrypto], everything above it
/// treats commits, Welcomes, trees and messages as opaque base64url strings.
///
/// Errors are [CryptoException]s with chatcore's codes: `invalid` (policy or limit; permanent),
/// `poison` (a sequenced commit this device rejects; report it), `unknown-group`, `replay`,
/// `skip-limit`, `auth`, `malformed`, and `storage` (the key database itself: `keysLocked`).
library;

import 'chat_crypto.dart';

export 'chat_crypto.dart' show CryptoException;

enum GroupKind { group, dm }

enum JoinPolicy { open, invite }

/// The group's `roles` extension. A DM names its two users (sorted), who are also its admins.
class GroupRoles {
  const GroupRoles({required this.kind, required this.admins, required this.joinPolicy, this.dm});

  /// A group DM, private channel or public channel ([JoinPolicy.open]: anyone may join or add).
  const GroupRoles.group(this.admins, {this.joinPolicy = JoinPolicy.invite}) : kind = GroupKind.group, dm = null;

  final GroupKind kind;
  final List<String> admins;
  final JoinPolicy joinPolicy;
  final List<String>? dm;

  bool isAdmin(String userId) => admins.contains(userId);

  GroupRoles withAdmins(List<String> next) => GroupRoles(kind: kind, admins: next, joinPolicy: joinPolicy, dm: dm);

  @override
  bool operator ==(Object other) =>
      other is GroupRoles && other.kind == kind && other.joinPolicy == joinPolicy && _same(other.admins, admins) && _same(other.dm, dm);
  @override
  int get hashCode => Object.hash(kind, joinPolicy, Object.hashAll(admins), dm == null ? null : Object.hashAll(dm!));
}

bool _same(List<String>? a, List<String>? b) {
  if (a == null || b == null) return a == b;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Public state after a change: what the delivery service and external joiners need.
class GroupView {
  const GroupView({required this.groupId, required this.epoch, required this.groupInfo, required this.tree});
  final String groupId;
  final int epoch;
  final String groupInfo;
  final String tree;
}

/// A commit built here and kept pending until the delivery service answers for [epoch].
class GroupCommit {
  const GroupCommit({required this.groupId, required this.commit, required this.digest, required this.epoch, this.welcome});
  final String groupId;
  final String commit;
  final String? welcome;

  /// SHA-256 of the commit (hex): finds it in the log after an ambiguous submit.
  final String digest;
  final int epoch;
}

class PendingGroupCommit {
  const PendingGroupCommit({required this.digest, required this.epoch});
  final String digest;
  final int epoch;
}

class GroupMember {
  const GroupMember({required this.leaf, required this.userId, required this.deviceId, required this.platform, required this.admin});
  final int leaf;
  final String userId;
  final String deviceId;
  final String platform;
  final bool admin;
}

/// One device to remove ([deviceId] null: every device of [userId]).
class GroupRemoval {
  const GroupRemoval(this.userId, [this.deviceId]);
  final String userId;
  final String? deviceId;
}

/// [GroupCrypto.commitAuthor]'s verdict. A `tag` failure lies outside the author's signature, so a server could
/// have caused it in transit: it never blames the author.
class CommitCheck {
  const CommitCheck({required this.authenticated, required this.signedContentInvalid, required this.cls, this.author});
  final bool authenticated;
  final bool signedContentInvalid;

  /// `signed-content` or `tag`.
  final String cls;
  final GroupMember? author;

  /// The leaf index the engine reports for an external joiner's commit (not yet a member).
  static const externalLeaf = 0xFFFFFFFF;

  /// Only an authenticated member whose own signed content is invalid may be blamed (named and removed).
  GroupMember? get blame => authenticated && cls == 'signed-content' && author != null && author!.leaf != externalLeaf ? author : null;
}

enum ProcessedKind { application, commit, own, removed }

/// One log entry, authenticated (and decrypted) but not persisted: store what it carries, then
/// [GroupCrypto.receiveCommit]; [GroupCrypto.receiveAbort] lets redelivery process it again.
class GroupProcessed {
  const GroupProcessed({required this.pendingId, required this.kind, required this.sender, required this.epoch, this.plaintext, this.digest});
  final String pendingId;
  final ProcessedKind kind;
  final String? plaintext;
  final GroupMember sender;

  /// The epoch after processing.
  final int epoch;
  final String? digest;
}

/// This device's group credential (the AIK-signed certificate over its leaf key).
class GroupDevice {
  const GroupDevice({required this.userId, required this.deviceId, required this.platform, required this.leafSigKey, required this.aikSign, required this.issuedAt});
  final String userId;
  final String deviceId;
  final String platform;
  final String leafSigKey;
  final String aikSign;
  final int issuedAt;
}

abstract class GroupCrypto {
  /// Creates (once) this device's leaf key and its certificate, signed by the account identity key.
  /// Calling it again returns the same device.
  Future<GroupDevice> initDevice({required String userId, required String deviceId, required String platform, required int issuedAt});

  /// [count] one-time KeyPackages (1-100), or one last-resort one.
  Future<List<String>> keyPackages(int count, {bool lastResort = false});

  Future<GroupView> create(String groupId, GroupRoles roles);

  /// Builds a commit (added KeyPackages, removals, a roles change, a self-update) and keeps it pending.
  Future<GroupCommit> commit(String groupId, {List<String> adds = const [], List<GroupRemoval> removes = const [], GroupRoles? roles, bool update = false});
  Future<GroupView> mergeOwn(String groupId);
  Future<void> clearOwn(String groupId);
  Future<PendingGroupCommit?> pendingCommit(String groupId);

  Future<GroupView> join(String welcome, String tree);
  Future<GroupCommit> joinExternal(String groupInfo, String tree);
  Future<void> forget(String groupId);

  Future<String> encrypt(String groupId, String plaintext);
  /// [expect]: what the log entry's kind says it is ([ProcessedKind.application] or [ProcessedKind.commit]);
  /// a mismatch is refused before anything is staged.
  Future<GroupProcessed> receive(String groupId, String message, {ProcessedKind? expect});
  Future<void> receiveCommit(String pendingId);

  /// The core's verdict on a commit for the group's current epoch, checked against this device's own tree
  /// (nothing changes): whether its author is authenticated, and whether the failure is in what the author
  /// signed (`signed-content`) or only in a tag outside the signature (`tag`).
  Future<CommitCheck> commitAuthor(String groupId, String message);

  /// An admin's resolution of a frozen channel, signed with this device's MLS leaf key (m4-groups §7).
  Future<String> signResolution(String groupId, {required String action, required int seq, required String digest, required String author});

  /// Checks a resolution signed by device [by]: it must be an admin device in this device's own tree. Returns
  /// the signer's user id; throws [CryptoException] (`auth` bad signature, `invalid` otherwise).
  Future<String> verifyResolution(String groupId, {required String action, required int seq, required String digest, required String author, required String by, required String signature});
  Future<void> receiveAbort(String pendingId);

  Future<List<GroupMember>> members(String groupId);
  Future<GroupRoles> roles(String groupId);
  Future<GroupView> view(String groupId);
}
