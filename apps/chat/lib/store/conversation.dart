import 'dart:convert';

/// Kinds of group conversation, as the delivery service names them (`POST /api/channels` `kind`).
enum GroupKindName {
  public('public'),
  private('private'),
  groupDm('group_dm'),
  dm('dm'),
  self('self');

  const GroupKindName(this.wire);
  final String wire;
  static GroupKindName fromWire(String value) => values.firstWhere((k) => k.wire == value, orElse: () => throw FormatException('Invalid kind $value'));

  /// Channels (public and private) list under Channels; group DMs (and MLS DMs) under Groups.
  bool get isChannel => this == public || this == private;
}

/// Where this device stands in a group.
enum Membership { active, left, removed }

/// A channel the delivery service froze after a member reported its latest commit (`seq`, `digest`).
class Frozen {
  const Frozen({required this.seq, required this.digest});
  final int seq;
  final String digest;
  Map<String, Object?> toJson() => {'seq': seq, 'digest': digest};
  factory Frozen.fromJson(Object? json) {
    if (json is! Map || json['seq'] is! int || json['digest'] is! String) throw const FormatException('Invalid frozen state');
    return Frozen(seq: json['seq'] as int, digest: json['digest'] as String);
  }
  @override
  bool operator ==(Object other) => other is Frozen && other.seq == seq && other.digest == digest;
  @override
  int get hashCode => Object.hash(seq, digest);
}

/// One group conversation on this device (schema v3 `conversations`): its MLS group id, what the members
/// named it (only public channel names are known to the server), where this device's log processing stands,
/// and local list state (pinned, unread). Membership itself lives in the MLS group, not here.
class GroupConversation {
  const GroupConversation({
    required this.id,
    required this.kind,
    required this.createdAt,
    this.name = '',
    this.topic = '',
    this.cursor = 0,
    this.membership = Membership.active,
    this.frozen,
    this.pinned = false,
    this.unread = 0,
    this.mentioned = false,
  });

  /// The MLS group id (22 base64url characters); also the message store's conversation id.
  final String id;
  final GroupKindName kind;
  final String name;
  final String topic;

  /// The last log `seq` this device processed.
  final int cursor;
  final Membership membership;
  final Frozen? frozen;
  final bool pinned;
  final int unread;

  /// An unread message mentions me.
  final bool mentioned;
  final int createdAt;

  bool get active => membership == Membership.active;

  GroupConversation copyWith({
    String? name,
    String? topic,
    int? cursor,
    Membership? membership,
    Frozen? frozen,
    bool clearFrozen = false,
    bool? pinned,
    int? unread,
    bool? mentioned,
    GroupKindName? kind,
  }) => GroupConversation(
    id: id,
    kind: kind ?? this.kind,
    createdAt: createdAt,
    name: name ?? this.name,
    topic: topic ?? this.topic,
    cursor: cursor ?? this.cursor,
    membership: membership ?? this.membership,
    frozen: clearFrozen ? null : frozen ?? this.frozen,
    pinned: pinned ?? this.pinned,
    unread: unread ?? this.unread,
    mentioned: mentioned ?? this.mentioned,
  );

  Map<String, Object?> toRow() => {
    'id': id,
    'kind': kind.wire,
    'name': name,
    'topic': topic,
    'cursor': cursor,
    'membership': membership.name,
    'frozen': frozen == null ? null : jsonEncode(frozen!.toJson()),
    'pinned': pinned ? 1 : 0,
    'unread': unread,
    'mentioned': mentioned ? 1 : 0,
    'created_at': createdAt,
  };

  static GroupConversation fromRow(Map<String, Object?> row) => GroupConversation(
    id: row['id']! as String,
    kind: GroupKindName.fromWire(row['kind']! as String),
    name: row['name'] as String? ?? '',
    topic: row['topic'] as String? ?? '',
    cursor: row['cursor'] as int? ?? 0,
    membership: Membership.values.byName(row['membership'] as String? ?? 'active'),
    frozen: row['frozen'] == null ? null : Frozen.fromJson(jsonDecode(row['frozen']! as String)),
    pinned: row['pinned'] == 1,
    unread: row['unread'] as int? ?? 0,
    mentioned: row['mentioned'] == 1,
    createdAt: row['created_at']! as int,
  );
}

final groupIdPattern = RegExp(r'^[A-Za-z0-9_-]{22}$');
