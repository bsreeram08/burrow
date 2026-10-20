import 'dart:convert';

import 'rich.dart';

export 'rich.dart';

/// Delivery state, as in the web client: queued (on this device), sent (on
/// the server), delivered (the peer's device stored it), read (the peer showed
/// it; for incoming records: we told the peer we read it), uncertain (restored).
enum MessageStatus { queued, sent, delivered, read, uncertain }

/// Statuses only move forward; `uncertain` sits outside the order and may only become delivered or read.
int statusRank(MessageStatus s) => switch (s) {
  MessageStatus.queued => 0,
  MessageStatus.sent => 1,
  MessageStatus.uncertain => 1,
  MessageStatus.delivered => 2,
  MessageStatus.read => 3,
};

/// `system` rows are group events written by this device ("alice added bob"): never sent, never counted.
enum Direction { incoming, outgoing, system }

/// One stored message. Only content and delivery metadata are ever stored:
/// never tokens, keys or UI state (same rule as chat-store.js). An edit keeps
/// the original [text] (so a redelivered original is still a duplicate, not a
/// conflict) and stores the latest [editedText] beside it.
class ChatMessage {
  const ChatMessage({
    required this.id,
    required this.conversationId,
    required this.direction,
    required this.text,
    required this.createdAt,
    required this.status,
    this.expiresAt,
    this.replyTo,
    this.attachment,
    this.link,
    this.editedText,
    this.editedAt,
    this.reactions = const Reactions(),
    this.sender,
    this.senderName,
    this.mentions = const [],
    this.readBy = const [],
  });

  final String id;
  final String conversationId;
  final Direction direction;
  final String text;
  final int createdAt;
  final MessageStatus status;
  final int? expiresAt;
  final ReplyTo? replyTo;
  final Attachment? attachment;
  final LinkPreview? link;
  final String? editedText;
  final int? editedAt;
  final Reactions reactions;

  /// Incoming group messages (m4-groups §10 `from`): the MLS sender's user id. Null in 1:1 chats.
  final String? sender;

  /// Incoming group messages (`fromName`): the sender's username when it arrived, so it still reads right
  /// after they leave.
  final String? senderName;

  /// Group messages: the user ids the text mentions (`@username`), for highlighting and notifications.
  final List<String> mentions;

  /// Outgoing group messages: the members whose `read` named this message.
  final List<String> readBy;

  bool get outgoing => direction == Direction.outgoing;
  bool get system => direction == Direction.system;
  bool get inGroup => conversationId.length == 22;
  bool expired(int now) => expiresAt != null && expiresAt! <= now;

  /// What to show: the latest edit, else the original.
  String get body => editedText ?? text;
  bool get edited => editedAt != null;

  ChatMessage copyWith({MessageStatus? status, String? editedText, int? editedAt, Reactions? reactions, List<String>? readBy}) => ChatMessage(
    id: id,
    conversationId: conversationId,
    direction: direction,
    text: text,
    createdAt: createdAt,
    status: status ?? this.status,
    expiresAt: expiresAt,
    replyTo: replyTo,
    attachment: attachment,
    link: link,
    editedText: editedText ?? this.editedText,
    editedAt: editedAt ?? this.editedAt,
    reactions: reactions ?? this.reactions,
    sender: sender,
    senderName: senderName,
    mentions: mentions,
    readBy: readBy ?? this.readBy,
  );

  ChatMessage withStatus(MessageStatus next) => copyWith(status: next);

  /// Everything the sender chose (not status, edits or reactions): a reused id with different content is a conflict.
  bool sameContent(ChatMessage other) =>
      id == other.id &&
      conversationId == other.conversationId &&
      direction == other.direction &&
      text == other.text &&
      createdAt == other.createdAt &&
      expiresAt == other.expiresAt &&
      replyTo == other.replyTo &&
      attachment == other.attachment &&
      link == other.link &&
      sender == other.sender &&
      _sameList(mentions, other.mentions);

  /// The encrypted wire payload (`{v:1, type:'message', ...}`); optional parts are omitted when absent.
  /// `mentions` only in groups.
  Map<String, Object?> toPayload() => {
    'v': 1,
    'type': 'message',
    'id': id,
    'text': text,
    'createdAt': createdAt,
    'expiresAt': expiresAt,
    if (replyTo != null) 'replyTo': replyTo!.toJson(),
    if (attachment != null) 'attachment': attachment!.toJson(),
    if (link != null) 'link': link!.toJson(),
    if (mentions.isNotEmpty) 'mentions': mentions,
  };

  Map<String, Object?> toRow() => {
    'conversation_id': conversationId,
    'id': id,
    'direction': direction.name,
    'text': text,
    'created_at': createdAt,
    'status': status.name,
    'expires_at': expiresAt,
    'reply_to': replyTo == null ? null : jsonEncode(replyTo!.toJson()),
    'attachment': attachment == null ? null : jsonEncode(attachment!.toJson()),
    'link': link == null ? null : jsonEncode(link!.toJson()),
    'edited_text': editedText,
    'edited_at': editedAt,
    'reactions': reactions.isEmpty ? null : jsonEncode(reactions.toJson()),
    'sender': sender,
    'sender_name': senderName,
    'mentions': mentions.isEmpty ? null : jsonEncode(mentions),
    'read_by': readBy.isEmpty ? null : jsonEncode(readBy),
  };

  static ChatMessage fromRow(Map<String, Object?> row) {
    Object? json(String column) {
      final raw = row[column];
      return raw == null ? null : jsonDecode(raw as String);
    }

    final text = row['text']! as String;
    final ChatMessage message;
    try {
      message = ChatMessage(
        id: row['id']! as String,
        conversationId: row['conversation_id']! as String,
        direction: Direction.values.byName(row['direction']! as String),
        text: text,
        createdAt: row['created_at']! as int,
        status: MessageStatus.values.byName(row['status']! as String),
        expiresAt: row['expires_at'] as int?,
        replyTo: row['reply_to'] == null ? null : ReplyTo.fromJson(json('reply_to')),
        attachment: row['attachment'] == null ? null : Attachment.fromJson(json('attachment')),
        link: row['link'] == null ? null : LinkPreview.fromJson(json('link'), text),
        editedText: row['edited_text'] as String?,
        editedAt: row['edited_at'] as int?,
        reactions: row['reactions'] == null ? const Reactions() : Reactions.fromJson(json('reactions')),
        sender: row['sender'] as String?,
        senderName: row['sender_name'] as String?,
        mentions: row['mentions'] == null ? const [] : _ids(json('mentions'), maxMentions),
        readBy: row['read_by'] == null ? const [] : _ids(json('read_by'), maxReaders),
      );
    } on FormatException {
      throw const StoreException('Invalid chat message.', code: 'invalid');
    }
    return validate(message);
  }
}

class StoreException implements Exception {
  const StoreException(this.message, {this.code});
  final String message;

  /// Deterministic rejections carry a code so an envelope is acknowledged and
  /// discarded instead of retried forever: invalid, conflict, conversation-full, full.
  final String? code;
  @override
  String toString() => message;
}

const maxMessages = 2000;
const maxPerConversation = 500;
const clockSkewMs = 300000;
const maxAgeMs = 30 * 86400000;
const maxTextBytes = 4096;

/// The whole encoded payload of any envelope (§1).
const maxPayloadBytes = 16 * 1024;
const _maxDate = 8640000000000000;
const _maxSafeInt = 9007199254740991;

final uuidPattern = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', caseSensitive: false);
/// A 1:1 pair id (43 characters) or an MLS group id (22).
final conversationPattern = RegExp(r'^([A-Za-z0-9_-]{43}|[A-Za-z0-9_-]{22})$');
final userIdPattern = RegExp(r'^[A-Za-z0-9_-]{22}$');
final usernamePattern = RegExp(r'^[a-z0-9_]{3,20}$');
const maxMentions = 64;
const maxReaders = 1000;

/// Groups keep their newest 500 messages each (older ones are evicted), within the device-wide cap.
const groupKeep = 500;

bool _sameList(List<String> a, List<String> b) => a.length == b.length && [for (var i = 0; i < a.length; i++) a[i] == b[i]].every((x) => x);

/// 1–[max] distinct user ids.
List<String> _ids(Object? json, int max) {
  if (json is! List || json.isEmpty || json.length > max || !json.every((v) => v is String && userIdPattern.hasMatch(v)) || json.toSet().length != json.length) {
    throw const FormatException('Invalid user ids');
  }
  return List<String>.unmodifiable(json.cast<String>());
}

/// Strict `mentions` from a payload: 1–64 distinct user ids.
List<String> mentionsFromJson(Object? json) => _ids(json, maxMentions);

/// Message text bounds: at most 4096 UTF-8 bytes, empty only beside an attachment.
bool validText(String text, {required bool hasAttachment}) => (text.isNotEmpty || hasAttachment) && utf8.encode(text).length <= maxTextBytes;

bool validTime(int value) => value >= 0 && value <= _maxDate && value <= _maxSafeInt;

/// The same rules every record in chat-store.js meets, plus the phase 1 parts.
/// Returns the canonical record (lowercase id) or throws [StoreException] with code `invalid`.
ChatMessage validate(ChatMessage message) {
  final expiresAt = message.expiresAt, editedText = message.editedText, editedAt = message.editedAt;
  final ok =
      uuidPattern.hasMatch(message.id) &&
      conversationPattern.hasMatch(message.conversationId) &&
      validText(message.text, hasAttachment: message.attachment != null) &&
      validTime(message.createdAt) &&
      (expiresAt == null ||
          (expiresAt > message.createdAt &&
              expiresAt <= (message.createdAt + maxAgeMs < _maxDate ? message.createdAt + maxAgeMs : _maxDate))) &&
      (message.link == null || message.text.contains(message.link!.url)) &&
      ((editedText == null) == (editedAt == null)) &&
      (editedText == null || validText(editedText, hasAttachment: message.attachment != null)) &&
      (editedAt == null || validTime(editedAt)) &&
      _groupFieldsOk(message);
  if (!ok) throw const StoreException('Invalid chat message.', code: 'invalid');
  return ChatMessage(
    id: message.id.toLowerCase(),
    conversationId: message.conversationId,
    direction: message.direction,
    text: message.text,
    createdAt: message.createdAt,
    status: message.status,
    expiresAt: expiresAt,
    replyTo: message.replyTo,
    attachment: message.attachment,
    link: message.link,
    editedText: editedText,
    editedAt: editedAt,
    reactions: message.reactions,
    sender: message.sender,
    senderName: message.senderName,
    mentions: message.mentions,
    readBy: message.readBy,
  );
}

/// m4-groups §10: incoming group rows always name their sender, outgoing ones never; names only on incoming;
/// mentions and read-by only in groups, read-by only on our own messages. System rows: group lines, and a 1:1 chat's move to MLS (m5 §8).
bool _groupFieldsOk(ChatMessage m) {
  final group = m.inGroup, incoming = m.direction == Direction.incoming;
  if (m.system) return m.sender == null && m.senderName == null && m.mentions.isEmpty && m.readBy.isEmpty && m.attachment == null;
  if (!group) return m.sender == null && m.senderName == null && m.mentions.isEmpty && m.readBy.isEmpty;
  return incoming == (m.sender != null) &&
      (m.sender == null || userIdPattern.hasMatch(m.sender!)) &&
      (m.senderName == null || (incoming && usernamePattern.hasMatch(m.senderName!))) &&
      m.mentions.length <= maxMentions &&
      m.mentions.every(userIdPattern.hasMatch) &&
      (m.readBy.isEmpty || m.outgoing) &&
      m.readBy.length <= maxReaders &&
      m.readBy.every(userIdPattern.hasMatch);
}
