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

enum Direction { incoming, outgoing }

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

  bool get outgoing => direction == Direction.outgoing;
  bool expired(int now) => expiresAt != null && expiresAt! <= now;

  /// What to show: the latest edit, else the original.
  String get body => editedText ?? text;
  bool get edited => editedAt != null;

  ChatMessage copyWith({MessageStatus? status, String? editedText, int? editedAt, Reactions? reactions}) => ChatMessage(
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
      link == other.link;

  /// The encrypted wire payload (`{v:1, type:'message', ...}`); optional parts are omitted when absent.
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
final conversationPattern = RegExp(r'^[A-Za-z0-9_-]{43}$');

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
      (editedAt == null || validTime(editedAt));
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
  );
}
