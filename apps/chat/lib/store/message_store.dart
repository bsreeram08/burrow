import 'dart:async';
import 'dart:convert';

import 'package:sqflite/sqflite.dart';

import 'message.dart';

enum ReceiveResult { stored, duplicate, expired }

/// Device-local message history (SQLite). Port of chat-store.js: the same
/// validation, the 2,000-message device cap and the 500-incoming-per-conversation
/// cap, idempotent receive, and burn by conversation. Expired disappearing
/// messages are deleted whenever the store is read.
class MessageStore {
  MessageStore(this._db, {int Function()? now}) : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final Database _db;
  final int Function() _now;
  final _changes = StreamController<String?>.broadcast();

  /// Emits the conversation id that changed (null: everything).
  Stream<String?> get changes => _changes.stream;

  static Future<MessageStore> open(DatabaseFactory factory, String path, {int Function()? now}) async {
    final db = await factory.openDatabase(
      path,
      options: OpenDatabaseOptions(
        version: schemaVersion,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE messages (
              conversation_id TEXT NOT NULL, id TEXT NOT NULL, direction TEXT NOT NULL, text TEXT NOT NULL,
              created_at INTEGER NOT NULL, status TEXT NOT NULL, expires_at INTEGER,
              PRIMARY KEY (conversation_id, id))''');
          await db.execute('CREATE INDEX messages_by_time ON messages (conversation_id, created_at)');
          await _addPhase1Columns(db);
        },
        // Additive only: every existing row keeps its content and reads back with the new parts absent.
        onUpgrade: (db, from, _) async {
          if (from < 2) await _addPhase1Columns(db);
        },
      ),
    );
    return MessageStore(db, now: now);
  }

  /// v2 (phase 1): reply, attachment, link preview, the latest edit and reactions, each as nullable columns.
  static const schemaVersion = 2;

  static Future<void> _addPhase1Columns(DatabaseExecutor db) async {
    for (final column in ['reply_to TEXT', 'attachment TEXT', 'link TEXT', 'edited_text TEXT', 'edited_at INTEGER', 'reactions TEXT']) {
      await db.execute('ALTER TABLE messages ADD COLUMN $column');
    }
  }

  Future<void> close() async {
    await _changes.close();
    await _db.close();
  }

  Future<void> _sweep(DatabaseExecutor tx, int now) =>
      tx.delete('messages', where: 'expires_at IS NOT NULL AND expires_at <= ?', whereArgs: [now]);

  Future<ChatMessage?> _get(DatabaseExecutor tx, String conversationId, String id) async {
    final rows = await tx.query('messages', where: 'conversation_id = ? AND id = ?', whereArgs: [conversationId, id], limit: 1);
    return rows.isEmpty ? null : ChatMessage.fromRow(rows.single);
  }

  Future<int> _count(DatabaseExecutor tx, [String? where, List<Object?>? args]) async =>
      Sqflite.firstIntValue(await tx.rawQuery('SELECT COUNT(*) FROM messages${where == null ? '' : ' WHERE $where'}', args)) ?? 0;

  /// Stores an outgoing message (or a status update of the same record).
  Future<ChatMessage> put(ChatMessage value) async {
    final message = validate(value);
    final result = await _db.transaction((tx) async {
      final now = _now();
      await _sweep(tx, now);
      if (message.expired(now)) throw const StoreException('This disappearing message has expired.');
      final previous = await _get(tx, message.conversationId, message.id);
      if (previous == null && await _count(tx) >= maxMessages) {
        throw const StoreException('This device holds 2,000 messages. Clear chat history before adding more.', code: 'full');
      }
      if (previous != null && !previous.sameContent(message)) {
        throw const StoreException('A duplicate message has conflicting content or expiration.', code: 'conflict');
      }
      // Keep what happened after the first write: a later status, the latest edit, reactions.
      var next = message;
      if (previous != null) {
        next = next.copyWith(
          status: statusRank(previous.status) > statusRank(message.status) ? previous.status : null,
          editedText: previous.editedText,
          editedAt: previous.editedAt,
          reactions: previous.reactions.isEmpty ? null : previous.reactions,
        );
      }
      await tx.insert('messages', next.toRow(), conflictAlgorithm: ConflictAlgorithm.replace);
      return next;
    });
    _changes.add(message.conversationId);
    return result;
  }

  /// Stores one decrypted incoming payload, idempotent by id. Deterministic
  /// rejections are coded (see [StoreException.code]); nothing is ever evicted.
  Future<ReceiveResult> receive(String conversationId, Map<String, Object?> payload) async {
    final now = _now();
    ChatMessage message;
    try {
      final expiresAt = payload['expiresAt'];
      final text = payload['text']! as String;
      message = validate(
        ChatMessage(
          id: payload['id']! as String,
          conversationId: conversationId,
          direction: Direction.incoming,
          text: text,
          createdAt: payload['createdAt']! as int,
          status: MessageStatus.delivered,
          expiresAt: expiresAt as int?,
          replyTo: payload.containsKey('replyTo') ? ReplyTo.fromJson(payload['replyTo']) : null,
          attachment: payload.containsKey('attachment') ? Attachment.fromJson(payload['attachment']) : null,
          link: payload.containsKey('link') ? LinkPreview.fromJson(payload['link'], text) : null,
        ),
      );
    } on StoreException {
      rethrow;
    } catch (_) {
      throw const StoreException('Invalid incoming message.', code: 'invalid');
    }
    if (message.createdAt > now + clockSkewMs) throw const StoreException('Incoming message is dated in the future.', code: 'invalid');
    if (message.expired(now)) return ReceiveResult.expired;
    final result = await _db.transaction((tx) async {
      await _sweep(tx, now);
      final previous = await _get(tx, conversationId, message.id);
      if (previous != null) {
        if (!previous.sameContent(message)) throw const StoreException('A message identifier was reused with different content.', code: 'conflict');
        return ReceiveResult.duplicate;
      }
      if (await _count(tx, "conversation_id = ? AND direction = 'incoming'", [conversationId]) >= maxPerConversation) {
        throw const StoreException('This conversation holds 500 incoming messages.', code: 'conversation-full');
      }
      if (await _count(tx) >= maxMessages) {
        throw const StoreException('This device holds 2,000 messages. Clear chat history to receive more.', code: 'full');
      }
      await tx.insert('messages', message.toRow());
      return ReceiveResult.stored;
    });
    if (result == ReceiveResult.stored) _changes.add(conversationId);
    return result;
  }

  /// A late receipt or send completion never recreates cleared content, never
  /// downgrades (queued < sent < delivered < read), and never turns restored history back into a queue.
  Future<bool> setStatus(String conversationId, String id, MessageStatus status) async {
    final changed = await _db.transaction((tx) => _advance(tx, conversationId, id, status));
    if (changed) _changes.add(conversationId);
    return changed;
  }

  Future<bool> _advance(DatabaseExecutor tx, String conversationId, String id, MessageStatus status, {Direction? only}) async {
    final previous = await _get(tx, conversationId, id.toLowerCase());
    if (previous == null || (only != null && previous.direction != only)) return false;
    if (previous.status == MessageStatus.uncertain && (status == MessageStatus.queued || status == MessageStatus.sent)) return false;
    if (statusRank(status) <= statusRank(previous.status)) return false;
    await tx.update('messages', {'status': status.name}, where: 'conversation_id = ? AND id = ?', whereArgs: [conversationId, previous.id]);
    return true;
  }

  /// Marks [ids] read, touching only records in [direction]: the peer's `read` for our outgoing
  /// messages, or our own reading of incoming ones. Returns the ids that changed.
  Future<List<String>> markRead(String conversationId, Iterable<String> ids, {required Direction direction}) async {
    final changed = await _db.transaction((tx) async {
      final out = <String>[];
      for (final id in ids) {
        if (await _advance(tx, conversationId, id, MessageStatus.read, only: direction)) out.add(id.toLowerCase());
      }
      return out;
    });
    if (changed.isNotEmpty) _changes.add(conversationId);
    return changed;
  }

  /// Adds or removes one person's reaction. Unknown targets are ignored (false); so is a no-op or a 21st distinct emoji.
  Future<bool> react(String conversationId, String target, {required String who, required String emoji, required bool on}) async {
    if (!Reactions.people.contains(who) || !isReactionEmoji(emoji)) throw const StoreException('Invalid reaction.', code: 'invalid');
    final changed = await _db.transaction((tx) async {
      final previous = await _get(tx, conversationId, target.toLowerCase());
      if (previous == null) return false;
      final next = previous.reactions.toggle(who, emoji, on);
      if (next == null) return false;
      await tx.update(
        'messages',
        {'reactions': next.isEmpty ? null : jsonEncode(next.toJson())},
        where: 'conversation_id = ? AND id = ?',
        whereArgs: [conversationId, previous.id],
      );
      return true;
    });
    if (changed) _changes.add(conversationId);
    return changed;
  }

  /// Applies an edit by the message's [author] only, last [editedAt] wins. Unknown targets, someone
  /// else's message, attachments' text and older edits are ignored (false); bad text is `invalid`.
  Future<bool> edit(String conversationId, String target, {required String text, required int editedAt, required Direction author}) async {
    if (!validTime(editedAt)) throw const StoreException('Invalid edit.', code: 'invalid');
    final changed = await _db.transaction((tx) async {
      final previous = await _get(tx, conversationId, target.toLowerCase());
      if (previous == null || previous.direction != author || previous.attachment != null) return false;
      if (!validText(text, hasAttachment: false)) throw const StoreException('Invalid edit.', code: 'invalid');
      if (previous.editedAt != null && previous.editedAt! >= editedAt) return false;
      final next = validate(previous.copyWith(editedText: text, editedAt: editedAt));
      await tx.update('messages', next.toRow(), where: 'conversation_id = ? AND id = ?', whereArgs: [conversationId, previous.id]);
      return true;
    });
    if (changed) _changes.add(conversationId);
    return changed;
  }

  Future<ChatMessage?> get(String conversationId, String id) => _get(_db, conversationId, id.toLowerCase());

  /// Oldest first.
  Future<List<ChatMessage>> list(String conversationId) async {
    final now = _now();
    await _sweep(_db, now);
    final rows = await _db.query('messages', where: 'conversation_id = ?', whereArgs: [conversationId], orderBy: 'created_at, id');
    return rows.map(ChatMessage.fromRow).toList();
  }

  Future<List<ChatMessage>> queued() async {
    final rows = await _db.query('messages', where: "direction = 'outgoing' AND status = 'queued'", orderBy: 'created_at, id');
    return rows.map(ChatMessage.fromRow).where((m) => !m.expired(_now())).toList();
  }

  /// The newest message of each conversation, for the chat list.
  Future<Map<String, ChatMessage>> latest() async {
    await _sweep(_db, _now());
    final rows = await _db.rawQuery(
      'SELECT m.* FROM messages m JOIN (SELECT conversation_id, MAX(created_at) AS t FROM messages GROUP BY conversation_id) l '
      'ON m.conversation_id = l.conversation_id AND m.created_at = l.t ORDER BY m.id',
    );
    return {for (final row in rows) row['conversation_id']! as String: ChatMessage.fromRow(row)};
  }

  Future<void> removeConversation(String conversationId) async {
    if (!conversationPattern.hasMatch(conversationId)) throw const StoreException('Invalid conversation.');
    await _db.delete('messages', where: 'conversation_id = ?', whereArgs: [conversationId]);
    _changes.add(conversationId);
  }

  Future<void> clear() async {
    await _db.delete('messages');
    _changes.add(null);
  }
}
