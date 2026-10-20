import 'dart:async';
import 'dart:convert';

import 'package:sqflite/sqflite.dart';
import 'package:uuid/uuid.dart';

import 'conversation.dart';
import 'message.dart';

export 'conversation.dart';

enum ReceiveResult { stored, duplicate, expired }

String _uuidV4() => const Uuid().v4();

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
          await _addGroupParts(db);
          await _addDmParts(db);
        },
        // Additive only: every existing row keeps its content and reads back with the new parts absent.
        onUpgrade: (db, from, _) async {
          if (from < 2) await _addPhase1Columns(db);
          if (from < 3) await _addGroupParts(db);
          if (from < 4) await _addDmParts(db);
        },
      ),
    );
    return MessageStore(db, now: now);
  }

  /// v2 (phase 1): reply, attachment, link preview, the latest edit and reactions, each as nullable columns.
  /// v3 (M4 groups, docs/m4-groups.md §10): sender, sender name, mentions and read-by of group messages,
  /// system rows, and a `conversations` table for groups.
  /// v4 (M5, docs/m5-linking.md §8): a 1:1 chat's DM group remembers its peer, whether it was checked, and when the chat moved.
  static const schemaVersion = 4;

  static Future<void> _addDmParts(DatabaseExecutor db) async {
    await db.execute('ALTER TABLE conversations ADD COLUMN peer TEXT');
    await db.execute('ALTER TABLE conversations ADD COLUMN dm_checked_peer TEXT');
    await db.execute('ALTER TABLE conversations ADD COLUMN moved_at INTEGER');
    // Channel names and topics from a link bundle (m5 §3 step 3), until this device joins those channels.
    await db.execute('CREATE TABLE bundle_names (id TEXT PRIMARY KEY, name TEXT NOT NULL, topic TEXT NOT NULL)');
  }

  static Future<void> _addGroupParts(DatabaseExecutor db) async {
    for (final column in ['sender TEXT', 'sender_name TEXT', 'mentions TEXT', 'read_by TEXT']) {
      await db.execute('ALTER TABLE messages ADD COLUMN $column');
    }
    await db.execute('''
      CREATE TABLE conversations (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', topic TEXT NOT NULL DEFAULT '',
        cursor INTEGER NOT NULL DEFAULT 0, membership TEXT NOT NULL DEFAULT 'active', frozen TEXT,
        pinned INTEGER NOT NULL DEFAULT 0, unread INTEGER NOT NULL DEFAULT 0, mentioned INTEGER NOT NULL DEFAULT 0, meta_at INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL)''');
  }

  static Future<void> _addPhase1Columns(DatabaseExecutor db) async {
    for (final column in ['reply_to TEXT', 'attachment TEXT', 'link TEXT', 'edited_text TEXT', 'edited_at INTEGER', 'reactions TEXT']) {
      await db.execute('ALTER TABLE messages ADD COLUMN $column');
    }
  }

  Future<void> close() async {
    await _changes.close();
    await _groupChanges.close();
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
          readBy: previous.readBy.isEmpty ? null : previous.readBy,
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
  /// In a group (22-character id) [sender] and [senderName] are the MLS sender and their username, never
  /// payload fields; `mentions` is allowed only there, and the group keeps its newest [groupKeep] messages.
  Future<ReceiveResult> receive(String conversationId, Map<String, Object?> payload, {String? sender, String? senderName}) async {
    final now = _now();
    final group = conversationId.length == 22;
    ChatMessage message;
    try {
      if (!group && payload.containsKey('mentions')) throw const FormatException('mentions outside a group');
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
          sender: group ? sender : null,
          senderName: group ? senderName : null,
          mentions: payload.containsKey('mentions') ? mentionsFromJson(payload['mentions']) : const [],
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
      if (group) {
        // A group keeps its newest 500: the oldest go instead of refusing the new one, within the device cap.
        final mine = await _count(tx, 'conversation_id = ?', [conversationId]);
        final over = [0, mine + 1 - groupKeep, await _count(tx) + 1 - maxMessages].reduce((a, b) => a > b ? a : b);
        if (over > mine) throw const StoreException('This device holds 2,000 messages. Clear chat history to receive more.', code: 'full');
        if (over > 0) {
          await tx.rawDelete(
            'DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages WHERE conversation_id = ? ORDER BY created_at, id LIMIT ?)',
            [conversationId, over],
          );
        }
        await tx.insert('messages', message.toRow());
        return ReceiveResult.stored;
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

  /// A group member read these messages of ours: [reader] joins each one's read-by (unknown ids and other
  /// people's messages are ignored). Returns the ids that changed.
  Future<List<String>> markReadBy(String conversationId, Iterable<String> ids, String reader) async {
    if (conversationId.length != 22 || !userIdPattern.hasMatch(reader)) throw const StoreException('Invalid read receipt.', code: 'invalid');
    final changed = await _db.transaction((tx) async {
      final out = <String>[];
      for (final id in ids.map((i) => i.toLowerCase()).toSet()) {
        final previous = await _get(tx, conversationId, id);
        if (previous == null || !previous.outgoing || previous.readBy.contains(reader) || previous.readBy.length >= maxReaders) continue;
        await tx.update('messages', {'read_by': jsonEncode([...previous.readBy, reader])}, where: 'conversation_id = ? AND id = ?', whereArgs: [conversationId, id]);
        out.add(id);
      }
      return out;
    });
    if (changed.isNotEmpty) _changes.add(conversationId);
    return changed;
  }

  /// A system line in a group ("alice added bob"), dated [at].
  Future<void> note(String conversationId, String text, {int? at}) async {
    await _db.transaction((tx) async {
      final over = await _count(tx) + 1 - maxMessages;
      if (over > 0) return; // Never evict history for a notice.
      await tx.insert(
        'messages',
        validate(ChatMessage(id: _uuidV4(), conversationId: conversationId, direction: Direction.system, text: text, createdAt: at ?? _now(), status: MessageStatus.delivered)).toRow(),
      );
    });
    _changes.add(conversationId);
  }

  /// History a linked device received in its bundle (m5 §2): records in the shape both clients store
  /// (`exportRecord`), added where absent, within the device cap; anything malformed is skipped. Returns how many.
  Future<int> importLinked(List<Object?> records) async {
    Object? text(Object? value) => value == null ? null : jsonEncode(value);
    var added = 0;
    await _db.transaction((tx) async {
      for (final r in records) {
        if (r is! Map || await _count(tx) >= maxMessages) continue;
        try {
          final m = ChatMessage.fromRow({
            'id': r['id'], 'conversation_id': r['conversationId'], 'direction': r['direction'], 'text': r['text'],
            'created_at': r['createdAt'], 'status': r['status'] == 'queued' ? 'uncertain' : r['status'], 'expires_at': r['expiresAt'],
            'reply_to': text(r['replyTo']), 'attachment': text(r['attachment']), 'link': text(r['link']),
            'edited_text': r['editedText'], 'edited_at': r['editedAt'], 'reactions': text(r['reactions']),
            'sender': r['from'], 'sender_name': r['fromName'], 'mentions': text(r['mentions']),
          });
          if (m.system || m.expired(_now())) continue;
          added += await tx.insert('messages', m.toRow(), conflictAlgorithm: ConflictAlgorithm.ignore) > 0 ? 1 : 0;
        } catch (_) {
          // Not a record this store accepts: skipped.
        }
      }
    });
    if (added > 0) _changes.add(null);
    return added;
  }

  /// Remembers channel names and topics from a link bundle until this device joins those channels.
  Future<void> putBundleNames(Map<String, ({String name, String topic})> names) async {
    await _db.transaction((tx) async {
      for (final e in names.entries) {
        await tx.insert('bundle_names', {'id': e.key, 'name': e.value.name, 'topic': e.value.topic}, conflictAlgorithm: ConflictAlgorithm.replace);
      }
    });
  }

  /// The bundle's name and topic for a channel this device is joining, once (then forgotten).
  Future<({String name, String topic})?> takeBundleName(String id) async {
    final rows = await _db.query('bundle_names', where: 'id = ?', whereArgs: [id]);
    if (rows.isEmpty) return null;
    await _db.delete('bundle_names', where: 'id = ?', whereArgs: [id]);
    return (name: rows.single['name']! as String, topic: rows.single['topic']! as String);
  }

  /// Adds or removes one person's reaction. Unknown targets are ignored (false); so is a no-op or a 21st distinct emoji.
  Future<bool> react(String conversationId, String target, {required String who, required String emoji, required bool on}) async {
    final group = conversationId.length == 22;
    final person = who == 'me' || (group ? userIdPattern.hasMatch(who) : who == 'peer');
    if (!person || !isReactionEmoji(emoji)) throw const StoreException('Invalid reaction.', code: 'invalid');
    final changed = await _db.transaction((tx) async {
      final previous = await _get(tx, conversationId, target.toLowerCase());
      if (previous == null || previous.system) return false;
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
  /// In a group, [sender] must be the target's stored sender (the payload's MLS sender).
  Future<bool> edit(String conversationId, String target, {required String text, required int editedAt, required Direction author, String? sender}) async {
    if (!validTime(editedAt)) throw const StoreException('Invalid edit.', code: 'invalid');
    final changed = await _db.transaction((tx) async {
      final previous = await _get(tx, conversationId, target.toLowerCase());
      if (previous == null || previous.direction != author || previous.attachment != null) return false;
      if (author == Direction.incoming && previous.sender != sender) return false;
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

  // ---------- Group conversations (v3) ----------
  final _groupChanges = StreamController<String>.broadcast();

  /// Emits a group id whose conversation record changed (name, cursor, unread, frozen, membership, pin).
  Stream<String> get groupChanges => _groupChanges.stream;

  Future<GroupConversation?> group(String id) async {
    final rows = await _db.query('conversations', where: 'id = ?', whereArgs: [id], limit: 1);
    return rows.isEmpty ? null : GroupConversation.fromRow(rows.single);
  }

  Future<List<GroupConversation>> groups() async => [for (final row in await _db.query('conversations', orderBy: 'created_at, id')) GroupConversation.fromRow(row)];

  /// Inserts or replaces a group record.
  Future<GroupConversation> putGroup(GroupConversation value) async {
    if (!groupIdPattern.hasMatch(value.id)) throw const StoreException('Invalid group.', code: 'invalid');
    await _db.insert('conversations', value.toRow(), conflictAlgorithm: ConflictAlgorithm.replace);
    _groupChanges.add(value.id);
    return value;
  }

  /// Applies [change] to the stored record atomically; null when the group is unknown here.
  Future<GroupConversation?> updateGroup(String id, GroupConversation Function(GroupConversation current) change) async {
    final next = await _db.transaction((tx) async {
      final rows = await tx.query('conversations', where: 'id = ?', whereArgs: [id], limit: 1);
      if (rows.isEmpty) return null;
      final updated = change(GroupConversation.fromRow(rows.single));
      await tx.update('conversations', updated.toRow(), where: 'id = ?', whereArgs: [id]);
      return updated;
    });
    if (next != null) _groupChanges.add(id);
    return next;
  }

  /// Forgets a group on this device: its record and its history.
  Future<void> removeGroup(String id) async {
    await _db.transaction((tx) async {
      await tx.delete('conversations', where: 'id = ?', whereArgs: [id]);
      await tx.delete('messages', where: 'conversation_id = ?', whereArgs: [id]);
    });
    _groupChanges.add(id);
    _changes.add(id);
  }

  Future<void> removeConversation(String conversationId) async {
    if (!conversationPattern.hasMatch(conversationId)) throw const StoreException('Invalid conversation.');
    await _db.delete('messages', where: 'conversation_id = ?', whereArgs: [conversationId]);
    _changes.add(conversationId);
  }

  Future<void> clear() async {
    await _db.delete('messages');
    await _db.delete('conversations');
    _changes.add(null);
  }
}
