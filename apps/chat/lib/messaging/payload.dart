import 'dart:convert';

import '../store/message.dart';

/// Shape checks for decrypted contact payloads (port of chat-store.js `checkPayload`, extended with
/// docs/phase1-protocol.md §1–§2). Message content is validated by the store; control payloads
/// (react, edit, read, typing) are validated here in full because they never become a row.
/// Anything else is `invalid`: acknowledged and discarded, never retried.
class PayloadException implements Exception {
  const PayloadException();
  @override
  String toString() => 'Invalid message';
}

const maxReadIds = 100;
const _messageOptional = {'replyTo', 'attachment', 'link'};

/// Decodes and checks one plaintext. Returns the payload; its `type` is one of
/// receipt, burn, message, rotate, policy, react, edit, read, typing.
Map<String, Object?> checkPayload(String json) {
  if (utf8.encode(json).length > maxPayloadBytes) throw const PayloadException();
  Object? decoded;
  try {
    decoded = jsonDecode(json);
  } catch (_) {
    throw const PayloadException();
  }
  if (decoded is! Map<String, dynamic> || decoded['v'] != 1 || decoded['id'] is! String || !uuidPattern.hasMatch(decoded['id'] as String)) {
    throw const PayloadException();
  }
  final p = decoded, size = p.length;
  bool exactly(Set<String> keys) => size == keys.length && keys.every(p.containsKey);
  final ok = switch (p['type']) {
    'receipt' || 'burn' => size == 3,
    // The six base keys plus any of replyTo / attachment / link (present means non-null).
    'message' =>
      ['text', 'createdAt', 'expiresAt'].every(p.containsKey) &&
          size == 6 + _messageOptional.where(p.containsKey).length &&
          _messageOptional.every((k) => !p.containsKey(k) || p[k] != null),
    'rotate' => size == 4 && (p['reason'] == 'manual' || p['reason'] == 'scheduled'),
    'policy' => size == 4 && p['rotateEveryMs'] is int && (p['rotateEveryMs'] as int) >= 0,
    'react' =>
      exactly(const {'v', 'type', 'id', 'target', 'emoji', 'on'}) &&
          _isId(p['target']) &&
          p['emoji'] is String &&
          isReactionEmoji(p['emoji'] as String) &&
          p['on'] is bool,
    'edit' =>
      exactly(const {'v', 'type', 'id', 'target', 'text', 'editedAt'}) &&
          _isId(p['target']) &&
          p['text'] is String &&
          utf8.encode(p['text'] as String).length <= maxTextBytes &&
          p['editedAt'] is int &&
          validTime(p['editedAt'] as int),
    'read' =>
      exactly(const {'v', 'type', 'id', 'ids'}) &&
          p['ids'] is List &&
          (p['ids'] as List).isNotEmpty &&
          (p['ids'] as List).length <= maxReadIds &&
          (p['ids'] as List).every(_isId),
    'typing' => exactly(const {'v', 'type', 'id', 'at', 'on'}) && p['at'] is int && validTime(p['at'] as int) && p['on'] is bool,
    _ => false,
  };
  if (!ok) throw const PayloadException();
  return p;
}

bool _isId(Object? value) => value is String && uuidPattern.hasMatch(value);

/// Encodes a payload for sending, refusing anything over the 16 KB envelope budget.
String encodePayload(Map<String, Object?> payload) {
  final json = jsonEncode(payload);
  if (utf8.encode(json).length > maxPayloadBytes) throw const StoreException('This message is too large to send. Try a shorter message or a smaller preview.');
  return json;
}
