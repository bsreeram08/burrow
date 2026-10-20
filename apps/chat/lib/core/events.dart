import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Server-to-client account events over `/api/events`.
sealed class AccountEvent {
  const AccountEvent();

  /// Unknown or malformed events are ignored (returns null), like the web client.
  static AccountEvent? parse(Object? raw) {
    if (raw is! String) return null;
    Object? decoded;
    try {
      decoded = jsonDecode(raw);
    } catch (_) {
      return null;
    }
    if (decoded is! Map<String, dynamic>) return null;
    final m = decoded;
    try {
      return switch (m['type']) {
        'hello' => Hello((m['online'] as List).cast<String>()),
        'presence' => Presence(m['id'] as String, m['online'] as bool),
        'contacts' => const ContactsChanged(),
        'keys' => KeysChanged(m['id'] as String),
        'devices' => DevicesChanged(m['id'] as String, needsList: m['needsList'] == true),
        'link' => LinkEvent(m['id'] as String, m['event'] as String),
        'ended' => Ended(m['roomId'] as String),
        'incoming' => Incoming(
          fromId: (m['from'] as Map)['id'] as String,
          fromUsername: (m['from'] as Map)['username'] as String,
          kind: m['kind'] as String,
          roomId: m['roomId'] as String,
          token: m['token'] as String,
        ),
        'envelope' => EnvelopeEvent(
          id: m['id'] as String,
          fromId: (m['from'] as Map)['id'] as String,
          fromUsername: (m['from'] as Map)['username'] as String,
          envelope: m['envelope'] as String,
          createdAt: m['createdAt'] as int,
          ephemeral: m['ephemeral'] == true,
        ),
        'group' => GroupEvent(
          channel: m['channel'] as String,
          seq: m['seq'] as int,
          epoch: m['epoch'] as int,
          kind: m['kind'] as String,
          fromUserId: (m['from'] as Map)['userId'] as String,
          fromDeviceId: (m['from'] as Map)['deviceId'] as String,
          message: m['message'] as String?,
          createdAt: m['createdAt'] as int,
          large: m['large'] == true,
        ),
        'welcome' => WelcomeEvent(
          id: m['id'] as String,
          channel: m['channel'] as String,
          from: m['from'] as String,
          epoch: m['epoch'] as int,
          seq: m['seq'] as int,
          welcome: m['welcome'] as String?,
          tree: m['tree'] as String?,
          createdAt: m['createdAt'] as int,
          large: m['large'] == true,
        ),
        'channel' => ChannelEvent(
          id: m['id'] as String,
          change: m['change'] as String,
          seq: m['seq'] as int?,
          digest: m['digest'] as String?,
          deviceId: m['deviceId'] as String?,
          oldest: m['oldest'] as int?,
          action: m['action'] as String?,
          author: m['author'] as String?,
          by: m['by'] as String?,
          byUser: m['byUser'] as String?,
          signature: m['signature'] as String?,
        ),
        'keypackages' => KeyPackagesLow(m['remaining'] as int),
        'ephemeral' => GroupEphemeral(
          channel: m['channel'] as String,
          fromUserId: (m['from'] as Map)['userId'] as String,
          fromDeviceId: (m['from'] as Map)['deviceId'] as String,
          message: m['message'] as String,
          createdAt: m['createdAt'] as int,
        ),
        _ => null,
      };
    } catch (_) {
      return null;
    }
  }
}

class Hello extends AccountEvent {
  const Hello(this.online);
  final List<String> online;
}

/// An account's device list changed (ours or a contact's): re-verify it.
class DevicesChanged extends AccountEvent {
  const DevicesChanged(this.id, {this.needsList = false});
  final String id;

  /// To the primary after a revocation: publish the next list without the revoked device.
  final bool needsList;
}

/// A link session of this account moved on: hello, offer, grant or a new sealed message.
class LinkEvent extends AccountEvent {
  const LinkEvent(this.id, this.event);
  final String id;
  final String event;
}

class Presence extends AccountEvent {
  const Presence(this.id, this.online);
  final String id;
  final bool online;
}

class ContactsChanged extends AccountEvent {
  const ContactsChanged();
}

class KeysChanged extends AccountEvent {
  const KeysChanged(this.id);
  final String id;
}

class Ended extends AccountEvent {
  const Ended(this.roomId);
  final String roomId;
}

class Incoming extends AccountEvent {
  const Incoming({required this.fromId, required this.fromUsername, required this.kind, required this.roomId, required this.token});
  final String fromId;
  final String fromUsername;

  /// chat, voice or video.
  final String kind;
  final String roomId;
  final String token;
}

class EnvelopeEvent extends AccountEvent {
  const EnvelopeEvent({
    required this.id,
    required this.fromId,
    required this.fromUsername,
    required this.envelope,
    required this.createdAt,
    this.ephemeral = false,
  });
  final String id;

  /// Live-only delivery (typing): never stored by the server, never acknowledged.
  final bool ephemeral;
  final String fromId;
  final String fromUsername;
  final String envelope;
  final int createdAt;
}

/// The next log entry of a channel for this device (never our own). [message] is null when [large]:
/// fetch it from the channel's log.
class GroupEvent extends AccountEvent {
  const GroupEvent({
    required this.channel,
    required this.seq,
    required this.epoch,
    required this.kind,
    required this.fromUserId,
    required this.fromDeviceId,
    required this.message,
    required this.createdAt,
    this.large = false,
  });
  final String channel;
  final int seq;
  final int epoch;

  /// `commit` or `app`.
  final String kind;
  final String fromUserId;
  final String fromDeviceId;
  final String? message;
  final int createdAt;
  final bool large;
}

/// A Welcome for this device; acknowledge it (`ack` with [id]) once the group is stored.
class WelcomeEvent extends AccountEvent {
  const WelcomeEvent({
    required this.id,
    required this.channel,
    required this.from,
    required this.epoch,
    required this.seq,
    required this.welcome,
    required this.tree,
    required this.createdAt,
    this.large = false,
  });
  final String id;
  final String channel;
  final String from;
  final int epoch;
  final int seq;
  final String? welcome;
  final String? tree;
  final int createdAt;
  final bool large;
}

/// A channel changed: joined, invited, updated, left, frozen (+seq, digest), thawed, remove-needed (+deviceId), gap (+oldest).
class ChannelEvent extends AccountEvent {
  const ChannelEvent({required this.id, required this.change, this.seq, this.digest, this.deviceId, this.oldest, this.action, this.author, this.by, this.byUser, this.signature});
  final String id;
  final String change;
  final int? seq;
  final String? digest;
  final String? deviceId;
  final int? oldest;

  /// `rolled-back`: the admin's resolution as signed with its MLS leaf key (author may be ""), and its device.
  final String? action;
  final String? author;
  final String? by;

  /// The resolving admin's user id: the signer must be exactly (byUser, by).
  final String? byUser;
  final String? signature;
}

/// A live-only group message (typing): never logged, processed only when the channel is idle.
class GroupEphemeral extends AccountEvent {
  const GroupEphemeral({required this.channel, required this.fromUserId, required this.fromDeviceId, required this.message, required this.createdAt});
  final String channel;
  final String fromUserId;
  final String fromDeviceId;
  final String message;
  final int createdAt;
}

/// This device's one-time KeyPackages are running low.
class KeyPackagesLow extends AccountEvent {
  const KeyPackagesLow(this.remaining);
  final int remaining;
}

/// Signed out by the server (code 4401): stop reconnecting.
class SignedOutEvent extends AccountEvent {
  const SignedOutEvent();
}

/// The always-on account connection, reconnecting with capped backoff.
class EventsClient {
  EventsClient({required this.url, required this.token});

  final Uri url;
  final String token;
  final _events = StreamController<AccountEvent>.broadcast();
  WebSocket? _socket;
  Timer? _retry;
  int _attempt = 0;
  bool _closed = false;

  Stream<AccountEvent> get events => _events.stream;
  bool get connected => _socket?.readyState == WebSocket.open;

  Future<void> connect() async {
    if (_closed || _socket != null) return;
    try {
      final socket = await WebSocket.connect(url.toString(), headers: {'Authorization': 'Bearer $token'}).timeout(const Duration(seconds: 10));
      if (_closed) {
        await socket.close();
        return;
      }
      _socket = socket;
      _attempt = 0;
      socket.listen(
        (data) {
          final event = AccountEvent.parse(data);
          if (event != null) _events.add(event);
        },
        onDone: () {
          _socket = null;
          if (socket.closeCode == 4401) {
            _closed = true;
            _events.add(const SignedOutEvent());
          } else {
            _schedule();
          }
        },
        cancelOnError: true,
      );
    } catch (_) {
      _socket = null;
      _schedule();
    }
  }

  void _schedule() {
    if (_closed) return;
    _retry?.cancel();
    final delay = Duration(milliseconds: (1000 * (1 << _attempt.clamp(0, 4))).clamp(1000, 15000));
    _attempt++;
    _retry = Timer(delay, connect);
  }

  /// The client messages the server accepts: envelope and Welcome acks, channel cursors and "ringing".
  void ack(String id) => _send({'type': 'ack', 'id': id});
  void cursor(String channel, int seq) => _send({'type': 'cursor', 'channel': channel, 'seq': seq});
  void ringing(String roomId) => _send({'type': 'ringing', 'roomId': roomId});

  void _send(Map<String, Object?> message) {
    if (connected) _socket!.add(jsonEncode(message));
  }

  Future<void> close() async {
    _closed = true;
    _retry?.cancel();
    await _socket?.close();
    _socket = null;
    await _events.close();
  }
}
