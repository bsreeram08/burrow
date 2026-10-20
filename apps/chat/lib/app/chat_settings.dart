import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Per-account messaging settings on this device (docs/phase1-protocol.md §2 and §4).
class ChatSettings {
  const ChatSettings({this.readReceipts = true, this.linkPreviews = true});

  /// "Send read receipts". Off: none are sent and others' are not shown either.
  final bool readReceipts;

  /// "Generate link previews": the server fetches the page for the sender; receivers never fetch.
  final bool linkPreviews;

  ChatSettings copyWith({bool? readReceipts, bool? linkPreviews}) =>
      ChatSettings(readReceipts: readReceipts ?? this.readReceipts, linkPreviews: linkPreviews ?? this.linkPreviews);

  factory ChatSettings.fromJson(Object? json) => json is Map
      ? ChatSettings(readReceipts: json['readReceipts'] != false, linkPreviews: json['linkPreviews'] != false)
      : const ChatSettings();

  Map<String, bool> toJson() => {'readReceipts': readReceipts, 'linkPreviews': linkPreviews};
}

class ChatSettingsNotifier extends Notifier<ChatSettings> {
  SharedPreferences? _prefs;
  String _account = 'guest';

  @override
  ChatSettings build() => const ChatSettings();

  Future<void> load(String account) async {
    _account = account;
    _prefs ??= await SharedPreferences.getInstance();
    try {
      state = ChatSettings.fromJson(jsonDecode(_prefs!.getString('chat-settings-v1:$_account') ?? '{}'));
    } catch (_) {
      state = const ChatSettings();
    }
  }

  void set(ChatSettings next) {
    state = next;
    _prefs?.setString('chat-settings-v1:$_account', jsonEncode(next.toJson()));
  }
}

final chatSettingsProvider = NotifierProvider<ChatSettingsNotifier, ChatSettings>(ChatSettingsNotifier.new);
