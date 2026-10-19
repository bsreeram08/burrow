import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../store/message.dart';
import '../../theme/tokens.dart';

/// The six quick reactions (§5).
const quickReactions = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

const _emojiGroups = <String, String>{
  'Smileys': '😀 😃 😄 😁 😆 😅 🤣 😂 🙂 🙃 😉 😊 😇 🥰 😍 🤩 😘 😗 😚 😙 😋 😛 😜 🤪 😝 🤑 🤗 🤭 🤫 🤔 🤐 🤨 😐 😑 😶 😏 😒 🙄 😬 😌 😔 😪 😴 😷 🤒 🤕 🤢 🥵 🥶 🥴 😵 🤯 🤠 🥳 😎 🤓 🧐 😕 😟 🙁 😮 😯 😲 😳 🥺 😦 😧 😨 😰 😥 😢 😭 😱 😖 😣 😞 😓 😩 😫 🥱 😤 😡 😠 🤬 😈 💀 💩 🤡 👻 👽 🤖',
  'People': '👋 🤚 ✋ 🖖 👌 🤌 🤏 ✌️ 🤞 🤟 🤘 🤙 👈 👉 👆 👇 ☝️ 👍 👎 ✊ 👊 🤛 🤜 👏 🙌 👐 🤲 🤝 🙏 ✍️ 💪 🫶 👀 🧠 🫡 🤷 🤦 🙋 🙇',
  'Hearts': '❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❣️ 💕 💞 💓 💗 💖 💘 💝 ✨ ⭐ 🌟 💫 🔥 💯 ✅ ❌ ❓ ❗ ⚡ 🎉 🎊 🎈 🎁 🏆 🥇',
  'Nature': '🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🐔 🐧 🐦 🦄 🐝 🦋 🐢 🐙 🐬 🐳 🌸 🌹 🌻 🌷 🌱 🌲 🍀 🍁 🌈 ☀️ 🌙 ☁️ ❄️ 🌊',
  'Food': '🍎 🍊 🍋 🍌 🍉 🍇 🍓 🍒 🍑 🥭 🍍 🥑 🌶️ 🌽 🥕 🥐 🍞 🧀 🍳 🍔 🍟 🍕 🌮 🍣 🍜 🍩 🍪 🎂 🍰 🍫 🍿 ☕ 🍵 🍺 🍷 🥂',
  'Things': '⚽ 🏀 🏈 🎾 🎮 🎲 🎯 🎸 🎧 🎬 📷 💻 📱 ⌚ 💡 📚 ✏️ 📌 📎 🔒 🔑 🔔 🚀 ✈️ 🚗 🚲 🏠 ⏰ 💰 🎵',
};

/// Emoji picker: groups to tap, or type / paste any single emoji.
Future<String?> showEmojiPicker(BuildContext context) => showModalBottomSheet<String>(
  context: context,
  isScrollControlled: true,
  builder: (context) => const _EmojiPicker(),
);

class _EmojiPicker extends StatefulWidget {
  const _EmojiPicker();
  @override
  State<_EmojiPicker> createState() => _EmojiPickerState();
}

class _EmojiPickerState extends State<_EmojiPicker> {
  final _typed = TextEditingController();

  @override
  void dispose() {
    _typed.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final height = MediaQuery.sizeOf(context).height * .6;
    return SafeArea(
      child: SizedBox(
        height: height,
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: TextField(
                controller: _typed,
                decoration: const InputDecoration(hintText: 'Type or paste an emoji', isDense: true, prefixIcon: Icon(Icons.emoji_emotions_outlined)),
                onChanged: (value) {
                  final v = value.trim();
                  if (isReactionEmoji(v)) Navigator.pop(context, v);
                },
              ),
            ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                children: [
                  for (final group in _emojiGroups.entries) ...[
                    Padding(padding: const EdgeInsets.fromLTRB(4, 10, 4, 4), child: Text(group.key, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13))),
                    Wrap(
                      children: [
                        for (final e in group.value.split(' '))
                          InkResponse(
                            onTap: () => Navigator.pop(context, e),
                            radius: 22,
                            child: Padding(padding: const EdgeInsets.all(6), child: Text(e, style: const TextStyle(fontSize: 26))),
                          ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

enum MessageAction { reply, edit, copy }

/// Long-press / right-click on a message: a row of quick reactions ("more" opens the picker) and actions.
/// Returns an emoji (reacted) or a [MessageAction].
Future<Object?> showMessageMenu(BuildContext context, {required ChatMessage message, required ChatTokens tokens, required bool canEdit, required bool canReact}) {
  HapticFeedback.selectionClick();
  final mine = message.reactions.of('me');
  return showModalBottomSheet<Object>(
    context: context,
    builder: (context) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (canReact)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    for (final e in quickReactions)
                      Semantics(
                        button: true,
                        selected: mine.contains(e),
                        label: 'React $e',
                        child: InkResponse(
                          onTap: () => Navigator.pop(context, e),
                          radius: 26,
                          child: Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(shape: BoxShape.circle, color: mine.contains(e) ? tokens.okBg : null),
                            child: Text(e, style: const TextStyle(fontSize: 28)),
                          ),
                        ),
                      ),
                    IconButton.filledTonal(
                      tooltip: 'More reactions',
                      onPressed: () async {
                        final picked = await showEmojiPicker(context);
                        if (picked != null && context.mounted) Navigator.pop(context, picked);
                      },
                      icon: const Icon(Icons.add_reaction_outlined),
                    ),
                  ],
                ),
              ),
            ListTile(leading: const Icon(Icons.reply_rounded), title: const Text('Reply'), onTap: () => Navigator.pop(context, MessageAction.reply)),
            if (canEdit) ListTile(leading: const Icon(Icons.edit_outlined), title: const Text('Edit'), onTap: () => Navigator.pop(context, MessageAction.edit)),
            if (message.body.isNotEmpty)
              ListTile(leading: const Icon(Icons.copy_rounded), title: const Text('Copy text'), onTap: () => Navigator.pop(context, MessageAction.copy)),
          ],
        ),
      ),
    ),
  );
}

/// Reaction pills under a bubble: emoji and count, ours highlighted. Tap toggles; long-press lists who.
class ReactionPills extends StatelessWidget {
  const ReactionPills({super.key, required this.reactions, required this.tokens, required this.peerName, this.onToggle});
  final Reactions reactions;
  final ChatTokens tokens;
  final String peerName;
  final void Function(String emoji, bool on)? onToggle;

  @override
  Widget build(BuildContext context) {
    final t = tokens;
    return Wrap(
      spacing: 4,
      runSpacing: 4,
      children: [
        for (final r in reactions.summary)
          Tooltip(
            message: [if (r.mine) 'You', if (reactions.of('peer').contains(r.emoji)) peerName].join(', '),
            triggerMode: TooltipTriggerMode.longPress,
            child: Semantics(
              button: true,
              selected: r.mine,
              label: '${r.emoji} ${r.count}',
              child: InkWell(
                borderRadius: BorderRadius.circular(12),
                onTap: onToggle == null ? null : () => onToggle!(r.emoji, !r.mine),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 150),
                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                  decoration: BoxDecoration(
                    color: r.mine ? t.okBg : t.surface2,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: r.mine ? t.accent : t.line, width: r.mine ? 1.4 : 1),
                  ),
                  child: Text(r.count > 1 ? '${r.emoji} ${r.count}' : r.emoji, style: TextStyle(fontSize: 14, color: t.text)),
                ),
              ),
            ),
          ),
      ],
    );
  }
}
