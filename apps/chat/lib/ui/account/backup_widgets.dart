import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/api.dart';
import '../../crypto/account_crypto.dart';
import '../../crypto/chat_crypto.dart' show CryptoException;
import '../../store/message.dart' show StoreException;
import 'copy.dart';

/// Copies a secret and clears the clipboard after 60 s, if it still holds it (docs/m6-account-key.md §3.4).
Future<void> copySecret(String text, {Duration clearAfter = const Duration(seconds: 60)}) async {
  await Clipboard.setData(ClipboardData(text: text));
  unawaited(Future<void>.delayed(clearAfter, () async {
    final now = await Clipboard.getData(Clipboard.kTextPlain);
    if (now?.text == text) await Clipboard.setData(const ClipboardData(text: ''));
  }));
}

/// What a failed backup step says. [auth]: the words for a secret that doesn't open it, which depend on the screen.
String backupError(Object e, {String auth = notCurrent}) => switch (e) {
  ApiException(status: 403) => auth,
  ApiException(status: 429) => 'Too many tries. Wait a while and try again.',
  ApiException(:final message) => message,
  StoreException(:final message) => message,
  CryptoException(code: 'auth') => auth,
  CryptoException(code: 'invalid') => checkTheWords,
  CryptoException(:final message) => message,
  _ => 'That didn’t work: $e',
};

/// A secret typed in one field: 24 words are the recovery key, anything else the passphrase.
Unlock unlockFrom(String text) {
  final t = text.trim();
  return t.split(RegExp(r'\s+')).length == 24 ? Unlock.words(t) : Unlock.passphrase(t);
}

class _CopyButton extends StatelessWidget {
  const _CopyButton({required this.text, this.buttonKey});
  final String text;
  final Key? buttonKey;
  @override
  Widget build(BuildContext context) => Align(
    alignment: Alignment.centerLeft,
    child: TextButton.icon(
      key: buttonKey,
      onPressed: () async {
        await copySecret(text);
        if (context.mounted) ScaffoldMessenger.maybeOf(context)?.showSnackBar(const SnackBar(content: Text(copied)));
      },
      icon: const Icon(Icons.copy, size: 16),
      label: const Text('Copy'),
    ),
  );
}

/// Copy for a passphrase.
class CopySecretButton extends StatelessWidget {
  const CopySecretButton({super.key, required this.text});
  final String text;
  @override
  Widget build(BuildContext context) => _CopyButton(text: text);
}

/// The 24 recovery words, numbered in three columns, shown once, with Copy.
class RecoveryWordsView extends StatelessWidget {
  const RecoveryWordsView({super.key, required this.words});
  final List<String> words;

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    const tabular = TextStyle(fontFeatures: [FontFeature.tabularFigures()]);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(wordsIntro),
        const SizedBox(height: 16),
        Row(
          key: const Key('recovery-words'),
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (var col = 0; col < 3; col++)
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (var i = col * 8; i < math.min(col * 8 + 8, words.length); i++)
                      Padding(padding: const EdgeInsets.symmetric(vertical: 2), child: Text('${i + 1}. ${words[i]}', key: Key('recovery-word-$i'), style: tabular)),
                  ],
                ),
              ),
          ],
        ),
        const SizedBox(height: 12),
        Text(walletWarning, style: TextStyle(color: muted)),
        _CopyButton(text: words.join(' '), buttonKey: const Key('recovery-copy')),
      ],
    );
  }
}

/// Three positions, chosen at random, ascending: the user types those words back (§3.4 step 2).
List<int> confirmPositions([math.Random? random]) {
  final r = random ?? math.Random.secure();
  final picked = <int>{};
  while (picked.length < 3) {
    picked.add(r.nextInt(24));
  }
  return picked.toList()..sort();
}

/// A typed answer matches a recovery word: the whole word, or its first four letters or more, any case.
bool wordMatches(String typed, String word) {
  final t = typed.trim().toLowerCase(), w = word.toLowerCase();
  return t == w || (t.length >= 4 && w.startsWith(t));
}

/// Types three of the recovery words back; [onConfirmed] once all three match.
class ConfirmWords extends StatefulWidget {
  const ConfirmWords({super.key, required this.words, required this.positions, required this.onConfirmed, this.onCancel, this.action = 'Turn on', this.busy = false});
  final List<String> words;
  final List<int> positions;
  final VoidCallback onConfirmed;
  final VoidCallback? onCancel;
  final String action;
  final bool busy;
  @override
  State<ConfirmWords> createState() => _ConfirmWordsState();
}

class _ConfirmWordsState extends State<ConfirmWords> {
  late final _fields = [for (final _ in widget.positions) TextEditingController()];
  String? _error;

  @override
  void dispose() {
    for (final f in _fields) {
      f.dispose();
    }
    super.dispose();
  }

  void _check() {
    for (final (i, p) in widget.positions.indexed) {
      if (!wordMatches(_fields[i].text, widget.words[p])) return setState(() => _error = wordMismatch(p + 1));
    }
    setState(() => _error = null);
    widget.onConfirmed();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const Text(checkIntro),
      const SizedBox(height: 12),
      for (final (i, p) in widget.positions.indexed)
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: TextField(key: Key('confirm-word-$i'), controller: _fields[i], autocorrect: false, decoration: InputDecoration(labelText: wordLabel(p + 1))),
        ),
      if (_error != null) Text(_error!, key: const Key('confirm-error'), style: TextStyle(color: Theme.of(context).colorScheme.error)),
      if (widget.busy) const Padding(padding: EdgeInsets.only(top: 8), child: Text(securing)),
      const SizedBox(height: 8),
      Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          if (widget.onCancel != null) TextButton(onPressed: widget.busy ? null : widget.onCancel, child: const Text('Cancel')),
          const SizedBox(width: 8),
          FilledButton(key: const Key('confirm-words'), onPressed: widget.busy ? null : _check, child: Text(widget.action)),
        ],
      ),
    ],
  );
}

/// Restore: the passphrase, or (switching) the 24 recovery words. [onUnlock] gets the one given.
class UnlockFields extends StatefulWidget {
  const UnlockFields({super.key, required this.onUnlock, this.label = 'Unlock', this.words = false, this.busy = false, this.error});
  final Future<void> Function(Unlock unlock) onUnlock;
  final String label;

  /// Start with the recovery words instead of the passphrase.
  final bool words;
  final bool busy;
  final String? error;
  @override
  State<UnlockFields> createState() => _UnlockFieldsState();
}

class _UnlockFieldsState extends State<UnlockFields> {
  final _text = TextEditingController();
  late bool _words = widget.words;

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(_words ? restoreWordsTitle : restorePassphraseTitle, style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        TextField(
          key: const Key('unlock-input'),
          controller: _text,
          obscureText: !_words,
          autocorrect: false,
          enableSuggestions: false,
          minLines: _words ? 3 : 1,
          maxLines: _words ? 4 : 1,
          decoration: InputDecoration(labelText: _words ? restoreWordsLabel : restorePassphraseLabel),
        ),
        if (_words) Padding(padding: const EdgeInsets.only(top: 6), child: Text(walletWarning, style: TextStyle(color: muted))),
        if (widget.busy) const Padding(padding: EdgeInsets.only(top: 8), child: Text(unlocking)),
        if (widget.error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(widget.error!, key: const Key('unlock-error'), style: TextStyle(color: Theme.of(context).colorScheme.error))),
        const SizedBox(height: 12),
        FilledButton(
          key: const Key('unlock-submit'),
          onPressed: widget.busy
              ? null
              : () {
                  final text = _text.text.trim();
                  if (text.isNotEmpty) widget.onUnlock(_words ? Unlock.words(text) : Unlock.passphrase(text));
                },
          child: Text(widget.label),
        ),
        TextButton(
          key: const Key('unlock-switch'),
          onPressed: widget.busy ? null : () => setState(() => _words = !_words),
          child: Text(_words ? 'Use your passphrase instead' : 'Use your recovery key instead'),
        ),
      ],
    );
  }
}

/// A change's proof: one field for the current passphrase or the recovery words.
class CurrentSecretField extends StatelessWidget {
  const CurrentSecretField({super.key, required this.controller});
  final TextEditingController controller;
  @override
  Widget build(BuildContext context) => TextField(
    key: const Key('current-secret'),
    controller: controller,
    obscureText: true,
    autocorrect: false,
    enableSuggestions: false,
    decoration: const InputDecoration(labelText: currentSecretLabel),
  );
}
