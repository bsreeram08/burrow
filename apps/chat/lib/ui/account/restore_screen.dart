import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../crypto/account_crypto.dart';
import '../link/link_this_device_screen.dart';
import 'backup_widgets.dart';
import 'copy.dart';

/// Signed in on a device the account doesn't list yet (docs/m6-account-key.md §4): unlock it with the backup, or
/// link it from a device already in use, or (small, with its warning) start over.
class RestoreScreen extends ConsumerStatefulWidget {
  const RestoreScreen({super.key});
  @override
  ConsumerState<RestoreScreen> createState() => _RestoreScreenState();
}

enum _Restore { choose, passphrase, words }

class _RestoreScreenState extends ConsumerState<RestoreScreen> {
  _Restore _step = _Restore.choose;
  bool _busy = false;
  String? _error;

  Future<void> _unlock(Unlock unlock) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(appProvider.notifier).restoreFromBackup(unlock);
    } catch (e) {
      if (mounted) setState(() => _error = backupError(e, auth: unlock.words != null ? wordsDontOpen : passphraseDoesntOpen));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _freshStart() async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Start over on this device?'),
        content: const Text(
          'Do this only if you have no other device and no passphrase or recovery key. This device makes new keys for your account: everyone you talk to sees that your security code changed, and your other devices stop working until you link them again.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(key: const Key('restore-fresh-confirm'), onPressed: () => Navigator.pop(context, true), child: const Text('Start over here')),
        ],
      ),
    );
    if (yes == true) await ref.read(appProvider.notifier).startOver();
  }

  @override
  Widget build(BuildContext context) {
    final hasBackup = ref.watch(appProvider.select((s) => s.hasBackup)) ?? false;
    final safety = ref.watch(appProvider.select((s) => s.restoredSafety));
    final reset = ref.watch(appProvider.select((s) => s.keyReset));
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: ListView(
              padding: const EdgeInsets.all(24),
              shrinkWrap: true,
              children: [
                if (reset != null && reset.mine && safety == null) ...[
                  const Icon(Icons.hourglass_top, size: 48),
                  const SizedBox(height: 12),
                  Text(resetWaiting, key: const Key('reset-waiting'), style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
                  const SizedBox(height: 8),
                  Text(resetGoesAhead(reset.executeAfter), textAlign: TextAlign.center, style: TextStyle(color: muted)),
                ] else if (safety != null) ...[
                  const Icon(Icons.check_circle_outline, size: 48),
                  const SizedBox(height: 12),
                  Text(restoredTitle, style: Theme.of(context).textTheme.titleLarge, textAlign: TextAlign.center),
                  const SizedBox(height: 12),
                  SelectableText('Safety number: $safety', key: const Key('restore-safety'), textAlign: TextAlign.center, style: const TextStyle(fontFeatures: [FontFeature.tabularFigures()])),
                  const SizedBox(height: 12),
                  const Text(noReverify, textAlign: TextAlign.center),
                  const SizedBox(height: 16),
                  FilledButton(key: const Key('restore-done'), onPressed: ref.read(appProvider.notifier).dismissRestored, child: const Text('Done')),
                ] else ...[
                  Text('Use your account here.', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700)),
                  const SizedBox(height: 8),
                  const Text('Your messages are end-to-end encrypted. Unlock them on this device with your backup, or link it from a device you already use.'),
                  const SizedBox(height: 24),
                  if (_step == _Restore.choose) ...[
                    if (hasBackup) ...[
                      FilledButton(key: const Key('restore-passphrase'), onPressed: () => setState(() => _step = _Restore.passphrase), child: const Text('Enter your passphrase')),
                      const SizedBox(height: 8),
                      OutlinedButton(key: const Key('restore-words'), onPressed: () => setState(() => _step = _Restore.words), child: const Text('Use your recovery key')),
                      const SizedBox(height: 8),
                    ] else
                      Padding(
                        padding: const EdgeInsets.only(bottom: 12),
                        child: Text('Turn on account backup on one of your devices to sign in without it next time.', key: const Key('restore-no-backup'), style: TextStyle(color: muted)),
                      ),
                    OutlinedButton(key: const Key('restore-link'), onPressed: () => showLinkThisDevice(context), child: const Text('Link from another device')),
                    const SizedBox(height: 16),
                    Center(
                      child: TextButton(key: const Key('restore-fresh'), onPressed: _freshStart, child: Text("I can't do any of these", style: TextStyle(color: muted, fontSize: 13))),
                    ),
                  ] else ...[
                    UnlockFields(key: ValueKey(_step), words: _step == _Restore.words, label: 'Unlock', busy: _busy, error: _error, onUnlock: _unlock),
                    TextButton(onPressed: _busy ? null : () => setState(() => _step = _Restore.choose), child: const Text('Back')),
                  ],
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
