import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../crypto/account_crypto.dart';
import 'backup_widgets.dart';
import 'copy.dart';

/// A device linked by short code waits for keys (docs/m6-account-key.md §2): the passphrase or recovery key makes it
/// able to unlock the account, checked against the account it already pins.
Future<void> showUnlockThisDevice(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const UnlockThisDeviceScreen()));

class UnlockThisDeviceScreen extends ConsumerStatefulWidget {
  const UnlockThisDeviceScreen({super.key});
  @override
  ConsumerState<UnlockThisDeviceScreen> createState() => _UnlockThisDeviceScreenState();
}

class _UnlockThisDeviceScreenState extends ConsumerState<UnlockThisDeviceScreen> {
  bool _busy = false;
  String? _error;

  Future<void> _unlock(Unlock unlock) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(appProvider.notifier).unlockWithBackup(unlock);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) setState(() => _error = backupError(e, auth: unlock.words != null ? wordsDontOpen : passphraseDoesntOpen));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Unlock this device')),
    body: ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const Text('Enter your passphrase or recovery key so this device can unlock your account by itself.'),
        const SizedBox(height: 16),
        UnlockFields(label: 'Unlock', busy: _busy, error: _error, onUnlock: _unlock),
      ],
    ),
  );
}
