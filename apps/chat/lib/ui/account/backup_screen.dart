import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../crypto/account_crypto.dart';
import '../../messaging/backup.dart';
import 'backup_widgets.dart';
import 'copy.dart';

export 'backup_widgets.dart' show backupError;

/// Settings → Devices → Account backup (docs/m6-account-key.md §3.4): turn it on (a passphrase, then 24 recovery
/// words typed back), or change the passphrase, make new recovery words, or turn it off, each with the current
/// passphrase or recovery key.
Future<void> showAccountBackup(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const AccountBackupScreen()));

/// The backup's line on the device list and this screen.
String backupStatus(AppState state) => switch (state.hasBackup) {
  true => backupOn(_date(state.backupUpdatedAt)),
  false => backupOff,
  null => '',
};

String _date(int? ms) => ms == null ? 'recently' : DateTime.fromMillisecondsSinceEpoch(ms).toLocal().toString().substring(0, 10);

class AccountBackupScreen extends ConsumerWidget {
  const AccountBackupScreen({super.key});
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final has = ref.watch(appProvider.select((s) => s.hasBackup));
    return Scaffold(
      appBar: AppBar(title: const Text('Account backup')),
      body: switch (has) {
        null => const Center(child: CircularProgressIndicator()),
        false => const TurnOnBackup(),
        true => const ManageBackup(),
      },
    );
  }
}

enum _SetupStep { passphrase, words, confirm, done }

/// Turning it on: the generated passphrase (or the user's own, typed twice), the recovery words shown once, three
/// of them typed back, and only then the upload.
class TurnOnBackup extends ConsumerStatefulWidget {
  const TurnOnBackup({super.key});
  @override
  ConsumerState<TurnOnBackup> createState() => _TurnOnBackupState();
}

class _TurnOnBackupState extends ConsumerState<TurnOnBackup> {
  final _own = TextEditingController(), _again = TextEditingController();
  _SetupStep _step = _SetupStep.passphrase;
  List<String>? _suggested;
  bool _custom = false, _busy = false;
  String? _error;
  BackupSealed? _sealed;
  final _positions = confirmPositions();

  @override
  void initState() {
    super.initState();
    unawaited(_suggest());
  }

  Future<void> _suggest() async {
    try {
      final words = await ref.read(accountCryptoProvider).passphraseGenerate();
      if (mounted) setState(() => _suggested = words);
    } catch (e) {
      if (mounted) setState(() => _custom = true);
    }
  }

  @override
  void dispose() {
    _own.dispose();
    _again.dispose();
    super.dispose();
  }

  Future<void> _seal(String passphrase) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final backup = await ref.read(appProvider.notifier).accountBackup();
      final sealed = await backup?.prepareTurnOn(passphrase);
      if (mounted) {
        setState(() {
          _sealed = sealed;
          _step = _SetupStep.words;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _error = backupError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _useOwn() {
    final problem = AccountBackup.passphraseProblem(_own.text);
    if (problem != null) return setState(() => _error = problem);
    if (_own.text.trim() != _again.text.trim()) return setState(() => _error = noMatch);
    unawaited(_seal(_own.text.trim()));
  }

  Future<void> _commit() async {
    final sealed = _sealed;
    if (sealed == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await (await ref.read(appProvider.notifier).accountBackup())?.commit(sealed);
      if (mounted) setState(() => _step = _SetupStep.done);
    } catch (e) {
      if (mounted) setState(() => _error = backupError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final suggested = _suggested;
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text(turnOnTitle, style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 12),
        if (_error != null) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(_error!, key: const Key('backup-error'), style: TextStyle(color: Theme.of(context).colorScheme.error))),
        switch (_step) {
          _SetupStep.passphrase => Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(backupIntro),
              const SizedBox(height: 20),
              if (!_custom && suggested != null) ...[
                const Text(yourPassphrase),
                const SizedBox(height: 8),
                SelectableText(suggested.join(' '), key: const Key('backup-suggested'), style: Theme.of(context).textTheme.titleLarge),
                CopySecretButton(text: suggested.join(' ')),
                const SizedBox(height: 16),
                FilledButton(key: const Key('backup-use-suggested'), onPressed: _busy ? null : () => _seal(suggested.join(' ')), child: const Text('Next')),
                TextButton(key: const Key('backup-own'), onPressed: _busy ? null : () => setState(() => _custom = true), child: const Text(useOwnPassphrase)),
              ] else ...[
                TextField(key: const Key('backup-own-1'), controller: _own, obscureText: true, decoration: const InputDecoration(labelText: passphraseLabel)),
                const SizedBox(height: 8),
                TextField(key: const Key('backup-own-2'), controller: _again, obscureText: true, decoration: const InputDecoration(labelText: typeItAgain)),
                const SizedBox(height: 16),
                FilledButton(key: const Key('backup-own-submit'), onPressed: _busy ? null : _useOwn, child: const Text('Next')),
                if (suggested != null) TextButton(onPressed: () => setState(() => _custom = false), child: const Text(useGeneratedPassphrase)),
              ],
              if (_busy) Padding(padding: const EdgeInsets.only(top: 8), child: Text(securing, style: TextStyle(color: muted))),
            ],
          ),
          _SetupStep.words => Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              RecoveryWordsView(words: _sealed?.words ?? const []),
              const SizedBox(height: 16),
              FilledButton(key: const Key('backup-words-next'), onPressed: () => setState(() => _step = _SetupStep.confirm), child: const Text('Next')),
            ],
          ),
          _SetupStep.confirm => ConfirmWords(
            words: _sealed?.words ?? const [],
            positions: _positions,
            busy: _busy,
            onConfirmed: _commit,
            onCancel: () => setState(() => _step = _SetupStep.words),
          ),
          _SetupStep.done => Column(
            children: [
              const Icon(Icons.check_circle_outline, size: 48),
              const SizedBox(height: 12),
              const Text('Account backup is on. To sign in on a new device, use your passphrase or your recovery key.', key: Key('backup-done'), textAlign: TextAlign.center),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: () async {
                  await ref.read(appProvider.notifier).backupChanged();
                  if (context.mounted) await Navigator.of(context).maybePop();
                },
                child: const Text('Done'),
              ),
            ],
          ),
        },
      ],
    );
  }
}

enum _Manage { menu, passphrase, recovery, off }

/// Changing it: every change first proves the current passphrase or recovery key.
class ManageBackup extends ConsumerStatefulWidget {
  const ManageBackup({super.key});
  @override
  ConsumerState<ManageBackup> createState() => _ManageBackupState();
}

class _ManageBackupState extends ConsumerState<ManageBackup> {
  final _new = TextEditingController(), _again = TextEditingController(), _current = TextEditingController();
  _Manage _what = _Manage.menu;
  bool _busy = false;
  String? _error, _done;
  ({BackupSealed sealed, String proof})? _recovery;
  bool _confirming = false;
  final _positions = confirmPositions();

  @override
  void dispose() {
    _new.dispose();
    _again.dispose();
    _current.dispose();
    super.dispose();
  }

  Future<void> _run(Future<void> Function(AccountBackup backup) work) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final backup = await ref.read(appProvider.notifier).accountBackup();
      if (backup != null) await work(backup);
    } catch (e) {
      if (mounted) setState(() => _error = backupError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _submit() {
    if (_what == _Manage.passphrase) {
      final problem = AccountBackup.passphraseProblem(_new.text);
      if (problem != null) return setState(() => _error = problem);
      if (_new.text.trim() != _again.text.trim()) return setState(() => _error = noMatch);
    }
    if (_current.text.trim().isEmpty) return setState(() => _error = enterCurrent);
    final current = unlockFrom(_current.text);
    unawaited(_run((backup) async {
      switch (_what) {
        case _Manage.passphrase:
          await backup.changePassphrase(current, _new.text.trim());
          if (mounted) setState(() => _done = 'Your passphrase is changed. Use the new one from now on.');
        case _Manage.recovery:
          final prepared = await backup.prepareNewRecoveryKey(current);
          if (mounted) setState(() => _recovery = prepared);
        case _Manage.off:
          await backup.turnOff(current);
          if (mounted) setState(() => _done = 'Account backup is off. A new device can sign in only by linking it from one you already use.');
        case _Manage.menu:
          break;
      }
    }));
  }

  Future<void> _commitRecovery() => _run((backup) async {
    final r = _recovery;
    if (r == null) return;
    await backup.commit(r.sealed, proof: r.proof);
    if (mounted) setState(() => _done = 'Your new recovery key is saved. The old words no longer open your backup.');
  });

  @override
  Widget build(BuildContext context) {
    final error = _error, done = _done, recovery = _recovery;
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final status = backupStatus(ref.watch(appProvider));
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        if (_what != _Manage.menu)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(switch (_what) {
              _Manage.passphrase => changePassphraseTitle,
              _Manage.recovery => newRecoveryTitle,
              _ => turnOffTitle,
            }, style: Theme.of(context).textTheme.titleLarge),
          ),
        if (done != null) ...[
          Text(done, key: const Key('manage-done')),
          const SizedBox(height: 16),
          FilledButton(
            onPressed: () async {
              await ref.read(appProvider.notifier).backupChanged();
              if (context.mounted) await Navigator.of(context).maybePop();
            },
            child: const Text('Done'),
          ),
        ] else if (recovery != null) ...[
          if (error != null) Text(error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          if (!_confirming) ...[
            RecoveryWordsView(words: recovery.sealed.words ?? const []),
            FilledButton(key: const Key('backup-words-next'), onPressed: () => setState(() => _confirming = true), child: const Text('Next')),
          ] else
            ConfirmWords(
              words: recovery.sealed.words ?? const [],
              positions: _positions,
              busy: _busy,
              action: 'Save',
              onConfirmed: _commitRecovery,
              onCancel: () => setState(() => _confirming = false),
            ),
        ] else if (_what == _Manage.menu) ...[
          Text(status, key: const Key('backup-status')),
          const SizedBox(height: 16),
          ListTile(key: const Key('backup-change-passphrase'), leading: const Icon(Icons.password), title: const Text('Change passphrase'), onTap: () => setState(() => _what = _Manage.passphrase)),
          ListTile(key: const Key('backup-new-recovery'), leading: const Icon(Icons.key), title: const Text('New recovery key'), onTap: () => setState(() => _what = _Manage.recovery)),
          ListTile(
            key: const Key('backup-turn-off'),
            leading: Icon(Icons.delete_outline, color: Theme.of(context).colorScheme.error),
            title: Text('Turn off', style: TextStyle(color: Theme.of(context).colorScheme.error)),
            onTap: () => setState(() => _what = _Manage.off),
          ),
        ] else ...[
          CurrentSecretField(controller: _current),
          if (_what == _Manage.passphrase) ...[
            const SizedBox(height: 8),
            TextField(key: const Key('backup-new-1'), controller: _new, obscureText: true, decoration: const InputDecoration(labelText: passphraseLabel)),
            TextField(key: const Key('backup-new-2'), controller: _again, obscureText: true, decoration: const InputDecoration(labelText: typeItAgain)),
          ],
          if (_what == _Manage.off) const Padding(padding: EdgeInsets.only(top: 12), child: Text('Without a backup, a lost device can lock you out of your account.')),
          if (error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(error, key: const Key('manage-error'), style: TextStyle(color: Theme.of(context).colorScheme.error))),
          if (_busy) Padding(padding: const EdgeInsets.only(top: 8), child: Text(securing, style: TextStyle(color: muted))),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(onPressed: _busy ? null : () => setState(() => _what = _Manage.menu), child: const Text('Cancel')),
              const SizedBox(width: 8),
              FilledButton(
                key: const Key('manage-submit'),
                onPressed: _busy ? null : _submit,
                child: Text(switch (_what) {
                  _Manage.passphrase => 'Change passphrase',
                  _Manage.recovery => 'Next',
                  _ => 'Turn off',
                }),
              ),
            ],
          ),
        ],
      ],
    );
  }
}
