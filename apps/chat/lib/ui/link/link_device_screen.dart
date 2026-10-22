import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../core/api.dart';
import '../../crypto/account_crypto.dart';
import '../../crypto/chat_crypto.dart' show CryptoException;
import '../../messaging/linking.dart';
import '../../store/message.dart' show StoreException;
import '../widgets/common.dart';
import '../account/backup_screen.dart';
import '../account/backup_widgets.dart' show unlockFrom;
import '../account/copy.dart';
import 'qr.dart';

/// "Link a device" on a device that holds the account key (docs/m5-linking.md §1, m6-account-key.md §2): scan the new device's QR (or type its 8-character
/// code), compare the 6-digit code shown on both screens with the device's name, then Link. Nothing is signed
/// before that tap.
Future<void> showLinkDevice(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const LinkDeviceScreen()));

class LinkDeviceScreen extends ConsumerStatefulWidget {
  const LinkDeviceScreen({super.key});
  @override
  ConsumerState<LinkDeviceScreen> createState() => _LinkDeviceScreenState();
}

enum _Step { start, connecting, compare, linking, done }

class _LinkDeviceScreenState extends ConsumerState<LinkDeviceScreen> {
  final _code = TextEditingController();
  _Step _step = _Step.start;
  PrimaryLink? _link;
  String? _error;

  @override
  void dispose() {
    final link = _link;
    if (link != null && _step != _Step.done) unawaited(link.cancel());
    _code.dispose();
    super.dispose();
  }

  String _message(Object e) => switch (e) {
    ApiException(:final message) => message,
    StoreException(:final message) => message,
    CryptoException(code: 'auth') => "The codes can't match: someone may be in the middle. Nothing was linked.",
    CryptoException(code: 'expired') => 'That code expired. Start again on the other device.',
    CryptoException(:final message) => message,
    _ => 'Linking failed: $e',
  };

  Future<void> _begin(Future<PrimaryLink> Function(LinkContext ctx) start) async {
    final ctx = ref.read(appProvider.notifier).linkContext();
    if (ctx == null) return;
    setState(() {
      _step = _Step.connecting;
      _error = null;
    });
    try {
      final link = await start(ctx);
      setState(() => _link = link);
      await link.waitHello();
      if (mounted) setState(() => _step = _Step.compare);
    } catch (e) {
      if (mounted) {
        setState(() {
          _step = _Step.start;
          _error = _message(e);
        });
      }
    }
  }

  Future<void> _scan() async {
    final qr = await showQrScanner(context, title: 'Scan the code on the new device');
    if (qr != null) await _begin((ctx) => PrimaryLink.fromQr(ctx, qr));
  }

  Future<void> _typed() async {
    final text = _code.text.trim();
    if (text.isEmpty) return;
    // A pasted QR text, or the 8-character code.
    await _begin((ctx) => text.replaceAll(RegExp(r'\s'), '').startsWith('wb-link1.') ? PrimaryLink.fromQr(ctx, text) : PrimaryLink.fromCode(ctx, text));
  }

  Future<void> _approve() async {
    final link = _link;
    if (link == null) return;
    setState(() => _step = _Step.linking);
    try {
      await link.approve();
      if (mounted) setState(() => _step = _Step.done);
    } catch (e) {
      if (mounted) {
        setState(() {
          _step = _Step.compare;
          _error = _message(e);
        });
      }
    }
  }

  Future<void> _reject() async {
    await _link?.cancel();
    if (mounted) Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final link = _link, hello = link?.hello;
    return Scaffold(
      appBar: AppBar(title: const Text('Link a device')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          if (_error != null) Padding(padding: const EdgeInsets.only(bottom: 16), child: Text(_error!, key: const Key('link-error'), style: TextStyle(color: Theme.of(context).colorScheme.error))),
          switch (_step) {
            _Step.start => Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text('On the new device, choose "Link to my account". It shows a code to scan, or an 8-character code to type here.'),
                const SizedBox(height: 20),
                FilledButton.icon(key: const Key('link-scan'), onPressed: _scan, icon: const Icon(Icons.qr_code_scanner), label: const Text('Scan its code')),
                const SizedBox(height: 20),
                TextField(
                  key: const Key('link-code-input'),
                  controller: _code,
                  textCapitalization: TextCapitalization.characters,
                  decoration: const InputDecoration(labelText: 'Or type its code'),
                  onSubmitted: (_) => _typed(),
                ),
                const SizedBox(height: 8),
                OutlinedButton(key: const Key('link-code-submit'), onPressed: _typed, child: const Text('Continue')),
              ],
            ),
            _Step.connecting => const Column(children: [SizedBox(height: 40), CircularProgressIndicator(), SizedBox(height: 16), Text('Waiting for the new device…')]),
            _Step.compare || _Step.linking => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Check that the new device shows the same code.', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 12),
                Center(child: ConfirmationCode(code: link!.code)),
                const SizedBox(height: 12),
                if (hello != null)
                  Text('${hello.label.isEmpty ? 'A new device' : hello.label} (${hello.platform})${hello.wantsHistory ? ' asks for your recent chat history.' : ''}', key: const Key('link-device-name')),
                const SizedBox(height: 8),
                Text("Link only a device you're holding. It will read your groups and channels.", style: TextStyle(color: muted)),
                const SizedBox(height: 20),
                Row(
                  children: [
                    Expanded(child: OutlinedButton(key: const Key('link-mismatch'), onPressed: _step == _Step.linking ? null : _reject, child: const Text("Codes don't match"))),
                    const SizedBox(width: 12),
                    Expanded(
                      child: FilledButton(key: const Key('link-match'), onPressed: _step == _Step.linking ? null : _approve, child: Text(_step == _Step.linking ? 'Linking…' : 'Link')),
                    ),
                  ],
                ),
              ],
            ),
            _Step.done => Column(
              children: [
                const Icon(Icons.check_circle_outline, size: 48),
                const SizedBox(height: 12),
                Text('${hello?.label ?? 'The device'} is linked. It will show your groups once it finishes setting up.', key: const Key('link-done'), textAlign: TextAlign.center),
                const SizedBox(height: 16),
                FilledButton(onPressed: () => Navigator.pop(context), child: const Text('Done')),
              ],
            ),
          },
        ],
      ),
    );
  }
}

/// Removes another device of this account (docs/m6-account-key.md §6.2). On a device that holds the account key the
/// key is changed too, so the removed device's copy is worthless: "Remove <label> and change your account key?",
/// with the passphrase when the account has a backup (a stolen device can't do this without it). Elsewhere the
/// device is only cut off and a device with the key finishes the change.
Future<bool> confirmRemove(BuildContext context, WidgetRef ref, String deviceId, String name, {bool alreadyRemoved = false}) async {
  final app = ref.read(appProvider.notifier), state = ref.read(appProvider);
  // With a backup, every removal needs the passphrase (M6 §6.3), whether or not this device changes the key.
  final full = state.fullDevice, backup = state.hasBackup ?? false;
  final answer = await showDialog<({Unlock? unlock, bool changePassphrase})>(
    context: context,
    builder: (context) => _RemoveDialog(name: name, rotate: full, backup: backup),
  );
  if (answer == null) return false;
  try {
    await app.removeAndRotate(deviceId, unlock: answer.unlock, alreadyRemoved: alreadyRemoved);
  } catch (e) {
    if (context.mounted) showSnack(context, backupError(e, auth: notYourSecret));
    return false;
  }
  if (answer.changePassphrase && context.mounted) await showAccountBackup(context);
  return true;
}

class _RemoveDialog extends StatefulWidget {
  const _RemoveDialog({required this.name, required this.rotate, required this.backup});
  final String name;
  final bool rotate, backup;
  @override
  State<_RemoveDialog> createState() => _RemoveDialogState();
}

class _RemoveDialogState extends State<_RemoveDialog> {
  final _secret = TextEditingController();
  bool _change = false;
  String? _error;

  @override
  void dispose() {
    _secret.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.rotate ? 'Remove ${widget.name} and change your account key?' : 'Remove ${widget.name}?'),
    content: SingleChildScrollView(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(widget.rotate ? removeText : 'The device is signed out and can’t read new messages. A device that can unlock your account then changes its key.'),
          if (widget.backup) ...[
            const SizedBox(height: 12),
            TextField(
              key: const Key('remove-secret'),
              controller: _secret,
              obscureText: true,
              autocorrect: false,
              decoration: const InputDecoration(labelText: currentSecretLabel),
            ),
            if (_error != null) Padding(padding: const EdgeInsets.only(top: 6), child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
            CheckboxListTile(
              key: const Key('remove-change-passphrase'),
              contentPadding: EdgeInsets.zero,
              value: _change,
              onChanged: (v) => setState(() => _change = v ?? false),
              title: const Text('Also change your passphrase'),
              subtitle: const Text('If that device may have seen it.'),
            ),
          ],
        ],
      ),
    ),
    actions: [
      TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
      FilledButton(
        key: const Key('revoke-confirm'),
        style: FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error),
        onPressed: () {
          final text = _secret.text.trim();
          if (widget.backup && text.isEmpty) return setState(() => _error = enterCurrent);
          Navigator.pop(context, (unlock: widget.backup ? unlockFrom(text) : null, changePassphrase: _change));
        },
        child: Text(widget.rotate ? removeAndChange : 'Remove'),
      ),
    ],
  );
}
