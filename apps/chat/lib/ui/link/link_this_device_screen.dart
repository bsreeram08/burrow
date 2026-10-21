import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../core/api.dart';
import '../../crypto/chat_crypto.dart' show CryptoException;
import '../../messaging/linking.dart';
import '../../store/message.dart' show StoreException;
import 'qr.dart';

/// Welcome → "Link to my account" (docs/m5-linking.md §1, §1.7): this install becomes a linked device. It shows
/// a code for another device of the account to scan (or, without a camera there, an 8-character code for one
/// account), then the 6 digits to compare, and signs in once that device taps Link. A QR link brings the account key
/// with it; a short-code link doesn't (docs/m6-account-key.md §2).
Future<void> showLinkThisDevice(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const LinkThisDeviceScreen()));

class LinkThisDeviceScreen extends ConsumerStatefulWidget {
  const LinkThisDeviceScreen({super.key});
  @override
  ConsumerState<LinkThisDeviceScreen> createState() => _LinkThisDeviceScreenState();
}

enum _Step { start, waiting, compare }

class _LinkThisDeviceScreenState extends ConsumerState<LinkThisDeviceScreen> {
  final _username = TextEditingController();
  _Step _step = _Step.start;
  NewDeviceLink? _link;
  String? _error;
  bool _done = false;

  @override
  void dispose() {
    final link = _link;
    if (link != null && !_done) unawaited(link.cancel());
    _username.dispose();
    super.dispose();
  }

  String _message(Object e) => switch (e) {
    ApiException(:final message) => message,
    StoreException(:final message) => message,
    CryptoException(code: 'auth') => "The codes can't match: someone may be in the middle. Nothing was linked.",
    CryptoException(:final message) => message,
    _ => 'Linking failed: $e',
  };

  Future<void> _start({String? username}) async {
    setState(() {
      _step = _Step.waiting;
      _error = null;
    });
    final app = ref.read(appProvider.notifier);
    try {
      final link = await app.startLink(username: username);
      if (!mounted) return unawaited(link.cancel());
      setState(() => _link = link);
      await link.waitOffer();
      if (!mounted) return;
      setState(() => _step = _Step.compare);
      await app.finishLink(link);
      _done = true;
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() {
          _step = _Step.start;
          _link = null;
          _error = _message(e);
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final link = _link;
    return Scaffold(
      appBar: AppBar(title: const Text('Link to my account')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          if (_error != null) Padding(padding: const EdgeInsets.only(bottom: 16), child: Text(_error!, key: const Key('link-error'), style: TextStyle(color: Theme.of(context).colorScheme.error))),
          switch (_step) {
            _Step.start => Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text('Use this device with your account. A device you already use approves it.'),
                const SizedBox(height: 20),
                FilledButton.icon(key: const Key('link-show-qr'), onPressed: () => _start(), icon: const Icon(Icons.qr_code_2), label: const Text('Show a code to scan')),
                const SizedBox(height: 28),
                Text("Your other device can't scan? Get a short code to type there instead.", style: TextStyle(color: muted)),
                const SizedBox(height: 8),
                TextField(key: const Key('link-username'), controller: _username, autocorrect: false, decoration: const InputDecoration(labelText: 'Your username')),
                const SizedBox(height: 8),
                OutlinedButton(
                  key: const Key('link-short-code'),
                  onPressed: () {
                    if (_username.text.trim().isNotEmpty) _start(username: _username.text);
                  },
                  child: const Text('Get a short code'),
                ),
              ],
            ),
            _Step.waiting when link == null => const Column(children: [SizedBox(height: 40), CircularProgressIndicator()]),
            _Step.waiting => Column(
              children: [
                if (link?.qr case final qr?) ...[
                  const Text('On a device you already use, open Settings → Devices → Link a device, and scan this.', textAlign: TextAlign.center),
                  const SizedBox(height: 16),
                  LinkQr(data: qr),
                  const SizedBox(height: 12),
                  SelectableText(qr, key: const Key('link-qr-text'), textAlign: TextAlign.center, style: TextStyle(color: muted, fontSize: 12)),
                  TextButton.icon(onPressed: () => Clipboard.setData(ClipboardData(text: qr)), icon: const Icon(Icons.copy, size: 16), label: const Text('Copy the text instead')),
                ] else if (link?.shortCode case final code?) ...[
                  const Text('On a device you already use, open Settings → Devices → Link a device, and type this code.', textAlign: TextAlign.center),
                  const SizedBox(height: 8),
                  const Text('To unlock everything on this device, enter your passphrase afterwards.', key: Key('link-short-passphrase'), textAlign: TextAlign.center),
                  const SizedBox(height: 16),
                  SelectableText(code, key: const Key('link-short'), style: Theme.of(context).textTheme.displaySmall?.copyWith(letterSpacing: 6, fontWeight: FontWeight.w700)),
                ],
              ],
            ),
            _Step.compare => Column(
              children: [
                const Text('Check that your other device shows the same code, then tap Link there.', textAlign: TextAlign.center),
                const SizedBox(height: 16),
                ConfirmationCode(code: link?.code ?? ''),
                const SizedBox(height: 16),
                const LinearProgressIndicator(),
              ],
            ),
          },
        ],
      ),
    );
  }
}
