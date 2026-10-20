import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_controller.dart';
import '../../core/api.dart';
import '../../crypto/chat_crypto.dart' show CryptoException;
import '../../messaging/succession.dart';
import '../../store/message.dart' show StoreException;
import 'qr.dart';

/// Primary transfer (docs/m5-linking.md §5). On the primary: hand the account over to another of its devices.
/// On a linked device: become the primary. The account key never moves: the new primary makes a new one and
/// the old primary signs the account over to it, so contacts keep their verification.
Future<void> showHandOver(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const HandOverScreen()));
Future<void> showTakeOver(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const TakeOverScreen()));

String _message(Object e) => switch (e) {
  ApiException(:final message) => message,
  StoreException(:final message) => message,
  CryptoException(code: 'auth') => "The codes can't match: someone may be in the middle. Nothing changed.",
  CryptoException(:final message) => message,
  _ => 'That didn\'t work: $e',
};

Widget _errorText(BuildContext context, String? error) =>
    error == null ? const SizedBox.shrink() : Padding(padding: const EdgeInsets.only(bottom: 16), child: Text(error, key: const Key('transfer-error'), style: TextStyle(color: Theme.of(context).colorScheme.error)));

class HandOverScreen extends ConsumerStatefulWidget {
  const HandOverScreen({super.key});
  @override
  ConsumerState<HandOverScreen> createState() => _HandOverScreenState();
}

enum _HandStep { start, connecting, compare, working }

class _HandOverScreenState extends ConsumerState<HandOverScreen> {
  final _code = TextEditingController();
  _HandStep _step = _HandStep.start;
  HandOver? _hand;
  String? _error;

  @override
  void dispose() {
    final hand = _hand;
    if (hand != null && _step != _HandStep.working) unawaited(hand.cancel());
    _code.dispose();
    super.dispose();
  }

  Future<void> _begin(String qr) async {
    setState(() {
      _step = _HandStep.connecting;
      _error = null;
    });
    try {
      final hand = await ref.read(appProvider.notifier).handOver(qr);
      setState(() => _hand = hand);
      await hand.waitRequest();
      if (mounted) setState(() => _step = _HandStep.compare);
    } catch (e) {
      if (mounted) {
        setState(() {
          _step = _HandStep.start;
          _hand = null;
          _error = _message(e);
        });
      }
    }
  }

  Future<void> _approve() async {
    final hand = _hand;
    if (hand == null) return;
    setState(() => _step = _HandStep.working);
    try {
      await ref.read(appProvider.notifier).finishHandOver(hand);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() {
          _step = _HandStep.compare;
          _error = _message(e);
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final hand = _hand;
    return Scaffold(
      appBar: AppBar(title: const Text('Hand over to another device')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          _errorText(context, _error),
          switch (_step) {
            _HandStep.start => Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text('On the device that should hold your keys, open Settings → Devices → Make this device primary. Scan the code it shows, or paste its text.'),
                const SizedBox(height: 20),
                FilledButton.icon(
                  key: const Key('transfer-scan'),
                  onPressed: () async {
                    final qr = await showQrScanner(context, title: 'Scan the code on the other device');
                    if (qr != null) await _begin(qr);
                  },
                  icon: const Icon(Icons.qr_code_scanner),
                  label: const Text('Scan its code'),
                ),
                const SizedBox(height: 20),
                TextField(key: const Key('transfer-code-input'), controller: _code, decoration: const InputDecoration(labelText: 'Or paste its text')),
                const SizedBox(height: 8),
                OutlinedButton(
                  key: const Key('transfer-code-submit'),
                  onPressed: () {
                    if (_code.text.trim().isNotEmpty) _begin(_code.text);
                  },
                  child: const Text('Continue'),
                ),
              ],
            ),
            _HandStep.connecting => const Column(children: [SizedBox(height: 40), CircularProgressIndicator(), SizedBox(height: 16), Text('Waiting for the other device…')]),
            _HandStep.compare || _HandStep.working => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Make this ${platformLabelOf(hand?.platform)} your primary device?', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 12),
                Center(child: ConfirmationCode(code: hand?.code ?? '')),
                const SizedBox(height: 12),
                Text('Check the other device shows the same code. It will hold your keys; this device stays linked and keeps your chats. Contacts keep their verification.', style: TextStyle(color: muted)),
                const SizedBox(height: 20),
                Row(
                  children: [
                    Expanded(child: OutlinedButton(onPressed: _step == _HandStep.working ? null : () => Navigator.of(context).pop(), child: const Text("Codes don't match"))),
                    const SizedBox(width: 12),
                    Expanded(
                      child: FilledButton(
                        key: const Key('transfer-confirm'),
                        onPressed: _step == _HandStep.working ? null : _approve,
                        child: Text(_step == _HandStep.working ? 'Handing over…' : 'Make primary'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          },
        ],
      ),
    );
  }
}

class TakeOverScreen extends ConsumerStatefulWidget {
  const TakeOverScreen({super.key});
  @override
  ConsumerState<TakeOverScreen> createState() => _TakeOverScreenState();
}

class _TakeOverScreenState extends ConsumerState<TakeOverScreen> {
  TakeOver? _take;
  String? _error;
  bool _done = false;

  @override
  void initState() {
    super.initState();
    unawaited(_run());
  }

  @override
  void dispose() {
    final take = _take;
    if (take != null && !_done) unawaited(take.cancel());
    super.dispose();
  }

  Future<void> _run() async {
    final app = ref.read(appProvider.notifier);
    try {
      final take = await app.startTakeOver();
      if (!mounted) return unawaited(take.cancel());
      setState(() => _take = take);
      await take.waitOffer();
      if (!mounted) return;
      setState(() {});
      await app.finishTakeOver(take);
      _done = true;
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) setState(() => _error = _message(e));
    }
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final take = _take, code = take?.code;
    return Scaffold(
      appBar: AppBar(title: const Text('Make this device primary')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          _errorText(context, _error),
          if (take == null && _error == null)
            const Center(child: CircularProgressIndicator())
          else if (take != null && code == null) ...[
            const Text('On your primary device, open Settings → Devices → Hand over to another device, and scan this.', textAlign: TextAlign.center),
            const SizedBox(height: 16),
            Center(child: LinkQr(data: take.qr)),
            const SizedBox(height: 12),
            SelectableText(take.qr, key: const Key('transfer-qr-text'), textAlign: TextAlign.center, style: TextStyle(color: muted, fontSize: 12)),
            TextButton.icon(onPressed: () => Clipboard.setData(ClipboardData(text: take.qr)), icon: const Icon(Icons.copy, size: 16), label: const Text('Copy the text instead')),
          ] else if (code != null) ...[
            const Text('Check your primary shows the same code, then confirm there. Keep this screen open.', textAlign: TextAlign.center),
            const SizedBox(height: 16),
            Center(child: ConfirmationCode(code: code)),
            const SizedBox(height: 16),
            const LinearProgressIndicator(),
          ],
        ],
      ),
    );
  }
}

String platformLabelOf(String? platform) =>
    const {'web': 'web browser', 'ios': 'iPhone', 'android': 'Android phone', 'macos': 'Mac', 'windows': 'Windows PC', 'linux': 'Linux computer'}[platform] ?? 'device';
