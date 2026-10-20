import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../crypto/chat_crypto.dart' show CryptoException;
import '../messaging/messenger.dart' show OwnDevice;
import 'widgets/common.dart';

/// Settings → Devices: this account's devices, labelled from the sealed list where this device can open it.
/// The primary (the device holding the account key) can remove the others.
Future<void> showDevices(BuildContext context) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const DevicesScreen()));

String platformName(String platform) =>
    const {'web': 'Web browser', 'ios': 'iPhone app', 'android': 'Android app', 'macos': 'Mac app', 'windows': 'Windows app', 'linux': 'Linux app'}[platform] ?? 'Device';

class DevicesScreen extends ConsumerStatefulWidget {
  const DevicesScreen({super.key});
  @override
  ConsumerState<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends ConsumerState<DevicesScreen> {
  List<OwnDevice>? _devices;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  Future<void> _load() async {
    final messenger = ref.read(appProvider.notifier).messenger;
    if (messenger == null) return;
    try {
      final list = await messenger.ownDevices();
      if (mounted) setState(() => _devices = list);
    } catch (e) {
      if (mounted) setState(() => _error = e is ApiException ? e.message : "Couldn't load your devices. Check your connection and try again.");
    }
  }

  Future<void> _remove(OwnDevice device) async {
    final name = device.label ?? platformName(device.platform);
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Remove $name?'),
        content: const Text("It's signed out and can no longer read new messages. To use it again, link it from this device."),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(
            key: const Key('device-remove-confirm'),
            style: FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (yes != true) return;
    setState(() => _busy = true);
    try {
      await ref.read(appProvider.notifier).messenger!.removeOwnDevice(device);
      if (mounted) showSnack(context, '$name was removed.');
      await _load();
    } on ApiException catch (e) {
      if (mounted) showSnack(context, e.message);
    } on CryptoException catch (e) {
      if (mounted) showSnack(context, e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final devices = _devices;
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final amPrimary = devices?.any((d) => d.current && d.primary) ?? false;
    return Scaffold(
      appBar: AppBar(title: const Text('Devices')),
      body: _error != null
          ? Center(child: Padding(padding: const EdgeInsets.all(24), child: Text(_error!, textAlign: TextAlign.center)))
          : devices == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              children: [
                if (_busy) const LinearProgressIndicator(),
                for (final d in devices)
                  ListTile(
                    key: ValueKey('device-${d.id}'),
                    leading: Icon(switch (d.platform) {
                      'web' => Icons.public,
                      'ios' || 'android' => Icons.smartphone,
                      _ => Icons.laptop_mac,
                    }),
                    title: Text(d.label ?? platformName(d.platform)),
                    subtitle: Text(
                      [
                        if (d.current) 'This device',
                        if (d.primary) 'Primary · holds your keys',
                        if (d.state == 'pending') 'Signed in · not linked',
                        if (d.lastSeenAt != null) 'Last seen ${DateTime.fromMillisecondsSinceEpoch(d.lastSeenAt!).toLocal().toString().substring(0, 16)}',
                      ].join(' · '),
                      style: TextStyle(color: muted),
                    ),
                    trailing: amPrimary && !d.current && !d.primary
                        ? TextButton(onPressed: _busy ? null : () => _remove(d), child: Text('Remove', style: TextStyle(color: Theme.of(context).colorScheme.error)))
                        : null,
                  ),
              ],
            ),
    );
  }
}
