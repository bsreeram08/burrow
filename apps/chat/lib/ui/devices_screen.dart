import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../messaging/messenger.dart' show OwnDevice;
import 'link/link_device_screen.dart';
import 'link/transfer_screen.dart';
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

  Future<void> _revoke(OwnDevice d) async {
    setState(() => _busy = true);
    try {
      if (await confirmRevoke(context, ref, d.id, d.label ?? platformName(d.platform))) {
        // On the primary, publish the list without it right away (other devices wait for the primary).
        final messenger = ref.read(appProvider.notifier).messenger;
        if (_devices?.any((x) => x.current && x.primary) ?? false) await messenger?.publishNextList().then((_) => null, onError: (_) => null);
        if (mounted) showSnack(context, '${d.label ?? platformName(d.platform)} was revoked.');
      }
      await _load();
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
                    // Any device of the account can revoke another (never the primary: that is a transfer).
                    trailing: !d.current && !d.primary && d.state != 'revoked'
                        ? TextButton(
                            key: ValueKey('revoke-${d.id}'),
                            onPressed: _busy ? null : () => _revoke(d),
                            child: Text('Revoke', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                          )
                        : null,
                  ),
                if (amPrimary)
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: FilledButton.icon(
                      key: const Key('device-link-new'),
                      onPressed: () async {
                        await showLinkDevice(context);
                        await _load();
                      },
                      icon: const Icon(Icons.add_link),
                      label: const Text('Link a device'),
                    ),
                  ),
                // Primary transfer (m5 §5): the primary hands over; a linked device takes over.
                if (amPrimary && devices.any((d) => !d.current && d.state == 'listed'))
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    child: OutlinedButton.icon(
                      key: const Key('device-hand-over'),
                      onPressed: () async {
                        await showHandOver(context);
                        await _load();
                      },
                      icon: const Icon(Icons.swap_horiz),
                      label: const Text('Hand over to another device'),
                    ),
                  ),
                if (ref.watch(appProvider.select((s) => s.companion)))
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: OutlinedButton.icon(
                      key: const Key('device-take-over'),
                      onPressed: () async {
                        await showTakeOver(context);
                        await _load();
                      },
                      icon: const Icon(Icons.key),
                      label: const Text('Make this device primary'),
                    ),
                  ),
              ],
            ),
    );
  }
}
