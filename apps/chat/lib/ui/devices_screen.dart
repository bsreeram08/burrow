import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../messaging/messenger.dart' show OwnDevice;
import 'link/link_device_screen.dart';
import 'account/backup_screen.dart';
import 'account/unlock_screen.dart';
import 'widgets/common.dart';

/// Settings → Devices: this account's devices, labelled from the sealed list where this device can open it.
/// Any device can remove another; one that holds the account key also changes the key (M6 §6.2).
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
      final label = d.label ?? platformName(d.platform);
      if (await confirmRemove(context, ref, d.id, label)) {
        if (mounted) showSnack(context, '$label was removed.');
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
    final state = ref.watch(appProvider);
    final full = state.fullDevice, removed = state.removedListed;
    return Scaffold(
      appBar: AppBar(title: const Text('Devices')),
      body: _error != null
          ? Center(child: Padding(padding: const EdgeInsets.all(24), child: Text(_error!, textAlign: TextAlign.center)))
          : devices == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              children: [
                if (_busy) const LinearProgressIndicator(),
                // Removed from a device that couldn't change the account key: finish it here (M6 §6.2).
                if (removed != null && full)
                  MaterialBanner(
                    key: const Key('removed-needs-rotation'),
                    content: Text('${removed.label} was removed. Change your account key now?'),
                    actions: [
                      TextButton(
                        onPressed: _busy
                            ? null
                            : () async {
                                setState(() => _busy = true);
                                try {
                                  await confirmRemove(context, ref, removed.id, removed.label, alreadyRemoved: true);
                                  await _load();
                                } finally {
                                  if (mounted) setState(() => _busy = false);
                                }
                              },
                        child: const Text('Change account key'),
                      ),
                    ],
                  ),
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
                        if (d.current && d.state == 'listed') full ? 'Can unlock your account' : 'Waiting for keys',
                        // Key status only for this device (M6 §7); another shows how it was linked when its meta says.
                        if (!d.current && d.viaCode) 'Linked by code',
                        if (d.state == 'pending') 'Signed in · not set up',
                        if (d.state == 'revoked') 'Removed',
                        if (d.lastSeenAt != null) 'Last seen ${DateTime.fromMillisecondsSinceEpoch(d.lastSeenAt!).toLocal().toString().substring(0, 16)}',
                      ].join(' · '),
                      style: TextStyle(color: muted),
                    ),
                    trailing: d.current && d.state == 'listed' && !full && state.companion && (state.hasBackup ?? false)
                        ? TextButton(key: const Key('device-enter-passphrase'), onPressed: () => showUnlockThisDevice(context), child: const Text('Enter passphrase'))
                        : !d.current && d.state != 'revoked'
                        ? TextButton(
                            key: ValueKey('revoke-${d.id}'),
                            onPressed: _busy ? null : () => _revoke(d),
                            child: Text('Remove', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                          )
                        : null,
                  ),
                if (full) ...[
                  const Divider(),
                  ListTile(
                    key: const Key('device-backup'),
                    leading: const Icon(Icons.shield_outlined),
                    title: const Text('Account backup'),
                    subtitle: Text(backupStatus(state)),
                    onTap: () => showAccountBackup(context),
                  ),
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
                ],
              ],
            ),
    );
  }
}
