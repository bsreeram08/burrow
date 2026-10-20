import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../text/fuzzy.dart';
import 'widgets/common.dart';

/// "Browse channels" (enclave-teardown §3): the public channel directory, searchable; join with one tap.
Future<void> showChannelBrowser(BuildContext context, WidgetRef ref) async {
  final id = await showModalBottomSheet<String>(
    context: context,
    isScrollControlled: true,
    builder: (context) => Padding(padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom), child: const ChannelBrowser()),
  );
  if (id != null && context.mounted) await context.push('/group/$id');
}

class ChannelBrowser extends ConsumerStatefulWidget {
  const ChannelBrowser({super.key});
  @override
  ConsumerState<ChannelBrowser> createState() => _ChannelBrowserState();
}

class _ChannelBrowserState extends ConsumerState<ChannelBrowser> {
  final _query = TextEditingController();
  List<Map<String, dynamic>>? _channels;
  String? _error, _joining;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final groups = ref.read(appProvider.notifier).groups;
    try {
      final list = await groups!.directory();
      if (mounted) setState(() => _channels = list);
    } catch (e) {
      if (mounted) setState(() => _error = e is ApiException ? e.message : "Couldn't load the channel list. Check your connection and try again.");
    }
  }

  Future<void> _join(Map<String, dynamic> channel) async {
    final id = channel['id'] as String;
    final app = ref.read(appProvider.notifier);
    if (channel['joined'] == true && app.groupById(id)?.active == true) {
      Navigator.pop(context, id);
      return;
    }
    setState(() => _joining = id);
    try {
      await app.groups!.joinPublic(id);
      if (mounted) Navigator.pop(context, id);
    } catch (e) {
      if (mounted) showSnack(context, e is ApiException ? e.message : 'Could not join: $e');
    } finally {
      if (mounted) setState(() => _joining = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final channels = _channels == null ? null : fuzzyFilter(_query.text, _channels!, (c) => c['name'] as String? ?? '');
    return SafeArea(
      child: SizedBox(
        height: MediaQuery.sizeOf(context).height * .8,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text('Browse channels', style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 8),
              TextField(
                key: const Key('channel-search'),
                controller: _query,
                decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Find a public channel', isDense: true),
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 8),
              Expanded(
                child: _error != null
                    ? Center(child: Text(_error!, textAlign: TextAlign.center, style: TextStyle(color: muted)))
                    : channels == null
                    ? const Center(child: CircularProgressIndicator())
                    : channels.isEmpty
                    ? Center(
                        child: Text(
                          _query.text.isEmpty ? 'No public channels yet. Start one from the new chat menu.' : 'No channel matches that.',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: muted),
                        ),
                      )
                    : ListView.builder(
                        itemCount: channels.length,
                        itemBuilder: (context, i) {
                          final c = channels[i];
                          final joined = c['joined'] == true;
                          final members = c['members'] as int? ?? 0;
                          return ListTile(
                            key: ValueKey('channel-${c['name']}'),
                            leading: const Icon(Icons.tag),
                            title: Text(c['name'] as String? ?? '', style: const TextStyle(fontWeight: FontWeight.w700)),
                            subtitle: Text(members == 1 ? '1 member' : '$members members'),
                            trailing: _joining == c['id']
                                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                                : FilledButton.tonal(key: ValueKey('join-${c['name']}'), onPressed: () => _join(c), child: Text(joined ? 'Open' : 'Join')),
                            onTap: () => _join(c),
                          );
                        },
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
