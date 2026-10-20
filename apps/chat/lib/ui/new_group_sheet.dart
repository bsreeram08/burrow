import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../store/message.dart' show StoreException;
import '../store/message_store.dart' show GroupKindName;
import 'widgets/common.dart';

/// Group: 2–8 other people (m4-groups §1). Channels: any number, named.
const minGroupPeople = 2, maxGroupPeople = 8;
final publicChannelName = RegExp(r'^[\p{L}\p{N}_\- ]{1,64}$', unicode: true);

/// "New group", "New private channel", "New public channel": a name, a topic and contacts to add.
Future<void> showNewGroupSheet(BuildContext context, WidgetRef ref, {required GroupKindName kind}) async {
  final id = await showModalBottomSheet<String>(
    context: context,
    isScrollControlled: true,
    builder: (context) => Padding(padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom), child: NewGroupSheet(kind: kind)),
  );
  if (id != null && context.mounted) await context.push('/group/$id');
}

class NewGroupSheet extends ConsumerStatefulWidget {
  const NewGroupSheet({super.key, required this.kind});
  final GroupKindName kind;
  @override
  ConsumerState<NewGroupSheet> createState() => _NewGroupSheetState();
}

class _NewGroupSheetState extends ConsumerState<NewGroupSheet> {
  final _name = TextEditingController(), _topic = TextEditingController();
  final Set<String> _picked = {};
  bool _busy = false;
  String? _error;

  bool get _group => widget.kind == GroupKindName.groupDm;

  String get _title => switch (widget.kind) {
    GroupKindName.public => 'New public channel',
    GroupKindName.private => 'New private channel',
    _ => 'New group',
  };

  String? get _problem {
    final name = _name.text.trim();
    if (_group && (_picked.length < minGroupPeople || _picked.length > maxGroupPeople)) return 'Pick two to eight people to start a group.';
    if (!_group && name.isEmpty) return 'A channel needs a name.';
    if (widget.kind == GroupKindName.public && !publicChannelName.hasMatch(name)) return 'Public channel names use letters, digits, spaces, - or _ (up to 64).';
    if (name.runes.length > 64) return 'Names can be up to 64 characters.';
    return null;
  }

  @override
  void dispose() {
    _name.dispose();
    _topic.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    final problem = _problem;
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    final groups = ref.read(appProvider.notifier).groups;
    if (groups == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final group = await groups.create(widget.kind, name: _name.text.trim(), topic: _topic.text.trim(), memberIds: _picked.toList());
      if (mounted) Navigator.pop(context, group.id);
    } on ApiException catch (e) {
      setState(() => _error = e.message);
    } on StoreException catch (e) {
      setState(() => _error = e.message);
    } catch (e) {
      setState(() => _error = 'Could not create it: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final contacts = [for (final c in ref.watch(appProvider).contacts) if (c.state == ContactState.mutual && c.id != null) c];
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    return SafeArea(
      child: ConstrainedBox(
        constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * .85),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(_title, style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 4),
              Text(
                switch (widget.kind) {
                  GroupKindName.public => 'Anyone here can find and join it. The server sees its name, never its messages.',
                  GroupKindName.private => 'Only people you add can read it. Its name is end-to-end encrypted.',
                  _ => 'Choose at least two people for a group. Everything in it is end-to-end encrypted.',
                },
                style: TextStyle(color: muted),
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('group-name'),
                controller: _name,
                maxLength: 64,
                decoration: InputDecoration(labelText: _group ? 'Name (optional)' : 'Name', counterText: ''),
                onChanged: (_) => setState(() => _error = null),
              ),
              const SizedBox(height: 8),
              TextField(key: const Key('group-topic'), controller: _topic, maxLength: 256, decoration: const InputDecoration(labelText: 'Topic (optional)', counterText: '')),
              const SizedBox(height: 8),
              Text(_group ? 'People (${_picked.length} of 2–8)' : 'Add people (optional)', style: const TextStyle(fontWeight: FontWeight.w700)),
              Flexible(
                child: contacts.isEmpty
                    ? Padding(padding: const EdgeInsets.all(16), child: Text('Add contacts first: only people you have accepted can be added.', style: TextStyle(color: muted)))
                    : ListView(
                        shrinkWrap: true,
                        children: [
                          for (final c in contacts)
                            CheckboxListTile(
                              key: ValueKey('pick-${c.username}'),
                              value: _picked.contains(c.id),
                              onChanged: (on) => setState(() {
                                on == true ? _picked.add(c.id!) : _picked.remove(c.id);
                                _error = null;
                              }),
                              secondary: Avatar(name: c.username, size: 36),
                              title: Text(c.username),
                            ),
                        ],
                      ),
              ),
              if (_error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_error!, key: const Key('group-error'), style: TextStyle(color: Theme.of(context).colorScheme.error))),
              const SizedBox(height: 12),
              FilledButton(key: const Key('group-create'), onPressed: _busy ? null : _create, child: Text(_busy ? 'Creating…' : 'Create')),
            ],
          ),
        ),
      ),
    );
  }
}
