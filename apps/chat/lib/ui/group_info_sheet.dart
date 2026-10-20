import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../messaging/group_messenger.dart';
import '../store/message.dart' show StoreException;
import '../store/message_store.dart' show GroupConversation, GroupKindName;
import 'safety_sheet.dart';
import 'widgets/common.dart';

/// The conversation info sheet (design notes §4): name and topic, members with roles, add and remove
/// people, security codes, pin, encryption, leave.
Future<void> showGroupInfo(BuildContext context, WidgetRef ref, String groupId) => showModalBottomSheet<void>(
  context: context,
  isScrollControlled: true,
  builder: (_) => GroupInfoSheet(groupId: groupId),
);

/// A member's security code (any member, contact or not), with the same review actions as a contact's.
Future<void> showMemberSafety(BuildContext context, WidgetRef ref, String userId, String username) async {
  final app = ref.read(appProvider.notifier);
  final me = ref.read(appProvider).user;
  final crypto = ref.read(cryptoProvider);
  if (me == null) return;
  var safety = await crypto.safety(me.username, userId, username);
  if (safety == null) {
    await app.groups?.ensurePinned([userId]);
    safety = await crypto.safety(me.username, userId, username);
  }
  if (!context.mounted) return;
  if (safety == null) {
    showSnack(context, "Couldn't get $username's security code. Try again when you're online.");
    return;
  }
  final result = await showSafetySheet(context, username, safety);
  if (result == null) return;
  await app.reviewedKey(userId, verified: result == SafetyAction.verify);
  if (result == SafetyAction.unverify) await crypto.setVerified(userId, false);
}

class GroupInfoSheet extends ConsumerStatefulWidget {
  const GroupInfoSheet({super.key, required this.groupId});
  final String groupId;
  @override
  ConsumerState<GroupInfoSheet> createState() => _GroupInfoSheetState();
}

class _GroupInfoSheetState extends ConsumerState<GroupInfoSheet> {
  List<GroupPerson> _members = const [];
  bool _admin = false, _busy = false;

  GroupMessenger? get _groups => ref.read(appProvider.notifier).groups;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  Future<void> _load() async {
    final groups = _groups;
    if (groups == null) return;
    final members = await groups.members(widget.groupId, refresh: true);
    final admin = await groups.isAdmin(widget.groupId);
    if (mounted) {
      setState(() {
        _members = members;
        _admin = admin;
      });
    }
  }

  Future<void> _run(Future<void> Function() task) async {
    setState(() => _busy = true);
    try {
      await task();
      await _load();
    } on ApiException catch (e) {
      if (mounted) showSnack(context, e.message);
    } on StoreException catch (e) {
      if (mounted) showSnack(context, e.message);
    } catch (e) {
      if (mounted) showSnack(context, '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _edit(GroupConversation group) async {
    final name = TextEditingController(text: group.name), topic = TextEditingController(text: group.topic);
    final save = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Name and topic'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              key: const Key('meta-name'),
              controller: name,
              maxLength: 64,
              enabled: group.kind != GroupKindName.public,
              decoration: InputDecoration(labelText: 'Name', helperText: group.kind == GroupKindName.public ? 'A public channel keeps the name it was created with.' : null),
            ),
            TextField(key: const Key('meta-topic'), controller: topic, maxLength: 256, decoration: const InputDecoration(labelText: 'Topic')),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(key: const Key('meta-save'), onPressed: () => Navigator.pop(context, true), child: const Text('Save')),
        ],
      ),
    );
    if (save == true) {
      await _run(() => _groups!.setMeta(widget.groupId, name: group.kind == GroupKindName.public ? '' : name.text, topic: topic.text));
    }
    name.dispose();
    topic.dispose();
  }

  Future<void> _add() async {
    final contacts = [
      for (final c in ref.read(appProvider).contacts)
        if (c.state == ContactState.mutual && c.id != null && !_members.any((m) => m.userId == c.id)) c,
    ];
    if (contacts.isEmpty) {
      showSnack(context, 'Everyone in your contacts is already here. Add contacts first to invite more people.');
      return;
    }
    final picked = await showModalBottomSheet<Set<String>>(context: context, isScrollControlled: true, builder: (_) => _PickPeople(contacts: contacts));
    if (picked == null || picked.isEmpty) return;
    await _run(() => _groups!.addMembers(widget.groupId, picked.toList()));
  }

  Future<void> _member(GroupPerson person, String me) async {
    final action = await showModalBottomSheet<String>(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(title: Text(person.username, style: const TextStyle(fontWeight: FontWeight.w700)), subtitle: Text(person.admin ? 'Admin' : 'Member')),
            if (person.userId != me) ListTile(leading: const Icon(Icons.shield_outlined), title: const Text('Security code'), onTap: () => Navigator.pop(context, 'safety')),
            if (_admin && !person.admin) ListTile(key: const Key('make-admin'), leading: const Icon(Icons.star_outline), title: const Text('Make admin'), onTap: () => Navigator.pop(context, 'admin')),
            if (_admin && person.userId != me)
              ListTile(
                key: const Key('remove-member'),
                leading: Icon(Icons.person_remove_outlined, color: Theme.of(context).colorScheme.error),
                title: Text('Remove from this ${_kindWord()}', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                onTap: () => Navigator.pop(context, 'remove'),
              ),
          ],
        ),
      ),
    );
    if (!mounted) return;
    switch (action) {
      case 'safety':
        await showMemberSafety(context, ref, person.userId, person.username);
      case 'admin':
        await _run(() => _groups!.makeAdmin(widget.groupId, person.userId));
      case 'remove':
        await _run(() => _groups!.removeMember(widget.groupId, person.userId));
    }
  }

  String _kindWord() => (ref.read(appProvider.notifier).groupById(widget.groupId)?.kind.isChannel ?? false) ? 'channel' : 'group';

  Future<void> _leave() async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Leave this ${_kindWord()}?'),
        content: const Text("You stop receiving its messages on all your devices. What's on this device stays until you delete it."),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Stay')),
          FilledButton(key: const Key('leave-confirm'), style: FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error), onPressed: () => Navigator.pop(context, true), child: const Text('Leave')),
        ],
      ),
    );
    if (yes == true) await _run(() => _groups!.leave(widget.groupId));
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(appProvider);
    final app = ref.read(appProvider.notifier);
    final group = app.groupById(widget.groupId);
    if (group == null) return const SizedBox.shrink();
    final me = state.user?.id ?? '';
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final name = app.groups?.displayName(group) ?? group.name;
    final kind = switch (group.kind) {
      GroupKindName.public => 'Public channel',
      GroupKindName.private => 'Private channel',
      _ => 'Group',
    };
    final canAdd = group.active && (_admin || group.kind == GroupKindName.public);
    return SafeArea(
      child: SizedBox(
        height: MediaQuery.sizeOf(context).height * .85,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 20),
          children: [
            Row(
              children: [
                Expanded(child: Text(group.kind.isChannel ? '#$name' : name, key: const Key('info-name'), style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800))),
                if (_admin && group.active) IconButton(key: const Key('edit-meta'), tooltip: 'Edit name and topic', onPressed: () => _edit(group), icon: const Icon(Icons.edit_outlined)),
              ],
            ),
            Text('$kind · ${_members.length} ${_members.length == 1 ? 'member' : 'members'}', style: TextStyle(color: muted)),
            if (group.topic.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8), child: Text(group.topic, key: const Key('info-topic'))),
            const SizedBox(height: 12),
            Row(
              children: [
                Icon(Icons.lock_outline, size: 16, color: muted),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    'End-to-end encrypted with MLS. New members see messages from when they join.${group.kind == GroupKindName.public ? ' The server knows this channel\'s name.' : ''}',
                    style: TextStyle(color: muted, fontSize: 13),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Keep this chat at the top'),
              value: group.pinned,
              onChanged: (on) => app.groups?.setPinned(group.id, on),
            ),
            const Divider(),
            Row(
              children: [
                Expanded(child: Text('Members', style: Theme.of(context).textTheme.titleMedium)),
                if (canAdd) TextButton.icon(key: const Key('add-people'), onPressed: _busy ? null : _add, icon: const Icon(Icons.person_add_alt_1_outlined), label: const Text('Add people')),
              ],
            ),
            if (_busy) const LinearProgressIndicator(),
            for (final m in _members)
              ListTile(
                key: ValueKey('member-${m.username}'),
                contentPadding: EdgeInsets.zero,
                leading: Avatar(name: m.username, size: 36),
                title: Text(m.userId == me ? '${m.username} (you)' : m.username),
                trailing: m.admin ? const Chip(label: Text('Admin'), visualDensity: VisualDensity.compact) : null,
                onTap: group.active ? () => _member(m, me) : null,
              ),
            const Divider(),
            if (group.active)
              ListTile(
                key: const Key('leave-group'),
                contentPadding: EdgeInsets.zero,
                leading: Icon(Icons.logout, color: Theme.of(context).colorScheme.error),
                title: Text('Leave ${_kindWord()}', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                onTap: _busy ? null : _leave,
              )
            else
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(Icons.delete_outline, color: Theme.of(context).colorScheme.error),
                title: Text('Delete from this device', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                onTap: () async {
                  await app.groups?.forget(group.id);
                  if (context.mounted) {
                    Navigator.pop(context);
                    context.go('/');
                  }
                },
              ),
          ],
        ),
      ),
    );
  }
}

class _PickPeople extends StatefulWidget {
  const _PickPeople({required this.contacts});
  final List<Contact> contacts;
  @override
  State<_PickPeople> createState() => _PickPeopleState();
}

class _PickPeopleState extends State<_PickPeople> {
  final Set<String> _picked = {};
  @override
  Widget build(BuildContext context) => SafeArea(
    child: ConstrainedBox(
      constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * .7),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 4, 20, 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Add people', style: Theme.of(context).textTheme.titleLarge),
            Flexible(
              child: ListView(
                shrinkWrap: true,
                children: [
                  for (final c in widget.contacts)
                    CheckboxListTile(
                      key: ValueKey('add-${c.username}'),
                      value: _picked.contains(c.id),
                      onChanged: (on) => setState(() => on == true ? _picked.add(c.id!) : _picked.remove(c.id)),
                      secondary: Avatar(name: c.username, size: 36),
                      title: Text(c.username),
                    ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            FilledButton(key: const Key('add-confirm'), onPressed: _picked.isEmpty ? null : () => Navigator.pop(context, _picked), child: const Text('Add')),
          ],
        ),
      ),
    ),
  );
}
