import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_callkit_incoming/entities/entities.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'app/app_controller.dart';
import 'push/push_service.dart';
import 'theme/theme_prefs.dart';
import 'ui/call_screen.dart';
import 'ui/chat_list_screen.dart';
import 'ui/command_palette.dart';
import 'ui/conversation_screen.dart';
import 'ui/group_screen.dart';
import 'ui/incoming_call.dart';
import 'ui/welcome_screen.dart';

/// Bumped when the app speaks a newer protocol; compared with `/api/version`'s `minClient`.
const clientVersion = 1;

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ProviderScope(child: PrivateChatApp()));
}

final routerProvider = Provider<GoRouter>((ref) {
  final refresh = ValueNotifier(0);
  ref.listen(appProvider.select((s) => s.phase), (_, _) => refresh.value++);
  ref.onDispose(refresh.dispose);
  return GoRouter(
    refreshListenable: refresh,
    redirect: (context, state) {
      final phase = ref.read(appProvider).phase;
      final signedIn = phase == AuthPhase.signedIn;
      if (phase == AuthPhase.loading) return state.matchedLocation == '/loading' ? null : '/loading';
      if (!signedIn) return state.matchedLocation == '/welcome' ? null : '/welcome';
      if (state.matchedLocation == '/welcome' || state.matchedLocation == '/loading') return '/';
      return null;
    },
    routes: [
      GoRoute(path: '/loading', builder: (_, _) => const Scaffold(body: Center(child: CircularProgressIndicator()))),
      GoRoute(path: '/welcome', builder: (_, state) => WelcomeScreen(invite: _invite(state.uri))),
      GoRoute(path: '/', builder: (_, _) => const ChatListScreen()),
      GoRoute(path: '/chat/:id', builder: (_, state) => ConversationScreen(contactId: state.pathParameters['id']!)),
      GoRoute(path: '/group/:id', builder: (_, state) => GroupScreen(groupId: state.pathParameters['id']!)),
      GoRoute(path: '/call', pageBuilder: (_, _) => const MaterialPage(fullscreenDialog: true, child: CallScreen())),
    ],
  );
});

/// Invite links are `https://calls.sreerams.in/#invite=CODE`.
String? _invite(Uri uri) {
  final match = RegExp(r'invite=([A-Za-z0-9_-]{22})').firstMatch(uri.fragment);
  return match?.group(1);
}

class PrivateChatApp extends ConsumerStatefulWidget {
  const PrivateChatApp({super.key});
  @override
  ConsumerState<PrivateChatApp> createState() => _PrivateChatAppState();
}

class _PrivateChatAppState extends ConsumerState<PrivateChatApp> with WidgetsBindingObserver {
  final _subscriptions = <StreamSubscription<Object?>>[];
  PushService? _push;
  String? _callkitAccepted;
  bool _updateRequired = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(ref.read(themePrefsProvider.notifier).load(null));
    unawaited(ref.read(appProvider.notifier).restore());
    unawaited(_checkVersion());
  }

  Future<void> _checkVersion() async {
    try {
      final api = ref.read(apiProvider);
      final min = (await api.version())['minClient'];
      final required = min is Map ? (min[api.client] ?? min['native']) : null;
      if (required is int && required > clientVersion && mounted) setState(() => _updateRequired = true);
    } catch (_) {}
  }

  void _startPush() {
    if (_push != null || !ref.read(pushEnabledProvider)) return;
    final push = PushService(ref.read(apiProvider));
    _push = push;
    final router = ref.read(routerProvider);
    _subscriptions
      ..add(push.opens.listen((username) {
        final contact = ref.read(appProvider).contacts.where((c) => c.username == username && c.id != null).firstOrNull;
        if (contact != null) router.push('/chat/${contact.id}');
      }))
      ..add(push.callEvents.listen(_onCallKit));
    unawaited(push.start());
  }

  /// Accept/Decline on the system call UI. Accept there IS the user's consent;
  /// the room credential arrives over the events connection, then the call starts.
  void _onCallKit(CallEvent? event) {
    final extra = switch (event) {
      CallEventActionCallAccept(:final callKitParams) || CallEventActionCallDecline(:final callKitParams) => callKitParams.extra,
      _ => null,
    };
    final from = extra?['from'] as String?;
    if (from == null) return;
    if (event is CallEventActionCallAccept) {
      _callkitAccepted = from;
      _acceptIfRinging();
    } else {
      final ring = ref.read(appProvider).incoming;
      if (ring?.contact.username == from) unawaited(ref.read(appProvider.notifier).decline());
    }
  }

  Future<void> _acceptIfRinging() async {
    final ring = ref.read(appProvider).incoming;
    if (ring == null || ring.contact.username != _callkitAccepted) return;
    _callkitAccepted = null;
    await ref.read(appProvider.notifier).accept(audioOnly: false);
    unawaited(ref.read(routerProvider).push('/call'));
  }

  @override
  void didChangePlatformBrightness() => ref.read(platformBrightnessProvider.notifier).set(WidgetsBinding.instance.platformDispatcher.platformBrightness);

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    for (final s in _subscriptions) {
      s.cancel();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final router = ref.watch(routerProvider);
    final prefs = ref.watch(themePrefsProvider);
    final tokens = prefs.tokens(null, ref.watch(platformBrightnessProvider));
    final textScale = prefs.display.textSize.scale;
    ref.listen(appProvider.select((s) => s.phase), (_, phase) {
      if (phase == AuthPhase.signedIn) _startPush();
    });
    ref.listen(appProvider.select((s) => s.incoming), (_, ring) {
      if (ring != null) _acceptIfRinging();
    });
    return MaterialApp.router(
      title: 'Private Chat',
      debugShowCheckedModeBanner: false,
      theme: tokens.material(),
      routerConfig: router,
      builder: (context, child) {
        final ring = ref.watch(appProvider.select((s) => s.incoming));
        final inactive = ref.watch(appProvider.select((s) => s.inactiveDevice));
        final locked = ref.watch(appProvider.select((s) => s.keysLocked));
        final media = MediaQuery.of(context);
        return PaletteShortcut(
          navigatorContext: () => router.routerDelegate.navigatorKey.currentContext,
          child: Stack(
            children: [
              MediaQuery(
                // Text size (S/M/L/XL) multiplies the system's own text scaling.
                data: media.copyWith(textScaler: _ScaledText(media.textScaler, textScale)),
                child: child ?? const SizedBox.shrink(),
              ),
              if (inactive && !locked) const Positioned(left: 0, right: 0, bottom: 0, child: InactiveDeviceBanner()),
              if (locked) const Positioned(left: 0, right: 0, bottom: 0, child: KeysLockedBanner()),
              if (_updateRequired)
                const Positioned(
                  left: 0,
                  right: 0,
                  bottom: 0,
                  child: Material(
                    color: Color(0xFF3D321A),
                    child: SafeArea(
                      top: false,
                      child: Padding(
                        padding: EdgeInsets.all(14),
                        child: Text('Update required: this app version is too old for the server.', style: TextStyle(color: Color(0xFFF2C14E))),
                      ),
                    ),
                  ),
                ),
              if (ring != null)
                Positioned.fill(
                  child: IncomingCallCard(
                    caller: ring.contact.username,
                    video: ring.kind == 'video',
                    onDecline: ref.read(appProvider.notifier).decline,
                    onAccept: ({required audioOnly}) async {
                      await ref.read(appProvider.notifier).accept(audioOnly: audioOnly);
                      unawaited(router.push('/call'));
                    },
                  ),
                ),
            ],
          ),
        );
      },
    );
  }
}

class _ScaledText extends TextScaler {
  const _ScaledText(this.base, this.factor);
  final TextScaler base;
  final double factor;
  @override
  double scale(double fontSize) => base.scale(fontSize) * factor;
  @override
  // ignore: deprecated_member_use
  double get textScaleFactor => base.textScaleFactor * factor;
  @override
  bool operator ==(Object other) => other is _ScaledText && other.base == base && other.factor == factor;
  @override
  int get hashCode => Object.hash(base, factor);
}

/// Shown while another device or browser holds this account's encryption keys.
class InactiveDeviceBanner extends ConsumerWidget {
  const InactiveDeviceBanner({super.key});
  @override
  Widget build(BuildContext context, WidgetRef ref) => Material(
    color: const Color(0xFF3D321A),
    child: SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 12, 12),
        child: Row(
          children: [
            const Expanded(
              child: Text('Encrypted messaging for this account is active on another device or browser.', style: TextStyle(color: Color(0xFFF2C14E))),
            ),
            const SizedBox(width: 8),
            FilledButton(
              key: const Key('use-this-device'),
              onPressed: () async {
                final yes = await showDialog<bool>(
                  context: context,
                  builder: (context) => AlertDialog(
                    title: const Text('Start over on this device?'),
                    content: const Text(
                      'Do this only if your primary device is lost. This device makes new keys for your account: everyone you talk to sees that your security code changed, and your other devices stop working until you link them again.',
                    ),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
                      FilledButton(key: const Key('use-this-device-confirm'), onPressed: () => Navigator.pop(context, true), child: const Text('Start over here')),
                    ],
                  ),
                );
                if (yes == true) await ref.read(appProvider.notifier).useThisDevice();
              },
              child: const Text('Use this device instead'),
            ),
          ],
        ),
      ),
    ),
  );
}

/// This device's key database can't be unlocked (store key missing, database reset or tampered). Messaging
/// stays off; nothing is reset until the user explicitly chooses to start over on this device.
class KeysLockedBanner extends ConsumerWidget {
  const KeysLockedBanner({super.key});
  Future<void> _recover(BuildContext context, WidgetRef ref) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Start encrypted messaging over on this device?'),
        content: const Text(
          "This device's encryption keys can't be unlocked, so it can't read new messages. Starting over creates "
          'new keys here. Your contacts will see that your security code changed, and messages sent to the old '
          'keys can\'t be recovered. Message history already on this device stays.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Not now')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Start over')),
        ],
      ),
    );
    if (yes == true) await ref.read(appProvider.notifier).recoverKeys();
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) => Material(
    color: const Color(0xFF3D1A1A),
    child: SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 12, 12),
        child: Row(
          children: [
            const Expanded(
              child: Text(
                "This device's encryption keys can't be unlocked. Messaging is paused; nothing has been reset.",
                style: TextStyle(color: Color(0xFFF28B82)),
              ),
            ),
            const SizedBox(width: 8),
            FilledButton(key: const Key('recover-keys'), onPressed: () => _recover(context, ref), child: const Text('Recover')),
          ],
        ),
      ),
    ),
  );
}
