import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:video_player/video_player.dart';

/// Full-window photo viewer with pinch / scroll zoom. Esc or the close button returns.
Future<void> showImageViewer(BuildContext context, Uint8List bytes, String name) => Navigator.of(context).push(
  PageRouteBuilder<void>(
    opaque: false,
    barrierColor: Colors.black,
    pageBuilder: (_, _, _) => _Viewer(
      name: name,
      child: InteractiveViewer(minScale: 1, maxScale: 6, child: Center(child: Image.memory(bytes, fit: BoxFit.contain))),
    ),
    transitionsBuilder: (_, animation, _, child) => FadeTransition(opacity: animation, child: child),
  ),
);

Future<void> showVideoViewer(BuildContext context, File file, String name) =>
    Navigator.of(context).push(MaterialPageRoute<void>(fullscreenDialog: true, builder: (_) => _Viewer(name: name, child: _VideoView(file: file))));

class _Viewer extends StatelessWidget {
  const _Viewer({required this.name, required this.child});
  final String name;
  final Widget child;

  @override
  Widget build(BuildContext context) => CallbackShortcuts(
    bindings: {const SingleActivator(LogicalKeyboardKey.escape): () => Navigator.maybePop(context)},
    child: Focus(
      autofocus: true,
      child: Scaffold(
        backgroundColor: Colors.black,
        appBar: AppBar(
          backgroundColor: Colors.black,
          foregroundColor: Colors.white,
          title: Text(name, style: const TextStyle(fontSize: 15), overflow: TextOverflow.ellipsis),
          leading: IconButton(tooltip: 'Close', icon: const Icon(Icons.close), onPressed: () => Navigator.pop(context)),
        ),
        body: SafeArea(child: child),
      ),
    ),
  );
}

class _VideoView extends StatefulWidget {
  const _VideoView({required this.file});
  final File file;
  @override
  State<_VideoView> createState() => _VideoViewState();
}

class _VideoViewState extends State<_VideoView> {
  late final VideoPlayerController _controller = VideoPlayerController.file(widget.file);
  String? _error;

  @override
  void initState() {
    super.initState();
    _controller.initialize().then((_) {
      if (!mounted) return;
      setState(() {});
      _controller.play();
    }, onError: (_) {
      if (mounted) setState(() => _error = "This video can't play on this device.");
    });
    _controller.addListener(_tick);
  }

  void _tick() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _controller.removeListener(_tick);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) return Center(child: Text(_error!, style: const TextStyle(color: Colors.white70)));
    final value = _controller.value;
    if (!value.isInitialized) return const Center(child: CircularProgressIndicator(color: Colors.white));
    return Column(
      children: [
        Expanded(
          child: GestureDetector(
            onTap: () => value.isPlaying ? _controller.pause() : _controller.play(),
            child: Center(child: AspectRatio(aspectRatio: value.aspectRatio, child: VideoPlayer(_controller))),
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(8, 8, 16, 16),
          child: Row(
            children: [
              IconButton(
                tooltip: value.isPlaying ? 'Pause' : 'Play',
                color: Colors.white,
                icon: Icon(value.isPlaying ? Icons.pause_rounded : Icons.play_arrow_rounded),
                onPressed: () => value.isPlaying ? _controller.pause() : _controller.play(),
              ),
              Expanded(child: VideoProgressIndicator(_controller, allowScrubbing: true, colors: const VideoProgressColors(playedColor: Colors.white))),
            ],
          ),
        ),
      ],
    );
  }
}
