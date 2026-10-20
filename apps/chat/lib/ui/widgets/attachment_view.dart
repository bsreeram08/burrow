import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';
import 'dart:ui' show ImageFilter;

import 'package:flutter/material.dart';
import 'package:just_audio/just_audio.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../messaging/attachments.dart';
import '../../store/message.dart';
import '../../theme/tokens.dart';
import '../media_viewer.dart';
import 'common.dart';

/// One attachment inside a bubble (docs/phase1-protocol.md §3, §5). [onBubble] is the bubble's
/// text colour. Without a [service] (widget tests, demo) nothing is fetched.
class AttachmentView extends StatelessWidget {
  const AttachmentView({super.key, required this.attachment, required this.tokens, required this.onBubble, this.service, this.maxWidth = 320});
  final Attachment attachment;
  final ChatTokens tokens;
  final Color onBubble;
  final AttachmentService? service;
  final double maxWidth;

  @override
  Widget build(BuildContext context) => switch (attachment.kind) {
    'image' => _ImageAttachment(a: attachment, tokens: tokens, service: service, maxWidth: maxWidth),
    'video' => _VideoAttachment(a: attachment, tokens: tokens, service: service, maxWidth: maxWidth),
    'voice' || 'audio' => VoicePlayer(attachment: attachment, tokens: tokens, color: onBubble, service: service),
    _ => _FileAttachment(a: attachment, tokens: tokens, color: onBubble, service: service),
  };
}

/// Shared download state: idle (lazy), loading with progress, loaded bytes, or an error message.
mixin _Loads<T extends StatefulWidget> on State<T> {
  Attachment get attachment;
  AttachmentService? get service;
  Uint8List? bytes;
  String? error;
  bool loading = false;

  Future<Uint8List?> load() async {
    final s = service;
    if (s == null || loading) return bytes;
    setState(() {
      loading = true;
      error = null;
    });
    try {
      final data = await s.open(attachment);
      if (mounted) setState(() => bytes = data);
      return data;
    } on BlobUnreadable {
      if (mounted) setState(() => error = "That file couldn't be read.");
    } catch (_) {
      if (mounted) setState(() => error = "Couldn't load. Retry");
    } finally {
      if (mounted) setState(() => loading = false);
    }
    return null;
  }

  void startIfEager() {
    bytes = service?.cached(attachment);
    if (bytes == null && loadsEagerly(attachment)) WidgetsBinding.instance.addPostFrameCallback((_) => mounted ? load() : null);
  }
}

Size _fit(Attachment a, double maxWidth) {
  final w = (a.width ?? 4).toDouble(), h = (a.height ?? 3).toDouble();
  final width = math.min(maxWidth, math.max(120.0, w));
  final height = (width * h / w).clamp(80.0, 420.0);
  return Size(width, height);
}

Widget _thumb(String? thumb, Color fallback) {
  if (thumb == null) return ColoredBox(color: fallback);
  try {
    final data = base64.decode(thumb.substring(thumb.indexOf(',') + 1));
    return ImageFiltered(
      imageFilter: ImageFilter.blur(sigmaX: 12, sigmaY: 12, tileMode: TileMode.clamp),
      child: Image.memory(data, fit: BoxFit.cover, gaplessPlayback: true, errorBuilder: (_, _, _) => ColoredBox(color: fallback)),
    );
  } catch (_) {
    return ColoredBox(color: fallback);
  }
}

class _ProgressRing extends StatelessWidget {
  const _ProgressRing({required this.service, required this.attachment});
  final AttachmentService? service;
  final Attachment attachment;
  @override
  Widget build(BuildContext context) {
    final s = service;
    final ring = s == null
        ? const CircularProgressIndicator(strokeWidth: 3)
        : ValueListenableBuilder<double?>(valueListenable: s.progressOf(attachment), builder: (_, v, _) => CircularProgressIndicator(value: v, strokeWidth: 3));
    return Container(
      width: 46,
      height: 46,
      padding: const EdgeInsets.all(8),
      decoration: const BoxDecoration(color: Color(0x88000000), shape: BoxShape.circle),
      child: Theme(data: ThemeData(progressIndicatorTheme: const ProgressIndicatorThemeData(color: Colors.white)), child: ring),
    );
  }
}

class _Overlay extends StatelessWidget {
  const _Overlay({required this.icon, required this.label, this.onTap});
  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  @override
  Widget build(BuildContext context) => Material(
    color: const Color(0x99000000),
    shape: const StadiumBorder(),
    child: InkWell(
      customBorder: const StadiumBorder(),
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(mainAxisSize: MainAxisSize.min, spacing: 6, children: [
          Icon(icon, color: Colors.white, size: 18),
          Flexible(child: Text(label, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600))),
        ]),
      ),
    ),
  );
}

class _ImageAttachment extends StatefulWidget {
  const _ImageAttachment({required this.a, required this.tokens, required this.service, required this.maxWidth});
  final Attachment a;
  final ChatTokens tokens;
  final AttachmentService? service;
  final double maxWidth;
  @override
  State<_ImageAttachment> createState() => _ImageAttachmentState();
}

class _ImageAttachmentState extends State<_ImageAttachment> with _Loads {
  @override
  Attachment get attachment => widget.a;
  @override
  AttachmentService? get service => widget.service;

  @override
  void initState() {
    super.initState();
    startIfEager();
  }

  @override
  Widget build(BuildContext context) {
    final size = _fit(widget.a, widget.maxWidth);
    final data = bytes;
    return Semantics(
      image: true,
      label: 'Photo ${widget.a.name}',
      child: GestureDetector(
        onTap: () async {
          final ready = data ?? await load();
          if (ready != null && context.mounted) unawaited(showImageViewer(context, ready, cleanName(widget.a.name)));
        },
        child: ClipRRect(
          borderRadius: BorderRadius.circular(12),
          child: SizedBox(
            width: size.width,
            height: size.height,
            child: Stack(
              fit: StackFit.expand,
              children: [
                _thumb(widget.a.thumb, widget.tokens.surface2),
                if (data != null)
                  Image.memory(data, fit: BoxFit.cover, gaplessPlayback: true, errorBuilder: (_, _, _) => const Center(child: Icon(Icons.broken_image_outlined))),
                if (data == null)
                  Center(
                    child: loading
                        ? _ProgressRing(service: widget.service, attachment: widget.a)
                        : error != null
                        ? _Overlay(icon: Icons.refresh, label: error!, onTap: error!.startsWith("That file") ? null : load)
                        : _Overlay(icon: Icons.download_rounded, label: fileSize(widget.a.size), onTap: load),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _VideoAttachment extends StatefulWidget {
  const _VideoAttachment({required this.a, required this.tokens, required this.service, required this.maxWidth});
  final Attachment a;
  final ChatTokens tokens;
  final AttachmentService? service;
  final double maxWidth;
  @override
  State<_VideoAttachment> createState() => _VideoAttachmentState();
}

class _VideoAttachmentState extends State<_VideoAttachment> with _Loads {
  @override
  Attachment get attachment => widget.a;
  @override
  AttachmentService? get service => widget.service;

  Future<void> _play() async {
    final s = widget.service;
    if (s == null) return;
    if (await load() == null) return;
    try {
      final file = await s.file(widget.a);
      if (mounted) unawaited(showVideoViewer(context, file, cleanName(widget.a.name)));
    } catch (_) {
      if (mounted) setState(() => error = "Couldn't load. Retry");
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = _fit(widget.a, widget.maxWidth);
    return Semantics(
      button: true,
      label: 'Video ${widget.a.name}',
      child: GestureDetector(
        onTap: loading ? null : _play,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(12),
          child: SizedBox(
            width: size.width,
            height: size.height,
            child: Stack(
              fit: StackFit.expand,
              children: [
                _thumb(widget.a.thumb, const Color(0xFF15181C)),
                Center(
                  child: loading
                      ? _ProgressRing(service: widget.service, attachment: widget.a)
                      : error != null
                      ? _Overlay(icon: Icons.refresh, label: error!, onTap: error!.startsWith("That file") ? null : _play)
                      : Container(
                          width: 54,
                          height: 54,
                          decoration: const BoxDecoration(color: Color(0x99000000), shape: BoxShape.circle),
                          child: const Icon(Icons.play_arrow_rounded, color: Colors.white, size: 34),
                        ),
                ),
                Positioned(
                  left: 8,
                  bottom: 8,
                  child: _Overlay(icon: Icons.videocam_outlined, label: [if (widget.a.duration != null) duration(widget.a.duration!), fileSize(widget.a.size)].join(' · ')),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

IconData _fileIcon(String mime) => switch (mime) {
  'application/pdf' => Icons.picture_as_pdf_outlined,
  'application/zip' => Icons.folder_zip_outlined,
  _ when mime.startsWith('image/') => Icons.image_outlined,
  _ when mime.startsWith('audio/') => Icons.audio_file_outlined,
  _ when mime.startsWith('video/') => Icons.video_file_outlined,
  _ when mime.startsWith('text/') => Icons.description_outlined,
  _ => Icons.insert_drive_file_outlined,
};

/// How to show a saved file in the desktop file manager without opening it: `open -R` selects it in
/// Finder, `explorer /select,` in Explorer. Null (Linux): open the containing folder instead.
({String executable, List<String> arguments})? revealCommand(String path, {String? os}) => switch (os ?? Platform.operatingSystem) {
  'macos' => (executable: '/usr/bin/open', arguments: ['-R', path]),
  'windows' => (executable: 'explorer.exe', arguments: ['/select,', path]),
  _ => null,
};

/// Desktop: saves to Downloads and reveals it in the file manager. A received file is never launched
/// here; the person opens it themselves. Phones: hands it to the share sheet, where they choose.
Future<String> deliverFile(AttachmentService service, Attachment a) async {
  if (Platform.isMacOS || Platform.isWindows || Platform.isLinux) {
    final dir = await getDownloadsDirectory() ?? await getApplicationDocumentsDirectory();
    final saved = await service.saveTo(a, dir);
    final reveal = revealCommand(saved.path);
    try {
      if (reveal == null) throw const ProcessException('', []);
      await Process.run(reveal.executable, reveal.arguments);
    } catch (_) {
      await launchUrl(Uri.directory(dir.path));
    }
    return 'Saved to ${dir.path.split(Platform.pathSeparator).last} as ${p.basename(saved.path)}.';
  }
  final file = await service.file(a);
  final name = cleanName(a.name);
  await SharePlus.instance.share(ShareParams(files: [XFile(file.path, mimeType: a.mime, name: name)], fileNameOverrides: [name]));
  return '';
}

class _FileAttachment extends StatefulWidget {
  const _FileAttachment({required this.a, required this.tokens, required this.color, required this.service});
  final Attachment a;
  final ChatTokens tokens;
  final Color color;
  final AttachmentService? service;
  @override
  State<_FileAttachment> createState() => _FileAttachmentState();
}

class _FileAttachmentState extends State<_FileAttachment> with _Loads {
  @override
  Attachment get attachment => widget.a;
  @override
  AttachmentService? get service => widget.service;

  Future<void> _open() async {
    final s = widget.service;
    if (s == null || await load() == null) return;
    try {
      final note = await deliverFile(s, widget.a);
      if (mounted && note.isNotEmpty) showSnack(context, note);
    } catch (_) {
      if (mounted) showSnack(context, "Couldn't open the file. Try again.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.color;
    return Semantics(
      button: true,
      label: 'File ${cleanName(widget.a.name)}, ${fileSize(widget.a.size)}',
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: loading || (error?.startsWith('That file') ?? false) ? null : _open,
        child: Container(
          constraints: const BoxConstraints(minWidth: 200, maxWidth: 300),
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(color: c.withValues(alpha: .08), borderRadius: BorderRadius.circular(12)),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(color: c.withValues(alpha: .12), borderRadius: BorderRadius.circular(10)),
                child: loading
                    ? Padding(
                        padding: const EdgeInsets.all(10),
                        child: ValueListenableBuilder<double?>(
                          valueListenable: widget.service?.progressOf(widget.a) ?? ValueNotifier(null),
                          builder: (_, v, _) => CircularProgressIndicator(value: v, strokeWidth: 2.5, color: c),
                        ),
                      )
                    : Icon(_fileIcon(widget.a.mime), color: c),
              ),
              const SizedBox(width: 10),
              Flexible(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(cleanName(widget.a.name), maxLines: 2, overflow: TextOverflow.ellipsis, style: TextStyle(color: c, fontWeight: FontWeight.w600, fontSize: 14.5)),
                    Text(
                      key: const Key('file-meta'),
                      error ?? [?extensionLabel(widget.a.name), fileSize(widget.a.size)].join(' · '),
                      style: TextStyle(color: error != null ? widget.tokens.dangerText : c.withValues(alpha: .7), fontSize: 12.5),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 6),
              Icon(error != null && !error!.startsWith('That file') ? Icons.refresh : Icons.download_rounded, color: c.withValues(alpha: .8), size: 20),
            ],
          ),
        ),
      ),
    );
  }
}

/// Whether this device's player can decode [mime]. Apple's AVFoundation has no WebM or Ogg/Opus
/// (what most browsers record), so those get a save / open fallback instead of a silent failure.
bool playableHere(String mime, {bool? apple}) {
  final base = mime.split(';').first.trim().toLowerCase();
  final codecs = mime.toLowerCase();
  final isApple = apple ?? (Platform.isIOS || Platform.isMacOS);
  if (!isApple) return true;
  return !(base == 'audio/webm' || base == 'video/webm' || base == 'audio/ogg' || base == 'audio/opus' || codecs.contains('opus') || codecs.contains('vorbis'));
}

/// Voice and audio: play/pause, a waveform you can scrub, duration and 1× / 1.5× / 2× speed.
class VoicePlayer extends StatefulWidget {
  const VoicePlayer({super.key, required this.attachment, required this.tokens, required this.color, this.service});
  final Attachment attachment;
  final ChatTokens tokens;
  final Color color;
  final AttachmentService? service;
  @override
  State<VoicePlayer> createState() => _VoicePlayerState();
}

class _VoicePlayerState extends State<VoicePlayer> with _Loads {
  @override
  Attachment get attachment => widget.attachment;
  @override
  AttachmentService? get service => widget.service;

  AudioPlayer? _player;
  final _subs = <StreamSubscription<Object?>>[];
  Duration _position = Duration.zero;
  Duration? _length;
  bool _playing = false;
  double _speed = 1;
  late bool _unplayable = !playableHere(widget.attachment.mime);

  Future<void> _save() async {
    final s = widget.service;
    if (s == null) return;
    try {
      final note = await deliverFile(s, widget.attachment);
      if (mounted && note.isNotEmpty) showSnack(context, note);
    } catch (_) {
      if (mounted) showSnack(context, "Couldn't save the recording. Try again.");
    }
  }

  @override
  void initState() {
    super.initState();
    startIfEager();
  }

  @override
  void dispose() {
    for (final s in _subs) {
      s.cancel();
    }
    _player?.dispose();
    super.dispose();
  }

  Future<AudioPlayer?> _ready() async {
    if (_player != null) return _player;
    final s = widget.service;
    if (s == null || await load() == null) return null;
    try {
      final file = await s.file(widget.attachment);
      final player = AudioPlayer();
      _length = await player.setFilePath(file.path);
      await player.setSpeed(_speed);
      _subs
        ..add(player.positionStream.listen((p) => mounted ? setState(() => _position = p) : null))
        ..add(player.playerStateStream.listen((state) {
          if (!mounted) return;
          if (state.processingState == ProcessingState.completed) {
            player.pause();
            player.seek(Duration.zero);
          }
          setState(() => _playing = state.playing && state.processingState != ProcessingState.completed);
        }));
      _player = player;
      return player;
    } catch (_) {
      if (mounted) setState(() => _unplayable = true);
      return null;
    }
  }

  Future<void> _toggle() async {
    final player = await _ready();
    if (player == null) return;
    player.playing ? await player.pause() : unawaited(player.play());
  }

  Future<void> _seek(double fraction) async {
    final player = await _ready();
    final total = _total;
    if (player == null || total == null) return;
    await player.seek(total * fraction.clamp(0, 1));
  }

  Duration? get _total => _length ?? (widget.attachment.duration == null ? null : Duration(milliseconds: (widget.attachment.duration! * 1000).round()));

  Future<void> _cycleSpeed() async {
    final next = _speed == 1 ? 1.5 : (_speed == 1.5 ? 2.0 : 1.0);
    setState(() => _speed = next);
    await _player?.setSpeed(next);
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.color, t = widget.tokens;
    if (_unplayable) {
      return SizedBox(
        width: 260,
        child: Row(
          children: [
            Icon(Icons.music_off_outlined, color: c.withValues(alpha: .8)),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text("This voice message can't play here", style: TextStyle(color: c, fontWeight: FontWeight.w600, fontSize: 14)),
                  Text(
                    'It was recorded in a format this device can\'t play. Save it to open in another app.',
                    style: TextStyle(color: c.withValues(alpha: .7), fontSize: 12.5),
                  ),
                ],
              ),
            ),
            TextButton(key: const Key('voice-save'), onPressed: widget.service == null ? null : _save, child: Text(Platform.isIOS ? 'Open' : 'Save')),
          ],
        ),
      );
    }
    final total = _total;
    final progress = total == null || total.inMilliseconds == 0 ? 0.0 : _position.inMilliseconds / total.inMilliseconds;
    final shown = _playing || _position > Duration.zero ? _position : (total ?? Duration.zero);
    final bars = widget.attachment.waveform ?? List<int>.generate(32, (i) => 6 + (math.sin(i * 1.7) * 5).round().abs());
    return SizedBox(
      width: 260,
      child: Row(
        children: [
          Semantics(
            button: true,
            label: _playing ? 'Pause voice message' : 'Play voice message',
            child: InkResponse(
              onTap: loading ? null : _toggle,
              child: Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(color: c.withValues(alpha: .14), shape: BoxShape.circle),
                child: loading
                    ? Padding(padding: const EdgeInsets.all(10), child: CircularProgressIndicator(strokeWidth: 2.5, color: c))
                    : Icon(_playing ? Icons.pause_rounded : Icons.play_arrow_rounded, color: c, size: 26),
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                LayoutBuilder(
                  builder: (context, box) => GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onTapDown: (d) => _seek(d.localPosition.dx / box.maxWidth),
                    onHorizontalDragUpdate: (d) => _seek(d.localPosition.dx / box.maxWidth),
                    child: Semantics(
                      slider: true,
                      label: 'Position',
                      value: '${(progress * 100).round()}%',
                      child: CustomPaint(size: Size(box.maxWidth, 28), painter: _WavePainter(bars, progress, c)),
                    ),
                  ),
                ),
                Row(
                  children: [
                    Text(error ?? duration(shown.inMilliseconds / 1000), style: TextStyle(color: error != null ? t.dangerText : c.withValues(alpha: .75), fontSize: 12)),
                    const Spacer(),
                    if (error == null)
                      InkWell(
                        borderRadius: BorderRadius.circular(8),
                        onTap: _cycleSpeed,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                          decoration: BoxDecoration(color: c.withValues(alpha: .12), borderRadius: BorderRadius.circular(8)),
                          child: Text('${_speed == 1.5 ? '1.5' : _speed.toStringAsFixed(0)}×', style: TextStyle(color: c, fontSize: 12, fontWeight: FontWeight.w700)),
                        ),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _WavePainter extends CustomPainter {
  _WavePainter(this.bars, this.progress, this.color);
  final List<int> bars;
  final double progress;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    if (bars.isEmpty) return;
    final step = size.width / bars.length;
    final width = math.max(1.5, step * .6);
    for (var i = 0; i < bars.length; i++) {
      final h = math.max(3.0, bars[i] / 31 * size.height);
      final x = i * step + step / 2;
      final played = (i + .5) / bars.length <= progress;
      canvas.drawRRect(
        RRect.fromRectAndRadius(Rect.fromCenter(center: Offset(x, size.height / 2), width: width, height: h), Radius.circular(width / 2)),
        Paint()..color = played ? color : color.withValues(alpha: .35),
      );
    }
  }

  @override
  bool shouldRepaint(_WavePainter old) => old.progress != progress || old.bars != bars || old.color != color;
}

/// The compact link card under a message: thumb, title, site. Tapping opens the page.
class LinkCard extends StatelessWidget {
  const LinkCard({super.key, required this.link, required this.color, this.onRemove, this.onTap});
  final LinkPreview link;
  final Color color;
  final VoidCallback? onRemove;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final host = Uri.tryParse(link.url)?.host ?? '';
    final thumb = link.thumb;
    return Semantics(
      link: true,
      label: 'Link preview: ${link.title ?? host}',
      child: InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: onTap,
        child: Container(
          constraints: const BoxConstraints(maxWidth: 320),
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withValues(alpha: .07),
            borderRadius: BorderRadius.circular(10),
            border: Border(left: BorderSide(color: color.withValues(alpha: .5), width: 3)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (thumb != null) ...[
                ClipRRect(
                  borderRadius: BorderRadius.circular(6),
                  child: SizedBox(width: 44, height: 44, child: Image.memory(base64.decode(thumb.substring(thumb.indexOf(',') + 1)), fit: BoxFit.cover, errorBuilder: (_, _, _) => const SizedBox())),
                ),
                const SizedBox(width: 10),
              ],
              Flexible(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(link.title ?? host, maxLines: 2, overflow: TextOverflow.ellipsis, style: TextStyle(color: color, fontWeight: FontWeight.w700, fontSize: 14)),
                    if (link.description != null && onRemove != null)
                      Text(link.description!, maxLines: 1, overflow: TextOverflow.ellipsis, style: TextStyle(color: color.withValues(alpha: .75), fontSize: 12.5)),
                    Text(link.site ?? host, maxLines: 1, overflow: TextOverflow.ellipsis, style: TextStyle(color: color.withValues(alpha: .65), fontSize: 12)),
                  ],
                ),
              ),
              if (onRemove != null)
                IconButton(tooltip: 'Remove link preview', visualDensity: VisualDensity.compact, onPressed: onRemove, icon: Icon(Icons.close, size: 18, color: color)),
            ],
          ),
        ),
      ),
    );
  }
}
