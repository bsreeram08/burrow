import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:record/record.dart';

import '../../messaging/attachments.dart';
import '../../theme/tokens.dart';

/// A finished recording: AAC in an M4A container (`audio/mp4`), its length and waveform.
typedef VoiceNote = ({Uint8List bytes, double seconds, List<int> waveform});

/// The recording bar (§5): cancel (✕ or Esc), a live level meter, the timer, and send.
/// Recording starts as soon as the bar appears; [onCancel] also runs when the microphone is unavailable.
class VoiceRecorderBar extends StatefulWidget {
  const VoiceRecorderBar({super.key, required this.tokens, required this.onSend, required this.onCancel});
  final ChatTokens tokens;
  final void Function(VoiceNote note) onSend;
  final void Function(String? problem) onCancel;

  @override
  State<VoiceRecorderBar> createState() => _VoiceRecorderBarState();
}

class _VoiceRecorderBarState extends State<VoiceRecorderBar> {
  static const maxSeconds = 15 * 60;
  final _recorder = AudioRecorder();
  final _levels = <double>[];
  StreamSubscription<Amplitude>? _amplitude;
  final _started = Stopwatch();
  Timer? _tick;
  String? _path;
  bool _finishing = false;

  @override
  void initState() {
    super.initState();
    unawaited(_start());
  }

  Future<void> _start() async {
    try {
      if (!await _recorder.hasPermission()) {
        widget.onCancel('Allow microphone access in Settings to record voice messages.');
        return;
      }
      final dir = await getTemporaryDirectory();
      _path = p.join(dir.path, 'voice-${DateTime.now().microsecondsSinceEpoch}.m4a');
      await _recorder.start(const RecordConfig(encoder: AudioEncoder.aacLc, bitRate: 64000, sampleRate: 44100, numChannels: 1), path: _path!);
      _started.start();
      _amplitude = _recorder.onAmplitudeChanged(const Duration(milliseconds: 100)).listen((a) {
        if (!mounted) return;
        setState(() => _levels.add(a.current.isFinite ? a.current : -160));
      });
      _tick = Timer.periodic(const Duration(milliseconds: 250), (_) {
        if (!mounted) return;
        if (_started.elapsed.inSeconds >= maxSeconds) unawaited(_finish(send: true));
        setState(() {});
      });
    } catch (_) {
      widget.onCancel("Couldn't start recording. Check that a microphone is connected.");
    }
  }

  Future<void> _finish({required bool send}) async {
    if (_finishing) return;
    _finishing = true;
    _tick?.cancel();
    await _amplitude?.cancel();
    _started.stop();
    try {
      final path = send ? await _recorder.stop() : null;
      if (!send) await _recorder.cancel();
      if (path == null || _started.elapsed.inMilliseconds < 500) {
        widget.onCancel(send ? 'Hold on a little longer to record a voice message.' : null);
        return;
      }
      final file = File(path);
      final bytes = await file.readAsBytes();
      unawaited(file.delete().catchError((_) => file));
      widget.onSend((bytes: bytes, seconds: _started.elapsed.inMilliseconds / 1000, waveform: waveformFrom(_levels)));
    } catch (_) {
      widget.onCancel("Couldn't save the recording. Try again.");
    }
  }

  @override
  void dispose() {
    _tick?.cancel();
    _amplitude?.cancel();
    if (!_finishing) unawaited(_recorder.cancel().catchError((_) {}));
    unawaited(_recorder.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = widget.tokens;
    final recent = _levels.length > 40 ? _levels.sublist(_levels.length - 40) : _levels;
    return Focus(
      autofocus: true,
      onKeyEvent: (_, event) {
        if (event is KeyDownEvent && event.logicalKey == LogicalKeyboardKey.escape) {
          unawaited(_finish(send: false));
          return KeyEventResult.handled;
        }
        return KeyEventResult.ignored;
      },
      child: Row(
        children: [
          IconButton(tooltip: 'Cancel recording', onPressed: () => _finish(send: false), icon: Icon(Icons.close_rounded, color: t.muted)),
          Icon(Icons.fiber_manual_record, color: t.danger, size: 14),
          const SizedBox(width: 6),
          Text(duration(_started.elapsed.inMilliseconds / 1000), style: TextStyle(color: t.text, fontFeatures: const [FontFeature.tabularFigures()])),
          const SizedBox(width: 12),
          Expanded(
            child: Semantics(
              label: 'Recording level',
              child: SizedBox(height: 32, child: CustomPaint(painter: _LevelPainter(recent, t.accent))),
            ),
          ),
          const SizedBox(width: 8),
          IconButton.filled(
            key: const Key('send-voice'),
            tooltip: 'Send voice message',
            style: IconButton.styleFrom(backgroundColor: t.accent, fixedSize: const Size(46, 46)),
            onPressed: () => _finish(send: true),
            icon: Icon(Icons.arrow_upward_rounded, color: t.accentInk),
          ),
        ],
      ),
    );
  }
}

class _LevelPainter extends CustomPainter {
  _LevelPainter(this.levels, this.color);
  final List<double> levels;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    const count = 40;
    final step = size.width / count;
    final paint = Paint()..color = color;
    for (var i = 0; i < count; i++) {
      final index = levels.length - count + i;
      final db = index >= 0 ? levels[index] : -60.0;
      final h = math.max(3.0, ((db + 50) / 50).clamp(0.0, 1.0) * size.height);
      canvas.drawRRect(
        RRect.fromRectAndRadius(Rect.fromCenter(center: Offset(i * step + step / 2, size.height / 2), width: math.max(2, step * .55), height: h), const Radius.circular(2)),
        paint..color = index >= 0 ? color : color.withValues(alpha: .25),
      );
    }
  }

  @override
  bool shouldRepaint(_LevelPainter old) => true;
}
