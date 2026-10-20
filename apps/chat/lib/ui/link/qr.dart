import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// A QR code for device linking (shown by the device being linked, typically a desktop).
class LinkQr extends StatelessWidget {
  const LinkQr({super.key, required this.data, this.size = 240});
  final String data;
  final double size;

  @override
  Widget build(BuildContext context) => Semantics(
    label: 'Linking code',
    child: Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
      // Dark modules on white whatever the theme: scanners read that best.
      child: QrImageView(data: data, size: size, backgroundColor: Colors.white, errorCorrectionLevel: QrErrorCorrectLevel.M),
    ),
  );
}

/// Scans one QR code with the camera (mobile_scanner: iOS, Android, macOS) and returns its text, or null if
/// cancelled. Where there is no camera, the code's text can be pasted instead.
Future<String?> showQrScanner(BuildContext context, {String title = 'Scan the code on your other device'}) =>
    Navigator.of(context).push<String>(MaterialPageRoute(fullscreenDialog: true, builder: (_) => QrScannerScreen(title: title)));

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key, required this.title});
  final String title;
  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen> {
  static final _camera = !kIsWeb && (Platform.isIOS || Platform.isAndroid || Platform.isMacOS);
  final MobileScannerController? _controller = _camera ? MobileScannerController(formats: const [BarcodeFormat.qrCode]) : null;
  final _paste = TextEditingController();
  bool _done = false;

  @override
  void dispose() {
    unawaited(_controller?.dispose());
    _paste.dispose();
    super.dispose();
  }

  void _finish(String? value) {
    if (_done || value == null || value.trim().isEmpty) return;
    _done = true;
    Navigator.pop(context, value.trim());
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: Text(widget.title)),
    body: Column(
      children: [
        if (_controller != null)
          Expanded(
            child: MobileScanner(
              controller: _controller,
              onDetect: (capture) => _finish(capture.barcodes.firstOrNull?.rawValue),
              errorBuilder: (context, error) => Center(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Text(
                    error.errorCode == MobileScannerErrorCode.permissionDenied
                        ? 'Camera access is off. Allow it in Settings, or paste the code below.'
                        : "The camera couldn't start. Paste the code below instead.",
                    textAlign: TextAlign.center,
                  ),
                ),
              ),
            ),
          )
        else
          const Expanded(child: Center(child: Text('No camera here. Paste the code shown on your other device.'))),
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    key: const Key('qr-paste'),
                    controller: _paste,
                    decoration: const InputDecoration(hintText: 'Or paste the code', isDense: true),
                    onSubmitted: _finish,
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  tooltip: 'Paste',
                  onPressed: () async => _paste.text = (await Clipboard.getData(Clipboard.kTextPlain))?.text ?? '',
                  icon: const Icon(Icons.content_paste_rounded),
                ),
                FilledButton(key: const Key('qr-paste-use'), onPressed: () => _finish(_paste.text), child: const Text('Use')),
              ],
            ),
          ),
        ),
      ],
    ),
  );
}

/// A short confirmation code both devices show, to compare before linking ("123 456").
class ConfirmationCode extends StatelessWidget {
  const ConfirmationCode({super.key, required this.code});
  final String code;
  @override
  Widget build(BuildContext context) => Semantics(
    label: 'Confirmation code ${code.split('').join(' ')}',
    child: Text(
      code,
      key: const Key('link-code'),
      style: Theme.of(context).textTheme.displaySmall?.copyWith(fontFeatures: const [FontFeature.tabularFigures()], letterSpacing: 4, fontWeight: FontWeight.w700),
    ),
  );
}
