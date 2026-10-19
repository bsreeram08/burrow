import 'dart:async';

import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math' as math;

import 'package:crypto/crypto.dart' as hash;
import 'package:flutter/foundation.dart';
import 'package:image/image.dart' as img;
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart';

import '../core/api.dart';
import '../store/message.dart';

/// Encrypted attachments (docs/phase1-protocol.md §3). Each file gets a fresh AES-256-GCM key; the
/// server stores `nonce(12) || ciphertext || tag(16)` and sees nothing else. The key and the SHA-256 of
/// that ciphertext travel inside the end-to-end encrypted message. Downloads are verified before
/// decrypting; plaintext is cached in memory and, for playback, in this app's temporary directory.

String b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
Uint8List unb64u(String text) => base64Url.decode(base64Url.normalize(text));

const _nonceBytes = 12, _tagBits = 128;

Uint8List _random(int n) {
  final r = math.Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => r.nextInt(256)));
}

/// `nonce || AES-256-GCM(key, nonce, plaintext)` with the 16-byte tag appended; no AAD.
Uint8List sealBlob(Uint8List key, Uint8List plaintext, {Uint8List? nonce}) {
  if (key.length != 32) throw ArgumentError('AES-256 needs a 32-byte key');
  final iv = nonce ?? _random(_nonceBytes);
  final gcm = GCMBlockCipher(AESEngine())..init(true, AEADParameters(KeyParameter(key), _tagBits, iv, Uint8List(0)));
  final sealed = gcm.process(plaintext);
  return Uint8List(iv.length + sealed.length)
    ..setAll(0, iv)
    ..setAll(iv.length, sealed);
}

/// Throws [BlobUnreadable] when the tag doesn't verify.
Uint8List openBlob(Uint8List key, Uint8List blob) {
  if (key.length != 32 || blob.length < _nonceBytes + 16) throw const BlobUnreadable();
  final gcm = GCMBlockCipher(AESEngine())..init(false, AEADParameters(KeyParameter(key), _tagBits, Uint8List.sublistView(blob, 0, _nonceBytes), Uint8List(0)));
  try {
    return gcm.process(Uint8List.sublistView(blob, _nonceBytes));
  } on InvalidCipherTextException {
    throw const BlobUnreadable();
  }
}

/// The file's hash or tag didn't match: never render it.
class BlobUnreadable implements Exception {
  const BlobUnreadable();
  @override
  String toString() => "That file couldn't be read.";
}

/// A ciphertext and what the message must carry to open it.
typedef Sealed = ({Uint8List ciphertext, String key, String sha256});

Sealed _seal(Uint8List plaintext) {
  final key = _random(32);
  final ciphertext = sealBlob(key, plaintext);
  return (ciphertext: ciphertext, key: b64u(key), sha256: b64u(hash.sha256.convert(ciphertext).bytes));
}

Uint8List _open(({Uint8List blob, String key, String sha256}) input) {
  if (b64u(hash.sha256.convert(input.blob).bytes) != input.sha256) throw const BlobUnreadable();
  return openBlob(unb64u(input.key), input.blob);
}

// Background work goes through top-level functions so the isolate closure captures only its bytes
// (a closure made inside a method would try to copy the whole object graph it can see).
Future<Sealed> _sealInBackground(Uint8List plaintext) => Isolate.run(() => _seal(plaintext));
Future<Uint8List> _openInBackground(Uint8List blob, String key, String sha256) => Isolate.run(() => _open((blob: blob, key: key, sha256: sha256)));
Future<ImageFacts> imageFactsInBackground(Uint8List bytes) => Isolate.run(() => imageFacts(bytes));
Future<String?> thumbInBackground(Uint8List bytes) => Isolate.run(() => thumbFromBytes(bytes));

/// Width, height and a ≤ 4 KB blurry JPEG placeholder for an image, or nulls when it can't be decoded here.
typedef ImageFacts = ({int? width, int? height, String? thumb});

ImageFacts imageFacts(Uint8List bytes) {
  try {
    final decoded = img.decodeImage(bytes);
    if (decoded == null) return (width: null, height: null, thumb: null);
    final upright = img.bakeOrientation(decoded);
    return (width: upright.width, height: upright.height, thumb: thumbFor(upright));
  } catch (_) {
    return (width: null, height: null, thumb: null);
  }
}

/// A tiny JPEG data URL, shrinking until it fits the protocol's 4 KB.
String? thumbFor(img.Image image) {
  for (final (side, quality) in const [(32, 60), (24, 50), (16, 40), (12, 30)]) {
    final scaled = image.width >= image.height
        ? img.copyResize(image, width: math.min(side, image.width), interpolation: img.Interpolation.average)
        : img.copyResize(image, height: math.min(side, image.height), interpolation: img.Interpolation.average);
    final url = 'data:image/jpeg;base64,${base64.encode(img.encodeJpg(scaled, quality: quality))}';
    if (url.length <= maxThumbChars) return url;
  }
  return null;
}

/// A thumb from arbitrary image bytes (the link preview image), or null.
String? thumbFromBytes(Uint8List bytes) {
  try {
    final decoded = img.decodeImage(bytes);
    return decoded == null ? null : thumbFor(img.bakeOrientation(decoded));
  } catch (_) {
    return null;
  }
}

const _mimes = {
  'jpg': 'image/jpeg',
  'jpeg': 'image/jpeg',
  'png': 'image/png',
  'gif': 'image/gif',
  'webp': 'image/webp',
  'heic': 'image/heic',
  'mp4': 'video/mp4',
  'mov': 'video/quicktime',
  'm4v': 'video/x-m4v',
  'webm': 'video/webm',
  'm4a': 'audio/mp4',
  'aac': 'audio/aac',
  'mp3': 'audio/mpeg',
  'wav': 'audio/wav',
  'ogg': 'audio/ogg',
  'opus': 'audio/ogg',
  'pdf': 'application/pdf',
  'txt': 'text/plain',
  'csv': 'text/csv',
  'zip': 'application/zip',
  'json': 'application/json',
};

String mimeFor(String name) => _mimes[p.extension(name).replaceFirst('.', '').toLowerCase()] ?? 'application/octet-stream';

/// Images every client can draw become `image`; other pictures go as files.
String kindFor(String mime) => switch (mime) {
  'image/jpeg' || 'image/png' || 'image/gif' || 'image/webp' => 'image',
  'video/mp4' || 'video/quicktime' || 'video/x-m4v' || 'video/webm' => 'video',
  _ when mime.startsWith('audio/') => 'audio',
  _ => 'file',
};

/// A file name safe to show and to write: no path, no control characters, at most 120 characters.
/// Bidi controls, format characters and zero-width characters: they can disguise an extension
/// ("invoice\u202Efdp.exe" shows as "invoiceexe.pdf") and are never needed in a file name.
final _invisible = RegExp('[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]');

String cleanName(String name) {
  final base = p.basename(name.replaceAll(_invisible, '')).replaceAll(RegExp(r'[\x00-\x1f\x7f/\\:]'), '_').trim();
  final safe = base.isEmpty ? 'file' : base;
  if (safe.length <= 120) return safe;
  final ext = p.extension(safe);
  return ext.length < 20 ? '${safe.substring(0, 120 - ext.length)}$ext' : safe.substring(0, 120);
}

/// Up to 64 values 0–31 from a recording's level samples (dBFS, -160…0).
List<int> waveformFrom(List<double> levels, {int bars = 64}) {
  if (levels.isEmpty) return const [];
  final n = math.min(bars, levels.length);
  return [
    for (var i = 0; i < n; i++)
      (() {
        final from = i * levels.length ~/ n, to = math.max(from + 1, (i + 1) * levels.length ~/ n);
        final loudest = levels.sublist(from, to).reduce(math.max);
        return (((loudest + 50) / 50).clamp(0, 1) * 31).round();
      })(),
  ];
}

/// A picked or recorded file on its way to the server.
class PendingUpload {
  PendingUpload({required this.id, required this.conversationId, required this.name, required this.kind, required this.bytes, this.replyTo});
  final String id, conversationId, name, kind;
  final Uint8List bytes;
  final ReplyTo? replyTo;
  final progress = ValueNotifier<double>(0);
  final error = ValueNotifier<String?>(null);
}

/// Everything the message needs besides the blob: dimensions, thumb, voice waveform and duration.
class FileFacts {
  const FileFacts({this.width, this.height, this.duration, this.waveform, this.thumb});
  final int? width, height;
  final num? duration;
  final List<int>? waveform;
  final String? thumb;
}

class AttachmentService {
  AttachmentService(this.api, {Future<Directory> Function()? cacheDir}) : _cacheDir = cacheDir ?? getTemporaryDirectory;

  final Api api;
  final Future<Directory> Function() _cacheDir;

  /// Uploads in flight or failed, newest last.
  final uploads = ValueNotifier<List<PendingUpload>>(const []);

  static const _memoryBudget = 64 * 1024 * 1024;
  // Every cache is keyed by blob id AND ciphertext hash: a sender can reuse someone else's blob id with
  // another key, and must never be served the plaintext the first message opened.
  static String cacheKey(Attachment a) => '${a.blob}.${a.sha256}';
  final _memory = <String, Uint8List>{}; // Insertion-ordered: least recently used first.
  int _memoryBytes = 0;
  final Map<String, Future<Uint8List>> _inflight = {};
  final Map<String, ValueNotifier<double?>> _progress = {};

  /// SHA-256 of plaintext this session decrypted and verified; a file on disk is used only if it matches.
  final Map<String, String> _verified = {};

  /// Download progress (0–1, null while unknown) for an attachment, for a ring on the bubble.
  ValueListenable<double?> progressOf(Attachment a) => _progress.putIfAbsent(cacheKey(a), () => ValueNotifier(null));

  Uint8List? cached(Attachment a) {
    final key = cacheKey(a);
    final hit = _memory.remove(key);
    if (hit != null) _memory[key] = hit; // Most recently used last.
    return hit;
  }

  void _remember(String key, Uint8List bytes) {
    _verified[key] = hash.sha256.convert(bytes).toString();
    if (bytes.length > _memoryBudget ~/ 4) return;
    _memoryBytes -= _memory.remove(key)?.length ?? 0;
    _memory[key] = bytes;
    _memoryBytes += bytes.length;
    while (_memoryBytes > _memoryBudget && _memory.isNotEmpty) {
      final oldest = _memory.keys.first;
      _memoryBytes -= _memory.remove(oldest)!.length;
    }
  }

  /// Encrypts and uploads [bytes]; returns the attachment for the message. [onProgress] runs 0–1.
  Future<Attachment> upload({
    required Uint8List bytes,
    required String name,
    required String mime,
    required String kind,
    FileFacts facts = const FileFacts(),
    void Function(double)? onProgress,
  }) async {
    if (bytes.length > maxAttachmentBytes) throw const ApiException('That file is too large. Files can be up to 25 MB.', 413);
    final sealed = await _sealInBackground(bytes);
    final blob = await api.uploadBlob(sealed.ciphertext, onProgress: (sent, total) => onProgress?.call(total == 0 ? 1 : sent / total));
    _remember('$blob.${sealed.sha256}', bytes);
    return Attachment(
      kind: kind,
      blob: blob,
      key: sealed.key,
      sha256: sealed.sha256,
      mime: mime,
      name: cleanName(name),
      size: bytes.length,
      width: facts.width,
      height: facts.height,
      duration: facts.duration,
      waveform: facts.waveform,
      thumb: facts.thumb,
    );
  }

  /// Downloads, verifies and decrypts once; concurrent callers share the work.
  Future<Uint8List> open(Attachment a) {
    final hit = cached(a);
    if (hit != null) return Future.value(hit);
    final key = cacheKey(a);
    // A block body: returning the removed future from whenComplete would make it wait on itself.
    return _inflight[key] ??= _fetch(a).whenComplete(() {
      _inflight.remove(key);
    });
  }

  Future<Uint8List> _fetch(Attachment a) async {
    final key = cacheKey(a);
    final progress = _progress.putIfAbsent(key, () => ValueNotifier(null));
    progress.value = 0;
    final blob = await api.downloadBlob(
      a.blob,
      maxBytes: maxAttachmentBytes + _nonceBytes + 16,
      onProgress: (received, total) => progress.value = total == null || total == 0 ? null : received / total,
    );
    final plaintext = await _openInBackground(blob, a.key, a.sha256);
    progress.value = 1;
    _remember(key, plaintext);
    return plaintext;
  }

  /// The decrypted file on this device (for players), one per blob id and hash. A file already on disk is
  /// used only when its size and SHA-256 match plaintext this session decrypted and verified; anything else
  /// is rewritten from a verified decryption.
  Future<File> file(Attachment a) async {
    final dir = Directory(p.join((await _cacheDir()).path, 'attachments'));
    await dir.create(recursive: true);
    final key = cacheKey(a);
    final ext = p.extension(cleanName(a.name)).replaceAll(RegExp(r'[^A-Za-z0-9.]'), '');
    final file = File(p.join(dir.path, '${a.blob}-${a.sha256}${ext.length <= 8 ? ext : ''}'));
    final known = _verified[key];
    if (known != null && await file.exists() && await file.length() == a.size) {
      if (hash.sha256.convert(await file.readAsBytes()).toString() == known) return file;
    }
    final plaintext = await open(a);
    await file.writeAsBytes(plaintext, flush: true);
    return file;
  }

  /// Saves the decrypted file under its own name in [directory], never overwriting another file.
  Future<File> saveTo(Attachment a, Directory directory) async {
    final name = cleanName(a.name);
    var target = File(p.join(directory.path, name));
    for (var i = 1; await target.exists(); i++) {
      target = File(p.join(directory.path, '${p.basenameWithoutExtension(name)} ($i)${p.extension(name)}'));
    }
    return target.writeAsBytes(await open(a), flush: true);
  }

  void addPending(PendingUpload upload) => uploads.value = [...uploads.value, upload];
  void removePending(String id) => uploads.value = [
    for (final u in uploads.value)
      if (u.id != id) u,
  ];

  /// Removes decrypted files left from earlier sessions (sign-out).
  Future<void> clearDisk() async {
    _memory.clear();
    _memoryBytes = 0;
    _verified.clear();
    try {
      final dir = Directory(p.join((await _cacheDir()).path, 'attachments'));
      if (await dir.exists()) await dir.delete(recursive: true);
    } catch (_) {}
  }
}

/// Decides eager vs lazy download (§3): images and voice under 2 MiB load at once.
bool loadsEagerly(Attachment a) => (a.kind == 'image' || a.kind == 'voice') && a.size < 2 * 1024 * 1024;

/// The real extension of a received name, upper case without the dot ("PDF"), or null.
String? extensionLabel(String name) {
  final ext = p.extension(cleanName(name));
  return ext.length < 2 || ext.length > 11 ? null : ext.substring(1).toUpperCase();
}

/// "1.2 MB", "820 KB", "12 bytes".
String fileSize(int bytes) {
  if (bytes < 1024) return '$bytes bytes';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).round()} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB';
}

/// "0:07", "12:30".
String duration(num seconds) {
  final s = seconds.round();
  return '${s ~/ 60}:${(s % 60).toString().padLeft(2, '0')}';
}
