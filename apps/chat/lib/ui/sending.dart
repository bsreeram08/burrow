import 'dart:async';
import 'dart:io' show File;

import 'package:cross_file/cross_file.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:uuid/uuid.dart';
import 'package:video_player/video_player.dart';

import '../app/app_controller.dart';
import '../app/chat_settings.dart';
import '../messaging/attachments.dart';
import '../store/message.dart';
import 'widgets/common.dart';
import 'widgets/voice_recorder.dart';

/// Sends a message that carries an uploaded attachment (1:1 or group).
typedef SendAttachment = Future<void> Function(Attachment attachment, {ReplyTo? replyTo, Duration? disappearAfter});

/// What both conversation screens do the same way: encrypt and upload files and voice notes with progress
/// and retry, and build the sender-side link preview (docs/phase1-protocol.md §3–§4).
mixin AttachmentSending<T extends ConsumerStatefulWidget> on ConsumerState<T> {
  String get conversationId;
  SendAttachment get sendAttachment;

  late final AttachmentService attachmentService = ref.read(attachmentsProvider);
  final Map<String, Future<void> Function()> uploadRetries = {};

  Future<List<XFile>> pickFiles({required bool media}) async {
    final files = await FilePicker.pickFiles(type: media ? FileType.media : FileType.any);
    return [for (final f in files) f.xFile];
  }

  Future<FileFacts> _facts(XFile file, Uint8List bytes, String kind) async {
    if (kind == 'image') {
      final facts = await imageFactsInBackground(bytes);
      return FileFacts(width: facts.width, height: facts.height, thumb: facts.thumb);
    }
    if (kind == 'video' && file.path.isNotEmpty) {
      // Best effort: the platform player reads the size and length; no poster frame is made here.
      final player = VideoPlayerController.file(File(file.path));
      try {
        await player.initialize().timeout(const Duration(seconds: 5));
        final size = player.value.size;
        return FileFacts(
          width: size.width >= 1 ? size.width.round() : null,
          height: size.height >= 1 ? size.height.round() : null,
          duration: player.value.duration.inMilliseconds / 1000,
        );
      } catch (_) {
        return const FileFacts();
      } finally {
        unawaited(player.dispose());
      }
    }
    return const FileFacts();
  }

  Future<void> attachFiles(List<XFile> files, {ReplyTo? replyTo, Duration? disappearAfter}) async {
    for (final file in files) {
      if (await file.length() > maxAttachmentBytes) {
        if (mounted) showSnack(context, '${file.name} is larger than 25 MB, so it can\'t be sent.');
        continue;
      }
      final bytes = await file.readAsBytes();
      final mime = file.mimeType ?? mimeFor(file.name);
      final kind = kindFor(mime);
      final upload = PendingUpload(id: const Uuid().v4(), conversationId: conversationId, name: cleanName(file.name), kind: kind, bytes: bytes, replyTo: replyTo);
      attachmentService.addPending(upload);
      Future<void> run() async {
        upload.error.value = null;
        upload.progress.value = 0;
        try {
          final facts = await _facts(file, bytes, kind);
          final attachment = await attachmentService.upload(bytes: bytes, name: file.name, mime: mime, kind: kind, facts: facts, onProgress: (v) => upload.progress.value = v);
          await sendAttachment(attachment, replyTo: upload.replyTo, disappearAfter: disappearAfter);
          attachmentService.removePending(upload.id);
          uploadRetries.remove(upload.id);
        } catch (e) {
          upload.error.value = e.toString();
        }
      }

      uploadRetries[upload.id] = run;
      replyTo = null; // Only the first file of a batch carries the reply.
      unawaited(run());
    }
  }

  Future<void> sendVoiceNote(VoiceNote note, {ReplyTo? replyTo, Duration? disappearAfter}) async {
    final upload = PendingUpload(id: const Uuid().v4(), conversationId: conversationId, name: 'Voice message', kind: 'voice', bytes: note.bytes, replyTo: replyTo);
    attachmentService.addPending(upload);
    Future<void> run() async {
      upload.error.value = null;
      try {
        final attachment = await attachmentService.upload(
          bytes: note.bytes,
          name: 'voice.m4a',
          mime: 'audio/mp4',
          kind: 'voice',
          facts: FileFacts(duration: (note.seconds * 10).round() / 10, waveform: note.waveform),
          onProgress: (v) => upload.progress.value = v,
        );
        await sendAttachment(attachment, replyTo: replyTo, disappearAfter: disappearAfter);
        attachmentService.removePending(upload.id);
        uploadRetries.remove(upload.id);
      } catch (e) {
        upload.error.value = e.toString();
      }
    }

    uploadRetries[upload.id] = run;
    unawaited(run());
  }

  /// The sender-side preview (§4): the server fetches the page, this device makes the thumb.
  Future<LinkPreview?> unfurlLink(String url) async {
    if (!ref.read(chatSettingsProvider).linkPreviews) return null;
    try {
      final api = ref.read(apiProvider);
      final data = await api.unfurl(url);
      String? clip(Object? v, int max) {
        if (v is! String) return null;
        final s = v.replaceAll(RegExp(r'\s+'), ' ').trim();
        if (s.isEmpty) return null;
        return s.length <= max ? s : '${s.substring(0, max - 1)}…';
      }

      final title = clip(data['title'], 200), description = clip(data['description'], 300), site = clip(data['site'], 60);
      if (title == null && description == null) return null;
      String? thumb;
      final image = data['image'];
      if (image is String && LinkPreview.isHttpsUrl(image)) {
        try {
          final bytes = await api.unfurlImage(image);
          thumb = await thumbInBackground(bytes);
        } catch (_) {}
      }
      return LinkPreview(url: url, title: title, description: description, site: site, thumb: thumb);
    } catch (_) {
      return null;
    }
  }

  void retryUpload(PendingUpload upload) => unawaited(uploadRetries[upload.id]?.call());
  void removeUpload(PendingUpload upload) {
    uploadRetries.remove(upload.id);
    attachmentService.removePending(upload.id);
  }
}
