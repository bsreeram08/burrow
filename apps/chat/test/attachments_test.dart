import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:image/image.dart' as img;
import 'package:private_chat/core/api.dart';
import 'package:private_chat/messaging/attachments.dart';
import 'package:private_chat/store/message.dart';

Uint8List hex(String s) => Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);
String toHex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('blob encryption (nonce || AES-256-GCM ciphertext || tag, no AAD)', () {
    test('matches the AES-256-GCM reference vector (same bytes WebCrypto produces)', () {
      // NIST GCM test case 14: 256-bit zero key, 96-bit zero IV, one zero block.
      final sealed = sealBlob(Uint8List(32), Uint8List(16), nonce: Uint8List(12));
      expect(toHex(sealed.sublist(0, 12)), '0' * 24);
      expect(toHex(sealed.sublist(12, 28)), 'cea7403d4d606b6e074ec5d3baf39d18');
      expect(toHex(sealed.sublist(28)), 'd0d1c8a799996bf0265b98b5d48ab919');
      expect(openBlob(Uint8List(32), sealed), Uint8List(16));
    });

    test('a random nonce per file, and any changed byte fails to open', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final plain = Uint8List.fromList(utf8.encode('hello file'));
      final a = sealBlob(key, plain), b = sealBlob(key, plain);
      expect(a.sublist(0, 12), isNot(b.sublist(0, 12)));
      final tampered = Uint8List.fromList(a)..[20] ^= 1;
      expect(() => openBlob(key, tampered), throwsA(isA<BlobUnreadable>()));
      expect(() => openBlob(Uint8List(32), a), throwsA(isA<BlobUnreadable>()));
    });
  });

  group('service', () {
    late Map<String, Uint8List> server;
    late AttachmentService service;
    late Directory cache;
    setUp(() async {
      server = {};
      cache = await Directory.systemTemp.createTemp('attachments');
      final client = MockClient((request) async {
        expect(request.headers['authorization'], 'Bearer t0ken');
        if (request.method == 'POST' && request.url.path == '/api/blobs') {
          expect(request.headers['content-type'], 'application/octet-stream');
          final id = 'b' * 21 + server.length.toString();
          server[id] = request.bodyBytes;
          return http.Response(jsonEncode({'id': id}), 201);
        }
        final match = RegExp(r'^/api/blobs/(.+)$').firstMatch(request.url.path);
        if (match != null) {
          final bytes = server[match.group(1)];
          return bytes == null ? http.Response('{"error":"gone"}', 404) : http.Response.bytes(bytes, 200);
        }
        return http.Response('{}', 404);
      });
      service = AttachmentService(Api(baseUrl: 'https://calls.example', client: client)..token = 't0ken', cacheDir: () async => cache);
    });
    tearDown(() => cache.delete(recursive: true));

    test('upload sends only ciphertext; a fresh device downloads, verifies and decrypts it', () async {
      final plain = Uint8List.fromList(List.generate(200000, (i) => i % 251));
      final progress = <double>[];
      final a = await service.upload(bytes: plain, name: '../../etc/report.pdf', mime: 'application/pdf', kind: 'file', onProgress: progress.add);
      expect(a.name, 'report.pdf', reason: 'no path survives');
      expect(a.size, plain.length);
      expect(progress.last, 1);
      final stored = server[a.blob]!;
      expect(stored.length, plain.length + 28);
      expect(b64u(hash.sha256.convert(stored).bytes), a.sha256);
      expect(Attachment.fromJson(a.toJson()), a, reason: 'what the message carries passes the store rules');

      final other = AttachmentService(service.api, cacheDir: () async => cache);
      expect(await other.open(a), plain);
      final file = await other.file(a);
      expect(await file.readAsBytes(), plain);
    });

    test('caches are keyed by blob id and hash: a reused blob id with another key never gets the first plaintext', () async {
      final first = await service.upload(bytes: Uint8List.fromList(utf8.encode('the real file')), name: 'a.txt', mime: 'text/plain', kind: 'file');
      expect(await service.open(first), utf8.encode('the real file'));
      // Someone else's message points at the same blob with their own key and hash.
      final forged = Attachment.fromJson({...first.toJson(), 'key': b64u(List.filled(32, 9)), 'sha256': b64u(List.filled(32, 7))});
      expect(service.cached(forged), isNull);
      await expectLater(service.open(forged), throwsA(isA<BlobUnreadable>()));
      await expectLater(service.file(forged), throwsA(isA<BlobUnreadable>()));
    });

    test('a decrypted file on disk is reused only when it still matches what was verified', () async {
      final plain = Uint8List.fromList(List.generate(4000, (i) => i % 200));
      final a = await service.upload(bytes: plain, name: 'clip.bin', mime: 'application/octet-stream', kind: 'file');
      final file = await service.file(a);
      expect(await file.readAsBytes(), plain);
      // Same length, different bytes: rewritten from a verified decryption, never served.
      await file.writeAsBytes(Uint8List(4000)..[0] = 1);
      expect(await (await service.file(a)).readAsBytes(), plain);
      // A new session has verified nothing yet: the file is rebuilt from the server, not trusted.
      await file.writeAsBytes(Uint8List(4000));
      final fresh = AttachmentService(service.api, cacheDir: () async => cache);
      expect(await (await fresh.file(a)).readAsBytes(), plain);
    });

    test('a hash mismatch is unreadable and never decrypted; a missing blob is an error', () async {
      final a = await service.upload(bytes: Uint8List.fromList([1, 2, 3]), name: 'x.bin', mime: 'application/octet-stream', kind: 'file');
      server[a.blob]![14] ^= 1;
      final fresh = AttachmentService(service.api, cacheDir: () async => cache);
      await expectLater(fresh.open(a), throwsA(isA<BlobUnreadable>()));
      server.clear();
      await expectLater(fresh.open(a), throwsA(isA<ApiException>().having((e) => e.status, 'status', 404)));
    });
  });

  test('image facts: dimensions and a JPEG thumb within 4 KB', () {
    final image = img.Image(width: 1200, height: 800);
    for (final p in image) {
      p.setRgb(p.x % 256, p.y % 256, 128);
    }
    final facts = imageFacts(img.encodePng(image));
    expect((facts.width, facts.height), (1200, 800));
    expect(facts.thumb, startsWith('data:image/jpeg;base64,'));
    expect(facts.thumb!.length, lessThanOrEqualTo(4096));
    expect(imageFacts(Uint8List.fromList([1, 2, 3])).thumb, isNull);
  });

  test('waveform, names, kinds and sizes', () {
    expect(waveformFrom([-160, -50, -25, 0]), [0, 0, 16, 31]);
    expect(waveformFrom(List.filled(500, -10.0)), hasLength(64));
    expect(cleanName('a\u0000b/c:d.txt'), 'c_d.txt');
    expect(cleanName('invoice\u202Efdp.exe'), 'invoicefdp.exe', reason: 'right-to-left override would show it as invoiceexe.pdf');
    expect(cleanName('re\u200Bport\u2066.pdf\u2069\u200E\u061C\uFEFF'), 'report.pdf');
    expect(extensionLabel('invoice\u202Efdp.exe'), 'EXE');
    expect(extensionLabel('README'), isNull);
    expect(cleanName('${'x' * 200}.jpeg').length, 120);
    expect(kindFor(mimeFor('IMG.JPG')), 'image');
    expect(kindFor(mimeFor('photo.heic')), 'file', reason: 'not every client can draw HEIC');
    expect(kindFor(mimeFor('clip.mov')), 'video');
    expect(fileSize(1536), '2 KB');
    expect(duration(65.4), '1:05');
    expect(loadsEagerly(Attachment.fromJson({'kind': 'image', 'blob': 'b' * 22, 'key': 'k' * 43, 'sha256': 's' * 43, 'mime': 'image/png', 'name': 'a.png', 'size': 1000})), isTrue);
  });
}
