import 'dart:convert';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/devices.dart';
import 'package:private_chat/crypto/account_crypto.dart';
import 'package:private_chat/crypto/chat_crypto.dart';

/// The server side of the account backup (docs/m6-account-key.md §3.5), in memory: one record, epochs that go up by
/// one, and the proof checked against the stored hashes on every change after the first.
class FakeBackupServer {
  Map<String, Object?>? record;
  final List<Map<String, Object?>> puts = [];
  int reads = 0;

  /// One proof-free re-seal is allowed right after a succession the server accepted (§3.5); tests set it there.
  bool resealAllowed = false;


  Api api() => Api(baseUrl: 'https://calls.example', clientName: 'ios', client: MockClient(handle))..token = 't';

  Future<http.Response> handle(http.Request request) async {
    if (request.url.path != '/api/backup') return http.Response('{"error":"nope"}', 404);
    switch (request.method) {
      case 'GET':
        reads++;
        final r = record;
        return r == null ? http.Response('{"error":"No backup."}', 404) : http.Response(jsonEncode(r), 200);
      case 'PUT':
        final body = (jsonDecode(request.body) as Map).cast<String, Object?>();
        puts.add(body);
        final current = record;
        if ((body['epoch'] as int) != ((current?['epoch'] as int?) ?? 0) + 1) return http.Response('{"error":"Wrong epoch."}', 400);
        final reseal = resealAllowed && body['passProofHash'] == current?['passProofHash'] && body['recoveryProofHash'] == current?['recoveryProofHash'];
        if (current != null && reseal) resealAllowed = false;
        if (current != null && !reseal) {
          final proof = body['proof'] as String?;
          if (proof == null || (proofHash(proof) != current['passProofHash'] && proofHash(proof) != current['recoveryProofHash'])) return http.Response('{"error":"Wrong passphrase."}', 403);
        }
        record = {for (final e in body.entries) if (!['proof', 'passProof', 'recoveryProof'].contains(e.key)) e.key: e.value};
        return http.Response('{"updatedAt":1}', 200);
      case 'DELETE':
        final proof = (jsonDecode(request.body) as Map)['proof'] as String?;
        final current = record;
        if (current == null) return http.Response('', 404);
        if (proof == null || (proofHash(proof) != current['passProofHash'] && proofHash(proof) != current['recoveryProofHash'])) return http.Response('{"error":"Wrong passphrase."}', 403);
        record = null;
        return http.Response('', 204);
    }
    return http.Response('', 405);
  }
}

/// A full device's account key with a real Ed25519 signer, so served records verify like the real ones.
({Identity identity, FakeAccountCrypto crypto}) signingAccount() {
  final key = ed.generateKey();
  final identity = Identity(dh: b64(List.filled(32, 4)), sign: b64(key.publicKey.bytes));
  final crypto = FakeAccountCrypto(held: identity)..sign = (record) => b64(ed.sign(key.privateKey, backupKeysBytes(record)));
  return (identity: identity, crypto: crypto);
}

