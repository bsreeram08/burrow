import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/devices.dart';

/// docs/m5-linking.md §1.3 and §5.1 byte layouts (SHA-256 of fixed inputs, computed independently from the
/// contract's TLS-style encoding).
void main() {
  test('link start, link claim and succession bytes', () {
    final key1 = b64(List.filled(32, 1)), key2 = b64(List.filled(32, 2));
    expect(sha256.convert(linkStartBytes('a' * 22, 'ios', key1)).toString(), '1f9848b5414f7d90cbf8277e3d4730267f72ee8d028ad67fd58a69c33c5d05f7');
    expect(sha256.convert(linkClaimBytes('L' * 22, 'a' * 22, key2)).toString(), '273bab88d9d3840481bfd63b210753922a6c999c2b58fd5c76c54c2d12b57116');
    expect(
      sha256.convert(successionBytes('user_1', b64(List.filled(32, 3)), b64(List.filled(32, 4)), b64(List.filled(32, 5)), 1700000000000)).toString(),
      'ba9d21a694b578849a380ef5cc9db652bec880543922e660c8f2fb2777758b54',
    );
    expect(() => linkStartBytes('a' * 22, 'toaster', key1), throwsA(anything));
    expect(() => linkClaimBytes('short', 'a' * 22, key2), throwsA(anything));
  });

  test('a succession chain verifies from the pinned key to the served one, and nothing else', () {
    final k0 = ed.generateKey(), k1 = ed.generateKey(), k2 = ed.generateKey();
    String pub(ed.KeyPair k) => b64(k.publicKey.bytes);
    Map<String, dynamic> record(ed.KeyPair from, ed.KeyPair to, int at) {
      final bytes = successionBytes('user_1', pub(from), pub(to), b64(List.filled(32, 9)), at);
      return {'v': 1, 'userId': 'user_1', 'oldSign': pub(from), 'newSign': pub(to), 'newDh': b64(List.filled(32, 9)), 'at': at, 'signature': b64(ed.sign(from.privateKey, bytes))};
    }

    final chain = [record(k0, k1, 1), record(k1, k2, 2)];
    expect(verifySuccessionChain('user_1', pub(k0), pub(k2), chain), isTrue);
    expect(verifySuccessionChain('user_1', pub(k1), pub(k2), chain), isFalse, reason: 'must start at the pinned key');
    expect(verifySuccessionChain('user_1', pub(k0), pub(k1), chain), isFalse, reason: 'must end at the served key');
    expect(verifySuccessionChain('user_2', pub(k0), pub(k2), chain), isFalse);
    final forged = [record(k0, k1, 1), {...record(k1, k2, 2), 'at': 3}];
    expect(verifySuccessionChain('user_1', pub(k0), pub(k2), forged), isFalse);
  });
}
