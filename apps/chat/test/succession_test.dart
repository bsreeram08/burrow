import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// docs/m5-linking.md §5.3: a contact's new account key reached by a signed chain from our pin moves the pin
/// with verification kept; anything else is a security-code change for review.
void main() {
  sqfliteFfiInit();
  const me = User(id: 'me-id', username: 'me');
  const bob = Contact(id: 'bob-id', username: 'bob', state: ContactState.mutual);
  const old = Identity(dh: 'old-dh', sign: 'old-sign'), fresh = Identity(dh: 'new-dh', sign: 'new-sign');

  Future<(Messenger, FakeChatCrypto, List<String>)> setUpMessenger() async {
    final crypto = FakeChatCrypto();
    await crypto.notePeer(bob.id!, old);
    await crypto.setVerified(bob.id!, true);
    final store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    final messenger = Messenger(
      api: Api(baseUrl: 'https://calls.example', client: MockClient((_) async => http.Response('{}', 200)), clientName: 'ios'),
      crypto: crypto,
      store: store,
      me: me,
      contactById: (_) => bob,
      mutualContacts: () => [bob],
      ack: (_) {},
    );
    final notices = <String>[];
    messenger.notices.listen(notices.add);
    return (messenger, crypto, notices);
  }

  test('a valid chain from the pin moves it and keeps verification, with a soft notice', () async {
    final (messenger, crypto, notices) = await setUpMessenger();
    final chain = [{'v': 1, 'userId': 'bob-id', 'oldSign': 'old-sign', 'newSign': 'new-sign', 'newDh': 'new-dh', 'at': 1, 'signature': 's'}];
    expect(await messenger.followIdentity(bob, fresh, chain), isTrue);
    final pin = (await crypto.peer('bob-id'))!;
    expect((pin.identity, pin.verified, pin.blocked), (fresh, true, false));
    await Future<void>.delayed(Duration.zero);
    expect(notices.single, 'bob updated their security key. Verification kept.');
  });

  test('a move the group pins saw first is told once: the 1:1 refresh after it adds nothing', () async {
    final (messenger, crypto, notices) = await setUpMessenger();
    final chain = [{'v': 1, 'userId': 'bob-id', 'oldSign': 'old-sign', 'newSign': 'new-sign', 'newDh': 'new-dh', 'at': 1, 'signature': 's'}];
    // What the group pins do (GroupMessenger.onKeyMoved, wired to keyMoved for contacts).
    await crypto.acceptSuccession('bob-id', chain);
    messenger.keyMoved(bob, fresh);
    messenger.keyMoved(bob, fresh);
    expect(await messenger.followIdentity(bob, fresh, chain), isFalse);
    expect((await crypto.peer('bob-id'))!.blocked, isFalse);
    await Future<void>.delayed(Duration.zero);
    expect(notices, ['bob updated their security key. Verification kept.']);
  });

  test('no chain, or one that does not start at our pin, is a security-code change to review', () async {
    final (messenger, crypto, _) = await setUpMessenger();
    final elsewhere = [{'v': 1, 'userId': 'bob-id', 'oldSign': 'other', 'newSign': 'new-sign', 'newDh': 'new-dh', 'at': 1, 'signature': 's'}];
    expect(await messenger.followIdentity(bob, fresh, elsewhere), isFalse);
    expect((await crypto.peer('bob-id'))!.blocked, isTrue);
    final (m2, c2, _) = await setUpMessenger();
    expect(await m2.followIdentity(bob, fresh, null), isFalse);
    expect((await c2.peer('bob-id'))!.blocked, isTrue);
  });

  test('a pin waiting for review never starts a succession: a chain from the unaccepted key goes to review', () async {
    final (messenger, crypto, notices) = await setUpMessenger();
    const planted = Identity(dh: 'srv-dh', sign: 'srv-sign');
    await crypto.notePeer(bob.id!, planted); // The server served another key: changed, blocked, not accepted.
    final chain = [{'v': 1, 'userId': 'bob-id', 'oldSign': 'srv-sign', 'newSign': 'new-sign', 'newDh': 'new-dh', 'at': 1, 'signature': 's'}];
    expect(await messenger.followIdentity(bob, fresh, chain), isFalse);
    final pin = (await crypto.peer('bob-id'))!;
    expect((pin.blocked, pin.verified), (true, false));
    await Future<void>.delayed(Duration.zero);
    expect(notices, isEmpty);
  });

  test('identity checks for one contact run one at a time: a second refresh sees the moved pin', () async {
    final (messenger, crypto, notices) = await setUpMessenger();
    final chain = [{'v': 1, 'userId': 'bob-id', 'oldSign': 'old-sign', 'newSign': 'new-sign', 'newDh': 'new-dh', 'at': 1, 'signature': 's'}];
    final both = await Future.wait([messenger.followIdentity(bob, fresh, chain), messenger.followIdentity(bob, fresh, chain)]);
    expect(both, [true, false], reason: 'the second ran after the first moved the pin');
    final pin = (await crypto.peer('bob-id'))!;
    expect((pin.identity, pin.verified, pin.blocked), (fresh, true, false));
    await Future<void>.delayed(Duration.zero);
    expect(notices, hasLength(1));
  });
}
