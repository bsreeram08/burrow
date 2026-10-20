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
    expect(notices.single, 'bob moved to a new device. Verification kept.');
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
}
