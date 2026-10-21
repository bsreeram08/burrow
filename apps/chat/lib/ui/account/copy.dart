/// The account key and backup screens' words (docs/m6-account-key.md §3.4, §4, §6.2), the same as the web client's
/// (packages/signaling/public/index.html and link.js) so both read alike.
library;

const walletWarning = 'This is not a wallet seed; don’t enter it anywhere else.';

const turnOnTitle = 'Turn on account backup';
const changePassphraseTitle = 'Change your passphrase';
const newRecoveryTitle = 'New recovery key';
const turnOffTitle = 'Turn off account backup';

const backupIntro = 'Your backup is encrypted with a passphrase only you know. With it, you can use your account on a new device without your other devices.';
const yourPassphrase = 'Your passphrase:';
const useOwnPassphrase = 'Use my own passphrase';
const useGeneratedPassphrase = 'Use a generated passphrase';
const passphraseLabel = 'Passphrase (at least 14 characters)';
const typeItAgain = 'Type it again';
const currentSecretLabel = 'Current passphrase or recovery key';

const wordsIntro = 'Your recovery key. It opens your backup if you forget the passphrase. Store it offline, for example on paper.';
const checkIntro = 'Type these words from your recovery key to check you have it.';
String wordLabel(int n) => 'Word $n';
String wordMismatch(int n) => 'Word $n doesn’t match. Check your copy of the words.';

const securing = 'Securing your backup… this takes a few seconds.';
const copied = 'Copied. The clipboard is cleared in 60 seconds.';

const tooShort = 'Use at least 14 characters, or the generated passphrase.';
const noMatch = 'The two passphrases don’t match.';
const tooCommon = 'That passphrase is too common. Choose another.';
const enterCurrent = 'Enter your current passphrase or recovery key.';
const notCurrent = 'That isn’t your current passphrase or recovery key.';

const restorePassphraseTitle = 'Enter your passphrase';
const restoreWordsTitle = 'Use your recovery key';
const restorePassphraseLabel = 'Passphrase';
const restoreWordsLabel = 'Your 24 recovery words';
const unlocking = 'Unlocking… this takes a few seconds.';
const passphraseDoesntOpen = 'That passphrase doesn’t open your backup.';
const wordsDontOpen = 'Those words don’t open your backup.';
const checkTheWords = 'Check the words: one isn’t a recovery word, or one is missing.';
const restoredTitle = 'This device can now use your account.';
const noReverify = 'Your contacts don’t need to re-verify you. To check this device, compare a contact’s safety number with them, or with your other device.';

String backupOn(String date) => 'On. Last changed $date.';
const backupOff = 'Off. Turn on account backup so a lost device can’t lock you out.';

const removeText =
    'The device is signed out and can’t read new messages. Because it could unlock your account, your account gets a new key; your other devices pick it up by themselves and your contacts keep their verification.';
const removeAndChange = 'Remove and change key';
const notYourSecret = 'That isn’t your passphrase or recovery key.';

String _day(int ms) => DateTime.fromMillisecondsSinceEpoch(ms).toLocal().toString().substring(0, 10);

/// The delayed reset of the account key (§6.5): the asking device waits, every listed device may cancel.
const resetWaiting = 'Your account key will be reset in 7 days unless one of your devices cancels it';
String resetGoesAhead(int executeAfter) => 'It goes ahead after ${_day(executeAfter)}. Keep this app signed in.';
String resetBanner(String platform, int at) => 'Someone asked to reset your account key from $platform on ${_day(at)}. If this wasn’t you, cancel it.';
