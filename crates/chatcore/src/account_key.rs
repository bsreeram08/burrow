//! The account key on every device and its encrypted backup (docs/m6-account-key.md §1, §3): the AccountKey bytes,
//! the passphrase and recovery-key unlock keys (Argon2id, BIP-39) with their proofs, the box a backup is sealed in
//! and the record. Pure functions; `core::account` wires them to a core's stores.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};
use crate::primitives::{b64, hkdf, random_bytes, unb64};

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", what) }

pub const ACCOUNT_KEY_LABEL: &str = "webrtc-bun-account-key-v1";
pub const BACKUP_LABEL: &str = "webrtc-bun-backup-v1";
pub const KEYS_LABEL: &str = "webrtc-bun-backup-keys-v2";
pub const REKEY_LABEL: &str = "webrtc-bun-rekey-v1";
pub const BACKUP_BOX_INFO: &str = "webrtc-bun-backup-box-v1";
pub const REKEY_BOX_INFO: &str = "webrtc-bun-rekey-box-v1";
const PASS_INFO: &str = "webrtc-bun-backup-pass-v1";
const PASS_PROOF_INFO: &str = "webrtc-bun-backup-pass-proof-v1";
const RECOVERY_INFO: &str = "webrtc-bun-backup-recovery-v1";
const RECOVERY_PROOF_INFO: &str = "webrtc-bun-backup-recovery-proof-v1";

/// The Argon2id cost a new backup uses, and the range a record may name (so the cost can be raised later; a server
/// cannot make a client derive at a cost outside it).
pub const KDF_M: u32 = 65536;
pub const KDF_T: u32 = 3;
pub const KDF_P: u32 = 1;
pub const KDF_M_RANGE: std::ops::RangeInclusive<u32> = 65536..=1_048_576;
pub const KDF_T_RANGE: std::ops::RangeInclusive<u32> = 3..=10;
pub const KDF_P_RANGE: std::ops::RangeInclusive<u32> = 1..=4;
/// A custom passphrase, after NFKC (a generated one is six words and always longer).
pub const MIN_PASSPHRASE_CHARS: usize = 14;

// ---------- Canonical bytes ----------

/// `text16`, `bytes8`, `u32` as in docs/m5-linking.md §1.3.
#[derive(Default)]
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self { Self::default() }
    pub fn text16(mut self, text: &str) -> Self { self.0.extend_from_slice(&(text.len() as u16).to_be_bytes()); self.0.extend_from_slice(text.as_bytes()); self }
    pub fn bytes8(mut self, bytes: &[u8]) -> Self { self.0.push(bytes.len() as u8); self.0.extend_from_slice(bytes); self }
    pub fn u32(mut self, value: u32) -> Self { self.0.extend_from_slice(&value.to_be_bytes()); self }
    pub fn raw(mut self, bytes: &[u8]) -> Self { self.0.extend_from_slice(bytes); self }
    pub fn done(self) -> Vec<u8> { self.0 }
}

fn key(text: &str) -> Result<[u8; 32]> { unb64(text, Some(32)).map_err(|_| invalid("malformed key"))?.try_into().map_err(|_| invalid("malformed key")) }

/// `base64url(SHA-256(bytes))`.
pub fn sha256_b64(bytes: &[u8]) -> String { b64(&Sha256::digest(bytes)) }

struct Cursor<'a> { bytes: &'a [u8], at: usize }

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let slice = self.bytes.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(slice)
    }
    fn text16(&mut self) -> Option<String> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize;
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }
    fn key8(&mut self) -> Option<[u8; 32]> {
        if self.take(1)? != [32] { return None; }
        self.take(32)?.try_into().ok()
    }
}

// ---------- AccountKey ----------

/// `text16(label) ‖ text16(userId) ‖ bytes8(signSeed) ‖ bytes8(dhSecret)`.
pub fn account_key_bytes(user_id: &str, sign_seed: &[u8; 32], dh_secret: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Writer::new().text16(ACCOUNT_KEY_LABEL).text16(user_id).bytes8(sign_seed).bytes8(dh_secret).done())
}

type Parsed = (String, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Reads an AccountKey at the start of `bytes`; returns it and how many bytes it took.
fn parse_account_key_prefix(bytes: &[u8]) -> Result<(Parsed, usize)> {
    let bad = || invalid("malformed account key");
    let mut cursor = Cursor { bytes, at: 0 };
    if cursor.text16().ok_or_else(bad)? != ACCOUNT_KEY_LABEL { return Err(bad()); }
    let user_id = cursor.text16().ok_or_else(bad)?;
    let seed = Zeroizing::new(cursor.key8().ok_or_else(bad)?);
    let dh = Zeroizing::new(cursor.key8().ok_or_else(bad)?);
    Ok(((user_id, seed, dh), cursor.at))
}

/// The inverse: strict (exact label, nothing after). Returns `(userId, signSeed, dhSecret)`.
pub fn parse_account_key(bytes: &[u8]) -> Result<Parsed> {
    let (parsed, used) = parse_account_key_prefix(bytes)?;
    if used != bytes.len() { return Err(invalid("malformed account key")); }
    Ok(parsed)
}

pub fn sign_public(seed: &[u8; 32]) -> [u8; 32] { ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes() }
pub fn dh_public(secret: &[u8; 32]) -> [u8; 32] { PublicKey::from(&StaticSecret::from(*secret)).to_bytes() }

// ---------- Unlock keys ----------

/// The passphrase as typed, NFKC-normalized.
pub fn normalize_passphrase(passphrase: &str) -> String { passphrase.nfkc().collect() }

/// `Argon2id(passphrase, salt, m, t, p, 32)`.
pub fn pass_seed(passphrase: &str, salt: &[u8; 16], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m, t, p, Some(32)).map_err(|_| invalid("unsupported key derivation parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalize_passphrase(passphrase).as_bytes(), salt, &mut *out)
        .map_err(|_| invalid("the passphrase could not be processed"))?;
    Ok(out)
}

fn derive(ikm: &[u8; 32], info: &str) -> Zeroizing<[u8; 32]> { Zeroizing::new(hkdf(ikm, &[], info, 32).try_into().expect("32")) }

/// The X25519 secret a passphrase unlocks with (HKDF-SHA-256, no salt) and the proof of knowing it.
pub fn pass_secret(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> { derive(seed, PASS_INFO) }
pub fn pass_proof(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> { derive(seed, PASS_PROOF_INFO) }
/// The same for a recovery key's entropy.
pub fn recovery_secret(entropy: &[u8; 32]) -> Zeroizing<[u8; 32]> { derive(entropy, RECOVERY_INFO) }
pub fn recovery_proof(entropy: &[u8; 32]) -> Zeroizing<[u8; 32]> { derive(entropy, RECOVERY_PROOF_INFO) }

// ---------- BIP-39 ----------

const WORDLIST: &str = include_str!("account/bip39_english.txt");

fn wordlist() -> Vec<&'static str> { WORDLIST.lines().collect() }

/// 32 bytes of entropy as 24 words (standard checksum: the first 8 bits of SHA-256).
pub fn words_from_entropy(entropy: &[u8; 32]) -> Vec<String> {
    let list = wordlist();
    let mut bits = Zeroizing::new(entropy.to_vec());
    bits.push(Sha256::digest(entropy)[0]);
    (0..24).map(|i| {
        let mut index = 0usize;
        for bit in i * 11..(i + 1) * 11 { index = (index << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1) as usize; }
        list[index].to_string()
    }).collect()
}

/// Six random words (66 bits): the passphrase offered by default.
pub fn generate_passphrase() -> String {
    let list = wordlist();
    let random = Zeroizing::new(random_bytes::<12>());
    (0..6).map(|i| {
        let mut index = 0usize;
        for bit in i * 11..(i + 1) * 11 { index = (index << 1) | ((random[bit / 8] >> (7 - bit % 8)) & 1) as usize; }
        list[index]
    }).collect::<Vec<_>>().join(" ")
}

/// Reads typed words: NFKD, case-insensitive, any whitespace, each word in full or by its first four letters. Wrong
/// count, a word (or prefix) that matches none, or a failed checksum is `invalid`.
pub fn entropy_from_words(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let list = wordlist();
    let tokens: Vec<String> = text.split_whitespace().map(|word| word.nfkd().collect::<String>().to_lowercase()).collect();
    if tokens.len() != 24 { return Err(invalid("a recovery key is 24 words")); }
    let mut bits = Zeroizing::new(vec![0u8; 33]);
    for (i, token) in tokens.iter().enumerate() {
        let index = list.iter().position(|word| word == token)
            .or_else(|| if token.chars().count() == 4 { list.iter().position(|word| word.starts_with(token.as_str())) } else { None })
            .ok_or_else(|| invalid("that is not a recovery word"))?;
        for bit in 0..11 {
            if (index >> (10 - bit)) & 1 == 1 { let at = i * 11 + bit; bits[at / 8] |= 1 << (7 - at % 8); }
        }
    }
    let entropy: [u8; 32] = bits[..32].try_into().expect("32");
    if Sha256::digest(entropy)[0] != bits[32] { return Err(invalid("these words do not form a recovery key; check them")); }
    Ok(Zeroizing::new(entropy))
}

// ---------- The box ----------

fn box_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32], info: &str) -> [u8; 32] {
    let mut salt = eph_pub.to_vec();
    salt.extend_from_slice(recipient_pub);
    hkdf(shared, &salt, info, 32).try_into().expect("32")
}

fn shared_secret(secret: &[u8; 32], public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() { return Err(invalid("invalid public key")); }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// Seals `plaintext` to `recipient_pub`; `eph` and `nonce` are fixed by the caller only in tests.
pub fn seal_box_with(recipient_pub: &[u8; 32], plaintext: &[u8], aad: &[u8], info: &str, eph: &[u8; 32], nonce: &[u8; 12]) -> Result<String> {
    let eph_pub = dh_public(eph);
    let shared = shared_secret(eph, recipient_pub)?;
    let key = Zeroizing::new(box_key(&shared, &eph_pub, recipient_pub, info));
    let sealed = Aes256Gcm::new_from_slice(&*key).expect("32-byte key")
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| invalid("could not seal"))?;
    let mut out = eph_pub.to_vec();
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(b64(&out))
}

pub fn seal_box(recipient_pub: &[u8; 32], plaintext: &[u8], aad: &[u8], info: &str) -> Result<String> {
    let eph = Zeroizing::new(random_bytes::<32>());
    seal_box_with(recipient_pub, plaintext, aad, info, &eph, &random_bytes::<12>())
}

/// Opens a box with the recipient's secret. Any failure is `auth` (the caller maps wrong secrets onto it).
pub fn open_box(recipient_secret: &[u8; 32], text: &str, aad: &[u8], info: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bad = || ChatError::coded("auth", "that does not open this box");
    let raw = unb64(text, None).map_err(|_| invalid("malformed box"))?;
    if raw.len() < 32 + 12 + 16 { return Err(invalid("malformed box")); }
    let (eph_pub, nonce, ciphertext) = (<[u8; 32]>::try_from(&raw[..32]).expect("32"), &raw[32..44], &raw[44..]);
    let recipient_pub = dh_public(recipient_secret);
    let shared = shared_secret(recipient_secret, &eph_pub).map_err(|_| bad())?;
    let key = Zeroizing::new(box_key(&shared, &eph_pub, &recipient_pub, info));
    let plain = Aes256Gcm::new_from_slice(&*key).expect("32-byte key")
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| bad())?;
    Ok(Zeroizing::new(plain))
}

// ---------- The backup record ----------

/// What a device keeps locally to re-seal the backup: the epoch and the public unlock keys (never given to the server).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupKeys {
    pub epoch: u32,
    pub pass_pub: [u8; 32],
    pub recovery_pub: [u8; 32],
}

impl BackupKeys {
    pub fn json(&self) -> serde_json::Value { serde_json::json!({ "epoch": self.epoch, "passPub": b64(&self.pass_pub), "recoveryPub": b64(&self.recovery_pub) }) }

    pub fn parse(value: &serde_json::Value) -> Result<Self> {
        let bad = || invalid("malformed backup keys");
        let object = value.as_object().filter(|o| exactly(o, &["epoch", "passPub", "recoveryPub"])).ok_or_else(bad)?;
        let epoch = object["epoch"].as_u64().filter(|e| (1..=u32::MAX as u64).contains(e)).ok_or_else(bad)? as u32;
        Ok(Self { epoch, pass_pub: key(object["passPub"].as_str().ok_or_else(bad)?)?, recovery_pub: key(object["recoveryPub"].as_str().ok_or_else(bad)?)? })
    }
}

/// `text16(label) ‖ text16(userId) ‖ bytes8(aikSign) ‖ u32(epoch)`: what every backup box is bound to.
pub fn backup_aad(user_id: &str, aik_sign: &[u8; 32], epoch: u32) -> Vec<u8> { Writer::new().text16(BACKUP_LABEL).text16(user_id).bytes8(aik_sign).u32(epoch).done() }

/// `AccountKey ‖ bytes8(passPub) ‖ bytes8(recoveryPub)`: what a backup box holds.
pub fn backup_plaintext(account_key: &[u8], keys: &BackupKeys) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Writer::new().raw(account_key).bytes8(&keys.pass_pub).bytes8(&keys.recovery_pub).done())
}

/// The inverse: the AccountKey bytes (strictly parsed) and the backup keys (epoch from the caller).
pub fn parse_backup_plaintext(bytes: &[u8], epoch: u32) -> Result<(Parsed, BackupKeys)> {
    let bad = || invalid("malformed backup");
    let (parsed, used) = parse_account_key_prefix(bytes)?;
    let mut cursor = Cursor { bytes, at: used };
    let (pass_pub, recovery_pub) = (cursor.key8().ok_or_else(bad)?, cursor.key8().ok_or_else(bad)?);
    if cursor.at != bytes.len() { return Err(bad()); }
    Ok((parsed, BackupKeys { epoch, pass_pub, recovery_pub }))
}

/// The bytes the AIK signs over a backup's public record (docs/m6-account-key.md §3.3).
#[allow(clippy::too_many_arguments)]
pub fn keys_bytes(user_id: &str, aik_sign: &[u8; 32], epoch: u32, salt: &[u8; 16], m: u32, t: u32, p: u32, pass_hash: &[u8; 32], recovery_hash: &[u8; 32], pass_proof_hash: &[u8; 32], recovery_proof_hash: &[u8; 32]) -> Vec<u8> {
    Writer::new().text16(KEYS_LABEL).text16(user_id).bytes8(aik_sign).u32(epoch).bytes8(salt).u32(m).u32(t).u32(p)
        .bytes8(pass_hash).bytes8(recovery_hash).bytes8(pass_proof_hash).bytes8(recovery_proof_hash).done()
}

/// `text16(label) ‖ text16(userId) ‖ text16(deviceId) ‖ text16(platform) ‖ bytes8(eph) ‖ bytes8(leafSigKey) ‖ bytes8(aikSign)`:
/// what a companion's MLS leaf key signs to ask for the account key, and what the answer is bound to (docs §5).
pub fn rekey_bytes(user_id: &str, device_id: &str, platform: &str, eph: &[u8; 32], leaf_sig_key: &[u8; 32], aik_sign: &[u8; 32]) -> Vec<u8> {
    Writer::new().text16(REKEY_LABEL).text16(user_id).text16(device_id).text16(platform).bytes8(eph).bytes8(leaf_sig_key).bytes8(aik_sign).done()
}

fn exactly(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> bool { object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k)) }

/// A backup record as the server stores it (`signature` and `updatedAt` only once signed and stored).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub user_id: String,
    pub aik_sign: String,
    pub epoch: u32,
    pub salt: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub pass_hash: String,
    pub recovery_hash: String,
    pub pass: String,
    pub recovery: String,
    pub pass_proof_hash: String,
    pub recovery_proof_hash: String,
    pub signature: Option<String>,
}

/// The size of a backup box: ephemeral key, nonce, the plaintext (AccountKey and two `bytes8` keys) and the GCM tag.
pub fn box_length(user_id: &str) -> usize { 32 + 12 + (95 + user_id.len()) + 66 + 16 }

impl Record {
    /// Strict parse: exact keys (`signature` optional, `updatedAt` ignored when present), canonical sizes, a cost in range.
    pub fn parse(value: &serde_json::Value) -> Result<Self> {
        let bad = || invalid("malformed backup");
        let object = value.as_object().ok_or_else(bad)?;
        let base = ["v", "userId", "aikSign", "epoch", "kdf", "passHash", "recoveryHash", "pass", "recovery", "passProofHash", "recoveryProofHash"];
        let with = |extra: &[&'static str]| -> Vec<&'static str> { [&base[..], extra].concat() };
        if !(exactly(object, &base) || exactly(object, &with(&["signature"])) || exactly(object, &with(&["signature", "updatedAt"]))) { return Err(bad()); }
        if object["v"].as_u64() != Some(1) { return Err(bad()); }
        let text = |name: &str| object[name].as_str().map(str::to_string).ok_or_else(bad);
        let kdf = object["kdf"].as_object().filter(|k| exactly(k, &["alg", "salt", "m", "t", "p"])).ok_or_else(bad)?;
        let num = |name: &str| kdf[name].as_u64().filter(|n| *n <= u32::MAX as u64).map(|n| n as u32).ok_or_else(bad);
        let (m, t, p) = (num("m")?, num("t")?, num("p")?);
        if kdf["alg"].as_str() != Some("argon2id") || !KDF_M_RANGE.contains(&m) || !KDF_T_RANGE.contains(&t) || !KDF_P_RANGE.contains(&p) { return Err(bad()); }
        let record = Self {
            user_id: text("userId")?, aik_sign: text("aikSign")?, epoch: object["epoch"].as_u64().filter(|e| (1..=u32::MAX as u64).contains(e)).ok_or_else(bad)? as u32,
            salt: kdf["salt"].as_str().ok_or_else(bad)?.to_string(), m, t, p,
            pass_hash: text("passHash")?, recovery_hash: text("recoveryHash")?, pass: text("pass")?, recovery: text("recovery")?,
            pass_proof_hash: text("passProofHash")?, recovery_proof_hash: text("recoveryProofHash")?,
            signature: match object.get("signature") { None => None, Some(v) => Some(v.as_str().ok_or_else(bad)?.to_string()) },
        };
        if !crate::devicelist::user_id_ok(&record.user_id) { return Err(bad()); }
        for k in [&record.aik_sign, &record.pass_hash, &record.recovery_hash, &record.pass_proof_hash, &record.recovery_proof_hash] { key(k)?; }
        unb64(&record.salt, Some(16)).map_err(|_| bad())?;
        for b in [&record.pass, &record.recovery] { unb64(b, Some(box_length(&record.user_id))).map_err(|_| bad())?; }
        if let Some(sig) = &record.signature { unb64(sig, Some(64)).map_err(|_| bad())?; }
        Ok(record)
    }

    pub fn json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "v": 1, "userId": self.user_id, "aikSign": self.aik_sign, "epoch": self.epoch,
            "kdf": { "alg": "argon2id", "salt": self.salt, "m": self.m, "t": self.t, "p": self.p },
            "passHash": self.pass_hash, "recoveryHash": self.recovery_hash, "pass": self.pass, "recovery": self.recovery,
            "passProofHash": self.pass_proof_hash, "recoveryProofHash": self.recovery_proof_hash,
        });
        if let Some(signature) = &self.signature { value["signature"] = serde_json::json!(signature); }
        value
    }

    pub fn keys_bytes(&self) -> Result<Vec<u8>> {
        Ok(keys_bytes(&self.user_id, &key(&self.aik_sign)?, self.epoch, &unb64(&self.salt, Some(16))?.try_into().expect("16"), self.m, self.t, self.p,
            &key(&self.pass_hash)?, &key(&self.recovery_hash)?, &key(&self.pass_proof_hash)?, &key(&self.recovery_proof_hash)?))
    }

    /// Verifies `signature` over the keys bytes under `aik_sign` (and, when given, that it is the key the caller expects).
    pub fn verify(&self, expected_sign: Option<&str>) -> Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};
        if expected_sign.is_some_and(|expected| expected != self.aik_sign) { return Err(ChatError::coded("auth", "the backup is for another account key")); }
        let signature = self.signature.as_deref().ok_or_else(|| invalid("the backup is not signed"))?;
        let verifying = VerifyingKey::from_bytes(&key(&self.aik_sign)?).map_err(|_| invalid("malformed key"))?;
        let raw: [u8; 64] = unb64(signature, Some(64)).map_err(|_| invalid("malformed signature"))?.try_into().expect("64");
        verifying.verify_strict(&self.keys_bytes()?, &Signature::from_bytes(&raw)).map_err(|_| ChatError::coded("auth", "the backup's signature is not valid"))
    }
}

/// Seals `account_key` and the backup keys to both unlock keys under `aik_sign` and `keys.epoch`.
pub fn seal_both(user_id: &str, aik_sign: &[u8; 32], account_key: &[u8], keys: &BackupKeys) -> Result<(String, String)> {
    let (aad, plain) = (backup_aad(user_id, aik_sign, keys.epoch), backup_plaintext(account_key, keys));
    Ok((seal_box(&keys.pass_pub, &plain, &aad, BACKUP_BOX_INFO)?, seal_box(&keys.recovery_pub, &plain, &aad, BACKUP_BOX_INFO)?))
}

/// Checks a new custom passphrase's length (after NFKC).
pub fn check_new_passphrase(passphrase: &str) -> Result<()> {
    if normalize_passphrase(passphrase).chars().count() < MIN_PASSPHRASE_CHARS { return Err(invalid("a passphrase is at least 14 characters")); }
    Ok(())
}
