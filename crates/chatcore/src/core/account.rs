//! The account key on every device and its encrypted backup (docs/m6-account-key.md). A core holds the account
//! identity key (AIK) as its `identity` row (a **full** core) or only the account's public identity as `account`
//! (a companion). These calls move the AIK between cores: export/import, the passphrase and recovery-key backup,
//! and the rekey a companion asks for.
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::Core;
use crate::account_key::{self as ak, BackupKeys, Record};
use crate::error::{ChatError, Result};
use crate::primitives::{b64, random_bytes, unb64, unb64_32, DhPair, Secret32};
use crate::protocol::{Identity, IdentityPub};
use crate::store::Write;

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", what) }
fn companion() -> ChatError { ChatError::coded("companion", "This device does not hold the account's identity key") }
fn auth(what: &str) -> ChatError { ChatError::coded("auth", what) }

/// What `backup_create` returns: the unsigned record, the recovery words (show once), the backup keys to keep locally
/// after the server accepts the record, and the proofs the server checks against the record's proof hashes.
pub struct BackupCreated {
    pub record: Value,
    pub words: String,
    pub backup_keys: Value,
    pub pass_proof: String,
    pub recovery_proof: String,
}

/// What `backup_reseal` returns: the same, with `words` and the proofs only for a side that changed.
pub struct BackupResealed {
    pub record: Value,
    pub backup_keys: Value,
    pub words: Option<String>,
    pub pass_proof: Option<String>,
    pub recovery_proof: Option<String>,
}

const BACKUP_KEYS_ROW: &str = "backup:keys";

/// The public unlock key of one side of a backup and the proof of knowing its secret.
struct Side {
    public: [u8; 32],
    proof: Zeroizing<[u8; 32]>,
}

impl Core {
    fn user_id_checked(user_id: &str) -> Result<()> { if crate::devicelist::user_id_ok(user_id) { Ok(()) } else { Err(invalid("invalid user id")) } }

    /// The AccountKey of this (full) core. Never mints an identity.
    fn own_account_key(&mut self, user_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        Self::user_id_checked(user_id)?;
        self.reject_companion()?;
        let identity = self.identity_row()?.ok_or_else(|| invalid("this device holds no account identity"))?;
        Ok(ak::account_key_bytes(user_id, &identity.sign.0, &identity.dh.secret.0))
    }

    /// The AccountKey from `given` (base64url, e.g. a web-held AIK) or, when absent, this core's own.
    fn account_key_or_own(&mut self, user_id: &str, given: Option<&str>) -> Result<(Zeroizing<Vec<u8>>, [u8; 32])> {
        let bytes = match given {
            Some(text) => Zeroizing::new(unb64(text, None).map_err(|_| invalid("malformed account key"))?),
            None => self.own_account_key(user_id)?,
        };
        let (owner, seed, _) = ak::parse_account_key(&bytes)?;
        if owner != user_id { return Err(invalid("the account key is for another account")); }
        Ok((bytes, ak::sign_public(&seed)))
    }

    /// `exportAccountKey`: the bytes of docs/m6 §1 (base64url). Full cores only (`companion` otherwise).
    pub fn export_account_key(&mut self, user_id: &str) -> Result<String> { Ok(b64(&self.own_account_key(user_id)?)) }

    /// `importAccountKey`: this core becomes full. The key must match what this core pins (a companion's `account`
    /// identity, or its own identity), or, on a core with neither (restore), `published`, the identity the server
    /// serves for the account. Pins, MLS state and `own-previous` stay.
    pub fn import_account_key(&mut self, user_id: &str, key: &str, published: Option<&IdentityPub>) -> Result<IdentityPub> {
        Self::user_id_checked(user_id)?;
        let bytes = Zeroizing::new(unb64(key, None).map_err(|_| invalid("malformed account key"))?);
        let (owner, seed, dh_secret) = ak::parse_account_key(&bytes)?;
        if owner != user_id { return Err(invalid("the account key is for another account")); }
        let derived = IdentityPub { dh: b64(&ak::dh_public(&dh_secret)), sign: b64(&ak::sign_public(&seed)) };
        let account = self.account()?;
        let own = self.identity_row()?;
        let expected = match (&account, &own) {
            (Some(account), _) => {
                if account.user_id != user_id { return Err(invalid("the account key is for another account")); }
                account.identity.clone()
            }
            (None, Some(own)) => own.public.clone(),
            (None, None) => published.cloned().ok_or_else(|| invalid("the account's published identity is needed"))?,
        };
        if derived != expected { return Err(invalid("the account key does not match this account's identity")); }
        if own.is_some() { return Ok(derived); }
        let identity = Identity { sign: Secret32(*seed), dh: DhPair { secret: Secret32(*dh_secret), public: ak::dh_public(&dh_secret) }, public: derived.clone() };
        self.store.batch(vec![Write::Put("identity".into(), super::to_value(&identity)), Write::Delete("account".into())])?;
        self.may_create_identity = false;
        Ok(derived)
    }

    // ---------- Backup keys kept locally ----------

    /// The backup keys this core holds (the epoch and the public unlock keys), if any.
    pub fn backup_keys(&mut self) -> Result<Option<BackupKeys>> {
        self.store.get(BACKUP_KEYS_ROW)?.map(|value| BackupKeys::parse(&value)).transpose()
    }

    /// Remembers backup keys unless this core already holds a higher epoch; returns the keys it holds afterwards.
    pub fn set_backup_keys(&mut self, keys: &BackupKeys) -> Result<BackupKeys> {
        if let Some(held) = self.backup_keys()? { if held.epoch > keys.epoch { return Ok(held); } }
        self.store.put(BACKUP_KEYS_ROW, keys.json())?;
        Ok(keys.clone())
    }

    // ---------- Backup ----------

    /// `passphraseGenerate`: six words.
    pub fn generate_passphrase() -> String { ak::generate_passphrase() }

    fn salted_pass(passphrase: &str) -> Result<([u8; 16], Side)> {
        ak::check_new_passphrase(passphrase)?;
        let salt = random_bytes::<16>();
        let seed = ak::pass_seed(passphrase, &salt, ak::KDF_M, ak::KDF_T, ak::KDF_P)?;
        Ok((salt, Side { public: ak::dh_public(&ak::pass_secret(&seed)), proof: ak::pass_proof(&seed) }))
    }

    fn fresh_recovery() -> (String, Side) {
        let entropy = Zeroizing::new(random_bytes::<32>());
        (ak::words_from_entropy(&entropy).join(" "), Side { public: ak::dh_public(&ak::recovery_secret(&entropy)), proof: ak::recovery_proof(&entropy) })
    }

    #[allow(clippy::too_many_arguments)]
    fn make_record(user_id: &str, aik_sign: &[u8; 32], keys: &BackupKeys, salt: &[u8; 16], (m, t, p): (u32, u32, u32), account_key: &[u8], pass_proof_hash: String, recovery_proof_hash: String) -> Result<Record> {
        let (pass, recovery) = ak::seal_both(user_id, aik_sign, account_key, keys)?;
        Ok(Record {
            user_id: user_id.to_string(), aik_sign: b64(aik_sign), epoch: keys.epoch, salt: b64(salt), m, t, p,
            pass_hash: ak::sha256_b64(&keys.pass_pub), recovery_hash: ak::sha256_b64(&keys.recovery_pub), pass, recovery,
            pass_proof_hash, recovery_proof_hash, signature: None,
        })
    }

    /// `backupCreate`: a first backup (epoch 1) of this account's key (or of `account_key`, for a core that does not
    /// hold the AIK), sealed to the passphrase and a fresh recovery key.
    pub fn backup_create(&mut self, user_id: &str, passphrase: &str, account_key: Option<&str>) -> Result<BackupCreated> {
        Self::user_id_checked(user_id)?;
        let (bytes, aik_sign) = self.account_key_or_own(user_id, account_key)?;
        let (salt, pass) = Self::salted_pass(passphrase)?;
        let (words, recovery) = Self::fresh_recovery();
        let keys = BackupKeys { epoch: 1, pass_pub: pass.public, recovery_pub: recovery.public };
        let record = Self::make_record(user_id, &aik_sign, &keys, &salt, (ak::KDF_M, ak::KDF_T, ak::KDF_P), &bytes, ak::sha256_b64(&*pass.proof), ak::sha256_b64(&*recovery.proof))?;
        Ok(BackupCreated { record: record.json(), words, backup_keys: keys.json(), pass_proof: b64(&*pass.proof), recovery_proof: b64(&*recovery.proof) })
    }

    /// `backupSignKeys`: the AIK's signature over the record's keys bytes. Full cores only; the record must be this
    /// account's and name this core's own key.
    pub fn backup_sign_keys(&mut self, user_id: &str, record: &Value) -> Result<String> {
        use ed25519_dalek::Signer;
        let record = Record::parse(record)?;
        let identity = self.identity_row()?.filter(|_| self.account().ok().flatten().is_none()).ok_or_else(companion)?;
        if record.user_id != user_id || record.aik_sign != identity.public.sign { return Err(invalid("the backup is not for this account key")); }
        let key = ed25519_dalek::SigningKey::from_bytes(&identity.sign.0);
        Ok(b64(&key.sign(&record.keys_bytes()?).to_bytes()))
    }

    /// `backupProve`: the proof of knowing the passphrase or the recovery key, which the server holds the hash of. It is
    /// checked against the record first, so a wrong secret is `auth` here rather than a refused request later.
    pub fn backup_prove(&mut self, record: &Value, passphrase: Option<&str>, words: Option<&str>) -> Result<String> {
        let record = Record::parse(record)?;
        match (passphrase, words) {
            (Some(text), None) => {
                let seed = ak::pass_seed(text, &unb64(&record.salt, Some(16))?.try_into().expect("16"), record.m, record.t, record.p)?;
                let proof = ak::pass_proof(&seed);
                if ak::sha256_b64(&*proof) != record.pass_proof_hash { return Err(auth("That passphrase doesn't open your backup.")); }
                Ok(b64(&*proof))
            }
            (None, Some(text)) => {
                let proof = ak::recovery_proof(&*ak::entropy_from_words(text)?);
                if ak::sha256_b64(&*proof) != record.recovery_proof_hash { return Err(auth("Those words don't open your backup.")); }
                Ok(b64(&*proof))
            }
            _ => Err(invalid("give a passphrase or a recovery key")),
        }
    }

    /// `backupReseal`: the record again at `epoch + 1` with the account key now held, sealed to the **locally held**
    /// backup keys (never to anything the server says): after a rotation (no secret needed), a new passphrase, or a new
    /// recovery key. The old record must be signed by this account's current AIK, or by the one immediately before it
    /// (right after a rotation), must not be older than the local keys, and the side that does not change must be the
    /// one the local keys belong to.
    pub fn backup_reseal(&mut self, user_id: &str, record: &Value, keys: &BackupKeys, account_key: Option<&str>, passphrase: Option<&str>, new_recovery: bool) -> Result<BackupResealed> {
        let old = Record::parse(record)?;
        if old.user_id != user_id { return Err(invalid("the backup is for another account")); }
        let current = self.public_identity()?.sign;
        // The previous key counts only as the old key of the rotation this core itself just committed (`rotation:last`), not any
        // key it ever had: a record signed by an older key is not this account's to re-seal.
        let own_rotation = self.store.get("rotation:last")?.is_some_and(|last| last["old"].as_str() == Some(old.aik_sign.as_str()) && last["new"].as_str() == Some(current.as_str()));
        if old.aik_sign != current && !own_rotation { return Err(auth("the backup was not signed by this account's key")); }
        old.verify(None)?;
        if old.epoch < keys.epoch { return Err(auth("the backup is older than the keys this device holds")); }
        if (passphrase.is_none() && ak::sha256_b64(&keys.pass_pub) != old.pass_hash) || (!new_recovery && ak::sha256_b64(&keys.recovery_pub) != old.recovery_hash) {
            return Err(auth("this device does not hold the keys of that backup"));
        }
        let (bytes, aik_sign) = self.account_key_or_own(user_id, account_key)?;
        let epoch = old.epoch.checked_add(1).ok_or_else(|| invalid("the backup cannot be changed again"))?;
        let (mut salt, mut cost) = (unb64(&old.salt, Some(16))?.try_into().expect("16"), (old.m, old.t, old.p));
        let (mut pass_pub, mut pass_proof_hash, mut pass_proof) = (keys.pass_pub, old.pass_proof_hash.clone(), None);
        if let Some(text) = passphrase {
            let (new_salt, side) = Self::salted_pass(text)?;
            (salt, cost, pass_pub, pass_proof_hash, pass_proof) = (new_salt, (ak::KDF_M, ak::KDF_T, ak::KDF_P), side.public, ak::sha256_b64(&*side.proof), Some(b64(&*side.proof)));
        }
        let (mut recovery_pub, mut recovery_proof_hash, mut recovery_proof, mut words) = (keys.recovery_pub, old.recovery_proof_hash.clone(), None, None);
        if new_recovery {
            let (new_words, side) = Self::fresh_recovery();
            (recovery_pub, recovery_proof_hash, recovery_proof, words) = (side.public, ak::sha256_b64(&*side.proof), Some(b64(&*side.proof)), Some(new_words));
        }
        let next = BackupKeys { epoch, pass_pub, recovery_pub };
        let record = Self::make_record(user_id, &aik_sign, &next, &salt, cost, &bytes, pass_proof_hash, recovery_proof_hash)?;
        Ok(BackupResealed { record: record.json(), backup_keys: next.json(), words, pass_proof, recovery_proof })
    }

    /// `backupOpen`: the AccountKey (base64url) and the backup keys from a backup, with the passphrase or the 24 words.
    /// The record's signature is checked first (and, when given, that it names the account's published key). A wrong
    /// passphrase or wrong words is `auth`; malformed words are `invalid`.
    pub fn backup_open(&mut self, user_id: &str, record: &Value, passphrase: Option<&str>, words: Option<&str>, published: Option<&IdentityPub>) -> Result<(String, Value)> {
        let record = Record::parse(record)?;
        if record.user_id != user_id { return Err(invalid("the backup is for another account")); }
        record.verify(published.map(|p| p.sign.as_str()))?;
        let (secret, hash, boxed, wrong) = match (passphrase, words) {
            (Some(text), None) => {
                let seed = ak::pass_seed(text, &unb64(&record.salt, Some(16))?.try_into().expect("16"), record.m, record.t, record.p)?;
                (ak::pass_secret(&seed), &record.pass_hash, &record.pass, "That passphrase doesn't open your backup.")
            }
            (None, Some(text)) => (ak::recovery_secret(&*ak::entropy_from_words(text)?), &record.recovery_hash, &record.recovery, "Those words don't open your backup."),
            _ => return Err(invalid("give a passphrase or a recovery key")),
        };
        if &ak::sha256_b64(&ak::dh_public(&secret)) != hash { return Err(auth(wrong)); }
        let aik_sign = unb64_32(&record.aik_sign)?;
        let plain = ak::open_box(&secret, boxed, &ak::backup_aad(user_id, &aik_sign, record.epoch), ak::BACKUP_BOX_INFO).map_err(|_| auth(wrong))?;
        let ((owner, seed, _), keys) = ak::parse_backup_plaintext(&plain, record.epoch)?;
        // What the box holds must be what the signed record commits to.
        if owner != user_id || ak::sign_public(&seed) != aik_sign || ak::sha256_b64(&keys.pass_pub) != record.pass_hash || ak::sha256_b64(&keys.recovery_pub) != record.recovery_hash {
            return Err(invalid("the backup does not hold this account's key"));
        }
        let (account_key, _) = plain.split_at(plain.len() - 66);
        Ok((b64(account_key), keys.json()))
    }

    // ---------- Rekey (docs/m6 §5) ----------

    /// `rekeyRequest`: a companion asks for the account key. Makes (once) the ephemeral key the answer is sealed to
    /// and signs the request with this device's MLS leaf key. Repeating it returns the same request.
    #[cfg(feature = "mls")]
    pub fn rekey_request(&mut self, user_id: &str, device_id: &str, platform: &str) -> Result<Value> {
        Self::user_id_checked(user_id)?;
        Self::device_platform_ok(platform)?;
        let account = self.account()?.ok_or_else(|| invalid("only a device without the account key asks for it"))?;
        if account.user_id != user_id { return Err(invalid("this device belongs to another account")); }
        let eph = match self.get::<RekeyPending>("rekey:pending")? {
            Some(pending) if pending.device_id == device_id => pending.eph,
            _ => {
                let eph = DhPair::generate();
                self.store.put("rekey:pending", super::to_value(&RekeyPending { device_id: device_id.to_string(), eph: eph.clone() }))?;
                eph
            }
        };
        let (groups, store) = self.groups()?;
        if groups.own_cert(store)?.device_id != device_id { return Err(invalid("that is not this device")); }
        let aik_sign = unb64_32(&account.identity.sign)?;
        let leaf: [u8; 32] = unb64_32(&groups.device_leaf(store)?)?;
        let bytes = ak::rekey_bytes(user_id, device_id, platform, &eph.public, &leaf, &aik_sign);
        let (leaf_sig_key, signature) = groups.leaf_sign(store, &bytes)?;
        Ok(json!({ "eph": b64(&eph.public), "leafSigKey": leaf_sig_key, "signature": signature }))
    }

    #[cfg(feature = "mls")]
    fn device_platform_ok(platform: &str) -> Result<()> {
        if crate::mls::cert::PLATFORMS.contains(&platform) && platform != "bot" && platform != "mcp" { Ok(()) } else { Err(invalid("unknown platform")) }
    }

    /// `rekeyAnswer`: a full device seals the account key, a certificate for the asking device's leaf and the current
    /// backup keys to its ephemeral key. The request's signature (under the leaf key, over bytes naming this core's AIK)
    /// and the leaf being known to a group of ours (`groups`) are checked here; that the device is in the newest signed
    /// list is the caller's check. `backup_keys` defaults to the keys this core holds.
    #[cfg(feature = "mls")]
    #[allow(clippy::too_many_arguments)]
    pub fn rekey_answer(&mut self, user_id: &str, device_id: &str, platform: &str, eph: &str, leaf_sig_key: &str, signature: &str, groups: &[openmls::prelude::GroupId], now: u64, backup_keys: Option<&BackupKeys>) -> Result<String> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use crate::mls::cert::DeviceCert;
        if !crate::devicelist::device_id_ok(device_id) { return Err(invalid("invalid device id")); }
        Self::device_platform_ok(platform)?;
        let bytes = self.own_account_key(user_id)?;
        let (eph_key, leaf) = (unb64_32(eph)?, unb64_32(leaf_sig_key)?);
        let aik = self.identity_row()?.ok_or_else(companion)?;
        let aik_sign = unb64_32(&aik.public.sign)?;
        let bound = ak::rekey_bytes(user_id, device_id, platform, &eph_key, &leaf, &aik_sign);
        let raw: [u8; 64] = unb64(signature, Some(64)).map_err(|_| invalid("malformed signature"))?.try_into().expect("64");
        VerifyingKey::from_bytes(&leaf).map_err(|_| invalid("malformed key"))?
            .verify_strict(&bound, &Signature::from_bytes(&raw))
            .map_err(|_| auth("the request is not signed by that device's leaf key"))?;
        let known = { let (g, store) = self.groups()?; g.leaf_known(store, groups, device_id, leaf_sig_key)? };
        if !known { return Err(auth("no group of ours holds that leaf for that device")); }
        let keys = match backup_keys { Some(keys) => Some(keys.clone()), None => self.backup_keys()? };
        let signing = ed25519_dalek::SigningKey::from_bytes(&aik.sign.0);
        let cert = DeviceCert::issue(&signing, user_id, device_id, platform, &leaf, now)?;
        // Built by hand so the AccountKey's text is never in a value that is not wiped (field order is part of the answer).
        let account_key = Zeroizing::new(b64(&bytes));
        let cert_text = serde_json::to_string(&String::from_utf8(cert.encode()).map_err(ChatError::storage)?).map_err(ChatError::storage)?;
        let keys_text = serde_json::to_string(&keys.as_ref().map(BackupKeys::json)).map_err(ChatError::storage)?;
        let plaintext = Zeroizing::new(format!(r#"{{"v":1,"accountKey":"{}","cert":{cert_text},"backupKeys":{keys_text}}}"#, &*account_key));
        ak::seal_box(&eph_key, plaintext.as_bytes(), &bound, ak::REKEY_BOX_INFO)
    }

    /// `rekeyOpen`: the companion opens the answer with its pending ephemeral key, checks the key against the identity
    /// it pins and the certificate against this device, installs both (and the backup keys unless it holds a higher
    /// epoch) and becomes full. Returns the identity and the backup keys it holds.
    #[cfg(feature = "mls")]
    pub fn rekey_open(&mut self, user_id: &str, device_id: &str, platform: &str, boxed: &str) -> Result<(IdentityPub, Option<Value>)> {
        Self::device_platform_ok(platform)?;
        let account = self.account()?.ok_or_else(|| invalid("only a device without the account key opens an answer"))?;
        let pending = self.get::<RekeyPending>("rekey:pending")?.filter(|p| p.device_id == device_id).ok_or_else(|| invalid("no key was asked for"))?;
        if account.user_id != user_id { return Err(invalid("this device belongs to another account")); }
        let aik_sign = unb64_32(&account.identity.sign)?;
        let leaf: [u8; 32] = { let (groups, store) = self.groups()?; unb64_32(&groups.device_leaf(store)?)? };
        let plain = ak::open_box(&pending.eph.secret.0, boxed, &ak::rekey_bytes(user_id, device_id, platform, &pending.eph.public, &leaf, &aik_sign), ak::REKEY_BOX_INFO)?;
        let mut value: Value = serde_json::from_slice(&plain).map_err(|_| invalid("malformed answer"))?;
        let object = value.as_object_mut().filter(|o| o.len() == 4 && o.get("v").and_then(Value::as_u64) == Some(1)).ok_or_else(|| invalid("malformed answer"))?;
        // The AccountKey's text is moved out of the parsed value into a wiped string rather than copied.
        let key = Zeroizing::new(match object.remove("accountKey") { Some(Value::String(text)) => text, _ => return Err(invalid("malformed answer")) });
        let cert = object.get("cert").and_then(Value::as_str).ok_or_else(|| invalid("malformed answer"))?.to_string();
        let keys = match object.get("backupKeys") { Some(Value::Null) => None, Some(value) => Some(BackupKeys::parse(value)?), None => return Err(invalid("malformed answer")) };
        // The key is checked against the pinned identity before anything is installed.
        let bytes = Zeroizing::new(unb64(&key, None).map_err(|_| invalid("malformed account key"))?);
        let (owner, seed, dh_secret) = ak::parse_account_key(&bytes)?;
        let derived = IdentityPub { dh: b64(&ak::dh_public(&dh_secret)), sign: b64(&ak::sign_public(&seed)) };
        if owner != user_id || derived != account.identity { return Err(invalid("the account key does not match this account's identity")); }
        let installed = { let (groups, store) = self.groups()?; groups.set_device_cert(store, &cert, &aik_sign)? };
        if installed.user_id != user_id || installed.device_id != device_id { return Err(invalid("the certificate is for another device")); }
        let identity = Identity { sign: Secret32(*seed), dh: DhPair { secret: Secret32(*dh_secret), public: ak::dh_public(&dh_secret) }, public: derived.clone() };
        self.store.batch(vec![Write::Put("identity".into(), super::to_value(&identity)), Write::Delete("account".into()), Write::Delete("rekey:pending".into())])?;
        self.may_create_identity = false;
        let held = match keys { Some(keys) => Some(self.set_backup_keys(&keys)?), None => self.backup_keys()? };
        Ok((derived, held.map(|k| k.json())))
    }
}

#[cfg(feature = "mls")]
#[derive(serde::Serialize, serde::Deserialize)]
struct RekeyPending {
    #[serde(rename = "deviceId")]
    device_id: String,
    eph: DhPair,
}
