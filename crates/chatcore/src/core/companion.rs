//! Linked devices, identity succession and pin transfer (docs/m5-linking.md). A **companion** is a device with its
//! own device and MLS leaf keys but no secret of the account identity key (AIK): its core stores only `account`, the
//! account's public identity, and refuses to mint an identity or do 1:1 crypto (code `companion`).
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{from_value, same_identity, to_value, Core, PeerRecord, PreviousKey};
use crate::error::{ChatError, Result};
use crate::primitives::{b64, dh, is_key_b64, random_bytes, unb64, unb64_32, DhPair};
use crate::protocol::{Identity, IdentityPub};
use crate::store::Write;
use crate::succession::{self, Record};

const LINK_TTL_MS: u64 = 15 * 60 * 1000;
const MAX_PINS: usize = 5000;

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", what) }
fn companion() -> ChatError { ChatError::coded("companion", "This device does not hold the account's identity key") }

/// What a companion knows of its account: the public identity, pinned at link time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub identity: IdentityPub,
}

/// A pin as it travels in the link bundle (docs §2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinExport {
    pub contact: String,
    pub identity: IdentityPub,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous: Vec<PreviousKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LinkState {
    #[serde(rename = "linkId")]
    link_id: String,
    /// `n` (the new device that showed the QR) or `p` (the primary that scanned it).
    role: String,
    secret: String,
    #[serde(rename = "ephN")]
    eph_n: String,
    eph: DhPair,
    #[serde(rename = "ephP")]
    eph_p: Option<String>,
    #[serde(rename = "kOut")]
    k_out: Option<String>,
    #[serde(rename = "kIn")]
    k_in: Option<String>,
    out: u64,
    inn: u64,
    at: u64,
    /// Short-code variant (docs §1.7): the commitment, nonce and device ids involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_mode: Option<CodeMode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CodeMode {
    commit: Option<String>,
    nonce: Option<String>,
    #[serde(rename = "deviceN")]
    device_n: String,
    #[serde(rename = "deviceP")]
    device_p: Option<String>,
}

/// What `link_accept` returns to the primary.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LinkAccepted {
    #[serde(rename = "linkId")]
    pub link_id: String,
    /// The primary's ephemeral public key (base64url), to offer to the server.
    pub eph: String,
    pub code: String,
}

fn user_id_ok(text: &str) -> bool { crate::devicelist::user_id_ok(text) }

impl Core {
    pub fn account(&mut self) -> Result<Option<Account>> { self.get("account") }

    /// Whether this core is a companion (no identity secret; the account's public identity is pinned).
    pub fn is_companion(&mut self) -> Result<bool> { Ok(self.account()?.is_some()) }

    /// The account's public identity: a companion's pinned one, else this core's own.
    pub fn public_identity(&mut self) -> Result<IdentityPub> {
        match self.account()? { Some(account) => Ok(account.identity), None => Ok(self.identity()?.public) }
    }

    /// The account key that certifies this device's MLS certificate: own, or a companion's pinned one.
    #[cfg(feature = "mls")]
    pub(crate) fn account_aik_bytes(&mut self) -> Result<[u8; 32]> { unb64_32(&self.public_identity()?.sign) }

    /// 1:1 crypto and everything that signs with the account key needs the key itself.
    pub(super) fn reject_companion(&mut self) -> Result<()> { if self.account()?.is_some() { Err(companion()) } else { Ok(()) } }

    fn identity_row(&mut self) -> Result<Option<Identity>> { self.get::<Identity>("identity") }

    // ---------- Becoming a companion ----------

    /// Installs a link grant on a new device: pins the account's identity, installs the MLS certificate the primary
    /// signed for this device's leaf key (`mls_device_leaf` was called before the hello), and enters companion mode.
    #[cfg(feature = "mls")]
    pub fn companion_setup(&mut self, user_id: &str, identity: &IdentityPub, cert_json: &str) -> Result<crate::mls::cert::DeviceCert> {
        if self.identity_row()?.is_some() { return Err(invalid("This device holds an identity; retire it first")); }
        if !user_id_ok(user_id) || !is_key_b64(&identity.sign) || !is_key_b64(&identity.dh) { return Err(invalid("Invalid account identity")); }
        let aik = unb64_32(&identity.sign)?;
        unb64_32(&identity.dh)?;
        let cert = {
            let (groups, store) = self.groups()?;
            groups.set_device_cert(store, cert_json, &aik)?
        };
        if cert.user_id != user_id { return Err(invalid("The certificate is for another account")); }
        self.store.put("account", to_value(&Account { user_id: user_id.to_string(), identity: identity.clone() }))?;
        self.may_create_identity = false;
        Ok(cert)
    }

    /// The primary signs an MLS device certificate for another device's leaf key (docs §1.5): only for a device in
    /// the last list this core signed, a known platform and a canonical key.
    #[cfg(feature = "mls")]
    pub fn sign_device_cert(&mut self, user_id: &str, device_id: &str, platform: &str, leaf_sig_key: &str, issued_at: u64, now: u64) -> Result<String> {
        use crate::mls::cert::{DeviceCert, PLATFORMS};
        let identity = self.identity_row()?.ok_or_else(companion)?;
        let memory = self.get::<super::ListMemory>("devlist:last")?.ok_or_else(|| invalid("Publish the device list first"))?;
        if memory.user_id != user_id || !memory.devices.iter().any(|id| id == device_id) { return Err(invalid("That device is not in the last device list this identity signed")); }
        if !PLATFORMS.contains(&platform) || platform == "bot" || platform == "mcp" { return Err(invalid("Unknown platform")); }
        if now > 0 && issued_at.abs_diff(now) > 10 * 60 * 1000 { return Err(invalid("The certificate time is not now")); }
        let leaf = unb64_32(leaf_sig_key)?;
        let key = ed25519_dalek::SigningKey::from_bytes(&identity.sign.0);
        let cert = DeviceCert::issue(&key, user_id, device_id, platform, &leaf, issued_at)?;
        String::from_utf8(cert.encode()).map_err(ChatError::storage)
    }

    // ---------- Succession ----------

    /// A companion about to become primary mints the identity it will publish (kept aside until the old primary's
    /// signed record arrives).
    pub fn succession_start(&mut self) -> Result<IdentityPub> {
        if self.account()?.is_none() { return Err(invalid("Only a companion device can take over as primary")); }
        if let Some(next) = self.get::<Identity>("identity-next")? { return Ok(next.public); }
        let next = crate::protocol::generate_identity();
        self.store.put("identity-next", to_value(&next))?;
        Ok(next.public)
    }

    /// The old primary signed `record` for the identity `succession_start` returned: this device now holds the
    /// account identity, remembering the key it succeeded so older certificates stay valid until `at`.
    pub fn succession_complete(&mut self, record: &Value, signature: &str) -> Result<IdentityPub> {
        let account = self.account()?.ok_or_else(|| invalid("Only a companion device can take over as primary"))?;
        let next = self.get::<Identity>("identity-next")?.ok_or_else(|| invalid("Start the succession first"))?;
        let record = Record::parse(record)?;
        if record.user_id != account.user_id || record.old_sign != account.identity.sign { return Err(invalid("The record does not continue from this account's identity")); }
        if record.new_sign != next.public.sign || record.new_dh != next.public.dh { return Err(invalid("The record is for another identity")); }
        record.verify(signature)?;
        let mut previous = self.own_previous()?;
        previous.push(PreviousKey { sign: record.old_sign.clone(), until: record.at });
        self.store.batch(vec![
            Write::Put("identity".into(), to_value(&next)), Write::Delete("identity-next".into()), Write::Delete("account".into()),
            Write::Delete("devlist:last".into()), Write::Put("own-previous".into(), to_value(&previous)),
        ])?;
        self.may_create_identity = false;
        Ok(next.public)
    }

    fn own_previous(&mut self) -> Result<Vec<PreviousKey>> { Ok(self.get::<Vec<PreviousKey>>("own-previous")?.unwrap_or_default()) }

    /// The primary signs the record handing the account to `new_sign`/`new_dh` (docs §5.1). Changes nothing here;
    /// `retire_identity` follows once the new primary has the record.
    pub fn sign_succession(&mut self, user_id: &str, published_sign: &str, new_sign: &str, new_dh: &str, at: u64) -> Result<Value> {
        let identity = self.identity_row()?.ok_or_else(companion)?;
        if identity.public.sign != published_sign { return Err(ChatError::coded("mismatch", "This device does not hold the account's published identity key")); }
        let record = Record::parse(&serde_json::json!({ "v": 1, "userId": user_id, "oldSign": published_sign, "newSign": new_sign, "newDh": new_dh, "at": at }))?;
        let signature = {
            use ed25519_dalek::Signer;
            b64(&ed25519_dalek::SigningKey::from_bytes(&identity.sign.0).sign(&record.bytes()).to_bytes())
        };
        Ok(record.json(&signature))
    }

    /// The old primary steps down: its identity secret and 1:1 state are deleted and it becomes a companion of the
    /// account under `new_identity`. Its device and MLS leaf keys stay.
    pub fn retire_identity(&mut self, user_id: &str, new_identity: &IdentityPub, at: u64) -> Result<()> {
        let identity = self.identity_row()?.ok_or_else(companion)?;
        if !user_id_ok(user_id) || !is_key_b64(&new_identity.sign) || !is_key_b64(&new_identity.dh) || same_identity(&identity.public, new_identity) { return Err(invalid("Invalid new identity")); }
        for prefix in ["sessions:", "opk:", "claim:", "claims:"] { self.store.delete_prefix(prefix)?; }
        let mut previous = self.own_previous()?;
        previous.push(PreviousKey { sign: identity.public.sign.clone(), until: at });
        self.pending.clear();
        self.pending_order.clear();
        self.store.batch(vec![
            Write::Delete("identity".into()), Write::Delete("spk".into()), Write::Delete("opk-next".into()), Write::Delete("devlist:last".into()),
            Write::Put("account".into(), to_value(&Account { user_id: user_id.to_string(), identity: new_identity.clone() })),
            Write::Put("own-previous".into(), to_value(&previous)),
        ])?;
        self.may_create_identity = false;
        Ok(())
    }

    /// A contact moved on: follows the signed chain from the pinned identity and moves the pin, keeping
    /// `verified` and remembering each earlier key as a predecessor (docs §5.3). Call it before `note_peer` with
    /// the identity the server now serves. No chain from the pin, no change.
    pub fn accept_succession(&mut self, contact: &str, records: &[Value]) -> Result<PeerRecord> {
        let known = self.peer(contact)?.ok_or_else(|| invalid("No pinned identity for that contact"))?;
        if known.changed || known.blocked { return Err(invalid("That contact's code changed and is waiting for review")); }
        let chain = succession::follow(&known.identity.sign, contact, records)?;
        let last = chain.last().expect("non-empty");
        let mut previous = known.previous.clone();
        for record in &chain { previous.push(PreviousKey { sign: record.old_sign.clone(), until: record.at }); }
        let record = PeerRecord { identity: IdentityPub { dh: last.new_dh.clone(), sign: last.new_sign.clone() }, verified: known.verified, changed: false, blocked: false, previous };
        // The 1:1 sessions were with the old identity: the next message opens a fresh one.
        self.store.batch(vec![Write::Put(format!("peer:{contact}"), to_value(&record)), Write::Delete(format!("sessions:{contact}"))])?;
        Ok(record)
    }

    // ---------- Pins ----------

    /// Every pinned contact whose code is settled (not changed or waiting for review), for a new device.
    pub fn export_pins(&mut self) -> Result<Vec<PinExport>> {
        let mut out = Vec::new();
        for (key, value) in self.store.scan("peer:")? {
            let record: PeerRecord = from_value(value)?;
            if record.changed || record.blocked { continue; }
            out.push(PinExport { contact: key["peer:".len()..].to_string(), identity: record.identity, verified: record.verified, previous: record.previous });
        }
        Ok(out)
    }

    /// Creates pins where none exists (never overwrites one); returns how many were created.
    pub fn import_pins(&mut self, pins: &[PinExport]) -> Result<usize> {
        if pins.len() > MAX_PINS { return Err(invalid("Too many pins")); }
        let mut writes = Vec::new();
        for pin in pins {
            if !user_id_ok(&pin.contact) || !is_key_b64(&pin.identity.sign) || !is_key_b64(&pin.identity.dh) || pin.previous.len() > succession::MAX_CHAIN { return Err(invalid("Invalid pin")); }
            unb64_32(&pin.identity.sign)?;
            unb64_32(&pin.identity.dh)?;
            if self.peer(&pin.contact)?.is_some() { continue; }
            let record = PeerRecord { identity: pin.identity.clone(), verified: pin.verified, changed: false, blocked: false, previous: pin.previous.clone() };
            writes.push(Write::Put(format!("peer:{}", pin.contact), to_value(&record)));
        }
        let created = writes.len();
        if created > 0 { self.store.batch(writes)?; }
        Ok(created)
    }

    // ---------- Linking (docs §1) ----------

    fn link_state(&mut self, link_id: &str, now: u64) -> Result<LinkState> {
        let state = self.get::<LinkState>("link:state")?.filter(|s| s.link_id == link_id).ok_or_else(|| ChatError::coded("unknown-link", "No such device link on this device"))?;
        if now > 0 && state.at > 0 && now > state.at + LINK_TTL_MS {
            self.store.delete("link:state")?;
            return Err(ChatError::coded("expired", "This device link expired"));
        }
        Ok(state)
    }

    /// The new device: an ephemeral key and a link secret for `link_id` (from the server); returns the QR text.
    pub fn link_qr(&mut self, link_id: &str, now: u64) -> Result<String> {
        let id = crate::link::link_id_bytes(link_id)?;
        let eph = DhPair::generate();
        let secret = random_bytes::<16>();
        let state = LinkState { link_id: link_id.to_string(), role: "n".into(), secret: b64(&secret), eph_n: b64(&eph.public), eph: eph.clone(), eph_p: None, k_out: None, k_in: None, out: 0, inn: 0, at: now, code_mode: None };
        self.store.put("link:state", to_value(&state))?;
        Ok(crate::link::qr_text(&id, &eph.public, &secret))
    }

    /// The primary: checks the scanned QR, makes its ephemeral key and derives the keys and the code.
    pub fn link_accept(&mut self, qr: &str, now: u64) -> Result<LinkAccepted> {
        self.reject_companion()?;
        let (id, eph_n, secret) = crate::link::parse_qr(qr)?;
        let eph = DhPair::generate();
        let shared = dh(&eph, &eph_n)?;
        let keys = crate::link::derive(&shared.0, &secret, &id, &eph_n, &eph.public);
        let link_id = b64(&id);
        let state = LinkState { link_id: link_id.clone(), role: "p".into(), secret: b64(&secret), eph_n: b64(&eph_n), eph: eph.clone(), eph_p: Some(b64(&eph.public)), k_out: Some(b64(&keys.p2n)), k_in: Some(b64(&keys.n2p)), out: 0, inn: 0, at: now, code_mode: None };
        self.store.put("link:state", to_value(&state))?;
        Ok(LinkAccepted { link_id, eph: b64(&eph.public), code: keys.code })
    }

    /// The new device: the primary's ephemeral key arrived; derive the keys and the code.
    pub fn link_complete(&mut self, link_id: &str, eph_p: &str, now: u64) -> Result<String> {
        let mut state = self.link_state(link_id, now)?;
        if state.role != "n" || state.k_out.is_some() || state.code_mode.is_some() { return Err(invalid("This link is not waiting for an offer")); }
        let eph_p_bytes = unb64_32(eph_p)?;
        let shared = dh(&state.eph, &eph_p_bytes)?;
        let (id, eph_n, secret) = (crate::link::link_id_bytes(link_id)?, unb64_32(&state.eph_n)?, unb64(&state.secret, Some(16))?.try_into().expect("16"));
        let keys = crate::link::derive(&shared.0, &secret, &id, &eph_n, &eph_p_bytes);
        state.eph_p = Some(eph_p.to_string());
        state.k_out = Some(b64(&keys.n2p));
        state.k_in = Some(b64(&keys.p2n));
        self.store.put("link:state", to_value(&state))?;
        Ok(keys.code)
    }

    fn link_directions(state: &LinkState) -> (u8, u8) { if state.role == "n" { (crate::link::N2P, crate::link::P2N) } else { (crate::link::P2N, crate::link::N2P) } }

    pub fn link_seal(&mut self, link_id: &str, plaintext: &str, now: u64) -> Result<String> {
        let mut state = self.link_state(link_id, now)?;
        let key = unb64_32(state.k_out.as_deref().ok_or_else(|| invalid("The link has no keys yet"))?)?;
        let (out_dir, _) = Self::link_directions(&state);
        let sealed = crate::link::seal(&key, &crate::link::link_id_bytes(link_id)?, out_dir, state.out, plaintext.as_bytes())?;
        state.out += 1;
        self.store.put("link:state", to_value(&state))?;
        Ok(sealed)
    }

    pub fn link_open(&mut self, link_id: &str, data: &str, now: u64) -> Result<String> {
        let mut state = self.link_state(link_id, now)?;
        let key = unb64_32(state.k_in.as_deref().ok_or_else(|| invalid("The link has no keys yet"))?)?;
        let (_, in_dir) = Self::link_directions(&state);
        let plaintext = crate::link::open(&key, &crate::link::link_id_bytes(link_id)?, in_dir, state.inn, data)?;
        state.inn += 1;
        self.store.put("link:state", to_value(&state))?;
        String::from_utf8(plaintext).map_err(|_| invalid("A link message is UTF-8 text"))
    }

    // ----- Short-code rendezvous (docs §1.7) -----

    /// The new device commits to its ephemeral key for `link_id` before it can see the primary's. Returns the
    /// commitment to send to the server.
    pub fn link_commit(&mut self, link_id: &str, device_id: &str, now: u64) -> Result<String> {
        let id = crate::link::link_id_bytes(link_id)?;
        if !crate::devicelist::device_id_ok(device_id) { return Err(invalid("A device id is 22 base64url characters")); }
        let eph = DhPair::generate();
        let nonce = random_bytes::<16>();
        let commit = crate::link::commitment(&id, device_id, &eph.public, &nonce);
        let state = LinkState { link_id: link_id.to_string(), role: "n".into(), secret: b64(&[0u8; 16]), eph_n: b64(&eph.public), eph: eph.clone(), eph_p: None, k_out: None, k_in: None, out: 0, inn: 0, at: now,
            code_mode: Some(CodeMode { commit: Some(commit.clone()), nonce: Some(b64(&nonce)), device_n: device_id.to_string(), device_p: None }) };
        self.store.put("link:state", to_value(&state))?;
        Ok(commit)
    }

    /// The new device opens its commitment: the ephemeral key and nonce the primary checks. Sent once the primary's
    /// key has arrived (never before).
    pub fn link_reveal(&mut self, link_id: &str, eph_p: &str, now: u64) -> Result<(String, String)> {
        let mut state = self.link_state(link_id, now)?;
        let mode = state.code_mode.clone().filter(|_| state.role == "n" && state.k_out.is_none()).ok_or_else(|| invalid("This link is not waiting to be opened"))?;
        unb64_32(eph_p)?;
        // One-shot: once our key and nonce are shown, a different primary key would let a man in the middle grind the
        // 6-digit code. An identical repeat is harmless; anything else burns the link.
        match state.eph_p.as_deref() {
            Some(prev) if prev == eph_p => return Ok((state.eph_n.clone(), mode.nonce.expect("set at commit"))),
            Some(_) => {
                self.store.delete("link:state")?;
                return Err(ChatError::coded("auth", "The primary's key changed after this device revealed its own"));
            }
            None => {}
        }
        // The primary's key is fixed before ours is shown: remember it so `link_complete_code` cannot be handed another.
        state.eph_p = Some(eph_p.to_string());
        self.store.put("link:state", to_value(&state))?;
        Ok((state.eph_n.clone(), mode.nonce.expect("set at commit")))
    }

    /// The primary looked a code up: remembers the new device's commitment and device id and makes its own
    /// ephemeral key. Returns the key to offer. No keys exist yet.
    pub fn link_lookup(&mut self, link_id: &str, device_n: &str, commit: &str, device_p: &str, now: u64) -> Result<String> {
        self.reject_companion()?;
        crate::link::link_id_bytes(link_id)?;
        if !crate::devicelist::device_id_ok(device_n) || !crate::devicelist::device_id_ok(device_p) { return Err(invalid("A device id is 22 base64url characters")); }
        unb64_32(commit)?;
        let eph = DhPair::generate();
        let state = LinkState { link_id: link_id.to_string(), role: "p".into(), secret: b64(&[0u8; 16]), eph_n: String::new(), eph: eph.clone(), eph_p: Some(b64(&eph.public)), k_out: None, k_in: None, out: 0, inn: 0, at: now,
            code_mode: Some(CodeMode { commit: Some(commit.to_string()), nonce: None, device_n: device_n.to_string(), device_p: Some(device_p.to_string()) }) };
        self.store.put("link:state", to_value(&state))?;
        Ok(b64(&eph.public))
    }

    /// The primary checks the revealed key against the commitment it was given first, then derives keys and code.
    /// A mismatch ends the link (the code is burned).
    pub fn link_open_commitment(&mut self, link_id: &str, eph_n: &str, nonce: &str, now: u64) -> Result<String> {
        let mut state = self.link_state(link_id, now)?;
        let mode = state.code_mode.clone().filter(|m| state.role == "p" && state.k_out.is_none() && m.device_p.is_some()).ok_or_else(|| invalid("This link is not waiting for a reveal"))?;
        let (eph_n_bytes, nonce_bytes) = (unb64_32(eph_n)?, unb64(nonce, Some(16)).map_err(|_| invalid("Invalid nonce"))?.try_into().expect("16"));
        let id = crate::link::link_id_bytes(link_id)?;
        if crate::link::commitment(&id, &mode.device_n, &eph_n_bytes, &nonce_bytes) != mode.commit.clone().unwrap_or_default() {
            self.store.delete("link:state")?;
            return Err(ChatError::coded("auth", "The new device's key does not match what it committed to"));
        }
        let shared = dh(&state.eph, &eph_n_bytes)?;
        let own = unb64_32(state.eph_p.as_deref().expect("set at lookup"))?;
        let keys = crate::link::derive_code_mode(&shared.0, &id, &eph_n_bytes, &own, &mode.device_n, mode.device_p.as_deref().expect("checked"));
        state.eph_n = eph_n.to_string();
        state.k_out = Some(b64(&keys.p2n));
        state.k_in = Some(b64(&keys.n2p));
        self.store.put("link:state", to_value(&state))?;
        Ok(keys.code)
    }

    /// The new device: derive the keys and code from the key it was shown (and revealed against) and the primary's
    /// device id.
    pub fn link_complete_code(&mut self, link_id: &str, eph_p: &str, device_p: &str, now: u64) -> Result<String> {
        let mut state = self.link_state(link_id, now)?;
        let mut mode = state.code_mode.clone().filter(|_| state.role == "n" && state.k_out.is_none()).ok_or_else(|| invalid("This link is not waiting for a key"))?;
        if state.eph_p.as_deref() != Some(eph_p) { return Err(invalid("That is not the key this link revealed against")); }
        if !crate::devicelist::device_id_ok(device_p) { return Err(invalid("A device id is 22 base64url characters")); }
        let eph_p_bytes = unb64_32(eph_p)?;
        let shared = dh(&state.eph, &eph_p_bytes)?;
        let keys = crate::link::derive_code_mode(&shared.0, &crate::link::link_id_bytes(link_id)?, &unb64_32(&state.eph_n)?, &eph_p_bytes, &mode.device_n, device_p);
        mode.device_p = Some(device_p.to_string());
        state.code_mode = Some(mode);
        state.k_out = Some(b64(&keys.n2p));
        state.k_in = Some(b64(&keys.p2n));
        self.store.put("link:state", to_value(&state))?;
        Ok(keys.code)
    }

    pub fn link_end(&mut self, link_id: &str) -> Result<()> {
        if self.get::<LinkState>("link:state")?.is_some_and(|s| s.link_id == link_id) { self.store.delete("link:state")?; }
        Ok(())
    }
}
