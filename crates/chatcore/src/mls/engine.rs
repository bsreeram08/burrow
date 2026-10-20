//! The MLS engine (API.md, "Groups over MLS"): device setup, KeyPackages, groups, commits, messages, and the delivery-service
//! (DS) validator. One [`Groups`] serves one namespace of the account store: `mls` for this device's groups,
//! `mlsds` for a delivery service's public (secret-free) group state.
//!
//! Every entry point that changes group state runs the gate listed in API.md for it. `MlsGroup` / `PublicGroup`
//! values never outlive a call (they are loaded from storage each time), so no caller can merge, join or
//! process around the gates, and a failed call rolls its storage changes back.
#![cfg_attr(not(all(feature = "mls", feature = "ds")), allow(dead_code, unused_imports))]
use std::collections::{BTreeMap, HashMap, VecDeque};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::cert::{cert_of, key32, DeviceCert, Directory};
use super::persist::{tag_of_group_json, Persist, Written};
use super::policy::{capabilities, group_extensions, validate_context, validate_group_state, validate_staged, Kind, Roles};
use super::rows::{Change, Rows};
use super::storage::MlsStorage;
use super::{bounded, digest, limits, CS, ROLES_EXT};
use crate::error::{ChatError, Result};
use crate::store::{Store, Write};

/// OpenMLS provider over the engine's journaled storage.
#[derive(Default)]
pub struct Provider {
    crypto: RustCrypto,
    storage: MlsStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStorage;
    fn storage(&self) -> &MlsStorage { &self.storage }
    fn crypto(&self) -> &RustCrypto { &self.crypto }
    fn rand(&self) -> &RustCrypto { &self.crypto }
}

fn invalid(message: impl Into<String>) -> ChatError { ChatError::coded("invalid", &message.into()) }
fn mls<E: std::fmt::Debug>(error: E) -> ChatError { invalid(format!("MLS: {error:?}")) }
fn b64(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }
fn unb64(text: &str, what: &str) -> Result<Vec<u8>> { URL_SAFE_NO_PAD.decode(text).map_err(|_| ChatError::coded("malformed", &format!("{what} is not base64url"))) }
fn tls<T: openmls::prelude::tls_codec::Serialize>(value: &T) -> Result<Vec<u8>> { value.tls_serialize_detached().map_err(mls) }

/// Group ids are 1–64 bytes, base64url without padding on the API.
pub fn group_id(text: &str) -> Result<GroupId> {
    let bytes = unb64(text, "group id")?;
    if bytes.is_empty() || bytes.len() > 64 || b64(&bytes) != text { return Err(invalid("group ids are 1–64 bytes of base64url")); }
    Ok(GroupId::from_slice(&bytes))
}
fn group_text(id: &GroupId) -> String { b64(id.as_slice()) }
fn group_tag(id: &GroupId) -> String { tag_of_group_json(&serde_json::to_vec(id).expect("group id serializes")) }

pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .max_past_epochs(2)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 1000))
        .build()
}

/// Pinned account keys from the account store: `peer:<userId>` (the client's TOFU contacts) or
/// `mlsdsx:pin:<userId>` (the delivery service's device registry), plus this device's own account.
struct StoreDirectory<'a> {
    store: &'a mut dyn Store,
    prefix: &'static str,
    own: Option<(String, [u8; 32])>,
}

impl Directory for StoreDirectory<'_> {
    fn aik(&mut self, user_id: &str) -> Result<Option<[u8; 32]>> {
        if let Some((own, aik)) = &self.own {
            if own == user_id { return Ok(Some(*aik)); }
        }
        let Some(value) = self.store.get(&format!("{}{user_id}", self.prefix))? else { return Ok(None) };
        // A changed identity awaiting review is not a pin: fail closed until the user accepts it.
        if value.get("blocked").and_then(Value::as_bool) == Some(true) { return Ok(None); }
        let text = value.pointer("/identity/sign").or_else(|| value.get("aik")).and_then(Value::as_str);
        Ok(text.and_then(key32))
    }
}

/// This device in groups: its certificate and leaf signature key.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceRecord {
    cert: DeviceCert,
}

const DEVICE: &str = "mlsx:device";
const LEAF: &str = "mlsx:leaf";
fn pending_key(group: &GroupId) -> String { format!("mlsx:pending:{}", group_text(group)) }

/// What a commit or a join produced, to send to the delivery service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Outgoing {
    #[serde(rename = "groupId")]
    pub group_id: String,
    /// The commit (an MLS message, base64url). Submit it to the DS for `epoch`.
    pub commit: String,
    /// For added devices (Welcome, base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
    /// SHA-256 of the commit bytes (hex): resolves an ambiguous submit by finding it in the log.
    pub digest: String,
    /// The epoch the commit was built on.
    pub epoch: u64,
}

/// What a log entry is supposed to be. Handshake messages (commits) are public messages and application messages
/// are private ones; a caller that knows which it expects (the entry's `kind`) says so, and anything else is refused
/// before it is decrypted or staged. A private message that decrypts to a commit or proposal is refused regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    Application,
    Commit,
}

impl Expect {
    pub fn parse(text: &str) -> Result<Self> {
        match text { "application" => Ok(Self::Application), "commit" => Ok(Self::Commit), _ => Err(invalid("expect must be \"application\" or \"commit\"")) }
    }
    fn name(self) -> &'static str { match self { Self::Application => "application", Self::Commit => "commit" } }
    /// The kind a message's framing allows: public messages are handshakes, private ones application messages.
    fn of(protocol: &ProtocolMessage) -> Self { match protocol { ProtocolMessage::PublicMessage(_) => Self::Commit, ProtocolMessage::PrivateMessage(_) => Self::Application } }
    fn check(expect: Option<Self>, protocol: &ProtocolMessage) -> Result<Self> {
        let actual = Self::of(protocol);
        match expect {
            Some(wanted) if wanted != actual => Err(invalid(format!("expected a {} message, but this is a {} one", wanted.name(), actual.name()))),
            _ => Ok(actual),
        }
    }
}

/// Whether a commit's author can be held to what it contains. A member's commit carries a signature over its
/// content (proposals, path, group context) and two tags (the membership tag and the confirmation tag) that are NOT
/// covered by the signature and that only members can check: whoever relays the commit can flip them without
/// breaking the signature, so a commit rejected for its tags tells nothing about its author.
/// - `authenticated`: the signature verifies under the author's leaf key in this device's tree.
/// - `signed_content_invalid`: authenticated, and the signed content fails validation or policy (invalid proposals or
///   path, a non-admin's add, a bad roles change, ...): the author really signed it.
/// - `class()`: `signed-content` only for both of the above, else `tag` (a bad tag, a bad signature, anything
///   outside the signature). Only `signed-content` failures justify removing the author.
#[cfg(feature = "mls")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommitCheck {
    pub authenticated: bool,
    #[serde(rename = "signedContentInvalid")]
    pub signed_content_invalid: bool,
    pub class: &'static str,
    /// The author, when the signature verified.
    pub author: Option<MemberView>,
}

#[cfg(feature = "mls")]
impl CommitCheck {
    fn new(authenticated: bool, signed_content_invalid: bool, author: Option<MemberView>) -> Self {
        Self { authenticated, signed_content_invalid, class: if authenticated && signed_content_invalid { "signed-content" } else { "tag" }, author }
    }
    pub fn class(&self) -> &'static str { self.class }
}

/// A commit checked as the delivery service checks it: the signature and the signed content, without the tags.
#[cfg(feature = "mls")]
fn check_commit(provider: &Provider, group: &MlsGroup, protocol: ProtocolMessage, store: &mut dyn Store, cert: &DeviceCert) -> Result<CommitCheck> {
    let ProtocolMessage::PublicMessage(ref message) = protocol else { return Ok(CommitCheck::new(false, false, None)) };
    let claimed = message.sender().clone();
    // An external commit is signed with a key and credential the joiner puts in the commit itself: there is no leaf
    // in this tree to authenticate it against, so nobody can be named as its author (a forged certificate could name
    // any device). It is rejected like any other bad commit, but never attributed.
    if !matches!(claimed, Sender::Member(_)) { return Ok(CommitCheck::new(false, false, None)); }
    let roles = validate_context(group.extensions())?;
    let view = |sender: &Sender, _leaf: Option<&LeafNode>| match sender {
        Sender::Member(index) => Groups::member_view(group, &roles, *index),
        _ => None,
    };
    match group.public_group().process_message(provider.crypto(), protocol) {
        Ok(processed) => {
            let sender = processed.sender().clone();
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else { return Ok(CommitCheck::new(true, true, view(&sender, None))) };
            let author = view(&sender, staged.update_path_leaf_node());
            let mut directory = Groups::client_directory(store, cert);
            let policy = validate_staged(group.extensions(), group.members(), &sender, &staged, &mut directory);
            Ok(CommitCheck::new(true, policy.is_err(), author))
        }
        // Staging happens after the signature has been checked: the author signed content that does not stage.
        Err(PublicProcessMessageError::InvalidCommit(_)) => Ok(CommitCheck::new(true, true, view(&claimed, None))),
        // Anything earlier (framing, epoch, signature, credentials): not attributable to the named author.
        Err(_) => Ok(CommitCheck::new(false, false, None)),
    }
}

/// A commit built here and not yet resolved: the DS has neither accepted nor refused it as far as this device knows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCommit {
    /// SHA-256 of the commit bytes (hex): find it in the group's log to learn whether the DS sequenced it.
    pub digest: String,
    /// The epoch it was built on.
    pub epoch: u64,
}

/// Public state of a group after a change: what the DS and joiners need.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupView {
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub epoch: u64,
    /// Signed GroupInfo (base64url) for external joins.
    #[serde(rename = "groupInfo")]
    pub group_info: String,
    /// The ratchet tree (base64url): joiners verify it against the signed GroupInfo.
    pub tree: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberView {
    pub leaf: u32,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub platform: String,
    pub admin: bool,
}

/// One received message, decrypted and authenticated but not yet persisted (two-phase receive).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Processed {
    #[serde(rename = "pendingId")]
    pub pending_id: String,
    /// `application`, `commit` (another member's), or `own` (our own pending commit, found in the log).
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
    pub sender: MemberView,
    /// Epoch after processing.
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Delivery-service verdict on a submitted message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Submit {
    /// Sequenced. `epoch` is the group's epoch after it (a commit advances it).
    Accepted { epoch: u64, digest: String },
    /// Built on a stale epoch: process the log from your cursor and retry.
    Conflict { epoch: u64 },
}

struct Staged {
    changes: Vec<Change>,
    extra: Vec<Write>,
    /// A commit changes the membership: the group's gate entry is dropped when it is persisted.
    regate: Option<String>,
}

/// What a passed gate was based on. The entry is only reused while every user's pin (including "blocked" or
/// "unknown", as the directory reports it) and this device's certificate are exactly what they were; a pin that
/// was changed, removed or blocked in the store makes the next gated call validate the whole group again.
struct Verified {
    cert: Option<DeviceCert>,
    pins: Vec<(String, Option<[u8; 32]>)>,
}

impl Verified {
    fn of(cert: Option<DeviceCert>, directory: &mut dyn Directory, certs: &[(LeafNodeIndex, DeviceCert)]) -> Result<Self> {
        let users: std::collections::BTreeSet<&str> = certs.iter().map(|(_, c)| c.user_id.as_str()).collect();
        Ok(Self { cert, pins: Self::read(directory, users.into_iter())? })
    }
    fn read<'a>(directory: &mut dyn Directory, users: impl Iterator<Item = &'a str>) -> Result<Vec<(String, Option<[u8; 32]>)>> {
        users.map(|user| Ok((user.to_string(), directory.aik(user)?))).collect()
    }
    fn still_holds(&self, cert: Option<&DeviceCert>, directory: &mut dyn Directory) -> Result<bool> {
        if self.cert.as_ref() != cert { return Ok(false); }
        Ok(Self::read(directory, self.pins.iter().map(|(user, _)| user.as_str()))? == self.pins)
    }
}

const MAX_PENDING: usize = 256;
/// KeyPackages stay valid for 90 days (the delivery service keeps them until then).
pub const KEY_PACKAGE_LIFETIME_SECS: u64 = 90 * 86_400;

pub struct Groups {
    ns: &'static str,
    provider: Provider,
    persist: Persist,
    pending: BTreeMap<String, Staged>,
    pending_order: VecDeque<String>,
    next_pending: u64,
    /// External-join commits waiting for the DS (group id → staged state).
    external: BTreeMap<String, Staged>,
    /// Groups that passed whole-group validation in this process (the load gate); see [`Groups::gate`].
    verified: HashMap<String, Verified>,
    /// Set when a store write failed: the in-memory state ran ahead of disk, so the owner must reload.
    stale: bool,
    /// Rows and bytes the last flush wrote (benchmarks).
    pub last_written: Written,
}

impl Groups {
    /// Loads a namespace (`mls` or `mlsds`) from the account store.
    pub fn load(store: &mut dyn Store, ns: &'static str) -> Result<Self> {
        let (map, persist) = Persist::load(store, ns)?;
        let provider = Provider { crypto: RustCrypto::default(), storage: MlsStorage { values: std::sync::RwLock::new(Rows::from_map(map)) } };
        Ok(Self { ns, provider, persist, pending: BTreeMap::new(), pending_order: VecDeque::new(), next_pending: 0, external: BTreeMap::new(), verified: HashMap::new(), stale: false, last_written: Written::default() })
    }
    pub fn is_stale(&self) -> bool { self.stale }

    fn rows(&self) -> std::sync::RwLockWriteGuard<'_, Rows> { self.provider.storage.values.write().unwrap_or_else(|poisoned| poisoned.into_inner()) }

    fn flush(&mut self, store: &mut dyn Store, changes: &[Change], extra: Vec<Write>) -> Result<()> {
        let mut written = Written::default();
        let mut writes = self.persist.writes(changes, &mut written);
        written.rows += extra.len();
        writes.extend(extra);
        if writes.is_empty() { self.last_written = written; return Ok(()); }
        if let Err(error) = store.batch(writes) {
            self.stale = true;
            return Err(error);
        }
        self.last_written = written;
        Ok(())
    }

    /// Runs one state-changing call: success persists its changes (plus `extra` rows) in one store batch;
    /// failure rolls them back in memory.
    fn run<T>(&mut self, store: &mut dyn Store, work: impl FnOnce(&Provider, &mut dyn Store, &mut Vec<Write>) -> Result<T>) -> Result<T> {
        if self.stale { return Err(ChatError::storage("group state must be reloaded")); }
        let mut extra = Vec::new();
        match work(&self.provider, store, &mut extra) {
            Ok(value) => {
                let changes = self.rows().take_changes();
                self.flush(store, &changes, extra)?;
                Ok(value)
            }
            Err(error) => {
                self.rows().rollback();
                Err(error)
            }
        }
    }

    #[cfg(feature = "ds")]
    fn ds_directory(store: &mut dyn Store) -> StoreDirectory<'_> { StoreDirectory { store, prefix: "mlsdsx:pin:", own: None } }

    pub fn namespace(&self) -> &str { self.ns }
    pub fn row_count(&self) -> usize { self.rows().len() }
}

#[cfg(feature = "mls")]
impl Groups {
    // ---------- This device ----------

    fn device(store: &mut dyn Store) -> Result<DeviceCert> {
        let value = store.get(DEVICE)?.ok_or_else(|| invalid("this device has no group identity yet (mlsDevice)"))?;
        Ok(serde_json::from_value::<DeviceRecord>(value).map_err(ChatError::storage)?.cert)
    }
    fn signer(provider: &Provider, cert: &DeviceCert) -> Result<SignatureKeyPair> {
        let public = key32(&cert.leaf_sig_key).ok_or_else(|| ChatError::storage("malformed device record"))?;
        SignatureKeyPair::read(provider.storage(), &public, SignatureScheme::ED25519).ok_or_else(|| ChatError::storage("device signature key missing"))
    }
    fn credential(cert: &DeviceCert) -> Result<CredentialWithKey> {
        let public = key32(&cert.leaf_sig_key).ok_or_else(|| ChatError::storage("malformed device record"))?;
        Ok(CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: public.to_vec().into() })
    }
    fn client_directory<'a>(store: &'a mut dyn Store, own: &DeviceCert) -> StoreDirectory<'a> {
        StoreDirectory { store, prefix: "peer:", own: key32(&own.aik_sign).map(|aik| (own.user_id.clone(), aik)) }
    }
    /// The load gate, once per group per process (and again after a restore): the stored group must still pass
    /// whole-group validation under today's pins, and this device's own leaf must still be this device. A group
    /// that fails stays unusable (the others are unaffected) until its pins or state are repaired.
    fn gate(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<()> {
        let key = group_text(group);
        let cert = Self::device(store)?;
        let mut directory = Self::client_directory(store, &cert);
        if let Some(seen) = self.verified.get(&key) {
            if seen.still_holds(Some(&cert), &mut directory)? { return Ok(()); }
            self.verified.remove(&key);
        }
        let mls_group = Self::load_group(&self.provider, group)?;
        let (_, certs) = validate_group_state(mls_group.extensions(), mls_group.members(), &mut directory)?;
        if mls_group.is_active() {
            let own = certs.iter().find(|(index, _)| *index == mls_group.own_leaf_index()).ok_or_else(|| invalid("this device's leaf is missing from its group"))?;
            if own.1 != cert { return Err(invalid("this device's leaf does not match its certificate")); }
        }
        let seen = Verified::of(Some(cert.clone()), &mut directory, &certs)?;
        self.verified.insert(key, seen);
        Ok(())
    }

    /// The leaf signature key this device will use (created once). For signing the certificate outside the
    /// core (web AIK in WebCrypto): sign [`DeviceCert::tbs`] and pass the result to [`Groups::set_device_cert`].
    pub fn device_leaf(&mut self, store: &mut dyn Store) -> Result<String> {
        self.run(store, |provider, store, extra| {
            if let Some(cert) = store.get(DEVICE)? { return Ok(serde_json::from_value::<DeviceRecord>(cert).map_err(ChatError::storage)?.cert.leaf_sig_key); }
            if let Some(leaf) = store.get(LEAF)?.and_then(|v| v.get("leafSigKey").and_then(Value::as_str).map(str::to_string)) { return Ok(leaf); }
            let signer = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(mls)?;
            signer.store(provider.storage()).map_err(mls)?;
            let leaf = b64(signer.public());
            extra.push(Write::Put(LEAF.into(), json!({ "leafSigKey": leaf })));
            Ok(leaf)
        })
    }

    /// Installs this device's certificate (signed elsewhere). It must name the prepared leaf key and verify under
    /// `aik`, this core's own account key (the caller passes the pinned identity, never the certificate's claim).
    pub fn set_device_cert(&mut self, store: &mut dyn Store, cert_json: &str, aik: &[u8; 32]) -> Result<DeviceCert> {
        let cert = DeviceCert::decode(cert_json.as_bytes())?;
        let leaf = self.device_leaf(store)?;
        if cert.leaf_sig_key != leaf { return Err(invalid("certificate names another leaf key")); }
        cert.verify(aik, &key32(&leaf).ok_or_else(|| invalid("malformed leaf key"))?)?;
        if let Some(existing) = store.get(DEVICE)? {
            let existing = serde_json::from_value::<DeviceRecord>(existing).map_err(ChatError::storage)?.cert;
            if existing.user_id != cert.user_id || existing.device_id != cert.device_id { return Err(invalid("this device already has another group identity")); }
        }
        store.batch(vec![Write::Put(DEVICE.into(), serde_json::to_value(DeviceRecord { cert: cert.clone() }).expect("serializes")), Write::Delete(LEAF.into())])?;
        Ok(cert)
    }

    /// Creates (once) this device's group identity, certified by `aik` (this core's own account key).
    pub fn init_device(&mut self, store: &mut dyn Store, user_id: &str, device_id: &str, platform: &str, issued_at: u64, aik: &SigningKey) -> Result<DeviceCert> {
        if let Some(existing) = store.get(DEVICE)? {
            let cert = serde_json::from_value::<DeviceRecord>(existing).map_err(ChatError::storage)?.cert;
            if cert.user_id == user_id && cert.device_id == device_id { return Ok(cert); }
            return Err(invalid("this device already has another group identity"));
        }
        let leaf = key32(&self.device_leaf(store)?).ok_or_else(|| ChatError::storage("malformed leaf key"))?;
        let cert = DeviceCert::issue(aik, user_id, device_id, platform, &leaf, issued_at)?;
        self.set_device_cert(store, &String::from_utf8(cert.encode()).expect("utf8"), &aik.verifying_key().to_bytes())
    }

    /// KeyPackages for the server (MLS messages, base64url). Their private keys stay here until a Welcome uses them.
    pub fn key_packages(&mut self, store: &mut dyn Store, count: u32, last_resort: bool) -> Result<Vec<String>> {
        if count == 0 || count > 100 { return Err(invalid("request 1–100 KeyPackages")); }
        let cert = Self::device(store)?;
        self.run(store, |provider, _store, _extra| {
            let signer = Self::signer(provider, &cert)?;
            let credential = Self::credential(&cert)?;
            (0..count).map(|_| {
                let mut builder = KeyPackage::builder().leaf_node_capabilities(capabilities()).key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECS));
                if last_resort { builder = builder.mark_as_last_resort(); }
                let bundle = builder.build(CS, provider, &signer, credential.clone()).map_err(mls)?;
                Ok(b64(&tls(&MlsMessageOut::from(bundle.key_package().clone()))?))
            }).collect()
        })
    }

    // ---------- Groups ----------

    fn load_group(provider: &Provider, group: &GroupId) -> Result<MlsGroup> {
        MlsGroup::load(provider.storage(), group).map_err(|_| ChatError::storage("group state unreadable"))?.ok_or_else(|| ChatError::coded("unknown-group", "not a member of this group"))
    }

    fn view(provider: &Provider, group: &MlsGroup, signer: &SignatureKeyPair) -> Result<GroupView> {
        let info = group.export_group_info(provider.crypto(), signer, false).map_err(mls)?;
        Ok(GroupView { group_id: group_text(group.group_id()), epoch: group.epoch().as_u64(), group_info: b64(&tls(&info)?), tree: b64(&tls(&group.export_ratchet_tree())?) })
    }

    pub fn create(&mut self, store: &mut dyn Store, group: &GroupId, roles: &Roles) -> Result<GroupView> {
        let cert = Self::device(store)?;
        let extensions = group_extensions(roles)?;
        validate_context(&extensions)?;
        let creator_ok = match roles.kind { Kind::Dm => roles.dm.as_ref().is_some_and(|u| u.contains(&cert.user_id)), Kind::Group => roles.is_admin(&cert.user_id) };
        if !creator_ok { return Err(invalid("the creator must be an admin (or one of a DM's users)")); }
        self.run(store, |provider, _store, _extra| {
            if MlsGroup::load(provider.storage(), group).map_err(|_| ChatError::storage("group state unreadable"))?.is_some() { return Err(invalid("group already exists")); }
            let signer = Self::signer(provider, &cert)?;
            let created = MlsGroup::builder()
                .with_group_id(group.clone())
                .ciphersuite(CS)
                .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(false)
                .max_past_epochs(2)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 1000))
                .with_capabilities(capabilities())
                .with_group_context_extensions(extensions)
                .build(provider, &signer, Self::credential(&cert)?)
                .map_err(mls)?;
            Self::view(provider, &created, &signer)
        })
    }

    /// Builds one commit: adds (KeyPackages, base64url), removals (`userId`, `deviceId` pairs; a missing deviceId
    /// removes every device of that user), a roles change, a self-update. Validated by the shared validator before
    /// it leaves the device; stays pending until [`Groups::merge_own`] (DS accepted) or [`Groups::clear_own`].
    pub fn commit(&mut self, store: &mut dyn Store, group: &GroupId, adds: &[String], removes: &[(String, Option<String>)], roles: Option<&Roles>, update: bool) -> Result<Outgoing> {
        self.build_commit(store, group, adds, removes, roles, update, true)
    }

    /// Raw OpenMLS access as this device, for tests that play a malicious member: runs `work` with the provider,
    /// this device's signer and certificate, then discards every in-memory change it made.
    #[cfg(test)]
    pub(crate) fn scratch<T>(&mut self, store: &mut dyn Store, work: impl FnOnce(&Provider, &SignatureKeyPair, &DeviceCert) -> T) -> T {
        let cert = Self::device(store).expect("device");
        let signer = Self::signer(&self.provider, &cert).expect("signer");
        let out = work(&self.provider, &signer, &cert);
        self.rows().rollback();
        out
    }

    /// A commit that skips this device's own policy check: tests use it to play a malicious member.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn commit_unchecked(&mut self, store: &mut dyn Store, group: &GroupId, adds: &[String], removes: &[(String, Option<String>)], roles: Option<&Roles>, update: bool) -> Result<Outgoing> {
        self.build_commit(store, group, adds, removes, roles, update, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_commit(&mut self, store: &mut dyn Store, group: &GroupId, adds: &[String], removes: &[(String, Option<String>)], roles: Option<&Roles>, update: bool, check: bool) -> Result<Outgoing> {
        let cert = Self::device(store)?;
        self.gate(store, group)?;
        if check && adds.len() + removes.len() > limits::MAX_PROPOSALS { return Err(invalid("too many changes in one commit")); }
        self.run(store, |provider, store, extra| {
            let mut mls_group = Self::load_group(provider, group)?;
            if mls_group.pending_commit().is_some() { return Err(invalid("a commit is already pending: merge it or clear it first")); }
            let signer = Self::signer(provider, &cert)?;
            let mut packages = Vec::new();
            for text in adds {
                let bytes = unb64(text, "KeyPackage")?;
                bounded("KeyPackage", &bytes, limits::MAX_KEY_PACKAGE_BYTES)?;
                let message = MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(|_| ChatError::malformed())?;
                let MlsMessageBodyIn::KeyPackage(package) = message.extract() else { return Err(invalid("not a KeyPackage")) };
                packages.push(package.validate(provider.crypto(), ProtocolVersion::Mls10).map_err(mls)?);
            }
            let mut leaves = Vec::new();
            for (user, device) in removes {
                let before = leaves.len();
                for member in mls_group.members() {
                    if let Some(c) = cert_of(&member.credential) {
                        if &c.user_id == user && device.as_ref().is_none_or(|d| d == &c.device_id) { leaves.push(member.index); }
                    }
                }
                if leaves.len() == before { return Err(invalid("no such member")); }
            }
            let mut builder = mls_group.commit_builder().propose_adds(packages).propose_removals(leaves).force_self_update(update);
            if let Some(roles) = roles { builder = builder.propose_group_context_extensions(group_extensions(roles)?).map_err(mls)?; }
            let bundle = builder
                .load_psks(provider.storage())
                .map_err(mls)?
                .build(provider.rand(), provider.crypto(), &signer, |_| true)
                .map_err(mls)?
                .stage_commit(provider)
                .map_err(mls)?;
            let commit = tls(bundle.commit())?;
            let welcome = bundle.to_welcome_msg().map(|w| tls(&w)).transpose()?.map(|w| b64(&w));
            // The same validator receivers and the DS run, before anything leaves this device.
            let staged = mls_group.pending_commit().ok_or_else(|| invalid("no pending commit"))?;
            if check {
                let mut directory = Self::client_directory(store, &cert);
                validate_staged(mls_group.extensions(), mls_group.members(), &Sender::Member(mls_group.own_leaf_index()), staged, &mut directory)?;
            }
            let outgoing = Outgoing { group_id: group_text(group), commit: b64(&commit), welcome, digest: digest(&commit), epoch: mls_group.epoch().as_u64() };
            extra.push(Write::Put(pending_key(group), serde_json::to_value(PendingCommit { digest: outgoing.digest.clone(), epoch: outgoing.epoch }).expect("serializes")));
            Ok(outgoing)
        })
    }

    /// The DS accepted our commit: validate it once more and merge it. Also completes a pending external join.
    pub fn merge_own(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<GroupView> {
        let cert = Self::device(store)?;
        let external = self.external.remove(&group_text(group));
        if external.is_none() { self.gate(store, group)?; }
        self.run(store, |provider, store, extra| {
            if let Some(staged) = &external {
                let applied = provider.storage.values.write().map_err(|_| ChatError::storage("lock"))?.apply_staged(&staged.changes);
                if !applied { return Err(ChatError::transient("group state changed; join again")); }
            }
            let mut mls_group = Self::load_group(provider, group)?;
            let mut directory = Self::client_directory(store, &cert);
            if external.is_some() {
                // OpenMLS merges an external commit when it builds it, and join_external already ran the shared
                // validator on it; the DS accepting it makes it final. Last gate: the state we now hold.
                let (_, certs) = validate_group_state(mls_group.extensions(), mls_group.members(), &mut directory)?;
                if !certs.iter().any(|(index, c)| *index == mls_group.own_leaf_index() && c == &cert) { return Err(invalid("this device's leaf does not match its certificate")); }
                return Ok(());
            }
            let staged = mls_group.pending_commit().ok_or_else(|| invalid("no pending commit"))?;
            validate_staged(mls_group.extensions(), mls_group.members(), &Sender::Member(mls_group.own_leaf_index()), staged, &mut directory)?;
            mls_group.merge_pending_commit(provider).map_err(mls)?;
            extra.push(Write::Delete(pending_key(group)));
            Ok(())
        })?;
        self.verified.remove(&group_text(group));
        self.group_view(store, group)
    }

    /// The DS refused our commit (conflict): drop it. Process the log, then build it again.
    pub fn clear_own(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<()> {
        if self.external.remove(&group_text(group)).is_some() { return Ok(()); }
        self.run(store, |provider, _store, extra| {
            let mut mls_group = Self::load_group(provider, group)?;
            mls_group.clear_pending_commit(provider.storage()).map_err(mls)?;
            extra.push(Write::Delete(pending_key(group)));
            Ok(())
        })
    }

    /// Our pending commit, if any (to resolve an ambiguous submit against the log).
    pub fn pending_commit(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<Option<PendingCommit>> {
        store.get(&pending_key(group))?.map(|value| serde_json::from_value(value).map_err(ChatError::storage)).transpose()
    }

    pub fn group_view(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<GroupView> {
        let cert = Self::device(store)?;
        self.gate(store, group)?;
        let provider = &self.provider;
        let mls_group = Self::load_group(provider, group)?;
        Self::view(provider, &mls_group, &Self::signer(provider, &cert)?)
    }

    pub fn members(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<Vec<MemberView>> {
        self.gate(store, group)?;
        let mls_group = Self::load_group(&self.provider, group)?;
        let roles = validate_context(mls_group.extensions())?;
        Ok(mls_group.members().filter_map(|m| cert_of(&m.credential).map(|c| MemberView { leaf: m.index.u32(), admin: roles.is_admin(&c.user_id), user_id: c.user_id, device_id: c.device_id, platform: c.platform })).collect())
    }

    pub fn roles(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<Roles> {
        self.gate(store, group)?;
        validate_context(Self::load_group(&self.provider, group)?.extensions())
    }

    /// Joins from a Welcome and the (post-commit) ratchet tree, after checking every member's certificate,
    /// the roles and the size.
    pub fn join(&mut self, store: &mut dyn Store, welcome: &str, tree: &str) -> Result<GroupView> {
        let cert = Self::device(store)?;
        let (welcome, tree) = (unb64(welcome, "welcome")?, unb64(tree, "tree")?);
        bounded("welcome", &welcome, limits::MAX_WELCOME_BYTES)?;
        bounded("ratchet tree", &tree, limits::MAX_TREE_BYTES)?;
        let group = self.run(store, |provider, store, _extra| {
            let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome.as_slice()).map_err(|_| ChatError::malformed())?.extract() else { return Err(invalid("not a Welcome")) };
            let tree = RatchetTreeIn::tls_deserialize_exact(tree.as_slice()).map_err(|_| ChatError::malformed())?;
            let staged = StagedWelcome::new_from_welcome(provider, &join_config(), welcome, Some(tree)).map_err(mls)?;
            let mut directory = Self::client_directory(store, &cert);
            validate_group_state(staged.group_context().extensions(), staged.members(), &mut directory)?;
            let group = staged.into_group(provider).map_err(mls)?;
            Ok(group.group_id().clone())
        })?;
        self.verified.remove(&group_text(&group));
        self.group_view(store, &group)
    }

    /// External commit: public-channel self-join, this user's new device, or resync. Returns the commit for the
    /// DS; the group is kept (in memory) until [`Groups::merge_own`] after the DS accepts it.
    pub fn join_external(&mut self, store: &mut dyn Store, group_info: &str, tree: &str) -> Result<Outgoing> { self.external_commit(store, group_info, tree, true) }

    /// An external join that skips this device's own policy check: tests use it to play a malicious joiner.
    #[cfg(test)]
    pub(crate) fn join_external_unchecked(&mut self, store: &mut dyn Store, group_info: &str, tree: &str) -> Result<Outgoing> { self.external_commit(store, group_info, tree, false) }

    fn external_commit(&mut self, store: &mut dyn Store, group_info: &str, tree: &str, check: bool) -> Result<Outgoing> {
        if self.stale { return Err(ChatError::storage("group state must be reloaded")); }
        let cert = Self::device(store)?;
        let (info_bytes, tree_bytes) = (unb64(group_info, "group info")?, unb64(tree, "tree")?);
        bounded("group info", &info_bytes, limits::MAX_GROUP_INFO_BYTES)?;
        bounded("ratchet tree", &tree_bytes, limits::MAX_TREE_BYTES)?;
        let result = (|| -> Result<(Outgoing, GroupId)> {
            let provider = &self.provider;
            let MlsMessageBodyIn::GroupInfo(info) = MlsMessageIn::tls_deserialize_exact(info_bytes.as_slice()).map_err(|_| ChatError::malformed())?.extract() else { return Err(invalid("not a GroupInfo")) };
            let group = info.group_id().clone();
            if MlsGroup::load(provider.storage(), &group).map_err(|_| ChatError::storage("group state unreadable"))?.is_some() && !self.external.contains_key(&group_text(&group)) {
                // Resync replaces a broken local copy: the caller must have dropped it first (`forgetGroup`).
                return Err(invalid("already a member of this group on this device"));
            }
            let tree_in = RatchetTreeIn::tls_deserialize_exact(tree_bytes.as_slice()).map_err(|_| ChatError::malformed())?;
            let signer = Self::signer(provider, &cert)?;
            let (joined, bundle) = MlsGroup::external_commit_builder()
                .with_ratchet_tree(tree_in)
                .with_config(join_config())
                .build_group(provider, info, Self::credential(&cert)?)
                .map_err(mls)?
                .leaf_node_parameters(LeafNodeParameters::builder().with_capabilities(capabilities()).build())
                .load_psks(provider.storage())
                .map_err(mls)?
                .build(provider.rand(), provider.crypto(), &signer, |_| true)
                .map_err(mls)?
                .finalize(provider)
                .map_err(mls)?;
            let commit = tls(bundle.commit())?;
            // Our own external commit through the exact DS/client validator, against the pre-join public state.
            if check {
                let scratch = Provider::default();
                let mut directory = Self::client_directory(store, &cert);
                let before = ds_bootstrap(&scratch, &info_bytes, &tree_bytes, &mut directory)?;
                ds_check(&scratch, &before, &commit, &mut directory)?;
            }
            let epoch = joined.epoch().as_u64().saturating_sub(1);
            Ok((Outgoing { group_id: group_text(&group), commit: b64(&commit), welcome: None, digest: digest(&commit), epoch }, group))
        })();
        match result {
            Ok((outgoing, group)) => {
                let changes = self.rows().stage();
                self.external.insert(group_text(&group), Staged { changes, extra: Vec::new(), regate: None });
                Ok(outgoing)
            }
            Err(error) => { self.rows().rollback(); Err(error) }
        }
    }

    /// Drops this device's copy of a group (before a resync external join, or after leaving).
    pub fn forget_group(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<()> {
        self.verified.remove(&group_text(group));
        self.external.remove(&group_text(group));
        self.run(store, |provider, _store, extra| {
            let mut mls_group = Self::load_group(provider, group)?;
            mls_group.delete(provider.storage()).map_err(mls)?;
            extra.push(Write::Delete(pending_key(group)));
            Ok(())
        })
    }

    /// Encrypts an application payload (API.md §5) for the group's current epoch.
    pub fn encrypt(&mut self, store: &mut dyn Store, group: &GroupId, plaintext: &str) -> Result<String> {
        bounded("plaintext", plaintext.as_bytes(), limits::MAX_PLAINTEXT_BYTES)?;
        let cert = Self::device(store)?;
        self.gate(store, group)?;
        self.run(store, |provider, _store, _extra| {
            let mut mls_group = Self::load_group(provider, group)?;
            let signer = Self::signer(provider, &cert)?;
            let message = mls_group.create_message(provider, &signer, plaintext.as_bytes()).map_err(mls)?;
            Ok(b64(&tls(&message)?))
        })
    }

    fn member_view(mls_group: &MlsGroup, roles: &Roles, index: LeafNodeIndex) -> Option<MemberView> {
        let member = mls_group.member_at(index)?;
        let cert = cert_of(&member.credential)?;
        Some(MemberView { leaf: index.u32(), admin: roles.is_admin(&cert.user_id), user_id: cert.user_id, device_id: cert.device_id, platform: cert.platform })
    }

    /// Phase one of receiving a message from the group's log: authenticate, decrypt, validate (commits through
    /// the shared validator), without persisting. Store the result, then [`Groups::commit_pending`].
    /// A rejected commit at the current epoch is `poison` (message `poison <digest>: <reason>`); report it (M3).
    pub fn process(&mut self, store: &mut dyn Store, group: &GroupId, message: &str) -> Result<Processed> { self.process_as(store, group, message, None) }

    /// [`Groups::process`] for a caller that knows what the entry should be (`expect`): a mismatch is refused before
    /// anything is decrypted, merged or staged.
    /// What a commit at the group's current epoch is, judged only by what the delivery service can also see (the
    /// author's signature and the signed content, not the confirmation and membership tags, which need epoch
    /// secrets): see [`CommitCheck`]. Changes nothing. For resolving a reported commit: whether the author may be
    /// removed is decided here, on a member's own tree, never by the server.
    pub fn commit_author(&mut self, store: &mut dyn Store, group: &GroupId, message: &str) -> Result<CommitCheck> {
        if self.stale { return Err(ChatError::storage("group state must be reloaded")); }
        let bytes = unb64(message, "message")?;
        bounded("message", &bytes, limits::MAX_HANDSHAKE_BYTES)?;
        let protocol: ProtocolMessage = MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(|_| ChatError::malformed())?.try_into_protocol_message().map_err(|_| ChatError::malformed())?;
        Expect::check(Some(Expect::Commit), &protocol)?;
        let cert = Self::device(store)?;
        self.gate(store, group)?;
        let mls_group = Self::load_group(&self.provider, group)?;
        if protocol.epoch() != mls_group.epoch() { return Err(invalid("that commit is not for this group's current epoch")); }
        check_commit(&self.provider, &mls_group, protocol, store, &cert)
    }

    /// The `poison` error for a commit this device rejects, carrying the class of the failure.
    #[allow(clippy::too_many_arguments)]
    fn poisoned(provider: &Provider, group: &MlsGroup, again: ProtocolMessage, store: &mut dyn Store, cert: &DeviceCert, digest: &str, reason: String) -> ChatError {
        // If the check itself can't run, nothing is known about the author: not attributable, so class `tag`.
        let class = check_commit(provider, group, again, store, cert).map(|check| check.class()).unwrap_or("tag");
        ChatError::coded("poison", &format!("poison {digest}: {reason}")).with_class(class)
    }

    pub fn process_as(&mut self, store: &mut dyn Store, group: &GroupId, message: &str, expect: Option<Expect>) -> Result<Processed> {
        if self.stale { return Err(ChatError::storage("group state must be reloaded")); }
        let bytes = unb64(message, "message")?;
        bounded("message", &bytes, limits::MAX_HANDSHAKE_BYTES)?;
        let protocol: ProtocolMessage = MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(|_| ChatError::malformed())?.try_into_protocol_message().map_err(|_| ChatError::malformed())?;
        let framing = Expect::check(expect, &protocol)?;
        let cert = Self::device(store)?;
        self.gate(store, group)?;
        let message_digest = digest(&bytes);
        let own_pending = self.pending_commit(store, group)?.map(|pending| pending.digest);
        if own_pending.as_deref() == Some(message_digest.as_str()) {
            // Our own commit, sequenced by the DS: merge it (after the same validation).
            self.merge_own(store, group)?;
            let mls_group = Self::load_group(&self.provider, group)?;
            let roles = validate_context(mls_group.extensions())?;
            let sender = Self::member_view(&mls_group, &roles, mls_group.own_leaf_index()).ok_or_else(|| invalid("own leaf missing"))?;
            let id = self.stash(Staged { changes: Vec::new(), extra: Vec::new(), regate: None });
            return Ok(Processed { pending_id: id, kind: "own".into(), plaintext: None, sender, epoch: mls_group.epoch().as_u64(), digest: Some(message_digest) });
        }
        let result = (|| -> Result<(Processed, Vec<Write>)> {
            let provider = &self.provider;
            let is_commit = matches!(&protocol, ProtocolMessage::PublicMessage(public) if public.content_type() == ContentType::Commit);
            if matches!(protocol, ProtocolMessage::PrivateMessage(_)) { bounded("application message", &bytes, limits::MAX_APPLICATION_BYTES)?; }
            let mut mls_group = Self::load_group(provider, group)?;
            let (epoch, current) = (protocol.epoch().as_u64(), mls_group.epoch().as_u64());
            if is_commit && epoch < current { return Err(ChatError::replay()); }
            if epoch > current { return Err(ChatError::transient("message from a later epoch: process the log in order")); }
            // A rejected commit is `poison`, classified by what the author's signature covers (see CommitCheck).
            let public_copy = if is_commit { Some(MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(|_| ChatError::malformed())?.try_into_protocol_message().map_err(|_| ChatError::malformed())?) } else { None };
            let processed = match mls_group.process_message(provider, protocol) {
                Ok(processed) => processed,
                Err(error) if is_commit => return Err(Self::poisoned(provider, &mls_group, public_copy.expect("commit"), store, &cert, &message_digest, format!("{error:?}"))),
                Err(error) => return Err(classify(&error)),
            };
            let roles = validate_context(mls_group.extensions())?;
            let sender_index = match processed.sender() { Sender::Member(index) => Some(*index), _ => None };
            let sender_view = |g: &MlsGroup| sender_index.and_then(|i| Self::member_view(g, &roles, i));
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(app) => {
                    let sender = sender_view(&mls_group).ok_or_else(|| ChatError::coded("auth", "unknown sender"))?;
                    let text = String::from_utf8(app.into_bytes()).map_err(|_| ChatError::coded("invalid", "payload is not UTF-8"))?;
                    Ok((Processed { pending_id: String::new(), kind: "application".into(), plaintext: Some(text), sender, epoch: current, digest: None }, Vec::new()))
                }
                // Handshakes travel as public messages (the DS can only validate those): a commit hidden inside a
                // private message would skip the DS's checks, so it is never applied.
                ProcessedMessageContent::StagedCommitMessage(_) if framing == Expect::Application => Err(invalid("a commit must be a public message")),
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    let sender_kind = match sender_index { Some(i) => Sender::Member(i), None => Sender::NewMemberCommit };
                    let sender = match sender_index {
                        Some(_) => sender_view(&mls_group),
                        None => staged.update_path_leaf_node().and_then(|leaf| cert_of(leaf.credential())).map(|c| MemberView { leaf: u32::MAX, admin: roles.is_admin(&c.user_id), user_id: c.user_id, device_id: c.device_id, platform: c.platform }),
                    };
                    let Some(sender) = sender else { return Err(Self::poisoned(provider, &mls_group, public_copy.expect("commit"), store, &cert, &message_digest, "unknown committer".into())) };
                    let policy = {
                        let mut directory = Self::client_directory(store, &cert);
                        validate_staged(mls_group.extensions(), mls_group.members(), &sender_kind, &staged, &mut directory)
                    };
                    if let Err(error) = policy { return Err(Self::poisoned(provider, &mls_group, public_copy.expect("commit"), store, &cert, &message_digest, error.message)); }
                    if let Err(error) = mls_group.merge_staged_commit(provider, *staged) { return Err(Self::poisoned(provider, &mls_group, public_copy.expect("commit"), store, &cert, &message_digest, format!("{error:?}"))); }
                    // After the merge: is this device still a member?
                    let removed = !mls_group.is_active();
                    let kind = if removed { "removed" } else { "commit" };
                    Ok((Processed { pending_id: String::new(), kind: kind.into(), plaintext: None, sender, epoch: mls_group.epoch().as_u64(), digest: Some(message_digest.clone()) }, Vec::new()))
                }
                // Standalone proposals are never stored, so nothing can be committed by reference later.
                _ => Err(invalid("standalone proposals are not accepted")),
            }
        })();
        match result {
            Ok((mut processed, extra)) => {
                let changes = self.rows().stage();
                let regate = (processed.kind != "application").then(|| group_text(group));
                processed.pending_id = self.stash(Staged { changes, extra, regate });
                Ok(processed)
            }
            Err(error) => { self.rows().rollback(); Err(error) }
        }
    }

    fn stash(&mut self, staged: Staged) -> String {
        self.next_pending += 1;
        let id = format!("m{}", self.next_pending);
        self.pending.insert(id.clone(), staged);
        self.pending_order.push_back(id.clone());
        while self.pending_order.len() > MAX_PENDING {
            if let Some(old) = self.pending_order.pop_front() { self.pending.remove(&old); }
        }
        id
    }

    /// Phase two: persist what [`Groups::process`] staged. Refused (transient) if the group changed in between:
    /// process the message again.
    pub fn commit_pending(&mut self, store: &mut dyn Store, pending_id: &str) -> Result<()> {
        if self.stale { return Err(ChatError::storage("group state must be reloaded")); }
        let staged = self.pending.remove(pending_id).ok_or_else(|| ChatError::transient("unknown or expired pending message"))?;
        self.pending_order.retain(|id| id != pending_id);
        if !self.rows().apply_staged(&staged.changes) { return Err(ChatError::transient("group state changed; process the message again")); }
        let changes = self.rows().take_changes();
        if let Some(group) = &staged.regate { self.verified.remove(group); }
        self.flush(store, &changes, staged.extra)
    }

    pub fn abort(&mut self, pending_id: &str) {
        self.pending.remove(pending_id);
        self.pending_order.retain(|id| id != pending_id);
    }

}

/// A validated KeyPackage, as the delivery service records it (seconds since the Unix epoch for the lifetime).
#[cfg(feature = "ds")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyPackageInfo {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "leafSigKey")]
    pub leaf_sig_key: String,
    #[serde(rename = "aikSign")]
    pub aik_sign: String,
    #[serde(rename = "lastResort")]
    pub last_resort: bool,
    #[serde(rename = "notBefore")]
    pub not_before: u64,
    #[serde(rename = "notAfter")]
    pub not_after: u64,
}

/// A group's public membership and roles.
#[cfg(feature = "ds")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupMembers {
    pub epoch: u64,
    pub roles: Roles,
    pub members: Vec<MemberView>,
}

/// The delivery service's validator over public (secret-free) group state, namespace `mlsds`. It runs the exact
/// code members run (`validate_staged`) against the pre-commit state, so a commit it sequences is a commit every
/// member accepts (poison commits aside: see [`Ds::snapshot`]).
#[cfg(feature = "ds")]
pub struct Ds {
    groups: Groups,
}

#[cfg(feature = "ds")]
impl Ds {
    /// Loads the DS namespace from the store.
    pub fn new(store: &mut dyn Store) -> Result<Self> { Ok(Self { groups: Groups::load(store, "mlsds")? }) }
    pub fn is_stale(&self) -> bool { self.groups.is_stale() }
    pub fn row_count(&self) -> usize { self.groups.row_count() }
    pub fn last_written(&self) -> Written { self.groups.last_written }

    /// Records the account key the device registry holds for a user (M1). The DS validates against these.
    /// A pin never changes silently: re-pinning a different key is refused.
    pub fn pin(&mut self, store: &mut dyn Store, user_id: &str, aik: &str) -> Result<()> {
        if !super::cert::canonical_id(user_id) || key32(aik).is_none() { return Err(invalid("invalid user id or account key")); }
        let key = format!("mlsdsx:pin:{user_id}");
        if let Some(existing) = store.get(&key)? {
            if existing.get("aik").and_then(Value::as_str) != Some(aik) { return Err(invalid("this user is already pinned to another account key")); }
            return Ok(());
        }
        store.put(&key, json!({ "aik": aik }))
    }

    /// Starts tracking a group from the creator's GroupInfo and tree (validated like a Welcome).
    pub fn create(&mut self, store: &mut dyn Store, group_info: &str, tree: &str) -> Result<Value> {
        let (info, tree) = (unb64(group_info, "group info")?, unb64(tree, "tree")?);
        let value = self.groups.run(store, |provider, store, _extra| {
            let mut directory = Groups::ds_directory(store);
            let public = ds_bootstrap(provider, &info, &tree, &mut directory)?;
            Ok(json!({ "groupId": group_text(public.group_id()), "epoch": public.group_context().epoch().as_u64() }))
        })?;
        Ok(value)
    }

    /// Once per group per process: the stored public state must still pass whole-group validation.
    fn gate(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<()> {
        let key = group_text(group);
        let mut directory = Groups::ds_directory(store);
        if let Some(seen) = self.groups.verified.get(&key) {
            if seen.still_holds(None, &mut directory)? { return Ok(()); }
            self.groups.verified.remove(&key);
        }
        let public = Self::public(&self.groups.provider, group)?;
        let (_, certs) = validate_group_state(public.group_context().extensions(), public.members(), &mut directory)?;
        let seen = Verified::of(None, &mut directory, &certs)?;
        self.groups.verified.insert(key, seen);
        Ok(())
    }

    fn public(provider: &Provider, group: &GroupId) -> Result<PublicGroup> {
        PublicGroup::load(provider.storage(), group).map_err(|_| ChatError::storage("group state unreadable"))?.ok_or_else(|| ChatError::coded("unknown-group", "unknown group"))
    }

    /// Sequences one message: commits must target the current epoch and pass the shared validator (then the
    /// public state advances); application messages must target the current epoch. Standalone proposals refused.
    pub fn submit(&mut self, store: &mut dyn Store, group: &GroupId, message: &str) -> Result<Submit> { self.submit_as(store, group, message, None) }

    /// [`Ds::submit`] for a caller that knows what the message should be: an `application` submission must be a
    /// private message and a `commit` one a public message, else it is refused (not a conflict, not sequenced).
    pub fn submit_as(&mut self, store: &mut dyn Store, group: &GroupId, message: &str, expect: Option<Expect>) -> Result<Submit> {
        let bytes = unb64(message, "message")?;
        bounded("message", &bytes, limits::MAX_HANDSHAKE_BYTES)?;
        self.gate(store, group)?;
        let before = self.epoch(group)?;
        let verdict = self.groups.run(store, |provider, store, _extra| {
            let public = Self::public(provider, group)?;
            let mut directory = Groups::ds_directory(store);
            ds_submit(provider, public, &bytes, expect, &mut directory)
        })?;
        // A sequenced commit may have added users whose pins the entry doesn't cover.
        if matches!(verdict, Submit::Accepted { epoch, .. } if epoch != before) { self.groups.verified.remove(&group_text(group)); }
        Ok(verdict)
    }

    /// The group's whole public state (to keep before sequencing a commit; restore if members report poison).
    pub fn snapshot(&mut self, group: &GroupId) -> Result<String> {
        let tag = group_tag(group);
        let rows = self.groups.rows().entries(|key| super::persist::group_tag_of_key(key).as_deref() == Some(tag.as_str()));
        if rows.is_empty() { return Err(ChatError::coded("unknown-group", "unknown group")); }
        let list: Vec<Value> = rows.iter().map(|(k, v)| json!([b64(k), b64(v)])).collect();
        Ok(b64(serde_json::to_string(&json!({ "v": 1, "group": group_text(group), "rows": list })).expect("json").as_bytes()))
    }

    /// Replaces the group's public state with a snapshot (poison-commit rollback), after validating it.
    pub fn restore(&mut self, store: &mut dyn Store, group: &GroupId, snapshot: &str) -> Result<Value> {
        let bytes = unb64(snapshot, "snapshot")?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid("malformed snapshot"))?;
        if value.get("v").and_then(Value::as_u64) != Some(1) || value.get("group").and_then(Value::as_str) != Some(group_text(group).as_str()) { return Err(invalid("snapshot of another group")); }
        let tag = group_tag(group);
        let mut entries = Vec::new();
        for item in value.get("rows").and_then(Value::as_array).ok_or_else(|| invalid("malformed snapshot"))? {
            let pair = item.as_array().filter(|p| p.len() == 2).ok_or_else(|| invalid("malformed snapshot"))?;
            let key = unb64(pair[0].as_str().unwrap_or(""), "snapshot key")?;
            let val = unb64(pair[1].as_str().unwrap_or(""), "snapshot value")?;
            if super::persist::group_tag_of_key(&key).as_deref() != Some(tag.as_str()) { return Err(invalid("snapshot row of another group")); }
            entries.push((key, val));
        }
        self.groups.verified.remove(&group_text(group));
        let value = self.groups.run(store, |provider, store, _extra| {
            {
                let mut rows = provider.storage.values.write().map_err(|_| ChatError::storage("lock"))?;
                for (key, _) in rows.entries(|key| super::persist::group_tag_of_key(key).as_deref() == Some(tag.as_str())) { rows.remove(&key); }
                for (key, val) in entries { rows.insert(key, val); }
            }
            let public = Self::public(provider, group).map_err(|_| invalid("snapshot unreadable"))?;
            let mut directory = Groups::ds_directory(store);
            validate_group_state(public.group_context().extensions(), public.members(), &mut directory)?;
            Ok(json!({ "groupId": group_text(group), "epoch": public.group_context().epoch().as_u64() }))
        })?;
        Ok(value)
    }

    /// What the DS learns from a KeyPackage it is asked to store: validated (signature, lifetime, capabilities) and
    /// its certificate checked under the pinned account key of its user.
    pub fn key_package(&mut self, store: &mut dyn Store, text: &str) -> Result<KeyPackageInfo> {
        let bytes = unb64(text, "KeyPackage")?;
        bounded("KeyPackage", &bytes, limits::MAX_KEY_PACKAGE_BYTES)?;
        let MlsMessageBodyIn::KeyPackage(package) = MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(|_| ChatError::malformed())?.extract() else { return Err(invalid("not a KeyPackage")) };
        let package = package.validate(self.groups.provider.crypto(), ProtocolVersion::Mls10).map_err(mls)?;
        let leaf = package.leaf_node();
        if !leaf.capabilities().extensions().contains(&ExtensionType::Unknown(ROLES_EXT)) { return Err(invalid("the KeyPackage does not support the roles extension")); }
        let mut directory = Groups::ds_directory(store);
        let cert = super::cert::verify_credential(&mut directory, leaf.credential(), leaf.signature_key().as_slice())?;
        let lifetime = package.life_time();
        Ok(KeyPackageInfo { user_id: cert.user_id, device_id: cert.device_id, leaf_sig_key: cert.leaf_sig_key, aik_sign: cert.aik_sign, last_resort: package.last_resort(), not_before: lifetime.not_before(), not_after: lifetime.not_after() })
    }

    /// Who is in the group right now, and its roles (public state: the DS mirrors this for fan-out).
    pub fn members(&mut self, store: &mut dyn Store, group: &GroupId) -> Result<GroupMembers> {
        self.gate(store, group)?;
        let public = Self::public(&self.groups.provider, group)?;
        let roles = validate_context(public.group_context().extensions())?;
        let members = public.members().filter_map(|m| cert_of(&m.credential).map(|c| MemberView { leaf: m.index.u32(), admin: roles.is_admin(&c.user_id), user_id: c.user_id, device_id: c.device_id, platform: c.platform })).collect();
        Ok(GroupMembers { epoch: public.group_context().epoch().as_u64(), roles, members })
    }

    pub fn epoch(&mut self, group: &GroupId) -> Result<u64> { Ok(Self::public(&self.groups.provider, group)?.group_context().epoch().as_u64()) }

    pub fn tree(&mut self, group: &GroupId) -> Result<String> { Ok(b64(&tls(&Self::public(&self.groups.provider, group)?.export_ratchet_tree())?)) }
}

/// DS bootstrap: a PublicGroup from a GroupInfo and tree, validated like a Welcome (certificates, roles, size).
fn ds_bootstrap(provider: &Provider, info: &[u8], tree: &[u8], directory: &mut dyn Directory) -> Result<PublicGroup> {
    bounded("group info", info, limits::MAX_GROUP_INFO_BYTES)?;
    bounded("ratchet tree", tree, limits::MAX_TREE_BYTES)?;
    let MlsMessageBodyIn::GroupInfo(info) = MlsMessageIn::tls_deserialize_exact(info).map_err(|_| ChatError::malformed())?.extract() else { return Err(invalid("not a GroupInfo")) };
    if PublicGroup::load(provider.storage(), info.group_id()).map_err(|_| ChatError::storage("group state unreadable"))?.is_some() { return Err(invalid("group already tracked")); }
    let tree = RatchetTreeIn::tls_deserialize_exact(tree).map_err(|_| ChatError::malformed())?;
    let (public, _) = PublicGroup::from_external(provider.crypto(), provider.storage(), tree, info, ProposalStore::new()).map_err(mls)?;
    validate_group_state(public.group_context().extensions(), public.members(), directory)?;
    Ok(public)
}

/// The DS commit check without persisting (used by a joiner on its own external commit).
fn ds_check(provider: &Provider, public: &PublicGroup, commit: &[u8], directory: &mut dyn Directory) -> Result<()> {
    let protocol = MlsMessageIn::tls_deserialize_exact(commit).map_err(|_| ChatError::malformed())?.try_into_protocol_message().map_err(|_| ChatError::malformed())?;
    let ProtocolMessage::PublicMessage(message) = protocol else { return Err(invalid("commits are public messages")) };
    let processed = public.process_message(provider.crypto(), *message).map_err(mls)?;
    let sender = processed.sender().clone();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else { return Err(invalid("not a commit")) };
    validate_staged(public.group_context().extensions(), public.members(), &sender, &staged, directory)
}

fn ds_submit(provider: &Provider, mut public: PublicGroup, bytes: &[u8], expect: Option<Expect>, directory: &mut dyn Directory) -> Result<Submit> {
    bounded("message", bytes, limits::MAX_HANDSHAKE_BYTES)?;
    let protocol = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| ChatError::malformed())?.try_into_protocol_message().map_err(|_| ChatError::malformed())?;
    // The DS can't look inside a private message, but it can insist on the framing the submission is for.
    Expect::check(expect, &protocol)?;
    let current = public.group_context().epoch().as_u64();
    if protocol.epoch().as_u64() != current { return Ok(Submit::Conflict { epoch: current }); }
    match protocol {
        ProtocolMessage::PublicMessage(message) => {
            let processed = public.process_message(provider.crypto(), *message).map_err(|e| invalid(format!("rejected: {e:?}")))?;
            let sender = processed.sender().clone();
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else { return Err(invalid("only commits may be public messages")) };
            validate_staged(public.group_context().extensions(), public.members(), &sender, &staged, directory)?;
            public.merge_commit(provider.storage(), *staged).map_err(mls)?;
            Ok(Submit::Accepted { epoch: public.group_context().epoch().as_u64(), digest: digest(bytes) })
        }
        ProtocolMessage::PrivateMessage(_) => {
            bounded("application message", bytes, limits::MAX_APPLICATION_BYTES)?;
            Ok(Submit::Accepted { epoch: current, digest: digest(bytes) })
        }
    }
}

/// Disposition codes for a rejected application message (commits are `poison`).
fn classify(error: &ProcessMessageError<super::storage::MlsStorageError>) -> ChatError {
    use openmls::framing::errors::{MessageDecryptionError as D, SecretTreeError as S};
    use openmls::prelude::ValidationError as V;
    match error {
        ProcessMessageError::ValidationError(V::WrongEpoch | V::NoPastEpochData) => ChatError::replay(),
        ProcessMessageError::ValidationError(V::UnableToDecrypt(D::SecretTreeError(S::SecretReuseError | S::TooDistantInThePast | S::RatchetTypeError))) => ChatError::replay(),
        ProcessMessageError::ValidationError(V::UnableToDecrypt(D::SecretTreeError(S::TooDistantInTheFuture))) => ChatError::coded("skip-limit", "message too far ahead"),
        ProcessMessageError::ValidationError(V::UnableToDecrypt(D::MalformedContent)) => ChatError::malformed(),
        ProcessMessageError::ValidationError(_) => ChatError::coded("auth", "message authentication failed"),
        other => ChatError::coded("auth", &format!("message rejected: {other:?}")),
    }
}
