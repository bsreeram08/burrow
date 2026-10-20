//! What Dart sees (see `lib/src/rust/api.dart`). Prekey payloads cross as JSON strings because the app
//! uploads them to the server as JSON unchanged; everything else is typed.
use chatcore::api as core;
use chatcore::protocol::IdentityPub;
use chatcore::{ChatError, EncryptOutcome};
use flutter_rust_bridge::frb;

/// A core failure. `code` is the web client's vocabulary (replay, malformed, auth, …); `None` is transient.
#[derive(Debug)]
pub struct CoreError {
    pub code: Option<String>,
    pub message: String,
}
impl From<ChatError> for CoreError {
    fn from(error: ChatError) -> Self { Self { code: error.code, message: error.message } }
}
type Result<T> = std::result::Result<T, CoreError>;

pub struct Identity {
    pub dh: String,
    pub sign: String,
}
impl From<IdentityPub> for Identity {
    fn from(value: IdentityPub) -> Self { Self { dh: value.dh, sign: value.sign } }
}
impl From<Identity> for IdentityPub {
    fn from(value: Identity) -> Self { Self { dh: value.dh, sign: value.sign } }
}

pub struct Decrypted {
    pub pending_id: String,
    pub plaintext_json: String,
    pub identity_changed: bool,
    pub first_contact: bool,
    pub identity: Option<Identity>,
}

pub struct Safety {
    pub number: String,
    pub verified: bool,
    pub changed: bool,
    pub blocked: bool,
}

pub struct SessionInfo {
    pub sid: String,
    pub started_at: u64,
}

/// Opens the account's key database, sealed with `store_key` (32 bytes from the platform keystore).
/// `expect_existing`: the keystore already held this key, so the database must exist (fails closed otherwise).
pub fn init(db_path: String, store_key: Vec<u8>, expect_existing: bool) -> Result<()> { Ok(core::init(db_path, store_key, expect_existing)?) }

pub fn identity() -> Result<Identity> { Ok(core::identity()?.into()) }

/// JSON of `{identity, rotated, signedPreKey}` (signal.js `prekeys()`).
pub fn prepare_prekeys(now_ms: u64) -> Result<String> {
    Ok(serde_json::to_string(&core::prepare_prekeys(now_ms)?).map_err(|error| CoreError { code: None, message: error.to_string() })?)
}

/// JSON array of `{id, key}` one-time prekeys to upload.
pub fn one_time_prekeys(count: u64) -> Result<String> {
    Ok(serde_json::to_string(&core::one_time_prekeys(count)?).map_err(|error| CoreError { code: None, message: error.to_string() })?)
}

/// `Some(envelope)`, or `None` when there is no sending session: fetch the bundle and call again with it.
pub fn encrypt_to(contact_id: String, plaintext_json: String, bundle_json: Option<String>) -> Result<Option<String>> {
    Ok(match core::encrypt_to(contact_id, plaintext_json, bundle_json)? {
        EncryptOutcome::Envelope(envelope) => Some(envelope),
        EncryptOutcome::NeedsBundle => None,
    })
}

pub fn decrypt_from(contact_id: String, envelope: String, published_identity: Option<Identity>) -> Result<Decrypted> {
    let decrypted = core::decrypt_from(contact_id, envelope, published_identity.map(Into::into))?;
    Ok(Decrypted {
        pending_id: decrypted.pending_id,
        plaintext_json: decrypted.plaintext_json,
        identity_changed: decrypted.identity_changed,
        first_contact: decrypted.first_contact,
        identity: decrypted.identity.map(Into::into),
    })
}

/// After the message is stored. `rotate` when the payload was the peer's `{type:'rotate'}` session reset.
pub fn commit(pending_id: String, rotate: bool) -> Result<bool> { Ok(core::commit(pending_id, rotate)?) }
pub fn abort(pending_id: String) -> Result<()> { Ok(core::abort(pending_id)?) }

pub fn note_peer(contact_id: String, identity: Identity) -> Result<()> { Ok(core::note_peer(contact_id, identity.into())?) }

pub fn safety(my_username: String, contact_id: String, their_username: String) -> Result<Option<Safety>> {
    Ok(core::safety(my_username, contact_id, their_username)?.map(|value| Safety { number: value.number, verified: value.verified, changed: value.changed, blocked: value.blocked }))
}
/// The pinned identity of a contact (or a group member pinned on first use), with its review state.
pub struct Peer {
    pub identity: Identity,
    pub verified: bool,
    pub changed: bool,
    pub blocked: bool,
}
pub fn peer(contact_id: String) -> Result<Option<Peer>> {
    Ok(core::peer(contact_id)?.map(|p| Peer { identity: p.identity.into(), verified: p.verified, changed: p.changed, blocked: p.blocked }))
}
/// Accept / verify only the identity the user was shown: `mismatch` if the pinned one changed since.
pub fn accept_change_for(contact_id: String, identity: Identity) -> Result<()> { Ok(core::accept_change_for(contact_id, identity.into())?) }
pub fn set_verified_for(contact_id: String, verified: bool, identity: Identity) -> Result<()> { Ok(core::set_verified_for(contact_id, verified, identity.into())?) }
pub fn set_verified(contact_id: String, verified: bool) -> Result<()> { Ok(core::set_verified(contact_id, verified)?) }
pub fn accept_change(contact_id: String) -> Result<()> { Ok(core::accept_change(contact_id)?) }
pub fn forget(contact_id: String) -> Result<()> { Ok(core::forget(contact_id)?) }

// ---- Chat key rotation ----
pub fn rotate(contact_id: String) -> Result<()> { Ok(core::rotate(contact_id)?) }
pub fn session_info(contact_id: String) -> Result<Option<SessionInfo>> {
    Ok(core::session_info(contact_id)?.map(|value| SessionInfo { sid: value.sid, started_at: value.started_at }))
}
pub fn reset_identity() -> Result<()> { Ok(core::reset_identity()?) }

/// Signs the account's next DeviceList (JSON in devices.js's shape) and one certificate per device: chatcore
/// validates the list (devices.js validateList), checks it names `user_id` and that `published_sign` (the
/// identity the server publishes for the account) is this core's own key, and signs only the canonical bytes it
/// builds. JSON of `{signature, certs: {deviceId: signature}}`.
/// `head_list_json` / `head_signature`: the list the server serves now and its signature, so the core can follow
/// lists another device of the account signed (it trusts them only if they verify under its own key).
pub fn sign_device_list(user_id: String, published_sign: String, list_json: String, head_list_json: Option<String>, head_signature: Option<String>) -> Result<String> {
    let head = match (head_list_json, head_signature) {
        (Some(list_json), Some(signature)) => Some(chatcore::devicelist::ListHead { list_json, signature }),
        _ => None,
    };
    let signed = core::sign_device_list(user_id, published_sign, list_json, head)?;
    serde_json::to_string(&signed).map_err(|error| CoreError { code: None, message: error.to_string() })
}

/// The seed of the device-meta sealing key: the identity key's signature over the fixed devicemeta label and
/// `user_id` only (devices.js deviceMetaKey). A secret: keep it on the device.
pub fn device_meta_signature(user_id: String) -> Result<String> { Ok(core::device_meta_signature(user_id)?) }

/// Signs a device-claim challenge with the account identity key (docs/devices.md). The core builds the
/// domain-separated bytes itself, so this is never a general signing oracle.
pub fn prove_identity(user_id: String, device_id: String, challenge: String) -> Result<String> { Ok(core::prove_identity(user_id, device_id, challenge)?) }
#[frb(sync)]
pub fn rotation_interval(mine: u64, theirs: u64) -> u64 { core::rotation_interval(mine, theirs) }

// ---- Call verification (verify.js) ----
#[frb(sync)]
pub fn sas_new_nonce() -> String { core::sas_new_nonce() }
#[frb(sync)]
pub fn sas_commitment(nonce: String) -> Result<String> { Ok(core::sas_commitment(nonce)?) }
#[frb(sync)]
pub fn sas_check_reveal(peer_commitment: String, peer_nonce: String) -> bool { core::sas_check_reveal(peer_commitment, peer_nonce) }
#[frb(sync)]
pub fn sas_code(local_sdp: String, remote_sdp: String, my_nonce: String, peer_nonce: String) -> Result<String> {
    Ok(core::sas_code(local_sdp, remote_sdp, my_nonce, peer_nonce)?)
}

// ---- Groups over MLS (crates/chatcore/API.md "Groups over MLS") ----
// Group ids, KeyPackages, Welcomes, ratchet trees, GroupInfos and messages are base64url strings. The MLS
// state lives in the same sealed key database as the 1:1 sessions (rows `mls:*` / `mlsx:*`).
use chatcore::api::{JoinPolicy, Kind, PayloadContext, Roles};

/// This device's group credential: a certificate for its leaf key, signed by the account identity key.
pub struct MlsDeviceCert {
    pub user_id: String,
    pub device_id: String,
    pub platform: String,
    pub leaf_sig_key: String,
    pub aik_sign: String,
    pub issued_at: u64,
}

pub enum MlsKind {
    Group,
    Dm,
}

pub enum MlsJoinPolicy {
    Open,
    Invite,
}

/// The group's `roles` extension: who administers it, who may add people, and for a DM its two users.
pub struct MlsRoles {
    pub kind: MlsKind,
    pub admins: Vec<String>,
    pub join_policy: MlsJoinPolicy,
    pub dm: Option<Vec<String>>,
}
impl From<Roles> for MlsRoles {
    fn from(value: Roles) -> Self {
        Self {
            kind: match value.kind { Kind::Group => MlsKind::Group, Kind::Dm => MlsKind::Dm },
            admins: value.admins,
            join_policy: match value.join_policy { JoinPolicy::Open => MlsJoinPolicy::Open, JoinPolicy::Invite => MlsJoinPolicy::Invite },
            dm: value.dm,
        }
    }
}
impl From<MlsRoles> for Roles {
    fn from(value: MlsRoles) -> Self {
        Self {
            v: 1,
            kind: match value.kind { MlsKind::Group => Kind::Group, MlsKind::Dm => Kind::Dm },
            admins: value.admins,
            join_policy: match value.join_policy { MlsJoinPolicy::Open => JoinPolicy::Open, MlsJoinPolicy::Invite => JoinPolicy::Invite },
            dm: value.dm,
        }
    }
}

/// Public state after a change: the signed GroupInfo and the ratchet tree, for the delivery service and joiners.
pub struct MlsGroupView {
    pub group_id: String,
    pub epoch: u64,
    pub group_info: String,
    pub tree: String,
}
impl From<chatcore::api::GroupView> for MlsGroupView {
    fn from(value: chatcore::api::GroupView) -> Self { Self { group_id: value.group_id, epoch: value.epoch, group_info: value.group_info, tree: value.tree } }
}

/// A commit to submit to the delivery service for `epoch`, with the Welcome for added devices.
pub struct MlsOutgoing {
    pub group_id: String,
    pub commit: String,
    pub welcome: Option<String>,
    pub digest: String,
    pub epoch: u64,
}
impl From<chatcore::api::Outgoing> for MlsOutgoing {
    fn from(value: chatcore::api::Outgoing) -> Self {
        Self { group_id: value.group_id, commit: value.commit, welcome: value.welcome, digest: value.digest, epoch: value.epoch }
    }
}

pub struct MlsPendingCommit {
    pub digest: String,
    pub epoch: u64,
}

pub struct MlsMember {
    pub leaf: u32,
    pub user_id: String,
    pub device_id: String,
    pub platform: String,
    pub admin: bool,
}
impl From<chatcore::api::MemberView> for MlsMember {
    fn from(value: chatcore::api::MemberView) -> Self {
        Self { leaf: value.leaf, user_id: value.user_id, device_id: value.device_id, platform: value.platform, admin: value.admin }
    }
}

/// One log entry, authenticated and decrypted but not persisted: store it, then `mls_receive_commit`.
/// `kind`: `application`, `commit` (another member's), `own` (our pending commit, found in the log), `removed`.
pub struct MlsProcessed {
    pub pending_id: String,
    pub kind: String,
    pub plaintext: Option<String>,
    pub sender: MlsMember,
    pub epoch: u64,
    pub digest: Option<String>,
}

/// What a log entry's kind says a message is: a refused mismatch is never decrypted or staged.
pub enum MlsExpect {
    Application,
    Commit,
}

/// One device to remove; every device of the user when `device_id` is `None`.
pub struct MlsRemoval {
    pub user_id: String,
    pub device_id: Option<String>,
}

pub fn mls_init_device(user_id: String, device_id: String, platform: String, issued_at_ms: u64) -> Result<MlsDeviceCert> {
    let cert = core::mls_init_device(user_id, device_id, platform, issued_at_ms)?;
    Ok(MlsDeviceCert { user_id: cert.user_id, device_id: cert.device_id, platform: cert.platform, leaf_sig_key: cert.leaf_sig_key, aik_sign: cert.aik_sign, issued_at: cert.issued_at })
}
/// `count` one-time KeyPackages (1-100), or one last-resort one.
pub fn mls_key_packages(count: u32, last_resort: bool) -> Result<Vec<String>> { Ok(core::mls_key_packages(count, last_resort)?) }
pub fn mls_create_group(group_id: String, roles: MlsRoles) -> Result<MlsGroupView> { Ok(core::mls_create_group(group_id, roles.into())?.into()) }
/// Builds a commit and keeps it pending: `mls_merge_own` once the delivery service accepted it, `mls_clear_own` on a conflict.
pub fn mls_commit(group_id: String, adds: Vec<String>, removes: Vec<MlsRemoval>, roles: Option<MlsRoles>, update: bool) -> Result<MlsOutgoing> {
    let removes = removes.into_iter().map(|r| core::Removal { user_id: r.user_id, device_id: r.device_id }).collect();
    Ok(core::mls_commit(group_id, adds, removes, roles.map(Into::into), update)?.into())
}
pub fn mls_merge_own(group_id: String) -> Result<MlsGroupView> { Ok(core::mls_merge_own(group_id)?.into()) }
pub fn mls_clear_own(group_id: String) -> Result<()> { Ok(core::mls_clear_own(group_id)?) }
pub fn mls_pending_commit(group_id: String) -> Result<Option<MlsPendingCommit>> {
    Ok(core::mls_pending_commit(group_id)?.map(|p| MlsPendingCommit { digest: p.digest, epoch: p.epoch }))
}
pub fn mls_join(welcome: String, tree: String) -> Result<MlsGroupView> { Ok(core::mls_join(welcome, tree)?.into()) }
pub fn mls_join_external(group_info: String, tree: String) -> Result<MlsOutgoing> { Ok(core::mls_join_external(group_info, tree)?.into()) }
pub fn mls_forget_group(group_id: String) -> Result<()> { Ok(core::mls_forget_group(group_id)?) }
pub fn mls_encrypt(group_id: String, plaintext: String) -> Result<String> { Ok(core::mls_encrypt(group_id, plaintext)?) }
/// `expect`: the log entry's kind (`app` → Application, `commit` → Commit), whenever it is known.
pub fn mls_receive(group_id: String, message: String, expect: Option<MlsExpect>) -> Result<MlsProcessed> {
    let expect = expect.map(|e| match e { MlsExpect::Application => chatcore::api::Expect::Application, MlsExpect::Commit => chatcore::api::Expect::Commit });
    let p = core::mls_receive(group_id, message, expect)?;
    Ok(MlsProcessed { pending_id: p.pending_id, kind: p.kind, plaintext: p.plaintext, sender: p.sender.into(), epoch: p.epoch, digest: p.digest })
}
/// The core's verdict on a commit at the current epoch, checked against this device's own tree like the
/// delivery service does (changes nothing). `class` is `signed-content` only when the author's signature
/// verifies and what they signed is itself invalid; otherwise `tag` (outside the signature: proves nothing
/// about the author). `author` is set when the signature verified.
pub struct MlsCommitCheck {
    pub authenticated: bool,
    pub signed_content_invalid: bool,
    pub class: String,
    pub author: Option<MlsMember>,
}
pub fn mls_commit_author(group_id: String, message: String) -> Result<MlsCommitCheck> {
    let check = core::mls_commit_author(group_id, message)?;
    Ok(MlsCommitCheck { authenticated: check.authenticated, signed_content_invalid: check.signed_content_invalid, class: check.class.to_string(), author: check.author.map(Into::into) })
}
/// Signs a frozen-channel resolution (`rollback` or `dismiss`) with this device's MLS leaf key over the
/// `webrtc-bun-mlsresolve-leaf-v1` bytes; nothing else is ever signed this way.
pub fn mls_sign_resolution(group_id: String, action: String, seq: u64, digest: String, author: String) -> Result<String> {
    Ok(core::mls_sign_resolution(group_id, action, seq, digest, author)?)
}
/// Verifies a resolution signed by device `by`, which must be an admin device in this device's own tree.
/// Returns the signer (`user_id`, `device_id`); `auth` for a bad signature, `invalid` otherwise.
pub fn mls_verify_resolution(group_id: String, action: String, seq: u64, digest: String, author: String, by: String, signature: String) -> Result<MlsRemoval> {
    let signer = core::mls_verify_resolution(group_id, action, seq, digest, author, by, signature)?;
    Ok(MlsRemoval { user_id: signer.user_id, device_id: Some(signer.device_id) })
}
pub fn mls_receive_commit(pending_id: String) -> Result<()> { Ok(core::mls_receive_commit(pending_id)?) }
pub fn mls_receive_abort(pending_id: String) -> Result<()> { Ok(core::mls_receive_abort(pending_id)?) }
pub fn mls_members(group_id: String) -> Result<Vec<MlsMember>> { Ok(core::mls_members(group_id)?.into_iter().map(Into::into).collect()) }
pub fn mls_roles(group_id: String) -> Result<MlsRoles> { Ok(core::mls_roles(group_id)?.into()) }
pub fn mls_group_view(group_id: String) -> Result<MlsGroupView> { Ok(core::mls_group_view(group_id)?.into()) }
/// Validates one decrypted payload against the v2 schema and the sender's authority; returns its type.
pub fn mls_validate_payload(payload_json: String, sender: String, sender_is_admin: bool, target_sender: Option<String>) -> Result<String> {
    Ok(core::mls_validate_payload(payload_json, PayloadContext { sender, sender_is_admin, target_sender })?)
}
