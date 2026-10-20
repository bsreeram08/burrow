//! The flat, flutter_rust_bridge-friendly API: owned types, no lifetimes, one process-wide core
//! behind a mutex (which also gives signal.js's per-contact and x3dh serialization). See API.md.
use std::sync::Mutex;

use crate::core::{Core, Decrypted, EncryptOutcome, PeerRecord, PrekeyUpload, Safety};
use crate::devicelist::ListHead;
use crate::error::{ChatError, Result};
use crate::protocol::{Bundle, IdentityPub, PublishedOneTimePreKey};
use crate::sas;
use crate::store::{Open, SqliteStore};

static CORE: Mutex<Option<Core>> = Mutex::new(None);

fn with<T>(work: impl FnOnce(&mut Core) -> Result<T>) -> Result<T> {
    let mut guard = CORE.lock().map_err(|_| ChatError::transient("Core lock poisoned"))?;
    // No open key database (never opened, or the last open failed): fail closed, never act on stale state.
    let core = guard.as_mut().ok_or_else(|| ChatError::storage("key database is not open"))?;
    work(core)
}

/// Opens the account's key database, sealed with `store_key` (32 bytes from the platform keystore).
/// `expect_existing`: the app created this database before (its keystore holds a key for it), so a missing
/// marker is a reset or replaced database and fails closed. Otherwise only an empty database is initialized.
/// No key, no implicit migration, no silent fresh start: every failure is a `storage` error.
pub fn init(db_path: String, store_key: Vec<u8>, expect_existing: bool) -> Result<()> {
    let key = <[u8; 32]>::try_from(store_key.as_slice()).map_err(|_| ChatError::storage("store key must be 32 bytes"))?;
    let mode = if expect_existing { Open::Existing } else { Open::Create };
    let mut guard = CORE.lock().map_err(|_| ChatError::transient("Core lock poisoned"))?;
    // Close whatever was open first: a failed open must never leave a previous account's store in use.
    *guard = None;
    *guard = Some(Core::new(Box::new(SqliteStore::open_sealed(&db_path, key, mode)?)));
    Ok(())
}

pub fn identity() -> Result<IdentityPub> { with(|core| core.public_identity()) }

/// Signed prekey state to upload (rotates weekly). `now_ms` is Unix time in milliseconds.
pub fn prepare_prekeys(now_ms: u64) -> Result<PrekeyUpload> { with(|core| core.prekeys(now_ms, None)) }

pub fn one_time_prekeys(count: u64) -> Result<Vec<PublishedOneTimePreKey>> { with(|core| core.one_time_prekeys(count)) }

/// Encrypts a JSON payload for a contact. Without a sending session it returns `NeedsBundle`:
/// fetch `/api/keys/<username>` and call again with that JSON.
pub fn encrypt_to(contact_id: String, plaintext_json: String, bundle_json: Option<String>) -> Result<EncryptOutcome> {
    let bundle = bundle_json
        .map(|json| serde_json::from_str::<Bundle>(&json).map_err(|_| ChatError::transient("Invalid key bundle")))
        .transpose()?;
    with(|core| core.encrypt_to(&contact_id, &plaintext_json, bundle.as_ref()))
}

/// Phase one of receiving: decrypt and authenticate; store the message, then `commit(pending_id)`.
pub fn decrypt_from(contact_id: String, envelope: String, published_identity: Option<IdentityPub>) -> Result<Decrypted> {
    with(|core| core.decrypt_from(&contact_id, &envelope, published_identity.as_ref()))
}

/// Phase two: persist the ratchet advance. Returns true when a changed identity was recorded.
/// `rotate` is true when the stored payload was the peer's `{type:'rotate'}` session reset.
pub fn commit(pending_id: String, rotate: bool) -> Result<bool> { with(|core| core.commit(&pending_id, rotate)) }

pub fn abort(pending_id: String) -> Result<()> { with(|core| { core.abort(&pending_id); Ok(()) }) }

pub fn safety(my_username: String, contact_id: String, their_username: String) -> Result<Option<Safety>> {
    with(|core| core.safety(&my_username, &contact_id, &their_username))
}

pub fn peer(contact_id: String) -> Result<Option<PeerRecord>> { with(|core| core.peer(&contact_id)) }
pub fn set_verified(contact_id: String, verified: bool) -> Result<()> { with(|core| core.set_verified(&contact_id, verified)) }
pub fn accept_change(contact_id: String) -> Result<()> { with(|core| core.accept_change(&contact_id)) }
/// Accept / verify only the identity the user was shown; `mismatch` if the pinned one is different now.
pub fn accept_change_for(contact_id: String, identity: IdentityPub) -> Result<()> { with(|core| core.accept_change_for(&contact_id, Some(&identity))) }
pub fn set_verified_for(contact_id: String, verified: bool, identity: IdentityPub) -> Result<()> { with(|core| core.set_verified_for(&contact_id, verified, Some(&identity))) }
pub fn forget(contact_id: String) -> Result<()> { with(|core| core.forget(&contact_id)) }

/// Records an identity the server published for a contact (key-change events); a change is flagged and blocks sending.
pub fn note_peer(contact_id: String, identity: IdentityPub) -> Result<()> { with(|core| core.note_peer(&contact_id, &identity).map(|_| ())) }

/// Chat key rotation: the next message to this contact opens a fresh session.
pub fn rotate(contact_id: String) -> Result<()> { with(|core| core.rotate(&contact_id)) }

/// The active session with a contact: id and start time (Unix ms), for scheduled rotation.
pub fn session_info(contact_id: String) -> Result<Option<SessionInfo>> {
    with(|core| Ok(core.session_info(&contact_id)?.map(|(sid, started_at)| SessionInfo { sid, started_at })))
}

/// Replaces this device's identity (explicit user action only); contacts see a security-code change.
/// Signs a device-claim challenge with the account identity key (docs/devices.md); nothing else.
pub fn prove_identity(user_id: String, device_id: String, challenge: String) -> Result<String> { with(|core| core.prove_identity(&user_id, &device_id, &challenge)) }
pub fn reset_identity() -> Result<()> { with(|core| core.reset_identity()) }

/// Signs the account's next DeviceList (JSON, devices.js shape) and its device certificates; see
/// `Core::sign_device_list`. `published_sign` is the account's identity signing key as the server publishes it;
/// `head` is the list the server serves now (with its signature), so lists signed by another device are followed.
pub fn sign_device_list(user_id: String, published_sign: String, list_json: String, head: Option<ListHead>) -> Result<crate::devicelist::SignedList> {
    with(|core| core.sign_device_list(&user_id, &published_sign, &list_json, head.as_ref()))
}
/// The device-meta seed (base64url signature); see `Core::device_meta_signature`.
pub fn device_meta_signature(user_id: String) -> Result<String> { with(|core| core.device_meta_signature(&user_id)) }

/// Chat key rotation schedule: the shorter non-off interval of the two sides wins (0 = off).
pub fn rotation_interval(mine: u64, theirs: u64) -> u64 { crate::core::rotation_interval(mine, theirs) }

pub struct SessionInfo {
    pub sid: String,
    pub started_at: u64,
}

// ---------- Call verification (verify.js) ----------
pub fn sas_new_nonce() -> String { sas::new_nonce() }
pub fn sas_commitment(nonce: String) -> Result<String> { sas::commitment(&nonce) }
pub fn sas_check_reveal(peer_commitment: String, peer_nonce: String) -> bool { sas::check_reveal(&peer_commitment, &peer_nonce) }
pub fn sas_code(local_sdp: String, remote_sdp: String, my_nonce: String, peer_nonce: String) -> Result<String> {
    sas::sas_from_sdp(&local_sdp, &remote_sdp, [&my_nonce, &peer_nonce])
}

// ---------- Linked devices, succession and pin transfer (docs/m5-linking.md) ----------
pub use crate::core::{Account, LinkAccepted, PinExport, PreviousKey};

/// New device: ephemeral key and link secret for `link_id` (from the server); returns the QR text.
pub fn link_qr(link_id: String, now_ms: u64) -> Result<String> { with(|core| core.link_qr(&link_id, now_ms)) }
/// Primary: checks a scanned QR and derives the keys; the result carries the ephemeral key to offer and the code.
pub fn link_accept(qr: String, now_ms: u64) -> Result<LinkAccepted> { with(|core| core.link_accept(&qr, now_ms)) }
/// New device: the primary's ephemeral key arrived; returns the confirmation code.
pub fn link_complete(link_id: String, eph: String, now_ms: u64) -> Result<String> { with(|core| core.link_complete(&link_id, &eph, now_ms)) }
pub fn link_seal(link_id: String, plaintext: String, now_ms: u64) -> Result<String> { with(|core| core.link_seal(&link_id, &plaintext, now_ms)) }
pub fn link_open(link_id: String, data: String, now_ms: u64) -> Result<String> { with(|core| core.link_open(&link_id, &data, now_ms)) }
/// Short-code rendezvous, new device: commits to an ephemeral key before the primary's is known.
pub fn link_commit(link_id: String, device_id: String, now_ms: u64) -> Result<String> { with(|core| core.link_commit(&link_id, &device_id, now_ms)) }
/// New device, after the primary's key arrived: opens the commitment `(eph, nonce)` for the primary to check.
pub fn link_reveal(link_id: String, eph_p: String, now_ms: u64) -> Result<(String, String)> { with(|core| core.link_reveal(&link_id, &eph_p, now_ms)) }
/// Primary, after looking a code up: remembers the commitment; returns the ephemeral key to offer.
pub fn link_lookup(link_id: String, device_n: String, commit: String, device_p: String, now_ms: u64) -> Result<String> { with(|core| core.link_lookup(&link_id, &device_n, &commit, &device_p, now_ms)) }
/// Primary: checks the revealed key against the commitment, derives the keys; returns the confirmation code.
pub fn link_open_commitment(link_id: String, eph_n: String, nonce: String, now_ms: u64) -> Result<String> { with(|core| core.link_open_commitment(&link_id, &eph_n, &nonce, now_ms)) }
/// New device: derives the keys; returns the confirmation code (it must equal the primary's).
pub fn link_complete_code(link_id: String, eph_p: String, device_p: String, now_ms: u64) -> Result<String> { with(|core| core.link_complete_code(&link_id, &eph_p, &device_p, now_ms)) }
pub fn link_end(link_id: String) -> Result<()> { with(|core| core.link_end(&link_id)) }
pub fn export_pins() -> Result<Vec<PinExport>> { with(|core| core.export_pins()) }
pub fn import_pins(pins: Vec<PinExport>) -> Result<u32> { with(|core| Ok(core.import_pins(&pins)? as u32)) }
/// Companion becoming primary: mints the identity it will publish.
pub fn succession_start() -> Result<IdentityPub> { with(|core| core.succession_start()) }
/// `record_json` is the signed record the old primary sent (`{v,userId,oldSign,newSign,newDh,at}`), `signature` its signature.
pub fn succession_complete(record_json: String, signature: String) -> Result<IdentityPub> {
    let record = serde_json::from_str(&record_json).map_err(|_| ChatError::coded("invalid", "malformed succession record"))?;
    with(|core| core.succession_complete(&record, &signature))
}
/// A companion core whose account key lives outside it adopts the succession the old primary signed (see `Core::adopt_succession`).
#[cfg(feature = "mls")]
pub fn adopt_succession(user_id: String, record_json: String, signature: String, cert_json: Option<String>) -> Result<IdentityPub> {
    let record = serde_json::from_str(&record_json).map_err(|_| ChatError::coded("invalid", "malformed succession record"))?;
    with(|core| core.adopt_succession(&user_id, &record, &signature, cert_json.as_deref()))
}
/// Old primary: the signed record (JSON, `signature` included) for the new identity.
pub fn sign_succession(user_id: String, published_sign: String, new_sign: String, new_dh: String, at: u64) -> Result<String> {
    with(|core| Ok(core.sign_succession(&user_id, &published_sign, &new_sign, &new_dh, at)?.to_string()))
}
/// Old primary steps down to a companion of the account under `new_identity`.
pub fn retire_identity(user_id: String, new_identity: IdentityPub, at: u64) -> Result<()> { with(|core| core.retire_identity(&user_id, &new_identity, at)) }
/// Contact: follows the served `succession` records (a JSON list) from the pinned identity.
pub fn accept_succession(contact_id: String, records_json: String) -> Result<PeerRecord> {
    let records: Vec<serde_json::Value> = serde_json::from_str(&records_json).map_err(|_| ChatError::coded("invalid", "malformed succession records"))?;
    with(|core| core.accept_succession(&contact_id, &records))
}
/// New device: installs a link grant (the account's public identity and this device's MLS certificate).
#[cfg(feature = "mls")]
pub fn companion_setup(user_id: String, identity: IdentityPub, cert_json: String) -> Result<DeviceCert> { with(|core| core.companion_setup(&user_id, &identity, &cert_json)) }
/// Primary: the MLS certificate for a linked device's leaf key (only for a device in the last list it signed).
#[cfg(feature = "mls")]
pub fn sign_device_cert(user_id: String, device_id: String, platform: String, leaf_sig_key: String, issued_at: u64, now_ms: u64) -> Result<String> {
    with(|core| core.sign_device_cert(&user_id, &device_id, &platform, &leaf_sig_key, issued_at, now_ms))
}

// ---------- Groups over MLS (src/mls; API.md "Groups over MLS") ----------
// Group ids, KeyPackages, Welcomes, ratchet trees, GroupInfos and messages are base64url strings. Contact ids used
// for 1:1 pins (`note_peer`) must be the user's canonical id for MLS to find that user's pinned account key.
#[cfg(feature = "mls")]
pub use crate::mls::cert::DeviceCert;
#[cfg(feature = "mls")]
pub use crate::mls::engine::{CommitCheck, Expect, GroupInspection, ResolutionSigner, GroupView, MemberView, Outgoing, PendingCommit, Processed};
#[cfg(feature = "mls")]
pub use crate::mls::payload::Context as PayloadContext;
#[cfg(feature = "mls")]
pub use crate::mls::policy::{JoinPolicy, Kind, Roles};

#[cfg(feature = "mls")]
fn with_groups<T>(work: impl FnOnce(&mut crate::mls::engine::Groups, &mut dyn crate::store::Store) -> Result<T>) -> Result<T> {
    with(|core| {
        let (groups, store) = core.groups()?;
        work(groups, store)
    })
}

/// One device to remove: all of a user's devices when `device_id` is `None`.
#[cfg(feature = "mls")]
pub struct Removal {
    pub user_id: String,
    pub device_id: Option<String>,
}

/// Creates (once) this device's group identity, certified by the account identity key held by this core.
#[cfg(feature = "mls")]
pub fn mls_init_device(user_id: String, device_id: String, platform: String, issued_at_ms: u64) -> Result<DeviceCert> {
    with(|core| {
        let aik = core.account_signing_key()?;
        let (groups, store) = core.groups()?;
        groups.init_device(store, &user_id, &device_id, &platform, issued_at_ms, &aik)
    })
}

/// Whether one of this account's devices holds exactly this leaf key as a current leaf in any of `groups`: what a
/// new primary requires before it certifies a companion's leaf under the new account key.
#[cfg(feature = "mls")]
pub fn mls_leaf_known(device_id: String, leaf_sig_key: String, groups: Vec<String>) -> Result<bool> {
    let ids = groups.iter().map(|g| crate::mls::engine::group_id(g)).collect::<Result<Vec<_>>>()?;
    with_groups(|g, store| g.leaf_known(store, &ids, &device_id, &leaf_sig_key))
}

/// This device's MLS leaf signature key (base64url), made on first use. A new device sends it in its link hello
/// before it has a certificate.
#[cfg(feature = "mls")]
pub fn mls_device_leaf() -> Result<String> { with_groups(|groups, store| groups.device_leaf(store)) }

/// The account a companion core is linked to (user id and pinned public identity); `None` on a primary.
#[cfg(feature = "mls")]
pub fn account() -> Result<Option<Account>> { with(|core| core.account()) }

/// The device re-signs its own, unchanged leaf under the identity this core now holds (after a succession, or to
/// refresh a certificate). A primary only.
#[cfg(feature = "mls")]
pub fn mls_recertify(platform: String, issued_at_ms: u64) -> Result<DeviceCert> {
    with(|core| {
        let aik = core.account_signing_key()?;
        let (groups, store) = core.groups()?;
        groups.recertify_device(store, &platform, issued_at_ms, &aik)
    })
}

/// KeyPackages for the server: `count` one-time ones (1–100), or one last-resort one.
#[cfg(feature = "mls")]
pub fn mls_key_packages(count: u32, last_resort: bool) -> Result<Vec<String>> {
    with_groups(|groups, store| groups.key_packages(store, count, last_resort))
}

#[cfg(feature = "mls")]
pub fn mls_create_group(group_id: String, roles: Roles) -> Result<GroupView> {
    with_groups(|groups, store| groups.create(store, &crate::mls::engine::group_id(&group_id)?, &roles))
}

/// Builds a commit (adds, removals, a roles change, a self-update) and keeps it pending: submit `commit` to the
/// delivery service, then `mls_merge_own` if it was accepted or `mls_clear_own` if it answered with a conflict.
#[cfg(feature = "mls")]
pub fn mls_commit(group_id: String, adds: Vec<String>, removes: Vec<Removal>, roles: Option<Roles>, update: bool) -> Result<Outgoing> {
    let removes: Vec<(String, Option<String>)> = removes.into_iter().map(|r| (r.user_id, r.device_id)).collect();
    with_groups(|groups, store| groups.commit(store, &crate::mls::engine::group_id(&group_id)?, &adds, &removes, roles.as_ref(), update))
}

#[cfg(feature = "mls")]
pub fn mls_merge_own(group_id: String) -> Result<GroupView> {
    with_groups(|groups, store| groups.merge_own(store, &crate::mls::engine::group_id(&group_id)?))
}
#[cfg(feature = "mls")]
pub fn mls_clear_own(group_id: String) -> Result<()> {
    with_groups(|groups, store| groups.clear_own(store, &crate::mls::engine::group_id(&group_id)?))
}
#[cfg(feature = "mls")]
pub fn mls_pending_commit(group_id: String) -> Result<Option<PendingCommit>> {
    with_groups(|groups, store| groups.pending_commit(store, &crate::mls::engine::group_id(&group_id)?))
}

/// Joins from a Welcome and the post-commit ratchet tree.
#[cfg(feature = "mls")]
pub fn mls_join(welcome: String, tree: String) -> Result<GroupView> { with_groups(|groups, store| groups.join(store, &welcome, &tree)) }

/// External join (public channel, own new device, resync after `mls_forget_group`): submit the commit, then `mls_merge_own`.
#[cfg(feature = "mls")]
pub fn mls_join_external(group_info: String, tree: String, group: String) -> Result<Outgoing> { with_groups(|groups, store| groups.join_external(store, &group_info, &tree, &group)) }

#[cfg(feature = "mls")]
pub fn mls_forget_group(group_id: String) -> Result<()> {
    with_groups(|groups, store| groups.forget_group(store, &crate::mls::engine::group_id(&group_id)?))
}

/// Encrypts one payload (64 KiB at most; 60 KiB of plaintext) for the group's current epoch.
#[cfg(feature = "mls")]
pub fn mls_encrypt(group_id: String, plaintext: String) -> Result<String> {
    with_groups(|groups, store| groups.encrypt(store, &crate::mls::engine::group_id(&group_id)?, &plaintext))
}

/// Phase one of receiving a message from the group's log; store the result, then `mls_receive_commit(pending_id)`.
#[cfg(feature = "mls")]
/// `expect`: what the log entry's kind says it is (`Application` or `Commit`); a mismatch is refused before anything
/// is staged. Pass it whenever the entry's kind is known.
pub fn mls_receive(group_id: String, message: String, expect: Option<Expect>) -> Result<Processed> {
    with_groups(|groups, store| groups.process_as(store, &crate::mls::engine::group_id(&group_id)?, &message, expect))
}
#[cfg(feature = "mls")]
/// Who signed a commit at the current epoch, checked against this device's tree (signature only; changes nothing).
#[cfg(feature = "mls")]
pub fn mls_commit_author(group_id: String, message: String) -> Result<CommitCheck> { with_groups(|groups, store| groups.commit_author(store, &crate::mls::engine::group_id(&group_id)?, &message)) }
/// Signs a resolution of a frozen channel (`action`: `rollback` or `dismiss`) with this device's leaf key; see
/// `Groups::sign_resolution`.
#[cfg(feature = "mls")]
pub fn mls_sign_resolution(group_id: String, action: String, seq: u64, digest: String, author: String) -> Result<String> {
    with_groups(|groups, store| groups.sign_resolution(store, &crate::mls::engine::group_id(&group_id)?, &action, seq, &digest, &author))
}
/// Verifies a resolution signed by the admin device `by`; see `Groups::verify_resolution`.
#[cfg(feature = "mls")]
pub fn mls_verify_resolution(group_id: String, action: String, seq: u64, digest: String, author: String, by: String, by_user: String, signature: String) -> Result<ResolutionSigner> {
    with_groups(|groups, store| groups.verify_resolution(store, &crate::mls::engine::group_id(&group_id)?, &action, seq, &digest, &author, &by, &by_user, &signature))
}
#[cfg(feature = "mls")]
pub fn mls_receive_commit(pending_id: String) -> Result<()> { with_groups(|groups, store| groups.commit_pending(store, &pending_id)) }
#[cfg(feature = "mls")]
pub fn mls_receive_abort(pending_id: String) -> Result<()> { with_groups(|groups, _| { groups.abort(&pending_id); Ok(()) }) }

#[cfg(feature = "mls")]
pub fn mls_members(group_id: String) -> Result<Vec<MemberView>> {
    with_groups(|groups, store| groups.members(store, &crate::mls::engine::group_id(&group_id)?))
}
#[cfg(feature = "mls")]
pub fn mls_roles(group_id: String) -> Result<Roles> { with_groups(|groups, store| groups.roles(store, &crate::mls::engine::group_id(&group_id)?)) }
#[cfg(feature = "mls")]
pub fn mls_group_view(group_id: String) -> Result<GroupView> {
    with_groups(|groups, store| groups.group_view(store, &crate::mls::engine::group_id(&group_id)?))
}

/// The members of a served GroupInfo/tree after the join validation, without joining (`stale` flags old identities).
#[cfg(feature = "mls")]
pub fn mls_inspect_group(group_info: String, tree: String) -> Result<GroupInspection> { with_groups(|groups, store| groups.inspect_group(store, &group_info, &tree)) }

/// Accepts a DM pointer's group only if it is the DM of this account and `peer` and every leaf chains to the pins.
#[cfg(feature = "mls")]
pub fn mls_check_dm(group_id: String, peer_user_id: String) -> Result<()> {
    with_groups(|groups, store| groups.check_dm(store, &crate::mls::engine::group_id(&group_id)?, &peer_user_id))
}

/// Validates one decrypted payload (v2 schema and the sender's authority); returns its type.
#[cfg(feature = "mls")]
pub fn mls_validate_payload(payload_json: String, context: PayloadContext) -> Result<String> { crate::mls::payload::validate(&payload_json, &context) }
