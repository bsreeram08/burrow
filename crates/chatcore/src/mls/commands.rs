//! The MLS and delivery-service commands of the JSON command protocol (`crate::commands`), shared by the
//! browser worker, the node interop party and the Bun delivery service. Group ids, KeyPackages, Welcomes,
//! trees and messages are base64url strings; see API.md for each command's fields.
#[cfg(feature = "ds")]
use serde_json::json;
use serde_json::Value;

use crate::core::Core;
use crate::error::{ChatError, Result};

fn text(command: &Value, key: &str) -> Result<String> {
    command.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| ChatError::transient(format!("missing {key}")))
}

#[cfg(feature = "mls")]
fn flag(command: &Value, key: &str) -> bool { command.get(key).and_then(Value::as_bool).unwrap_or(false) }

#[cfg(feature = "mls")]
fn list(command: &Value, key: &str) -> Result<Vec<String>> {
    match command.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|v| v.as_str().map(str::to_string).ok_or_else(|| ChatError::transient(format!("{key} must be strings")))).collect(),
        Some(_) => Err(ChatError::transient(format!("{key} must be a list"))),
    }
}

#[cfg(feature = "mls")]
fn roles_of(value: &Value) -> Result<crate::mls::policy::Roles> {
    serde_json::from_value(value.clone()).map_err(|_| ChatError::coded("invalid", "malformed roles"))
}

/// The optional `expect` of `mlsReceive` and `dsSubmit`: `"application"` or `"commit"`.
fn expect(command: &Value) -> Result<Option<crate::mls::engine::Expect>> {
    match command.get("expect") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => crate::mls::engine::Expect::parse(text).map(Some),
        Some(_) => Err(ChatError::coded("invalid", "expect must be a string")),
    }
}

fn ok<T: serde::Serialize>(value: T) -> Result<Value> { Ok(serde_json::to_value(value).expect("serializes")) }

/// `None`: not an MLS command.
pub fn run(core: &mut Core, cmd: &str, command: &Value) -> Option<Result<Value>> {
    #[cfg(feature = "mls")]
    if cmd.starts_with("mls") || matches!(cmd, "companionSetup" | "signDeviceCert" | "adoptSuccession" | "rotateIdentity" | "rotationPending" | "rotationDrop" | "rekeyRequest" | "rekeyAnswer" | "rekeyOpen") { return run_mls(core, cmd, command); }
    #[cfg(feature = "ds")]
    if cmd.starts_with("ds") { return run_ds(core, cmd, command); }
    let _ = (core, cmd, command);
    None
}

#[cfg(feature = "mls")]
fn run_mls(core: &mut Core, cmd: &str, command: &Value) -> Option<Result<Value>> {
    use crate::mls::engine::group_id;
    use crate::mls::payload;
    let result = (|| -> Result<Value> {
        let group = || group_id(&text(command, "group")?);
        match cmd {
            "mlsValidate" => {
                let context = payload::Context {
                    sender: text(command, "sender")?,
                    sender_is_admin: flag(command, "senderIsAdmin"),
                    target_sender: command.get("targetSender").and_then(Value::as_str).map(str::to_string),
                };
                return ok(payload::validate(&text(command, "payload")?, &context)?);
            }
            "mlsInitDevice" => {
                let aik = core.account_signing_key()?;
                let (groups, store) = core.groups()?;
                let issued_at = command.get("issuedAt").and_then(Value::as_u64).unwrap_or(0);
                return ok(groups.init_device(store, &text(command, "userId")?, &text(command, "deviceId")?, &text(command, "platform")?, issued_at, &aik)?);
            }
            "mlsSetDeviceCert" => {
                // A core with its own 1:1 identity certifies under that key only. A core without one (the web keeps the
                // AIK in WebCrypto and runs MLS in a store of its own) takes the account key from its caller, once:
                // the certificate must verify under it, and a store that holds a certificate never changes account.
                let aik = if core.has_identity()? {
                    core.account_aik_bytes()?
                } else {
                    command.get("aik").and_then(Value::as_str).and_then(crate::mls::cert::key32).ok_or_else(|| ChatError::coded("invalid", "aik: the account key is needed"))?
                };
                let (groups, store) = core.groups()?;
                return ok(groups.set_device_cert(store, &text(command, "cert")?, &aik)?);
            }
            // Linked devices (docs/m5-linking.md §1).
            "companionSetup" => {
                let identity: crate::protocol::IdentityPub = serde_json::from_value(command.get("identity").cloned().unwrap_or(Value::Null)).map_err(|_| ChatError::coded("invalid", "Invalid identity"))?;
                return ok(core.companion_setup(&text(command, "userId")?, &identity, &text(command, "cert")?)?);
            }
            // The account key to a companion (docs/m6-account-key.md §5).
            "rekeyRequest" => return ok(core.rekey_request(&text(command, "userId")?, &text(command, "deviceId")?, &text(command, "platform")?)?),
            "rekeyAnswer" => {
                let listed = command.get("groups").and_then(Value::as_array).ok_or_else(|| ChatError::coded("invalid", "groups must be a list"))?;
                if listed.len() > 1000 { return Err(ChatError::coded("invalid", "too many groups")); }
                let ids = listed.iter().map(|g| g.as_str().ok_or_else(|| ChatError::coded("invalid", "group ids are strings")).and_then(group_id)).collect::<Result<Vec<_>>>()?;
                let keys = match command.get("backupKeys") { None | Some(Value::Null) => None, Some(value) => Some(crate::account_key::BackupKeys::parse(value)?) };
                return ok(core.rekey_answer(&text(command, "userId")?, &text(command, "deviceId")?, &text(command, "platform")?, &text(command, "eph")?, &text(command, "leafSigKey")?, &text(command, "signature")?, &ids, command.get("now").and_then(Value::as_u64).unwrap_or(0), keys.as_ref())?);
            }
            "rekeyOpen" => {
                let (identity, backup_keys) = core.rekey_open(&text(command, "userId")?, &text(command, "deviceId")?, &text(command, "platform")?, &text(command, "box")?)?;
                return ok(serde_json::json!({ "identity": identity, "backupKeys": backup_keys }));
            }
            // A prepared rotation survives a restart (docs/m6-account-key.md §6.2): look at it, or drop it.
            "rotationPending" => return ok(core.rotation_pending()?.map(|(identity, record)| serde_json::json!({ "identity": identity, "record": record }))),
            "rotationDrop" => { core.rotation_drop()?; return Ok(Value::Null); }
            // A full core replaces its own account identity (docs/m6-account-key.md §6.2).
            "rotateIdentity" => {
                let external = match (command.get("record"), command.get("signature").and_then(Value::as_str)) {
                    (Some(record), Some(signature)) => Some((record, signature)),
                    (None, None) => None,
                    _ => return Err(ChatError::coded("invalid", "give both the record and its signature, or neither")),
                };
                let commit = command.get("commit").and_then(Value::as_bool).unwrap_or(true);
                let (identity, record, key) = core.rotate_identity(&text(command, "userId")?, command.get("key").and_then(Value::as_str), external, command.get("at").and_then(Value::as_u64).unwrap_or(0), commit)?;
                return ok(serde_json::json!({ "identity": identity, "record": record, "key": key }));
            }
            "adoptSuccession" => {
                let record = command.get("record").ok_or_else(|| ChatError::coded("invalid", "record is required"))?;
                return ok(core.adopt_succession(&text(command, "userId")?, record, &text(command, "signature")?, command.get("cert").and_then(Value::as_str))?);
            }
            "signDeviceCert" => {
                let issued_at = command.get("issuedAt").and_then(Value::as_u64).ok_or_else(|| ChatError::coded("invalid", "issuedAt must be a number"))?;
                return ok(core.sign_device_cert(&text(command, "userId")?, &text(command, "deviceId")?, &text(command, "platform")?, &text(command, "leafSigKey")?, issued_at, command.get("now").and_then(Value::as_u64).unwrap_or(0))?);
            }
            // The primary signs a fresh certificate for its own, unchanged leaf under the identity it now holds
            // (after a succession, §5.2).
            "mlsRecertify" => {
                let aik = core.account_signing_key()?;
                let (groups, store) = core.groups()?;
                let issued_at = command.get("issuedAt").and_then(Value::as_u64).unwrap_or(0);
                return ok(groups.recertify_device(store, &text(command, "platform")?, issued_at, &aik)?);
            }
            _ => {}
        }
        let (groups, store) = core.groups()?;
        match cmd {
            "mlsDeviceLeaf" => ok(groups.device_leaf(store)?),
            "mlsKeyPackages" => {
                let count = command.get("count").and_then(Value::as_u64).unwrap_or(1);
                ok(groups.key_packages(store, u32::try_from(count).unwrap_or(u32::MAX), flag(command, "lastResort"))?)
            }
            "mlsCreate" => ok(groups.create(store, &group()?, &roles_of(command.get("roles").unwrap_or(&Value::Null))?)?),
            "mlsCommit" => {
                let removes: Vec<(String, Option<String>)> = match command.get("removes") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| Ok((text(item, "userId")?, item.get("deviceId").and_then(Value::as_str).map(str::to_string))))
                        .collect::<Result<_>>()?,
                    Some(_) => return Err(ChatError::transient("removes must be a list")),
                };
                let roles = match command.get("roles") { None | Some(Value::Null) => None, Some(value) => Some(roles_of(value)?) };
                ok(groups.commit(store, &group()?, &list(command, "adds")?, &removes, roles.as_ref(), flag(command, "update"))?)
            }
            // Test builds only (`test-hooks`, never in build:wasm): a commit that skips this device's own policy check,
            // to play a malicious member against the delivery service and the other members.
            #[cfg(feature = "test-hooks")]
            "mlsTestUnchecked" => {
                let removes: Vec<(String, Option<String>)> = match command.get("removes") {
                    Some(Value::Array(items)) => items.iter().map(|item| Ok((text(item, "userId")?, item.get("deviceId").and_then(Value::as_str).map(str::to_string)))).collect::<Result<_>>()?,
                    _ => Vec::new(),
                };
                let roles = match command.get("roles") { None | Some(Value::Null) => None, Some(value) => Some(roles_of(value)?) };
                ok(groups.commit_unchecked(store, &group()?, &list(command, "adds")?, &removes, roles.as_ref(), flag(command, "update"))?)
            }
            "mlsSignResolution" | "mlsVerifyResolution" => {
                let (action, digest, author) = (text(command, "action")?, text(command, "digest")?, command.get("author").and_then(Value::as_str).unwrap_or("").to_string());
                let seq = command.get("seq").and_then(Value::as_u64).ok_or_else(|| ChatError::coded("invalid", "seq must be a number"))?;
                if cmd == "mlsSignResolution" { ok(groups.sign_resolution(store, &group()?, &action, seq, &digest, &author)?) }
                else { ok(groups.verify_resolution(store, &group()?, &action, seq, &digest, &author, &text(command, "by")?, &text(command, "byUser")?, &text(command, "signature")?)?) }
            }
            "mlsInspectGroup" => ok(groups.inspect_group(store, &text(command, "groupInfo")?, &text(command, "tree")?)?),
            "mlsLeafKnown" => {
                let listed = command.get("groups").and_then(Value::as_array).ok_or_else(|| ChatError::coded("invalid", "groups must be a list"))?;
                if listed.len() > 1000 { return Err(ChatError::coded("invalid", "too many groups")); }
                let ids = listed.iter().map(|g| g.as_str().ok_or_else(|| ChatError::coded("invalid", "group ids are strings")).and_then(group_id)).collect::<Result<Vec<_>>>()?;
                ok(groups.leaf_known(store, &ids, &text(command, "deviceId")?, &text(command, "leafSigKey")?)?)
            }
            "mlsCheckDm" => { groups.check_dm(store, &group()?, &text(command, "peer")?)?; Ok(Value::Null) }
            "mlsMergeOwn" => ok(groups.merge_own(store, &group()?)?),
            "mlsClearOwn" => { groups.clear_own(store, &group()?)?; Ok(Value::Null) }
            "mlsPending" => ok(groups.pending_commit(store, &group()?)?),
            "mlsJoin" => ok(groups.join(store, &text(command, "welcome")?, &text(command, "tree")?)?),
            "mlsJoinExternal" => ok(groups.join_external(store, &text(command, "groupInfo")?, &text(command, "tree")?, &text(command, "group")?)?),
            "mlsForget" => { groups.forget_group(store, &group()?)?; Ok(Value::Null) }
            "mlsEncrypt" => ok(groups.encrypt(store, &group()?, &text(command, "plaintext")?)?),
            "mlsReceive" => {
                let processed = groups.process_as(store, &group()?, &text(command, "message")?, expect(command)?)?;
                // Like `decrypt`: commit unless the caller wants to store the message first (commit: false).
                if command.get("commit").and_then(Value::as_bool).unwrap_or(true) { groups.commit_pending(store, &processed.pending_id)?; }
                ok(processed)
            }
            "mlsCommitAuthor" => ok(groups.commit_author(store, &group()?, &text(command, "message")?)?),
            "mlsCommitReceived" => { groups.commit_pending(store, &text(command, "pendingId")?)?; Ok(Value::Null) }
            "mlsAbortReceived" => { groups.abort(&text(command, "pendingId")?); Ok(Value::Null) }
            "mlsMembers" => ok(groups.members(store, &group()?)?),
            "mlsRoles" => ok(groups.roles(store, &group()?)?),
            "mlsView" => ok(groups.group_view(store, &group()?)?),
            other => Err(ChatError::transient(format!("unknown command {other}"))),
        }
    })();
    Some(result)
}

#[cfg(feature = "ds")]
fn run_ds(core: &mut Core, cmd: &str, command: &Value) -> Option<Result<Value>> {
    use crate::mls::engine::group_id;
    let result = (|| -> Result<Value> {
        let (ds, store) = core.ds()?;
        let group = || group_id(&text(command, "group")?);
        match cmd {
            "dsPin" => { ds.pin(store, &text(command, "userId")?, &text(command, "aik")?)?; Ok(Value::Null) }
            "dsCreate" => Ok(ds.create(store, &text(command, "groupInfo")?, &text(command, "tree")?)?),
            "dsRepin" => { ds.repin(store, &text(command, "userId")?, &text(command, "aik")?)?; Ok(Value::Null) }
            "dsSucceed" => {
                let records = command.get("records").and_then(Value::as_array).ok_or_else(|| ChatError::coded("invalid", "records must be a list"))?;
                ds.succeed(store, &text(command, "userId")?, records)?;
                Ok(Value::Null)
            }
            "dsKeyPackage" => ok(ds.key_package(store, &text(command, "keyPackage")?)?),
            "dsMembers" => ok(ds.members(store, &group()?)?),
            "dsSubmit" => ok(ds.submit_as(store, &group()?, &text(command, "message")?, expect(command)?)?),
            "dsEpoch" => Ok(json!(ds.epoch(&group()?)?)),
            "dsTree" => ok(ds.tree(&group()?)?),
            "dsSnapshot" => ok(ds.snapshot(&group()?)?),
            "dsRestore" => Ok(ds.restore(store, &group()?, &text(command, "snapshot")?)?),
            other => Err(ChatError::transient(format!("unknown command {other}"))),
        }
    })();
    Some(result)
}
