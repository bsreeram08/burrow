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

fn ok<T: serde::Serialize>(value: T) -> Result<Value> { Ok(serde_json::to_value(value).expect("serializes")) }

/// `None`: not an MLS command.
pub fn run(core: &mut Core, cmd: &str, command: &Value) -> Option<Result<Value>> {
    #[cfg(feature = "mls")]
    if cmd.starts_with("mls") { return run_mls(core, cmd, command); }
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
                let aik = core.account_signing_key()?.verifying_key().to_bytes();
                let (groups, store) = core.groups()?;
                return ok(groups.set_device_cert(store, &text(command, "cert")?, &aik)?);
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
            "mlsMergeOwn" => ok(groups.merge_own(store, &group()?)?),
            "mlsClearOwn" => { groups.clear_own(store, &group()?)?; Ok(Value::Null) }
            "mlsPending" => ok(groups.pending_commit(store, &group()?)?),
            "mlsJoin" => ok(groups.join(store, &text(command, "welcome")?, &text(command, "tree")?)?),
            "mlsJoinExternal" => ok(groups.join_external(store, &text(command, "groupInfo")?, &text(command, "tree")?)?),
            "mlsForget" => { groups.forget_group(store, &group()?)?; Ok(Value::Null) }
            "mlsEncrypt" => ok(groups.encrypt(store, &group()?, &text(command, "plaintext")?)?),
            "mlsReceive" => {
                let processed = groups.process(store, &group()?, &text(command, "message")?)?;
                // Like `decrypt`: commit unless the caller wants to store the message first (commit: false).
                if command.get("commit").and_then(Value::as_bool).unwrap_or(true) { groups.commit_pending(store, &processed.pending_id)?; }
                ok(processed)
            }
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
            "dsSubmit" => ok(ds.submit(store, &group()?, &text(command, "message")?)?),
            "dsEpoch" => Ok(json!(ds.epoch(&group()?)?)),
            "dsTree" => ok(ds.tree(&group()?)?),
            "dsSnapshot" => ok(ds.snapshot(&group()?)?),
            "dsRestore" => Ok(ds.restore(store, &group()?, &text(command, "snapshot")?)?),
            other => Err(ChatError::transient(format!("unknown command {other}"))),
        }
    })();
    Some(result)
}
