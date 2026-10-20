//! The JSON command protocol shared by every message-driven caller of a [`Core`]: the interop CLI
//! (tests/interop), the WASM build (the browser worker and the node interop party). One command object
//! in; `{"ok": value}` or `{"error": message, "code": code|null}` out. Commands: identity, prekeys, opks,
//! encrypt, decrypt, commit, abort, rotate, sessionInfo, sids, resetIdentity, safety, peer, notePeer,
//! setVerified, acceptChange, forget, rotationInterval, sas, sasCommitment, sasCheck, sasNonce, proveIdentity; with the
//! `mls` feature the `mls*` group commands and with `ds` the `ds*` delivery-service commands (crate::mls::commands).
use serde_json::{json, Value};

use crate::core::Core;
use crate::error::ChatError;
use crate::protocol::{Bundle, IdentityPub};
use crate::sas;
use crate::EncryptOutcome;

/// Runs one command and wraps the outcome the way every driver reports it.
/// The optional `identity` of `acceptChange` / `setVerified`: the exact code the user was shown.
fn shown_identity(command: &Value) -> crate::error::Result<Option<IdentityPub>> {
    match command.get("identity") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone()).map(Some).map_err(|_| ChatError::coded("invalid", "malformed identity")),
    }
}

pub fn respond(core: &mut Core, command: &Value) -> Value {
    match run(core, command) {
        Ok(value) => json!({ "ok": value }),
        Err(error) => match &error.class {
            Some(class) => json!({ "error": error.message, "code": error.code, "class": class }),
            None => json!({ "error": error.message, "code": error.code }),
        },
    }
}

fn now(command: &Value) -> u64 { command.get("now").and_then(Value::as_u64).unwrap_or(0) }

fn text(command: &Value, key: &str) -> Result<String, ChatError> {
    command.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| ChatError::transient(format!("missing {key}")))
}

pub fn run(core: &mut Core, command: &Value) -> Result<Value, ChatError> {
    let cmd = text(command, "cmd")?;
    match cmd.as_str() {
        "identity" => Ok(json!(core.public_identity()?)),
        "prekeys" => {
            let now = command.get("now").and_then(Value::as_u64).unwrap_or(0);
            let max_age = command.get("maxAge").and_then(Value::as_u64);
            Ok(json!(core.prekeys(now, max_age)?))
        }
        "opks" => Ok(json!(core.one_time_prekeys(command.get("count").and_then(Value::as_u64).unwrap_or(1))?)),
        "encrypt" => {
            let bundle: Option<Bundle> = match command.get("bundle") {
                Some(Value::Null) | None => None,
                Some(value) => Some(serde_json::from_value(value.clone()).map_err(|_| ChatError::transient("Invalid key bundle"))?),
            };
            match core.encrypt_to(&text(command, "contact")?, &text(command, "plaintext")?, bundle.as_ref())? {
                EncryptOutcome::Envelope(envelope) => Ok(json!({ "envelope": envelope })),
                EncryptOutcome::NeedsBundle => Ok(json!({ "needsBundle": true })),
            }
        }
        "decrypt" => {
            let published: Option<IdentityPub> = match command.get("published") {
                Some(Value::Null) | None => None,
                Some(value) => serde_json::from_value(value.clone()).ok(),
            };
            let decrypted = core.decrypt_from(&text(command, "contact")?, &text(command, "envelope")?, published.as_ref())?;
            let commit = command.get("commit").and_then(Value::as_bool).unwrap_or(true);
            // `rotate`: the app treats this payload as the peer's session reset (signal.js handle() → {rotate:true}).
            let rotate = command.get("rotate").and_then(Value::as_bool).unwrap_or(false);
            let recorded = if commit { Some(core.commit(&decrypted.pending_id, rotate)?) } else { None };
            Ok(json!({
                "plaintext": decrypted.plaintext_json, "identityChanged": decrypted.identity_changed, "firstContact": decrypted.first_contact,
                "identity": decrypted.identity, "pendingId": decrypted.pending_id, "identityRecorded": recorded,
            }))
        }
        "commit" => Ok(json!(core.commit(&text(command, "pendingId")?, command.get("rotate").and_then(Value::as_bool).unwrap_or(false))?)),
        "rotate" => { core.rotate(&text(command, "contact")?)?; Ok(Value::Null) }
        "sessionInfo" => Ok(match core.session_info(&text(command, "contact")?)? { Some((sid, started)) => json!({ "sid": sid, "startedAt": started }), None => Value::Null }),
        "sids" => {
            let contact = text(command, "contact")?;
            let record = core.store_mut().get(&format!("sessions:{contact}"))?;
            Ok(record.and_then(|value| value.get("order").cloned()).unwrap_or(json!([])))
        }
        "proveIdentity" => Ok(json!(core.prove_identity(&text(command, "userId")?, &text(command, "deviceId")?, &text(command, "challenge")?)?)),
        "resetIdentity" => { core.reset_identity()?; Ok(Value::Null) }
        "safety" => Ok(match core.safety(&text(command, "me")?, &text(command, "contact")?, &text(command, "them")?)? {
            Some(safety) => json!({ "number": safety.number, "verified": safety.verified, "changed": safety.changed, "blocked": safety.blocked }),
            None => Value::Null,
        }),
        "peer" => Ok(json!(core.peer(&text(command, "contact")?)?)),
        "setVerified" => { core.set_verified_for(&text(command, "contact")?, command.get("verified").and_then(Value::as_bool).unwrap_or(true), shown_identity(command)?.as_ref())?; Ok(Value::Null) }
        "acceptChange" => { core.accept_change_for(&text(command, "contact")?, shown_identity(command)?.as_ref())?; Ok(Value::Null) }
        "forget" => { core.forget(&text(command, "contact")?)?; Ok(Value::Null) }
        "abort" => { core.abort(&text(command, "pendingId")?); Ok(Value::Null) }
        "notePeer" => {
            let identity: IdentityPub = serde_json::from_value(command.get("identity").cloned().unwrap_or(Value::Null)).map_err(|_| ChatError::transient("Invalid identity"))?;
            Ok(json!(core.note_peer(&text(command, "contact")?, &identity)?))
        }
        "rotationInterval" => Ok(json!(crate::core::rotation_interval(
            command.get("mine").and_then(Value::as_u64).unwrap_or(0),
            command.get("theirs").and_then(Value::as_u64).unwrap_or(0),
        ))),
        "sasNonce" => Ok(json!(sas::new_nonce())),
        "sas" => {
            let nonces: Vec<String> = command.get("nonces").and_then(Value::as_array).map(|list| list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            if nonces.len() != 2 { return Err(ChatError::transient("nonces")); }
            Ok(json!(sas::sas_from_sdp(&text(command, "localSdp")?, &text(command, "remoteSdp")?, [&nonces[0], &nonces[1]])?))
        }
        "sasCommitment" => Ok(json!(sas::commitment(&text(command, "nonce")?)?)),
        "sasCheck" => Ok(json!(sas::check_reveal(&text(command, "commitment")?, &text(command, "nonce")?))),
        // Linked devices (docs/m5-linking.md): the link crypto, pins, succession.
        "linkQr" => Ok(json!({ "qr": core.link_qr(&text(command, "linkId")?, now(command))? })),
        "linkAccept" => Ok(json!(core.link_accept(&text(command, "qr")?, now(command))?)),
        "linkComplete" => Ok(json!({ "code": core.link_complete(&text(command, "linkId")?, &text(command, "eph")?, now(command))? })),
        "linkSeal" => Ok(json!(core.link_seal(&text(command, "linkId")?, &text(command, "plaintext")?, now(command))?)),
        "linkOpen" => Ok(json!(core.link_open(&text(command, "linkId")?, &text(command, "data")?, now(command))?)),
        // Short-code rendezvous (docs/m5-linking.md §1.7).
        "linkCommit" => Ok(json!({ "commit": core.link_commit(&text(command, "linkId")?, &text(command, "deviceId")?, now(command))? })),
        "linkReveal" => { let (eph, nonce) = core.link_reveal(&text(command, "linkId")?, &text(command, "eph")?, now(command))?; Ok(json!({ "eph": eph, "nonce": nonce })) }
        "linkLookup" => Ok(json!({ "eph": core.link_lookup(&text(command, "linkId")?, &text(command, "deviceN")?, &text(command, "commit")?, &text(command, "deviceP")?, now(command))? })),
        "linkOpenCommitment" => Ok(json!({ "code": core.link_open_commitment(&text(command, "linkId")?, &text(command, "eph")?, &text(command, "nonce")?, now(command))? })),
        "linkCompleteCode" => Ok(json!({ "code": core.link_complete_code(&text(command, "linkId")?, &text(command, "eph")?, &text(command, "deviceP")?, now(command))? })),
        "linkEnd" => { core.link_end(&text(command, "linkId")?)?; Ok(Value::Null) }
        "exportPins" => Ok(json!(core.export_pins()?)),
        "importPins" => {
            let pins: Vec<crate::core::PinExport> = serde_json::from_value(command.get("pins").cloned().unwrap_or(Value::Null)).map_err(|_| ChatError::coded("invalid", "Invalid pins"))?;
            Ok(json!(core.import_pins(&pins)?))
        }
        "successionStart" => Ok(json!(core.succession_start()?)),
        "successionComplete" => Ok(json!(core.succession_complete(command.get("record").unwrap_or(&Value::Null), &text(command, "signature")?)?)),
        "signSuccession" => Ok(core.sign_succession(&text(command, "userId")?, &text(command, "published")?, &text(command, "newSign")?, &text(command, "newDh")?, command.get("at").and_then(Value::as_u64).unwrap_or(0))?),
        "retireIdentity" => {
            let identity: IdentityPub = serde_json::from_value(command.get("identity").cloned().unwrap_or(Value::Null)).map_err(|_| ChatError::coded("invalid", "Invalid identity"))?;
            core.retire_identity(&text(command, "userId")?, &identity, command.get("at").and_then(Value::as_u64).unwrap_or(0))?;
            Ok(Value::Null)
        }
        "acceptSuccession" => {
            let records = command.get("records").and_then(Value::as_array).ok_or_else(|| ChatError::coded("invalid", "records must be a list"))?;
            Ok(json!(core.accept_succession(&text(command, "contact")?, records)?))
        }
        other => {
            #[cfg(any(feature = "mls", feature = "ds"))]
            if let Some(result) = crate::mls::commands::run(core, other, command) { return result; }
            Err(ChatError::transient(format!("unknown command {other}")))
        }
    }
}

