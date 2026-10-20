//! The MLS and delivery-service commands end to end through the JSON command protocol, with real cores: the
//! path the browser worker, the node interop party and the Bun delivery service take. Account keys come from each
//! core's 1:1 identity and are pinned the way contacts are (`notePeer`).
#![cfg(all(feature = "mls", feature = "ds"))]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chatcore::commands::respond;
use chatcore::core::Core;
use chatcore::store::{MemoryStore, Store};
use serde_json::{json, Value};

fn id() -> String { URL_SAFE_NO_PAD.encode(rand_core::RngCore::next_u64(&mut rand_core::OsRng).to_be_bytes().repeat(2)) }

/// The account key, read from the identity row (the crate itself offers no accessor to it).
fn aik_of(core: &mut Core) -> ed25519_dalek::SigningKey {
    let row = core.store_mut().get("identity").unwrap().unwrap();
    let identity: chatcore::protocol::Identity = serde_json::from_value(row).unwrap();
    ed25519_dalek::SigningKey::from_bytes(&identity.sign.0)
}

fn core() -> Core { Core::new(Box::new(MemoryStore::default())) }

fn call(core: &mut Core, command: Value) -> Value {
    let out = respond(core, &command);
    assert!(out.get("error").is_none(), "{command}: {out}");
    out["ok"].clone()
}

fn fails(core: &mut Core, command: Value) -> Value { respond(core, &command) }

#[test]
fn two_devices_and_a_delivery_service_over_json_commands() {
    let (alice_id, bob_id) = (id(), id());
    let (mut alice, mut bob, mut ds) = (core(), core(), core());
    let alice_identity = call(&mut alice, json!({ "cmd": "identity" }));
    let bob_identity = call(&mut bob, json!({ "cmd": "identity" }));
    // Contacts pin each other; the DS's device registry holds both account keys.
    call(&mut alice, json!({ "cmd": "notePeer", "contact": bob_id, "identity": bob_identity }));
    call(&mut bob, json!({ "cmd": "notePeer", "contact": alice_id, "identity": alice_identity }));
    call(&mut ds, json!({ "cmd": "dsPin", "userId": alice_id, "aik": alice_identity["sign"] }));
    call(&mut ds, json!({ "cmd": "dsPin", "userId": bob_id, "aik": bob_identity["sign"] }));

    let cert = call(&mut alice, json!({ "cmd": "mlsInitDevice", "userId": alice_id, "deviceId": id(), "platform": "linux", "issuedAt": 1 }));
    assert_eq!(cert["aikSign"], alice_identity["sign"], "certified by the core's own account key");
    call(&mut bob, json!({ "cmd": "mlsInitDevice", "userId": bob_id, "deviceId": id(), "platform": "web", "issuedAt": 1 }));

    let group = id();
    let roles = json!({ "v": 1, "kind": "group", "admins": [alice_id], "joinPolicy": "invite" });
    let view = call(&mut alice, json!({ "cmd": "mlsCreate", "group": group, "roles": roles }));
    call(&mut ds, json!({ "cmd": "dsCreate", "groupInfo": view["groupInfo"], "tree": view["tree"] }));

    let kps = call(&mut bob, json!({ "cmd": "mlsKeyPackages", "count": 2 }));
    let out = call(&mut alice, json!({ "cmd": "mlsCommit", "group": group, "adds": [kps[0]] }));
    let pending = call(&mut alice, json!({ "cmd": "mlsPending", "group": group }));
    assert_eq!(pending["digest"], out["digest"]);
    let verdict = call(&mut ds, json!({ "cmd": "dsSubmit", "group": group, "message": out["commit"] }));
    assert_eq!(verdict["accepted"]["epoch"], 1);
    let merged = call(&mut alice, json!({ "cmd": "mlsMergeOwn", "group": group }));
    assert_eq!(merged["epoch"], 1);
    let tree = call(&mut ds, json!({ "cmd": "dsTree", "group": group }));
    call(&mut bob, json!({ "cmd": "mlsJoin", "welcome": out["welcome"], "tree": tree }));
    assert_eq!(call(&mut ds, json!({ "cmd": "dsEpoch", "group": group })), 1);

    let payload = json!({ "v": 2, "type": "message", "id": "123e4567-e89b-42d3-a456-426614174000", "text": "hello over MLS", "createdAt": 5, "expiresAt": null }).to_string();
    assert_eq!(call(&mut alice, json!({ "cmd": "mlsValidate", "payload": payload, "sender": alice_id })), "message");
    let sealed = call(&mut alice, json!({ "cmd": "mlsEncrypt", "group": group, "plaintext": payload }));
    let verdict = call(&mut ds, json!({ "cmd": "dsSubmit", "group": group, "message": sealed }));
    assert_eq!(verdict["accepted"]["epoch"], 1);
    let received = call(&mut bob, json!({ "cmd": "mlsReceive", "group": group, "message": sealed }));
    assert_eq!(received["plaintext"], payload);
    assert_eq!(received["sender"]["userId"], alice_id);
    assert_eq!(received["sender"]["admin"], true);

    // `expect` names what a log entry should be; the wrong kind is refused before anything is staged.
    let probe = call(&mut alice, json!({ "cmd": "mlsEncrypt", "group": group, "plaintext": "{}" }));
    assert_eq!(fails(&mut bob, json!({ "cmd": "mlsReceive", "group": group, "message": probe, "expect": "commit" }))["code"], "invalid");
    assert_eq!(fails(&mut bob, json!({ "cmd": "mlsReceive", "group": group, "message": probe, "expect": "proposal" }))["code"], "invalid");
    assert_eq!(fails(&mut ds, json!({ "cmd": "dsSubmit", "group": group, "message": probe, "expect": "commit" }))["code"], "invalid");
    assert_eq!(call(&mut ds, json!({ "cmd": "dsSubmit", "group": group, "message": probe, "expect": "application" }))["accepted"]["epoch"], 1);
    assert_eq!(call(&mut bob, json!({ "cmd": "mlsReceive", "group": group, "message": probe, "expect": "application" }))["plaintext"], "{}");

    // Two-phase receive: nothing persists until the caller commits.
    let second = call(&mut alice, json!({ "cmd": "mlsEncrypt", "group": group, "plaintext": "{}" }));
    let staged = call(&mut bob, json!({ "cmd": "mlsReceive", "group": group, "message": second, "commit": false }));
    call(&mut bob, json!({ "cmd": "mlsCommitReceived", "pendingId": staged["pendingId"] }));
    assert_eq!(fails(&mut bob, json!({ "cmd": "mlsReceive", "group": group, "message": second }))["code"], "replay");

    let members = call(&mut bob, json!({ "cmd": "mlsMembers", "group": group }));
    assert_eq!(members.as_array().unwrap().len(), 2);
    assert_eq!(call(&mut bob, json!({ "cmd": "mlsRoles", "group": group }))["admins"], json!([alice_id]));
    assert_eq!(call(&mut bob, json!({ "cmd": "mlsView", "group": group }))["epoch"], 1);

    // A frozen-channel resolution is signed with the admin device's leaf key and checked by any member.
    let digest = "ab".repeat(32);
    let signature = call(&mut alice, json!({ "cmd": "mlsSignResolution", "group": group, "action": "rollback", "seq": 3, "digest": digest, "author": "" }));
    let signer = call(&mut bob, json!({ "cmd": "mlsVerifyResolution", "group": group, "action": "rollback", "seq": 3, "digest": digest, "author": "", "by": cert["deviceId"], "byUser": alice_id, "signature": signature }));
    assert_eq!(signer, json!({ "userId": alice_id, "deviceId": cert["deviceId"] }));
    assert_eq!(fails(&mut bob, json!({ "cmd": "mlsVerifyResolution", "group": group, "action": "dismiss", "seq": 3, "digest": digest, "author": "", "by": cert["deviceId"], "byUser": alice_id, "signature": signature }))["code"], "auth");
    assert_eq!(fails(&mut alice, json!({ "cmd": "mlsSignResolution", "group": group, "action": "remove", "seq": 3, "digest": digest }))["code"], "invalid");

    // A conflict leaves nothing behind; a stale commit is answered, not applied.
    let stale = call(&mut bob, json!({ "cmd": "mlsCommit", "group": group, "update": true }));
    call(&mut ds, json!({ "cmd": "dsSubmit", "group": group, "message": stale["commit"] }));
    let out = call(&mut alice, json!({ "cmd": "mlsCommit", "group": group, "update": true }));
    assert_eq!(call(&mut ds, json!({ "cmd": "dsSubmit", "group": group, "message": out["commit"] }))["conflict"]["epoch"], 2);
    call(&mut alice, json!({ "cmd": "mlsClearOwn", "group": group }));
    assert_eq!(call(&mut alice, json!({ "cmd": "mlsPending", "group": group })), Value::Null);

    // Failures keep their dispositions.
    assert_eq!(fails(&mut alice, json!({ "cmd": "mlsCommit", "group": group, "removes": [{ "userId": id() }] }))["code"], "invalid");
    assert_eq!(fails(&mut alice, json!({ "cmd": "mlsEncrypt", "group": id(), "plaintext": "x" }))["code"], "unknown-group");
    assert_eq!(fails(&mut alice, json!({ "cmd": "mlsCreate", "group": id(), "roles": { "nope": 1 } }))["code"], "invalid");
    assert!(fails(&mut alice, json!({ "cmd": "mlsNope" })).get("error").is_some());
}

#[test]
fn a_device_certificate_signed_elsewhere_must_name_the_prepared_key_and_this_cores_account() {
    let user = id();
    let mut web = core();
    let identity = call(&mut web, json!({ "cmd": "identity" }));
    let leaf = call(&mut web, json!({ "cmd": "mlsDeviceLeaf" }));
    assert_eq!(call(&mut web, json!({ "cmd": "mlsDeviceLeaf" })), leaf, "created once");

    // A certificate signed by some other account key is refused, even for the right leaf key.
    let other = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let leaf_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(leaf.as_str().unwrap()).unwrap().try_into().unwrap();
    let forged = chatcore::mls::cert::DeviceCert::issue(&other, &user, &id(), "web", &leaf_bytes, 1).unwrap();
    let out = fails(&mut web, json!({ "cmd": "mlsSetDeviceCert", "cert": String::from_utf8(forged.encode()).unwrap() }));
    assert_eq!(out["code"], "invalid");

    // Signed with the account key (as the web client does in WebCrypto): installed.
    let device = id();
    let signed = chatcore::mls::cert::DeviceCert::issue(&aik_of(&mut web), &user, &device, "web", &leaf_bytes, 1).unwrap();
    let cert = call(&mut web, json!({ "cmd": "mlsSetDeviceCert", "cert": String::from_utf8(signed.encode()).unwrap() }));
    assert_eq!(cert["deviceId"], device);
    assert_eq!(cert["aikSign"], identity["sign"]);
    assert_eq!(call(&mut web, json!({ "cmd": "mlsKeyPackages", "count": 1 })).as_array().unwrap().len(), 1);
}
