//! Certificates, roles, payloads, ids and limits on their own.
use serde_json::{json, Value};

use super::harness::*;
use crate::mls::cert::{canonical_id, DeviceCert};
use crate::mls::engine::group_id;
use crate::mls::payload::{validate, Context};
use crate::mls::policy::{JoinPolicy, Roles};

fn cert(account: &Account) -> DeviceCert { DeviceCert::issue(&account.aik, &account.id, &rid(), "web", &[9u8; 32], 123).unwrap() }

#[test]
fn a_certificate_round_trips_and_verifies_only_under_its_account_key() {
    let (alice, mallory) = (Account::new(), Account::new());
    let c = cert(&alice);
    let aik = alice.aik.verifying_key().to_bytes();
    assert_eq!(DeviceCert::decode(&c.encode()).unwrap(), c);
    c.verify(&aik, &[9u8; 32]).unwrap();
    assert!(c.verify(&mallory.aik.verifying_key().to_bytes(), &[9u8; 32]).is_err(), "another account key");
    assert!(c.verify(&aik, &[8u8; 32]).is_err(), "another leaf key");

    for (field, replacement) in [("userId", json!(rid())), ("deviceId", json!(rid())), ("platform", json!("ios")), ("issuedAt", json!(124))] {
        let mut value: Value = serde_json::from_slice(&c.encode()).unwrap();
        value[field] = replacement;
        let tampered = DeviceCert::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(tampered.verify(&aik, &[9u8; 32]).is_err(), "{field} is signed");
    }
}

#[test]
fn certificates_have_exactly_one_encoding() {
    let c = cert(&Account::new());
    let text = String::from_utf8(c.encode()).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();

    // Whitespace, reordered fields, unknown fields and padding all fail.
    assert!(DeviceCert::decode(serde_json::to_string_pretty(&value).unwrap().as_bytes()).is_err());
    let mut reordered = serde_json::Map::new();
    for key in ["v", "deviceId", "userId", "platform", "leafSigKey", "aikSign", "issuedAt", "sig"] { reordered.insert(key.into(), value[key].clone()); }
    assert!(DeviceCert::decode(Value::Object(reordered).to_string().as_bytes()).is_err());
    let mut extra = value.clone();
    extra["extra"] = json!(1);
    assert!(DeviceCert::decode(extra.to_string().as_bytes()).is_err());
    let mut padded = value.clone();
    padded["leafSigKey"] = json!(format!("{}=", value["leafSigKey"].as_str().unwrap()));
    assert!(DeviceCert::decode(padded.to_string().as_bytes()).is_err());
    let mut platform = value.clone();
    platform["platform"] = json!("toaster");
    assert!(DeviceCert::decode(platform.to_string().as_bytes()).is_err());
    let mut version = value;
    version["v"] = json!(2);
    assert!(DeviceCert::decode(version.to_string().as_bytes()).is_err());
    assert!(DeviceCert::decode(b"").is_err());
    assert!(DeviceCert::decode(&vec![b' '; 1025]).unwrap_err().message.contains("too large"));
}

#[test]
fn ids_are_one_canonical_string_each() {
    assert!(canonical_id(&rid()));
    for bad in ["", "short", &"A".repeat(21), &"A".repeat(23), &format!("{}=", &rid()[..22]), &format!("{}+", &rid()[..21]), "AAAAAAAAAAAAAAAAAAAAA!"] {
        assert!(!canonical_id(bad), "{bad:?}");
    }
    assert!(!canonical_id("AAAAAAAAAAAAAAAAAAAAAB"), "the spare bits of the last character must be zero");
    assert!(canonical_id("AAAAAAAAAAAAAAAAAAAAAA"));
    assert!(group_id("AAAA").is_ok());
    assert!(group_id("").is_err());
    assert!(group_id("AB").is_err(), "does not re-encode");
    assert!(group_id("AAA=").is_err(), "padding");
    assert!(group_id(&b64(&[1u8; 65])).is_err());
    assert!(group_id(&b64(&[1u8; 64])).is_ok());
}

#[test]
fn roles_decode_strictly() {
    let (a, b) = (rid(), rid());
    let good = Roles::group(vec![a.clone()], JoinPolicy::Invite);
    assert_eq!(Roles::decode(&good.encode()).unwrap(), good);
    let dm = Roles::dm(&a, &b);
    assert_eq!(Roles::decode(&dm.encode()).unwrap(), dm);

    let reject = |value: Value| assert!(Roles::decode(value.to_string().as_bytes()).is_err(), "{value}");
    reject(json!({ "v": 1, "kind": "group", "admins": [], "joinPolicy": "invite" }));
    reject(json!({ "v": 1, "kind": "group", "admins": [a, a], "joinPolicy": "invite" }));
    reject(json!({ "v": 1, "kind": "group", "admins": ["nope"], "joinPolicy": "invite" }));
    reject(json!({ "v": 2, "kind": "group", "admins": [a], "joinPolicy": "invite" }));
    reject(json!({ "v": 1, "kind": "group", "admins": [a], "joinPolicy": "invite", "extra": 1 }));
    reject(json!({ "v": 1, "kind": "group", "admins": [a], "joinPolicy": "invite", "dm": [a, b] }));
    reject(json!({ "v": 1, "kind": "dm", "admins": [a], "joinPolicy": "invite" }));
    reject(json!({ "v": 1, "kind": "dm", "admins": [a, b], "joinPolicy": "open", "dm": [a, b] }));
    assert!(Roles::decode(b"{}").is_err());
    assert!(Roles::decode(&good.encode().iter().chain(b" ").copied().collect::<Vec<_>>()).is_err(), "trailing bytes");
    assert!(Roles::decode(serde_json::to_string_pretty(&good).unwrap().as_bytes()).is_err(), "not the canonical encoding");
    // 65 admins, and over 4 KiB.
    let many: Vec<String> = (0..65).map(|_| rid()).collect();
    assert!(Roles::decode(&Roles::group(many, JoinPolicy::Open).encode()).is_err());
    assert!(Roles::decode(&vec![b' '; 4097]).unwrap_err().message.contains("too large"));
    // A DM's users are sorted.
    let (lo, hi) = if a < b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
    assert_eq!(Roles::dm(&hi, &lo).dm.unwrap(), vec![lo, hi]);
}

#[test]
fn only_a_valid_creator_may_create() {
    let alice = Account::new();
    let bob = Account::new();
    let mut a1 = Dev::new(&alice, "linux", &[&alice, &bob]);
    let mut server = Server::new(&[&alice, &bob]);
    // The creator must be an admin / one of a DM's users, and can't create the same group twice.
    assert!(a1.groups.create(&mut a1.store, &group_id("AAAA").unwrap(), &Roles::group(vec![bob.id.clone()], JoinPolicy::Open)).is_err());
    assert!(a1.groups.create(&mut a1.store, &group_id("AAAA").unwrap(), &Roles::dm(&bob.id, &rid())).is_err());
    a1.create(&mut server, "AAAA", &Roles::group(vec![alice.id.clone()], JoinPolicy::Open));
    assert!(a1.groups.create(&mut a1.store, &group_id("AAAA").unwrap(), &Roles::group(vec![alice.id.clone()], JoinPolicy::Open)).is_err());
    assert_eq!(a1.groups.roles(&mut a1.store, &group_id("AAAA").unwrap()).unwrap().join_policy, JoinPolicy::Open);
    assert_eq!(a1.groups.group_view(&mut a1.store, &group_id("AAAA").unwrap()).unwrap().epoch, 0);
}

#[test]
fn key_package_batches_are_bounded() {
    let alice = Account::new();
    let mut a1 = Dev::new(&alice, "linux", &[&alice]);
    assert!(a1.groups.key_packages(&mut a1.store, 0, false).is_err());
    assert!(a1.groups.key_packages(&mut a1.store, 101, false).is_err());
    let batch = a1.groups.key_packages(&mut a1.store, 100, false).unwrap();
    assert_eq!(batch.len(), 100);
    assert!(batch.iter().all(|k| k.len() < 4 * 1024 * 4 / 3), "each KeyPackage fits the 4 KiB limit");
    assert_eq!(batch.iter().collect::<std::collections::HashSet<_>>().len(), 100);
}

#[test]
fn the_digest_is_sha256_hex() {
    assert_eq!(crate::mls::digest(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

fn ctx(sender: &str, admin: bool, target: Option<&str>) -> Context { Context { sender: sender.into(), sender_is_admin: admin, target_sender: target.map(str::to_string) } }
fn uuid() -> String { "123e4567-e89b-42d3-a456-426614174000".into() }
fn other_uuid() -> String { "123e4567-e89b-42d3-a456-426614174001".into() }

#[test]
fn payloads_accept_exactly_their_schema() {
    let (u, t) = (uuid(), other_uuid());
    let member = ctx("u1", false, Some("u1"));
    let admin = ctx("u1", true, Some("u2"));
    let accepted: Vec<(Value, &Context)> = vec![
        (json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1000, "expiresAt": null }), &member),
        (json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1000, "expiresAt": 2000, "thread": t, "mentions": [rid()], "format": "md",
                 "attachments": [{ "blobId": "b", "key": "k", "digest": "d", "size": 3, "mime": "text/plain", "name": "a.txt" }] }), &member),
        (json!({ "v": 2, "type": "edit", "id": u, "target": t, "text": "x", "editedAt": 5 }), &member),
        (json!({ "v": 2, "type": "delete", "id": u, "target": t }), &admin),
        (json!({ "v": 2, "type": "reaction", "id": u, "target": t, "emoji": "x", "op": "add" }), &member),
        (json!({ "v": 2, "type": "pin", "id": u, "target": t, "op": "pin" }), &admin),
        (json!({ "v": 2, "type": "topic", "id": u, "topic": "news" }), &admin),
        (json!({ "v": 2, "type": "settings", "id": u, "expireAfter": 3_600_000, "history": "none" }), &admin),
        (json!({ "v": 2, "type": "settings", "id": u, "expireAfter": null, "history": "share-30d" }), &admin),
        (json!({ "v": 2, "type": "receipt", "id": u, "upTo": 7, "kind": "read" }), &member),
        (json!({ "v": 2, "type": "poll", "id": u, "question": "q", "options": ["a", "b"], "multi": false }), &member),
        (json!({ "v": 2, "type": "vote", "id": u, "poll": t, "choices": [0, 1] }), &member),
        (json!({ "v": 2, "type": "command", "id": u, "bot": rid(), "name": "poll", "args": "a b", "visibility": "ephemeral" }), &member),
        (json!({ "v": 2, "type": "burn", "id": u }), &admin),
        (json!({ "v": 2, "type": "typing", "state": "start" }), &member),
    ];
    for (payload, context) in &accepted {
        let kind = validate(&payload.to_string(), context).unwrap_or_else(|e| panic!("{payload}: {e}"));
        assert_eq!(kind, payload["type"].as_str().unwrap());
    }
}

#[test]
fn payloads_reject_everything_else() {
    let (u, t) = (uuid(), other_uuid());
    let member = ctx("u1", false, Some("u1"));
    let stranger = ctx("u1", false, Some("u2"));
    let admin = ctx("u1", true, Some("u2"));
    let unknown_target = ctx("u1", false, None);
    let rejected: Vec<(&str, Value, &Context)> = vec![
        ("unknown type", json!({ "v": 2, "type": "nuke", "id": u }), &member),
        ("version 1", json!({ "v": 1, "type": "message", "id": u, "text": "hi", "createdAt": 1, "expiresAt": null }), &member),
        ("no version", json!({ "type": "message", "id": u, "text": "hi", "createdAt": 1, "expiresAt": null }), &member),
        ("unknown field", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1, "expiresAt": null, "admin": true }), &member),
        ("missing field", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1 }), &member),
        ("bad id", json!({ "v": 2, "type": "message", "id": "7", "text": "hi", "createdAt": 1, "expiresAt": null }), &member),
        ("upper-case id", json!({ "v": 2, "type": "message", "id": u.to_uppercase(), "text": "hi", "createdAt": 1, "expiresAt": null }), &member),
        ("blank text", json!({ "v": 2, "type": "message", "id": u, "text": "  ", "createdAt": 1, "expiresAt": null }), &member),
        ("huge text", json!({ "v": 2, "type": "message", "id": u, "text": "x".repeat(16 * 1024 + 1), "createdAt": 1, "expiresAt": null }), &member),
        ("expiry before creation", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 10, "expiresAt": 5 }), &member),
        ("expiry beyond 30 days", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 10, "expiresAt": 10 + 31 * 86_400_000u64 }), &member),
        ("bad mention", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1, "expiresAt": null, "mentions": ["x"] }), &member),
        ("bad format", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1, "expiresAt": null, "format": "html" }), &member),
        ("11 attachments", json!({ "v": 2, "type": "message", "id": u, "text": "hi", "createdAt": 1, "expiresAt": null,
                 "attachments": (0..11).map(|_| json!({ "blobId": "b", "key": "k", "digest": "d", "size": 3, "mime": "m", "name": "n" })).collect::<Vec<_>>() }), &member),
        ("edit of someone else's message", json!({ "v": 2, "type": "edit", "id": u, "target": t, "text": "x", "editedAt": 5 }), &stranger),
        ("edit of an unknown message", json!({ "v": 2, "type": "edit", "id": u, "target": t, "text": "x", "editedAt": 5 }), &unknown_target),
        ("delete by a non-admin stranger", json!({ "v": 2, "type": "delete", "id": u, "target": t }), &stranger),
        ("pin by a non-admin", json!({ "v": 2, "type": "pin", "id": u, "target": t, "op": "pin" }), &member),
        ("topic by a non-admin", json!({ "v": 2, "type": "topic", "id": u, "topic": "x" }), &member),
        ("settings by a non-admin", json!({ "v": 2, "type": "settings", "id": u, "expireAfter": null, "history": "none" }), &member),
        ("odd expiry choice", json!({ "v": 2, "type": "settings", "id": u, "expireAfter": 5, "history": "none" }), &admin),
        ("burn by a non-admin", json!({ "v": 2, "type": "burn", "id": u }), &member),
        ("typing with an id", json!({ "v": 2, "type": "typing", "id": u, "state": "start" }), &member),
        ("one poll option", json!({ "v": 2, "type": "poll", "id": u, "question": "q", "options": ["a"], "multi": false }), &member),
        ("duplicate votes", json!({ "v": 2, "type": "vote", "id": u, "poll": t, "choices": [1, 1] }), &member),
        ("bad command name", json!({ "v": 2, "type": "command", "id": u, "bot": rid(), "name": "Poll!", "args": "", "visibility": "channel" }), &member),
        ("bad reaction op", json!({ "v": 2, "type": "reaction", "id": u, "target": t, "emoji": "x", "op": "toggle" }), &member),
    ];
    for (name, payload, context) in &rejected {
        let err = validate(&payload.to_string(), context).expect_err(name);
        assert_eq!(err.code(), Some("invalid"), "{name}");
    }
    for raw in ["", "null", "[]", "\"x\"", "{", &"x".repeat(64 * 1024 + 1)] {
        assert_eq!(validate(raw, &member).unwrap_err().code(), Some("invalid"), "{raw:.20}");
    }
}
