//! Linked devices end to end at the core: the link crypto (with pinned vectors for the ports), the sealed channel,
//! the primary signing a certificate for a companion, companion mode, pin transfer, and succession.
#![cfg(feature = "mls")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chatcore::core::{Core, PinExport};
use chatcore::protocol::IdentityPub;
use chatcore::store::MemoryStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn core() -> Core { Core::new(Box::new(MemoryStore::default())) }
fn b64(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }
fn id() -> String { b64(&rand_core::RngCore::next_u64(&mut rand_core::OsRng).to_be_bytes().repeat(2)) }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn code_of<T>(result: Result<T, chatcore::ChatError>) -> Option<String> { result.err().and_then(|e| e.code) }

#[test]
fn the_link_crypto_matches_its_pinned_vectors() {
    use chatcore::link::{derive, open, parse_qr, qr_text, seal, N2P, P2N};
    // Fixed inputs; the same values are asserted by the ports (see docs/m5-linking.md §12). The key derivation was
    // also computed independently (HKDF-SHA-256 over the documented bytes).
    let (link_id, eph_n, eph_p, secret, shared) = ([1u8; 16], [2u8; 32], [3u8; 32], [4u8; 16], [5u8; 32]);
    let qr = qr_text(&link_id, &eph_n, &secret);
    assert_eq!(qr, "wb-link1.AQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQEBAQEBAQEBAQEBAQEBAQ");
    assert_eq!(parse_qr(&qr).unwrap(), (link_id, eph_n, secret));
    let keys = derive(&shared, &secret, &link_id, &eph_n, &eph_p);
    assert_eq!(hex(&keys.n2p), "2be315e799993aec88ffd90b9aaaac2bb9abc6a997c636d518e99fb954184433");
    assert_eq!(hex(&Sha256::digest(keys.n2p)), "fe393dcbd455266e62cccf2bdd516699b6219824a50183b867e6600ab228ef0a");
    assert_eq!(hex(&Sha256::digest(keys.p2n)), "181e30671723195577a4194bb18509e6264cea42628bc0823921ccd945461386");
    assert_eq!(keys.code, "791 839");
    let first = seal(&keys.n2p, &link_id, N2P, 0, b"hello").unwrap();
    let later = seal(&keys.p2n, &link_id, P2N, 7, b"{\"v\":1}").unwrap();
    assert_eq!(first, "AAAAAAAAAAA7lVyChun4RCFi2xS97qW80fUovJo");
    assert_eq!(later, "AAAAAAAAAAfM3aBIGci52FbuMvu8xBrYUSSol0Ld3w");
    assert_eq!(open(&keys.n2p, &link_id, N2P, 0, &first).unwrap(), b"hello");
    // Counter, direction, link and key are all bound.
    assert_eq!(code_of(open(&keys.n2p, &link_id, N2P, 1, &first)).as_deref(), Some("replay"));
    assert_eq!(code_of(open(&keys.n2p, &link_id, P2N, 0, &first)).as_deref(), Some("auth"));
    assert_eq!(code_of(open(&keys.n2p, &[9u8; 16], N2P, 0, &first)).as_deref(), Some("auth"));
    assert_eq!(code_of(open(&keys.p2n, &link_id, N2P, 0, &first)).as_deref(), Some("auth"));
    let mut tampered = URL_SAFE_NO_PAD.decode(&first).unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(code_of(open(&keys.n2p, &link_id, N2P, 0, &b64(&tampered))).as_deref(), Some("auth"));
    assert!(parse_qr("wb-link1.AAAA").is_err() && parse_qr("nope").is_err());
    let mut wrong_version = URL_SAFE_NO_PAD.decode(qr.strip_prefix("wb-link1.").unwrap()).unwrap();
    wrong_version[0] = 2;
    assert!(parse_qr(&format!("wb-link1.{}", b64(&wrong_version))).is_err());
}

/// A primary with a published identity and a listed device, and a fresh device to link.
struct Pair { primary: Core, new: Core, user: String, identity: IdentityPub }

fn pair() -> Pair {
    let mut primary = core();
    let identity = primary.identity().unwrap().public;
    Pair { primary, new: core(), user: id(), identity }
}

fn list_json(user: &str, version: u64, prev: &str, devices: &[&str]) -> String {
    let mut sorted: Vec<&str> = devices.to_vec();
    sorted.sort();
    json!({ "v": 1, "userId": user, "version": version, "prevHash": prev,
        "devices": sorted.iter().map(|d| json!({ "deviceId": d, "addedAt": 1, "meta": "" })).collect::<Vec<_>>() }).to_string()
}

#[test]
fn a_new_device_links_through_a_sealed_channel_and_becomes_a_companion() {
    let mut w = pair();
    let (link, now) = (id(), 1_000_000u64);
    // N shows the QR; P scans; both derive the same code.
    let qr = w.new.link_qr(&link, now).unwrap();
    let accepted = w.primary.link_accept(&qr, now).unwrap();
    assert_eq!(accepted.link_id, link);
    let code = w.new.link_complete(&link, &accepted.eph, now).unwrap();
    assert_eq!(code, accepted.code);
    assert_eq!(code.len(), 7);

    // Sealed in both directions, counted, in order only.
    let hello = w.new.link_seal(&link, r#"{"v":1,"type":"hello"}"#, now).unwrap();
    let second = w.new.link_seal(&link, "second", now).unwrap();
    assert_eq!(code_of(w.primary.link_open(&link, &second, now)).as_deref(), Some("replay"), "out of order");
    assert_eq!(w.primary.link_open(&link, &hello, now).unwrap(), r#"{"v":1,"type":"hello"}"#);
    assert_eq!(code_of(w.primary.link_open(&link, &hello, now)).as_deref(), Some("replay"), "repeated");
    assert_eq!(w.primary.link_open(&link, &second, now).unwrap(), "second");
    let reply = w.primary.link_seal(&link, "grant", now).unwrap();
    assert!(w.primary.link_open(&link, &reply, now).is_err(), "a side cannot open its own messages");
    assert_eq!(w.new.link_open(&link, &reply, now).unwrap(), "grant");

    // The primary signs the list naming the new device, then its MLS certificate (only for a listed device).
    let device = id();
    let leaf = { let (groups, store) = w.new.groups().unwrap(); groups.device_leaf(store).unwrap() };
    let signed = w.primary.sign_device_list(&w.user, &w.identity.sign, &list_json(&w.user, 1, "", &[&id(), &device]), None).unwrap();
    assert_eq!(signed.certs.len(), 2);
    assert!(w.primary.sign_device_cert(&w.user, &id(), "web", &leaf, now, now).is_err(), "not in the list");
    assert!(w.primary.sign_device_cert(&w.user, &device, "toaster", &leaf, now, now).is_err());
    assert!(w.primary.sign_device_cert(&w.user, &device, "web", &leaf, now + 11 * 60 * 1000, now).is_err(), "issued at another time");
    assert!(w.primary.sign_device_cert(&w.user, &device, "web", "short", now, now).is_err());
    assert_eq!(code_of(w.new.sign_device_cert(&w.user, &device, "web", &leaf, now, now)).as_deref(), Some("companion"), "a companion signs nothing");
    let cert = w.primary.sign_device_cert(&w.user, &device, "web", &leaf, now, now).unwrap();

    // The new device installs it: companion mode, the account identity pinned, no identity of its own.
    // A certificate for another account, another key, or signed by another identity is refused; the real one installs.
    let other = core().identity().unwrap().public;
    assert!(w.new.companion_setup(&w.user, &other, &cert).is_err());
    assert!(w.new.companion_setup(&w.user, &w.identity, "{}").is_err());
    let installed = w.new.companion_setup(&w.user, &w.identity, &cert).unwrap();
    assert_eq!((installed.user_id.as_str(), installed.device_id.as_str()), (w.user.as_str(), device.as_str()));
    assert!(w.new.is_companion().unwrap());
    assert_eq!(w.new.public_identity().unwrap(), w.identity);
    assert_eq!(code_of(w.new.identity()).as_deref(), Some("companion"));
    assert_eq!(code_of(w.new.prekeys(1, None)).as_deref(), Some("companion"));
    assert_eq!(code_of(w.new.encrypt_to(&id(), "{}", None)).as_deref(), Some("companion"), "no 1:1 sessions on a companion");
    assert_eq!(code_of(w.new.decrypt_from(&id(), "x", None)).as_deref(), Some("companion"));
    assert_eq!(code_of(w.new.prove_identity(&w.user, &device, &b64(&[1u8; 32]))).as_deref(), Some("companion"));
    assert_eq!(code_of(w.new.device_meta_signature(&w.user)).as_deref(), Some("companion"));
    assert_eq!(code_of(w.new.link_accept(&qr, now)).as_deref(), Some("companion"), "a companion cannot scan");

    // Ended and expired links are gone.
    w.new.link_end(&link).unwrap();
    assert_eq!(code_of(w.new.link_seal(&link, "x", now)).as_deref(), Some("unknown-link"));
    let stale = w.primary.link_seal(&link, "x", now + 16 * 60 * 1000);
    assert_eq!(code_of(stale).as_deref(), Some("expired"));
}

#[test]
fn pins_travel_to_a_new_device_without_overwriting_or_carrying_unreviewed_codes() {
    let mut primary = core();
    let (alice, bob, carol) = ((id(), core().identity().unwrap().public), (id(), core().identity().unwrap().public), (id(), core().identity().unwrap().public));
    for (contact, identity) in [&alice, &bob, &carol] { primary.note_peer(contact, identity).unwrap(); }
    primary.set_verified(&alice.0, true).unwrap();
    // Carol's code changed and is waiting for review: it does not travel.
    primary.note_peer(&carol.0, &core().identity().unwrap().public).unwrap();
    let pins = primary.export_pins().unwrap();
    assert_eq!(pins.len(), 2);
    assert!(pins.iter().any(|p| p.contact == alice.0 && p.verified && p.identity == alice.1));
    assert!(pins.iter().any(|p| p.contact == bob.0 && !p.verified));

    let mut new = core();
    // Something already pinned stays as it is.
    let mine = core().identity().unwrap().public;
    new.note_peer(&bob.0, &mine).unwrap();
    assert_eq!(new.import_pins(&pins).unwrap(), 1);
    assert_eq!(new.peer(&alice.0).unwrap().unwrap().identity, alice.1);
    assert!(new.peer(&alice.0).unwrap().unwrap().verified);
    assert_eq!(new.peer(&bob.0).unwrap().unwrap().identity, mine);
    assert!(new.peer(&carol.0).unwrap().is_none());
    // Bad pins are refused as a whole.
    let mut bad = |pin: PinExport| new.import_pins(&[pin]).is_err();
    let good = pins[0].clone();
    assert!(bad(PinExport { contact: "no spaces".into(), ..good.clone() }));
    assert!(bad(PinExport { identity: IdentityPub { dh: "short".into(), sign: good.identity.sign.clone() }, ..good.clone() }));
    assert!(bad(PinExport { contact: id(), identity: IdentityPub { dh: good.identity.dh.clone(), sign: format!("{}x", &good.identity.sign[..42]) }, ..good }));
}

fn record_of(value: &Value) -> (Value, String) {
    let mut record = value.clone();
    let signature = record.as_object_mut().unwrap().remove("signature").unwrap().as_str().unwrap().to_string();
    (record, signature)
}

#[test]
fn the_account_moves_to_a_new_primary_by_a_signed_record_that_contacts_follow() {
    let mut w = pair();
    let (link, now) = (id(), 5_000u64);
    // N is linked first (as a companion of the account).
    let qr = w.new.link_qr(&link, now).unwrap();
    let accepted = w.primary.link_accept(&qr, now).unwrap();
    w.new.link_complete(&link, &accepted.eph, now).unwrap();
    let device = id();
    let leaf = { let (groups, store) = w.new.groups().unwrap(); groups.device_leaf(store).unwrap() };
    w.primary.sign_device_list(&w.user, &w.identity.sign, &list_json(&w.user, 1, "", &[&device]), None).unwrap();
    let cert = w.primary.sign_device_cert(&w.user, &device, "web", &leaf, now, now).unwrap();
    w.new.companion_setup(&w.user, &w.identity, &cert).unwrap();

    // A contact has the old identity pinned and verified.
    let mut contact = core();
    let contact_id = id();
    contact.note_peer(&w.user, &w.identity).unwrap();
    contact.set_verified(&w.user, true).unwrap();

    // N prepares its identity, the old primary signs a record for it, N completes.
    assert!(w.primary.succession_start().is_err(), "only a companion takes over");
    let next = w.new.succession_start().unwrap();
    assert_eq!(w.new.succession_start().unwrap(), next, "idempotent");
    assert!(w.primary.sign_succession(&w.user, &next.sign, &next.sign, &next.dh, 9_000).is_err(), "must name a new key");
    assert_eq!(code_of(w.primary.sign_succession(&w.user, &"B".repeat(43), &next.sign, &next.dh, 9_000)).as_deref(), Some("mismatch"));
    assert_eq!(code_of(w.new.sign_succession(&w.user, &w.identity.sign, &next.sign, &next.dh, 9_000)).as_deref(), Some("companion"));
    let signed = w.primary.sign_succession(&w.user, &w.identity.sign, &next.sign, &next.dh, 9_000).unwrap();
    let (record, signature) = record_of(&signed);
    // Another identity, a record for another account or a tampered one cannot complete it.
    let other = core().identity().unwrap().public;
    let for_other = w.primary.sign_succession(&w.user, &w.identity.sign, &other.sign, &other.dh, 9_000).unwrap();
    let (other_record, other_signature) = record_of(&for_other);
    assert!(w.new.succession_complete(&other_record, &other_signature).is_err());
    let mut tampered = record.clone();
    tampered["at"] = json!(9_001);
    assert_eq!(code_of(w.new.succession_complete(&tampered, &signature)).as_deref(), Some("auth"));
    assert!(w.new.is_companion().unwrap(), "nothing changed yet");

    // The contact follows the chain from the pinned identity (and only that chain).
    assert!(contact.accept_succession(&w.user, &[]).is_err());
    assert!(contact.accept_succession(&w.user, &[tampered.clone().as_object().map(|o| { let mut o = o.clone(); o.insert("signature".into(), json!(signature)); Value::Object(o) }).unwrap()]).is_err());
    assert!(contact.accept_succession(&contact_id, &[signed.clone()]).is_err(), "no pin for that contact");
    let moved = contact.accept_succession(&w.user, &[signed.clone()]).unwrap();
    assert_eq!(moved.identity, next);
    assert!(moved.verified && !moved.changed && !moved.blocked, "verification is kept, no review");
    assert_eq!(moved.previous.len(), 1);
    assert_eq!((moved.previous[0].sign.as_str(), moved.previous[0].until), (w.identity.sign.as_str(), 9_000));
    assert_eq!(contact.peer(&w.user).unwrap().unwrap(), moved);
    assert!(contact.accept_succession(&w.user, &[signed.clone()]).is_err(), "already past it: the chain must start at the pin");
    // A plain code change (no record) is the usual review, with no predecessor.
    let mut stranger = core();
    stranger.note_peer(&w.user, &w.identity).unwrap();
    stranger.note_peer(&w.user, &next).unwrap();
    assert!(stranger.peer(&w.user).unwrap().unwrap().blocked);
    assert!(stranger.accept_succession(&w.user, &[signed]).is_err(), "unreviewed changes are not followed");

    // N now holds the identity; the old primary steps down to a companion of the new one.
    let identity = w.new.succession_complete(&record, &signature).unwrap();
    assert_eq!(identity, next);
    assert!(!w.new.is_companion().unwrap());
    assert_eq!(w.new.identity().unwrap().public, next);
    assert!(w.new.succession_complete(&record, &signature).is_err());
    w.primary.retire_identity(&w.user, &next, 9_000).unwrap();
    assert!(w.primary.is_companion().unwrap());
    assert_eq!(w.primary.public_identity().unwrap(), next);
    assert_eq!(code_of(w.primary.identity()).as_deref(), Some("companion"));
    assert!(w.primary.retire_identity(&w.user, &next, 9_000).is_err(), "already retired");
}

#[test]
fn the_json_commands_drive_a_link_and_a_succession() {
    use chatcore::commands::respond;
    let call = |core: &mut Core, command: Value| -> Value { let out = respond(core, &command); assert!(out.get("error").is_none(), "{command}: {out}"); out["ok"].clone() };
    let (mut p, mut n) = (core(), core());
    let (user, link) = (id(), id());
    let identity = call(&mut p, json!({ "cmd": "identity" }));
    let qr = call(&mut n, json!({ "cmd": "linkQr", "linkId": link, "now": 1 }))["qr"].as_str().unwrap().to_string();
    let accepted = call(&mut p, json!({ "cmd": "linkAccept", "qr": qr, "now": 1 }));
    let code = call(&mut n, json!({ "cmd": "linkComplete", "linkId": link, "eph": accepted["eph"], "now": 1 }));
    assert_eq!(code["code"], accepted["code"]);
    let sealed = call(&mut n, json!({ "cmd": "linkSeal", "linkId": link, "plaintext": "hi" }));
    assert_eq!(call(&mut p, json!({ "cmd": "linkOpen", "linkId": link, "data": sealed })), json!("hi"));
    assert_eq!(respond(&mut p, &json!({ "cmd": "linkOpen", "linkId": link, "data": sealed }))["code"], "replay");
    call(&mut p, json!({ "cmd": "linkEnd", "linkId": link }));
    assert_eq!(respond(&mut p, &json!({ "cmd": "linkSeal", "linkId": link, "plaintext": "x" }))["code"], "unknown-link");

    // Pins and a succession through commands.
    let contact = id();
    call(&mut p, json!({ "cmd": "notePeer", "contact": contact, "identity": core().identity().unwrap().public }));
    let pins = call(&mut p, json!({ "cmd": "exportPins" }));
    assert_eq!(call(&mut n, json!({ "cmd": "importPins", "pins": pins })), json!(1));
    let device = id();
    p.sign_device_list(&user, identity["sign"].as_str().unwrap(), &list_json(&user, 1, "", &[&device]), None).unwrap();
    let leaf = call(&mut n, json!({ "cmd": "mlsDeviceLeaf" }));
    let cert = call(&mut p, json!({ "cmd": "signDeviceCert", "userId": user, "deviceId": device, "platform": "linux", "leafSigKey": leaf, "issuedAt": 7, "now": 7 }));
    call(&mut n, json!({ "cmd": "companionSetup", "userId": user, "identity": identity, "cert": cert }));
    assert_eq!(call(&mut n, json!({ "cmd": "identity" })), identity);
    let next = call(&mut n, json!({ "cmd": "successionStart" }));
    let signed = call(&mut p, json!({ "cmd": "signSuccession", "userId": user, "published": identity["sign"], "newSign": next["sign"], "newDh": next["dh"], "at": 99 }));
    let (record, signature) = record_of(&signed);
    assert_eq!(call(&mut n, json!({ "cmd": "successionComplete", "record": record, "signature": signature })), next);
    call(&mut p, json!({ "cmd": "retireIdentity", "userId": user, "identity": next, "at": 99 }));
    assert_eq!(call(&mut p, json!({ "cmd": "identity" })), next);
    // A contact follows it.
    let mut c = core();
    c.note_peer(&user, &serde_json::from_value(identity).unwrap()).unwrap();
    let moved = call(&mut c, json!({ "cmd": "acceptSuccession", "contact": user, "records": [signed] }));
    assert_eq!(moved["identity"], next);
}

#[test]
fn the_succession_record_bytes_match_devices_js() {
    use chatcore::succession::Record;
    // The vector of tests/unit/link.test.ts (devices.js successionBytes).
    let record = Record { user_id: "user_1".into(), old_sign: b64(&[3u8; 32]), new_sign: b64(&[4u8; 32]), new_dh: b64(&[5u8; 32]), at: 1_700_000_000_000 };
    assert_eq!(hex(&Sha256::digest(record.bytes())), "ba9d21a694b578849a380ef5cc9db652bec880543922e660c8f2fb2777758b54");
    // Strict parsing: exact keys, canonical keys, a new key.
    let value = |f: &dyn Fn(&mut Value)| { let mut v = json!({ "v": 1, "userId": "user_1", "oldSign": b64(&[3u8; 32]), "newSign": b64(&[4u8; 32]), "newDh": b64(&[5u8; 32]), "at": 5 }); f(&mut v); v };
    assert!(Record::parse(&value(&|_| {})).is_ok());
    assert!(Record::parse(&value(&|v| v["extra"] = json!(1))).is_err());
    assert!(Record::parse(&value(&|v| v["newSign"] = json!("x"))).is_err());
    assert!(Record::parse(&value(&|v| v["newSign"] = v["oldSign"].clone())).is_err());
    assert!(Record::parse(&value(&|v| v["v"] = json!(2))).is_err());
    assert!(Record::parse(&value(&|v| v["userId"] = json!("no spaces"))).is_err());
}

#[test]
fn the_short_code_variant_commits_before_it_reveals_and_binds_both_device_ids() {
    let (mut p, mut n) = (core(), core());
    p.identity().unwrap();
    let (link, device_n, device_p, now) = (id(), id(), id(), 10u64);
    let commit = n.link_commit(&link, &device_n, now).unwrap();
    let eph_p = p.link_lookup(&link, &device_n, &commit, &device_p, now).unwrap();
    // The new device reveals only once the primary's key is in, and the primary checks it against the commitment.
    let (eph_n, nonce) = n.link_reveal(&link, &eph_p, now).unwrap();
    assert!(p.link_seal(&link, "too early", now).is_err(), "no keys before the reveal checks out");
    let code_p = p.link_open_commitment(&link, &eph_n, &nonce, now).unwrap();
    let code_n = n.link_complete_code(&link, &eph_p, &device_p, now).unwrap();
    assert_eq!(code_p, code_n);
    let sealed = n.link_seal(&link, "hello", now).unwrap();
    assert_eq!(p.link_open(&link, &sealed, now).unwrap(), "hello");
    assert_eq!(n.link_open(&link, &p.link_seal(&link, "grant", now).unwrap(), now).unwrap(), "grant");

    // The code covers the device ids: a relay that swaps the primary's device id gets a different code and keys.
    let (mut p2, mut n2) = (core(), core());
    p2.identity().unwrap();
    let commit = n2.link_commit(&link, &device_n, now).unwrap();
    let eph_p = p2.link_lookup(&link, &device_n, &commit, &device_p, now).unwrap();
    let (eph_n, nonce) = n2.link_reveal(&link, &eph_p, now).unwrap();
    let honest = p2.link_open_commitment(&link, &eph_n, &nonce, now).unwrap();
    let swapped = n2.link_complete_code(&link, &eph_p, &id(), now).unwrap();
    assert_ne!(honest, swapped);

    // A key other than the committed one is refused and burns the link; so is a wrong nonce.
    for tamper in ["key", "nonce"] {
        let (mut p3, mut n3) = (core(), core());
        p3.identity().unwrap();
        let commit = n3.link_commit(&link, &device_n, now).unwrap();
        let eph_p = p3.link_lookup(&link, &device_n, &commit, &device_p, now).unwrap();
        let (eph_n, nonce) = n3.link_reveal(&link, &eph_p, now).unwrap();
        let (eph_n, nonce) = if tamper == "key" { (core().link_qr(&link, now).map(|_| b64(&[9u8; 32])).unwrap(), nonce) } else { (eph_n, b64(&[7u8; 16])) };
        assert_eq!(code_of(p3.link_open_commitment(&link, &eph_n, &nonce, now)).as_deref(), Some("auth"), "{tamper}");
        assert_eq!(code_of(p3.link_seal(&link, "x", now)).as_deref(), Some("unknown-link"), "burned");
    }
    // The primary's key must be the one the new device revealed against; a QR link and a code link don't mix.
    let (mut p4, mut n4) = (core(), core());
    p4.identity().unwrap();
    let commit = n4.link_commit(&link, &device_n, now).unwrap();
    let eph_p = p4.link_lookup(&link, &device_n, &commit, &device_p, now).unwrap();
    assert!(n4.link_complete_code(&link, &eph_p, &device_p, now).is_err(), "not revealed yet");
    n4.link_reveal(&link, &eph_p, now).unwrap();
    assert!(n4.link_complete_code(&link, &b64(&[1u8; 32]), &device_p, now).is_err(), "another key");
    assert!(n4.link_complete(&link, &eph_p, now).is_err(), "a code link is not a QR link");
    let (mut c, mut q) = (core(), core());
    c.identity().unwrap();
    assert!(c.link_lookup(&link, &device_n, &b64(&[1u8; 32]), &device_p, now).is_ok());
    assert_eq!(code_of(q.link_lookup(&link, &device_n, &b64(&[1u8; 32]), &device_p, now)).as_deref(), Some("companion"), "only an identity holder scans");
}
