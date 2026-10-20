//! Every row of FINDINGS.md's "What OpenMLS does NOT enforce" table, with a malicious member or joiner built from
//! raw OpenMLS (or the engine's unchecked builders). Each attack must be refused by the delivery service, by every
//! member (as a `poison` commit), and, where the attacker uses the engine, by the attacker's own device.
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use rand_core::OsRng;

use super::harness::*;
use crate::mls::cert::{key32, DeviceCert};
use crate::mls::engine::{group_id, Submit};
use crate::mls::policy::{capabilities, JoinPolicy, Roles};
use crate::mls::{CS, ROLES_EXT};
use crate::store::Store;

fn tls<T: openmls::prelude::tls_codec::Serialize>(value: &T) -> String { b64(&value.tls_serialize_detached().unwrap()) }

fn parse_kp(text: &str, provider: &impl OpenMlsProvider) -> KeyPackage {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, text).unwrap();
    let MlsMessageBodyIn::KeyPackage(kp) = MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).unwrap().extract() else { panic!("not a key package") };
    kp.validate(provider.crypto(), ProtocolVersion::Mls10).unwrap()
}

/// The attack must fail at the DS and at an honest member (Carol's device), and change nothing. `needle` is in both messages.
fn expect_rejected(f: &mut Fixture, commit: &str, needle: &str) {
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let epoch = f.server.epoch(&g);
    let err = f.server.submit(&g, commit).expect_err("the DS must refuse it");
    assert!(err.message.contains(needle), "DS: {err} (wanted {needle:?})");
    let err = f.c1.groups.process(&mut f.c1.store, &gid, commit).expect_err("a member must refuse it");
    assert_eq!(err.code(), Some("poison"), "{err}");
    assert!(err.message.contains(needle), "member: {err} (wanted {needle:?})");
    assert_eq!(f.server.epoch(&g), epoch);
    assert_eq!(f.c1.epoch(&g), epoch);
    assert_eq!(f.c1.members(&g).len(), f.b2.members(&g).len());
}

/// A commit by `dev` that rotates its leaf to a new key under a certificate for `user`/`device` signed by `aik`.
fn rekey_commit(dev: &mut Dev, group: &str, user: &str, device: &str, aik: &SigningKey) -> String {
    let gid = group_id(group).unwrap();
    dev.groups.scratch(&mut dev.store, |p, signer, _| {
        let mut g = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        let new_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        new_signer.store(p.storage()).unwrap();
        let key = key32(&b64(new_signer.public())).unwrap();
        let cert = DeviceCert::issue(aik, user, device, "web", &key, 0).unwrap();
        let cred = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: new_signer.public().into() };
        let params = LeafNodeParameters::builder().with_credential_with_key(cred.clone()).with_capabilities(capabilities()).build();
        let bundle = g
            .commit_builder()
            .leaf_node_parameters(params)
            .load_psks(p.storage()).unwrap()
            .build_with_new_signer(p.rand(), p.crypto(), signer, NewSignerBundle { signer: &new_signer, credential_with_key: cred }, |_| true).unwrap()
            .stage_commit(p).unwrap();
        tls(bundle.commit())
    })
}

#[test]
fn an_update_may_not_swap_the_credential() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let (user, aik) = (f.b1.user.clone(), f.b1.aik.clone());

    // Another device of the same account (a perfectly valid certificate): still not this leaf's device.
    let commit = rekey_commit(&mut f.b1, &g, &user, &rid(), &aik);
    expect_rejected(&mut f, &commit, "may not change the leaf's user or device");

    // Carol's user id under a certificate Bob signed himself: not Carol's pinned account key.
    let commit = rekey_commit(&mut f.b1, &g, &f.carol.id.clone(), &rid(), &aik);
    expect_rejected(&mut f, &commit, "not signed by the pinned account key");

    // Same user and device with a rotated leaf key is legitimate, and the group continues.
    let device = f.b1.device.clone();
    let commit = rekey_commit(&mut f.b1, &g, &user, &device, &aik);
    f.server.submit(&g, &commit).unwrap();
    let processed = f.a1.groups.process(&mut f.a1.store, &group_id(&g).unwrap(), &commit).unwrap();
    f.a1.groups.commit_pending(&mut f.a1.store, &processed.pending_id).unwrap();
    assert_eq!(f.a1.members(&g).len(), 5);
}

#[test]
fn a_non_admin_cannot_add_a_new_user_to_an_invite_only_group() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let kp = d1.kp(1);
    assert!(f.b1.groups.commit(&mut f.b1.store, &group_id(&g).unwrap(), &kp, &[], None, false).is_err(), "refused on the attacker's own device");
    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &group_id(&g).unwrap(), &kp, &[], None, false).unwrap();
    expect_rejected(&mut f, &out.commit, "only admins add new users");
    // Adding a new device of a user who is already in the group is fine for anyone.
    f.b1.groups.clear_own(&mut f.b1.store, &group_id(&g).unwrap()).unwrap();
    let mut b3 = Dev::new(&f.bob, "ios", &[&f.alice, &f.bob, &f.carol]);
    let kp = b3.kp(1);
    let out = f.b1.accepted(&mut f.server, &g, &kp, &[], None, false);
    b3.join(&mut f.server, &out.welcome.unwrap(), &g);
}

#[test]
fn in_an_open_group_any_member_may_add() {
    let mut f = Fixture::new(JoinPolicy::Open);
    let g = f.group.clone();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let kp = d1.kp(1);
    let out = f.b1.accepted(&mut f.server, &g, &kp, &[], None, false);
    d1.join(&mut f.server, &out.welcome.unwrap(), &g);
    assert_eq!(d1.members(&g).len(), 6);
}

#[test]
fn a_non_admin_cannot_remove_another_user() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    assert!(f.b1.groups.commit(&mut f.b1.store, &gid, &[], &[(f.carol.id.clone(), None)], None, false).is_err());
    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &[], &[(f.carol.id.clone(), None)], None, false).unwrap();
    expect_rejected(&mut f, &out.commit, "only admins remove other users");
    f.b1.groups.clear_own(&mut f.b1.store, &gid).unwrap();
    // Not even the admin's devices.
    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &[], &[(f.alice.id.clone(), Some(f.a2.device.clone()))], None, false).unwrap();
    expect_rejected(&mut f, &out.commit, "only admins remove other users");
}

/// A group-context-extensions commit by the admin carrying `extensions`.
fn extensions_commit(dev: &mut Dev, group: &str, extensions: Extensions<GroupContext>) -> Option<String> {
    let gid = group_id(group).unwrap();
    dev.groups.scratch(&mut dev.store, |p, signer, _| {
        let mut g = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        let builder = g.commit_builder().propose_group_context_extensions(extensions).ok()?;
        let bundle = builder.load_psks(p.storage()).ok()?.build(p.rand(), p.crypto(), signer, |_| true).ok()?.stage_commit(p).ok()?;
        Some(tls(bundle.commit()))
    })
}

#[test]
fn the_roles_extension_cannot_be_dropped_or_diluted() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let roles = Roles::group(vec![f.alice.id.clone()], JoinPolicy::Invite);
    let requires_roles = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(ROLES_EXT)], &[], &[]));
    let requires_nothing = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));
    let stray = Extension::Unknown(0xF0A2, UnknownExtension(b"x".to_vec()));
    let cases: Vec<(&str, Vec<Extension>, &str)> = vec![
        ("nothing", vec![], "exactly"),
        ("required capabilities only", vec![requires_roles.clone()], "exactly"),
        ("roles only", vec![roles.extension()], "exactly"),
        ("roles no longer required", vec![requires_nothing, roles.extension()], "not a required capability"),
        ("a stray extension", vec![requires_roles.clone(), roles.extension(), stray], "not allowed"),
        ("no admins", vec![requires_roles.clone(), Roles::group(vec![], JoinPolicy::Invite).extension()], "admins"),
        ("garbage roles", vec![requires_roles.clone(), Extension::Unknown(ROLES_EXT, UnknownExtension(b"{}".to_vec()))], "roles"),
        ("another kind", vec![requires_roles.clone(), Roles::dm(&f.alice.id, &f.bob.id).extension()], "never change"),
    ];
    let mut built = 0;
    for (name, extensions, needle) in cases {
        let Some(commit) = extensions_commit(&mut f.a1, &g, Extensions::from_vec(extensions).unwrap()) else { continue };
        built += 1;
        let epoch = f.server.epoch(&g);
        let err = f.server.submit(&g, &commit).expect_err(name);
        assert!(err.message.contains(needle) || err.message.contains("group context"), "{name}: {err}");
        assert_eq!(f.server.epoch(&g), epoch, "{name}");
        let err = f.b1.groups.process(&mut f.b1.store, &group_id(&g).unwrap(), &commit).expect_err(name);
        assert_eq!(err.code(), Some("poison"), "{name}: {err}");
    }
    assert!(built >= 5, "the attacks were actually built ({built})");
}

#[test]
fn only_an_admin_changes_roles_and_a_roles_change_never_authorizes_its_own_commit() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let kp = d1.kp(1);
    let promote_bob = Roles::group(vec![f.alice.id.clone(), f.bob.id.clone()], JoinPolicy::Invite);

    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &[], &[], Some(&promote_bob), false).unwrap();
    expect_rejected(&mut f, &out.commit, "only admins change group settings");
    f.b1.groups.clear_own(&mut f.b1.store, &gid).unwrap();

    // Promote himself and add Dave in one commit: judged by the roles before the commit.
    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &kp, &[], Some(&promote_bob), false).unwrap();
    expect_rejected(&mut f, &out.commit, "only admins");
    f.b1.groups.clear_own(&mut f.b1.store, &gid).unwrap();

    // The real admin may promote Bob; from the next epoch Bob can add Dave.
    f.a1.accepted(&mut f.server, &g, &[], &[], Some(&promote_bob), false);
    f.b1.sync(&f.server, &g);
    assert!(f.b1.members(&g).iter().filter(|m| m.user_id == f.bob.id).all(|m| m.admin));
    let out = f.b1.accepted(&mut f.server, &g, &kp, &[], None, false);
    d1.join(&mut f.server, &out.welcome.unwrap(), &g);

    // The kind never changes.
    for dev in [&mut f.a1, &mut f.a2, &mut f.b2, &mut f.c1] { dev.sync(&f.server, &g); }
    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &[], &[], Some(&Roles::dm(&f.alice.id, &f.bob.id)), false).unwrap();
    expect_rejected(&mut f, &out.commit, "never change");
}

#[test]
fn a_welcome_for_a_group_we_would_not_accept_is_refused() {
    let f = Fixture::new(JoinPolicy::Invite);
    let mut c1 = f.c1;

    // 1. A group whose creator's account key nobody pinned (the invitee has no pin for Mallory).
    let mallory = Account::new();
    let mut m1 = Dev::new(&mallory, "web", &[&mallory, &f.carol]);
    let mg = rid();
    let mut server = Server::new(&[&mallory, &f.carol]);
    m1.create(&mut server, &mg, &Roles::group(vec![mallory.id.clone()], JoinPolicy::Open));
    let out = m1.accepted(&mut server, &mg, &c1.kp(1), &[], None, false);
    let err = c1.groups.join(&mut c1.store, &out.welcome.unwrap(), &server.tree(&mg)).unwrap_err();
    assert!(err.message.contains("no pinned account key"), "{err}");

    // 2. A pinned member's real certificate, but a group with no roles extension at all.
    let mut b1 = f.b1;
    let bad_tree_and_welcome = b1.groups.scratch(&mut b1.store, |p, signer, cert| {
        let credential = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: signer.public().into() };
        let mut g = MlsGroup::builder().ciphersuite(CS).with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY).with_capabilities(capabilities()).build(p, signer, credential).unwrap();
        let kp = parse_kp(&c1.kp(1)[0], p);
        let bundle = g.commit_builder().propose_adds([kp]).load_psks(p.storage()).unwrap().build(p.rand(), p.crypto(), signer, |_| true).unwrap().stage_commit(p).unwrap();
        g.merge_pending_commit(p).unwrap();
        (tls(&bundle.to_welcome_msg().unwrap()), tls(&g.export_ratchet_tree()))
    });
    let err = c1.groups.join(&mut c1.store, &bad_tree_and_welcome.0, &bad_tree_and_welcome.1).unwrap_err();
    assert!(err.message.contains("group context must hold exactly") || err.message.contains("no roles"), "{err}");

    // 3. A DM that contains a device of a third user.
    let mut dm_server = Server::new(&[&f.alice, &f.bob, &f.carol]);
    let dm = rid();
    b1.create(&mut dm_server, &dm, &Roles::dm(&f.alice.id, &f.bob.id));
    let dm_id = group_id(&dm).unwrap();
    b1.store.put(&format!("peer:{}", f.carol.id), serde_json::json!({ "aik": f.carol.pin() })).unwrap();
    let out = b1.groups.commit_unchecked(&mut b1.store, &dm_id, &c1.kp(1), &[], None, false).unwrap();
    let (welcome, tree) = b1.groups.scratch(&mut b1.store, |p, _, _| {
        let mut g = MlsGroup::load(p.storage(), &dm_id).unwrap().unwrap();
        g.merge_pending_commit(p).unwrap();
        (out.welcome.clone().unwrap(), tls(&g.export_ratchet_tree()))
    });
    let err = c1.groups.join(&mut c1.store, &welcome, &tree).unwrap_err();
    assert!(err.message.contains("third user"), "{err}");

    // 4. Garbage, and a message that is not a Welcome.
    assert_eq!(c1.groups.join(&mut c1.store, &b64(b"nope"), &tree).unwrap_err().code(), Some("malformed"));
    assert!(c1.groups.join(&mut c1.store, &out.commit, &tree).is_err());
    assert!(c1.groups.members(&mut c1.store, &dm_id).is_err(), "nothing was adopted");
}

#[test]
fn a_member_whose_credential_is_not_a_certificate_is_refused() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let mut b1 = std::mem::replace(&mut f.b1, Dev::new(&f.bob, "web", &[]));
    // A group of plain-identity credentials (as OpenMLS would happily build it).
    let (welcome, tree) = b1.groups.scratch(&mut b1.store, |p, _, _| {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(p.storage()).unwrap();
        let credential = CredentialWithKey { credential: BasicCredential::new(b"alice".to_vec()).into(), signature_key: signer.public().into() };
        let roles = Roles::group(vec![f.alice.id.clone()], JoinPolicy::Invite);
        let mut g = MlsGroup::builder().ciphersuite(CS).with_capabilities(capabilities()).with_group_context_extensions(crate::mls::policy::group_extensions(&roles).unwrap()).build(p, &signer, credential).unwrap();
        let kp = parse_kp(&f.c1.kp(1)[0], p);
        let bundle = g.commit_builder().propose_adds([kp]).load_psks(p.storage()).unwrap().build(p.rand(), p.crypto(), &signer, |_| true).unwrap().stage_commit(p).unwrap();
        g.merge_pending_commit(p).unwrap();
        (tls(&bundle.to_welcome_msg().unwrap()), tls(&g.export_ratchet_tree()))
    });
    let err = f.c1.groups.join(&mut f.c1.store, &welcome, &tree).unwrap_err();
    assert!(err.message.contains("device certificate"), "{err}");
}

#[test]
fn key_packages_must_carry_a_certificate_for_their_own_leaf_key() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let (user, aik) = (f.b1.user.clone(), f.b1.aik.clone());

    // Bob's real account certifies a different key than the one the KeyPackage is signed with.
    let forged = f.b1.groups.scratch(&mut f.b1.store, |p, _, _| {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(p.storage()).unwrap();
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let cert = DeviceCert::issue(&aik, &user, &rid(), "web", &other, 0).unwrap();
        let credential = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: signer.public().into() };
        let bundle = KeyPackage::builder().leaf_node_capabilities(capabilities()).build(CS, p, &signer, credential).unwrap();
        tls(&MlsMessageOut::from(bundle.key_package().clone()))
    });
    let err = f.a1.groups.commit(&mut f.a1.store, &gid, &[forged.clone()], &[], None, false).unwrap_err();
    assert!(err.message.contains("does not match the certificate"), "{err}");
    let out = f.a1.groups.commit_unchecked(&mut f.a1.store, &gid, &[forged], &[], None, false).unwrap();
    expect_rejected(&mut f, &out.commit, "does not match the certificate");
}

#[test]
fn a_user_without_a_pinned_account_key_cannot_be_added() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let mallory = Account::new();
    let mut m1 = Dev::new(&mallory, "web", &[&mallory]);
    let kp = m1.kp(1);
    assert!(f.a1.groups.commit(&mut f.a1.store, &gid, &kp, &[], None, false).unwrap_err().message.contains("no pinned account key"));
    let out = f.a1.groups.commit_unchecked(&mut f.a1.store, &gid, &kp, &[], None, false).unwrap();
    expect_rejected(&mut f, &out.commit, "no pinned account key");
}

#[test]
fn standalone_proposals_and_commits_by_reference_are_refused() {
    let mut f = Fixture::new(JoinPolicy::Open);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let kp_text = d1.kp(1).remove(0);
    let (proposal, commit) = f.b1.groups.scratch(&mut f.b1.store, |p, signer, _| {
        let mut g = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        let (proposal, _) = g.propose_add_member(p, signer, &parse_kp(&kp_text, p)).unwrap();
        let (commit, _, _) = g.commit_to_pending_proposals(p, signer).unwrap();
        (tls(&proposal), tls(&commit))
    });
    let epoch = f.server.epoch(&g);

    assert!(f.server.submit(&g, &proposal).is_err(), "the DS never relays proposals");
    let err = f.a1.groups.process(&mut f.a1.store, &gid, &proposal).unwrap_err();
    assert!(err.message.contains("standalone proposals"), "{err}");

    // The commit refers to a proposal nobody stored: nobody can apply it.
    assert!(f.server.submit(&g, &commit).is_err());
    let err = f.a1.groups.process(&mut f.a1.store, &gid, &commit).unwrap_err();
    assert_eq!(err.code(), Some("poison"));
    assert_eq!(f.server.epoch(&g), epoch);
    assert_eq!(f.a1.epoch(&g), epoch);
    assert_eq!(f.a1.members(&g).len(), 5);
}

#[test]
fn oversize_inputs_are_refused_before_parsing() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let junk = |n: usize| b64(&vec![0u8; n]);

    // KeyPackage 4 KiB, Welcome 4 MiB, tree 4 MiB, GroupInfo 64 KiB, handshake 1 MiB, application 64 KiB.
    let err = f.a1.groups.commit(&mut f.a1.store, &gid, &[junk(4 * 1024 + 1)], &[], None, false).unwrap_err();
    assert!(err.message.contains("exceeds"), "{err}");
    let err = f.c1.groups.join(&mut f.c1.store, &junk(4 * 1024 * 1024 + 1), &junk(1)).unwrap_err();
    assert!(err.message.contains("exceeds"), "{err}");
    let err = f.c1.groups.join(&mut f.c1.store, &junk(1), &junk(4 * 1024 * 1024 + 1)).unwrap_err();
    assert!(err.message.contains("exceeds"), "{err}");
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let err = d1.groups.join_external(&mut d1.store, &junk(64 * 1024 + 1), &junk(1)).unwrap_err();
    assert!(err.message.contains("exceeds"), "{err}");
    let err = f.server.ds.create(&mut f.server.store, &junk(64 * 1024 + 1), &junk(1)).unwrap_err();
    assert!(err.message.contains("exceeds"), "{err}");
    let big = junk(1024 * 1024 + 1);
    assert!(f.server.submit(&g, &big).unwrap_err().message.contains("exceeds"));
    assert!(f.a1.groups.process(&mut f.a1.store, &gid, &big).unwrap_err().message.contains("exceeds"));

    // Plaintext over 60 KiB is refused by the sender; a hostile 65 KiB ciphertext by the DS and the receivers.
    let long = "x".repeat(60 * 1024 + 1);
    assert!(f.b1.groups.encrypt(&mut f.b1.store, &gid, &long).unwrap_err().message.contains("exceeds"));
    let oversize = f.b1.groups.scratch(&mut f.b1.store, |p, signer, _| {
        let mut g = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        tls(&g.create_message(p, signer, &vec![b'a'; 65 * 1024]).unwrap())
    });
    assert!(f.server.submit(&g, &oversize).unwrap_err().message.contains("exceeds"));
    assert!(f.a1.groups.process(&mut f.a1.store, &gid, &oversize).unwrap_err().message.contains("exceeds"));
    // Exactly at the limit is fine.
    f.b1.send(&mut f.server, &g, &"y".repeat(60 * 1024));
    assert_eq!(f.a1.texts(&f.server, &g)[0].len(), 60 * 1024);
}

#[test]
fn a_commit_may_carry_at_most_128_proposals() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    // 129 distinct devices of Bob (a user already in the group, so only the count is at issue).
    let mut kps = Vec::new();
    for _ in 0..129 { kps.push(Dev::new(&f.bob, "bot", &[&f.alice, &f.bob, &f.carol]).kp(1).remove(0)); }
    let err = f.a1.groups.commit(&mut f.a1.store, &gid, &kps, &[], None, false).unwrap_err();
    assert!(err.message.contains("too many"), "{err}");
    let out = f.a1.groups.commit_unchecked(&mut f.a1.store, &gid, &kps, &[], None, false).unwrap();
    expect_rejected(&mut f, &out.commit, "too many proposals");
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();
    let out = f.a1.accepted(&mut f.server, &g, &kps[..128], &[], None, false);
    assert!(out.welcome.is_some());
    assert_eq!(f.a1.members(&g).len(), 5 + 128);
}

#[test]
fn merge_own_validates_what_the_device_built() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let out = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &[], &[(f.carol.id.clone(), None)], None, false).unwrap();
    assert!(out.epoch == f.b1.epoch(&g));
    let err = f.b1.groups.merge_own(&mut f.b1.store, &gid).unwrap_err();
    assert!(err.message.contains("only admins remove other users"), "{err}");
    assert_eq!(f.b1.epoch(&g), f.server.epoch(&g), "nothing merged");
    assert_eq!(f.b1.members(&g).len(), 5);
    f.b1.groups.clear_own(&mut f.b1.store, &gid).unwrap();
}

#[test]
fn unpinning_a_member_fails_the_group_closed_on_load_and_repinning_restores_it() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    f.b1.groups.encrypt(&mut f.b1.store, &gid, "fine").unwrap();
    f.b1.store.delete(&format!("peer:{}", f.carol.id)).unwrap();
    f.b1.restart();
    let err = f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").unwrap_err();
    assert!(err.message.contains("no pinned account key"), "{err}");
    assert!(f.b1.groups.members(&mut f.b1.store, &gid).is_err());
    assert!(f.b1.groups.process(&mut f.b1.store, &gid, &f.server.log[&g][0]).is_err());
    f.b1.store.put(&format!("peer:{}", f.carol.id), serde_json::json!({ "aik": f.carol.pin() })).unwrap();
    f.b1.groups.encrypt(&mut f.b1.store, &gid, "fine again").unwrap();

    // A changed identity awaiting review is not a pin.
    f.b1.store.put(&format!("peer:{}", f.carol.id), serde_json::json!({ "aik": f.carol.pin(), "blocked": true })).unwrap();
    f.b1.restart();
    assert!(f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").is_err());
}

#[test]
fn a_pin_for_another_key_makes_that_users_devices_stale_not_the_group_unusable() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let impostor = Account::new();
    f.a1.send(&mut f.server, &g, "from alice before");
    f.b1.store.put(&format!("peer:{}", f.alice.id), serde_json::json!({ "aik": impostor.pin() })).unwrap();
    f.b1.restart();
    // Bob keeps writing; Alice's two devices are shown as devices of an identity she left.
    f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").unwrap();
    let stale: Vec<_> = f.b1.members(&g).into_iter().filter(|m| m.stale).map(|m| m.user_id).collect();
    assert_eq!(stale, vec![f.alice.id.clone(), f.alice.id.clone()]);
    // What they say no longer counts (the first log entry is Alice's message), and they cannot commit.
    let err = f.b1.groups.process(&mut f.b1.store, &gid, &f.server.log[&g][1]).unwrap_err();
    assert_eq!(err.code(), Some("stale"), "{err}");
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    let err = f.b1.groups.process(&mut f.b1.store, &gid, &out.commit).unwrap_err();
    assert_eq!((err.code(), err.class.as_deref()), (Some("poison"), Some("signed-content")), "{err}");
    assert!(err.message.contains("outdated") || err.message.contains("left"), "{err}");
}

#[test]
fn the_load_gate_checks_the_devices_own_leaf() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let gid = group_id(&f.group).unwrap();
    // Replace this device's certificate with another valid one for the same key.
    let record = f.b1.store.get("mlsx:device").unwrap().unwrap();
    let old: DeviceCert = serde_json::from_value(record["cert"].clone()).unwrap();
    let leaf = key32(&old.leaf_sig_key).unwrap();
    let swapped = DeviceCert::issue(&f.b1.aik, &old.user_id, &rid(), &old.platform, &leaf, 0).unwrap();
    f.b1.store.put("mlsx:device", serde_json::json!({ "cert": swapped })).unwrap();
    f.b1.restart();
    let err = f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").unwrap_err();
    assert!(err.message.contains("does not match its certificate"), "{err}");
}

#[test]
fn the_ds_gate_rechecks_pins_after_a_restart() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let mut b2 = f.b2;
    // The registry no longer knows Carol's key: the DS refuses to sequence anything for a group she is in.
    f.server.store.delete(&format!("mlsdsx:pin:{}", f.carol.id)).unwrap();
    f.server.restart();
    let message = f.b1.groups.encrypt(&mut f.b1.store, &group_id(&g).unwrap(), "x").unwrap();
    let err = f.server.submit(&g, &message).unwrap_err();
    assert!(err.message.contains("no pinned account key"), "{err}");
    let _ = &mut b2;
}

#[test]
fn the_ds_validates_what_it_bootstraps_and_pins_do_not_move() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let view = f.a1.view(&g);
    // Already tracked.
    assert!(f.server.ds.create(&mut f.server.store, &view.group_info, &view.tree).unwrap_err().message.contains("already tracked"));
    // A group nobody's key is pinned for.
    let mut other = Server::new(&[&f.alice]);
    let err = other.ds.create(&mut other.store, &view.group_info, &view.tree).unwrap_err();
    assert!(err.message.contains("no pinned account key"), "{err}");
    // A tree that doesn't match the signed GroupInfo.
    let mut other = Server::new(&[&f.alice, &f.bob, &f.carol]);
    let mut tampered = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &view.tree).unwrap();
    let at = tampered.len() / 2;
    tampered[at] ^= 1;
    assert!(other.ds.create(&mut other.store, &view.group_info, &b64(&tampered)).is_err());
    // Re-pinning a user to another key is refused; pinning the same key again is a no-op.
    let eve = Account::new();
    assert!(f.server.ds.pin(&mut f.server.store, &f.alice.id, &eve.pin()).is_err());
    f.server.ds.pin(&mut f.server.store, &f.alice.id, &f.alice.pin()).unwrap();
    // Unknown group, bad ids.
    assert_eq!(f.server.ds.submit(&mut f.server.store, &group_id(&rid()).unwrap(), "AAAA").unwrap_err().code(), Some("unknown-group"));
    assert!(f.server.ds.pin(&mut f.server.store, "short", &eve.pin()).is_err());
}

#[test]
fn a_snapshot_of_another_group_or_a_corrupt_one_is_refused() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let alice = f.alice.id.clone();
    let mut server2 = Server::new(&[&f.alice, &f.bob, &f.carol]);
    let g2 = rid();
    f.a1.create(&mut server2, &g2, &Roles::group(vec![alice], JoinPolicy::Open));
    let other = server2.ds.snapshot(&group_id(&g2).unwrap()).unwrap();
    assert!(f.server.ds.restore(&mut f.server.store, &gid, &other).is_err());
    assert!(f.server.ds.restore(&mut f.server.store, &gid, &b64(b"{}")).is_err());
    assert!(f.server.ds.restore(&mut f.server.store, &gid, "!!").is_err());
    // The failed restores left the group intact.
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
}

#[test]
fn a_pin_that_changes_after_verification_fails_the_next_gated_call() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let key = format!("peer:{}", f.carol.id);
    // Verified and cached: these calls all pass without a restart.
    f.b1.groups.encrypt(&mut f.b1.store, &gid, "ok").unwrap();
    f.b1.groups.members(&mut f.b1.store, &gid).unwrap();

    for (name, row) in [
        ("blocked", Some(serde_json::json!({ "aik": f.carol.pin(), "blocked": true }))),
        ("changed", Some(serde_json::json!({ "aik": Account::new().pin() }))),
        ("deleted", None),
    ] {
        match &row { Some(value) => f.b1.store.put(&key, value.clone()).unwrap(), None => f.b1.store.delete(&key).unwrap() }
        // No restart: the cached verification must not survive the pin change.
        if name == "changed" {
            // A different key is not an unknown one: Carol's device is now stale, and the group goes on.
            assert!(f.b1.groups.members(&mut f.b1.store, &gid).unwrap().iter().any(|m| m.user_id == f.carol.id && m.stale));
            f.b1.store.put(&key, serde_json::json!({ "aik": f.carol.pin() })).unwrap();
            assert!(f.b1.groups.members(&mut f.b1.store, &gid).unwrap().iter().all(|m| !m.stale));
            continue;
        }
        assert!(f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").is_err(), "{name}");
        assert!(f.b1.groups.members(&mut f.b1.store, &gid).is_err(), "{name}");
        assert!(f.b1.groups.process(&mut f.b1.store, &gid, &f.server.log[&g][0]).is_err(), "{name}");
        f.b1.store.put(&key, serde_json::json!({ "aik": f.carol.pin() })).unwrap();
        f.b1.groups.encrypt(&mut f.b1.store, &gid, "restored").unwrap();
    }

    // The DS side: the registry pin for a member changes under a verified group.
    let msg = f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").unwrap();
    assert!(f.server.submit(&g, &msg).is_ok());
    let pin = format!("mlsdsx:pin:{}", f.carol.id);
    f.server.store.delete(&pin).unwrap();
    assert!(f.server.submit(&g, &msg).unwrap_err().message.contains("no pinned account key"));
    // A registry key that differs is a user who moved on, not an unknown one: their devices go stale and the group carries on.
    f.server.store.put(&pin, serde_json::json!({ "aik": Account::new().pin() })).unwrap();
    assert!(f.server.submit(&g, &msg).is_ok());
    assert!(f.server.ds.members(&mut f.server.store, &group_id(&g).unwrap()).unwrap().members.iter().any(|m| m.user_id == f.carol.id && m.stale));
    f.server.store.put(&pin, serde_json::json!({ "aik": f.carol.pin() })).unwrap();
    assert!(f.server.submit(&g, &msg).is_ok());

    // The device's own certificate record changing is caught the same way.
    let record = f.b1.store.get("mlsx:device").unwrap().unwrap();
    let old: DeviceCert = serde_json::from_value(record["cert"].clone()).unwrap();
    let swapped = DeviceCert::issue(&f.b1.aik, &old.user_id, &rid(), &old.platform, &key32(&old.leaf_sig_key).unwrap(), 0).unwrap();
    f.b1.store.put("mlsx:device", serde_json::json!({ "cert": swapped })).unwrap();
    assert!(f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").is_err());
}

#[test]
fn a_caller_that_knows_what_an_entry_is_says_so_and_a_mismatch_is_refused_before_anything_is_staged() {
    use crate::mls::engine::Expect;
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    f.a1.send(&mut f.server, &g, "hello");
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
    let (app, commit) = (f.server.log[&g][1].clone(), f.server.log[&g][2].clone());
    let epoch = f.b1.epoch(&g);

    // The wrong kind, either way, errors; nothing is decrypted, merged or staged.
    for (message, wrong) in [(&app, Expect::Commit), (&commit, Expect::Application)] {
        let err = f.b1.groups.process_as(&mut f.b1.store, &gid, message, Some(wrong)).unwrap_err();
        assert_eq!(err.code(), Some("invalid"), "{err}");
        assert!(err.message.contains("expected a"), "{err}");
    }
    assert_eq!(f.b1.epoch(&g), epoch);
    // The right kind, or none, goes through (and the refusals above consumed nothing).
    let first = f.b1.groups.process_as(&mut f.b1.store, &gid, &app, Some(Expect::Application)).unwrap();
    assert_eq!(first.plaintext.as_deref(), Some("hello"));
    f.b1.groups.commit_pending(&mut f.b1.store, &first.pending_id).unwrap();
    let second = f.b1.groups.process_as(&mut f.b1.store, &gid, &commit, Some(Expect::Commit)).unwrap();
    assert_eq!(second.kind, "commit");
    f.b1.groups.commit_pending(&mut f.b1.store, &second.pending_id).unwrap();
    assert_eq!(f.b1.epoch(&g), epoch + 1);
    // Our own commit is a commit too.
    let out = f.b1.groups.commit(&mut f.b1.store, &gid, &[], &[], None, true).unwrap();
    f.server.submit(&g, &out.commit).unwrap();
    assert!(f.b1.groups.process_as(&mut f.b1.store, &gid, &out.commit, Some(Expect::Application)).is_err());
    assert_eq!(f.b1.groups.process_as(&mut f.b1.store, &gid, &out.commit, Some(Expect::Commit)).unwrap().kind, "own");
    // The JSON spelling.
    assert_eq!(Expect::parse("application").unwrap(), Expect::Application);
    assert!(Expect::parse("proposal").is_err());
}

#[test]
fn the_ds_insists_on_the_framing_a_submission_is_for() {
    use crate::mls::engine::Expect;
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let message = f.a1.groups.encrypt(&mut f.a1.store, &gid, "x").unwrap();
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    let ds = &mut f.server.ds;
    let err = ds.submit_as(&mut f.server.store, &gid, &out.commit, Some(Expect::Application)).unwrap_err();
    assert!(err.message.contains("expected a application message, but this is a commit one"), "{err}");
    assert!(ds.submit_as(&mut f.server.store, &gid, &message, Some(Expect::Commit)).is_err());
    // Refusals are not conflicts and sequence nothing: both go through for what they are.
    assert_eq!(ds.epoch(&gid).unwrap(), f.a1.epoch(&g));
    assert!(matches!(ds.submit_as(&mut f.server.store, &gid, &message, Some(Expect::Application)).unwrap(), Submit::Accepted { .. }));
    assert!(matches!(ds.submit_as(&mut f.server.store, &gid, &out.commit, Some(Expect::Commit)).unwrap(), Submit::Accepted { .. }));
}

#[test]
fn a_commit_sent_as_a_private_message_is_never_applied() {
    use crate::mls::engine::Expect;
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    // A member that frames its commit as ciphertext, which the DS cannot read: the group is configured to allow it.
    let hidden = f.a1.groups.scratch(&mut f.a1.store, |p, signer, _| {
        let mut group = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        let config = MlsGroupJoinConfig::builder().wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY).build();
        group.set_configuration(p.storage(), &config).unwrap();
        let bundle = group.commit_builder().force_self_update(true).load_psks(p.storage()).unwrap().build(p.rand(), p.crypto(), signer, |_| true).unwrap().stage_commit(p).unwrap();
        tls(bundle.commit())
    });
    let epoch = f.c1.epoch(&g);
    // The DS refuses it as a commit; a member refuses it whatever it expects, and its state is untouched.
    assert!(f.server.ds.submit_as(&mut f.server.store, &gid, &hidden, Some(Expect::Commit)).is_err());
    for expect in [None, Some(Expect::Application)] {
        let err = f.c1.groups.process_as(&mut f.c1.store, &gid, &hidden, expect).unwrap_err();
        assert!(err.message.contains("must be a public message"), "{err}");
    }
    assert!(f.c1.groups.process_as(&mut f.c1.store, &gid, &hidden, Some(Expect::Commit)).is_err());
    assert_eq!(f.c1.epoch(&g), epoch);
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
    f.c1.sync(&f.server, &g);
}

#[test]
fn a_rejected_commit_is_classified_by_what_the_authors_signature_covers() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let epoch = f.c1.epoch(&g);
    let a1_device = f.a1.device.clone();

    // 1. Only a tag is wrong (the last bytes: confirmation tag; the DS cannot see it and relays the commit on). The
    //    author's signature verifies and the signed content is fine: the failure says nothing about the author.
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    let genuine = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &out.commit).unwrap();
    let mut seen_tag = 0;
    for from_end in 1..=40 {
        let mut bad = genuine.clone();
        let at = bad.len() - from_end;
        bad[at] ^= 1;
        let text = b64(&bad);
        let Err(err) = f.c1.groups.process(&mut f.c1.store, &gid, &text) else { panic!("a tampered commit was accepted") };
        if err.code() != Some("poison") { continue; }
        let check = f.c1.groups.commit_author(&mut f.c1.store, &gid, &text).unwrap();
        // The DS-visible part is untouched only for the tag bytes; a flip that reaches the signed content or the
        // signature is not attributable to anyone.
        if check.authenticated {
            assert!(!check.signed_content_invalid, "flip {from_end} from the end");
            assert_eq!(check.author.as_ref().map(|a| a.device_id.as_str()), Some(a1_device.as_str()));
            assert_eq!((err.class.as_deref(), check.class()), (Some("tag"), "tag"), "flip {from_end} from the end");
            seen_tag += 1;
        } else {
            assert_eq!((err.class.as_deref(), check.class(), check.author.is_none()), (Some("tag"), "tag", true), "flip {from_end} from the end");
        }
    }
    assert!(seen_tag > 0, "some flips hit only the tags");
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();

    // 2. A flip in the signed content breaks the signature: not authenticated, so not attributable either.
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    let genuine = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &out.commit).unwrap();
    let mut unauthenticated = 0;
    for at in (30..genuine.len().saturating_sub(100)).step_by(17) {
        let mut bad = genuine.clone();
        bad[at] ^= 1;
        let text = b64(&bad);
        if let Err(err) = f.c1.groups.process(&mut f.c1.store, &gid, &text) {
            if err.code() != Some("poison") { continue; }
            assert_eq!(err.class.as_deref(), Some("tag"), "flip at {at}");
            if let Ok(check) = f.c1.groups.commit_author(&mut f.c1.store, &gid, &text) {
                assert_eq!(check.class(), "tag");
                if !check.authenticated { unauthenticated += 1; }
            }
        }
    }
    assert!(unauthenticated > 0);
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();

    // 3. Content the author really signed that policy forbids (a plain member removing another user): signed-content.
    let evil = f.b1.groups.commit_unchecked(&mut f.b1.store, &gid, &[], &[(f.carol.id.clone(), None)], None, false).unwrap();
    let err = f.a1.groups.process(&mut f.a1.store, &gid, &evil.commit).unwrap_err();
    assert_eq!(err.code(), Some("poison"));
    assert_eq!(err.class.as_deref(), Some("signed-content"), "{err}");
    let check = f.a1.groups.commit_author(&mut f.a1.store, &gid, &evil.commit).unwrap();
    assert_eq!((check.authenticated, check.signed_content_invalid, check.class()), (true, true, "signed-content"));
    assert_eq!(check.author.unwrap().device_id, f.b1.device);
    // The same commit with its tags corrupted by the relay is still the author's signed content.
    let mut flipped = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &evil.commit).unwrap();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let check = f.a1.groups.commit_author(&mut f.a1.store, &gid, &b64(&flipped)).unwrap();
    assert_eq!(check.class(), "signed-content");

    // The group is untouched by all of it, and a commit for another epoch is not judged.
    assert_eq!(f.c1.epoch(&g), epoch);
    f.b1.groups.clear_own(&mut f.b1.store, &gid).unwrap();
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
    f.c1.sync(&f.server, &g);
    assert!(f.c1.groups.commit_author(&mut f.c1.store, &gid, &evil.commit).is_err());
}

#[test]
fn an_external_commit_is_never_attributed_to_anyone() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let (info_text, tree_text) = (f.a1.view(&g).group_info, f.server.tree(&g));
    let unb64 = |text: &str| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, text).unwrap();
    let (info_bytes, tree_bytes) = (unb64(&info_text), unb64(&tree_text));

    // Mallory joins externally with a certificate that names Alice's laptop but is signed by her own account key.
    let mallory = Account::new();
    let (alice_id, laptop) = (f.alice.id.clone(), f.a1.device.clone());
    let forged = f.b1.groups.scratch(&mut f.b1.store, |p, _, _| {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(p.storage()).unwrap();
        let key = key32(&b64(signer.public())).unwrap();
        let cert = DeviceCert::issue(&mallory.aik, &alice_id, &laptop, "web", &key, 0).unwrap();
        let credential = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: signer.public().into() };
        let MlsMessageBodyIn::GroupInfo(info) = MlsMessageIn::tls_deserialize_exact(info_bytes.as_slice()).unwrap().extract() else { panic!("not a GroupInfo") };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree_bytes.as_slice()).unwrap();
        let (_joined, bundle) = MlsGroup::external_commit_builder()
            .with_ratchet_tree(tree)
            .with_config(crate::mls::engine::join_config())
            .build_group(p, info, credential).unwrap()
            .leaf_node_parameters(LeafNodeParameters::builder().with_capabilities(capabilities()).build())
            .load_psks(p.storage()).unwrap()
            .build(p.rand(), p.crypto(), &signer, |_| true).unwrap()
            .finalize(p).unwrap();
        tls(bundle.commit())
    });
    // The DS refuses it (the certificate is not signed by Alice's pinned key)...
    assert!(f.server.submit(&g, &forged).is_err());
    // ...and if a faulty DS relayed it, members reject it without naming Alice's device as the author.
    let err = f.c1.groups.process(&mut f.c1.store, &gid, &forged).unwrap_err();
    assert_eq!((err.code(), err.class.as_deref()), (Some("poison"), Some("tag")), "{err}");
    let check = f.c1.groups.commit_author(&mut f.c1.store, &gid, &forged).unwrap();
    assert_eq!((check.authenticated, check.signed_content_invalid, check.class(), check.author), (false, false, "tag", None));

    // A genuine but unauthorized external join (a stranger to an invite-only group) is not attributed either.
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let out = d1.groups.join_external_unchecked(&mut d1.store, &info_text, &tree_text).unwrap();
    let check = f.c1.groups.commit_author(&mut f.c1.store, &gid, &out.commit).unwrap();
    assert_eq!((check.authenticated, check.class(), check.author), (false, "tag", None));
    assert_eq!(f.c1.groups.process(&mut f.c1.store, &gid, &out.commit).unwrap_err().class.as_deref(), Some("tag"));
}

#[test]
fn a_resolution_is_signed_with_a_leaf_key_every_member_can_check_and_only_admins_count() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let gid = group_id(&f.group).unwrap();
    let digest = "ab".repeat(32);
    let author = f.b1.device.clone();
    let sign = |dev: &mut Dev, action: &str, seq: u64, digest: &str, author: &str| dev.groups.sign_resolution(&mut dev.store, &gid, action, seq, digest, author);

    // An admin device signs; every other member's device verifies it against its own tree, learning who signed.
    let signature = sign(&mut f.a2, "rollback", 7, &digest, &author).unwrap();
    for verifier in [&mut f.b1, &mut f.b2, &mut f.c1, &mut f.a1] {
        let who = verifier.groups.verify_resolution(&mut verifier.store, &gid, "rollback", 7, &digest, &author, &f.a2.device, &f.alice.id, &signature).unwrap();
        assert_eq!((who.user_id.as_str(), who.device_id.as_str()), (f.alice.id.as_str(), f.a2.device.as_str()));
    }
    // An empty author (a rollback that removes nobody) and a dismissal sign too.
    let keep = sign(&mut f.a1, "rollback", 7, &digest, "").unwrap();
    assert!(f.c1.groups.verify_resolution(&mut f.c1.store, &gid, "rollback", 7, &digest, "", &f.a1.device, &f.alice.id, &keep).is_ok());
    let dismiss = sign(&mut f.a1, "dismiss", 7, &digest, "").unwrap();
    assert!(f.c1.groups.verify_resolution(&mut f.c1.store, &gid, "dismiss", 7, &digest, "", &f.a1.device, &f.alice.id, &dismiss).is_ok());

    // Every signed part matters: a different action, seq, digest, author, signer or signature is `auth`.
    let (a2, a1, alice, bob) = (f.a2.device.clone(), f.a1.device.clone(), f.alice.id.clone(), f.bob.id.clone());
    let verify = |dev: &mut Dev, action: &str, seq: u64, digest: &str, author: &str, by: &str, sig: &str| dev.groups.verify_resolution(&mut dev.store, &gid, action, seq, digest, author, by, if by == a1 || by == a2 { &alice } else { &bob }, sig);
    for (name, result) in [
        ("action", verify(&mut f.c1, "dismiss", 7, &digest, &author, &a2, &signature)),
        ("seq", verify(&mut f.c1, "rollback", 8, &digest, &author, &a2, &signature)),
        ("digest", verify(&mut f.c1, "rollback", 7, &"cd".repeat(32), &author, &a2, &signature)),
        ("author", verify(&mut f.c1, "rollback", 7, &digest, "", &a2, &signature)),
        ("signer", verify(&mut f.c1, "rollback", 7, &digest, &author, &a1, &signature)),
        ("signature", verify(&mut f.c1, "rollback", 7, &digest, &author, &a2, &keep)),
    ] {
        assert_eq!(result.unwrap_err().code(), Some("auth"), "{name}");
    }
    // Another group's resolution doesn't carry over.
    let other = rid();
    let mut server2 = Server::new(&[&f.alice]);
    f.a2.create(&mut server2, &other, &Roles::group(vec![f.alice.id.clone()], JoinPolicy::Invite));
    let other_id = group_id(&other).unwrap();
    let elsewhere = f.a2.groups.sign_resolution(&mut f.a2.store, &other_id, "rollback", 7, &digest, &author).unwrap();
    assert_eq!(verify(&mut f.c1, "rollback", 7, &digest, &author, &a2, &elsewhere).unwrap_err().code(), Some("auth"));

    // Only an admin's device counts; strangers and malformed inputs are refused before any signature work.
    let plain = sign(&mut f.b1, "rollback", 7, &digest, &author).unwrap();
    let err = verify(&mut f.c1, "rollback", 7, &digest, &author, &f.b1.device.clone(), &plain).unwrap_err();
    assert!(err.message.contains("only an admin"), "{err}");
    assert!(verify(&mut f.c1, "rollback", 7, &digest, &author, &rid(), &signature).unwrap_err().message.contains("not in this group"));
    for bad in [("remove", digest.clone(), author.clone()), ("rollback", "AB".repeat(32), author.clone()), ("rollback", "ab".repeat(31), author.clone()), ("rollback", digest.clone(), "not a device".to_string())] {
        assert!(sign(&mut f.a1, bad.0, 1, &bad.1, &bad.2).is_err(), "{bad:?}");
        assert!(verify(&mut f.c1, bad.0, 1, &bad.1, &bad.2, &a1, &signature).is_err());
    }
    assert!(verify(&mut f.c1, "rollback", 7, &digest, &author, "short", &signature).is_err());
    assert!(verify(&mut f.c1, "rollback", 7, &digest, &author, &a2, "!!").is_err());
    assert!(verify(&mut f.c1, "rollback", 7, &digest, &author, &a2, &b64(&[0u8; 10])).is_err());
    // A device that was removed can no longer sign for the group.
    f.a1.accepted(&mut f.server, &f.group.clone(), &[], &[(f.bob.id.clone(), Some(f.b2.device.clone()))], None, false);
    f.b2.sync(&f.server, &f.group.clone());
    assert!(sign(&mut f.b2, "rollback", 7, &digest, &author).is_err());
    // The commands spell it the same way.
    let _ = &mut f.server;
}

#[test]
fn a_device_id_names_one_leaf_of_a_group() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let digest = "ab".repeat(32);

    // The signer of a resolution is named by user and device: a device id under another user is not that leaf.
    let signature = f.a2.groups.sign_resolution(&mut f.a2.store, &gid, "rollback", 3, &digest, "").unwrap();
    let who = f.c1.groups.verify_resolution(&mut f.c1.store, &gid, "rollback", 3, &digest, "", &f.a2.device, &f.alice.id, &signature).unwrap();
    assert_eq!(who.device_id, f.a2.device);
    let err = f.c1.groups.verify_resolution(&mut f.c1.store, &gid, "rollback", 3, &digest, "", &f.a2.device, &f.bob.id, &signature).unwrap_err();
    assert!(err.message.contains("not in this group"), "{err}");

    // Carol certifies a leaf with Alice's laptop's device id under her own account key. Adding it is refused by the
    // adding device, by the DS and by members.
    let (laptop, carol_id) = (f.a1.device.clone(), f.carol.id.clone());
    let carol_aik = f.carol.aik.clone();
    let clash = f.c1.groups.scratch(&mut f.c1.store, |p, _, _| {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(p.storage()).unwrap();
        let key = key32(&b64(signer.public())).unwrap();
        let cert = DeviceCert::issue(&carol_aik, &carol_id, &laptop, "web", &key, 0).unwrap();
        let credential = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: signer.public().into() };
        let bundle = KeyPackage::builder().leaf_node_capabilities(capabilities()).build(CS, p, &signer, credential).unwrap();
        tls(&MlsMessageOut::from(bundle.key_package().clone()))
    });
    let err = f.a1.groups.commit(&mut f.a1.store, &gid, &[clash.clone()], &[], None, false).unwrap_err();
    assert!(err.message.contains("already taken"), "{err}");
    let evil = f.a1.groups.commit_unchecked(&mut f.a1.store, &gid, &[clash], &[], None, false).unwrap();
    expect_rejected(&mut f, &evil.commit, "already taken");
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();

    // The same through an external join by Carol with that device id.
    let (info, tree) = (f.a1.view(&g).group_info, f.server.tree(&g));
    let (info_bytes, tree_bytes) = (base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &info).unwrap(), base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &tree).unwrap());
    let (laptop, carol_id, carol_aik) = (f.a1.device.clone(), f.carol.id.clone(), f.carol.aik.clone());
    let joined = f.c1.groups.scratch(&mut f.c1.store, |p, _, _| {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(p.storage()).unwrap();
        let key = key32(&b64(signer.public())).unwrap();
        let cert = DeviceCert::issue(&carol_aik, &carol_id, &laptop, "web", &key, 0).unwrap();
        let credential = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: signer.public().into() };
        let MlsMessageBodyIn::GroupInfo(info) = MlsMessageIn::tls_deserialize_exact(info_bytes.as_slice()).unwrap().extract() else { panic!("not a GroupInfo") };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree_bytes.as_slice()).unwrap();
        let (_g, bundle) = MlsGroup::external_commit_builder().with_ratchet_tree(tree).with_config(crate::mls::engine::join_config())
            .build_group(p, info, credential).unwrap()
            .leaf_node_parameters(LeafNodeParameters::builder().with_capabilities(capabilities()).build())
            .load_psks(p.storage()).unwrap().build(p.rand(), p.crypto(), &signer, |_| true).unwrap().finalize(p).unwrap();
        tls(bundle.commit())
    });
    let err = f.server.submit(&g, &joined).unwrap_err();
    assert!(err.message.contains("already taken"), "{err}");
    // A real resync keeps working: the same user's same device replaces its own leaf.
    f.b2.groups.forget_group(&mut f.b2.store, &gid).unwrap();
    let info = f.a1.view(&g).group_info;
    f.b2.join_external(&mut f.server, &g, &info).unwrap();
    assert_eq!(f.a1.members(&g).len(), 5);
}

#[test]
fn a_missing_pin_is_blamed_on_the_author_only_for_a_leaf_the_commit_introduces() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    // The commit adds a device of a user nobody pinned: the author put that leaf in, so the author is blamed.
    let mallory = Account::new();
    let mut m1 = Dev::new(&mallory, "web", &[&mallory]);
    let kp = m1.kp(1);
    let out = f.a1.groups.commit_unchecked(&mut f.a1.store, &gid, &kp, &[], None, false).unwrap();
    let check = f.c1.groups.commit_author(&mut f.c1.store, &gid, &out.commit).unwrap();
    assert!(check.authenticated && check.signed_content_invalid, "{check:?}");
    assert_eq!(check.author.as_ref().map(|a| a.device_id.as_str()), Some(f.a1.device.as_str()));
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();

    // A leaf the group already held whose user this device has no pin for is this device's gap: the load gate fails
    // closed with a typed `unpinned` error and nobody is blamed.
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    f.c1.store.delete(&format!("peer:{}", f.bob.id)).unwrap();
    assert_eq!(f.c1.groups.commit_author(&mut f.c1.store, &gid, &out.commit).unwrap_err().code(), Some("unpinned"));
}
