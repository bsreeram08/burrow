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
use crate::mls::engine::group_id;
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
fn a_pin_for_another_key_fails_every_certificate() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let gid = group_id(&f.group).unwrap();
    let impostor = Account::new();
    f.b1.store.put(&format!("peer:{}", f.alice.id), serde_json::json!({ "aik": impostor.pin() })).unwrap();
    f.b1.restart();
    let err = f.b1.groups.encrypt(&mut f.b1.store, &gid, "x").unwrap_err();
    assert!(err.message.contains("not signed by the pinned account key"), "{err}");
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
