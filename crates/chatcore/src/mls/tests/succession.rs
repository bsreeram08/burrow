//! Identity succession in groups (docs/m5-linking.md §7): stale leaves, predecessor keys, recovery.
use ed25519_dalek::Signer;
use serde_json::{json, Value};

use super::harness::*;
use crate::mls::engine::group_id;
use crate::mls::policy::JoinPolicy;
use crate::store::Store;
use crate::succession::Record;

const AT: u64 = 1_800_000_000_000;

fn point(dev: &mut Dev, user: &Account, new: &Account, previous: Option<(&Account, u64)>) {
    let mut pin = json!({ "aik": new.pin() });
    if let Some((old, until)) = previous { pin["previous"] = json!([{ "sign": old.pin(), "until": until }]); }
    dev.store.put(&format!("peer:{}", user.id), pin).unwrap();
    dev.restart();
}

fn record(old: &Account, new: &Account, at: u64) -> Value {
    let record = Record { user_id: old.id.clone(), old_sign: old.pin(), new_sign: new.pin(), new_dh: b64(&[7u8; 32]), at };
    let signature = b64(&old.aik.sign(&record.bytes()).to_bytes());
    record.json(&signature)
}

#[test]
fn after_a_recovery_the_old_devices_are_stale_removable_and_cannot_act() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    f.b1.send(&mut f.server, &g, "before");
    let bob = f.bob.rekeyed();
    // Everyone who reviewed Bob's new code pins it; the registry (DS) follows.
    for dev in [&mut f.a1, &mut f.a2, &mut f.c1] { point(dev, &f.bob, &bob, None); }
    f.server.ds.repin(&mut f.server.store, &bob.id, &bob.pin()).unwrap();
    let all = [&f.alice, &bob, &f.carol];
    let mut b3 = Dev::new(&bob, "ios", &all);

    // Bob's old devices are stale, and nothing they say or commit counts any more.
    let stale: Vec<_> = f.a1.members(&g).into_iter().filter(|m| m.stale).map(|m| m.device_id).collect();
    assert_eq!(stale.len(), 2);
    assert!(stale.contains(&f.b1.device) && stale.contains(&f.b2.device));
    f.b1.send(&mut f.server, &g, "from an old device");
    let err = f.a1.try_sync(&f.server, &g).unwrap_err();
    assert_eq!(err.code(), Some("stale"), "{err}");
    f.a1.skip_next(&g);
    let err = f.b2.commit(&mut f.server, &g, &[], &[], None, true).unwrap_err();
    assert!(err.message.contains("an identity this user left"), "{err}");

    // Nobody can add people while stale leaves remain (a Welcome must be entirely current)...
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    for dev in [&mut f.a1] { point(dev, &f.bob, &bob, None); dev.store.put(&format!("peer:{}", dave.id), json!({ "aik": dave.pin() })).unwrap(); dev.restart(); }
    point(&mut d1, &f.bob, &bob, None);
    let kp = d1.kp(1);
    let err = f.a1.commit(&mut f.server, &g, &kp, &[], None, false).unwrap_err();
    assert!(err.message.contains("before adding people"), "{err}");
    // ...nor does a joiner accept a Welcome that still holds one.
    let evil = f.a1.groups.commit_unchecked(&mut f.a1.store, &gid, &kp, &[], None, false).unwrap();
    let err = f.server.submit(&g, &evil.commit).unwrap_err();
    assert!(err.message.contains("before adding people"), "{err}");
    let tree = f.a1.groups.scratch(&mut f.a1.store, |p, _, _| {
        use openmls::prelude::*;
        use openmls::prelude::tls_codec::Serialize as _;
        let mut group = MlsGroup::load(p.storage(), &gid).unwrap().unwrap();
        group.merge_pending_commit(p).unwrap();
        b64(&group.export_ratchet_tree().tls_serialize_detached().unwrap())
    });
    let err = d1.groups.join(&mut d1.store, &evil.welcome.unwrap(), &tree).unwrap_err();
    assert!(err.message.contains("not signed by the pinned account key"), "{err}");
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();

    // Bob's new device rejoins (the account is still in the group through its stale leaves) and cleans up.
    let info = f.a1.view(&g).group_info;
    b3.join_external(&mut f.server, &g, &info).unwrap();
    for dev in [&mut f.a1, &mut f.a2, &mut f.c1] { dev.sync_lossy(&f.server, &g); }
    b3.accepted(&mut f.server, &g, &[], &[(bob.id.clone(), Some(f.b1.device.clone())), (bob.id.clone(), Some(f.b2.device.clone()))], None, false);
    for dev in [&mut f.a1, &mut f.a2, &mut f.c1] { dev.sync(&f.server, &g); }
    assert!(f.a1.members(&g).iter().all(|m| !m.stale));
    // People can be added again.
    let out = f.a1.accepted(&mut f.server, &g, &kp, &[], None, false);
    d1.join(&mut f.server, &out.welcome.unwrap(), &g);
    b3.store.put(&format!("peer:{}", dave.id), json!({ "aik": dave.pin() })).unwrap();
    b3.sync(&f.server, &g);
    assert!(matches!(b3.send(&mut f.server, &g, "new device"), crate::mls::engine::Submit::Accepted { .. }));
    assert!(f.c1.texts(&f.server, &g).contains(&"new device".to_string()));
}

#[test]
fn a_signed_succession_keeps_the_old_devices_working_for_certificates_issued_before_it() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let bob = f.bob.rekeyed();
    let records = vec![record(&f.bob, &bob, AT)];
    // The DS and the members accept the record: the pin moves and keeps the old key as a predecessor.
    f.server.ds.succeed(&mut f.server.store, &bob.id, &records).unwrap();
    for dev in [&mut f.a1, &mut f.a2, &mut f.c1] { point(dev, &f.bob, &bob, Some((&f.bob, AT))); }
    assert!(f.a1.members(&g).iter().all(|m| !m.stale), "certificates issued before the succession still count");
    f.b1.send(&mut f.server, &g, "still me");
    assert_eq!(f.a1.texts(&f.server, &g), vec!["still me".to_string()]);
    f.b2.accepted(&mut f.server, &g, &[], &[], None, true);
    f.a1.sync(&f.server, &g);

    // A certificate the old key issues after the succession is stale: it cannot join, and cannot be added.
    let late = Dev::issued(&f.bob, "linux", &[&f.alice, &bob, &f.carol], AT + 1);
    let mut late = late;
    let err = f.a1.commit(&mut f.server, &g, &late.kp(1), &[], None, false).unwrap_err();
    assert!(err.message.contains("not signed by the pinned account key"), "{err}");

    // The old key cannot mint a backdated certificate for a new leaf either: issued_at is the signer's word.
    let mut backdated = Dev::issued(&f.bob, "linux", &[&f.alice, &bob, &f.carol], AT - 1);
    let err = f.a1.commit(&mut f.server, &g, &backdated.kp(1), &[], None, false).unwrap_err();
    assert!(err.message.contains("not signed by the pinned account key"), "{err}");

    // Nobody is added while leaves on the previous key remain (a Welcome would refuse them): they go (or recertify) first.
    let mut b3 = Dev::new(&bob, "ios", &[&f.alice, &bob, &f.carol]);
    // The new primary remembers the key it succeeded (succession_complete does this).
    b3.store.put("own-previous", json!([{ "sign": f.bob.pin(), "until": AT }])).unwrap();
    let err = f.a1.commit(&mut f.server, &g, &b3.kp(1), &[], None, false).unwrap_err();
    assert!(err.message.contains("previous account key"), "{err}");
    f.a1.accepted(&mut f.server, &g, &[], &[(f.bob.id.clone(), None)], None, false);
    let out = f.a1.accepted(&mut f.server, &g, &b3.kp(1), &[], None, false);
    b3.join(&mut f.server, &out.welcome.unwrap(), &g);
    b3.send(&mut f.server, &g, "from the new primary");
    assert!(f.c1.texts(&f.server, &g).contains(&"from the new primary".to_string()));
}

#[test]
fn a_device_takes_its_own_account_key_from_the_core_and_its_certificates_key_is_a_predecessor() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let bob = f.bob.rekeyed();
    // After a succession the core's account row holds the new key; this device's certificate still names the old one.
    f.b1.store.put("account", json!({ "userId": f.bob.id, "identity": { "sign": bob.pin(), "dh": b64(&[7u8; 32]) } })).unwrap();
    f.b1.restart();
    assert!(f.b1.members(&g).iter().any(|m| m.stale), "an unrecorded old key is stale, not trusted from our own certificate");
    f.b1.store.put("own-previous", json!([{ "sign": f.bob.pin(), "until": AT }])).unwrap();
    f.b1.restart();
    assert!(f.b1.members(&g).iter().all(|m| !m.stale), "recorded as a predecessor, the certificate still counts");
}

#[test]
fn succession_records_are_followed_only_from_the_pinned_key_and_only_when_signed_by_it() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let (bob, mallory) = (f.bob.rekeyed(), f.bob.rekeyed());
    let ds = |f: &mut Fixture, records: Vec<Value>| f.server.ds.succeed(&mut f.server.store, &f.bob.id.clone(), &records);
    let good = record(&f.bob, &bob, AT);
    // Signed by someone else, naming the wrong user, wrong start, unknown fields, empty, too long.
    let forged = { let r = Record { user_id: f.bob.id.clone(), old_sign: f.bob.pin(), new_sign: mallory.pin(), new_dh: b64(&[7u8; 32]), at: AT }; r.json(&b64(&mallory.aik.sign(&r.bytes()).to_bytes())) };
    assert_eq!(ds(&mut f, vec![forged]).unwrap_err().code(), Some("auth"));
    let mut elsewhere = good.clone(); elsewhere["userId"] = json!(rid());
    assert!(ds(&mut f, vec![elsewhere]).is_err());
    assert!(ds(&mut f, vec![record(&mallory, &bob, AT)]).is_err(), "must start at the pinned key");
    let mut extra = good.clone(); extra["x"] = json!(1);
    assert!(ds(&mut f, vec![extra]).is_err());
    assert!(ds(&mut f, vec![]).is_err());
    assert!(ds(&mut f, (0..9).map(|_| good.clone()).collect()).is_err());
    let mut tampered = good.clone(); tampered["at"] = json!(AT + 1);
    assert_eq!(ds(&mut f, vec![tampered]).unwrap_err().code(), Some("auth"));
    // A broken chain: the second record must start where the first ended.
    assert!(ds(&mut f, vec![good.clone(), record(&mallory, &bob, AT + 5)]).is_err());
    // Nothing above changed the pin; the real chain, two hops, does.
    let third = bob.rekeyed();
    ds(&mut f, vec![good.clone(), record(&bob, &third, AT + 5)]).unwrap();
    let pinned = f.server.store.get(&format!("mlsdsx:pin:{}", f.bob.id)).unwrap().unwrap();
    assert_eq!(pinned["aik"], json!(third.pin()));
    assert_eq!(pinned["previous"], json!([{ "aik": f.bob.pin(), "until": AT }, { "aik": bob.pin(), "until": AT + 5 }]));
}

#[test]
fn a_dm_pointer_is_accepted_only_for_the_dm_of_these_two_people_with_every_leaf_current() {
    use crate::mls::policy::Roles;
    let alice = Account::new();
    let (bob, carol) = (Account::new(), Account::new());
    let all = [&alice, &bob, &carol];
    let mut server = Server::new(&all);
    let (mut a1, mut a2, mut b1) = (Dev::new(&alice, "linux", &all), Dev::new(&alice, "ios", &all), Dev::new(&bob, "web", &all));
    let dm = rid();
    a1.create(&mut server, &dm, &Roles::dm(&alice.id, &bob.id));
    let out = a1.accepted(&mut server, &dm, &[a2.kp(1), b1.kp(1)].concat(), &[], None, false);
    let welcome = out.welcome.unwrap();
    a2.join(&mut server, &welcome, &dm);
    b1.join(&mut server, &welcome, &dm);
    let gid = group_id(&dm).unwrap();

    // Bob's device checks the pointer from Alice: the DM of exactly these two people, every leaf current.
    b1.groups.check_dm(&mut b1.store, &gid, &alice.id).unwrap();
    a2.groups.check_dm(&mut a2.store, &gid, &bob.id).unwrap();
    // Not another person's DM, not a group, not a DM that names someone else.
    assert!(b1.groups.check_dm(&mut b1.store, &gid, &carol.id).is_err());
    let group = rid();
    a1.create(&mut server, &group, &Roles::group(vec![alice.id.clone()], JoinPolicy::Invite));
    assert!(a1.groups.check_dm(&mut a1.store, &group_id(&group).unwrap(), &bob.id).is_err());
    let err = b1.groups.check_dm(&mut b1.store, &group_id(&rid()).unwrap(), &alice.id).unwrap_err();
    assert_eq!(err.code(), Some("unknown-group"));
    // A leaf of an identity Alice left no longer chains to the pins.
    let new_alice = alice.rekeyed();
    point(&mut b1, &alice, &new_alice, None);
    assert!(b1.groups.check_dm(&mut b1.store, &gid, &alice.id).unwrap_err().message.contains("does not chain"));
}

#[test]
fn a_new_primary_recertifies_its_own_leaf_under_the_identity_it_now_holds() {
    let account = Account::new();
    let mut dev = Dev::new(&account, "web", &[&account]);
    let old = dev.groups.key_packages(&mut dev.store, 1, false).unwrap();
    assert_eq!(old.len(), 1);
    let successor = account.rekeyed();
    let cert = dev.groups.recertify_device(&mut dev.store, "web", 2_000_000_000_000, &successor.aik).unwrap();
    assert_eq!((cert.user_id.as_str(), cert.device_id.as_str(), cert.aik_sign.as_str()), (account.id.as_str(), dev.device.as_str(), successor.pin().as_str()));
    // Same leaf key, so KeyPackages made now carry the new certificate.
    let fresh = dev.groups.key_packages(&mut dev.store, 1, false).unwrap();
    assert_ne!(fresh, old);
}

#[test]
fn inspecting_a_served_group_validates_it_without_joining_and_reports_stale_leaves() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let view = f.a1.view(&g);
    let seen = f.c1.groups.inspect_group(&mut f.c1.store, &view.group_info, &view.tree).unwrap();
    assert_eq!(seen.len(), 5);
    assert!(seen.iter().all(|m| !m.stale));
    assert!(f.c1.groups.members(&mut f.c1.store, &group_id(&g).unwrap()).is_ok(), "c1 was already a member; nothing changed");
    // A stranger device that is not in the group stores nothing either.
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    d1.store.put(&format!("peer:{}", f.alice.id), json!({ "aik": f.alice.pin() })).unwrap();
    d1.store.put(&format!("peer:{}", f.bob.id), json!({ "aik": f.bob.pin() })).unwrap();
    d1.store.put(&format!("peer:{}", f.carol.id), json!({ "aik": f.carol.pin() })).unwrap();
    assert_eq!(d1.groups.inspect_group(&mut d1.store, &view.group_info, &view.tree).unwrap().len(), 5);
    assert!(d1.groups.members(&mut d1.store, &group_id(&g).unwrap()).is_err(), "not joined");
    // Stale leaves are reported, a tampered tree or GroupInfo is refused, an unknown identity is refused.
    let bob = f.bob.rekeyed();
    point(&mut d1, &f.bob, &bob, None);
    let stale: Vec<_> = d1.groups.inspect_group(&mut d1.store, &view.group_info, &view.tree).unwrap().into_iter().filter(|m| m.stale).map(|m| m.user_id).collect();
    assert_eq!(stale, vec![f.bob.id.clone(), f.bob.id.clone()]);
    let mut tree = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &view.tree).unwrap();
    let at = tree.len() / 2;
    tree[at] ^= 1;
    assert!(d1.groups.inspect_group(&mut d1.store, &view.group_info, &b64(&tree)).is_err());
    assert!(d1.groups.inspect_group(&mut d1.store, "AAAA", &view.tree).is_err());
    d1.store.delete(&format!("peer:{}", f.carol.id)).unwrap();
    assert!(d1.groups.inspect_group(&mut d1.store, &view.group_info, &view.tree).unwrap_err().message.contains("no pinned account key"));
}
