//! The scenarios the OpenMLS spike proved, against the real engine.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::harness::*;
use crate::mls::engine::{group_id, Submit};
use crate::mls::policy::{JoinPolicy, Roles};

#[test]
fn multi_device_group_converges() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let members = f.a1.members(&g);
    assert_eq!(members.len(), 5);
    assert_eq!(members.iter().filter(|m| m.admin).count(), 2, "both of alice's devices are admins, nobody else");
    assert!(members.iter().any(|m| m.device_id == f.b2.device && m.user_id == f.bob.id && m.platform == "android"));
    let epoch = f.a1.epoch(&g);
    for dev in [&mut f.a2, &mut f.b1, &mut f.b2, &mut f.c1] { assert_eq!(dev.epoch(&g), epoch); }

    assert!(matches!(f.b2.send(&mut f.server, &g, r#"{"hello":1}"#), Submit::Accepted { .. }));
    f.c1.send(&mut f.server, &g, "from carol");
    for dev in [&mut f.a1, &mut f.a2, &mut f.b1] {
        assert_eq!(dev.texts(&f.server, &g), vec![r#"{"hello":1}"#.to_string(), "from carol".to_string()]);
    }
    let processed = f.a1.sync(&f.server, &g);
    assert!(processed.is_empty(), "already consumed");
}

#[test]
fn received_messages_name_the_authenticated_sender() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    f.b2.send(&mut f.server, &g, "hi");
    let got = f.a1.sync(&f.server, &g);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].kind, "application");
    assert_eq!(got[0].sender.user_id, f.bob.id);
    assert_eq!(got[0].sender.device_id, f.b2.device);
    assert!(!got[0].sender.admin);
}

#[test]
fn removal_is_forward_secret() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    f.a1.accepted(&mut f.server, &g, &[], &[(f.bob.id.clone(), Some(f.b2.device.clone()))], None, false);
    for dev in [&mut f.a2, &mut f.b1, &mut f.c1] { dev.sync(&f.server, &g); }
    let removed = f.b2.sync(&f.server, &g);
    assert_eq!(removed.last().unwrap().kind, "removed");

    f.a1.send(&mut f.server, &g, "after removal");
    assert_eq!(f.b1.texts(&f.server, &g), vec!["after removal".to_string()]);
    assert!(f.b2.try_sync(&f.server, &g).is_err(), "the removed device cannot read the next epoch");
    assert!(f.b2.groups.encrypt(&mut f.b2.store, &group_id(&g).unwrap(), "x").is_err(), "nor write to it");
    assert_eq!(f.a1.members(&g).len(), 4);
}

#[test]
fn removing_a_user_removes_every_device() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    f.a1.accepted(&mut f.server, &g, &[], &[(f.bob.id.clone(), None)], None, false);
    assert_eq!(f.a1.members(&g).len(), 3);
    assert_eq!(f.b1.sync(&f.server, &g).last().unwrap().kind, "removed");
    assert_eq!(f.b2.sync(&f.server, &g).last().unwrap().kind, "removed");
}

#[test]
fn a_member_may_remove_their_own_other_device() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    f.b1.accepted(&mut f.server, &g, &[], &[(f.bob.id.clone(), Some(f.b2.device.clone()))], None, false);
    assert_eq!(f.a1.sync(&f.server, &g).last().unwrap().kind, "commit");
    assert_eq!(f.b2.sync(&f.server, &g).last().unwrap().kind, "removed");
}

#[test]
fn self_update_rotates_the_epoch_and_keeps_messaging() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let before = f.c1.epoch(&g);
    f.c1.accepted(&mut f.server, &g, &[], &[], None, true);
    for dev in [&mut f.a1, &mut f.a2, &mut f.b1, &mut f.b2] { dev.sync(&f.server, &g); }
    assert_eq!(f.c1.epoch(&g), before + 1);
    assert_eq!(f.a1.epoch(&g), before + 1);
    f.b1.send(&mut f.server, &g, "still works");
    assert_eq!(f.c1.texts(&f.server, &g), vec!["still works".to_string()]);
}

#[test]
fn concurrent_commits_conflict_then_rebuild() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let kp = d1.kp(1);

    // a1 and a2 (both admins) build on the same epoch. a1 wins.
    let (_, first) = f.a1.commit(&mut f.server, &g, &[], &[], None, true).unwrap();
    assert!(matches!(first, Submit::Accepted { .. }));
    let (_, second) = f.a2.commit(&mut f.server, &g, &kp, &[], None, false).unwrap();
    assert!(matches!(second, Submit::Conflict { epoch } if epoch == f.server.epoch(&g)));
    assert_eq!(f.a2.epoch(&g), f.a1.epoch(&g) - 1, "the loser did not advance");

    // The loser catches up from the log and rebuilds.
    assert_eq!(f.a2.sync(&f.server, &g).len(), 1);
    let out = f.a2.accepted(&mut f.server, &g, &kp, &[], None, false);
    d1.join(&mut f.server, &out.welcome.unwrap(), &g);
    for dev in [&mut f.a1, &mut f.b1, &mut f.b2, &mut f.c1] { dev.sync(&f.server, &g); }
    let epoch = f.server.epoch(&g);
    for dev in [&mut f.a1, &mut f.a2, &mut f.b1, &mut f.b2, &mut f.c1, &mut d1] { assert_eq!(dev.epoch(&g), epoch); }
    assert_eq!(f.a1.members(&g).len(), 6);
}

#[test]
fn a_stale_application_message_is_a_conflict() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let stale = f.b1.groups.encrypt(&mut f.b1.store, &group_id(&g).unwrap(), "late").unwrap();
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
    assert!(matches!(f.server.submit(&g, &stale).unwrap(), Submit::Conflict { .. }));
}

#[test]
fn an_ambiguous_submit_is_resolved_from_the_log() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    // The DS sequenced a1's commit but the response was lost: a1 still holds it pending.
    let out = f.a1.groups.commit(&mut f.a1.store, &group_id(&g).unwrap(), &[], &[], None, true).unwrap();
    let pending = f.a1.groups.pending_digest(&mut f.a1.store, &group_id(&g).unwrap()).unwrap().unwrap();
    assert_eq!(pending["digest"], out.digest);
    f.server.submit(&g, &out.commit).unwrap();
    let before = f.a1.epoch(&g);
    let processed = f.a1.sync(&f.server, &g);
    assert_eq!(processed.last().unwrap().kind, "own");
    assert_eq!(processed.last().unwrap().digest.as_deref(), Some(out.digest.as_str()));
    assert_eq!(f.a1.epoch(&g), before + 1);
    assert!(f.a1.groups.pending_digest(&mut f.a1.store, &group_id(&g).unwrap()).unwrap().is_none());
    f.b1.sync(&f.server, &g);
    f.b1.send(&mut f.server, &g, "ok");
    assert_eq!(f.a1.texts(&f.server, &g), vec!["ok".to_string()]);
}

#[test]
fn only_one_commit_may_be_pending() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = group_id(&f.group).unwrap();
    f.a1.groups.commit(&mut f.a1.store, &g, &[], &[], None, true).unwrap();
    assert!(f.a1.groups.commit(&mut f.a1.store, &g, &[], &[], None, true).is_err());
    f.a1.groups.clear_own(&mut f.a1.store, &g).unwrap();
    f.a1.groups.commit(&mut f.a1.store, &g, &[], &[], None, true).unwrap();
}

#[test]
fn open_channel_allows_a_stranger_to_join_externally() {
    let mut f = Fixture::new(JoinPolicy::Open);
    let g = f.group.clone();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let info = f.a1.view(&g).group_info;
    d1.join_external(&mut f.server, &g, &info).unwrap();
    let seen = f.a1.sync(&f.server, &g);
    assert_eq!(seen.last().unwrap().sender.user_id, dave.id);
    assert_eq!(f.a1.members(&g).len(), 6);
    d1.send(&mut f.server, &g, "hi all");
    assert_eq!(f.c1.texts(&f.server, &g).last().unwrap(), "hi all");
    f.a2.sync(&f.server, &g);
    f.b1.sync(&f.server, &g);
}

#[test]
fn invite_only_refuses_a_stranger_everywhere() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let (info, tree) = (f.a1.view(&g).group_info, f.server.tree(&g));

    // The joiner refuses to build it.
    assert!(d1.groups.join_external(&mut d1.store, &info, &tree).is_err());
    // A joiner that skips its own check is refused by the DS...
    let out = d1.groups.join_external_unchecked(&mut d1.store, &info, &tree).unwrap();
    let err = f.server.submit(&g, &out.commit).unwrap_err();
    assert!(err.message.contains("may not join"), "{err}");
    // ...and by every member, if a faulty DS let it through.
    let err = f.a1.groups.process(&mut f.a1.store, &group_id(&g).unwrap(), &out.commit).unwrap_err();
    assert_eq!(err.code(), Some("poison"));
    assert!(err.message.contains("may not join"));
    assert_eq!(f.a1.epoch(&g), f.server.epoch(&g), "nothing changed");
}

#[test]
fn a_users_new_device_may_join_an_invite_only_group_externally() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let all = [&f.alice, &f.bob, &f.carol];
    let mut b3 = Dev::new(&f.bob, "ios", &all);
    let info = f.b1.view(&g).group_info;
    b3.join_external(&mut f.server, &g, &info).unwrap();
    f.a1.sync(&f.server, &g);
    assert_eq!(f.a1.members(&g).len(), 6);
    b3.send(&mut f.server, &g, "from my new phone");
    assert_eq!(f.c1.texts(&f.server, &g).last().unwrap(), "from my new phone");
    f.a2.sync(&f.server, &g);
    f.b1.sync(&f.server, &g);
    f.b2.sync(&f.server, &g);
}

#[test]
fn resync_replaces_a_broken_copy_with_the_same_leaf_key() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let info = f.a1.view(&g).group_info;
    f.b2.groups.forget_group(&mut f.b2.store, &gid).unwrap();
    assert!(f.b2.groups.members(&mut f.b2.store, &gid).is_err(), "forgotten");
    f.b2.join_external(&mut f.server, &g, &info).unwrap();
    f.a1.sync(&f.server, &g);
    assert_eq!(f.a1.members(&g).len(), 5, "the old leaf was replaced, not duplicated");
    f.b2.send(&mut f.server, &g, "back");
    assert_eq!(f.c1.texts(&f.server, &g).last().unwrap(), "back");
    f.a1.send(&mut f.server, &g, "welcome back");
    assert_eq!(f.b2.texts(&f.server, &g), vec!["welcome back".to_string()]);
    f.a2.sync(&f.server, &g);
    f.b1.sync(&f.server, &g);
}

#[test]
fn an_existing_copy_must_be_forgotten_before_resync() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let info = f.a1.view(&g).group_info;
    assert!(f.b2.groups.join_external(&mut f.b2.store, &info, &f.server.tree(&g)).is_err());
}

#[test]
fn last_resort_key_packages_are_reusable_and_normal_ones_are_consumed() {
    let alice = Account::new();
    let bob = Account::new();
    let all = [&alice, &bob];
    let mut server = Server::new(&all);
    let mut a1 = Dev::new(&alice, "linux", &all);
    let mut b1 = Dev::new(&bob, "web", &all);
    let mut b2 = Dev::new(&bob, "ios", &all);
    let reusable = b1.last_resort();
    let one_time = b2.kp(1).remove(0);
    let roles = Roles::group(vec![alice.id.clone()], JoinPolicy::Invite);

    let (g1, g2) = (rid(), rid());
    for g in [&g1, &g2] {
        a1.create(&mut server, g, &roles);
        let out = a1.accepted(&mut server, g, &[reusable.clone()], &[], None, false);
        b1.join(&mut server, &out.welcome.unwrap(), g);
    }
    assert_ne!(b1.epoch(&g1), 0);

    // A normal KeyPackage works once.
    let out = a1.accepted(&mut server, &g1, &[one_time.clone()], &[], None, false);
    b2.join(&mut server, &out.welcome.unwrap(), &g1);
    let out = a1.accepted(&mut server, &g2, &[one_time], &[], None, false);
    let err = b2.groups.join(&mut b2.store, &out.welcome.unwrap(), &server.tree(&g2)).unwrap_err();
    assert!(err.code().is_some(), "{err}");
}

#[test]
fn tampered_commits_are_rejected_by_the_ds_or_by_every_member() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let dave = Account::new();
    let mut d1 = f.admit(&dave, "web");
    let kp = d1.kp(1);
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &kp, &[], None, false).unwrap();
    let genuine = URL_SAFE_NO_PAD.decode(&out.commit).unwrap();
    let snapshot = f.server.ds.snapshot(&gid).unwrap();

    let mut ds_rejected = 0;
    let mut member_rejected = 0;
    let mut positions: Vec<usize> = (0..genuine.len().saturating_sub(64)).step_by(11).collect();
    positions.extend(genuine.len() - 64..genuine.len());
    for at in positions {
        let mut bad = genuine.clone();
        bad[at] ^= 0x01;
        let text = b64(&bad);
        match f.server.ds.submit(&mut f.server.store, &gid, &text) {
            Err(_) => ds_rejected += 1,
            Ok(Submit::Conflict { .. }) => ds_rejected += 1,
            Ok(Submit::Accepted { .. }) => {
                // The confirmation and membership tags need epoch secrets the DS lacks; members do not accept it.
                let err = f.b1.groups.process(&mut f.b1.store, &gid, &text).unwrap_err();
                assert_eq!(err.code(), Some("poison"), "flip at {at}: {err}");
                member_rejected += 1;
                f.server.ds.restore(&mut f.server.store, &gid, &snapshot).unwrap();
            }
        }
        assert_eq!(f.server.epoch(&g), f.b1.epoch(&g), "flip at {at} changed the DS");
    }
    assert!(ds_rejected > 20, "the DS rejects most flips ({ds_rejected})");
    assert!(member_rejected > 0, "the tag bytes are only caught by members");

    // Failed processing left the member untouched: the genuine commit still applies.
    f.server.submit(&g, &out.commit).unwrap();
    f.a1.groups.merge_own(&mut f.a1.store, &gid).unwrap();
    let processed = f.b1.groups.process(&mut f.b1.store, &gid, &out.commit).unwrap();
    f.b1.groups.commit_pending(&mut f.b1.store, &processed.pending_id).unwrap();
    assert_eq!(f.b1.epoch(&g), f.a1.epoch(&g));
}

#[test]
fn a_poison_commit_is_rolled_back_from_the_ds_snapshot() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let snapshot = f.server.ds.snapshot(&gid).unwrap();
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    let mut bad = URL_SAFE_NO_PAD.decode(&out.commit).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let text = b64(&bad);
    assert!(matches!(f.server.ds.submit(&mut f.server.store, &gid, &text).unwrap(), Submit::Accepted { .. }));
    let err = f.b1.groups.process(&mut f.b1.store, &gid, &text).unwrap_err();
    assert_eq!(err.code(), Some("poison"));
    assert!(err.message.starts_with(&format!("poison {}", crate::mls::digest(&bad))));
    // The DS is now one epoch ahead of every member. Roll it back.
    assert_eq!(f.server.epoch(&g), f.b1.epoch(&g) + 1);
    f.server.ds.restore(&mut f.server.store, &gid, &snapshot).unwrap();
    assert_eq!(f.server.epoch(&g), f.b1.epoch(&g));
    f.a1.groups.clear_own(&mut f.a1.store, &gid).unwrap();
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
    f.b1.sync(&f.server, &g);
    assert_eq!(f.b1.epoch(&g), f.a1.epoch(&g));
}

#[test]
fn tampered_application_messages_fail_without_harming_the_receiver() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let message = f.a1.groups.encrypt(&mut f.a1.store, &gid, "secret").unwrap();
    let genuine = URL_SAFE_NO_PAD.decode(&message).unwrap();
    for at in [genuine.len() - 1, genuine.len() / 2, 40] {
        let mut bad = genuine.clone();
        bad[at] ^= 0x80;
        let err = f.b1.groups.process(&mut f.b1.store, &gid, &b64(&bad)).unwrap_err();
        assert!(err.code().is_some(), "flip at {at} is a permanent failure: {err}");
    }
    let processed = f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap();
    assert_eq!(processed.plaintext.as_deref(), Some("secret"));
    f.b1.groups.commit_pending(&mut f.b1.store, &processed.pending_id).unwrap();
    // The same message again is a replay.
    assert_eq!(f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap_err().code(), Some("replay"));
}

#[test]
fn processing_is_two_phase_and_abortable() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    f.a1.send(&mut f.server, &g, "one");
    let message = f.server.log[&g].last().unwrap().clone();
    let first = f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap();
    f.b1.groups.abort(&first.pending_id);
    assert!(f.b1.groups.commit_pending(&mut f.b1.store, &first.pending_id).is_err(), "aborted");
    // Nothing advanced: redelivery decrypts again.
    let again = f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap();
    assert_eq!(again.plaintext.as_deref(), Some("one"));
    f.b1.groups.commit_pending(&mut f.b1.store, &again.pending_id).unwrap();
}

#[test]
fn a_dm_is_two_users_and_nobody_else() {
    let alice = Account::new();
    let bob = Account::new();
    let carol = Account::new();
    let all = [&alice, &bob, &carol];
    let mut server = Server::new(&all);
    let (mut a1, mut a2, mut b1, mut c1) = (Dev::new(&alice, "linux", &all), Dev::new(&alice, "ios", &all), Dev::new(&bob, "web", &all), Dev::new(&carol, "web", &all));
    let g = rid();
    a1.create(&mut server, &g, &Roles::dm(&alice.id, &bob.id));
    let kps = [a2.kp(1), b1.kp(1)].concat();
    let out = a1.accepted(&mut server, &g, &kps, &[], None, false);
    let welcome = out.welcome.unwrap();
    a2.join(&mut server, &welcome, &g);
    b1.join(&mut server, &welcome, &g);

    // A third user can't be added, and a DM's users can't remove each other.
    assert!(a1.commit(&mut server, &g, &c1.kp(1), &[], None, false).is_err());
    assert!(a1.commit(&mut server, &g, &[], &[(bob.id.clone(), None)], None, false).is_err());
    // Nor join externally.
    let info = a1.view(&g).group_info;
    assert!(c1.join_external(&mut server, &g, &info).is_err());
    // A new device of a DM user may.
    let mut b2 = Dev::new(&bob, "android", &all);
    b2.join_external(&mut server, &g, &info).unwrap();
    b1.sync(&server, &g);
    b2.send(&mut server, &g, "hello alice");
    assert_eq!(a2.texts(&server, &g).last().unwrap(), "hello alice");
}
