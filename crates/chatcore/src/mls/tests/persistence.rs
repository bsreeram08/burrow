//! Restart survival and the journaled store: what is written, what is reloaded, and what is refused on load.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use super::harness::*;
use crate::core::Core;
use crate::error::ChatError;
use crate::mls::engine::{group_id, Groups};
use crate::mls::policy::{JoinPolicy, Roles};
use crate::store::{JournaledStore, MemoryStore, Store, Write};

#[test]
fn every_device_and_the_ds_survive_a_restart() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    f.b1.send(&mut f.server, &g, "before");
    f.a1.sync(&f.server, &g);
    for dev in [&mut f.a1, &mut f.a2, &mut f.b1, &mut f.b2, &mut f.c1] { dev.restart(); }
    f.server.restart();

    f.a2.send(&mut f.server, &g, "after");
    assert_eq!(f.c1.texts(&f.server, &g), vec!["before".to_string(), "after".to_string()]);
    assert_eq!(f.b2.texts(&f.server, &g), vec!["before".to_string(), "after".to_string()]);
    f.c1.accepted(&mut f.server, &g, &[], &[], None, true);
    f.c1.restart();
    f.server.restart();
    for dev in [&mut f.a1, &mut f.a2, &mut f.b1, &mut f.b2] { dev.sync(&f.server, &g); }
    f.b2.send(&mut f.server, &g, "after the update");
    assert_eq!(f.a1.texts(&f.server, &g), vec!["after the update".to_string()]);
    assert_eq!(f.server.epoch(&g), f.a1.epoch(&g));
}

#[test]
fn a_pending_commit_survives_a_restart() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let out = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap();
    f.a1.restart();
    let pending = f.a1.groups.pending_commit(&mut f.a1.store, &gid).unwrap().unwrap();
    assert_eq!(pending.digest, out.digest);
    assert_eq!(pending.epoch, out.epoch);
    f.server.submit(&g, &out.commit).unwrap();
    let before = f.a1.epoch(&g);
    f.a1.groups.merge_own(&mut f.a1.store, &gid).unwrap();
    assert_eq!(f.a1.epoch(&g), before + 1);
    assert!(f.a1.groups.pending_commit(&mut f.a1.store, &gid).unwrap().is_none());
}

#[test]
fn a_received_message_persists_only_at_commit_pending() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    f.a1.send(&mut f.server, &g, "one");
    let message = f.server.log[&g].last().unwrap().clone();
    let processed = f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap();
    // The app crashed before storing the message and committing: the redelivery decrypts again.
    f.b1.restart();
    assert!(f.b1.groups.commit_pending(&mut f.b1.store, &processed.pending_id).is_err());
    let again = f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap();
    assert_eq!(again.plaintext.as_deref(), Some("one"));
    f.b1.groups.commit_pending(&mut f.b1.store, &again.pending_id).unwrap();
    f.b1.restart();
    assert_eq!(f.b1.groups.process(&mut f.b1.store, &gid, &message).unwrap_err().code(), Some("replay"));
}

#[test]
fn commit_pending_refuses_when_the_group_changed_in_between() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    f.a1.send(&mut f.server, &g, "one");
    f.a1.send(&mut f.server, &g, "two");
    let (one, two) = (f.server.log[&g][1].clone(), f.server.log[&g][2].clone());
    let first = f.b1.groups.process(&mut f.b1.store, &gid, &one).unwrap();
    let second = f.b1.groups.process(&mut f.b1.store, &gid, &two).unwrap();
    f.b1.groups.commit_pending(&mut f.b1.store, &second.pending_id).unwrap();
    let err = f.b1.groups.commit_pending(&mut f.b1.store, &first.pending_id).unwrap_err();
    assert_eq!(err.code(), None, "transient: process it again");
}

#[test]
fn a_journaled_store_replays_into_the_same_state() {
    let alice = Account::new();
    let bob = Account::new();
    let (mut store, journal) = JournaledStore::new(BTreeMap::new(), true);
    let mut groups = Groups::load(&mut store, "mls").unwrap();
    groups.init_device(&mut store, &alice.id, &rid(), "web", 0, &alice.aik).unwrap();
    store.put(&format!("peer:{}", bob.id), json!({ "aik": bob.pin() })).unwrap();
    let mut b1 = Dev::new(&bob, "ios", &[&alice, &bob]);
    let g = rid();
    let gid = group_id(&g).unwrap();
    groups.create(&mut store, &gid, &Roles::group(vec![alice.id.clone()], JoinPolicy::Invite)).unwrap();
    let out = groups.commit(&mut store, &gid, &b1.kp(1), &[], None, false).unwrap();
    let view = {
        groups.merge_own(&mut store, &gid).unwrap()
    };
    let message = groups.encrypt(&mut store, &gid, "journaled").unwrap();

    // The web shim persists the drained writes; a fresh core loads exactly them.
    let mut rows: BTreeMap<String, Value> = BTreeMap::new();
    for write in journal.drain() {
        match write {
            Write::Put(key, value) => { rows.insert(key, value); }
            Write::Delete(key) => { rows.remove(&key); }
        }
    }
    let (mut reopened, _) = JournaledStore::new(rows, false);
    let mut groups = Groups::load(&mut reopened, "mls").unwrap();
    assert_eq!(groups.group_view(&mut reopened, &gid).unwrap().epoch, view.epoch);
    b1.groups.join(&mut b1.store, &out.welcome.unwrap(), &view.tree).unwrap();
    let got = b1.groups.process(&mut b1.store, &gid, &message).unwrap();
    assert_eq!(got.plaintext.as_deref(), Some("journaled"));
    let later = groups.encrypt(&mut reopened, &gid, "after reload").unwrap();
    b1.groups.commit_pending(&mut b1.store, &got.pending_id).unwrap();
    assert_eq!(b1.groups.process(&mut b1.store, &gid, &later).unwrap().plaintext.as_deref(), Some("after reload"));
}

/// 60 devices: the ratchet tree is far above the chunking threshold.
fn big_group() -> (Account, Dev, Vec<Dev>, Server, String) {
    let alice = Account::new();
    let bob = Account::new();
    let all = [&alice, &bob];
    let mut server = Server::new(&all);
    let mut a1 = Dev::new(&alice, "linux", &all);
    let mut others: Vec<Dev> = (0..60).map(|_| Dev::new(&bob, "bot", &all)).collect();
    let g = rid();
    a1.create(&mut server, &g, &Roles::group(vec![alice.id.clone()], JoinPolicy::Invite));
    let kps: Vec<String> = others.iter_mut().flat_map(|d| d.kp(1)).collect();
    a1.accepted(&mut server, &g, &kps, &[], None, false);
    (alice, a1, others, server, g)
}

#[test]
fn large_values_are_chunked_and_a_commit_rewrites_little() {
    let (_alice, mut a1, _others, mut server, g) = big_group();
    let stored = |dev: &Dev| -> usize { dev.store.map.iter().filter(|(k, _)| k.starts_with("mls:g:")).map(|(_, v)| v.to_string().len()).sum() };
    let tree_bytes = stored(&a1);
    assert!(tree_bytes > 100_000, "the group occupies {tree_bytes} bytes");
    let rows = a1.store.map.keys().filter(|k| k.contains(":c:")).count();
    assert!(rows > 4, "chunk rows: {rows}");
    a1.restart();
    assert_eq!(a1.members(&g).len(), 61);

    // A new epoch re-keys the whole message-secret tree, so its row is rewritten; the ratchet tree is chunked, and
    // the chunks a self-update did not touch are kept, not rewritten.
    let chunks = |dev: &Dev| -> std::collections::HashSet<String> { dev.store.map.keys().filter(|k| k.contains(":c:")).cloned().collect() };
    let before = chunks(&a1);
    a1.accepted(&mut server, &g, &[], &[], None, true);
    let kept = before.intersection(&chunks(&a1)).count();
    assert!(kept > 0, "no chunk survived a self-update ({} before)", before.len());
    // A message touches only the sender's ratchet.
    a1.send(&mut server, &g, "x");
    let written = a1.groups.last_written.bytes;
    assert!(written < tree_bytes / 4, "a message wrote {written} of {tree_bytes} stored bytes");
    a1.restart();
    assert_eq!(a1.members(&g).len(), 61);
}

#[test]
fn corrupt_rows_are_refused_on_load() {
    let (_alice, mut a1, _others, _server, g) = big_group();
    let gid = group_id(&g).unwrap();
    let chunk = a1.store.map.keys().find(|k| k.contains(":c:")).cloned().unwrap();
    let good = a1.store.map[&chunk].clone();

    // A chunk whose content no longer hashes to its name.
    a1.store.map.insert(chunk.clone(), json!({ "b": b64(b"tampered") }));
    assert!(Groups::load(&mut a1.store, "mls").err().unwrap().message.contains("does not match its name"));

    // A missing chunk.
    a1.store.map.remove(&chunk);
    assert!(Groups::load(&mut a1.store, "mls").err().unwrap().message.contains("missing MLS chunk"));
    a1.store.map.insert(chunk.clone(), good);

    // A row filed under another group's prefix.
    let entry = a1.store.map.keys().find(|k| k.starts_with("mls:g:") && k.contains(":k:")).cloned().unwrap();
    let value = a1.store.map.remove(&entry).unwrap();
    let parts: Vec<&str> = entry.splitn(4, ':').collect();
    let wrong = format!("{}:{}:{}:{}", parts[0], parts[1], "0".repeat(24), parts[3]);
    a1.store.map.insert(wrong, value.clone());
    assert!(Groups::load(&mut a1.store, "mls").err().unwrap().message.contains("wrong group"));
    a1.store.map.retain(|k, _| !k.contains(&"0".repeat(24)));

    // A value that is not what OpenMLS wrote: the group is unreadable (and nothing else breaks).
    a1.store.map.insert(entry.clone(), json!({ "b": b64(b"not json") }));
    a1.restart();
    assert_eq!(a1.groups.encrypt(&mut a1.store, &gid, "x").unwrap_err().code(), Some("storage"));
    // A malformed row.
    a1.store.map.insert(entry, json!({ "nope": 1 }));
    assert!(Groups::load(&mut a1.store, "mls").is_err());
}

#[test]
fn a_failed_write_leaves_the_device_at_its_last_persisted_state() {
    let mut f = Fixture::new(JoinPolicy::Invite);
    let g = f.group.clone();
    let gid = group_id(&g).unwrap();
    let epoch = f.a1.epoch(&g);
    f.a1.store.fail_writes = 1;
    let err = f.a1.groups.commit(&mut f.a1.store, &gid, &[], &[], None, true).unwrap_err();
    assert_eq!(err.code(), Some("storage"));
    assert!(f.a1.groups.is_stale());
    assert_eq!(f.a1.groups.encrypt(&mut f.a1.store, &gid, "x").unwrap_err().code(), Some("storage"), "memory ran ahead of disk: reload first");
    f.a1.restart();
    assert_eq!(f.a1.epoch(&g), epoch);
    assert!(f.a1.groups.pending_commit(&mut f.a1.store, &gid).unwrap().is_none());
    f.a1.accepted(&mut f.server, &g, &[], &[], None, true);
}

/// A store that fails the next N batches.
struct Flaky {
    inner: MemoryStore,
    fail: Arc<AtomicUsize>,
}

impl Store for Flaky {
    fn get(&mut self, key: &str) -> crate::Result<Option<Value>> { self.inner.get(key) }
    fn scan(&mut self, prefix: &str) -> crate::Result<Vec<(String, Value)>> { self.inner.scan(prefix) }
    fn delete_prefix(&mut self, prefix: &str) -> crate::Result<()> { self.inner.delete_prefix(prefix) }
    fn batch(&mut self, writes: Vec<Write>) -> crate::Result<()> {
        if self.fail.load(Ordering::SeqCst) > 0 { self.fail.fetch_sub(1, Ordering::SeqCst); return Err(ChatError::storage("injected")); }
        self.inner.batch(writes)
    }
}

#[test]
fn the_core_reloads_its_groups_after_a_failed_write() {
    let fail = Arc::new(AtomicUsize::new(0));
    let mut core = Core::new(Box::new(Flaky { inner: MemoryStore::default(), fail: fail.clone() }));
    let aik = core.account_signing_key().unwrap();
    let user = rid();
    {
        let (groups, store) = core.groups().unwrap();
        groups.init_device(store, &user, &rid(), "linux", 0, &aik).unwrap();
        groups.create(store, &group_id("AAAA").unwrap(), &Roles::group(vec![user.clone()], JoinPolicy::Open)).unwrap();
    }
    fail.store(1, Ordering::SeqCst);
    {
        let (groups, store) = core.groups().unwrap();
        assert!(groups.commit(store, &group_id("AAAA").unwrap(), &[], &[], None, true).is_err());
    }
    // The next access sees a stale engine and reloads it from the store.
    let (groups, store) = core.groups().unwrap();
    assert_eq!(groups.group_view(store, &group_id("AAAA").unwrap()).unwrap().epoch, 0);
    groups.commit(store, &group_id("AAAA").unwrap(), &[], &[], None, true).unwrap();
}

#[test]
fn a_device_has_one_identity_and_it_must_match_the_core_account_key() {
    let account = Account::new();
    let mut store = MemoryStore::default();
    let mut groups = Groups::load(&mut store, "mls").unwrap();
    let leaf = groups.device_leaf(&mut store).unwrap();
    assert_eq!(groups.device_leaf(&mut store).unwrap(), leaf, "created once");
    let key = crate::mls::cert::key32(&leaf).unwrap();
    let cert = crate::mls::cert::DeviceCert::issue(&account.aik, &account.id, &rid(), "web", &key, 5).unwrap();
    let text = String::from_utf8(cert.encode()).unwrap();

    // Signed elsewhere (WebCrypto): accepted only under the core's own account key.
    let other = Account::new();
    assert!(groups.set_device_cert(&mut store, &text, &other.aik.verifying_key().to_bytes()).is_err());
    groups.set_device_cert(&mut store, &text, &account.aik.verifying_key().to_bytes()).unwrap();
    // A certificate for some other leaf key is refused.
    let mut again = Groups::load(&mut store, "mls").unwrap();
    let wrong = crate::mls::cert::DeviceCert::issue(&account.aik, &account.id, &cert.device_id, "web", &[7u8; 32], 5).unwrap();
    assert!(again.set_device_cert(&mut store, &String::from_utf8(wrong.encode()).unwrap(), &account.aik.verifying_key().to_bytes()).is_err());
    // init_device is idempotent for the same device and refuses another.
    assert_eq!(again.init_device(&mut store, &account.id, &cert.device_id, "web", 9, &account.aik).unwrap(), cert);
    assert!(again.init_device(&mut store, &account.id, &rid(), "web", 9, &account.aik).is_err());
    // Without a device identity nothing works.
    let mut empty_store = MemoryStore::default();
    let mut empty = Groups::load(&mut empty_store, "mls").unwrap();
    assert!(empty.key_packages(&mut empty_store, 1, false).is_err());
}
