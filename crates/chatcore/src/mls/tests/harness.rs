use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::json;

use crate::error::Result;
use crate::mls::engine::{group_id, Ds, Groups, GroupView, Outgoing, Processed, Submit};
use crate::mls::policy::Roles;
use crate::store::{MemoryStore, Store};

pub fn rid() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn b64(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }

/// A user: an id and the account identity key that certifies their devices.
pub struct Account {
    pub id: String,
    pub aik: SigningKey,
}

impl Account {
    pub fn new() -> Self { Self { id: rid(), aik: SigningKey::generate(&mut OsRng) } }
    pub fn pin(&self) -> String { b64(&self.aik.verifying_key().to_bytes()) }
}

/// The delivery service and its per-group message log.
pub struct Server {
    pub store: MemoryStore,
    pub ds: Ds,
    pub log: HashMap<String, Vec<String>>,
}

impl Server {
    pub fn new(accounts: &[&Account]) -> Self {
        let mut store = MemoryStore::default();
        let mut ds = Ds::new(&mut store).unwrap();
        for account in accounts { ds.pin(&mut store, &account.id, &account.pin()).unwrap(); }
        Self { store, ds, log: HashMap::new() }
    }
    pub fn create(&mut self, view: &GroupView) {
        self.ds.create(&mut self.store, &view.group_info, &view.tree).unwrap();
        self.log.insert(view.group_id.clone(), Vec::new());
    }
    /// Sequences a message; accepted ones join the log.
    pub fn submit(&mut self, group: &str, message: &str) -> Result<Submit> {
        let verdict = self.ds.submit(&mut self.store, &group_id(group)?, message)?;
        if matches!(verdict, Submit::Accepted { .. }) { self.log.entry(group.to_string()).or_default().push(message.to_string()); }
        Ok(verdict)
    }
    pub fn tree(&mut self, group: &str) -> String { self.ds.tree(&group_id(group).unwrap()).unwrap() }
    pub fn epoch(&mut self, group: &str) -> u64 { self.ds.epoch(&group_id(group).unwrap()).unwrap() }
    pub fn restart(&mut self) { self.ds = Ds::new(&mut self.store).unwrap(); }
}

/// One device: its own sealed store, MLS state and position in each group's log.
pub struct Dev {
    pub user: String,
    pub device: String,
    pub aik: SigningKey,
    pub store: MemoryStore,
    pub groups: Groups,
    cursor: HashMap<String, usize>,
    skip: HashSet<String>,
}

impl Dev {
    /// `peers`: the accounts whose keys this device has pinned (TOFU contacts).
    pub fn new(account: &Account, platform: &str, peers: &[&Account]) -> Self {
        let mut store = MemoryStore::default();
        let mut groups = Groups::load(&mut store, "mls").unwrap();
        let device = rid();
        groups.init_device(&mut store, &account.id, &device, platform, 1_700_000_000_000, &account.aik).unwrap();
        for peer in peers { store.put(&format!("peer:{}", peer.id), json!({ "aik": peer.pin() })).unwrap(); }
        Self { user: account.id.clone(), device, aik: account.aik.clone(), store, groups, cursor: HashMap::new(), skip: HashSet::new() }
    }

    pub fn kp(&mut self, count: u32) -> Vec<String> { self.groups.key_packages(&mut self.store, count, false).unwrap() }
    pub fn last_resort(&mut self) -> String { self.groups.key_packages(&mut self.store, 1, true).unwrap().remove(0) }

    pub fn create(&mut self, server: &mut Server, group: &str, roles: &Roles) -> GroupView {
        let view = self.groups.create(&mut self.store, &group_id(group).unwrap(), roles).unwrap();
        server.create(&view);
        self.cursor.insert(group.to_string(), 0);
        view
    }

    /// Builds a commit and submits it. Accepted: merged. Conflict: dropped (process the log, then rebuild).
    pub fn commit(&mut self, server: &mut Server, group: &str, adds: &[String], removes: &[(String, Option<String>)], roles: Option<&Roles>, update: bool) -> Result<(Outgoing, Submit)> {
        let out = self.groups.commit(&mut self.store, &group_id(group)?, adds, removes, roles, update)?;
        self.submit_built(server, group, out)
    }

    pub fn submit_built(&mut self, server: &mut Server, group: &str, out: Outgoing) -> Result<(Outgoing, Submit)> {
        let gid = group_id(group)?;
        match server.submit(group, &out.commit) {
            Ok(Submit::Accepted { epoch, digest }) => {
                self.groups.merge_own(&mut self.store, &gid)?;
                self.skip.insert(out.digest.clone());
                *self.cursor.entry(group.to_string()).or_default() = server.log[group].len();
                Ok((out, Submit::Accepted { epoch, digest }))
            }
            Ok(conflict) => { self.groups.clear_own(&mut self.store, &gid)?; Ok((out, conflict)) }
            Err(error) => { self.groups.clear_own(&mut self.store, &gid)?; Err(error) }
        }
    }

    pub fn accepted(&mut self, server: &mut Server, group: &str, adds: &[String], removes: &[(String, Option<String>)], roles: Option<&Roles>, update: bool) -> Outgoing {
        let (out, verdict) = self.commit(server, group, adds, removes, roles, update).unwrap();
        assert!(matches!(verdict, Submit::Accepted { .. }), "{verdict:?}");
        out
    }

    pub fn join(&mut self, server: &mut Server, welcome: &str, group: &str) -> GroupView {
        let view = self.groups.join(&mut self.store, welcome, &server.tree(group)).unwrap();
        self.cursor.insert(group.to_string(), server.log[group].len());
        view
    }

    pub fn join_external(&mut self, server: &mut Server, group: &str, info: &str) -> Result<Outgoing> {
        let out = self.groups.join_external(&mut self.store, info, &server.tree(group))?;
        self.finish_external(server, group, out)
    }

    pub fn finish_external(&mut self, server: &mut Server, group: &str, out: Outgoing) -> Result<Outgoing> {
        let gid = group_id(group)?;
        match server.submit(group, &out.commit) {
            Ok(Submit::Accepted { .. }) => {
                self.groups.merge_own(&mut self.store, &gid)?;
                self.skip.insert(out.digest.clone());
                self.cursor.insert(group.to_string(), server.log[group].len());
                Ok(out)
            }
            Ok(other) => { self.groups.clear_own(&mut self.store, &gid)?; Err(crate::error::ChatError::transient(format!("{other:?}"))) }
            Err(error) => { self.groups.clear_own(&mut self.store, &gid)?; Err(error) }
        }
    }

    pub fn send(&mut self, server: &mut Server, group: &str, text: &str) -> Submit {
        let message = self.groups.encrypt(&mut self.store, &group_id(group).unwrap(), text).unwrap();
        self.skip.insert(crate::mls::digest(&URL_SAFE_NO_PAD.decode(&message).unwrap()));
        let verdict = server.submit(group, &message).unwrap();
        *self.cursor.entry(group.to_string()).or_default() = server.log[group].len();
        verdict
    }

    /// Processes the log from this device's cursor, persisting each result. Stops at the first error and leaves
    /// the cursor on that message.
    pub fn try_sync(&mut self, server: &Server, group: &str) -> Result<Vec<Processed>> {
        let gid = group_id(group)?;
        let mut out = Vec::new();
        let log = server.log.get(group).cloned().unwrap_or_default();
        loop {
            let at = *self.cursor.get(group).unwrap_or(&0);
            let Some(message) = log.get(at) else { return Ok(out) };
            let bytes = URL_SAFE_NO_PAD.decode(message).unwrap();
            if !self.skip.contains(&crate::mls::digest(&bytes)) {
                let processed = self.groups.process(&mut self.store, &gid, message)?;
                self.groups.commit_pending(&mut self.store, &processed.pending_id)?;
                out.push(processed);
            }
            self.cursor.insert(group.to_string(), at + 1);
        }
    }

    pub fn sync(&mut self, server: &Server, group: &str) -> Vec<Processed> { self.try_sync(server, group).unwrap() }

    pub fn texts(&mut self, server: &Server, group: &str) -> Vec<String> {
        self.sync(server, group).into_iter().filter_map(|p| p.plaintext).collect()
    }

    pub fn view(&mut self, group: &str) -> GroupView { self.groups.group_view(&mut self.store, &group_id(group).unwrap()).unwrap() }
    pub fn epoch(&mut self, group: &str) -> u64 { self.view(group).epoch }
    pub fn members(&mut self, group: &str) -> Vec<crate::mls::engine::MemberView> { self.groups.members(&mut self.store, &group_id(group).unwrap()).unwrap() }

    /// Process restart: everything in memory is dropped and reloaded from the store.
    pub fn restart(&mut self) { self.groups = Groups::load(&mut self.store, "mls").unwrap(); }
}

/// Alice (admin), her phone and laptop, Bob with two devices, Carol with one: a 5-device invite-only group.
pub struct Fixture {
    pub alice: Account,
    pub bob: Account,
    pub carol: Account,
    pub server: Server,
    pub group: String,
    pub a1: Dev,
    pub a2: Dev,
    pub b1: Dev,
    pub b2: Dev,
    pub c1: Dev,
}

impl Fixture {
    pub fn new(join_policy: crate::mls::policy::JoinPolicy) -> Self {
        let (alice, bob, carol) = (Account::new(), Account::new(), Account::new());
        let all = [&alice, &bob, &carol];
        let mut server = Server::new(&all);
        let (mut a1, mut a2) = (Dev::new(&alice, "linux", &all), Dev::new(&alice, "ios", &all));
        let (mut b1, mut b2) = (Dev::new(&bob, "web", &all), Dev::new(&bob, "android", &all));
        let mut c1 = Dev::new(&carol, "macos", &all);
        let group = rid();
        a1.create(&mut server, &group, &Roles::group(vec![alice.id.clone()], join_policy));
        let kps = [a2.kp(1), b1.kp(1), b2.kp(1), c1.kp(1)].concat();
        let out = a1.accepted(&mut server, &group, &kps, &[], None, false);
        let welcome = out.welcome.unwrap();
        for dev in [&mut a2, &mut b1, &mut b2, &mut c1] { dev.join(&mut server, &welcome, &group); }
        Self { alice, bob, carol, server, group, a1, a2, b1, b2, c1 }
    }

    /// A new user the DS and every existing device have pinned; returns their first device.
    pub fn admit(&mut self, account: &Account, platform: &str) -> Dev {
        self.server.ds.pin(&mut self.server.store, &account.id, &account.pin()).unwrap();
        for dev in [&mut self.a1, &mut self.a2, &mut self.b1, &mut self.b2, &mut self.c1] {
            dev.store.put(&format!("peer:{}", account.id), json!({ "aik": account.pin() })).unwrap();
        }
        Dev::new(account, platform, &[&self.alice, &self.bob, &self.carol, account])
    }
}
