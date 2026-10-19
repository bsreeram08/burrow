//! The one validator (MLS.md §3). Clients run it before merging any commit (their own or received) and the
//! delivery service runs the same code before sequencing one, so a commit the server accepts is a commit every
//! member accepts (a disagreement would fork the group). Everything it reads is public: the pre-commit group
//! context and members, the commit, and pinned account keys.
//!
//! OpenMLS has already checked signatures, epochs, tree and parent hashes, KeyPackage validity and lifetimes,
//! capabilities and duplicate keys. It enforces nothing application-level; this module does.
use std::collections::{HashMap, HashSet};

use openmls::prelude::*;
use serde::{Deserialize, Serialize};

use super::cert::{canonical_id, verify_credential, DeviceCert, Directory};
use super::{limits, ROLES_EXT};
use crate::error::{ChatError, Result};

fn policy(message: impl Into<String>) -> ChatError { ChatError::coded("invalid", &message.into()) }

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A conversation between exactly two users (all their devices); nobody else can ever be added.
    Dm,
    /// A group DM or channel.
    Group,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JoinPolicy {
    /// Anyone in the workspace may join (external commit) and any member may add users.
    Open,
    /// Only admins add users; self-joins only for users already in the group (own devices, resync).
    Invite,
}

/// The `roles` GroupContext extension (0xF0A1). Field order is the canonical encoding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Roles {
    pub v: u8,
    pub kind: Kind,
    pub admins: Vec<String>,
    #[serde(rename = "joinPolicy")]
    pub join_policy: JoinPolicy,
    /// DMs only: the two users (sorted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dm: Option<Vec<String>>,
}

impl Roles {
    pub fn group(admins: Vec<String>, join_policy: JoinPolicy) -> Self { Self { v: 1, kind: Kind::Group, admins, join_policy, dm: None } }
    pub fn dm(a: &str, b: &str) -> Self {
        let mut users = vec![a.to_string(), b.to_string()];
        users.sort();
        Self { v: 1, kind: Kind::Dm, admins: users.clone(), join_policy: JoinPolicy::Invite, dm: Some(users) }
    }
    pub fn encode(&self) -> Vec<u8> { serde_json::to_vec(self).expect("roles serialize") }
    pub fn extension(&self) -> Extension { Extension::Unknown(ROLES_EXT, UnknownExtension(self.encode())) }

    /// Strict decoding: bounded, canonical, internally consistent. Malformed roles are an error, never "no roles".
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > limits::MAX_ROLES_BYTES { return Err(policy("roles extension too large")); }
        let roles: Self = serde_json::from_slice(raw).map_err(|_| policy("malformed roles extension"))?;
        if roles.v != 1 { return Err(policy("unsupported roles version")); }
        if roles.admins.is_empty() || roles.admins.len() > limits::MAX_ADMINS { return Err(policy("roles must name 1–64 admins")); }
        let mut seen = HashSet::new();
        if !roles.admins.iter().all(|a| canonical_id(a) && seen.insert(a)) { return Err(policy("roles admins are not canonical")); }
        match (roles.kind, &roles.dm) {
            (Kind::Dm, Some(users)) => {
                if users.len() != 2 || users[0] >= users[1] || !users.iter().all(|u| canonical_id(u)) { return Err(policy("a DM names two distinct users, sorted")); }
                if &roles.admins != users || roles.join_policy != JoinPolicy::Invite { return Err(policy("a DM's admins are its two users and it is invite-only")); }
            }
            (Kind::Group, None) => {}
            _ => return Err(policy("roles kind and dm list disagree")),
        }
        if roles.encode() != raw { return Err(policy("roles extension is not canonically encoded")); }
        Ok(roles)
    }
    pub fn is_admin(&self, user: &str) -> bool { self.admins.iter().any(|a| a == user) }
}

pub fn capabilities() -> Capabilities { Capabilities::builder().extensions(vec![ExtensionType::Unknown(ROLES_EXT)]).build() }

pub fn group_extensions(roles: &Roles) -> Result<Extensions<GroupContext>> {
    let required = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(ROLES_EXT)], &[], &[]);
    Extensions::from_vec(vec![Extension::RequiredCapabilities(required), roles.extension()]).map_err(|_| policy("invalid group extensions"))
}

/// The only GroupContext a group may have: required_capabilities (which must require roles) and one roles.
pub fn validate_context(extensions: &Extensions<GroupContext>) -> Result<Roles> {
    let mut count = 0;
    for extension in extensions.iter() {
        count += 1;
        match extension.extension_type() {
            ExtensionType::RequiredCapabilities | ExtensionType::Unknown(ROLES_EXT) => {}
            other => return Err(policy(format!("group context extension {other:?} is not allowed"))),
        }
    }
    if count != 2 { return Err(policy("group context must hold exactly required_capabilities and roles")); }
    let required = extensions.required_capabilities().ok_or_else(|| policy("required_capabilities missing"))?;
    if !required.extension_types().contains(&ExtensionType::Unknown(ROLES_EXT)) { return Err(policy("roles is not a required capability")); }
    let raw = &extensions.unknown(ROLES_EXT).ok_or_else(|| policy("group has no roles extension"))?.0;
    Roles::decode(raw)
}

/// Whole-group check wherever a device or the DS adopts a group it did not build: Welcome, external join,
/// load after restart, DS bootstrap/restore. Every member must carry a valid certificate; size is bounded;
/// a DM may only hold devices of its two users.
pub fn validate_group_state(extensions: &Extensions<GroupContext>, members: impl Iterator<Item = Member>, directory: &mut dyn Directory) -> Result<(Roles, Vec<(LeafNodeIndex, DeviceCert)>)> {
    let roles = validate_context(extensions)?;
    let mut certs = Vec::new();
    for member in members {
        let cert = verify_credential(directory, &member.credential, &member.signature_key)?;
        if let Some(users) = &roles.dm {
            if !users.contains(&cert.user_id) { return Err(policy("a DM holds a device of a third user")); }
        }
        certs.push((member.index, cert));
        if certs.len() > limits::MAX_LEAVES { return Err(policy("group exceeds the leaf limit")); }
    }
    Ok((roles, certs))
}

/// The commit validator. Rules (MLS.md §3):
/// - every introduced or changed leaf carries a valid certificate; updates keep the same user and device;
/// - only inline Add / Remove / Update / GroupContextExtensions / ExternalInit, at most 128, within 1,000 leaves;
/// - Add of a new user: admin or an open group (DM: only its two users, never a third);
/// - Remove of another user's leaf: admin (never in a DM);
/// - GroupContextExtensions: admin, roles stay valid, kind (and a DM's users) never change;
/// - external commit: own device or resync of a user already in the group, or a new user in an open group.
pub fn validate_staged(
    extensions: &Extensions<GroupContext>,
    members: impl Iterator<Item = Member>,
    sender: &Sender,
    staged: &StagedCommit,
    directory: &mut dyn Directory,
) -> Result<()> {
    // Policy is evaluated against the PRE-commit context, decoded once by the one strict decoder; a roles change
    // in this very commit never authorizes the other proposals bundled with it.
    let roles = validate_context(extensions)?;
    let mut tree: HashMap<LeafNodeIndex, DeviceCert> = HashMap::new();
    for member in members {
        tree.insert(member.index, verify_credential(directory, &member.credential, &member.signature_key)?);
    }
    let users: HashSet<String> = tree.values().map(|c| c.user_id.clone()).collect();

    let (committer, external) = match sender {
        Sender::Member(index) => (tree.get(index).cloned().ok_or_else(|| policy("committer is not in the tree"))?, false),
        Sender::NewMemberCommit => {
            let leaf = staged.update_path_leaf_node().ok_or_else(|| policy("external commit without a path"))?;
            (verify_credential(directory, leaf.credential(), leaf.signature_key().as_slice())?, true)
        }
        _ => return Err(policy("commits are only accepted from members or external joiners")),
    };
    let admin = roles.is_admin(&committer.user_id);
    if external {
        let returning = users.contains(&committer.user_id);
        let allowed = match roles.kind {
            Kind::Dm => roles.dm.as_ref().is_some_and(|u| u.contains(&committer.user_id)) && returning,
            Kind::Group => returning || roles.join_policy == JoinPolicy::Open,
        };
        if !allowed { return Err(policy("this user may not join this group by itself")); }
    }

    // The committer's new leaf (UpdatePath) must stay the same user and device.
    if let Some(leaf) = staged.update_path_leaf_node() {
        let cert = verify_credential(directory, leaf.credential(), leaf.signature_key().as_slice())?;
        if cert.user_id != committer.user_id || cert.device_id != committer.device_id {
            return Err(policy("an update path may not change the leaf's user or device"));
        }
    }

    let (mut count, mut adds, mut removes) = (0usize, 0usize, 0usize);
    for queued in staged.queued_proposals() {
        count += 1;
        if count > limits::MAX_PROPOSALS { return Err(policy("too many proposals in one commit")); }
        // Inline only: a proposal sent earlier and committed by reference would skip this check when it was sent.
        if !matches!(queued.proposal_or_ref_type(), ProposalOrRefType::Proposal) {
            return Err(policy("proposals by reference are not accepted"));
        }
        match queued.proposal() {
            Proposal::Add(add) => {
                adds += 1;
                let leaf = add.key_package().leaf_node();
                let cert = verify_credential(directory, leaf.credential(), leaf.signature_key().as_slice())?;
                match roles.kind {
                    Kind::Dm => {
                        if !roles.dm.as_ref().is_some_and(|u| u.contains(&cert.user_id)) { return Err(policy("nobody else can be added to a DM")); }
                    }
                    Kind::Group => {
                        if !users.contains(&cert.user_id) && !admin && roles.join_policy == JoinPolicy::Invite {
                            return Err(policy("only admins add new users to an invite-only group"));
                        }
                    }
                }
            }
            Proposal::Remove(remove) => {
                removes += 1;
                let target = tree.get(&remove.removed()).ok_or_else(|| policy("remove of an empty leaf"))?;
                if target.user_id != committer.user_id && (roles.kind == Kind::Dm || !admin) {
                    return Err(policy("only admins remove other users"));
                }
            }
            Proposal::Update(update) => {
                let Sender::Member(index) = queued.sender() else { return Err(policy("update from a non-member")) };
                let old = tree.get(index).ok_or_else(|| policy("update for an empty leaf"))?;
                let leaf = update.leaf_node();
                let cert = verify_credential(directory, leaf.credential(), leaf.signature_key().as_slice())?;
                if cert.user_id != old.user_id || cert.device_id != old.device_id { return Err(policy("an update may not change the leaf's user or device")); }
            }
            Proposal::GroupContextExtensions(change) => {
                if !admin { return Err(policy("only admins change group settings")); }
                let next = validate_context(change.extensions())?;
                if next.kind != roles.kind || next.dm != roles.dm { return Err(policy("a group's kind and a DM's users never change")); }
            }
            Proposal::ExternalInit(_) if external => {}
            other => return Err(policy(format!("{:?} proposals are not accepted", other.proposal_type()))),
        }
    }
    let after = tree.len() + adds + usize::from(external);
    if after.saturating_sub(removes) > limits::MAX_LEAVES { return Err(policy("the group would exceed the leaf limit")); }
    Ok(())
}
