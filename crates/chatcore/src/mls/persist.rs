//! How OpenMLS's logical key/value state maps onto rows of the account [`Store`] (sealed SQLite natively,
//! encrypted IndexedDB rows in the browser): grouped by group id, and with large values split into
//! content-defined chunks so a commit or a message rewrites only the chunks it changed.
//!
//! Row layout (`ns` is `mls` for this device's groups, `mlsds` for delivery-service state):
//! - `{ns}:g:{tag}:k:{hex(key)}` — one logical OpenMLS entry of the group whose id hashes to `tag`
//! - `{ns}:g:{tag}:c:{hash}`     — one content chunk of a large value of that group (shared, ref-counted)
//! - `{ns}:x:k:{hex(key)}` / `{ns}:x:c:{hash}` — entries not tied to a group (key packages, signature keys)
//!
//! Entry rows hold `{"b": base64}` (inline) or `{"c": [chunk row keys], "n": length}`. Group-first keys let a
//! store load or drop one group by prefix. Why chunks rather than "tree nodes per row": OpenMLS persists the
//! ratchet tree and the message secrets as single serialized values (6.5 MB / 85 KB at 2,500 leaves in the spike),
//! and a commit changes only the nodes on one path. Content-defined chunk boundaries follow the content, so an
//! edit in one place changes the chunks around it, not everything after it, without depending on OpenMLS's
//! internal layout.
use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::rows::Change;
use crate::error::{ChatError, Result};
use crate::store::{Store, Write};

/// Values longer than this are chunked.
const CHUNK_ABOVE: usize = 8 * 1024;
const MIN_CHUNK: usize = 1024;
const MAX_CHUNK: usize = 16 * 1024;
/// ~4 KiB average chunk.
const BOUNDARY_MASK: u64 = (1 << 12) - 1;

/// OpenMLS storage labels whose key starts with the group id.
const GROUP_LABELS: [&str; 14] = [
    "Tree", "GroupContext", "InterimTranscriptHash", "ConfirmationTag", "MlsGroupJoinConfig", "OwnLeafNodes", "GroupState",
    "QueuedProposal", "ProposalQueueRefs", "OwnLeafNodeIndex", "EpochSecrets", "ResumptionPsk", "MessageSecrets", "EpochKeyPairs",
];

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 { return None; }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
}

/// The group a logical key belongs to: OpenMLS's group-scoped keys are `label ‖ json(group_id …) ‖ version`.
pub fn group_tag_of_key(key: &[u8]) -> Option<String> {
    let label_len = key.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    let label = std::str::from_utf8(&key[..label_len]).ok()?;
    if !GROUP_LABELS.contains(&label) { return None; }
    let rest = &key[label_len..key.len().checked_sub(2)?];
    let first: Value = serde_json::Deserializer::from_slice(rest).into_iter::<Value>().next()?.ok()?;
    let group = match first { Value::Array(items) => items.into_iter().next()?, other => other };
    Some(tag_of_group_json(&serde_json::to_vec(&group).ok()?))
}

/// `tag` for a group id's JSON encoding (as OpenMLS serializes `GroupId`).
pub fn tag_of_group_json(group_json: &[u8]) -> String { hex(&Sha256::digest(group_json)[..12]) }

/// Gear-hash content-defined chunking (FastCDC-style boundaries, deterministic).
fn chunks(value: &[u8]) -> Vec<&[u8]> {
    static GEAR: std::sync::OnceLock<[u64; 256]> = std::sync::OnceLock::new();
    let gear = GEAR.get_or_init(|| {
        let mut table = [0u64; 256];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for slot in table.iter_mut() {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *slot = z ^ (z >> 31);
        }
        table
    });
    let mut out = Vec::new();
    let (mut start, mut hash) = (0usize, 0u64);
    for (i, byte) in value.iter().enumerate() {
        hash = (hash << 1).wrapping_add(gear[*byte as usize]);
        let len = i + 1 - start;
        if (len >= MIN_CHUNK && hash & BOUNDARY_MASK == 0) || len >= MAX_CHUNK {
            out.push(&value[start..=i]);
            start = i + 1;
            hash = 0;
        }
    }
    if start < value.len() { out.push(&value[start..]); }
    out
}

#[derive(Clone, Debug)]
enum Manifest {
    Inline,
    Chunks(Vec<String>),
}

/// The persisted side of the logical map: which rows each logical key occupies, and chunk reference counts.
pub struct Persist {
    ns: String,
    manifests: HashMap<Vec<u8>, Manifest>,
    refs: HashMap<String, usize>,
}

/// Bytes a flush wrote, for benchmarks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Written {
    pub rows: usize,
    pub bytes: usize,
}

impl Persist {
    fn scope(&self, key: &[u8]) -> String {
        match group_tag_of_key(key) {
            Some(tag) => format!("{}:g:{tag}", self.ns),
            None => format!("{}:x", self.ns),
        }
    }

    /// Loads every row under `{ns}:` into the logical map. Fails closed on a malformed row or a missing chunk.
    pub fn load(store: &mut dyn Store, ns: &str) -> Result<(HashMap<Vec<u8>, Vec<u8>>, Self)> {
        let rows: BTreeMap<String, Value> = store.scan(&format!("{ns}:"))?.into_iter().collect();
        let mut persist = Self { ns: ns.to_string(), manifests: HashMap::new(), refs: HashMap::new() };
        let mut map = HashMap::new();
        let bytes_of = |value: &Value| -> Result<Vec<u8>> {
            let text = value.get("b").and_then(Value::as_str).ok_or_else(|| ChatError::storage("malformed MLS row"))?;
            URL_SAFE_NO_PAD.decode(text).map_err(|_| ChatError::storage("malformed MLS row"))
        };
        for (row, value) in &rows {
            let Some(at) = row.find(":k:") else { continue };
            let key = unhex(&row[at + 3..]).ok_or_else(|| ChatError::storage("malformed MLS row key"))?;
            if persist.scope(&key) != row[..at] { return Err(ChatError::storage("MLS row stored under the wrong group")); }
            if let Some(list) = value.get("c").and_then(Value::as_array) {
                let names: Vec<String> = list.iter().map(|v| v.as_str().map(str::to_string).ok_or_else(|| ChatError::storage("malformed MLS row"))).collect::<Result<_>>()?;
                let mut whole = Vec::new();
                for name in &names {
                    let chunk = rows.get(name).ok_or_else(|| ChatError::storage("missing MLS chunk"))?;
                    let piece = bytes_of(chunk)?;
                    if !name.ends_with(&hex(&Sha256::digest(&piece)[..16])) { return Err(ChatError::storage("MLS chunk does not match its name")); }
                    whole.extend_from_slice(&piece);
                    *persist.refs.entry(name.clone()).or_default() += 1;
                }
                if value.get("n").and_then(Value::as_u64) != Some(whole.len() as u64) { return Err(ChatError::storage("MLS value length mismatch")); }
                persist.manifests.insert(key.clone(), Manifest::Chunks(names));
                map.insert(key, whole);
            } else {
                map.insert(key.clone(), bytes_of(value)?);
                persist.manifests.insert(key, Manifest::Inline);
            }
        }
        Ok((map, persist))
    }

    /// Store writes for a set of logical changes; updates manifests and chunk references. If the caller fails to
    /// apply the writes, it must discard this `Persist` (and reload), since its bookkeeping already moved on.
    pub fn writes(&mut self, changes: &[Change], written: &mut Written) -> Vec<Write> {
        let mut writes = Vec::new();
        for change in changes {
            let scope = self.scope(&change.key);
            let row = format!("{scope}:k:{}", hex(&change.key));
            let old = self.manifests.remove(&change.key);
            let mut released = Vec::new();
            if let Some(Manifest::Chunks(names)) = old { released = names; }
            match &change.after {
                None => writes.push(Write::Delete(row)),
                Some(value) if value.len() <= CHUNK_ABOVE => {
                    let text = URL_SAFE_NO_PAD.encode(value);
                    written.rows += 1;
                    written.bytes += row.len() + text.len();
                    writes.push(Write::Put(row, json!({ "b": text })));
                    self.manifests.insert(change.key.clone(), Manifest::Inline);
                }
                Some(value) => {
                    let mut names = Vec::new();
                    for piece in chunks(value) {
                        let name = format!("{scope}:c:{}", hex(&Sha256::digest(piece)[..16]));
                        let count = self.refs.entry(name.clone()).or_default();
                        if *count == 0 {
                            let text = URL_SAFE_NO_PAD.encode(piece);
                            written.rows += 1;
                            written.bytes += name.len() + text.len();
                            writes.push(Write::Put(name.clone(), json!({ "b": text })));
                        }
                        *count += 1;
                        names.push(name);
                    }
                    let manifest = json!({ "c": names, "n": value.len() });
                    written.rows += 1;
                    written.bytes += row.len() + manifest.to_string().len();
                    writes.push(Write::Put(row, manifest));
                    self.manifests.insert(change.key.clone(), Manifest::Chunks(names));
                }
            }
            for name in released {
                if let Some(count) = self.refs.get_mut(&name) {
                    *count -= 1;
                    if *count == 0 {
                        self.refs.remove(&name);
                        writes.push(Write::Delete(name));
                    }
                }
            }
        }
        // A chunk released and re-added in the same flush must survive: drop deletes of chunks that are live again.
        let live: std::collections::HashSet<String> = writes.iter().filter_map(|w| match w { Write::Put(k, _) => Some(k.clone()), _ => None }).collect();
        writes.retain(|w| !matches!(w, Write::Delete(k) if live.contains(k) && self.refs.contains_key(k)));
        writes
    }
}
