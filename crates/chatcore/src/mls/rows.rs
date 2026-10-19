//! The in-memory logical key/value map OpenMLS reads and writes (keys are OpenMLS's own storage keys), with an
//! undo log of every key touched since the last checkpoint. That gives the engine three operations a plain map
//! can't: persist only what a call changed, roll a failed call back, and stage a received message's changes
//! for the two-phase `group_process` → `commit` flow.
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct Rows {
    map: HashMap<Vec<u8>, Vec<u8>>,
    /// First value seen for every key touched since the last checkpoint (`None` = absent then).
    undo: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

/// One key a call changed: its value before (the checkpoint) and after (`None` = deleted).
#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    pub key: Vec<u8>,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}

impl Rows {
    pub fn from_map(map: HashMap<Vec<u8>, Vec<u8>>) -> Self { Self { map, undo: HashMap::new() } }

    pub fn get(&self, key: &Vec<u8>) -> Option<&Vec<u8>> { self.map.get(key) }

    fn touch(&mut self, key: &[u8]) {
        if !self.undo.contains_key(key) {
            let before = self.map.get(key).cloned();
            self.undo.insert(key.to_vec(), before);
        }
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.touch(&key);
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &Vec<u8>) -> Option<Vec<u8>> {
        self.touch(key);
        self.map.remove(key)
    }

    /// Changes since the last checkpoint (keys whose value really changed), and a new checkpoint.
    pub fn take_changes(&mut self) -> Vec<Change> {
        let undo = std::mem::take(&mut self.undo);
        let mut changes: Vec<Change> = undo
            .into_iter()
            .filter_map(|(key, before)| {
                let after = self.map.get(&key).cloned();
                (after != before).then_some(Change { key, before, after })
            })
            .collect();
        changes.sort_by(|a, b| a.key.cmp(&b.key));
        changes
    }

    /// Undoes everything since the last checkpoint.
    pub fn rollback(&mut self) {
        for (key, before) in std::mem::take(&mut self.undo) {
            match before {
                Some(value) => { self.map.insert(key, value); }
                None => { self.map.remove(&key); }
            }
        }
    }

    /// Changes since the checkpoint, then rolls them back: the memory state is as before, and the caller holds
    /// the changes to apply later (two-phase receive).
    pub fn stage(&mut self) -> Vec<Change> {
        let changes = self.take_changes();
        for change in &changes {
            match &change.before {
                Some(value) => { self.map.insert(change.key.clone(), value.clone()); }
                None => { self.map.remove(&change.key); }
            }
        }
        changes
    }

    /// Applies staged changes if every key still holds its `before` value; false (nothing applied) otherwise.
    pub fn apply_staged(&mut self, changes: &[Change]) -> bool {
        if changes.iter().any(|change| self.map.get(&change.key) != change.before.as_ref()) { return false; }
        for change in changes {
            match &change.after {
                Some(value) => { self.insert(change.key.clone(), value.clone()); }
                None => { self.remove(&change.key); }
            }
        }
        true
    }

    /// Every entry whose key satisfies `keep` (snapshots).
    pub fn entries(&self, keep: impl Fn(&[u8]) -> bool) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out: Vec<_> = self.map.iter().filter(|(key, _)| keep(key)).map(|(k, v)| (k.clone(), v.clone())).collect();
        out.sort();
        out
    }

    pub fn len(&self) -> usize { self.map.len() }
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}
