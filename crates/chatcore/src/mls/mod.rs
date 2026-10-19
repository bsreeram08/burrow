//! Groups over MLS (RFC 9420, OpenMLS 0.9): see API.md for the protocol this implements.
use openmls::prelude::Ciphersuite;
use sha2::{Digest, Sha256};

use crate::error::{ChatError, Result};

pub mod cert;
pub mod engine;
pub mod payload;
pub mod persist;
pub mod policy;
mod rows;
mod storage;
#[cfg(all(test, feature = "mls", feature = "ds"))]
mod tests;

pub const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// The `roles` GroupContext extension (private-use range).
pub const ROLES_EXT: u16 = 0xF0A1;

/// Byte and count limits, checked before parsing.
pub mod limits {
    pub const MAX_LEAVES: usize = 1000;
    pub const MAX_PROPOSALS: usize = 128;
    pub const MAX_HANDSHAKE_BYTES: usize = 1024 * 1024;
    pub const MAX_APPLICATION_BYTES: usize = 64 * 1024;
    pub const MAX_PLAINTEXT_BYTES: usize = 60 * 1024;
    pub const MAX_KEY_PACKAGE_BYTES: usize = 4 * 1024;
    pub const MAX_WELCOME_BYTES: usize = 4 * 1024 * 1024;
    pub const MAX_TREE_BYTES: usize = 4 * 1024 * 1024;
    pub const MAX_GROUP_INFO_BYTES: usize = 64 * 1024;
    pub const MAX_IDENTITY_BYTES: usize = 1024;
    pub const MAX_ROLES_BYTES: usize = 4096;
    pub const MAX_ADMINS: usize = 64;
}

pub(crate) fn bounded(what: &str, bytes: &[u8], max: usize) -> Result<()> {
    if bytes.len() > max { return Err(ChatError::coded("invalid", &format!("{what} exceeds {max} bytes"))); }
    Ok(())
}

/// SHA-256 (hex) of a message's bytes: commit identity for idempotency and poison reports.
pub fn digest(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }
