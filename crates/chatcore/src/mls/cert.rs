//! Device certificates (docs/workspace-architecture.md §2): an MLS `BasicCredential` whose identity
//! is a DeviceCert, signed by the account identity key (AIK, the Ed25519 half of today's `{dh, sign}` identity).
//! Every leaf that enters or changes in a group must carry a certificate that verifies under the AIK pinned for
//! its user and names that leaf's own signature key.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use openmls::prelude::{BasicCredential, Credential};
use serde::{Deserialize, Serialize};

use super::limits;
use crate::error::{ChatError, Result};

pub const PLATFORMS: [&str; 8] = ["web", "ios", "android", "macos", "windows", "linux", "bot", "mcp"];
const TBS_LABEL: &[u8] = b"webrtc-bun-devcert-v1";

/// Field order is the canonical encoding (serde serializes in declaration order).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceCert {
    pub v: u8,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub platform: String,
    /// base64url (no padding) of the 32-byte Ed25519 leaf signature key.
    #[serde(rename = "leafSigKey")]
    pub leaf_sig_key: String,
    /// base64url of the 32-byte Ed25519 account identity key (AIK).
    #[serde(rename = "aikSign")]
    pub aik_sign: String,
    /// Unix milliseconds.
    #[serde(rename = "issuedAt")]
    pub issued_at: u64,
    /// base64url of the 64-byte Ed25519 signature over [`DeviceCert::tbs`].
    pub sig: String,
}

/// User and device ids are server ids: 16 random bytes, base64url without padding (22 characters), and must
/// re-encode exactly, so two byte strings can never name the same user or device.
pub fn canonical_id(id: &str) -> bool {
    id.len() == 22
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && URL_SAFE_NO_PAD.decode(id).map(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(&bytes) == id).unwrap_or(false)
}

pub(crate) fn key32(text: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text { return None; }
    bytes.try_into().ok()
}

fn put(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
    out.extend_from_slice(part);
}

impl DeviceCert {
    /// The signed bytes: `"webrtc-bun-devcert-v1" ‖ lp(userId) ‖ lp(deviceId) ‖ lp(platform) ‖ leafSigKey(32) ‖
    /// aikSign(32) ‖ issuedAt(u64 BE)`, where `lp` is a u32 big-endian length then the UTF-8 bytes.
    pub fn tbs(user_id: &str, device_id: &str, platform: &str, leaf_sig_key: &[u8; 32], aik_sign: &[u8; 32], issued_at: u64) -> Vec<u8> {
        let mut out = TBS_LABEL.to_vec();
        put(&mut out, user_id.as_bytes());
        put(&mut out, device_id.as_bytes());
        put(&mut out, platform.as_bytes());
        out.extend_from_slice(leaf_sig_key);
        out.extend_from_slice(aik_sign);
        out.extend_from_slice(&issued_at.to_be_bytes());
        out
    }

    pub fn issue(aik: &SigningKey, user_id: &str, device_id: &str, platform: &str, leaf_sig_key: &[u8; 32], issued_at: u64) -> Result<Self> {
        let aik_pub = aik.verifying_key().to_bytes();
        let sig = aik.sign(&Self::tbs(user_id, device_id, platform, leaf_sig_key, &aik_pub, issued_at)).to_bytes();
        let cert = Self {
            v: 1,
            user_id: user_id.into(),
            device_id: device_id.into(),
            platform: platform.into(),
            leaf_sig_key: URL_SAFE_NO_PAD.encode(leaf_sig_key),
            aik_sign: URL_SAFE_NO_PAD.encode(aik_pub),
            issued_at,
            sig: URL_SAFE_NO_PAD.encode(sig),
        };
        cert.check_shape()?;
        Ok(cert)
    }

    /// Canonical identity bytes (compact JSON, fields in declaration order).
    pub fn encode(&self) -> Vec<u8> { serde_json::to_vec(self).expect("cert serializes") }

    fn check_shape(&self) -> Result<()> {
        let bad = |what: &str| Err(ChatError::coded("invalid", &format!("device certificate: {what}")));
        if self.v != 1 { return bad("unsupported version"); }
        if !canonical_id(&self.user_id) || !canonical_id(&self.device_id) { return bad("non-canonical user or device id"); }
        if !PLATFORMS.contains(&self.platform.as_str()) { return bad("unknown platform"); }
        if key32(&self.leaf_sig_key).is_none() || key32(&self.aik_sign).is_none() { return bad("malformed key"); }
        Ok(())
    }

    /// Parses identity bytes, requiring exactly the canonical encoding of what they decode to.
    pub fn decode(identity: &[u8]) -> Result<Self> {
        if identity.len() > limits::MAX_IDENTITY_BYTES { return Err(ChatError::coded("invalid", "device certificate too large")); }
        let cert: Self = serde_json::from_slice(identity).map_err(|_| ChatError::coded("invalid", "malformed device certificate"))?;
        cert.check_shape()?;
        if cert.encode() != identity { return Err(ChatError::coded("invalid", "device certificate is not canonically encoded")); }
        Ok(cert)
    }

    /// Verifies the signature under `aik` (the pinned account key) and that the cert names `leaf_sig_key`.
    pub fn verify(&self, aik: &[u8; 32], leaf_sig_key: &[u8]) -> Result<()> {
        let fail = |what: &str| Err(ChatError::coded("invalid", &format!("device certificate: {what}")));
        let aik_sign = key32(&self.aik_sign).ok_or_else(|| ChatError::coded("invalid", "malformed key"))?;
        if &aik_sign != aik { return fail("not signed by the pinned account key"); }
        let leaf = key32(&self.leaf_sig_key).ok_or_else(|| ChatError::coded("invalid", "malformed key"))?;
        if leaf.as_slice() != leaf_sig_key { return fail("leaf signature key does not match the certificate"); }
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD.decode(&self.sig).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| ChatError::coded("invalid", "malformed signature"))?;
        if URL_SAFE_NO_PAD.encode(sig_bytes) != self.sig { return fail("malformed signature"); }
        let key = VerifyingKey::from_bytes(aik).map_err(|_| ChatError::coded("invalid", "malformed account key"))?;
        key.verify_strict(&Self::tbs(&self.user_id, &self.device_id, &self.platform, &leaf, &aik_sign, self.issued_at), &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .map_err(|_| ChatError::coded("invalid", "device certificate: bad account signature"))
    }
}

/// Where pinned account keys come from: the client's pinned contacts (`peer:<userId>`, TOFU, plus its own
/// identity), or the delivery service's view of the device registry.
pub trait Directory {
    fn aik(&mut self, user_id: &str) -> Result<Option<[u8; 32]>>;
    /// Earlier account keys of the user that a signed succession record handed over from (oldest first), each valid
    /// for certificates issued up to `until` (the record's time). Empty unless a succession was accepted.
    fn previous(&mut self, _user_id: &str) -> Result<Vec<Predecessor>> { Ok(Vec::new()) }
}

/// An account key the user moved on from by a signed succession record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Predecessor {
    pub aik: [u8; 32],
    /// Unix milliseconds: certificates issued after this are not honoured under the old key.
    pub until: u64,
}

/// How a leaf's certificate stands against what this directory has pinned for its user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Signed by the pinned key, or by a predecessor of it before the succession.
    Current,
    /// Signed by a predecessor of the pinned key and honoured because the leaf was already in a validated tree. It acts
    /// like a current one, but a Welcome would refuse it, so nobody is added while one remains.
    Previous,
    /// The user is pinned to another key and this certificate is not a predecessor's: a device of an identity the
    /// user left (recovery, or a succession it was not covered by). It can be removed but can no longer act.
    Stale,
}

/// Error code for a certificate whose user has no usable pin on this device. It is this device's gap, not a fault of
/// whoever signed a commit that merely carries the leaf (see `check_commit`).
pub const UNPINNED: &str = "unpinned";

/// Decodes and verifies the certificate of a credential/signature-key pair against the pinned key (strict: a stale
/// certificate is an error here; use [`verify_standing`] where stale leaves are tolerated).
pub fn verify_credential(directory: &mut dyn Directory, credential: &Credential, leaf_sig_key: &[u8]) -> Result<DeviceCert> {
    match verify_standing(directory, credential, leaf_sig_key, false)? {
        (cert, Standing::Current) => Ok(cert),
        _ => Err(ChatError::coded("invalid", "device certificate: not signed by the pinned account key")),
    }
}

/// Like [`verify_credential`], but a certificate that is well formed and signed by the key it names, for a user
/// pinned to a different key, is `Stale` instead of an error. No pin at all, a bad signature or a leaf key that
/// does not match is still an error. `grandfather` honours predecessor keys (see below) and is for leaves of a tree
/// this device already validated, never for a leaf a commit or a Welcome introduces.
pub fn verify_standing(directory: &mut dyn Directory, credential: &Credential, leaf_sig_key: &[u8], grandfather: bool) -> Result<(DeviceCert, Standing)> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| ChatError::coded("invalid", "not a basic credential"))?;
    let cert = DeviceCert::decode(basic.identity())?;
    // The message names the user so a client can pin them (docs/m4-groups.md §3) and retry.
    let aik = directory.aik(&cert.user_id)?.ok_or_else(|| ChatError::coded(UNPINNED, &format!("no pinned account key for user {}", cert.user_id)))?;
    let claimed = key32(&cert.aik_sign).ok_or_else(|| ChatError::coded("invalid", "malformed key"))?;
    if claimed == aik {
        cert.verify(&aik, leaf_sig_key)?;
        return Ok((cert, Standing::Current));
    }
    // Moved on by a signed succession: certificates the old key issued before the succession stay good, but only for
    // leaves already in a tree this device validated (`grandfather`). A holder of the retired key could otherwise mint
    // backdated certificates (issued_at is the signer's word) for new leaves; those must chain to the current key.
    for earlier in directory.previous(&cert.user_id)? {
        if grandfather && earlier.aik == claimed && cert.issued_at <= earlier.until {
            cert.verify(&earlier.aik, leaf_sig_key)?;
            return Ok((cert, Standing::Previous));
        }
    }
    cert.verify(&claimed, leaf_sig_key)?;
    Ok((cert, Standing::Stale))
}

/// Decodes a credential's certificate without verifying it (display only).
pub fn cert_of(credential: &Credential) -> Option<DeviceCert> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    DeviceCert::decode(basic.identity()).ok()
}
