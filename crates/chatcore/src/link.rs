//! The crypto of device linking (docs/m5-linking.md §1.2): a QR text, two X25519 ephemerals and a link secret give
//! two directional keys and a short confirmation code; messages are sealed with AES-256-GCM and strictly counted.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::error::{ChatError, Result};
use crate::primitives::{b64, hkdf, unb64};

pub const QR_PREFIX: &str = "wb-link1.";
const VERSION: u8 = 1;
/// A sealed message is at most this many bytes decoded (docs: 64 KiB).
pub const MAX_SEALED: usize = 64 * 1024;
pub const N2P: u8 = 0x01;
pub const P2N: u8 = 0x02;

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", what) }

/// The QR text: `"wb-link1." + base64url(0x01 ‖ linkId(16) ‖ ephN(32) ‖ secret(16))`.
pub fn qr_text(link_id: &[u8; 16], eph_n: &[u8; 32], secret: &[u8; 16]) -> String {
    let mut raw = vec![VERSION];
    raw.extend_from_slice(link_id);
    raw.extend_from_slice(eph_n);
    raw.extend_from_slice(secret);
    format!("{QR_PREFIX}{}", b64(&raw))
}

pub fn parse_qr(text: &str) -> Result<([u8; 16], [u8; 32], [u8; 16])> {
    let body = text.strip_prefix(QR_PREFIX).ok_or_else(|| invalid("not a device-link code"))?;
    let raw = unb64(body, Some(65)).map_err(|_| invalid("not a device-link code"))?;
    if raw[0] != VERSION { return Err(invalid("unsupported device-link code")); }
    Ok((raw[1..17].try_into().expect("16"), raw[17..49].try_into().expect("32"), raw[49..65].try_into().expect("16")))
}

pub fn link_id_bytes(text: &str) -> Result<[u8; 16]> {
    unb64(text, Some(16)).map_err(|_| invalid("a link id is 16 bytes of base64url"))?.try_into().map_err(|_| invalid("a link id is 16 bytes of base64url"))
}

/// Directional keys and the confirmation code.
pub struct Keys {
    pub n2p: [u8; 32],
    pub p2n: [u8; 32],
    pub code: String,
}

/// `ikm = dh ‖ secret`; `salt = SHA-256("webrtc-bun-link-v1" ‖ linkId ‖ ephN ‖ ephP)`.
pub fn derive(dh: &[u8; 32], secret: &[u8; 16], link_id: &[u8; 16], eph_n: &[u8; 32], eph_p: &[u8; 32]) -> Keys {
    let mut ikm = dh.to_vec();
    ikm.extend_from_slice(secret);
    let salt = Sha256::digest([b"webrtc-bun-link-v1".as_slice(), link_id, eph_n, eph_p].concat());
    let key = |info: &str| -> [u8; 32] { hkdf(&ikm, &salt, info, 32).try_into().expect("32") };
    let code = hkdf(&ikm, &salt, "webrtc-bun-link-v1 code", 4);
    let number = u32::from_be_bytes(code.try_into().expect("4")) % 1_000_000;
    Keys { n2p: key("webrtc-bun-link-v1 n2p"), p2n: key("webrtc-bun-link-v1 p2n"), code: format!("{:03} {:03}", number / 1000, number % 1000) }
}

fn aad(link_id: &[u8; 16], dir: u8, counter: u64) -> Vec<u8> {
    let mut out = b"webrtc-bun-link-msg-v1".to_vec();
    out.extend_from_slice(link_id);
    out.push(dir);
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// `base64url(counter(8) ‖ AES-256-GCM(key, 0⁴ ‖ counter, plaintext))`.
pub fn seal(key: &[u8; 32], link_id: &[u8; 16], dir: u8, counter: u64, plaintext: &[u8]) -> Result<String> {
    if plaintext.len() > 48 * 1024 { return Err(invalid("a link message is at most 48 KiB")); }
    let sealed = Aes256Gcm::new_from_slice(key).expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce(counter)), Payload { msg: plaintext, aad: &aad(link_id, dir, counter) })
        .map_err(|_| invalid("link message could not be sealed"))?;
    let mut out = counter.to_be_bytes().to_vec();
    out.extend_from_slice(&sealed);
    Ok(b64(&out))
}

/// Opens one message, which must carry exactly `expected` as its counter.
pub fn open(key: &[u8; 32], link_id: &[u8; 16], dir: u8, expected: u64, data: &str) -> Result<Vec<u8>> {
    if data.len() > MAX_SEALED * 4 / 3 + 4 { return Err(invalid("link message too large")); }
    let raw = unb64(data, None).map_err(|_| ChatError::coded("malformed", "Invalid link message"))?;
    if raw.len() < 8 + 16 { return Err(ChatError::coded("malformed", "Invalid link message")); }
    let counter = u64::from_be_bytes(raw[..8].try_into().expect("8"));
    if counter != expected { return Err(ChatError::coded("replay", "Link message out of order or repeated")); }
    Aes256Gcm::new_from_slice(key).expect("32-byte key")
        .decrypt(Nonce::from_slice(&nonce(counter)), Payload { msg: &raw[8..], aad: &aad(link_id, dir, counter) })
        .map_err(|_| ChatError::coded("auth", "Link message authentication failed"))
}

// ---------- Short-code rendezvous (docs/m5-linking.md §1.7) ----------
// No QR means no link secret, so the 6-digit code is the only authentication of the key agreement. To make it hold
// against whoever relays the keys, the new device COMMITS to its ephemeral key before it sees the primary's, then
// reveals it. A relay that wants both screens to show one code would have to pick its key for the new device
// without knowing the new device's (committed, hidden) key: one guess in a million.

/// `SHA-256("webrtc-bun-link-commit-v1" ‖ linkId(16) ‖ text16(deviceN) ‖ ephN(32) ‖ nonce(16))`, base64url.
pub fn commitment(link_id: &[u8; 16], device_n: &str, eph_n: &[u8; 32], nonce: &[u8; 16]) -> String {
    let mut data = b"webrtc-bun-link-commit-v1".to_vec();
    data.extend_from_slice(link_id);
    data.extend_from_slice(&(device_n.len() as u16).to_be_bytes());
    data.extend_from_slice(device_n.as_bytes());
    data.extend_from_slice(eph_n);
    data.extend_from_slice(nonce);
    b64(&Sha256::digest(data))
}

/// Keys and code for the short-code variant: no link secret; the salt commits to both ephemeral keys and both
/// device ids: `SHA-256("webrtc-bun-link-v2" ‖ linkId ‖ ephN ‖ ephP ‖ text16(deviceN) ‖ text16(deviceP))`, and the
/// infos are `"webrtc-bun-link-v2 n2p|p2n|code"`.
pub fn derive_code_mode(dh: &[u8; 32], link_id: &[u8; 16], eph_n: &[u8; 32], eph_p: &[u8; 32], device_n: &str, device_p: &str) -> Keys {
    let mut salt_input = b"webrtc-bun-link-v2".to_vec();
    salt_input.extend_from_slice(link_id);
    salt_input.extend_from_slice(eph_n);
    salt_input.extend_from_slice(eph_p);
    for device in [device_n, device_p] {
        salt_input.extend_from_slice(&(device.len() as u16).to_be_bytes());
        salt_input.extend_from_slice(device.as_bytes());
    }
    let salt = Sha256::digest(salt_input);
    let key = |info: &str| -> [u8; 32] { hkdf(dh, &salt, info, 32).try_into().expect("32") };
    let code = hkdf(dh, &salt, "webrtc-bun-link-v2 code", 4);
    let number = u32::from_be_bytes(code.try_into().expect("4")) % 1_000_000;
    Keys { n2p: key("webrtc-bun-link-v2 n2p"), p2n: key("webrtc-bun-link-v2 p2n"), code: format!("{:03} {:03}", number / 1000, number % 1000) }
}
