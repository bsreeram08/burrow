//! Device lists and device certificates (docs/devices.md), for the device that holds the account identity key
//! (AIK) inside this core. A port of `packages/signaling/public/devices.js` `validateList`, `listBytes`,
//! `certBytes` and the device-meta seed: the core parses and validates the structured list itself and signs only
//! the canonical bytes it builds, so the AIK never signs caller-chosen bytes. Vectors are pinned against
//! `tests/unit/devices.test.ts` and `apps/chat/test/devices_test.dart`.
use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::{ChatError, Result};
use crate::primitives::unb64;

pub const LIST_LABEL: &str = "webrtc-bun-devicelist-v1";
pub const CERT_LABEL: &str = "webrtc-bun-devicecert-v1";
pub const META_LABEL: &str = "webrtc-bun-devicemeta-v1";
pub const MAX_DEVICES: usize = 16;
const MAX_VERSION: u64 = (1 << 31) - 1;
const MAX_SAFE: u64 = (1 << 53) - 1;

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", what) }

/// One entry of a DeviceList.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    pub device_id: String,
    pub added_at: u64,
    /// Sealed `{label, platform}` (base64url, IV ‖ ciphertext), or empty.
    pub meta: String,
}

/// A validated DeviceList (devices.js `validateList`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceList {
    pub user_id: String,
    pub version: u64,
    pub prev_hash: String,
    pub devices: Vec<DeviceEntry>,
}

/// The signatures that publish a list: the list's, and one certificate per device it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignedList {
    pub signature: String,
    pub certs: BTreeMap<String, String>,
}

fn alphabet(text: &str) -> bool { text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') }
pub fn user_id_ok(text: &str) -> bool { (1..=64).contains(&text.len()) && alphabet(text) }
fn device_id_ok(text: &str) -> bool { text.len() == 22 && alphabet(text) }

fn exactly(object: &Map<String, Value>, keys: &[&str]) -> bool { object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)) }

/// Strict schema check: exact keys, canonical encodings, 1-16 devices sorted by id without duplicates.
pub fn parse_list(json: &str) -> Result<DeviceList> {
    if json.len() > 64 * 1024 { return Err(invalid("Device list too large")); }
    let value: Value = serde_json::from_str(json).map_err(|_| invalid("Device list is not JSON"))?;
    let object = value.as_object().ok_or_else(|| invalid("Device list has unexpected fields"))?;
    if !exactly(object, &["v", "userId", "version", "prevHash", "devices"]) { return Err(invalid("Device list has unexpected fields")); }
    let user_id = object["userId"].as_str().filter(|id| user_id_ok(id)).ok_or_else(|| invalid("Invalid device list owner"))?;
    if object["v"].as_u64() != Some(1) || !object["v"].is_u64() { return Err(invalid("Invalid device list owner")); }
    let version = object["version"].as_u64().filter(|v| (1..=MAX_VERSION).contains(v)).ok_or_else(|| invalid("Invalid device list version"))?;
    let prev_hash = object["prevHash"].as_str().ok_or_else(|| invalid("Invalid previous-list hash"))?;
    let prev_ok = if version == 1 { prev_hash.is_empty() } else { prev_hash.len() == 43 && unb64(prev_hash, Some(32)).is_ok() };
    if !prev_ok { return Err(invalid("Invalid previous-list hash")); }
    let devices = object["devices"].as_array().filter(|d| (1..=MAX_DEVICES).contains(&d.len())).ok_or_else(|| invalid("A device list names 1–16 devices"))?;
    let mut out = Vec::with_capacity(devices.len());
    let mut previous = String::new();
    for device in devices {
        let entry = device.as_object().filter(|d| exactly(d, &["deviceId", "addedAt", "meta"])).ok_or_else(|| invalid("Device entry has unexpected fields"))?;
        let device_id = entry["deviceId"].as_str().filter(|id| device_id_ok(id)).ok_or_else(|| invalid("Invalid device id"))?;
        let added_at = entry["addedAt"].as_u64().filter(|t| *t <= MAX_SAFE).ok_or_else(|| invalid("Invalid device timestamp"))?;
        let meta = entry["meta"].as_str().ok_or_else(|| invalid("Invalid device metadata"))?;
        // Empty when the signer could not describe the device; otherwise sealed {label, platform}: 12-byte IV,
        // at least the 16-byte tag, at most 512 bytes in all, canonical base64url.
        if !meta.is_empty() && !((38..=683).contains(&meta.len()) && unb64(meta, None).is_ok()) { return Err(invalid("Invalid device metadata")); }
        // Byte order of the ids, as JavaScript compares these ASCII strings.
        if device_id.as_bytes() <= previous.as_bytes() { return Err(invalid("Devices must be sorted by id without duplicates")); }
        previous = device_id.to_string();
        out.push(DeviceEntry { device_id: device_id.into(), added_at, meta: meta.into() });
    }
    Ok(DeviceList { user_id: user_id.into(), version, prev_hash: prev_hash.into(), devices: out })
}

/// TLS-style writer (devices.js `writer`).
struct Writer(Vec<u8>);
impl Writer {
    fn text16(&mut self, text: &str) -> &mut Self { self.bytes16(text.as_bytes()) }
    fn bytes16(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }
    fn bytes8(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.push(bytes.len() as u8);
        self.0.extend_from_slice(bytes);
        self
    }
    fn u16(&mut self, value: u16) -> &mut Self { self.0.extend_from_slice(&value.to_be_bytes()); self }
    fn u32(&mut self, value: u32) -> &mut Self { self.0.extend_from_slice(&value.to_be_bytes()); self }
    fn u64(&mut self, value: u64) -> &mut Self { self.0.extend_from_slice(&value.to_be_bytes()); self }
}

/// The canonical bytes the AIK signs for a list (devices.js `listBytes`).
pub fn list_bytes(list: &DeviceList) -> Vec<u8> {
    let mut out = Writer(Vec::new());
    let prev = if list.prev_hash.is_empty() { Vec::new() } else { unb64(&list.prev_hash, Some(32)).expect("validated") };
    out.text16(LIST_LABEL).text16(&list.user_id).u32(list.version as u32).bytes8(&prev).u16(list.devices.len() as u16);
    for device in &list.devices {
        let meta = if device.meta.is_empty() { Vec::new() } else { unb64(&device.meta, None).expect("validated") };
        out.text16(&device.device_id).u64(device.added_at).bytes16(&meta);
    }
    out.0
}

/// The certificate a list implies for one of its devices (devices.js `certBytes(certFor(...))`; no leaf key yet).
pub fn cert_bytes(user_id: &str, device: &DeviceEntry) -> Vec<u8> {
    let mut out = Writer(Vec::new());
    out.text16(CERT_LABEL).text16(user_id).text16(&device.device_id).bytes8(&[]).u64(device.added_at);
    out.0
}

/// What the AIK signs to derive the account's device-meta sealing key (devices.js `deviceMetaKey`).
pub fn meta_bytes(user_id: &str) -> Result<Vec<u8>> {
    if !user_id_ok(user_id) { return Err(invalid("Invalid user id")); }
    let mut out = Writer(Vec::new());
    out.text16(META_LABEL).text16(user_id);
    Ok(out.0)
}
