//! Succession records (docs/m5-linking.md §5): how an account moves from one identity key (AIK) to another and
//! keeps its contacts' verification. The old AIK signs one record naming the new keys; anyone holding a pin for the
//! old key can follow the chain and move the pin. The core builds the signed bytes itself and signs nothing else.
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use crate::error::{ChatError, Result};
use crate::primitives::{b64, unb64_32};

pub const LABEL: &str = "webrtc-bun-succession-v1";
/// At most this many records form a chain.
pub const MAX_CHAIN: usize = 8;

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", what) }

/// `{ v: 1, userId, oldSign, newSign, newDh, at }`; the keys are base64url, `at` is Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub user_id: String,
    pub old_sign: String,
    pub new_sign: String,
    pub new_dh: String,
    pub at: u64,
}

fn exactly(object: &Map<String, Value>, keys: &[&str]) -> bool { object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)) }

impl Record {
    /// Strict parse: exact keys, canonical 32-byte keys, a plain user id.
    pub fn parse(value: &Value) -> Result<Self> {
        let object = value.as_object().filter(|o| exactly(o, &["v", "userId", "oldSign", "newSign", "newDh", "at"])).ok_or_else(|| invalid("malformed succession record"))?;
        if object["v"].as_u64() != Some(1) { return Err(invalid("unsupported succession record")); }
        let text = |key: &str| object[key].as_str().map(str::to_string).ok_or_else(|| invalid("malformed succession record"));
        let record = Self { user_id: text("userId")?, old_sign: text("oldSign")?, new_sign: text("newSign")?, new_dh: text("newDh")?, at: object["at"].as_u64().filter(|t| *t < (1 << 53)).ok_or_else(|| invalid("malformed succession record"))? };
        if !crate::devicelist::user_id_ok(&record.user_id) { return Err(invalid("malformed succession record")); }
        for key in [&record.old_sign, &record.new_sign, &record.new_dh] { unb64_32(key).map_err(|_| invalid("malformed succession record"))?; }
        if record.old_sign == record.new_sign { return Err(invalid("a succession names a new key")); }
        Ok(record)
    }

    /// `text16(label) ‖ text16(userId) ‖ bytes8(oldSign) ‖ bytes8(newSign) ‖ bytes8(newDh) ‖ u64(at)`.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let text16 = |out: &mut Vec<u8>, text: &str| { out.extend_from_slice(&(text.len() as u16).to_be_bytes()); out.extend_from_slice(text.as_bytes()); };
        text16(&mut out, LABEL);
        text16(&mut out, &self.user_id);
        for key in [&self.old_sign, &self.new_sign, &self.new_dh] { out.push(32); out.extend_from_slice(&unb64_32(key).expect("validated")); }
        out.extend_from_slice(&self.at.to_be_bytes());
        out
    }

    pub fn json(&self, signature: &str) -> Value {
        serde_json::json!({ "v": 1, "userId": self.user_id, "oldSign": self.old_sign, "newSign": self.new_sign, "newDh": self.new_dh, "at": self.at, "signature": signature })
    }

    /// Verifies `signature` (base64url, 64 bytes) under the record's old key.
    pub fn verify(&self, signature: &str) -> Result<()> {
        let key = VerifyingKey::from_bytes(&unb64_32(&self.old_sign)?).map_err(|_| invalid("malformed succession record"))?;
        let raw: [u8; 64] = crate::primitives::unb64(signature, Some(64)).map_err(|_| invalid("malformed signature"))?.try_into().expect("length checked");
        key.verify_strict(&self.bytes(), &Signature::from_bytes(&raw)).map_err(|_| ChatError::coded("auth", "the succession record is not signed by the old identity key"))
    }
}

/// A record with its signature, as served (`{ ..., signature }`).
pub fn parse_signed(value: &Value) -> Result<(Record, String)> {
    let mut object = value.as_object().cloned().ok_or_else(|| invalid("malformed succession record"))?;
    let signature = object.remove("signature").and_then(|s| s.as_str().map(str::to_string)).ok_or_else(|| invalid("malformed succession record"))?;
    Ok((Record::parse(&Value::Object(object))?, signature))
}

/// Follows `records` (oldest first) from the key a client has pinned: each must be for `user_id`, name the key the
/// last one ended at, and verify under it. Returns the final records and the chain of keys passed through.
pub fn follow(start_sign: &str, user_id: &str, records: &[Value]) -> Result<Vec<Record>> {
    if records.is_empty() || records.len() > MAX_CHAIN { return Err(invalid("a succession chain has 1-8 records")); }
    let mut at = start_sign.to_string();
    let mut chain = Vec::new();
    for value in records {
        let (record, signature) = parse_signed(value)?;
        if record.user_id != user_id || record.old_sign != at { return Err(invalid("the succession chain does not continue from the pinned key")); }
        record.verify(&signature)?;
        at = record.new_sign.clone();
        chain.push(record);
    }
    Ok(chain)
}

pub fn encode_signature(raw: [u8; 64]) -> String { b64(&raw) }
