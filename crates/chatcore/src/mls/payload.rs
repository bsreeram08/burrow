//! Application payload v2 (architecture §5; MLS.md §5): the JSON inside an MLS application message. Validated
//! here, in Rust, so the web app and the native apps accept and reject exactly the same payloads. Every payload is
//! an object with exactly the fields of its type (unknown fields rejected). Errors carry the existing
//! disposition codes: `invalid` (acknowledge and discard with a notice).
use serde_json::{Map, Value};

use super::cert::canonical_id;
use crate::error::{ChatError, Result};

pub const MAX_TEXT: usize = 16 * 1024;
const MAX_TOPIC: usize = 256;
const MAX_POLL_TEXT: usize = 200;
const MAX_OPTIONS: usize = 10;
const MAX_MENTIONS: usize = 64;
const MAX_ATTACHMENTS: usize = 10;
const MAX_ARGS: usize = 2048;
const MAX_EMOJI: usize = 64;
const THIRTY_DAYS: u64 = 30 * 86_400_000;
/// Disappearing-message choices (signal.js / chat-store.js): 1 h, 24 h, 7 d.
pub const EXPIRE_CHOICES: [u64; 3] = [3_600_000, 86_400_000, 604_800_000];

/// What the receiver knows about a payload's context (the app supplies it from its message store).
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// Authenticated MLS sender of this payload.
    pub sender: String,
    /// Whether the sender is a group admin (from the group's roles).
    pub sender_is_admin: bool,
    /// For edit / delete / reaction / pin / vote: the sender of the target message, if the app has it.
    pub target_sender: Option<String>,
}

fn invalid(what: &str) -> ChatError { ChatError::coded("invalid", &format!("invalid payload: {what}")) }

fn uuid(value: Option<&Value>) -> bool {
    let Some(text) = value.and_then(Value::as_str) else { return false };
    let b = text.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() && !c.is_ascii_uppercase() })
}
fn text_within(value: Option<&Value>, max: usize) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| !text.trim().is_empty() && text.len() <= max)
}
fn time(value: Option<&Value>) -> Option<u64> { value.and_then(Value::as_u64).filter(|t| *t < 8_640_000_000_000_000) }
fn exactly(object: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Result<()> {
    if !required.iter().all(|key| object.contains_key(*key)) { return Err(invalid("missing field")); }
    if !object.keys().all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())) { return Err(invalid("unknown field")); }
    Ok(())
}
fn needs_target_sender<'a>(context: &'a Context) -> Result<&'a str> {
    context.target_sender.as_deref().ok_or_else(|| invalid("target message unknown"))
}

/// Validates one decrypted payload against its type's schema and the sender's authority. Returns its type.
pub fn validate(payload: &str, context: &Context) -> Result<String> {
    if payload.len() > 64 * 1024 { return Err(invalid("too large")); }
    let value: Value = serde_json::from_str(payload).map_err(|_| invalid("not JSON"))?;
    let object = value.as_object().ok_or_else(|| invalid("not an object"))?;
    if object.get("v").and_then(Value::as_u64) != Some(2) { return Err(invalid("unsupported version")); }
    let kind = object.get("type").and_then(Value::as_str).ok_or_else(|| invalid("missing type"))?.to_string();
    let base = ["v", "type", "id"];
    let with = |extra: &[&'static str]| -> Vec<&'static str> { base.iter().copied().chain(extra.iter().copied()).collect() };
    if kind != "typing" && !uuid(object.get("id")) { return Err(invalid("id")); }
    match kind.as_str() {
        "message" => {
            exactly(object, &with(&["text", "createdAt", "expiresAt"]), &["thread", "mentions", "attachments", "format"])?;
            if !text_within(object.get("text"), MAX_TEXT) { return Err(invalid("text")); }
            let created = time(object.get("createdAt")).ok_or_else(|| invalid("createdAt"))?;
            match object.get("expiresAt") {
                Some(Value::Null) => {}
                other => {
                    let expires = time(other).ok_or_else(|| invalid("expiresAt"))?;
                    if expires <= created || expires > created + THIRTY_DAYS { return Err(invalid("expiresAt")); }
                }
            }
            if object.get("thread").is_some_and(|v| !uuid(Some(v))) { return Err(invalid("thread")); }
            if let Some(mentions) = object.get("mentions") {
                let list = mentions.as_array().ok_or_else(|| invalid("mentions"))?;
                if list.len() > MAX_MENTIONS || !list.iter().all(|m| m.as_str().is_some_and(canonical_id)) { return Err(invalid("mentions")); }
            }
            if let Some(format) = object.get("format") {
                if !matches!(format.as_str(), Some("md" | "me")) { return Err(invalid("format")); }
            }
            if let Some(attachments) = object.get("attachments") {
                let list = attachments.as_array().ok_or_else(|| invalid("attachments"))?;
                if list.len() > MAX_ATTACHMENTS { return Err(invalid("attachments")); }
                for item in list {
                    let att = item.as_object().ok_or_else(|| invalid("attachment"))?;
                    exactly(att, &["blobId", "key", "digest", "size", "mime", "name"], &["thumb"])?;
                    let short = |k: &str, max: usize| att.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty() && s.len() <= max);
                    if !short("blobId", 64) || !short("key", 64) || !short("digest", 128) || !short("mime", 128) || !short("name", 256) || att.get("size").and_then(Value::as_u64).is_none() {
                        return Err(invalid("attachment"));
                    }
                }
            }
        }
        "edit" => {
            exactly(object, &with(&["target", "text", "editedAt"]), &[])?;
            if !uuid(object.get("target")) || !text_within(object.get("text"), MAX_TEXT) || time(object.get("editedAt")).is_none() { return Err(invalid("edit")); }
            if needs_target_sender(context)? != context.sender { return Err(invalid("only the sender may edit a message")); }
        }
        "delete" => {
            exactly(object, &with(&["target"]), &[])?;
            if !uuid(object.get("target")) { return Err(invalid("target")); }
            if needs_target_sender(context)? != context.sender && !context.sender_is_admin { return Err(invalid("only the sender or an admin may delete a message")); }
        }
        "reaction" => {
            exactly(object, &with(&["target", "emoji", "op"]), &[])?;
            if !uuid(object.get("target")) || !text_within(object.get("emoji"), MAX_EMOJI) || !matches!(object.get("op").and_then(Value::as_str), Some("add" | "remove")) {
                return Err(invalid("reaction"));
            }
        }
        "pin" => {
            exactly(object, &with(&["target", "op"]), &[])?;
            if !uuid(object.get("target")) || !matches!(object.get("op").and_then(Value::as_str), Some("pin" | "unpin")) { return Err(invalid("pin")); }
            if !context.sender_is_admin { return Err(invalid("only admins pin messages")); }
        }
        "topic" => {
            exactly(object, &with(&["topic"]), &[])?;
            if !object.get("topic").and_then(Value::as_str).is_some_and(|t| t.len() <= MAX_TOPIC) { return Err(invalid("topic")); }
            if !context.sender_is_admin { return Err(invalid("only admins set the topic")); }
        }
        "settings" => {
            exactly(object, &with(&["expireAfter", "history"]), &[])?;
            let expire_ok = match object.get("expireAfter") { Some(Value::Null) => true, other => other.and_then(Value::as_u64).is_some_and(|v| EXPIRE_CHOICES.contains(&v)) };
            if !expire_ok || !matches!(object.get("history").and_then(Value::as_str), Some("none" | "share-30d")) { return Err(invalid("settings")); }
            if !context.sender_is_admin { return Err(invalid("only admins change settings")); }
        }
        "receipt" => {
            exactly(object, &with(&["upTo", "kind"]), &[])?;
            if object.get("upTo").and_then(Value::as_u64).is_none() || !matches!(object.get("kind").and_then(Value::as_str), Some("read" | "delivered")) { return Err(invalid("receipt")); }
        }
        "poll" => {
            exactly(object, &with(&["question", "options", "multi"]), &[])?;
            let options = object.get("options").and_then(Value::as_array).ok_or_else(|| invalid("options"))?;
            if !text_within(object.get("question"), MAX_POLL_TEXT) || options.len() < 2 || options.len() > MAX_OPTIONS
                || !options.iter().all(|o| text_within(Some(o), MAX_POLL_TEXT)) || !object.get("multi").is_some_and(Value::is_boolean) {
                return Err(invalid("poll"));
            }
        }
        "vote" => {
            exactly(object, &with(&["poll", "choices"]), &[])?;
            let choices = object.get("choices").and_then(Value::as_array).ok_or_else(|| invalid("choices"))?;
            let mut seen = std::collections::HashSet::new();
            if !uuid(object.get("poll")) || choices.len() > MAX_OPTIONS || !choices.iter().all(|c| c.as_u64().is_some_and(|i| (i as usize) < MAX_OPTIONS && seen.insert(i))) {
                return Err(invalid("vote"));
            }
        }
        "command" => {
            exactly(object, &with(&["bot", "name", "args", "visibility"]), &["thread"])?;
            let name_ok = object.get("name").and_then(Value::as_str).is_some_and(|n| !n.is_empty() && n.len() <= 32 && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'));
            if !object.get("bot").and_then(Value::as_str).is_some_and(canonical_id) || !name_ok
                || !object.get("args").and_then(Value::as_str).is_some_and(|a| a.len() <= MAX_ARGS)
                || !matches!(object.get("visibility").and_then(Value::as_str), Some("channel" | "ephemeral"))
                || object.get("thread").is_some_and(|v| !uuid(Some(v))) {
                return Err(invalid("command"));
            }
        }
        "burn" => {
            exactly(object, &base, &[])?;
            if !context.sender_is_admin { return Err(invalid("only admins burn a group conversation")); }
        }
        "typing" => {
            exactly(object, &["v", "type", "state"], &[])?;
            if !matches!(object.get("state").and_then(Value::as_str), Some("start" | "stop")) { return Err(invalid("typing")); }
        }
        _ => return Err(invalid("unknown type")),
    }
    Ok(kind)
}
