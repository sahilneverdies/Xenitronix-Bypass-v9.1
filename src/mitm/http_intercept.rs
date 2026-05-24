//! mitm/http_intercept.rs — MajorLogin and GetLoginData request/response patching.
//!
//! Mirrors Python MajorLoginInterceptor.request() and MajorLoginInterceptor.response().
//!
//! UID CHECK ORDER (matches Python exactly):
//!   1. Local whitelist (SQLite) → ALLOW immediately
//!   2. Local blacklist (SQLite) → BLOCK immediately
//!   3. Live HTTP fetch from UID_SERVERS (MAIN → BACKUP) → uid in text → ALLOW / BLOCK
//!   4. Both servers down → FAIL-OPEN (allow)

use anyhow::Result;
use tracing::{info, warn};

use crate::config::{MOBILE_PROTO_HEX, UID_SERVERS};
use crate::crypto::{aes_decrypt, encrypt_api};
use crate::db;
use crate::protobuf::{decode_proto_hex, encode_proto, get_str, set_str, ProtoData, ProtoFields};
use crate::uid_check::{lookup_geo, Db};

// ═══════════════════════════════════════════════════════════════
//  LIVE UID CHECK — mirrors Python checkUIDExists()
// ═══════════════════════════════════════════════════════════════

/// Fetch the UID whitelist from a server and check if `uid` is present.
/// Returns Some(true) = found, Some(false) = server up but UID not there, None = server down.
async fn fetch_and_check_uid(client: &reqwest::Client, url: &str, uid: &str) -> Option<bool> {
    let resp = client
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    Some(text.lines().any(|l| l.trim() == uid))
}

/// Check UID against live servers exactly like Python checkUIDExists().
/// Tries MAIN first, then BACKUP. If both down → fail-open (return true).
async fn live_check_uid(client: &reqwest::Client, uid: &str) -> bool {
    for &(_name, url) in UID_SERVERS {
        match fetch_and_check_uid(client, url, uid).await {
            Some(found) => return found,   // server responded — use its answer
            None => continue,              // server down — try next
        }
    }
    // All servers down → fail-open
    warn!("[UID] Both UID servers unreachable for UID={uid} — failing open");
    true
}

// ═══════════════════════════════════════════════════════════════
//  PROTO TEMPLATE (loaded once at startup)
// ═══════════════════════════════════════════════════════════════

fn load_mobile_proto_template() -> Result<ProtoFields> {
    let decrypted = aes_decrypt(MOBILE_PROTO_HEX)?;
    let hex = hex::encode(&decrypted);
    decode_proto_hex(&hex)
}

/// Lazy-loaded template (decrypted once).
pub fn get_proto_template() -> Result<ProtoFields> {
    load_mobile_proto_template()
}

// ═══════════════════════════════════════════════════════════════
//  FIELD EXTRACTION HELPERS
// ═══════════════════════════════════════════════════════════════

fn extract_uid(fields: &ProtoFields) -> Option<String> {
    match fields.get(&1)? {
        ProtoData::Varint(v) => {
            let s = v.to_string();
            if s.chars().all(|c| c.is_ascii_digit()) && s.len() > 5 {
                Some(s)
            } else {
                None
            }
        }
        ProtoData::Str(s) if s.chars().all(|c| c.is_ascii_digit()) && s.len() > 5 => {
            Some(s.clone())
        }
        _ => None,
    }
}

fn copy_field(src: &ProtoFields, dst: &mut ProtoFields, field: u32) {
    if let Some(data) = src.get(&field) {
        dst.insert(field, data.clone());
    } else {
        dst.remove(&field);
    }
}

// ═══════════════════════════════════════════════════════════════
//  MAJOR LOGIN REQUEST HANDLER
// ═══════════════════════════════════════════════════════════════

/// Process an intercepted MajorLogin POST body.
///
/// 1. AES-decrypt → parse protobuf
/// 2. Extract critical fields from real request
/// 3. Deep-copy proto template
/// 4. Overwrite template with real fields
/// 5. AES-encrypt → return modified body
///
/// Returns `(new_body_bytes, uid_string_or_empty)`.
pub fn handle_major_login_request(body: &[u8], template: &ProtoFields) -> Result<(Vec<u8>, String)> {
    let hex = hex::encode(body);
    let decrypted = aes_decrypt(&hex)?;
    let dec_hex = hex::encode(&decrypted);
    let proto_fields = decode_proto_hex(&dec_hex)?;

    let uid = extract_uid(&proto_fields).unwrap_or_default();

    let event_time = match proto_fields.get(&3) {
        Some(ProtoData::Varint(v)) => Some(ProtoData::Varint(*v)),
        Some(ProtoData::Str(s)) => Some(ProtoData::Str(s.clone())),
        _ => None,
    };
    let version_field = get_str(&proto_fields, 7).map(|s| s.to_string());
    let access_token = get_str(&proto_fields, 29).map(|s| s.to_string());
    let open_id = get_str(&proto_fields, 22).map(|s| s.to_string());

    let mut modified = template.clone();

    // Field 1: UID — must match the actual account
    if !uid.is_empty() {
        if let Ok(n) = uid.parse::<i64>() {
            modified.insert(1, ProtoData::Varint(n));
        }
    }

    // Field 3: event_time (prevents stale timestamp detection)
    if let Some(et) = event_time {
        modified.insert(3, et);
    }

    // Field 7: client_version
    if let Some(v) = version_field {
        set_str(&mut modified, 7, v);
    } else {
        set_str(&mut modified, 7, "1.123.1");
    }

    // Fields 29 / 22: access_token / open_id
    if let Some(at) = access_token {
        set_str(&mut modified, 29, at);
    }
    if let Some(oi) = open_id {
        set_str(&mut modified, 22, oi);
    }

    // Fields 99/100: copy exactly (platform context)
    copy_field(&proto_fields, &mut modified, 99);
    copy_field(&proto_fields, &mut modified, 100);

    // Critical device identifiers: mirror exactly from device request (stealth)
    for field in [19u32, 24, 25, 94] {
        copy_field(&proto_fields, &mut modified, field);
    }

    info!("[MITM] MajorLogin: critical fields mirrored. UID={uid}");

    let proto_bytes = encode_proto(&modified);
    let encrypted_hex = encrypt_api(&proto_bytes)?;
    let new_body = hex::decode(&encrypted_hex)?;
    Ok((new_body, uid))
}

// ═══════════════════════════════════════════════════════════════
//  GET LOGIN DATA HANDLER
// ═══════════════════════════════════════════════════════════════

/// Process an intercepted GetLoginData POST body (same approach as MajorLogin).
pub fn handle_get_login_data(body: &[u8], template: &ProtoFields) -> Result<Vec<u8>> {
    let hex = hex::encode(body);
    let decrypted = aes_decrypt(&hex)?;
    let dec_hex = hex::encode(&decrypted);
    let proto_fields = decode_proto_hex(&dec_hex)?;

    let access_token = get_str(&proto_fields, 29).map(|s| s.to_string());
    let open_id = get_str(&proto_fields, 22).map(|s| s.to_string());
    let client_version = get_str(&proto_fields, 7).map(|s| s.to_string());

    let mut modified = template.clone();

    // Field 3: event_time
    if let Some(et) = proto_fields.get(&3) {
        modified.insert(3, et.clone());
    }

    // Field 7: client_version
    if let Some(v) = client_version {
        set_str(&mut modified, 7, v);
    } else {
        set_str(&mut modified, 7, "1.123.1");
    }

    if let Some(at) = access_token {
        set_str(&mut modified, 29, at);
    }
    if let Some(oi) = open_id {
        set_str(&mut modified, 22, oi);
    }

    copy_field(&proto_fields, &mut modified, 99);
    copy_field(&proto_fields, &mut modified, 100);

    for field in [19u32, 24, 25, 94] {
        copy_field(&proto_fields, &mut modified, field);
    }

    info!("[MITM] GetLoginData: critical fields mirrored");

    let proto_bytes = encode_proto(&modified);
    let encrypted_hex = encrypt_api(&proto_bytes)?;
    Ok(hex::decode(&encrypted_hex)?)
}

// ═══════════════════════════════════════════════════════════════
//  BLOCK MESSAGE BUILDER
// ═══════════════════════════════════════════════════════════════

fn make_block_message(uid: &str) -> Vec<u8> {
    format!(
        "[FF0000]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\
         [FFD700]        SAGE 666 PROTECTION\n\
         [FF0000]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\
         [FFFFFF] ACCESS DENIED: UID NOT AUTHORIZED\n\
         [FFD700] ID: [FFFFFF]{uid}\n\
         [FF0000]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\
         [FFFFFF]  Contact Admin for Authorization\n\
         [FF0000]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    )
    .into_bytes()
}

// ═══════════════════════════════════════════════════════════════
//  MAJOR LOGIN RESPONSE HANDLER
// ═══════════════════════════════════════════════════════════════

pub struct LoginDecision {
    /// Modified response body (with emulator_score patched if needed)
    pub body: Vec<u8>,
    /// Whether this login should be blocked
    pub blocked: bool,
    /// The UID extracted from the response
    pub uid: String,
    /// Block message to send if blocked
    pub block_message: Option<Vec<u8>>,
}

/// Process a MajorLogin response:
/// 1. Decrypt → parse → patch emulator_score (fields 11/12) → re-encrypt
/// 2. Check UID against whitelist/blacklist/uid_cache
/// 3. Return decision
pub async fn handle_major_login_response(
    body: &[u8],
    db: &Db,
    client_ip: &str,
    http_client: &reqwest::Client,
) -> Result<LoginDecision> {
    let resp_hex = hex::encode(body);

    // Decrypt response (try encrypted first, fall back to raw)
    let proto_fields = {
        match aes_decrypt(&resp_hex) {
            Ok(dec) => {
                let dec_hex = hex::encode(&dec);
                decode_proto_hex(&dec_hex).or_else(|_| decode_proto_hex(&resp_hex))?
            }
            Err(_) => decode_proto_hex(&resp_hex)?,
        }
    };

    let uid = extract_uid(&proto_fields).unwrap_or_default();

    // Patch emulator_score (fields 11 and 12)
    let mut patched_fields = proto_fields.clone();
    let mut modified = false;
    for field in [11u32, 12] {
        if let Some(ProtoData::Varint(v)) = patched_fields.get(&field).cloned() {
            if v != 0 {
                info!("[MITM] Patching MajorLoginRes Field {field} emulator_score: {v} -> 0");
                patched_fields.insert(field, ProtoData::Varint(0));
                modified = true;
            }
        }
    }

    let response_body = if modified {
        let proto_bytes = encode_proto(&patched_fields);
        let encrypted_hex = encrypt_api(&proto_bytes)?;
        hex::decode(&encrypted_hex)?
    } else {
        body.to_vec()
    };

    if uid.is_empty() {
        return Ok(LoginDecision {
            body: response_body,
            blocked: false,
            uid: String::new(),
            block_message: None,
        });
    }

    // ─── Step 1: local whitelist (immediate allow) ───
    let (whitelisted, blacklisted) = {
        let locked = db.lock().unwrap();
        let wl = db::get_whitelist_region(&locked, &uid).is_some();
        let bl = db::is_blacklisted(&locked, &uid);
        (wl, bl)
    };

    if whitelisted {
        let locked = db.lock().unwrap();
        db::inc_stat(&locked, "allowed").ok();
        info!("[MITM] ALLOWED (whitelist): UID={uid}");
        return Ok(LoginDecision {
            body: response_body,
            blocked: false,
            uid,
            block_message: None,
        });
    }

    // ─── Step 2: local blacklist (immediate block) ───
    if blacklisted {
        let locked = db.lock().unwrap();
        db::inc_stat(&locked, "blocked").ok();
        warn!("[MITM] BLOCKED (blacklist): UID={uid}");
        let block_msg = make_block_message(&uid);
        return Ok(LoginDecision {
            body: response_body,
            blocked: true,
            uid,
            block_message: Some(block_msg),
        });
    }

    // ─── Step 3: LIVE check against UID servers (mirrors Python checkUIDExists) ───
    // Geo lookup (async, non-blocking)
    let (_country, _region, _city) = lookup_geo(http_client, client_ip).await;

    let uid_allowed = live_check_uid(http_client, &uid).await;

    if !uid_allowed {
        let locked = db.lock().unwrap();
        db::inc_stat(&locked, "blocked").ok();
        warn!("[MITM] BLOCKED (not in UID server): UID={uid}");
        let block_msg = make_block_message(&uid);
        return Ok(LoginDecision {
            body: response_body,
            blocked: true,
            uid,
            block_message: Some(block_msg),
        });
    }

    {
        let locked = db.lock().unwrap();
        db::inc_stat(&locked, "allowed").ok();
    }
    info!("[MITM] ALLOWED (UID server): UID={uid}");

    Ok(LoginDecision {
        body: response_body,
        blocked: false,
        uid,
        block_message: None,
    })
}
