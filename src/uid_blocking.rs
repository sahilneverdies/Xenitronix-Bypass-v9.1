//! uid_blocking.rs — Packet-level UID validation (runs inside WinDivert loop).
//!
//! Mirrors Python `handle_uid_blocking()` and `check_uid()`:
//!   1. Inspects raw packet payload for "majorlogin" marker
//!   2. Extracts hex-encoded AES payload from the packet
//!   3. AES-decrypts → protobuf decode → extract UID (fields 1/2/3)
//!   4. HTTP GET to VPS whitelist URL → check if UID is present
//!   5. Returns false to DROP packet if UID is not authorized
//!
//! FAIL-OPEN: If the VPS is unreachable, the packet is ALLOWED (matches Python).

use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::config::UID_URL;
use crate::crypto::aes_decrypt;
use crate::protobuf::{decode_proto_hex, ProtoData};

/// Cached UID whitelist from VPS — refreshed every 60 seconds.
pub struct UidCache {
    uids_text: String,
    last_refresh: Instant,
}

impl UidCache {
    pub fn new() -> Self {
        Self {
            uids_text: String::new(),
            last_refresh: Instant::now() - Duration::from_secs(9999), // force immediate refresh
        }
    }

    /// Refresh the UID list from VPS if stale (>60s).
    fn maybe_refresh(&mut self) {
        if self.last_refresh.elapsed() < Duration::from_secs(60) {
            return;
        }
        // Blocking HTTP GET (we're on a dedicated OS thread)
        match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .and_then(|c| c.get(UID_URL).send())
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text() {
                    self.uids_text = text;
                    info!("[UID] Refreshed whitelist from VPS ({} bytes)", self.uids_text.len());
                }
            }
            Ok(resp) => {
                warn!("[UID] VPS returned HTTP {}", resp.status());
            }
            Err(e) => {
                warn!("[UID] VPS unreachable: {e} — fail open");
            }
        }
        self.last_refresh = Instant::now();
    }

    /// Check if UID exists in the VPS whitelist.
    /// Returns true if found OR if VPS is unreachable (fail-open).
    pub fn check_uid(&mut self, uid: &str) -> bool {
        self.maybe_refresh();
        if self.uids_text.is_empty() {
            return true; // Fail open if VPS is down
        }
        self.uids_text.contains(uid)
    }
}

/// Check if a raw packet payload contains a "majorlogin" request,
/// extract the UID, and validate it against the VPS whitelist.
///
/// Returns `true` to ALLOW the packet, `false` to DROP it.
pub fn handle_uid_blocking(payload: &[u8], cache: &mut UidCache) -> bool {
    // Quick check: does the payload contain "majorlogin"?
    let payload_lower = payload.to_ascii_lowercase();
    if !payload_lower.windows(10).any(|w| w == b"majorlogin") {
        return true; // Not a login packet — allow
    }

    // Try to find a hex-encoded AES payload (128+ hex chars)
    let payload_hex = hex::encode(payload);
    if let Some(hex_payload) = extract_hex_payload(&payload_hex) {
        match extract_uid_from_encrypted(&hex_payload) {
            Some(uid) => {
                if !cache.check_uid(&uid) {
                    warn!("[UID] BLOCKED UNAUTHORIZED UID: {uid}");
                    return false; // DROP PACKET
                }
                info!("[UID] AUTHORIZED UID: {uid}");
            }
            None => {
                // Couldn't parse UID — allow (fail open)
            }
        }
    }

    true // ALLOW
}

/// Extract a long hex string (≥128 hex chars) from the packet hex.
/// Mirrors Python: `re.search(b'([a-fA-F0-9]{128,})', data.hex().encode())`
fn extract_hex_payload(full_hex: &str) -> Option<String> {
    // The full hex string is already all hex chars, but we need to find
    // the encrypted protobuf payload within it.
    // In practice, the entire packet body hex IS the payload for POST bodies.
    // For raw TCP packets, look for long runs of hex.
    
    // Simple approach: if full_hex is long enough, try the whole thing first
    if full_hex.len() >= 128 {
        return Some(full_hex.to_string());
    }
    
    // Otherwise scan for 128+ char hex runs
    let mut start = None;
    let mut run_len = 0usize;
    
    for (i, c) in full_hex.chars().enumerate() {
        if c.is_ascii_hexdigit() {
            if start.is_none() {
                start = Some(i);
            }
            run_len += 1;
        } else {
            if run_len >= 128 {
                let s = start.unwrap();
                return Some(full_hex[s..s + run_len].to_string());
            }
            start = None;
            run_len = 0;
        }
    }
    
    if run_len >= 128 {
        let s = start.unwrap();
        return Some(full_hex[s..s + run_len].to_string());
    }
    
    None
}

/// Decrypt the hex payload and extract a UID from protobuf fields 1/2/3.
/// Mirrors Python:
///   dec = aes_decrypt(payload_hex)
///   fields = json.loads(get_available_room(dec.hex()))
///   uid = next(str(fields[f]["data"]) for f in ["1","2","3"] if len(str(fields[f]["data"])) > 5)
fn extract_uid_from_encrypted(hex_payload: &str) -> Option<String> {
    let decrypted = aes_decrypt(hex_payload).ok()?;
    let dec_hex = hex::encode(&decrypted);
    let fields = decode_proto_hex(&dec_hex).ok()?;
    
    // Check fields 1, 2, 3 for a UID (numeric string > 5 digits)
    for field_num in [1u32, 2, 3] {
        if let Some(data) = fields.get(&field_num) {
            let candidate = match data {
                ProtoData::Varint(v) => v.to_string(),
                ProtoData::Str(s) => s.clone(),
                _ => continue,
            };
            if candidate.len() > 5 && candidate.chars().all(|c| c.is_ascii_digit()) {
                return Some(candidate);
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hex_finds_long_runs() {
        let s = "aa".repeat(80); // 160 hex chars
        assert!(extract_hex_payload(&s).is_some());
    }

    #[test]
    fn extract_hex_ignores_short_runs() {
        let s = "abcd1234";
        assert!(extract_hex_payload(s).is_none());
    }

    #[test]
    fn cache_fail_open_when_empty() {
        let mut cache = UidCache::new();
        // With empty cache, should fail open
        assert!(cache.check_uid("12345678"));
    }
}
