//! patcher.rs — Emulator flag scrubbing engine.
//!
//! Implements the same safety rules as the Python original:
//!   OUTBOUND TCP:  BOOL_PATCHES (3-byte always, 2-byte only on <150 bytes) + STRING_PATCHES
//!   OUTBOUND UDP:  STRING_PATCHES only
//!   INBOUND  TCP:  ONLY F25 (0xC8 0x01 0x0N → 0xC8 0x01 0x00)
//!   INBOUND  UDP:  NEVER touched (match data — do not corrupt)
//!   TLS/DTLS:      Skip entirely (encrypted — patching would break MAC)

use crate::config::{BOOL_PATCHES, STRING_PATCHES};

// ═══════════════════════════════════════════════════════════════
//  TLS / DTLS DETECTION
// ═══════════════════════════════════════════════════════════════

/// Returns true if `data` looks like a TLS or DTLS record.
/// Patching encrypted data breaks the MAC, so we skip these entirely.
#[inline]
pub fn is_tls_or_dtls(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let ct = data[0];
    // TLS content types: 0x14 (ChangeCipherSpec), 0x15 (Alert), 0x16 (Handshake), 0x17 (AppData)
    if matches!(ct, 0x14 | 0x15 | 0x16 | 0x17) {
        // TLS: version byte 0x03 followed by 0x01/0x02/0x03
        if data[1] == 0x03 && matches!(data[2], 0x01 | 0x02 | 0x03) {
            return true;
        }
        // DTLS: version 0xFE followed by 0xFD/0xFF
        if data[1] == 0xFE && matches!(data[2], 0xFD | 0xFF) {
            return true;
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════
//  BYTE-REPLACE HELPER
// ═══════════════════════════════════════════════════════════════

/// Replace all non-overlapping occurrences of `pattern` in `buf` with `replacement`.
/// `replacement` must be the same length as `pattern` (enforced by callers).
fn replace_all(buf: &mut Vec<u8>, pattern: &[u8], replacement: &[u8]) -> usize {
    let plen = pattern.len();
    if plen == 0 || plen != replacement.len() {
        return 0;
    }
    let mut count = 0usize;
    let mut i = 0usize;
    while i + plen <= buf.len() {
        if buf[i..i + plen] == *pattern {
            buf[i..i + plen].copy_from_slice(replacement);
            count += 1;
            i += plen; // non-overlapping
        } else {
            i += 1;
        }
    }
    count
}

// ═══════════════════════════════════════════════════════════════
//  STRING PATCH ENGINE
// ═══════════════════════════════════════════════════════════════

/// Apply all STRING_PATCHES to `buf`.  
/// Replacement is space-padded to match the original key length.
pub fn apply_string_patches(buf: &mut Vec<u8>) -> Vec<String> {
    let mut applied = Vec::new();
    for &(key, replacement) in STRING_PATCHES {
        let target_len = key.len();
        // Build a padded replacement of exactly `target_len` bytes
        let mut padded = replacement[..replacement.len().min(target_len)].to_vec();
        while padded.len() < target_len {
            padded.push(b' ');
        }
        let count = replace_all(buf, key, &padded);
        if count > 0 {
            let label = String::from_utf8_lossy(key).into_owned();
            for _ in 0..count {
                applied.push(format!("STR:{label}"));
            }
        }
    }
    applied
}

// ═══════════════════════════════════════════════════════════════
//  BOOL PATCH ENGINE (binary field tags)
// ═══════════════════════════════════════════════════════════════

/// Apply BOOL_PATCHES to `buf`.  
/// 2-byte patterns are skipped if `psize >= 150` (safety rule for large packets).
pub fn apply_bool_patches(buf: &mut Vec<u8>, psize: usize) -> Vec<String> {
    let mut applied = Vec::new();
    for &(search, replace, desc) in BOOL_PATCHES {
        // 2-byte patterns only on small packets (<150 bytes)
        if search.len() <= 2 && psize >= 150 {
            continue;
        }
        let count = replace_all(buf, search, replace);
        for _ in 0..count {
            applied.push(desc.to_string());
        }
    }
    applied
}

// ═══════════════════════════════════════════════════════════════
//  INBOUND F25 PATCH (PC icon removal)
// ═══════════════════════════════════════════════════════════════

/// Apply the ONLY inbound patch: F25 is_emulator (hides PC icon).
/// Replaces 0xC8 0x01 {0x01|0x02|0x03} → 0xC8 0x01 0x00
pub fn apply_inbound_f25(buf: &mut Vec<u8>) -> bool {
    let mut patched = false;
    let mut i = 0usize;
    while i + 3 <= buf.len() {
        if buf[i] == 0xC8 && buf[i + 1] == 0x01 && matches!(buf[i + 2], 0x01 | 0x02 | 0x03) {
            buf[i + 2] = 0x00;
            patched = true;
            i += 3;
        } else {
            i += 1;
        }
    }
    patched
}

// ═══════════════════════════════════════════════════════════════
//  UNIFIED PATCH ENTRY POINT
// ═══════════════════════════════════════════════════════════════

/// Apply appropriate patches to `data` according to direction and protocol.
///
/// Returns a list of patch descriptions that were applied (empty = not patched).
pub fn patch_emulator_flags(
    data: &mut Vec<u8>,
    is_outbound: bool,
    is_tcp: bool,
) -> Vec<String> {
    if data.len() < 2 {
        return vec![];
    }

    if is_tls_or_dtls(data) {
        return vec![];
    }

    let psize = data.len();
    let mut applied = Vec::new();

    if is_outbound {
        // ═══ OUTBOUND: scrub what WE send to server ═══
        if is_tcp {
            // Binary bool patches — TCP only, never UDP
            applied.extend(apply_bool_patches(data, psize));
        }
        // String patches — safe on both TCP and UDP
        applied.extend(apply_string_patches(data));
    } else if is_tcp {
        // ═══ INBOUND TCP: ONLY remove PC icon (F25) ═══
        if apply_inbound_f25(data) {
            applied.push("F25 is_emulator (PC icon removed)".to_string());
        }
        // INBOUND UDP: NEVER touched (match data)
    }

    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_detection() {
        // TLS 1.2 ApplicationData
        assert!(is_tls_or_dtls(&[0x17, 0x03, 0x03, 0x00, 0x10]));
        // DTLS 1.2
        assert!(is_tls_or_dtls(&[0x16, 0xFE, 0xFD, 0x00, 0x10]));
        // Normal game packet
        assert!(!is_tls_or_dtls(&[0x08, 0x01, 0xAB, 0xCD, 0x00]));
    }

    #[test]
    fn f25_patch() {
        let mut data = vec![0xC8, 0x01, 0x02, 0xC8, 0x01, 0x01, 0xFF];
        apply_inbound_f25(&mut data);
        assert_eq!(data, vec![0xC8, 0x01, 0x00, 0xC8, 0x01, 0x00, 0xFF]);
    }

    #[test]
    fn string_patch() {
        let mut data = b"is_emulator=1 test".to_vec();
        let applied = apply_string_patches(&mut data);
        assert!(!applied.is_empty());
        assert_eq!(&data[..13], b"is_emulator=0");
    }

    #[test]
    fn outbound_tcp_patches() {
        // Small packet with bool flag
        let mut data = vec![0xb0, 0x01, 0x01, 0x00, 0x00];
        let applied = patch_emulator_flags(&mut data, true, true);
        assert!(applied.iter().any(|s| s.contains("F22")));
        assert_eq!(data[2], 0x00);
    }
}
