//! mitm/stream_patch.rs — Raw TCP/UDP stream patching (xenitronix class equivalent).
//!
//! Mirrors Python xenitronix.tcp_message() and xenitronix.udp_message().

use crate::patcher::{apply_bool_patches, apply_inbound_f25, apply_string_patches, is_tls_or_dtls};

// ═══════════════════════════════════════════════════════════════
//  TCP STREAM PATCHING
// ═══════════════════════════════════════════════════════════════

/// Patch a raw TCP stream chunk.
///
/// - `from_client = true`:  OUTBOUND — bool + string patches
/// - `from_client = false`: INBOUND  — ONLY F25 PC icon removal
///
/// Returns true if any modification was made.
pub fn patch_tcp_message(data: &mut Vec<u8>, from_client: bool) -> bool {
    if data.len() < 2 {
        return false;
    }
    if is_tls_or_dtls(data) {
        return false;
    }

    let psize = data.len();

    if from_client {
        // OUTBOUND: binary + string patches
        let bool_applied = apply_bool_patches(data, psize);
        let str_applied = apply_string_patches(data);
        !bool_applied.is_empty() || !str_applied.is_empty()
    } else {
        // INBOUND: ONLY F25
        apply_inbound_f25(data)
    }
}

// ═══════════════════════════════════════════════════════════════
//  UDP STREAM PATCHING
// ═══════════════════════════════════════════════════════════════

/// Patch a raw UDP datagram.
///
/// - `from_client = true`:  OUTBOUND — string patches ONLY (never binary on UDP)
/// - `from_client = false`: INBOUND  — NEVER touched (match data)
///
/// Returns true if any modification was made.
pub fn patch_udp_message(data: &mut Vec<u8>, from_client: bool) -> bool {
    if !from_client {
        // INBOUND UDP: never touched
        return false;
    }
    if data.len() < 2 {
        return false;
    }
    if is_tls_or_dtls(data) {
        return false;
    }
    // OUTBOUND UDP: string patches only
    let applied = apply_string_patches(data);
    !applied.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_outbound_patches_bool_and_string() {
        // Small packet (<150 bytes) with a 2-byte bool pattern and a string pattern
        let mut data = b"\xb0\x01\x01is_emulator=1 filler".to_vec();
        let modified = patch_tcp_message(&mut data, true);
        assert!(modified);
        // Bool patch applied: 0x01 → 0x00
        assert_eq!(data[2], 0x00);
        // String patch applied
        assert_eq!(&data[3..16], b"is_emulator=0");
    }

    #[test]
    fn tcp_inbound_only_f25() {
        // Inbound should only patch F25, not string patterns
        let mut data = b"\xc8\x01\x02is_emulator=1".to_vec();
        patch_tcp_message(&mut data, false);
        assert_eq!(data[2], 0x00); // F25 patched
        assert_eq!(&data[3..16], b"is_emulator=1"); // string NOT patched
    }

    #[test]
    fn udp_inbound_never_touched() {
        let original = b"\xc8\x01\x01is_emulator=1".to_vec();
        let mut data = original.clone();
        let modified = patch_udp_message(&mut data, false);
        assert!(!modified);
        assert_eq!(data, original);
    }

    #[test]
    fn udp_outbound_string_only() {
        let mut data = b"is_emulator=1 \xb0\x01\x01".to_vec();
        patch_udp_message(&mut data, true);
        assert_eq!(&data[..13], b"is_emulator=0");
        // Bool pattern NOT patched on UDP — entire 3-byte sequence untouched
        assert_eq!(&data[14..17], &[0xb0, 0x01, 0x01]);
    }
}
