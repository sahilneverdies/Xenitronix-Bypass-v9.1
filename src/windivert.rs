//! windivert.rs — WinDivert packet-level bypass (Windows only).
//!
//! Mirrors Python run_windivert_bypass() + handle_uid_blocking() exactly.
//! Runs in a dedicated OS thread (WinDivert API is blocking).
//!
//! SAFETY RULES (same as Python):
//!   OUTBOUND TCP:  BOOL_PATCHES + STRING_PATCHES
//!   OUTBOUND UDP:  STRING_PATCHES only
//!   INBOUND  TCP:  ONLY F25
//!   INBOUND  UDP:  NEVER touched
//!
//! UID BLOCKING (local, packet-level):
//!   If outbound packet contains "majorlogin", extract UID from
//!   AES-encrypted protobuf and validate against VPS whitelist.
//!   Unauthorized UIDs → packet DROPPED (login blocked).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::config::WINDIVERT_FILTER;
use crate::patcher::patch_emulator_flags;
use crate::uid_blocking::{UidCache, handle_uid_blocking};

// ═══════════════════════════════════════════════════════════════
//  STATS
// ═══════════════════════════════════════════════════════════════

#[derive(Default, Debug)]
pub struct WinDivertStats {
    pub total: u64,
    pub tcp: u64,
    pub udp: u64,
    pub patched: u64,
    pub blocked: u64,
}

pub type SharedStats = Arc<Mutex<WinDivertStats>>;

pub fn new_stats() -> SharedStats {
    Arc::new(Mutex::new(WinDivertStats::default()))
}

// ═══════════════════════════════════════════════════════════════
//  WINDOWS IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
pub fn run_windivert_bypass(stats: SharedStats) {
    use windivert::{WinDivert, WinDivertFlags, WinDivertLayer};
    use chrono::Local;

    // Stealth console title via libloading
    {
        unsafe {
            let title: Vec<u16> = "Service Host: Local System (Network Restricted)\0"
                .encode_utf16()
                .collect();
            if let Ok(lib) = libloading::Library::new("kernel32.dll") {
                type Fn = unsafe extern "system" fn(*const u16) -> i32;
                if let Ok(f) = lib.get::<Fn>(b"SetConsoleTitleW\0") {
                    f(title.as_ptr());
                }
            }
        }
    }

    info!("[WD] Opening WinDivert handle with filter...");

    let handle = match WinDivert::new(
        WINDIVERT_FILTER,
        WinDivertLayer::Network,
        0,
        WinDivertFlags::default(),
    ) {
        Ok(h) => h,
        Err(e) => {
            error!("[WD] Failed to open WinDivert handle: {e:?}");
            error!("[WD] Ensure WinDivert64.sys is accessible and run as Administrator.");
            return;
        }
    };

    info!("[WD] Intercepting game traffic (In-Game Protection active)");
    info!("[WD] Outbound: full patches | Inbound: PC icon only");

    let mut last_hb = Instant::now();
    let heartbeat_interval = Duration::from_secs(30);

    // UID cache — refreshes from VPS every 60 seconds
    let mut uid_cache = UidCache::new();

    loop {
        let mut packet = match handle.recv(65535) {
            Ok(p) => p,
            Err(e) => {
                warn!("[WD] Recv error: {e:?}");
                continue;
            }
        };

        // Parse to get outbound/protocol info
        let parsed = packet.parse_slice();
        let (is_outbound, is_tcp) = match &parsed {
            windivert::WinDivertParsedSlice::Network { addr, data } => {
                let out = addr.outbound();
                // IP protocol at byte 9 (IPv4) or byte 6 (IPv6 next-header)
                let tcp = data.get(9).map(|&b| b == 6).unwrap_or(false)
                    || data.get(6).map(|&b| b == 6).unwrap_or(false);
                (out, tcp)
            }
            _ => (false, false),
        };
        drop(parsed);

        {
            let mut s = stats.lock().unwrap();
            s.total += 1;
            if is_tcp { s.tcp += 1; } else { s.udp += 1; }
        }

        if packet.data.len() >= 2 {
            // ═════ UID CHECK (packet-level, mirrors Python handle_uid_blocking) ═════
            if !handle_uid_blocking(&packet.data, &mut uid_cache) {
                // DROP — unauthorized UID login attempt
                let mut s = stats.lock().unwrap();
                s.blocked += 1;
                continue; // Don't re-inject this packet
            }

            // ═════ EMULATOR FLAG PATCHING ═════
            let mut data = packet.data.clone();
            let applied = patch_emulator_flags(&mut data, is_outbound, is_tcp);

            if !applied.is_empty() {
                let patch_count = applied.len() as u64;
                packet.data = data;

                let total_patched = {
                    let mut s = stats.lock().unwrap();
                    s.patched += patch_count;
                    s.patched
                };

                let ts = Local::now().format("%H:%M:%S");
                let dir = if is_outbound { "OUT" } else { "IN " };
                let proto = if is_tcp { "TCP" } else { "UDP" };
                info!("[WD] [{ts}] [{dir}|{proto}] +{patch_count} patches | Total: {total_patched}");
            }
        }

        // Re-inject packet (checksums recalculated by WinDivert)
        if let Err(e) = handle.send(packet) {
            let msg = format!("{e:?}");
            if !msg.contains("87") && !msg.contains("InvalidParameter") {
                warn!("[WD] Send error: {e:?}");
            }
        }

        // Heartbeat every 30 seconds
        if last_hb.elapsed() >= heartbeat_interval {
            let s = stats.lock().unwrap();
            let ts = Local::now().format("%H:%M:%S");
            info!(
                "[WD] [{ts}] heartbeat: pkts={} tcp={} udp={} patched={} blocked={}",
                s.total, s.tcp, s.udp, s.patched, s.blocked
            );
            drop(s);
            last_hb = Instant::now();
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  NON-WINDOWS STUB
// ═══════════════════════════════════════════════════════════════

#[cfg(not(target_os = "windows"))]
pub fn run_windivert_bypass(_stats: SharedStats) {
    tracing::info!("[WD] WinDivert is Windows-only. In-game protection runs via MITM stream patching.");
}
