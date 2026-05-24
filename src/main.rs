//! main.rs — Xenitronix Bypass v9.1 (Rust)
//!
//! ═══════════════════════════════════════════════════════════════════
//!     XENITRONIX BYPASS v9.1 - IN-GAME + MITM PROTECTION (Rust)
//!     Created by: Dev SAHIL
//!
//!     PURPOSE: Replaces both pydivert (in-game) AND mitmproxy (lobby)
//!              in a single Rust binary. Zero Python runtime required.
//!
//!     COMPONENTS:
//!       1. HTTP CONNECT Proxy (port 8082) — MajorLogin/GetLoginData intercept
//!       2. WinDivert Loop               — in-game packet patching (Windows)
//!       3. UID Sync Loop                — remote whitelist sync
//!       4. Discord Bot                  — admin control panel
//! ═══════════════════════════════════════════════════════════════════

mod config;
mod crypto;
mod db;
mod discord_bot;
mod mitm;
mod patcher;
mod protobuf;
mod tls_intercept;
mod uid_blocking;
mod uid_check;
mod windivert;

use std::sync::{Arc, Mutex};
use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // ─── Logging ───────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    // ─── Load .env ─────────────────────────────────────────────
    dotenvy::dotenv().ok();
    let discord_token = std::env::var("DISCORD_TOKEN").unwrap_or_default();

    // ─── Banner ────────────────────────────────────────────────
    println!();
    println!("{}",  "═".repeat(62));
    println!("   Xenitronix BYPASS v9.1 - Rust Edition");
    println!("{}",  "═".repeat(62));
    println!();
    println!("  SAFETY:");
    println!("   [+] Outbound TCP   : full emulator flag scrubbing");
    println!("   [+] Outbound UDP   : string patches only");
    println!("   [+] Inbound  TCP   : ONLY PC icon removal (F25)");
    println!("   [+] Inbound  UDP   : NEVER touched (match data)");
    println!("   [+] TLS interception: active (mitmproxy CA)");
    println!("   [+] 2-byte patches : only on packets <150 bytes");
    println!();
    println!("  PROXY  : 0.0.0.0:{} (HTTPS MITM)", config::PROXY_PORT);
    println!("  CERT   : mitmproxy-ca.pem (same dir as .exe)");
    println!();

    // ─── SQLite ────────────────────────────────────────────────
    let raw_db = rusqlite::Connection::open(config::DB_FILE)?;
    db::init_schema(&raw_db)?;
    let shared_db: uid_check::Db = Arc::new(Mutex::new(raw_db));

    // ─── HTTP Client (shared across tasks) ────────────────────
    let http_client = reqwest::Client::builder()
        .user_agent("Xenitronix/9.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // ─── 1. WinDivert (Windows in-game protection) ────────────
    // WinDivert driver init + filter parsing is stack-heavy.
    // Default 2MB stack overflows → give it 8MB.
    let wd_stats = windivert::new_stats();
    let wd_stats_thread = wd_stats.clone();
    std::thread::Builder::new()
        .name("windivert".into())
        .stack_size(8 * 1024 * 1024) // 8 MB — prevents STATUS_STACK_OVERFLOW
        .spawn(move || {
            windivert::run_windivert_bypass(wd_stats_thread);
        })?;

    // ─── 2. UID Sync Loop ─────────────────────────────────────
    {
        let db = shared_db.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            uid_check::uid_sync_loop(client, db).await;
        });
    }

    // ─── 3. Discord Bot ───────────────────────────────────────
    if !discord_token.is_empty() {
        let db = shared_db.clone();
        let client = http_client.clone();
        let token = discord_token.clone();
        tokio::spawn(async move {
            discord_bot::run_discord_bot(token, db, client).await;
        });
    } else {
        info!("[Bot] DISCORD_TOKEN not set — Discord bot disabled");
    }

    // ─── 4. MITM Proxy (main task, blocks until Ctrl+C) ───────
    println!("  ┌─────────────────────────────────────────────┐");
    println!("  │  1. Set your game proxy: 127.0.0.1:{}    │", config::PROXY_PORT);
    println!("  │  2. Wait for 'Intercepting...' below        │");
    println!("  │  3. THEN open the game                      │");
    println!("  │  4. Press Ctrl+C to stop                    │");
    println!("  └─────────────────────────────────────────────┘");
    println!();

    // Check if port is already in use
    if std::net::TcpListener::bind(format!("127.0.0.1:{}", config::PROXY_PORT)).is_err() {
        error!("[!] ERROR: Port {} is already in use! Close other proxies.", config::PROXY_PORT);
        std::process::exit(1);
    }

    // Run proxy (awaits Ctrl+C internally via select)
    let proxy_db = shared_db.clone();
    let proxy_client = http_client.clone();

    let _proxy_handle = tokio::spawn(async move {
        mitm::run_proxy(proxy_db, proxy_client).await;
    });

    // Wait for Ctrl+C
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            println!();
            println!("{}", "═".repeat(62));
            println!("  SESSION SUMMARY");
            println!("{}", "═".repeat(62));
            let s = wd_stats.lock().unwrap();
            println!("  WinDivert Packets : {}", s.total);
            println!("  TCP               : {}", s.tcp);
            println!("  UDP               : {}", s.udp);
            println!("  Patched           : {}", s.patched);
            println!("  Blocked (UID)     : {}", s.blocked);
            println!("{}", "═".repeat(62));
            println!("  Bypass stopped cleanly.");
        }
        Err(e) => error!("Failed to listen for Ctrl+C: {e}"),
    }

    Ok(())
}
