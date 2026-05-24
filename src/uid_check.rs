//! uid_check.rs — UID whitelist validation, remote server sync, and geo-lookup.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::config::UID_SERVERS;
use crate::db;

pub type Db = Arc<Mutex<rusqlite::Connection>>;

// ═══════════════════════════════════════════════════════════════
//  UID EXISTENCE CHECK (mirrors Python checkUIDExists)
// ═══════════════════════════════════════════════════════════════

/// Check if a UID is authorized.
///
/// Priority:
/// 1. Whitelist table (local SQLite override)
/// 2. uid_cache from remote server sync
/// 3. Blacklist → block regardless
pub fn check_uid_exists(db: &rusqlite::Connection, uid: &str) -> bool {
    let uid = uid.trim();
    info!("[WHITELIST CHECK] Checking UID: {uid}");

    // Whitelisted locally → always allow
    if db::get_whitelist_region(db, uid).is_some() {
        info!("[WHITELIST CHECK] Found in local whitelist");
        return true;
    }

    // In uid_cache from an active server → allow
    if db::is_uid_in_cache(db, uid) {
        info!("[WHITELIST CHECK] Found in uid_cache");
        return true;
    }

    info!("[WHITELIST CHECK] UID {uid} NOT FOUND");
    false
}

// ═══════════════════════════════════════════════════════════════
//  REMOTE UID SERVER FETCH
// ═══════════════════════════════════════════════════════════════

/// Fetch UIDs from a remote URL and sync to SQLite.  
/// Returns the set of valid UIDs, or `None` if the server is down.
pub async fn fetch_uids(
    client: &reqwest::Client,
    db: Db,
    server_name: &str,
    url: &str,
) -> Option<HashSet<String>> {
    let text = match client.get(url).timeout(std::time::Duration::from_secs(10)).send().await {
        Ok(resp) if resp.status().is_success() => {
            resp.text().await.ok()?
        }
        Ok(resp) => {
            warn!("[UID SERVER] {server_name} returned HTTP {}", resp.status());
            return None;
        }
        Err(e) => {
            warn!("[UID SERVER] {server_name} DOWN: {e}");
            return None;
        }
    };

    // Parse: one UID per line, digits only
    let uids: HashSet<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
        .map(|s| s.to_string())
        .collect();

    let now = now_secs();
    let uid_vec: Vec<String> = uids.iter().cloned().collect();

    // Sync to SQLite
    {
        let locked = db.lock().unwrap();
        // Delete removed UIDs
        let _ = db::prune_uid_cache_for_server(&locked, server_name, &uid_vec);
        // Upsert active UIDs
        for uid in &uids {
            let _ = db::upsert_uid_cache(&locked, server_name, uid, now);
        }
        // TTL cleanup
        let _ = db::prune_expired_uid_cache(&locked);
    }

    info!("[UID SERVER] {server_name} OK — {} UIDs", uids.len());
    Some(uids)
}

/// Sync all configured UID servers in parallel.
pub async fn sync_all_servers(client: &reqwest::Client, db: Db) {
    let mut handles = vec![];

    for &(name, url) in UID_SERVERS {
        let client = client.clone();
        let db = db.clone();
        let name = name.to_string();
        let url = url.to_string();

        handles.push(tokio::spawn(async move {
            fetch_uids(&client, db, &name, &url).await
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
}

// ═══════════════════════════════════════════════════════════════
//  GEO LOOKUP
// ═══════════════════════════════════════════════════════════════

/// Look up the geographic location of an IP address via ip-api.com.
/// Returns (country, region, city).
pub async fn lookup_geo(
    client: &reqwest::Client,
    ip: &str,
) -> (Option<String>, Option<String>, Option<String>) {
    if ip.is_empty() || ip == "127.0.0.1" || ip.starts_with("10.") || ip.starts_with("192.168.") {
        return (None, None, None);
    }
    let url = format!("http://ip-api.com/json/{ip}");
    match client.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let country = json["country"].as_str().map(String::from);
                let region  = json["regionName"].as_str().map(String::from);
                let city    = json["city"].as_str().map(String::from);
                return (country, region, city);
            }
        }
        _ => {}
    }
    (None, None, None)
}

// ═══════════════════════════════════════════════════════════════
//  BACKGROUND SYNC LOOP
// ═══════════════════════════════════════════════════════════════

/// Continuously sync UIDs from remote servers every `CHECK_INTERVAL_SECS`.
pub async fn uid_sync_loop(client: reqwest::Client, db: Db) {
    loop {
        sync_all_servers(&client, db.clone()).await;
        tokio::time::sleep(tokio::time::Duration::from_secs(crate::config::CHECK_INTERVAL_SECS)).await;
    }
}

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
