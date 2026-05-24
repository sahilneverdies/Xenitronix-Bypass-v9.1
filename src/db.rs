//! db.rs — SQLite schema initialization and low-level helpers.

use rusqlite::{Connection, Result as SqlResult, params};
use anyhow::Result;

use crate::config::{UID_SERVERS, UID_TTL_SECONDS};

/// Initialize all tables and insert default rows.
pub fn init_schema(db: &Connection) -> Result<()> {
    db.execute_batch("
        CREATE TABLE IF NOT EXISTS whitelist (
            uid TEXT PRIMARY KEY,
            region TEXT DEFAULT 'GLOBAL'
        );

        CREATE TABLE IF NOT EXISTS blacklist (
            uid TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS uid_cache (
            server_name TEXT,
            uid TEXT,
            last_seen INTEGER,
            PRIMARY KEY (server_name, uid)
        );

        CREATE TABLE IF NOT EXISTS server_rules (
            server_name TEXT PRIMARY KEY,
            mode TEXT
        );

        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT,
            ip TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            ts INTEGER,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS admins (
            user_id INTEGER PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS stats (
            key TEXT PRIMARY KEY,
            value INTEGER
        );
    ")?;

    // Add region column if missing (migration safety)
    let _ = db.execute("ALTER TABLE whitelist ADD COLUMN region TEXT DEFAULT 'GLOBAL'", []);

    // Initialize stats counters
    for key in &["total", "allowed", "blocked"] {
        db.execute(
            "INSERT OR IGNORE INTO stats (key, value) VALUES (?1, 0)",
            params![key],
        )?;
    }

    // Initialize server rules
    for &(name, _url) in UID_SERVERS {
        db.execute(
            "INSERT OR IGNORE INTO server_rules (server_name, mode) VALUES (?1, 'on')",
            params![name],
        )?;
    }

    Ok(())
}

/// Increment a named stat counter.
pub fn inc_stat(db: &Connection, name: &str) -> SqlResult<()> {
    db.execute(
        "UPDATE stats SET value = value + 1 WHERE key = ?1",
        params![name],
    )?;
    Ok(())
}

/// Retrieve all stats as a (key, value) map.
pub fn get_stats(db: &Connection) -> SqlResult<std::collections::HashMap<String, i64>> {
    let mut stmt = db.prepare("SELECT key, value FROM stats")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut map = std::collections::HashMap::new();
    for row in rows {
        let (k, v) = row?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Log a login attempt to the database.
pub fn log_login(
    db: &Connection,
    uid: &str,
    ip: Option<&str>,
    country: Option<&str>,
    region: Option<&str>,
    city: Option<&str>,
    status: &str,
) -> SqlResult<()> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    db.execute(
        "INSERT INTO login_logs (uid, ip, country, region, city, ts, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![uid, ip, country, region, city, ts, status],
    )?;
    Ok(())
}

/// Check if UID is blacklisted.
pub fn is_blacklisted(db: &Connection, uid: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM blacklist WHERE uid = ?1",
        params![uid],
        |_| Ok(true),
    )
    .unwrap_or(false)
}

/// Check if UID is whitelisted (returns region if found).
pub fn get_whitelist_region(db: &Connection, uid: &str) -> Option<String> {
    db.query_row(
        "SELECT region FROM whitelist WHERE uid = ?1",
        params![uid],
        |row| row.get(0),
    )
    .ok()
}

/// Check if UID is in uid_cache from an active server.
pub fn is_uid_in_cache(db: &Connection, uid: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let cutoff = now - UID_TTL_SECONDS;
    db.query_row(
        "SELECT 1 FROM uid_cache uc
         JOIN server_rules sr ON uc.server_name = sr.server_name
         WHERE uc.uid = ?1 AND uc.last_seen >= ?2 AND sr.mode = 'on'
         LIMIT 1",
        params![uid, cutoff],
        |_| Ok(true),
    )
    .unwrap_or(false)
}

/// Upsert a UID into uid_cache.
pub fn upsert_uid_cache(db: &Connection, server_name: &str, uid: &str, now: i64) -> SqlResult<()> {
    db.execute(
        "INSERT OR REPLACE INTO uid_cache (server_name, uid, last_seen) VALUES (?1, ?2, ?3)",
        params![server_name, uid, now],
    )?;
    Ok(())
}

/// Delete UIDs from cache that are no longer on a server's fresh list.
pub fn prune_uid_cache_for_server(db: &Connection, server_name: &str, active_uids: &[String]) -> SqlResult<()> {
    if active_uids.is_empty() {
        db.execute("DELETE FROM uid_cache WHERE server_name = ?1", params![server_name])?;
    } else {
        // Build parameterized NOT IN clause
        let placeholders: Vec<String> = active_uids.iter().enumerate()
            .map(|(i, _)| format!("?{}", i + 2))
            .collect();
        let sql = format!(
            "DELETE FROM uid_cache WHERE server_name = ?1 AND uid NOT IN ({})",
            placeholders.join(",")
        );
        let mut stmt = db.prepare(&sql)?;
        let mut values: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(server_name.to_string())];
        for uid in active_uids {
            values.push(Box::new(uid.clone()));
        }
        stmt.execute(rusqlite::params_from_iter(values.iter().map(|v| v.as_ref())))?;
    }
    Ok(())
}

/// Delete uid_cache rows older than UID_TTL_SECONDS.
pub fn prune_expired_uid_cache(db: &Connection) -> SqlResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let cutoff = now - UID_TTL_SECONDS;
    db.execute("DELETE FROM uid_cache WHERE last_seen < ?1", params![cutoff])?;
    Ok(())
}

/// Check if user_id is an admin.
pub fn is_admin(db: &Connection, user_id: i64, owner_id: u64) -> bool {
    if user_id as u64 == owner_id {
        return true;
    }
    db.query_row(
        "SELECT 1 FROM admins WHERE user_id = ?1",
        params![user_id],
        |_| Ok(true),
    )
    .unwrap_or(false)
}
