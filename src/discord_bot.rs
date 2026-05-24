//! discord_bot.rs — Serenity Discord bot with slash commands + live dashboard.
//!
//! Mirrors all Python discord.py bot functionality:
//!   /uid /stats /block /whitelist /blacklist
//!   /addadmin /removeadmin /setservermode /syncuids
//!   Dashboard embed updated every 10 seconds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serenity::all::{
    ChannelId, Client, Context, CreateEmbed, CreateEmbedFooter, CreateMessage,
    EditMessage, EventHandler, GatewayIntents, GuildId, Interaction, Ready,
};
use serenity::async_trait;
use serenity::builder::{
    CreateInteractionResponse, CreateInteractionResponseMessage,
};
use serenity::model::application::Command;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use crate::config::{LOGIN_LOG_CHANNEL_ID, OWNER_USER_ID, UID_SERVERS};
use crate::db;
use crate::uid_check::{sync_all_servers, Db};

// ═══════════════════════════════════════════════════════════════
//  BOT HANDLER
// ═══════════════════════════════════════════════════════════════

pub struct BotHandler {
    pub db: Db,
    pub http_client: reqwest::Client,
    /// dashboard message ID per guild
    pub dashboard_msgs: Arc<Mutex<HashMap<GuildId, serenity::model::id::MessageId>>>,
}

#[async_trait]
impl EventHandler for BotHandler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!("[Discord] Logged in as {}", ready.user.name);

        // Register global slash commands
        if let Err(e) = register_commands(&ctx).await {
            error!("[Discord] Failed to register commands: {e}");
        }

        // Spawn dashboard + monitor loops
        let db = self.db.clone();
        let http_client = self.http_client.clone();
        let dashboard_msgs = self.dashboard_msgs.clone();
        let ctx_arc = Arc::new(ctx.clone());

        tokio::spawn(dashboard_loop(ctx_arc.clone(), db.clone(), dashboard_msgs));
        tokio::spawn(uid_sync_task(db, http_client));
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        if let Interaction::Command(cmd) = interaction {
            let user_id = cmd.user.id.get() as i64;

            // All DB access is done synchronously before any .await
            // to avoid holding MutexGuard across await points.
            let content: String = {
                let locked = self.db.lock().unwrap();
                let admin = db::is_admin(&locked, user_id, OWNER_USER_ID);

                match cmd.data.name.as_str() {
                    "uid" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            let uid = get_str_option(&cmd, "uid");
                            let exists = crate::uid_check::check_uid_exists(&locked, &uid);
                            if exists { format!("✅ UID FOUND: `{uid}`") } else { format!("❌ UID NOT FOUND: `{uid}`") }
                        }
                    }
                    "stats" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            let s = db::get_stats(&locked).unwrap_or_default();
                            format!(
                                "📊 **Bypass Dashboard**\n━━━━━━━━━━━━━━\n\
                                 📥 Total  : `{}`\n\
                                 ✅ Allowed: `{}`\n\
                                 ❌ Blocked: `{}`",
                                s.get("total").unwrap_or(&0),
                                s.get("allowed").unwrap_or(&0),
                                s.get("blocked").unwrap_or(&0),
                            )
                        }
                    }
                    "block" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            let mode = get_str_option(&cmd, "mode");
                            let val: i64 = if mode.to_lowercase() == "on" { 1 } else { 0 };
                            let _ = locked.execute(
                                "INSERT OR REPLACE INTO stats (key, value) VALUES ('block_enabled', ?1)",
                                rusqlite::params![val],
                            );
                            if val == 1 { "Blocking ✅ ON".into() } else { "Blocking ❌ OFF".into() }
                        }
                    }
                    "whitelist" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            let action = get_str_option(&cmd, "action");
                            let uid = get_str_option(&cmd, "uid");
                            let region = get_str_option_default(&cmd, "region", "IND");
                            if action == "add" {
                                let _ = locked.execute(
                                    "INSERT OR REPLACE INTO whitelist (uid, region) VALUES (?1, ?2)",
                                    rusqlite::params![uid, region],
                                );
                                format!("✅ Whitelist updated for `{uid}` (Region: {region})")
                            } else {
                                let _ = locked.execute("DELETE FROM whitelist WHERE uid=?1", rusqlite::params![uid]);
                                format!("✅ `{uid}` removed from whitelist")
                            }
                        }
                    }
                    "blacklist" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            let action = get_str_option(&cmd, "action");
                            let uid = get_str_option(&cmd, "uid");
                            if action == "add" {
                                let _ = locked.execute("INSERT OR IGNORE INTO blacklist VALUES (?1)", rusqlite::params![uid]);
                            } else {
                                let _ = locked.execute("DELETE FROM blacklist WHERE uid=?1", rusqlite::params![uid]);
                            }
                            "✅ Blacklist updated".into()
                        }
                    }
                    "addadmin" => {
                        if cmd.user.id.get() != OWNER_USER_ID { "❌ Owner only".into() }
                        else {
                            let target_id = get_i64_option(&cmd, "user_id");
                            let _ = locked.execute("INSERT OR IGNORE INTO admins VALUES (?1)", rusqlite::params![target_id]);
                            "✅ Admin added".into()
                        }
                    }
                    "removeadmin" => {
                        if cmd.user.id.get() != OWNER_USER_ID { "❌ Owner only".into() }
                        else {
                            let target_id = get_i64_option(&cmd, "user_id");
                            let _ = locked.execute("DELETE FROM admins WHERE user_id=?1", rusqlite::params![target_id]);
                            "✅ Admin removed".into()
                        }
                    }
                    "setservermode" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            let server_name = get_str_option(&cmd, "server_name");
                            let mode = get_str_option(&cmd, "mode");
                            let valid = UID_SERVERS.iter().any(|&(n, _)| n == server_name);
                            if !valid {
                                "❌ Unknown server name".into()
                            } else if mode != "on" && mode != "off" {
                                "❌ Mode must be on/off".into()
                            } else {
                                let _ = locked.execute(
                                    "UPDATE server_rules SET mode=?1 WHERE server_name=?2",
                                    rusqlite::params![mode, server_name],
                                );
                                format!("✅ {server_name} set to {mode}")
                            }
                        }
                    }
                    "syncuids" => {
                        if !admin { "❌ No permission".into() }
                        else {
                            // Spawn sync — db lock is dropped before the spawn body runs
                            drop(locked);
                            let db = self.db.clone();
                            let client = self.http_client.clone();
                            tokio::spawn(async move { sync_all_servers(&client, db).await; });
                            "✅ UID servers syncing...".into()
                        }
                    }
                    _ => "❌ Unknown command".into(),
                }
            }; // MutexGuard dropped here — safe to .await now

            let resp = CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .content(content)
                    .ephemeral(true),
            );
            if let Err(e) = cmd.create_response(&ctx.http, resp).await {
                warn!("[Discord] Response error: {e}");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  SLASH COMMAND REGISTRATION
// ═══════════════════════════════════════════════════════════════

async fn register_commands(ctx: &Context) -> serenity::Result<()> {
    use serenity::builder::CreateCommand;
    use serenity::model::application::CommandOptionType;
    use serenity::builder::CreateCommandOption;

    let commands = vec![
        CreateCommand::new("uid").description("Check if UID exists")
            .add_option(CreateCommandOption::new(CommandOptionType::String, "uid", "UID to check").required(true)),
        CreateCommand::new("stats").description("Show bypass stats"),
        CreateCommand::new("block").description("Enable or disable blocking")
            .add_option(CreateCommandOption::new(CommandOptionType::String, "mode", "on or off").required(true)),
        CreateCommand::new("whitelist").description("Manage whitelist (add/remove)")
            .add_option(CreateCommandOption::new(CommandOptionType::String, "action", "add or remove").required(true))
            .add_option(CreateCommandOption::new(CommandOptionType::String, "uid", "UID").required(true))
            .add_option(CreateCommandOption::new(CommandOptionType::String, "region", "Region (default: IND)").required(false)),
        CreateCommand::new("blacklist").description("Manage blacklist")
            .add_option(CreateCommandOption::new(CommandOptionType::String, "action", "add or remove").required(true))
            .add_option(CreateCommandOption::new(CommandOptionType::String, "uid", "UID").required(true)),
        CreateCommand::new("addadmin").description("Add admin (owner only)")
            .add_option(CreateCommandOption::new(CommandOptionType::Integer, "user_id", "Discord user ID").required(true)),
        CreateCommand::new("removeadmin").description("Remove admin (owner only)")
            .add_option(CreateCommandOption::new(CommandOptionType::Integer, "user_id", "Discord user ID").required(true)),
        CreateCommand::new("setservermode").description("Enable/disable UID server")
            .add_option(CreateCommandOption::new(CommandOptionType::String, "server_name", "Server name").required(true))
            .add_option(CreateCommandOption::new(CommandOptionType::String, "mode", "on or off").required(true)),
        CreateCommand::new("syncuids").description("Force UID server sync"),
    ];

    Command::set_global_commands(&ctx.http, commands).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  DASHBOARD LOOP
// ═══════════════════════════════════════════════════════════════

async fn dashboard_loop(
    ctx: Arc<Context>,
    db: Db,
    dashboard_msgs: Arc<Mutex<HashMap<GuildId, serenity::model::id::MessageId>>>,
) {
    let mut ticker = interval(Duration::from_secs(10));
    loop {
        ticker.tick().await;

        let (stats, server_states) = {
            let locked = db.lock().unwrap();
            let s = db::get_stats(&locked).unwrap_or_default();
            // Count UIDs per server from uid_cache
            let mut srv: Vec<(String, i64)> = vec![];
            for &(name, _) in UID_SERVERS {
                let count: i64 = locked
                    .query_row(
                        "SELECT COUNT(*) FROM uid_cache WHERE server_name = ?1",
                        rusqlite::params![name],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                srv.push((name.to_string(), count));
            }
            (s, srv)
        };

        let embed = CreateEmbed::new()
            .title("🟥 UID BYPASS CONTROL PANEL")
            .color(0xE10600)
            .field(
                "📊 STATISTICS",
                format!(
                    "**Total Requests** ➜ `{}`\n🟢 **Allowed** ➜ `{}`\n🔴 **Blocked** ➜ `{}`",
                    stats.get("total").unwrap_or(&0),
                    stats.get("allowed").unwrap_or(&0),
                    stats.get("blocked").unwrap_or(&0),
                ),
                false,
            )
            .field(
                "🖥 UID SERVERS",
                server_states
                    .iter()
                    .map(|(name, count)| {
                        if *count > 0 {
                            format!("🟢 **{name}** — `{count}` UIDs")
                        } else {
                            format!("🔴 **{name}** — OFFLINE")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
                false,
            )
            .footer(CreateEmbedFooter::new("PRIVATE SYSTEM • REAL-TIME MONITORING"));

        // Send or edit per guild
        let guilds = ctx.cache.guilds();
        for guild_id in guilds {
            let channel_id = ChannelId::new(LOGIN_LOG_CHANNEL_ID);

            let existing_msg_id = dashboard_msgs.lock().unwrap().get(&guild_id).cloned();
            match existing_msg_id {
                Some(msg_id) => {
                    let edit = EditMessage::new().embed(embed.clone());
                    let _ = ctx.http.edit_message(channel_id, msg_id, &edit, vec![]).await;
                }
                None => {
                    if let Ok(msg) = channel_id
                        .send_message(&ctx.http, CreateMessage::new().embed(embed.clone()))
                        .await
                    {
                        dashboard_msgs.lock().unwrap().insert(guild_id, msg.id);
                    }
                }
            }
        }
    }
}

async fn uid_sync_task(db: Db, client: reqwest::Client) {
    crate::uid_check::uid_sync_loop(client, db).await;
}

// ═══════════════════════════════════════════════════════════════
//  COMMAND OPTION HELPERS
// ═══════════════════════════════════════════════════════════════

fn get_str_option(cmd: &serenity::model::application::CommandInteraction, name: &str) -> String {
    cmd.data.options.iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn get_str_option_default(
    cmd: &serenity::model::application::CommandInteraction,
    name: &str,
    default: &str,
) -> String {
    cmd.data.options.iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| default.to_string())
}

fn get_i64_option(cmd: &serenity::model::application::CommandInteraction, name: &str) -> i64 {
    cmd.data.options.iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value.as_i64())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════
//  BOT STARTUP
// ═══════════════════════════════════════════════════════════════

pub async fn run_discord_bot(token: String, db: Db, http_client: reqwest::Client) {
    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_MESSAGES;

    let handler = BotHandler {
        db,
        http_client,
        dashboard_msgs: Arc::new(Mutex::new(HashMap::new())),
    };

    let mut client = match Client::builder(&token, intents)
        .event_handler(handler)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!("[Discord] Failed to create client: {e}");
            return;
        }
    };

    if let Err(e) = client.start().await {
        error!("[Discord] Client error: {e}");
    }
}
