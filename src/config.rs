//! config.rs — All static patch tables, port ranges, and runtime constants.
//!
//! Safety rules (mirrors Python original):
//!   OUTBOUND TCP:  BOOL_PATCHES (3-byte always, 2-byte only on <150 bytes) + STRING_PATCHES
//!   OUTBOUND UDP:  STRING_PATCHES only
//!   INBOUND  TCP:  ONLY F25 is_emulator (PC icon removal)
//!   INBOUND  UDP:  NEVER touched

// ═══════════════════════════════════════════════════════════════
//  EMULATOR DETECTION PATCHES
// ═══════════════════════════════════════════════════════════════

/// Binary bool-flag patches. Each entry: (search_bytes, replace_bytes, description).
/// 2-byte patterns are skipped on packets ≥ 150 bytes.
pub static BOOL_PATCHES: &[(&[u8], &[u8], &str)] = &[
    // MatchmakingSussNtf (CMD 33601)
    (&[0xb0, 0x01, 0x01], &[0xb0, 0x01, 0x00], "MatchmakingSussNtf.is_in_emulator_pool (F22)"),
    (&[0x70, 0x01],       &[0x70, 0x00],        "MatchmakingSussNtf.is_in_special_pool (F14)"),

    // Telemetry / MMTotalTime
    (&[0xd0, 0x03, 0x01], &[0xd0, 0x03, 0x00], "MMTotalTime.is_cs_special_pool (F58)"),

    // GroupInfo / RoomInfo
    (&[0x90, 0x01, 0x01], &[0x90, 0x01, 0x00], "RoomBasicInfo.enable_emulator_check (F18)"),
    (&[0x98, 0x01, 0x01], &[0x98, 0x01, 0x00], "RoomInfo.enable_emulator_check (F19)"),

    // GroupMemberInfo — hides PC icon
    (&[0xc8, 0x01, 0x01], &[0xc8, 0x01, 0x00], "GroupMemberInfo.is_emulator (F25)"),

    // MatchAccountStats
    (&[0xa8, 0x14, 0x01], &[0xa8, 0x14, 0x00], "MatchAccountStats.is_emulator (F325)"),

    // MatchmakingPlayer Flags
    (&[0x48, 0x01], &[0x48, 0x00], "MatchmakingPlayer.emulator_score (F9)"),
    (&[0x68, 0x03], &[0x68, 0x01], "MatchmakingPlayer.plat_id: PC->Android (F13)"),
    (&[0x30, 0x01], &[0x30, 0x00], "MatchmakingPlayer.is_hacker (F6)"),

    // MajorLoginRes
    (&[0x60, 0x01], &[0x60, 0x00], "MajorLoginRes.emulator_score=1->0 (F12)"),
    (&[0x60, 0x02], &[0x60, 0x00], "MajorLoginRes.emulator_score=2->0 (F12)"),
    (&[0x60, 0x03], &[0x60, 0x00], "MajorLoginRes.emulator_score=3->0 (F12)"),

    // Admin & Debug Flags
    (&[0x40, 0x01],       &[0x40, 0x00],       "AdminDebugMatchmaking.is_emulator (F8)"),
    (&[0x60, 0x01],       &[0x60, 0x00],       "EventReport.is_emulator (F12)"),
    (&[0x80, 0x06, 0x01], &[0x80, 0x06, 0x00], "EventReport.is_emulator (F96)"),

    // FFAntiConfig / AntiHack Center Flags
    (&[0x10, 0x01], &[0x10, 0x00], "FFAntiConfig.enable (F2)"),
    (&[0x18, 0x01], &[0x18, 0x00], "FFAntiConfig.hpe_enable (F3)"),
    (&[0x20, 0x01], &[0x20, 0x00], "FFAntiConfig.ffi_enable (F4)"),
    (&[0x28, 0x01], &[0x28, 0x00], "FFAntiConfig.mtp_lite_data_enable (F5)"),
    (&[0x30, 0x01], &[0x30, 0x00], "FFAntiConfig.ffm_enable (F6)"),
    (&[0x38, 0x01], &[0x38, 0x00], "FFAntiConfig.ffo_enable (F7)"),

    // Environment/OS Platform ID
    (&[0x80, 0x01, 0x03], &[0x80, 0x01, 0x01], "system_platform: PC->Android (F16)"),
    (&[0x68, 0x03],       &[0x68, 0x01],       "system_platform: PC->Android (F13)"),
    (&[0x28, 0x03],       &[0x28, 0x01],       "system_platform: PC->Android (F5)"),
    (&[0x20, 0x03],       &[0x20, 0x01],       "system_platform: PC->Android (F4)"),
    (&[0x10, 0x03],       &[0x10, 0x01],       "system_platform: PC->Android (F2)"),
    (&[0x08, 0x03],       &[0x08, 0x01],       "system_platform: PC->Android (F1)"),
];

/// String/text patches. Replacement is always padded to match the original length with spaces.
pub static STRING_PATCHES: &[(&[u8], &[u8])] = &[
    // Telemetry log fields
    (b"is_emulator=1",          b"is_emulator=0"),
    (b"is_emulator:1",          b"is_emulator:0"),
    (b"\"is_emulator\":true",   b"\"is_emulator\":null"),
    (b"\"is_emulator\":1",      b"\"is_emulator\":0"),

    // CPU / Architecture
    (b"x86_64",   b"arm64-v"),
    (b"x86",      b"arm"),
    (b"Intel(R)", b"Qualcomm"),
    (b"Intel",    b"Qualcm"),
    (b"AMD ",     b"Snap"),

    // Emulator names
    (b"Nox",        b"Red"),
    (b"BlueStacks", b"XiaomiMI  "),
    (b"Google",     b"Xiaomi"),
    (b"VirtualBox", b"XiaomiVB  "),
    (b"vbox",       b"qcom"),
    (b"Genymotion", b"GooglePixel"),

    // UTF-16 emulator names (BlueStacks)
    (
        b"B\x00l\x00u\x00e\x00S\x00t\x00a\x00c\x00k\x00s\x00",
        b"X\x00i\x00a\x00o\x00m\x00i\x00M\x00I\x00 \x00 \x00",
    ),
    (
        b"G\x00o\x00o\x00g\x00l\x00e\x00",
        b"X\x00i\x00a\x00o\x00m\x00i\x00",
    ),

    // GPU / Graphics
    (b"Direct3D", b"Adreno  "),
    (b"OpenGL",   b"Mali-G"),

    // Device identity
    (b"SM-G950F", b"2412DPC0AG"),

    // UI strings
    (b"isEmulatorPool: ",    b"isEmulatorPool: 0"),
    (b"target is emulator",  b"target is phone   "),
];

// ═══════════════════════════════════════════════════════════════
//  PORT RANGES
// ═══════════════════════════════════════════════════════════════

/// TCP/UDP port ranges captured by WinDivert and relayed by the proxy.
pub const GAME_PORT_RANGES: &[(u16, u16)] = &[
    (6000,  8000),
    (10000, 10020),
    (12000, 13000),
    (27010, 27030),
    (39000, 39999),
    (49990, 50010),
];

// ═══════════════════════════════════════════════════════════════
//  SERVER ENDPOINTS
// ═══════════════════════════════════════════════════════════════

pub const UID_SERVERS: &[(&str, &str)] = &[
    ("MAIN",   "https://xenitronix.qzz.io/raw/uid"),
    ("BACKUP", "http://omega.vexanode.cloud:2009/raw/uid"),
];

/// Direct UID whitelist URL for local packet-level blocking.
pub const UID_URL: &str = "https://xenitronix.qzz.io/raw/uid";

pub const DB_FILE: &str = "bot_data.db";

/// Seconds between UID server sync cycles.
pub const CHECK_INTERVAL_SECS: u64 = 1;

/// UIDs older than this are considered expired (24 hours).
pub const UID_TTL_SECONDS: i64 = 86_400;

/// Discord channel for login logs.
pub const LOGIN_LOG_CHANNEL_ID: u64 = 1_419_334_943_879_987_331;

/// Bot owner Discord user ID.
pub const OWNER_USER_ID: u64 = 1_243_887_541_581_512_776;

/// MITM proxy listen port — matches installer setting (omega.vexanode.cloud:2039).
pub const PROXY_PORT: u16 = 2039;

/// Path to mitmproxy CA PEM (cert + private key).
/// This is loaded on startup for TLS interception.
pub const CA_PEM_PATH: &str = "mitmproxy-ca.pem";

/// Fallback: ~/.mitmproxy/mitmproxy-ca.pem
pub const CA_PEM_PATH_DEFAULT: &str = ".mitmproxy/mitmproxy-ca.pem";

// ═══════════════════════════════════════════════════════════════
//  AES KEYS (hardcoded, same as Python)
// ═══════════════════════════════════════════════════════════════

pub const AES_KEY: [u8; 16] = [89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56];
pub const AES_IV:  [u8; 16] = [54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37];

// ═══════════════════════════════════════════════════════════════
//  MOBILE PROTO TEMPLATE (hex-encoded AES ciphertext)
// ═══════════════════════════════════════════════════════════════

pub const MOBILE_PROTO_HEX: &str = "25f16c42b17c8239fccb04095cf57404c3b0bb26906e7ba86f20ce787935f3b9\
eea0e0cf108b16269a322d06d9cadf6b4e6822d26490eb78ac78ea85705321894d288f6517b2a17b6027ebfd00ed9b336\
a2ec1c6bed513c218e0bb142bbc045782b578328fe0cea774f6e60f3e278794110dc58ed62a87948fc4005882a1ac2a10\
d18762c6789d2c148d1924b3e04eff87b8538dfc5f8bfe8ff503dc2849f2343fa13bb892005d68bad712508475f173586\
9b65b24a48f96c95937794363497b7897600cf8786407d6d8bc01d87eaee4a00da554fc96b6f415119e29efe1fe491c2\
44edcc3091e5a2148954e870a3a1c5cddcf022ca8453a030013b4f2a8dd18d8e5e5be88c04cab6c0933d96bcc44600f6\
19b424e89f95f979b46f457e51d6742a4398ca4c8d4b9f5a3e8c9c3c08363bfcd8d072518973c099abf69958e130b027\
f36dc007d449e544037f61a21fbd7735c2014028c3d29ccefcf3a25f2a65bd574f75a8ac8325106b75155ede5ee1919f\
bc12b3d86f34e564f3728cdf8165d399f1de23a2cee57ec283d36e1525d2392cbcffd5a3bf7766867eda25720864aeb0\
6c729bc9fe254059376fcd70e4879ea6f77355948843585e6380c220793065084ecb64a8596183815c297d5bf878927a\
5205c57601ea87bbf7451d3c4d83ffdaec2f891e9da8959cfc5a655c5be056712538eee05518dfa80072a4c27d2203c2\
fd3c5dd2b20c0fbb1f2fd7db64d5d3e08e7141a3093007909f98c7984dcc940e9000ac573af6cd81f78d8e20f2fb0b34\
e6bf01dee9100f458019641dc854920cd8be6f5599e239d68e4b5fef9c257710f4b4009b45086391c6cda3314638dae2\
2a96cfeedf97b52d1fa6c30195f2ce4b1064db23929a38a1103d3d4edd6c9e29203a7b1ba975b681fbcff1e4c6d910dc\
9e98a02339d1d7d748c877a9726dd653547c8442aa12577a62954c19c24857ea605decf1ede72ce5b159398bd4082cafe\
aad73cdb5563c45f9476b6069f87dec9e0c18fa2c944806f35c8a07f52e3bf66b545f5457e06d04754a869388596f165\
3cf951caae15f2d48191ec8db0ec813682cbda38b4aaa3defcef332256fa549ff4fcc9f0b7e08f5c71d4ce6bc366f960\
e15c0018526b93c58f445e339b14ba5b296c546314de30f2c66508bf4436b6787b095603b918aaff638711ddb8255e1e\
782d299f48aa9fba0b334cff16e3cc1c43225e17cc51f39215e0d2c2afceaed18358787074475d928a6665130bb8cff4\
a901a7b8f5ec67298fb9b4d665a0182a11abb55109b838c58ebcb56e29c617fb82b1e1a7c49b934de0d12bd4775ae8ab\
d216848a6cea02ebc44fcd14a7aa9ac09b641fee138d5cad7eeb0a3c23df06846f2bfc8c0a87e4a884915909726c34dd\
dd35111a003f524437bdcbe10b3e60b7d442f39666ad7916c784160be8df";

// ═══════════════════════════════════════════════════════════════
//  WINDIVERT FILTER STRING
// ═══════════════════════════════════════════════════════════════

pub const WINDIVERT_FILTER: &str = concat!(
    "(outbound and (",
        "(tcp.DstPort >= 6000 and tcp.DstPort <= 8000) or ",
        "(tcp.DstPort >= 10000 and tcp.DstPort <= 10020) or ",
        "(tcp.DstPort >= 12000 and tcp.DstPort <= 13000) or ",
        "(tcp.DstPort >= 27010 and tcp.DstPort <= 27030) or ",
        "(tcp.DstPort >= 39000 and tcp.DstPort <= 39999) or ",
        "(tcp.DstPort >= 49990 and tcp.DstPort <= 50010) or ",
        "(udp.DstPort >= 10000 and udp.DstPort <= 10020) or ",
        "(udp.DstPort >= 27010 and udp.DstPort <= 27030) or ",
        "(udp.DstPort >= 39000 and udp.DstPort <= 39999) or ",
        "(udp.DstPort >= 49990 and udp.DstPort <= 50010)",
    ")) or ",
    "(inbound and (",
        "(tcp.SrcPort >= 6000 and tcp.SrcPort <= 8000) or ",
        "(tcp.SrcPort >= 10000 and tcp.SrcPort <= 10020) or ",
        "(tcp.SrcPort >= 12000 and tcp.SrcPort <= 13000) or ",
        "(tcp.SrcPort >= 27010 and tcp.SrcPort <= 27030) or ",
        "(tcp.SrcPort >= 39000 and tcp.SrcPort <= 39999) or ",
        "(tcp.SrcPort >= 49990 and tcp.SrcPort <= 50010)",
    "))"
);
