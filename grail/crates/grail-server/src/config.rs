use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "grail-server")]
pub struct Config {
    #[arg(long, env = "PORT", default_value = "3000")]
    pub port: u16,

    #[arg(long, env = "GRAIL_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Path (or name on PATH) for the `codex` binary.
    #[arg(long, env = "CODEX_BIN", default_value = "codex")]
    pub codex_bin: String,

    /// Optional override for CODEX_HOME. Defaults to `${GRAIL_DATA_DIR}/codex`.
    #[arg(long, env = "CODEX_HOME")]
    pub codex_home: Option<PathBuf>,

    /// Optional 32-byte key (hex or base64) used to encrypt secrets stored in SQLite.
    #[arg(long, env = "GRAIL_MASTER_KEY")]
    pub master_key: Option<String>,

    /// Basic-auth password for the admin dashboard.
    #[arg(long, env = "ADMIN_PASSWORD")]
    pub admin_password: String,

    #[arg(long, env = "SLACK_SIGNING_SECRET")]
    pub slack_signing_secret: Option<String>,

    #[arg(long, env = "SLACK_BOT_TOKEN")]
    pub slack_bot_token: Option<String>,

    #[arg(long, env = "TELEGRAM_BOT_TOKEN")]
    pub telegram_bot_token: Option<String>,

    /// If set, require incoming webhooks to include header:
    /// `X-Telegram-Bot-Api-Secret-Token: <value>`.
    #[arg(long, env = "TELEGRAM_WEBHOOK_SECRET")]
    pub telegram_webhook_secret: Option<String>,

    #[arg(long, env = "WHATSAPP_ACCESS_TOKEN")]
    pub whatsapp_access_token: Option<String>,

    #[arg(long, env = "WHATSAPP_VERIFY_TOKEN")]
    pub whatsapp_verify_token: Option<String>,

    #[arg(long, env = "WHATSAPP_PHONE_NUMBER_ID")]
    pub whatsapp_phone_number_id: Option<String>,

    #[arg(long, env = "DISCORD_BOT_TOKEN")]
    pub discord_bot_token: Option<String>,

    /// Discord application public key for verifying webhook signatures.
    #[arg(long, env = "DISCORD_PUBLIC_KEY")]
    pub discord_public_key: Option<String>,

    #[arg(long, env = "MSTEAMS_APP_ID")]
    pub msteams_app_id: Option<String>,

    #[arg(long, env = "MSTEAMS_APP_PASSWORD")]
    pub msteams_app_password: Option<String>,

    /// Optional base URL used when rendering links in the dashboard.
    #[arg(long, env = "BASE_URL")]
    pub base_url: Option<String>,

    /// Max number of tasks to process concurrently (across different conversations).
    /// Each worker slot maintains its own Codex app-server subprocess.
    #[arg(long, env = "GRAIL_WORKER_CONCURRENCY", default_value = "2")]
    pub worker_concurrency: usize,
}

impl Config {
    pub fn effective_codex_home(&self) -> PathBuf {
        self.codex_home
            .clone()
            .unwrap_or_else(|| self.data_dir.join("codex"))
    }
}
