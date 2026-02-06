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

    /// Optional base URL used when rendering links in the dashboard.
    #[arg(long, env = "BASE_URL")]
    pub base_url: Option<String>,
}

impl Config {
    pub fn effective_codex_home(&self) -> PathBuf {
        self.codex_home
            .clone()
            .unwrap_or_else(|| self.data_dir.join("codex"))
    }
}
