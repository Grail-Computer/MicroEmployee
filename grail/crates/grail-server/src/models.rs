use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionsMode {
    Read,
    Full,
}

impl PermissionsMode {
    pub fn as_db_str(self) -> &'static str {
        match self {
            PermissionsMode::Read => "read",
            PermissionsMode::Full => "full",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "full" => PermissionsMode::Full,
            _ => PermissionsMode::Read,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub context_last_n: i64,
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
    pub reasoning_summary: Option<String>,
    pub permissions_mode: PermissionsMode,
    pub allow_slack_mcp: bool,
    pub allow_context_writes: bool,
    pub shell_network_access: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: i64,
    pub status: String,
    pub workspace_id: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub event_ts: String,
    pub requested_by_user_id: String,
    pub prompt_text: String,
    pub result_text: Option<String>,
    pub error_text: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub conversation_key: String,
    pub codex_thread_id: Option<String>,
    pub memory_summary: String,
    pub last_used_at: i64,
}

#[derive(Debug, Clone)]
pub struct CodexDeviceLogin {
    pub id: String,
    pub status: String,
    pub verification_url: String,
    pub user_code: String,
    pub device_auth_id: String,
    pub interval_sec: i64,
    pub error_text: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}
