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
    pub workspace_id: Option<String>,
    pub slack_allow_from: String,
    pub slack_allow_channels: String,
    pub slack_proactive_enabled: bool,
    pub slack_proactive_snippet: String,
    pub allow_telegram: bool,
    pub telegram_allow_from: String,
    pub allow_whatsapp: bool,
    pub whatsapp_allow_from: String,
    pub allow_discord: bool,
    pub discord_allow_from: String,
    pub allow_msteams: bool,
    pub msteams_allow_from: String,
    pub allow_slack_mcp: bool,
    pub allow_web_mcp: bool,
    /// Extra TOML appended to CODEX_HOME/config.toml (advanced).
    /// This is intentionally free-form so users can add custom MCP servers.
    pub extra_mcp_config: String,
    pub allow_context_writes: bool,
    pub shell_network_access: bool,
    pub allow_cron: bool,
    pub auto_apply_cron_jobs: bool,
    pub agent_name: String,
    pub role_description: String,
    pub command_approval_mode: String,
    pub auto_apply_guardrail_tighten: bool,
    pub web_allow_domains: String,
    pub web_deny_domains: String,
    pub github_client_id: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: i64,
    pub status: String,
    pub provider: String,
    pub is_proactive: bool,
    pub workspace_id: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub conversation_key: String,
    pub event_ts: String,
    pub requested_by_user_id: String,
    pub prompt_text: String,
    pub files_json: String,
    pub result_text: Option<String>,
    pub error_text: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct TaskTrace {
    pub id: i64,
    pub task_id: i64,
    pub event_type: String,
    pub level: String,
    pub message: String,
    pub details: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub conversation_key: String,
    pub codex_thread_id: Option<String>,
    pub memory_summary: String,
    pub last_used_at: i64,
}

#[derive(Debug, Clone)]
pub struct ObservationalMemory {
    pub memory_key: String,
    pub scope: String, // thread | resource
    pub observation_log: String,
    pub reflection_summary: String,
    pub updated_at: i64,
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

#[derive(Debug, Clone)]
pub struct GithubDeviceLogin {
    pub id: String,
    pub status: String,
    pub verification_url: String,
    pub user_code: String,
    pub device_code: String,
    pub interval_sec: i64,
    pub error_text: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CronJob {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub mode: String,          // agent | message
    pub schedule_kind: String, // every | cron | at
    pub every_seconds: Option<i64>,
    pub cron_expr: Option<String>,
    pub at_ts: Option<i64>,
    pub workspace_id: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub prompt_text: String,
    pub next_run_at: Option<i64>,
    pub last_run_at: Option<i64>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct GuardrailRule {
    pub id: String,
    pub name: String,
    pub kind: String,         // command | web_fetch | ...
    pub pattern_kind: String, // regex | exact | substring
    pub pattern: String,
    pub action: String, // allow | require_approval | deny
    pub priority: i64,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct Approval {
    pub id: String,
    pub kind: String,   // command_execution | guardrail_rule_add | cron_job_add
    pub status: String, // pending | approved | denied | expired
    pub decision: Option<String>,
    pub workspace_id: Option<String>,
    pub channel_id: Option<String>,
    pub thread_ts: Option<String>,
    pub requested_by_user_id: Option<String>,
    pub details_json: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct TelegramMessage {
    pub chat_id: String,
    pub message_id: i64,
    pub from_user_id: Option<String>,
    pub is_bot: bool,
    pub text: Option<String>,
    pub ts: i64,
}
