use askama::Template;

use crate::models::Task;

#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusTemplate {
    pub active: &'static str,
    pub slack_signing_secret_set: bool,
    pub slack_bot_token_set: bool,
    pub openai_api_key_set: bool,
    pub master_key_set: bool,
    pub queue_depth: i64,
    pub permissions_mode: String,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub active: &'static str,
    pub context_last_n: i64,
    pub model: String,
    pub reasoning_effort: String,
    pub reasoning_summary: String,
    pub permissions_mode: String,
    pub allow_slack_mcp: bool,
    pub allow_context_writes: bool,
    pub shell_network_access: bool,
    pub master_key_set: bool,
    pub openai_api_key_set: bool,
}

#[derive(Template)]
#[template(path = "tasks.html")]
pub struct TasksTemplate {
    pub active: &'static str,
    pub tasks: Vec<TaskRow>,
}

#[derive(Template)]
#[template(path = "auth.html")]
pub struct AuthTemplate {
    pub active: &'static str,
    pub openai_api_key_set: bool,
    pub codex_auth_file_set: bool,
    pub codex_auth_mode: String,
    pub device_login: Option<DeviceLoginRow>,
}

#[derive(Debug, Clone)]
pub struct TaskRow {
    pub id: i64,
    pub status: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub prompt_text: String,
    pub result_text: String,
    pub error_text: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct DeviceLoginRow {
    pub status: String,
    pub verification_url: String,
    pub user_code: String,
    pub error_text: String,
    pub created_at: String,
}

impl From<Task> for TaskRow {
    fn from(t: Task) -> Self {
        fn compact(mut s: String) -> String {
            s = s.replace('\n', " ").replace('\r', " ");
            if s.len() > 220 {
                s = format!("{}…", s.chars().take(219).collect::<String>());
            }
            s
        }

        Self {
            id: t.id,
            status: t.status,
            channel_id: t.channel_id,
            thread_ts: t.thread_ts,
            prompt_text: t.prompt_text,
            result_text: compact(t.result_text.unwrap_or_default()),
            error_text: compact(t.error_text.unwrap_or_default()),
            created_at: format!("{}", t.created_at),
        }
    }
}
