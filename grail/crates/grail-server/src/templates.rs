use askama::Template;

use crate::models::{Approval, CronJob, GuardrailRule, Session, Task};

#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusTemplate {
    pub active: &'static str,
    pub slack_signing_secret_set: bool,
    pub slack_bot_token_set: bool,
    pub telegram_bot_token_set: bool,
    pub telegram_webhook_secret_set: bool,
    pub openai_api_key_set: bool,
    pub master_key_set: bool,
    pub queue_depth: i64,
    pub permissions_mode: String,
    pub slack_events_url: String,
    pub slack_actions_url: String,
    pub telegram_webhook_url: String,
    pub worker_lock_owner: String,
    pub active_task_id: String,
    pub active_task_started_at: String,
    pub pending_approvals: i64,
    pub guardrails_enabled: i64,
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
    pub slack_allow_from: String,
    pub slack_allow_channels: String,
    pub allow_telegram: bool,
    pub telegram_allow_from: String,
    pub allow_slack_mcp: bool,
    pub allow_web_mcp: bool,
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
    pub master_key_set: bool,
    pub openai_api_key_set: bool,
    pub slack_signing_secret_set: bool,
    pub slack_bot_token_set: bool,
    pub telegram_bot_token_set: bool,
    pub telegram_webhook_secret_set: bool,
    pub brave_search_api_key_set: bool,
}

#[derive(Template)]
#[template(path = "tasks.html")]
pub struct TasksTemplate {
    pub active: &'static str,
    pub tasks: Vec<TaskRow>,
}

#[derive(Template)]
#[template(path = "approvals.html")]
pub struct ApprovalsTemplate {
    pub active: &'static str,
    pub approvals: Vec<ApprovalRow>,
}

#[derive(Template)]
#[template(path = "guardrails.html")]
pub struct GuardrailsTemplate {
    pub active: &'static str,
    pub rules: Vec<GuardrailRuleRow>,
}

#[derive(Template)]
#[template(path = "cron.html")]
pub struct CronTemplate {
    pub active: &'static str,
    pub cron_enabled: bool,
    pub workspace_id: String,
    pub jobs: Vec<CronJobRow>,
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

#[derive(Template)]
#[template(path = "memory.html")]
pub struct MemoryTemplate {
    pub active: &'static str,
    pub sessions: Vec<SessionRow>,
}

#[derive(Template)]
#[template(path = "context.html")]
pub struct ContextTemplate {
    pub active: &'static str,
    pub files: Vec<ContextFileRow>,
}

#[derive(Template)]
#[template(path = "context_edit.html")]
pub struct ContextEditTemplate {
    pub active: &'static str,
    pub path: String,
    pub content: String,
    pub bytes: String,
}

#[derive(Template)]
#[template(path = "diagnostics.html")]
pub struct DiagnosticsTemplate {
    pub active: &'static str,
    pub codex_result: Option<String>,
    pub codex_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TaskRow {
    pub id: i64,
    pub status: String,
    pub provider: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub prompt_text: String,
    pub result_text: String,
    pub error_text: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct CronJobRow {
    pub id: String,
    pub enabled: bool,
    pub name: String,
    pub mode: String,
    pub schedule: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub prompt_text: String,
    pub next_run_at: String,
    pub last_run_at: String,
    pub last_status: String,
    pub last_error: String,
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

#[derive(Debug, Clone)]
pub struct ApprovalRow {
    pub id: String,
    pub status: String,
    pub kind: String,
    pub decision: String,
    pub created_at: String,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct GuardrailRuleRow {
    pub id: String,
    pub enabled: bool,
    pub kind: String,
    pub action: String,
    pub priority: String,
    pub name: String,
    pub pattern_kind: String,
    pub pattern: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub conversation_key: String,
    pub codex_thread_id: String,
    pub memory_summary: String,
    pub last_used_at: String,
}

#[derive(Debug, Clone)]
pub struct ContextFileRow {
    pub path: String,
    pub bytes: String,
    pub edit_url: String,
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
            provider: t.provider,
            channel_id: t.channel_id,
            thread_ts: t.thread_ts,
            prompt_text: t.prompt_text,
            result_text: compact(t.result_text.unwrap_or_default()),
            error_text: compact(t.error_text.unwrap_or_default()),
            created_at: format!("{}", t.created_at),
        }
    }
}

impl From<Session> for SessionRow {
    fn from(s: Session) -> Self {
        fn compact(mut v: String) -> String {
            v = v.replace('\n', " ").replace('\r', " ");
            if v.len() > 220 {
                v = format!("{}…", v.chars().take(219).collect::<String>());
            }
            v
        }

        Self {
            conversation_key: s.conversation_key,
            codex_thread_id: s.codex_thread_id.unwrap_or_default(),
            memory_summary: compact(s.memory_summary),
            last_used_at: format!("{}", s.last_used_at),
        }
    }
}

impl From<CronJob> for CronJobRow {
    fn from(j: CronJob) -> Self {
        fn compact(mut s: String) -> String {
            s = s.replace('\n', " ").replace('\r', " ");
            if s.len() > 220 {
                s = format!("{}…", s.chars().take(219).collect::<String>());
            }
            s
        }

        let schedule = match j.schedule_kind.as_str() {
            "every" => j
                .every_seconds
                .map(|s| format!("every {s}s"))
                .unwrap_or_else(|| "every (?)".to_string()),
            "cron" => j
                .cron_expr
                .clone()
                .map(|e| format!("cron {e}"))
                .unwrap_or_else(|| "cron (?)".to_string()),
            "at" => j
                .at_ts
                .map(|t| format!("at {t}"))
                .unwrap_or_else(|| "at (?)".to_string()),
            other => other.to_string(),
        };

        Self {
            id: j.id,
            enabled: j.enabled,
            name: j.name,
            mode: j.mode,
            schedule,
            channel_id: j.channel_id,
            thread_ts: j.thread_ts,
            prompt_text: compact(j.prompt_text),
            next_run_at: j.next_run_at.map(|t| format!("{t}")).unwrap_or_default(),
            last_run_at: j.last_run_at.map(|t| format!("{t}")).unwrap_or_default(),
            last_status: j.last_status.unwrap_or_default(),
            last_error: compact(j.last_error.unwrap_or_default()),
            created_at: format!("{}", j.created_at),
        }
    }
}

impl From<Approval> for ApprovalRow {
    fn from(a: Approval) -> Self {
        fn compact(mut s: String) -> String {
            s = s.replace('\n', " ").replace('\r', " ");
            if s.len() > 240 {
                s = format!("{}…", s.chars().take(239).collect::<String>());
            }
            s
        }

        Self {
            id: a.id,
            status: a.status,
            kind: a.kind,
            decision: a.decision.unwrap_or_default(),
            created_at: format!("{}", a.created_at),
            details: compact(a.details_json),
        }
    }
}

impl From<GuardrailRule> for GuardrailRuleRow {
    fn from(r: GuardrailRule) -> Self {
        fn compact(mut s: String) -> String {
            s = s.replace('\n', " ").replace('\r', " ");
            if s.len() > 240 {
                s = format!("{}…", s.chars().take(239).collect::<String>());
            }
            s
        }

        Self {
            id: r.id,
            enabled: r.enabled,
            kind: r.kind,
            action: r.action,
            priority: format!("{}", r.priority),
            name: r.name,
            pattern_kind: r.pattern_kind,
            pattern: compact(r.pattern),
            created_at: format!("{}", r.created_at),
        }
    }
}
