// JSON API handlers for the React frontend.
// These mirror the existing admin_* HTML handlers but return JSON.

use anyhow::Context;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::str::FromStr;

use crate::db;
use crate::models::PermissionsMode;
use crate::AppState;

type ApiResult<T> = Result<Json<T>, crate::AppError>;

// ─── Status ────────────────────────────────────────────────────────────────

pub async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let settings = db::get_settings(&state.pool).await?;
    let queue_depth: i64 = sqlx::query("SELECT COUNT(*) AS c FROM tasks WHERE status = 'queued'")
        .fetch_one(&state.pool)
        .await?
        .get::<i64, _>("c");
    let worker_lock_owner = db::get_worker_lock_owner(&state.pool)
        .await?
        .unwrap_or_default();
    let active_task = db::get_runtime_active_task(&state.pool).await?;
    let pending_approvals: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM approvals WHERE status = 'pending'")
            .fetch_one(&state.pool)
            .await?
            .get::<i64, _>("c");
    let guardrails_enabled: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM guardrail_rules WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await?
            .get::<i64, _>("c");
    let mk = |suffix: &str| {
        state
            .config
            .base_url
            .as_deref()
            .map(|b| format!("{}/{}", b.trim_end_matches('/'), suffix))
            .unwrap_or_else(|| format!("/{suffix}"))
    };

    Ok(Json(json!({
        "slack_signing_secret_set": crate::secrets::slack_signing_secret_configured(&state).await.unwrap_or(false),
        "slack_bot_token_set": crate::secrets::slack_bot_token_configured(&state).await.unwrap_or(false),
        "telegram_bot_token_set": crate::secrets::telegram_bot_token_configured(&state).await.unwrap_or(false),
        "telegram_webhook_secret_set": crate::secrets::telegram_webhook_secret_configured(&state).await.unwrap_or(false),
        "openai_api_key_set": crate::secrets::openai_api_key_configured(&state).await.unwrap_or(false),
        "master_key_set": state.crypto.is_some(),
        "queue_depth": queue_depth,
        "permissions_mode": settings.permissions_mode.as_db_str(),
        "slack_events_url": mk("slack/events"),
        "slack_actions_url": mk("slack/actions"),
        "telegram_webhook_url": mk("telegram/webhook"),
        "worker_lock_owner": worker_lock_owner,
        "active_task_id": active_task.as_ref().map(|(id, _)| format!("{id}")).unwrap_or_default(),
        "active_task_started_at": active_task.as_ref().map(|(_, ts)| format!("{ts}")).unwrap_or_default(),
        "pending_approvals": pending_approvals,
        "guardrails_enabled": guardrails_enabled,
    })))
}

// ─── Settings ──────────────────────────────────────────────────────────────

pub async fn api_settings_get(State(state): State<AppState>) -> ApiResult<Value> {
    let s = db::get_settings(&state.pool).await?;
    Ok(Json(json!({
        "context_last_n": s.context_last_n,
        "model": s.model.unwrap_or_default(),
        "reasoning_effort": s.reasoning_effort.unwrap_or_default(),
        "reasoning_summary": s.reasoning_summary.unwrap_or_default(),
        "permissions_mode": s.permissions_mode.as_db_str(),
        "slack_allow_from": s.slack_allow_from,
        "slack_allow_channels": s.slack_allow_channels,
        "slack_proactive_enabled": s.slack_proactive_enabled,
        "slack_proactive_snippet": s.slack_proactive_snippet,
        "allow_telegram": s.allow_telegram,
        "telegram_allow_from": s.telegram_allow_from,
        "allow_slack_mcp": s.allow_slack_mcp,
        "allow_web_mcp": s.allow_web_mcp,
        "extra_mcp_config": s.extra_mcp_config,
        "allow_context_writes": s.allow_context_writes,
        "shell_network_access": s.shell_network_access,
        "allow_cron": s.allow_cron,
        "auto_apply_cron_jobs": s.auto_apply_cron_jobs,
        "agent_name": s.agent_name,
        "role_description": s.role_description,
        "command_approval_mode": s.command_approval_mode,
        "auto_apply_guardrail_tighten": s.auto_apply_guardrail_tighten,
        "web_allow_domains": s.web_allow_domains,
        "web_deny_domains": s.web_deny_domains,
        "master_key_set": state.crypto.is_some(),
        "openai_api_key_set": crate::secrets::openai_api_key_configured(&state).await.unwrap_or(false),
        "slack_signing_secret_set": crate::secrets::slack_signing_secret_configured(&state).await.unwrap_or(false),
        "slack_bot_token_set": crate::secrets::slack_bot_token_configured(&state).await.unwrap_or(false),
        "telegram_bot_token_set": crate::secrets::telegram_bot_token_configured(&state).await.unwrap_or(false),
        "telegram_webhook_secret_set": crate::secrets::telegram_webhook_secret_configured(&state).await.unwrap_or(false),
        "brave_search_api_key_set": crate::secrets::brave_search_api_key_configured(&state).await.unwrap_or(false),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ApiSettingsPost {
    pub context_last_n: Option<i64>,
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
    pub reasoning_summary: Option<String>,
    pub permissions_mode: Option<String>,
    pub slack_allow_from: Option<String>,
    pub slack_allow_channels: Option<String>,
    pub slack_proactive_enabled: Option<bool>,
    pub slack_proactive_snippet: Option<String>,
    pub allow_telegram: Option<bool>,
    pub telegram_allow_from: Option<String>,
    pub allow_slack_mcp: Option<bool>,
    pub allow_web_mcp: Option<bool>,
    pub extra_mcp_config: Option<String>,
    pub allow_context_writes: Option<bool>,
    pub shell_network_access: Option<bool>,
    pub allow_cron: Option<bool>,
    pub auto_apply_cron_jobs: Option<bool>,
    pub agent_name: Option<String>,
    pub role_description: Option<String>,
    pub command_approval_mode: Option<String>,
    pub auto_apply_guardrail_tighten: Option<bool>,
    pub web_allow_domains: Option<String>,
    pub web_deny_domains: Option<String>,
}

pub async fn api_settings_post(
    State(state): State<AppState>,
    Json(form): Json<ApiSettingsPost>,
) -> ApiResult<Value> {
    let mut s = db::get_settings(&state.pool).await?;
    if let Some(v) = form.context_last_n {
        s.context_last_n = v.clamp(1, 200);
    }
    if let Some(v) = &form.permissions_mode {
        s.permissions_mode = match v.as_str() {
            "full" => PermissionsMode::Full,
            _ => PermissionsMode::Read,
        };
    }
    if let Some(v) = form.model {
        s.model = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.reasoning_effort {
        s.reasoning_effort = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.reasoning_summary {
        s.reasoning_summary = if v.trim().is_empty() { None } else { Some(v) };
    }
    if let Some(v) = form.slack_allow_from {
        s.slack_allow_from = v;
    }
    if let Some(v) = form.slack_allow_channels {
        s.slack_allow_channels = v;
    }
    if let Some(v) = form.slack_proactive_enabled {
        s.slack_proactive_enabled = v;
    }
    if let Some(v) = form.slack_proactive_snippet {
        s.slack_proactive_snippet = v.trim().chars().take(8_000).collect();
    }
    if let Some(v) = form.allow_telegram {
        s.allow_telegram = v;
    }
    if let Some(v) = form.telegram_allow_from {
        s.telegram_allow_from = v;
    }
    if let Some(v) = form.allow_slack_mcp {
        s.allow_slack_mcp = v;
    }
    if let Some(v) = form.allow_web_mcp {
        s.allow_web_mcp = v;
    }
    if let Some(v) = form.extra_mcp_config {
        s.extra_mcp_config = v;
    }
    if let Some(v) = form.allow_context_writes {
        s.allow_context_writes = v;
    }
    if let Some(v) = form.shell_network_access {
        s.shell_network_access = v;
    }
    if let Some(v) = form.allow_cron {
        s.allow_cron = v;
    }
    if let Some(v) = form.auto_apply_cron_jobs {
        s.auto_apply_cron_jobs = v;
    }
    if let Some(v) = form.agent_name {
        s.agent_name = if v.trim().is_empty() {
            "Grail".to_string()
        } else {
            v
        };
    }
    if let Some(v) = form.role_description {
        s.role_description = v;
    }
    if let Some(v) = form.command_approval_mode {
        s.command_approval_mode = match v.as_str() {
            "auto" | "guardrails" | "always_ask" => v,
            _ => "guardrails".to_string(),
        };
    }
    if let Some(v) = form.auto_apply_guardrail_tighten {
        s.auto_apply_guardrail_tighten = v;
    }
    if let Some(v) = form.web_allow_domains {
        s.web_allow_domains = v;
    }
    if let Some(v) = form.web_deny_domains {
        s.web_deny_domains = v;
    }
    db::update_settings(&state.pool, &s).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Secrets ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SecretValue {
    pub value: String,
}

pub async fn api_set_secret(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(body): Json<SecretValue>,
) -> ApiResult<Value> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };
    let v = body.value.trim().to_string();
    if v.is_empty() {
        return Err(anyhow::anyhow!("value is empty").into());
    }
    let db_key = match key.as_str() {
        "openai" => "openai_api_key",
        "brave" => "brave_search_api_key",
        "slack_signing" => "slack_signing_secret",
        "slack_bot" => "slack_bot_token",
        "telegram_bot" => "telegram_bot_token",
        "telegram_webhook" => "telegram_webhook_secret",
        _ => return Err(anyhow::anyhow!("unknown secret key: {key}").into()),
    };
    let (nonce, ciphertext) = crypto.encrypt(db_key.as_bytes(), v.as_bytes())?;
    db::upsert_secret(&state.pool, db_key, &nonce, &ciphertext).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_delete_secret(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> ApiResult<Value> {
    let db_key = match key.as_str() {
        "openai" => "openai_api_key",
        "brave" => "brave_search_api_key",
        "slack_signing" => "slack_signing_secret",
        "slack_bot" => "slack_bot_token",
        "telegram_bot" => "telegram_bot_token",
        "telegram_webhook" => "telegram_webhook_secret",
        _ => return Err(anyhow::anyhow!("unknown secret key: {key}").into()),
    };
    db::delete_secret(&state.pool, db_key).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Tasks ─────────────────────────────────────────────────────────────────

pub async fn api_tasks(State(state): State<AppState>) -> ApiResult<Value> {
    let tasks = db::list_recent_tasks(&state.pool, 50).await?;
    let rows: Vec<Value> = tasks
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "status": t.status,
                "provider": t.provider,
                "is_proactive": t.is_proactive,
                "channel_id": t.channel_id,
                "thread_ts": t.thread_ts,
                "prompt_text": t.prompt_text,
                "result_text": t.result_text.unwrap_or_default(),
                "error_text": t.error_text.unwrap_or_default(),
                "created_at": format!("{}", t.created_at),
            })
        })
        .collect();
    Ok(Json(json!({"tasks": rows})))
}

pub async fn api_task_cancel(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Value> {
    let _ = db::cancel_task(&state.pool, id).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_task_retry(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Value> {
    let _ = db::retry_task(&state.pool, id).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Memory ────────────────────────────────────────────────────────────────

pub async fn api_memory(State(state): State<AppState>) -> ApiResult<Value> {
    let sessions = db::list_sessions(&state.pool, 200).await?;
    let rows: Vec<Value> = sessions
        .into_iter()
        .map(|s| {
            json!({
                "conversation_key": s.conversation_key,
                "codex_thread_id": s.codex_thread_id.unwrap_or_default(),
                "memory_summary": s.memory_summary,
                "last_used_at": format!("{}", s.last_used_at),
            })
        })
        .collect();
    Ok(Json(json!({"sessions": rows})))
}

#[derive(Debug, Deserialize)]
pub struct MemoryClearBody {
    pub key: String,
}

pub async fn api_memory_clear(
    State(state): State<AppState>,
    Json(body): Json<MemoryClearBody>,
) -> ApiResult<Value> {
    let key = body.key.trim();
    if !key.is_empty() {
        let _ = db::delete_session(&state.pool, key).await?;
    }
    Ok(Json(json!({"ok": true})))
}

// ─── Context ───────────────────────────────────────────────────────────────

pub async fn api_context_list(State(state): State<AppState>) -> ApiResult<Value> {
    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);
    let files = crate::list_context_files(&context_dir).await?;
    let rows: Vec<Value> = files
        .into_iter()
        .map(|f| {
            json!({
                "path": f.path,
                "bytes": f.bytes.parse::<i64>().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(json!({"files": rows})))
}

#[derive(Debug, Deserialize)]
pub struct ContextFileQuery {
    pub path: Option<String>,
}

pub async fn api_context_file_get(
    State(state): State<AppState>,
    Query(q): Query<ContextFileQuery>,
) -> ApiResult<Value> {
    let path = q.path.unwrap_or_default();
    let path = path.trim().to_string();
    if path.is_empty() {
        return Ok(Json(json!({"content": "", "bytes": 0})));
    }
    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);
    let rel = crate::sanitize_rel_path(&path)?;
    let full = crate::resolve_under_root_no_symlinks(&context_dir, &rel).await?;
    let content = match tokio::fs::read_to_string(&full).await {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(anyhow::Error::new(e).context("read context file").into()),
    };
    let bytes = content.as_bytes().len();
    Ok(Json(json!({"content": content, "bytes": bytes})))
}

#[derive(Debug, Deserialize)]
pub struct ContextFileSave {
    pub path: String,
    pub content: String,
}

pub async fn api_context_file_post(
    State(state): State<AppState>,
    Json(body): Json<ContextFileSave>,
) -> ApiResult<Value> {
    let path = body.path.trim().to_string();
    if path.is_empty() {
        return Err(anyhow::anyhow!("path is empty").into());
    }
    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);
    let rel = crate::sanitize_rel_path(&path)?;
    let full = crate::resolve_under_root_no_symlinks(&context_dir, &rel).await?;
    if let Some(parent) = full.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create parent dir")?;
    }
    let content = if body.content.len() > 300_000 {
        body.content[..300_000].to_string()
    } else {
        body.content
    };
    tokio::fs::write(&full, content.as_bytes())
        .await
        .context("write context file")?;
    Ok(Json(json!({"ok": true})))
}

// ─── Cron ──────────────────────────────────────────────────────────────────

pub async fn api_cron_list(State(state): State<AppState>) -> ApiResult<Value> {
    let settings = db::get_settings(&state.pool).await?;
    let jobs = db::list_cron_jobs(&state.pool, 100).await?;
    let rows: Vec<Value> = jobs
        .into_iter()
        .map(|j| {
            json!({
                "id": j.id, "enabled": j.enabled, "name": j.name, "mode": j.mode,
                "schedule": match j.schedule_kind.as_str() {
                    "every" => format!("every {}s", j.every_seconds.unwrap_or(0)),
                    "cron" => j.cron_expr.clone().unwrap_or_default(),
                    "at" => format!("at {}", j.at_ts.unwrap_or(0)),
                    _ => j.schedule_kind.clone(),
                },
                "channel_id": j.channel_id, "thread_ts": j.thread_ts, "prompt_text": j.prompt_text,
                "next_run_at": j.next_run_at.map(|t| format!("{t}")).unwrap_or_default(),
                "last_run_at": j.last_run_at.map(|t| format!("{t}")).unwrap_or_default(),
                "last_status": j.last_status.unwrap_or_default(),
                "last_error": j.last_error.unwrap_or_default(),
                "created_at": format!("{}", j.created_at),
            })
        })
        .collect();
    Ok(Json(json!({
        "cron_enabled": settings.allow_cron,
        "workspace_id": settings.workspace_id.unwrap_or_default(),
        "jobs": rows,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CronAddBody {
    pub name: String,
    pub channel_id: String,
    pub thread_ts: Option<String>,
    pub prompt_text: String,
    pub schedule_kind: String,
    pub every_seconds: Option<i64>,
    pub cron_expr: Option<String>,
}

pub async fn api_cron_add(
    State(state): State<AppState>,
    Json(form): Json<CronAddBody>,
) -> ApiResult<Value> {
    let settings = db::get_settings(&state.pool).await?;
    let workspace_id = settings
        .workspace_id
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("workspace_id not set"))?;
    let now = chrono::Utc::now().timestamp();
    let mut job = crate::models::CronJob {
        id: crate::random_id("cron"),
        name: form.name.trim().to_string(),
        enabled: true,
        mode: "agent".to_string(),
        schedule_kind: form.schedule_kind.trim().to_string(),
        every_seconds: form.every_seconds,
        cron_expr: form
            .cron_expr
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        at_ts: None,
        workspace_id,
        channel_id: form.channel_id.trim().to_string(),
        thread_ts: form.thread_ts.unwrap_or_default().trim().to_string(),
        prompt_text: form.prompt_text.trim().to_string(),
        next_run_at: None,
        last_run_at: None,
        last_status: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    };
    job.next_run_at = match job.schedule_kind.as_str() {
        "every" => {
            let s = job.every_seconds.context("every_seconds required")?;
            Some(now + s)
        }
        "cron" => {
            let expr = job.cron_expr.as_deref().context("cron_expr required")?;
            let nrm = crate::cron_expr::normalize_cron_expr(expr)?;
            job.cron_expr = Some(nrm.clone());
            let sched = cron::Schedule::from_str(&nrm).context("parse cron")?;
            Some(
                sched
                    .upcoming(chrono::Utc)
                    .next()
                    .context("no upcoming")?
                    .timestamp(),
            )
        }
        other => return Err(anyhow::anyhow!("unknown schedule_kind: {other}").into()),
    };
    db::insert_cron_job(&state.pool, &job).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_cron_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    db::delete_cron_job(&state.pool, &id).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_cron_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    db::set_cron_job_enabled(&state.pool, &id, true).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_cron_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    db::set_cron_job_enabled(&state.pool, &id, false).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Guardrails ────────────────────────────────────────────────────────────

pub async fn api_guardrails_list(State(state): State<AppState>) -> ApiResult<Value> {
    let rules = db::list_guardrail_rules(&state.pool, None, 500).await?;
    let rows: Vec<Value> = rules
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id, "enabled": r.enabled, "kind": r.kind, "action": r.action,
                "priority": format!("{}", r.priority), "name": r.name,
                "pattern_kind": r.pattern_kind, "pattern": r.pattern,
                "created_at": format!("{}", r.created_at),
            })
        })
        .collect();
    Ok(Json(json!({"rules": rows})))
}

#[derive(Debug, Deserialize)]
pub struct GuardrailAddBody {
    pub kind: String,
    pub action: String,
    pub priority: i64,
    pub name: String,
    pub pattern_kind: String,
    pub pattern: String,
}

pub async fn api_guardrails_add(
    State(state): State<AppState>,
    Json(form): Json<GuardrailAddBody>,
) -> ApiResult<Value> {
    let now = chrono::Utc::now().timestamp();
    let rule = crate::models::GuardrailRule {
        id: crate::random_id("gr"),
        name: form.name.trim().to_string(),
        kind: form.kind.trim().to_string(),
        pattern_kind: form.pattern_kind.trim().to_string(),
        pattern: form.pattern.trim().to_string(),
        action: form.action.trim().to_string(),
        priority: form.priority.clamp(-10_000, 10_000),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    crate::guardrails::validate_rule(&rule)?;
    db::insert_guardrail_rule(&state.pool, &rule).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_guardrails_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    db::delete_guardrail_rule(&state.pool, &id).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_guardrails_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    db::set_guardrail_rule_enabled(&state.pool, &id, true).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_guardrails_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    db::set_guardrail_rule_enabled(&state.pool, &id, false).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Approvals ─────────────────────────────────────────────────────────────

pub async fn api_approvals_list(State(state): State<AppState>) -> ApiResult<Value> {
    let approvals = db::list_recent_approvals(&state.pool, 100).await?;
    let rows: Vec<Value> = approvals
        .into_iter()
        .map(|a| {
            json!({
                "id": a.id, "status": a.status, "kind": a.kind,
                "decision": a.decision.unwrap_or_default(),
                "details": a.details_json,
                "created_at": format!("{}", a.created_at),
            })
        })
        .collect();
    Ok(Json(json!({"approvals": rows})))
}

pub async fn api_approval_approve(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    crate::approvals::handle_approval_command(&state, "approve", &id).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_approval_always(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    crate::approvals::handle_approval_command(&state, "always", &id).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_approval_deny(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    crate::approvals::handle_approval_command(&state, "deny", &id).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Auth ──────────────────────────────────────────────────────────────────

pub async fn api_auth_get(State(state): State<AppState>) -> ApiResult<Value> {
    let codex_home = state.config.effective_codex_home();
    let auth_summary = crate::codex_login::read_auth_summary(&codex_home).await?;
    let latest = db::get_latest_codex_device_login(&state.pool).await?;
    let device_login = latest.map(|l| {
        json!({
            "status": l.status,
            "verification_url": l.verification_url,
            "user_code": l.user_code,
            "error_text": l.error_text.unwrap_or_default(),
            "created_at": format!("{}", l.created_at),
        })
    });
    Ok(Json(json!({
        "openai_api_key_set": crate::secrets::openai_api_key_configured(&state).await.unwrap_or(false),
        "codex_auth_file_set": auth_summary.file_present,
        "codex_auth_mode": auth_summary.auth_mode,
        "device_login": device_login,
    })))
}

pub async fn api_auth_device_start(State(state): State<AppState>) -> ApiResult<Value> {
    let _ = db::cancel_pending_codex_device_logins(&state.pool).await;
    let issuer = std::env::var("CODEX_ISSUER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::codex_login::DEFAULT_ISSUER.to_string());
    let client_id = std::env::var("CODEX_CLIENT_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::codex_login::DEFAULT_CLIENT_ID.to_string());
    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build http")?;
    let dc = crate::codex_login::request_device_code(&http, &issuer, &client_id).await?;
    let id = crate::random_id("codex_device_login");
    let login = crate::models::CodexDeviceLogin {
        id: id.clone(),
        status: "pending".to_string(),
        verification_url: dc.verification_url.clone(),
        user_code: dc.user_code.clone(),
        device_auth_id: dc.device_auth_id.clone(),
        interval_sec: dc.interval_sec as i64,
        error_text: None,
        created_at: chrono::Utc::now().timestamp(),
        completed_at: None,
    };
    db::insert_codex_device_login(&state.pool, &login).await?;
    let pool = state.pool.clone();
    let codex_home = state.config.effective_codex_home();
    tokio::spawn(async move {
        let _ = crate::run_device_login_flow(
            pool,
            id,
            codex_home,
            issuer,
            client_id,
            dc.device_auth_id,
            dc.user_code,
            dc.interval_sec,
        )
        .await;
    });
    Ok(Json(json!({"ok": true})))
}

pub async fn api_auth_device_cancel(State(state): State<AppState>) -> ApiResult<Value> {
    db::cancel_pending_codex_device_logins(&state.pool).await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn api_auth_logout(State(state): State<AppState>) -> ApiResult<Value> {
    let codex_home = state.config.effective_codex_home();
    let _ = crate::codex_login::delete_auth_json(&codex_home).await?;
    let _ = db::cancel_pending_codex_device_logins(&state.pool).await?;
    Ok(Json(json!({"ok": true})))
}

// ─── Diagnostics ───────────────────────────────────────────────────────────

pub async fn api_diagnostics(State(_state): State<AppState>) -> ApiResult<Value> {
    Ok(Json(json!({"codex_result": null, "codex_error": null})))
}

pub async fn api_diagnostics_codex(State(_state): State<AppState>) -> ApiResult<Value> {
    // Diagnostics test stub — can be expanded later
    Ok(Json(
        json!({"codex_result": "diagnostics endpoint ready", "codex_error": null}),
    ))
}
