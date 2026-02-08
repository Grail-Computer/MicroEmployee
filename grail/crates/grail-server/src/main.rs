mod api;
mod approvals;
mod bootstrap;
mod codex;
mod codex_login;
mod config;
mod cron_expr;
mod crypto;
mod db;
mod guardrails;
mod models;
mod secrets;
mod slack;
mod telegram;
mod templates;
mod worker;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use askama::Template;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use serde::Deserialize;
use sqlx::{Row, SqlitePool};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::crypto::{parse_master_key, Crypto};
use crate::models::PermissionsMode;
use crate::secrets::{
    brave_search_api_key_configured, openai_api_key_configured, slack_bot_token_configured,
    slack_signing_secret_configured, telegram_bot_token_configured,
    telegram_webhook_secret_configured,
};
use crate::slack::{verify_slack_signature, SlackClient};
use crate::templates::{
    ApprovalsTemplate, AuthTemplate, ContextEditTemplate, ContextTemplate, CronTemplate,
    DeviceLoginRow, DiagnosticsTemplate, GuardrailsTemplate, MemoryTemplate, SettingsTemplate,
    StatusTemplate, TasksTemplate,
};

type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
struct AppError(anyhow::Error);

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        Self(anyhow::Error::new(value))
    }
}

impl From<askama::Error> for AppError {
    fn from(value: askama::Error) -> Self {
        Self(anyhow::Error::new(value))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(error = %self.0, "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    pool: SqlitePool,
    http: reqwest::Client,
    crypto: Option<Arc<Crypto>>,
    slack_bot_user_id: Arc<RwLock<Option<String>>>,
    telegram_bot_username: Arc<RwLock<Option<String>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Arc::new(Config::parse());

    tokio::fs::create_dir_all(&config.data_dir).await?;
    bootstrap::ensure_defaults(&config.data_dir).await?;
    let db_path = config.data_dir.join("grail.sqlite");
    let pool = db::init_sqlite(&db_path).await?;

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;

    let state = AppState {
        config: config.clone(),
        pool,
        http,
        crypto: config
            .master_key
            .as_deref()
            .and_then(|k| match parse_master_key(k) {
                Ok(bytes) => Some(Arc::new(Crypto::new(&bytes))),
                Err(err) => {
                    warn!(error = %err, "invalid GRAIL_MASTER_KEY; secrets UI disabled");
                    None
                }
            }),
        slack_bot_user_id: Arc::new(RwLock::new(None)),
        telegram_bot_username: Arc::new(RwLock::new(None)),
    };

    // Background worker (single concurrency).
    tokio::spawn(worker::worker_loop(state.clone()));

    let admin = Router::new()
        .route("/", get(|| async { Redirect::to("/admin/status") }))
        .route("/status", get(admin_status))
        .route(
            "/settings",
            get(admin_settings_get).post(admin_settings_post),
        )
        .route("/auth", get(admin_auth_get))
        .route("/auth/device/start", post(admin_auth_device_start))
        .route("/auth/device/cancel", post(admin_auth_device_cancel))
        .route("/auth/logout", post(admin_auth_logout))
        .route("/secrets/openai", post(admin_set_openai_api_key))
        .route("/secrets/openai/delete", post(admin_delete_openai_api_key))
        .route("/secrets/brave", post(admin_set_brave_search_api_key))
        .route(
            "/secrets/brave/delete",
            post(admin_delete_brave_search_api_key),
        )
        .route(
            "/secrets/slack/signing",
            post(admin_set_slack_signing_secret),
        )
        .route(
            "/secrets/slack/signing/delete",
            post(admin_delete_slack_signing_secret),
        )
        .route("/secrets/slack/bot", post(admin_set_slack_bot_token))
        .route(
            "/secrets/slack/bot/delete",
            post(admin_delete_slack_bot_token),
        )
        .route("/secrets/telegram/bot", post(admin_set_telegram_bot_token))
        .route(
            "/secrets/telegram/bot/delete",
            post(admin_delete_telegram_bot_token),
        )
        .route(
            "/secrets/telegram/webhook",
            post(admin_set_telegram_webhook_secret),
        )
        .route(
            "/secrets/telegram/webhook/delete",
            post(admin_delete_telegram_webhook_secret),
        )
        .route("/tasks", get(admin_tasks))
        .route("/tasks/{id}/cancel", post(admin_task_cancel))
        .route("/tasks/{id}/retry", post(admin_task_retry))
        .route("/diagnostics", get(admin_diagnostics_get))
        .route("/diagnostics/codex", post(admin_diagnostics_codex_post))
        .route("/cron", get(admin_cron_get))
        .route("/cron/add", post(admin_cron_add))
        .route("/cron/{id}/delete", post(admin_cron_delete))
        .route("/cron/{id}/enable", post(admin_cron_enable))
        .route("/cron/{id}/disable", post(admin_cron_disable))
        .route("/guardrails", get(admin_guardrails_get))
        .route("/guardrails/add", post(admin_guardrails_add))
        .route("/guardrails/{id}/delete", post(admin_guardrails_delete))
        .route("/guardrails/{id}/enable", post(admin_guardrails_enable))
        .route("/guardrails/{id}/disable", post(admin_guardrails_disable))
        .route("/approvals", get(admin_approvals_get))
        .route("/approvals/{id}/approve", post(admin_approval_approve))
        .route("/approvals/{id}/always", post(admin_approval_always))
        .route("/approvals/{id}/deny", post(admin_approval_deny))
        .route("/memory", get(admin_memory_get))
        .route("/memory/clear", post(admin_memory_clear))
        .route("/context", get(admin_context_get))
        .route(
            "/context/edit",
            get(admin_context_edit_get).post(admin_context_edit_post),
        )
        .route("/context/view", get(admin_context_view_get));

    let api_routes = Router::new()
        .route("/status", get(api::api_status))
        .route(
            "/settings",
            get(api::api_settings_get).post(api::api_settings_post),
        )
        .route(
            "/secrets/{key}",
            post(api::api_set_secret).delete(api::api_delete_secret),
        )
        .route("/tasks", get(api::api_tasks))
        .route("/tasks/{id}/cancel", post(api::api_task_cancel))
        .route("/tasks/{id}/retry", post(api::api_task_retry))
        .route("/memory", get(api::api_memory))
        .route("/memory/clear", post(api::api_memory_clear))
        .route("/context", get(api::api_context_list))
        .route(
            "/context/file",
            get(api::api_context_file_get).post(api::api_context_file_post),
        )
        .route("/cron", get(api::api_cron_list))
        .route("/cron/add", post(api::api_cron_add))
        .route("/cron/{id}/delete", post(api::api_cron_delete))
        .route("/cron/{id}/enable", post(api::api_cron_enable))
        .route("/cron/{id}/disable", post(api::api_cron_disable))
        .route("/guardrails", get(api::api_guardrails_list))
        .route("/guardrails/add", post(api::api_guardrails_add))
        .route("/guardrails/{id}/delete", post(api::api_guardrails_delete))
        .route("/guardrails/{id}/enable", post(api::api_guardrails_enable))
        .route(
            "/guardrails/{id}/disable",
            post(api::api_guardrails_disable),
        )
        .route("/approvals", get(api::api_approvals_list))
        .route("/approvals/{id}/approve", post(api::api_approval_approve))
        .route("/approvals/{id}/always", post(api::api_approval_always))
        .route("/approvals/{id}/deny", post(api::api_approval_deny))
        .route("/auth", get(api::api_auth_get))
        .route("/auth/device/start", post(api::api_auth_device_start))
        .route("/auth/device/cancel", post(api::api_auth_device_cancel))
        .route("/auth/logout", post(api::api_auth_logout))
        .route("/diagnostics", get(api::api_diagnostics))
        .route("/diagnostics/codex", post(api::api_diagnostics_codex));

    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/admin/status") }))
        .route("/healthz", get(healthz))
        .route("/slack/events", post(slack_events))
        .route("/slack/actions", post(slack_actions))
        .route("/telegram/webhook", post(telegram_webhook));

    // If frontend-dist exists, serve the React SPA at /admin and assets at /assets.
    let frontend_dir = state
        .config
        .data_dir
        .parent()
        .unwrap_or(&state.config.data_dir)
        .join("frontend-dist");
    let frontend_dir_env = std::env::var("GRAIL_FRONTEND_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or(frontend_dir);

    let admin_protected = if frontend_dir_env.join("index.html").exists() {
        info!(
            dir = %frontend_dir_env.display(),
            "serving React SPA from frontend-dist"
        );
        let spa = tower_http::services::ServeFile::new(frontend_dir_env.join("index.html"));
        let assets = tower_http::services::ServeDir::new(frontend_dir_env.join("assets"));
        Router::new()
            .nest_service("/admin", spa)
            .nest_service("/assets", assets)
            .nest("/api/admin", api_routes)
    } else {
        info!("frontend-dist not found; serving Askama admin UI");
        Router::new()
            .nest("/admin", admin)
            .nest("/api/admin", api_routes)
    }
    .layer(middleware::from_fn_with_state(
        state.clone(),
        admin_basic_auth,
    ));

    let app = app.merge(admin_protected);

    let app = app
        .with_state(state)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TraceLayer::new_for_http());

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.port));
    info!(%addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn admin_basic_auth(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    match check_basic_auth(&state.config.admin_password, req.headers()) {
        Ok(true) => {
            if !csrf_ok(&req) {
                return (StatusCode::FORBIDDEN, "forbidden").into_response();
            }
            let path = req.uri().path().to_string();
            let mut resp = next.run(req).await;
            set_admin_security_headers(resp.headers_mut());
            set_admin_cache_headers(path.as_str(), resp.headers_mut());
            resp
        }
        Ok(false) => unauthorized_basic(),
        Err(err) => {
            warn!(error = %err, "admin auth failed");
            unauthorized_basic()
        }
    }
}

fn unauthorized_basic() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    resp.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"Grail\""),
    );
    resp
}

fn check_basic_auth(admin_password: &str, headers: &HeaderMap) -> anyhow::Result<bool> {
    use base64::Engine;

    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Ok(false);
    };
    let value = value.to_str().unwrap_or("");
    let Some(b64) = value.strip_prefix("Basic ") else {
        return Ok(false);
    };
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let decoded = String::from_utf8_lossy(&decoded);
    let Some((user, pass)) = decoded.split_once(':') else {
        return Ok(false);
    };
    if user != "admin" {
        return Ok(false);
    }
    Ok(pass == admin_password)
}

fn csrf_ok(req: &axum::http::Request<axum::body::Body>) -> bool {
    use axum::http::header::{HOST, ORIGIN, REFERER};

    // GET is safe; forms and state-changing routes should include Origin/Referer.
    if req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD {
        return true;
    }

    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if host.is_empty() {
        // If we don't have a host, we can't do a reliable same-origin check.
        return false;
    }
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();

    // Prefer Origin, fall back to Referer.
    if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
        if let Some(h) = host_from_url(origin) {
            return h.eq_ignore_ascii_case(&host);
        }
        return false;
    }

    if let Some(referer) = req.headers().get(REFERER).and_then(|v| v.to_str().ok()) {
        if let Some(h) = host_from_url(referer) {
            return h.eq_ignore_ascii_case(&host);
        }
        return false;
    }

    // Reject requests without Origin/Referer. Attackers can deliberately suppress Referer, and
    // some browsers may omit Origin in edge cases; requiring at least one keeps CSRF protection
    // meaningful for state-changing admin routes.
    false
}

fn set_admin_security_headers(headers: &mut HeaderMap) {
    // Note: Cache-Control is set separately based on route/asset type.
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow, nosnippet"),
    );

    // CSP must allow scripts for the React SPA and inline style attributes used throughout the UI.
    headers.insert(
	        axum::http::header::HeaderName::from_static("content-security-policy"),
	        HeaderValue::from_static(
	            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	        ),
	    );
}

fn set_admin_cache_headers(path: &str, headers: &mut HeaderMap) {
    use axum::http::header::{CACHE_CONTROL, PRAGMA, VARY};

    if path.starts_with("/assets/") {
        // Vite outputs content-hashed assets: safe to cache aggressively.
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=31536000, immutable"),
        );
        headers.remove(PRAGMA);
    } else {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    }
    headers.insert(VARY, HeaderValue::from_static("Authorization"));
}

fn host_from_url(s: &str) -> Option<&str> {
    let s = s.trim();
    let after_scheme = s.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    let host_port = host_port.split('@').last().unwrap_or(host_port);
    Some(host_port.split(':').next().unwrap_or(host_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, Method, Request};

    #[test]
    fn csrf_allows_get_without_headers() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/settings")
            .body(axum::body::Body::from(""))
            .unwrap();
        assert!(csrf_ok(&req));
    }

    #[test]
    fn csrf_rejects_post_without_origin_or_referer() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/settings")
            .header(header::HOST, "example.com")
            .body(axum::body::Body::from(""))
            .unwrap();
        assert!(!csrf_ok(&req));
    }

    #[test]
    fn csrf_accepts_matching_origin() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/settings")
            .header(header::HOST, "example.com")
            .header(header::ORIGIN, "https://example.com")
            .body(axum::body::Body::from(""))
            .unwrap();
        assert!(csrf_ok(&req));
    }

    #[test]
    fn csrf_rejects_mismatching_origin() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/settings")
            .header(header::HOST, "example.com")
            .header(header::ORIGIN, "https://evil.com")
            .body(axum::body::Body::from(""))
            .unwrap();
        assert!(!csrf_ok(&req));
    }

    #[test]
    fn csrf_accepts_matching_referer_when_origin_missing() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/settings")
            .header(header::HOST, "example.com")
            .header(header::REFERER, "https://example.com/admin/settings")
            .body(axum::body::Body::from(""))
            .unwrap();
        assert!(csrf_ok(&req));
    }

    #[test]
    fn host_from_url_parses_host_without_port() {
        assert_eq!(host_from_url("https://example.com"), Some("example.com"));
        assert_eq!(
            host_from_url("https://example.com:123"),
            Some("example.com")
        );
        assert_eq!(
            host_from_url("https://user:pass@example.com:123/x/y"),
            Some("example.com")
        );
        assert_eq!(host_from_url("null"), None);
    }
}

async fn admin_status(State(state): State<AppState>) -> AppResult<Html<String>> {
    let settings = db::get_settings(&state.pool).await?;
    let queue_depth: i64 = sqlx::query("SELECT COUNT(*) AS c FROM tasks WHERE status = 'queued'")
        .fetch_one(&state.pool)
        .await?
        .get::<i64, _>("c");

    let worker_lock_owner = db::get_worker_lock_owner(&state.pool)
        .await?
        .unwrap_or_else(|| "(none)".to_string());

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

    let slack_events_url = state
        .config
        .base_url
        .as_deref()
        .map(|b| format!("{}/slack/events", b.trim_end_matches('/')))
        .unwrap_or_else(|| "/slack/events".to_string());

    let slack_actions_url = state
        .config
        .base_url
        .as_deref()
        .map(|b| format!("{}/slack/actions", b.trim_end_matches('/')))
        .unwrap_or_else(|| "/slack/actions".to_string());

    let telegram_webhook_url = state
        .config
        .base_url
        .as_deref()
        .map(|b| format!("{}/telegram/webhook", b.trim_end_matches('/')))
        .unwrap_or_else(|| "/telegram/webhook".to_string());

    let tpl = StatusTemplate {
        active: "status",
        slack_signing_secret_set: slack_signing_secret_configured(&state).await?,
        slack_bot_token_set: slack_bot_token_configured(&state).await?,
        telegram_bot_token_set: telegram_bot_token_configured(&state).await?,
        telegram_webhook_secret_set: telegram_webhook_secret_configured(&state).await?,
        openai_api_key_set: openai_api_key_configured(&state).await?,
        master_key_set: state.crypto.is_some(),
        queue_depth,
        permissions_mode: settings.permissions_mode.as_db_str().to_string(),
        slack_events_url,
        slack_actions_url,
        telegram_webhook_url,
        worker_lock_owner,
        active_task_id: active_task
            .as_ref()
            .map(|(id, _)| format!("{id}"))
            .unwrap_or_default(),
        active_task_started_at: active_task
            .as_ref()
            .map(|(_, ts)| format!("{ts}"))
            .unwrap_or_default(),
        pending_approvals,
        guardrails_enabled,
    };
    Ok(Html(tpl.render()?))
}

async fn admin_settings_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let settings = db::get_settings(&state.pool).await?;
    let tpl = SettingsTemplate {
        active: "settings",
        context_last_n: settings.context_last_n,
        model: settings.model.unwrap_or_default(),
        reasoning_effort: settings.reasoning_effort.unwrap_or_default(),
        reasoning_summary: settings.reasoning_summary.unwrap_or_default(),
        permissions_mode: settings.permissions_mode.as_db_str().to_string(),
        slack_allow_from: settings.slack_allow_from,
        slack_allow_channels: settings.slack_allow_channels,
        slack_proactive_enabled: settings.slack_proactive_enabled,
        slack_proactive_snippet: settings.slack_proactive_snippet,
        allow_telegram: settings.allow_telegram,
        telegram_allow_from: settings.telegram_allow_from,
        allow_slack_mcp: settings.allow_slack_mcp,
        allow_web_mcp: settings.allow_web_mcp,
        extra_mcp_config: settings.extra_mcp_config,
        allow_context_writes: settings.allow_context_writes,
        shell_network_access: settings.shell_network_access,
        allow_cron: settings.allow_cron,
        auto_apply_cron_jobs: settings.auto_apply_cron_jobs,
        agent_name: settings.agent_name,
        role_description: settings.role_description,
        command_approval_mode: settings.command_approval_mode,
        auto_apply_guardrail_tighten: settings.auto_apply_guardrail_tighten,
        web_allow_domains: settings.web_allow_domains,
        web_deny_domains: settings.web_deny_domains,
        master_key_set: state.crypto.is_some(),
        openai_api_key_set: openai_api_key_configured(&state).await?,
        slack_signing_secret_set: slack_signing_secret_configured(&state).await?,
        slack_bot_token_set: slack_bot_token_configured(&state).await?,
        telegram_bot_token_set: telegram_bot_token_configured(&state).await?,
        telegram_webhook_secret_set: telegram_webhook_secret_configured(&state).await?,
        brave_search_api_key_set: brave_search_api_key_configured(&state).await?,
    };
    Ok(Html(tpl.render()?))
}

#[derive(Debug, Deserialize)]
struct SettingsForm {
    context_last_n: i64,
    model: Option<String>,
    reasoning_effort: Option<String>,
    reasoning_summary: Option<String>,
    permissions_mode: String,
    slack_allow_from: String,
    slack_allow_channels: String,
    slack_proactive_enabled: Option<String>,
    slack_proactive_snippet: String,
    allow_telegram: Option<String>,
    telegram_allow_from: String,
    allow_slack_mcp: Option<String>,
    allow_web_mcp: Option<String>,
    extra_mcp_config: String,
    allow_context_writes: Option<String>,
    shell_network_access: Option<String>,
    allow_cron: Option<String>,
    auto_apply_cron_jobs: Option<String>,
    agent_name: String,
    role_description: String,
    command_approval_mode: String,
    auto_apply_guardrail_tighten: Option<String>,
    web_allow_domains: String,
    web_deny_domains: String,
}

async fn admin_settings_post(
    State(state): State<AppState>,
    Form(form): Form<SettingsForm>,
) -> AppResult<Redirect> {
    let mut settings = db::get_settings(&state.pool).await?;

    settings.context_last_n = form.context_last_n.clamp(1, 200);
    settings.permissions_mode = match form.permissions_mode.as_str() {
        "full" => PermissionsMode::Full,
        _ => PermissionsMode::Read,
    };

    settings.model = normalize_optional_string(form.model);
    settings.reasoning_effort = normalize_optional_string(form.reasoning_effort);
    settings.reasoning_summary = normalize_optional_string(form.reasoning_summary);

    // Comma/whitespace/newline separated Slack user IDs (e.g. U0123...).
    settings.slack_allow_from = clamp_chars(form.slack_allow_from.trim().to_string(), 2_000);
    // Optional channel allow list (C/G IDs).
    settings.slack_allow_channels =
        clamp_chars(form.slack_allow_channels.trim().to_string(), 2_000);
    settings.slack_proactive_enabled = form.slack_proactive_enabled.is_some();
    settings.slack_proactive_snippet =
        clamp_chars(form.slack_proactive_snippet.trim().to_string(), 8_000);

    settings.allow_telegram = form.allow_telegram.is_some();
    // Comma/whitespace/newline separated Telegram user IDs (integers).
    settings.telegram_allow_from = clamp_chars(form.telegram_allow_from.trim().to_string(), 2_000);

    settings.allow_slack_mcp = form.allow_slack_mcp.is_some();
    settings.allow_web_mcp = form.allow_web_mcp.is_some();
    settings.extra_mcp_config = clamp_chars(form.extra_mcp_config, 60_000);
    settings.allow_context_writes = form.allow_context_writes.is_some();
    settings.shell_network_access = form.shell_network_access.is_some();
    settings.allow_cron = form.allow_cron.is_some();
    settings.auto_apply_cron_jobs = form.auto_apply_cron_jobs.is_some();

    settings.agent_name = {
        let v = clamp_chars(form.agent_name.trim().to_string(), 48);
        if v.is_empty() {
            "Grail".to_string()
        } else {
            v
        }
    };
    settings.role_description = clamp_chars(form.role_description.trim().to_string(), 8_000);
    settings.command_approval_mode = match form.command_approval_mode.as_str() {
        "auto" | "guardrails" | "always_ask" => form.command_approval_mode,
        _ => "guardrails".to_string(),
    };
    settings.auto_apply_guardrail_tighten = form.auto_apply_guardrail_tighten.is_some();
    settings.web_allow_domains = clamp_chars(form.web_allow_domains.trim().to_string(), 2_000);
    settings.web_deny_domains = clamp_chars(form.web_deny_domains.trim().to_string(), 2_000);

    db::update_settings(&state.pool, &settings).await?;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Debug, Deserialize)]
struct OpenAiKeyForm {
    openai_api_key: String,
}

async fn admin_set_openai_api_key(
    State(state): State<AppState>,
    Form(form): Form<OpenAiKeyForm>,
) -> AppResult<Redirect> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };

    let key = form.openai_api_key.trim();
    if key.is_empty() {
        return Ok(Redirect::to("/admin/settings"));
    }

    let (nonce, ciphertext) = crypto.encrypt(b"openai_api_key", key.as_bytes())?;
    db::upsert_secret(&state.pool, "openai_api_key", &nonce, &ciphertext).await?;
    Ok(Redirect::to("/admin/settings"))
}

async fn admin_delete_openai_api_key(State(state): State<AppState>) -> AppResult<Redirect> {
    db::delete_secret(&state.pool, "openai_api_key").await?;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Debug, Deserialize)]
struct BraveKeyForm {
    brave_search_api_key: String,
}

async fn admin_set_brave_search_api_key(
    State(state): State<AppState>,
    Form(form): Form<BraveKeyForm>,
) -> AppResult<Redirect> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };

    let key = form.brave_search_api_key.trim();
    if key.is_empty() {
        return Ok(Redirect::to("/admin/settings"));
    }

    let (nonce, ciphertext) = crypto.encrypt(b"brave_search_api_key", key.as_bytes())?;
    db::upsert_secret(&state.pool, "brave_search_api_key", &nonce, &ciphertext).await?;
    Ok(Redirect::to("/admin/settings"))
}

async fn admin_delete_brave_search_api_key(State(state): State<AppState>) -> AppResult<Redirect> {
    db::delete_secret(&state.pool, "brave_search_api_key").await?;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Debug, Deserialize)]
struct SlackSigningSecretForm {
    slack_signing_secret: String,
}

async fn admin_set_slack_signing_secret(
    State(state): State<AppState>,
    Form(form): Form<SlackSigningSecretForm>,
) -> AppResult<Redirect> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };

    let secret = form.slack_signing_secret.trim();
    if secret.is_empty() {
        return Ok(Redirect::to("/admin/settings"));
    }

    let (nonce, ciphertext) = crypto.encrypt(b"slack_signing_secret", secret.as_bytes())?;
    db::upsert_secret(&state.pool, "slack_signing_secret", &nonce, &ciphertext).await?;
    Ok(Redirect::to("/admin/settings"))
}

async fn admin_delete_slack_signing_secret(State(state): State<AppState>) -> AppResult<Redirect> {
    db::delete_secret(&state.pool, "slack_signing_secret").await?;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Debug, Deserialize)]
struct SlackBotTokenForm {
    slack_bot_token: String,
}

async fn admin_set_slack_bot_token(
    State(state): State<AppState>,
    Form(form): Form<SlackBotTokenForm>,
) -> AppResult<Redirect> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };

    let token = form.slack_bot_token.trim();
    if token.is_empty() {
        return Ok(Redirect::to("/admin/settings"));
    }

    let (nonce, ciphertext) = crypto.encrypt(b"slack_bot_token", token.as_bytes())?;
    db::upsert_secret(&state.pool, "slack_bot_token", &nonce, &ciphertext).await?;
    Ok(Redirect::to("/admin/settings"))
}

async fn admin_delete_slack_bot_token(State(state): State<AppState>) -> AppResult<Redirect> {
    db::delete_secret(&state.pool, "slack_bot_token").await?;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Debug, Deserialize)]
struct TelegramBotTokenForm {
    telegram_bot_token: String,
}

async fn admin_set_telegram_bot_token(
    State(state): State<AppState>,
    Form(form): Form<TelegramBotTokenForm>,
) -> AppResult<Redirect> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };

    let token = form.telegram_bot_token.trim();
    if token.is_empty() {
        return Ok(Redirect::to("/admin/settings"));
    }

    let (nonce, ciphertext) = crypto.encrypt(b"telegram_bot_token", token.as_bytes())?;
    db::upsert_secret(&state.pool, "telegram_bot_token", &nonce, &ciphertext).await?;
    Ok(Redirect::to("/admin/settings"))
}

async fn admin_delete_telegram_bot_token(State(state): State<AppState>) -> AppResult<Redirect> {
    db::delete_secret(&state.pool, "telegram_bot_token").await?;
    Ok(Redirect::to("/admin/settings"))
}

#[derive(Debug, Deserialize)]
struct TelegramWebhookSecretForm {
    telegram_webhook_secret: String,
}

async fn admin_set_telegram_webhook_secret(
    State(state): State<AppState>,
    Form(form): Form<TelegramWebhookSecretForm>,
) -> AppResult<Redirect> {
    let Some(crypto) = state.crypto.as_deref() else {
        return Err(anyhow::anyhow!("GRAIL_MASTER_KEY is required to store secrets").into());
    };

    let secret = form.telegram_webhook_secret.trim();
    if secret.is_empty() {
        return Ok(Redirect::to("/admin/settings"));
    }

    let (nonce, ciphertext) = crypto.encrypt(b"telegram_webhook_secret", secret.as_bytes())?;
    db::upsert_secret(&state.pool, "telegram_webhook_secret", &nonce, &ciphertext).await?;
    Ok(Redirect::to("/admin/settings"))
}

async fn admin_delete_telegram_webhook_secret(
    State(state): State<AppState>,
) -> AppResult<Redirect> {
    db::delete_secret(&state.pool, "telegram_webhook_secret").await?;
    Ok(Redirect::to("/admin/settings"))
}

fn normalize_optional_string(v: Option<String>) -> Option<String> {
    let Some(s) = v else { return None };
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

async fn admin_tasks(State(state): State<AppState>) -> AppResult<Html<String>> {
    let tasks = db::list_recent_tasks(&state.pool, 50).await?;
    let tpl = TasksTemplate {
        active: "tasks",
        tasks: tasks.into_iter().map(Into::into).collect(),
    };
    Ok(Html(tpl.render()?))
}

async fn admin_memory_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let sessions = db::list_sessions(&state.pool, 200).await?;
    let tpl = MemoryTemplate {
        active: "memory",
        sessions: sessions.into_iter().map(Into::into).collect(),
    };
    Ok(Html(tpl.render()?))
}

#[derive(Debug, Deserialize)]
struct MemoryClearForm {
    conversation_key: String,
}

async fn admin_memory_clear(
    State(state): State<AppState>,
    Form(form): Form<MemoryClearForm>,
) -> AppResult<Redirect> {
    let key = form.conversation_key.trim();
    if !key.is_empty() {
        let _ = db::delete_session(&state.pool, key).await?;
    }
    Ok(Redirect::to("/admin/memory"))
}

async fn admin_context_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);

    let files = list_context_files(&context_dir).await?;
    let tpl = ContextTemplate {
        active: "context",
        files,
    };
    Ok(Html(tpl.render()?))
}

#[derive(Debug, Deserialize)]
struct ContextEditQuery {
    path: Option<String>,
}

async fn admin_context_edit_get(
    State(state): State<AppState>,
    Query(q): Query<ContextEditQuery>,
) -> AppResult<Html<String>> {
    let path = q.path.unwrap_or_else(|| "INDEX.md".to_string());
    let path = path.trim().to_string();
    if path.is_empty() {
        return Ok(Html(
            ContextEditTemplate {
                active: "context",
                path: "INDEX.md".to_string(),
                content: String::new(),
                bytes: "0".to_string(),
            }
            .render()?,
        ));
    }

    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);
    let rel = sanitize_rel_path(&path)?;
    let full = resolve_under_root_no_symlinks(&context_dir, &rel).await?;

    let content = match tokio::fs::read_to_string(&full).await {
        Ok(v) => v,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(anyhow::Error::new(err).context("read context file").into()),
    };

    let bytes = content.as_bytes().len().to_string();
    let tpl = ContextEditTemplate {
        active: "context",
        path,
        content,
        bytes,
    };
    Ok(Html(tpl.render()?))
}

#[derive(Debug, Deserialize)]
struct ContextEditForm {
    path: String,
    content: String,
}

async fn admin_context_edit_post(
    State(state): State<AppState>,
    Form(form): Form<ContextEditForm>,
) -> AppResult<Redirect> {
    const MAX_CHARS: usize = 300_000;

    let path = form.path.trim().to_string();
    if path.is_empty() {
        return Ok(Redirect::to("/admin/context"));
    }

    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);
    let rel = sanitize_rel_path(&path)?;
    let full = resolve_under_root_no_symlinks(&context_dir, &rel).await?;

    if let Some(parent) = full.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create context file parent dir")?;
    }

    let content = clamp_chars(form.content, MAX_CHARS);
    tokio::fs::write(&full, content.as_bytes())
        .await
        .context("write context file")?;

    Ok(Redirect::to(&format!(
        "/admin/context/edit?path={}",
        urlencoding::encode(&path)
    )))
}

async fn admin_context_view_get(
    State(state): State<AppState>,
    Query(q): Query<ContextEditQuery>,
) -> AppResult<Html<String>> {
    let path = q.path.unwrap_or_else(|| "INDEX.md".to_string());
    let path = path.trim().to_string();
    if path.is_empty() {
        return Ok(Html(
            crate::templates::ContextViewTemplate {
                active: "context",
                path: "INDEX.md".to_string(),
                rendered_html: String::new(),
                bytes: "0".to_string(),
            }
            .render()?,
        ));
    }

    let context_dir = state.config.data_dir.join("context");
    let context_dir = tokio::fs::canonicalize(&context_dir)
        .await
        .unwrap_or(context_dir);
    let rel = sanitize_rel_path(&path)?;
    let full = resolve_under_root_no_symlinks(&context_dir, &rel).await?;

    let content = match tokio::fs::read_to_string(&full).await {
        Ok(v) => v,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(anyhow::Error::new(err).context("read context file").into()),
    };

    let bytes = content.as_bytes().len().to_string();

    // Detect if this is a markdown file
    let is_markdown = path.ends_with(".md") || path.ends_with(".markdown");

    let rendered_html = if is_markdown {
        // Render markdown to HTML
        let parser = pulldown_cmark::Parser::new(&content);
        let mut html_output = String::new();
        pulldown_cmark::html::push_html(&mut html_output, parser);
        html_output
    } else {
        // Detect language for display
        let lang = if path.ends_with(".py") {
            "python"
        } else if path.ends_with(".rs") {
            "rust"
        } else if path.ends_with(".toml") {
            "toml"
        } else if path.ends_with(".yaml") || path.ends_with(".yml") {
            "yaml"
        } else if path.ends_with(".json") {
            "json"
        } else if path.ends_with(".sh") || path.ends_with(".bash") {
            "bash"
        } else if path.ends_with(".sql") {
            "sql"
        } else if path.ends_with(".html") || path.ends_with(".htm") {
            "html"
        } else if path.ends_with(".css") {
            "css"
        } else if path.ends_with(".js") || path.ends_with(".ts") {
            "javascript"
        } else if path.contains("Dockerfile") {
            "dockerfile"
        } else if path.contains("Makefile") || path.ends_with(".mk") {
            "makefile"
        } else {
            "text"
        };
        // Escape HTML entities and wrap in <pre><code>
        let escaped = content
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        format!(
            "<pre class=\"code-view\"><code data-lang=\"{}\">{}</code></pre>",
            lang, escaped
        )
    };

    let tpl = crate::templates::ContextViewTemplate {
        active: "context",
        path,
        rendered_html,
        bytes,
    };
    Ok(Html(tpl.render()?))
}

async fn admin_task_cancel(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Redirect> {
    let _ = db::cancel_task(&state.pool, id).await?;
    Ok(Redirect::to("/admin/tasks"))
}

async fn admin_task_retry(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Redirect> {
    let _ = db::retry_task(&state.pool, id).await?;
    Ok(Redirect::to("/admin/tasks"))
}

async fn admin_diagnostics_get(State(_state): State<AppState>) -> AppResult<Html<String>> {
    let tpl = DiagnosticsTemplate {
        active: "diagnostics",
        codex_result: None,
        codex_error: None,
    };
    Ok(Html(tpl.render()?))
}

async fn admin_diagnostics_codex_post(State(state): State<AppState>) -> AppResult<Html<String>> {
    let res = run_codex_self_test(&state).await;
    let (codex_result, codex_error) = match res {
        Ok(v) => (Some(v), None),
        Err(err) => (None, Some(format!("{err:#}"))),
    };
    let tpl = DiagnosticsTemplate {
        active: "diagnostics",
        codex_result,
        codex_error,
    };
    Ok(Html(tpl.render()?))
}

async fn run_codex_self_test(state: &AppState) -> anyhow::Result<String> {
    let mut settings = db::get_settings(&state.pool).await?;
    // Keep diagnostics safe even if the instance is configured for full permissions.
    settings.permissions_mode = PermissionsMode::Read;
    settings.allow_context_writes = false;
    settings.allow_cron = false;
    settings.allow_slack_mcp = false;
    settings.allow_web_mcp = false;

    let openai_api_key = crate::secrets::load_openai_api_key_opt(state).await?;
    if openai_api_key.is_none() {
        let codex_home = state.config.effective_codex_home();
        let auth_summary = crate::codex_login::read_auth_summary(&codex_home).await?;
        if !auth_summary.file_present {
            anyhow::bail!(
                "OpenAI auth not configured. Set OPENAI_API_KEY (env), store it in /admin/settings, or log in via /admin/auth."
            );
        }
    }

    let cwd = state.config.data_dir.join("context");
    let cwd = tokio::fs::canonicalize(&cwd).await.unwrap_or(cwd);

    let mut codex = crate::codex::CodexManager::new(state.config.clone());
    codex
        .ensure_started(
            openai_api_key.as_deref(),
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
        )
        .await?;

    let thread_id = codex.resume_or_start_thread(None, &settings, &cwd).await?;
    let now = chrono::Utc::now().timestamp();
    let task = crate::models::Task {
        id: 0,
        status: "diagnostic".to_string(),
        provider: "admin".to_string(),
        is_proactive: false,
        workspace_id: "admin".to_string(),
        channel_id: "admin".to_string(),
        thread_ts: "".to_string(),
        event_ts: format!("{now}"),
        requested_by_user_id: "admin".to_string(),
        prompt_text: "diagnostic".to_string(),
        files_json: String::new(),
        result_text: None,
        error_text: None,
        created_at: now,
        started_at: Some(now),
        finished_at: None,
    };

    let input_text = r#"Diagnostics: return ONLY a single JSON object that matches the schema.

Set:
- should_reply: true
- reply: "ok"
- updated_memory_summary: ""
- context_writes: []
- upload_files: []
- cron_jobs: []
- guardrail_rules: []

Do not call tools."#;

    let schema = crate::worker::agent_output_schema();
    let result = codex
        .run_turn(
            state, &task, &thread_id, &settings, &cwd, input_text, schema,
        )
        .await
        .map(|o| o.agent_message_text);

    codex.stop().await;
    result
}

async fn admin_cron_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let settings = db::get_settings(&state.pool).await?;
    let jobs = db::list_cron_jobs(&state.pool, 100).await?;
    let tpl = CronTemplate {
        active: "cron",
        cron_enabled: settings.allow_cron,
        workspace_id: settings.workspace_id.unwrap_or_default(),
        jobs: jobs.into_iter().map(Into::into).collect(),
    };
    Ok(Html(tpl.render()?))
}

#[derive(Debug, Deserialize)]
struct CronAddForm {
    name: String,
    channel_id: String,
    thread_ts: Option<String>,
    prompt_text: String,

    mode: Option<String>, // agent | message

    schedule_kind: String, // every | cron | at
    every_seconds: Option<i64>,
    cron_expr: Option<String>,
    at_ts: Option<i64>,

    enabled: Option<String>,
}

async fn admin_cron_add(
    State(state): State<AppState>,
    Form(form): Form<CronAddForm>,
) -> AppResult<Redirect> {
    let settings = db::get_settings(&state.pool).await?;
    let Some(workspace_id) = settings
        .workspace_id
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Err(anyhow::anyhow!(
            "workspace_id is not set yet. Mention Grail once in Slack so it can pin the workspace id."
        )
        .into());
    };

    let now = chrono::Utc::now().timestamp();
    let mut job = crate::models::CronJob {
        id: random_id("cron"),
        name: form.name.trim().to_string(),
        enabled: form.enabled.is_some(),
        mode: form
            .mode
            .unwrap_or_else(|| "agent".to_string())
            .trim()
            .to_string(),
        schedule_kind: form.schedule_kind.trim().to_string(),
        every_seconds: form.every_seconds,
        cron_expr: form
            .cron_expr
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        at_ts: form.at_ts,
        workspace_id,
        channel_id: form.channel_id.trim().to_string(),
        thread_ts: form.thread_ts.unwrap_or_default().trim().to_string(), // empty = post in channel (no thread)
        prompt_text: clamp_chars(form.prompt_text.trim().to_string(), 8_000),
        next_run_at: None,
        last_run_at: None,
        last_status: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    };

    // Basic validation + compute initial next_run_at.
    if job.name.is_empty() {
        return Err(anyhow::anyhow!("name is required").into());
    }
    if job.channel_id.is_empty() {
        return Err(anyhow::anyhow!("channel_id is required").into());
    }
    if job.prompt_text.trim().is_empty() {
        return Err(anyhow::anyhow!("prompt_text is required").into());
    }

    job.next_run_at = match job.schedule_kind.as_str() {
        "every" => {
            let s = job.every_seconds.context("every_seconds is required")?;
            if s < 1 {
                return Err(anyhow::anyhow!("every_seconds must be >= 1").into());
            }
            Some(now + s)
        }
        "cron" => {
            let expr = job.cron_expr.as_deref().context("cron_expr is required")?;
            let normalized = crate::cron_expr::normalize_cron_expr(expr)?;
            // Store normalized so execution is predictable.
            job.cron_expr = Some(normalized.clone());
            let schedule = cron::Schedule::from_str(&normalized).context("parse cron expr")?;
            let next = schedule
                .upcoming(chrono::Utc)
                .next()
                .context("cron had no upcoming times")?;
            Some(next.timestamp())
        }
        "at" => {
            let at = job.at_ts.context("at_ts is required")?;
            if at <= now {
                return Err(anyhow::anyhow!("at_ts must be in the future (unix seconds)").into());
            }
            Some(at)
        }
        other => {
            return Err(anyhow::anyhow!("unknown schedule_kind: {other}").into());
        }
    };

    db::insert_cron_job(&state.pool, &job).await?;
    Ok(Redirect::to("/admin/cron"))
}

async fn admin_cron_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = db::delete_cron_job(&state.pool, &id).await?;
    Ok(Redirect::to("/admin/cron"))
}

async fn admin_cron_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = db::set_cron_job_enabled(&state.pool, &id, true).await?;
    Ok(Redirect::to("/admin/cron"))
}

async fn admin_cron_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = db::set_cron_job_enabled(&state.pool, &id, false).await?;
    Ok(Redirect::to("/admin/cron"))
}

async fn admin_guardrails_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let rules = db::list_guardrail_rules(&state.pool, None, 500).await?;
    let tpl = GuardrailsTemplate {
        active: "guardrails",
        rules: rules.into_iter().map(Into::into).collect(),
    };
    Ok(Html(tpl.render()?))
}

#[derive(Debug, Deserialize)]
struct GuardrailAddForm {
    name: String,
    kind: String,
    action: String,
    pattern_kind: String,
    pattern: String,
    priority: i64,
    enabled: Option<String>,
}

async fn admin_guardrails_add(
    State(state): State<AppState>,
    Form(form): Form<GuardrailAddForm>,
) -> AppResult<Redirect> {
    let now = chrono::Utc::now().timestamp();
    let rule = crate::models::GuardrailRule {
        id: random_id("gr"),
        name: clamp_chars(form.name.trim().to_string(), 120),
        kind: form.kind.trim().to_string(),
        pattern_kind: form.pattern_kind.trim().to_string(),
        pattern: clamp_chars(form.pattern.trim().to_string(), 2_000),
        action: form.action.trim().to_string(),
        priority: form.priority.clamp(-10_000, 10_000),
        enabled: form.enabled.is_some(),
        created_at: now,
        updated_at: now,
    };
    crate::guardrails::validate_rule(&rule)?;
    db::insert_guardrail_rule(&state.pool, &rule).await?;
    Ok(Redirect::to("/admin/guardrails"))
}

async fn admin_guardrails_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = db::delete_guardrail_rule(&state.pool, &id).await?;
    Ok(Redirect::to("/admin/guardrails"))
}

async fn admin_guardrails_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = db::set_guardrail_rule_enabled(&state.pool, &id, true).await?;
    Ok(Redirect::to("/admin/guardrails"))
}

async fn admin_guardrails_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = db::set_guardrail_rule_enabled(&state.pool, &id, false).await?;
    Ok(Redirect::to("/admin/guardrails"))
}

async fn admin_approvals_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let approvals = db::list_recent_approvals(&state.pool, 100).await?;
    let tpl = ApprovalsTemplate {
        active: "approvals",
        approvals: approvals.into_iter().map(Into::into).collect(),
    };
    Ok(Html(tpl.render()?))
}

async fn admin_approval_approve(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = crate::approvals::handle_approval_command(&state, "approve", &id).await?;
    Ok(Redirect::to("/admin/approvals"))
}

async fn admin_approval_always(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = crate::approvals::handle_approval_command(&state, "always", &id).await?;
    Ok(Redirect::to("/admin/approvals"))
}

async fn admin_approval_deny(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let _ = crate::approvals::handle_approval_command(&state, "deny", &id).await?;
    Ok(Redirect::to("/admin/approvals"))
}

async fn admin_auth_get(State(state): State<AppState>) -> AppResult<Html<String>> {
    let codex_home = state.config.effective_codex_home();
    let auth_summary = crate::codex_login::read_auth_summary(&codex_home).await?;
    let latest = db::get_latest_codex_device_login(&state.pool).await?;
    let device_login = latest.map(|l| DeviceLoginRow {
        status: l.status,
        verification_url: l.verification_url,
        user_code: l.user_code,
        error_text: l.error_text.unwrap_or_default(),
        created_at: format!("{}", l.created_at),
    });

    let tpl = AuthTemplate {
        active: "auth",
        openai_api_key_set: openai_api_key_configured(&state).await?,
        codex_auth_file_set: auth_summary.file_present,
        codex_auth_mode: auth_summary.auth_mode,
        device_login,
    };
    Ok(Html(tpl.render()?))
}

async fn admin_auth_device_start(State(state): State<AppState>) -> AppResult<Redirect> {
    // Cancel any pending login first.
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
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;

    let dc = crate::codex_login::request_device_code(&http, &issuer, &client_id).await?;
    let id = random_id("codex_device_login");

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
        if let Err(err) = run_device_login_flow(
            pool,
            id,
            codex_home,
            issuer,
            client_id,
            dc.device_auth_id,
            dc.user_code,
            dc.interval_sec,
        )
        .await
        {
            warn!(error = %err, "device login flow failed");
        }
    });

    Ok(Redirect::to("/admin/auth"))
}

async fn admin_auth_device_cancel(State(state): State<AppState>) -> AppResult<Redirect> {
    let _ = db::cancel_pending_codex_device_logins(&state.pool).await?;
    Ok(Redirect::to("/admin/auth"))
}

async fn admin_auth_logout(State(state): State<AppState>) -> AppResult<Redirect> {
    let codex_home = state.config.effective_codex_home();
    let _ = crate::codex_login::delete_auth_json(&codex_home).await?;
    let _ = db::cancel_pending_codex_device_logins(&state.pool).await?;
    Ok(Redirect::to("/admin/auth"))
}

async fn slack_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let secret = match crate::secrets::load_slack_signing_secret_opt(&state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            let mut resp = (
                StatusCode::SERVICE_UNAVAILABLE,
                "slack not configured (missing SLACK_SIGNING_SECRET)",
            )
                .into_response();
            resp.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-slack-no-retry"),
                HeaderValue::from_static("1"),
            );
            return resp;
        }
        Err(err) => {
            warn!(error = %err, "failed to load slack signing secret");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if let Err(err) = verify_slack_signature(&secret, &headers, &body) {
        warn!(error = %err, "invalid slack signature");
        return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
    }

    let env: SlackEnvelope = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "invalid slack payload");
            return (StatusCode::BAD_REQUEST, "invalid payload").into_response();
        }
    };

    match env {
        SlackEnvelope::UrlVerification { challenge } => {
            axum::Json(serde_json::json!({ "challenge": challenge })).into_response()
        }
        SlackEnvelope::EventCallback {
            team_id,
            event_id,
            event,
        } => {
            let (
                user,
                text,
                ts,
                channel,
                thread_ts,
                is_dm,
                is_proactive,
                strip_mentions,
                should_post_ack,
                allow_approval_commands,
                files,
            ) = match event {
                SlackEvent::AppMention {
                    user,
                    text,
                    ts,
                    channel,
                    thread_ts,
                    files,
                } => {
                    let thread_ts = thread_ts.unwrap_or_else(|| ts.clone());
                    (
                        user, text, ts, channel, thread_ts, false, false, true, true, true, files,
                    )
                }
                SlackEvent::Message {
                    user,
                    text,
                    ts,
                    channel,
                    thread_ts,
                    channel_type,
                    subtype,
                    bot_id,
                    files,
                    ..
                } => {
                    let ct = channel_type.as_deref().unwrap_or("");
                    // Ignore bot messages and non-user subtypes to avoid loops.
                    if bot_id.is_some() || subtype.is_some() {
                        return (StatusCode::OK, "").into_response();
                    }
                    let Some(user) = user else {
                        return (StatusCode::OK, "").into_response();
                    };
                    let text = text.unwrap_or_default();
                    if ct == "im" || ct == "mpim" {
                        // In DMs, reply in-channel (no thread).
                        (
                            user,
                            text,
                            ts,
                            channel,
                            String::new(),
                            true,
                            false,
                            false,
                            true,
                            true,
                            files,
                        )
                    } else if ct == "channel" || ct == "group" {
                        // Proactive mode: see all channel/group messages and decide whether to reply.
                        // We'll still enforce settings below.
                        let thread_ts = thread_ts.unwrap_or_else(|| ts.clone());
                        (
                            user, text, ts, channel, thread_ts, false, true, false, false, false,
                            files,
                        )
                    } else {
                        return (StatusCode::OK, "").into_response();
                    }
                }
                _ => return (StatusCode::OK, "").into_response(),
            };

            // Enforce single-workspace per deployment.
            match db::get_settings(&state.pool).await {
                Ok(settings) => {
                    if is_proactive && !settings.slack_proactive_enabled {
                        return (StatusCode::OK, "").into_response();
                    }

                    if let Some(want) = settings
                        .workspace_id
                        .as_deref()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                    {
                        if want != team_id {
                            warn!(want, got = %team_id, "ignoring slack event from unexpected workspace");
                            return (StatusCode::OK, "").into_response();
                        }
                    } else {
                        // Best-effort: pin to the first workspace we see.
                        let _ = db::set_workspace_id_if_missing(&state.pool, &team_id).await;
                    }

                    // Optional allow-list (nanobot-style allowFrom).
                    let allowed = parse_allow_from(&settings.slack_allow_from);
                    if !allowed.is_empty() && !allowed.contains(user.as_str()) {
                        warn!(user = %user, "slack user not in allow list; ignoring");
                        if !is_proactive {
                            if let Ok(Some(token)) =
                                crate::secrets::load_slack_bot_token_opt(&state).await
                            {
                                let slack = SlackClient::new(state.http.clone(), token);
                                let msg = "Sorry, you're not authorized to use this Grail instance.";
                                let _ = slack
                                    .post_message(&channel, thread_opt(&thread_ts), msg)
                                    .await;
                            }
                        }
                        return (StatusCode::OK, "").into_response();
                    }

                    // Optional channel allow-list (DMs always allowed).
                    if !is_dm {
                        let channels = parse_allow_from(&settings.slack_allow_channels);
                        if !channels.is_empty() && !channels.contains(channel.as_str()) {
                            warn!(channel = %channel, "slack channel not in allow list; ignoring");
                            if !is_proactive {
                                if let Ok(Some(token)) =
                                    crate::secrets::load_slack_bot_token_opt(&state).await
                                {
                                    let slack = SlackClient::new(state.http.clone(), token);
                                    let msg =
                                        "Sorry, this Grail instance isn't enabled in this channel.";
                                    let _ = slack
                                        .post_message(&channel, thread_opt(&thread_ts), msg)
                                        .await;
                                }
                            }
                            return (StatusCode::OK, "").into_response();
                        }
                    }
                }
                Err(err) => {
                    warn!(error = %err, "failed to load settings for slack authz");
                    if is_proactive {
                        return (StatusCode::OK, "").into_response();
                    }
                }
            }

            // If this proactive message explicitly mentions the bot, let the app_mention
            // event handle it so we don't double-enqueue and double-reply.
            if is_proactive {
                if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(&state).await {
                    match slack_bot_user_id_cached(&state, &token).await {
                        Ok(Some(bot_user_id)) => {
                            let needle = format!("<@{}", bot_user_id);
                            if text.contains(&needle) {
                                return (StatusCode::OK, "").into_response();
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            warn!(error = %err, "failed to resolve slack bot user id");
                        }
                    }
                }
            }

            let processed =
                match db::try_mark_event_processed(&state.pool, &team_id, &event_id).await {
                    Ok(v) => v,
                    Err(err) => {
                        error!(error = %err, "failed to dedupe event");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
                    }
                };

            if !processed {
                return (StatusCode::OK, "").into_response();
            }

            let mut prompt = clamp_chars(
                if strip_mentions {
                    strip_leading_mentions(&text)
                } else {
                    text.trim().to_string()
                },
                4_000,
            );

            if allow_approval_commands {
                if let Some((action, approval_id)) = parse_approval_command(&prompt) {
                    match crate::approvals::handle_approval_command(&state, action, &approval_id)
                        .await
                    {
                        Ok(Some(msg)) => {
                            if let Ok(Some(token)) =
                                crate::secrets::load_slack_bot_token_opt(&state).await
                            {
                                let slack = SlackClient::new(state.http.clone(), token);
                                let _ = slack
                                    .post_message(&channel, thread_opt(&thread_ts), msg.trim())
                                    .await;
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            warn!(error = %err, "failed to handle approval command");
                        }
                    }
                    return (StatusCode::OK, "").into_response();
                }
            }

            // --- File handling ---
            // Download any attached files and append info to the prompt.
            let mut files_meta: Vec<serde_json::Value> = Vec::new();
            if !files.is_empty() {
                if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(&state).await {
                    let slack_dl = SlackClient::new(state.http.clone(), token);
                    let download_dir = state.config.data_dir.join("downloads").join(&ts);
                    for f in &files {
                        let fname = f.name.as_deref().unwrap_or("unknown");
                        let mime = f.mimetype.as_deref().unwrap_or("application/octet-stream");
                        if let Some(url) = f.url_private_download.as_deref() {
                            let dest = download_dir.join(fname);
                            match slack_dl.download_file(url, &dest).await {
                                Ok(()) => {
                                    let dest_str = dest.display().to_string();
                                    if mime.starts_with("image/") {
                                        prompt.push_str(&format!(
                                            "\n[Attached image: {fname} — downloaded to {dest_str}]"
                                        ));
                                    } else {
                                        prompt.push_str(&format!(
                                            "\n[Attached file: {fname} ({mime}) — downloaded to {dest_str}]"
                                        ));
                                    }
                                    files_meta.push(serde_json::json!({
                                        "id": f.id,
                                        "name": fname,
                                        "mimetype": mime,
                                        "filetype": f.filetype,
                                        "size": f.size,
                                        "local_path": dest_str,
                                    }));
                                }
                                Err(err) => {
                                    warn!(error = %err, file = fname, "failed to download slack file");
                                    prompt.push_str(&format!(
                                        "\n[Attached file: {fname} ({mime}) — download failed]"
                                    ));
                                }
                            }
                        } else {
                            prompt.push_str(&format!(
                                "\n[Attached file: {fname} ({mime}) — no download URL]"
                            ));
                        }
                    }
                }
            }

            let files_json = if files_meta.is_empty() {
                String::new()
            } else {
                serde_json::to_string(&files_meta).unwrap_or_default()
            };

            let task_id = match db::enqueue_task_with_files(
                &state.pool,
                "slack",
                &team_id,
                &channel,
                &thread_ts,
                &ts,
                &user,
                &prompt,
                &files_json,
                is_proactive,
            )
            .await
            {
                Ok(id) => id,
                Err(err) => {
                    error!(error = %err, "failed to enqueue task");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
                }
            };

            // Ack immediately, post "Queued" asynchronously (but never for proactive messages).
            if should_post_ack {
                match crate::secrets::load_slack_bot_token_opt(&state).await {
                    Ok(Some(token)) => {
                        let slack = SlackClient::new(state.http.clone(), token);
                        let queued_text = format!("Queued as #{task_id}. I'll start soon.");
                        let thread_ts = thread_ts.clone();
                        tokio::spawn(async move {
                            if let Err(err) = slack
                                .post_message(&channel, thread_opt(&thread_ts), &queued_text)
                                .await
                            {
                                warn!(error = %err, "failed to post queued message");
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(error = %err, "failed to load slack bot token");
                    }
                }
            }

            (StatusCode::OK, "").into_response()
        }
    }
}

async fn slack_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let secret = match crate::secrets::load_slack_signing_secret_opt(&state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            let mut resp = (
                StatusCode::SERVICE_UNAVAILABLE,
                "slack not configured (missing SLACK_SIGNING_SECRET)",
            )
                .into_response();
            resp.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-slack-no-retry"),
                HeaderValue::from_static("1"),
            );
            return resp;
        }
        Err(err) => {
            warn!(error = %err, "failed to load slack signing secret");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    if let Err(err) = verify_slack_signature(&secret, &headers, &body) {
        warn!(error = %err, "invalid slack signature (actions)");
        return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
    }

    #[derive(Debug, Deserialize)]
    struct SlackActionUser {
        id: String,
    }
    #[derive(Debug, Deserialize)]
    struct SlackActionTeam {
        id: String,
    }
    #[derive(Debug, Deserialize)]
    struct SlackActionChannel {
        id: String,
    }
    #[derive(Debug, Deserialize)]
    struct SlackActionMessage {
        ts: String,
        #[serde(default)]
        thread_ts: Option<String>,
    }
    #[derive(Debug, Deserialize)]
    struct SlackAction {
        action_id: String,
        #[serde(default)]
        value: Option<String>,
    }
    #[derive(Debug, Deserialize)]
    struct SlackActionPayload {
        #[serde(rename = "type")]
        kind: String,
        user: SlackActionUser,
        #[serde(default)]
        team: Option<SlackActionTeam>,
        channel: SlackActionChannel,
        message: SlackActionMessage,
        actions: Vec<SlackAction>,
    }

    let form = parse_urlencoded_form(&body);
    let Some(payload_raw) = form.get("payload").map(|s| s.as_str()) else {
        return (StatusCode::BAD_REQUEST, "missing payload").into_response();
    };

    let payload: SlackActionPayload = match serde_json::from_str(payload_raw) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "invalid slack actions payload json");
            return (StatusCode::BAD_REQUEST, "invalid payload").into_response();
        }
    };

    if payload.kind != "block_actions" {
        return (StatusCode::OK, "").into_response();
    }

    // Enforce single-workspace per deployment (best-effort).
    if let Ok(settings) = db::get_settings(&state.pool).await {
        if let (Some(want), Some(team)) = (
            settings
                .workspace_id
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty()),
            payload.team.as_ref().map(|t| t.id.as_str()),
        ) {
            if want != team {
                warn!(
                    want,
                    got = team,
                    "ignoring slack action from unexpected workspace"
                );
                return (StatusCode::OK, "").into_response();
            }
        }

        // Optional allow-list.
        let allowed = parse_allow_from(&settings.slack_allow_from);
        if !allowed.is_empty() && !allowed.contains(payload.user.id.as_str()) {
            warn!(user = %payload.user.id, "slack user not in allow list; ignoring action");
            return (StatusCode::OK, "").into_response();
        }

        // Optional channel allow-list (DMs always allowed).
        let channels = parse_allow_from(&settings.slack_allow_channels);
        if !channels.is_empty()
            && !payload.channel.id.starts_with('D')
            && !channels.contains(payload.channel.id.as_str())
        {
            warn!(
                channel = %payload.channel.id,
                "slack channel not in allow list; ignoring action"
            );
            return (StatusCode::OK, "").into_response();
        }
    }

    let Some(action) = payload.actions.get(0) else {
        return (StatusCode::OK, "").into_response();
    };
    let approval_id = action.value.clone().unwrap_or_default();
    if approval_id.trim().is_empty() {
        return (StatusCode::OK, "").into_response();
    }

    let action_str = match action.action_id.as_str() {
        "grail_approve" => "approve",
        "grail_always" => "always",
        "grail_deny" => "deny",
        other => {
            warn!(action_id = other, "unknown slack action_id");
            return (StatusCode::OK, "").into_response();
        }
    };

    let msg =
        match crate::approvals::handle_approval_command(&state, action_str, &approval_id).await {
            Ok(v) => v,
            Err(err) => {
                warn!(error = %err, "failed to handle approval via slack actions");
                None
            }
        };

    if let Some(text) = msg {
        if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(&state).await {
            let slack = SlackClient::new(state.http.clone(), token);
            let thread_ts = payload
                .message
                .thread_ts
                .clone()
                .unwrap_or_else(|| payload.message.ts.clone());
            let _ = slack
                .post_message(&payload.channel.id, thread_opt(&thread_ts), text.trim())
                .await;
        }
    }

    (StatusCode::OK, "").into_response()
}

async fn telegram_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // If Telegram is disabled, ack to avoid retries.
    let settings = match db::get_settings(&state.pool).await {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, "failed to load settings for telegram webhook");
            return (StatusCode::OK, "").into_response();
        }
    };
    if !settings.allow_telegram {
        return (StatusCode::OK, "").into_response();
    }

    // Production default: require Telegram webhook secret verification when Telegram is enabled.
    let want = match crate::secrets::load_telegram_webhook_secret_opt(&state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "telegram not configured (missing TELEGRAM_WEBHOOK_SECRET)",
            )
                .into_response();
        }
        Err(err) => {
            warn!(error = %err, "failed to load telegram webhook secret");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let got = headers
        .get("X-Telegram-Bot-Api-Secret-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if got != want {
        warn!("invalid telegram webhook secret token");
        return (StatusCode::UNAUTHORIZED, "invalid secret").into_response();
    }

    let update: crate::telegram::TelegramUpdate = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "invalid telegram payload");
            return (StatusCode::BAD_REQUEST, "invalid payload").into_response();
        }
    };

    let Some(msg) = update.message.clone().or(update.edited_message.clone()) else {
        return (StatusCode::OK, "").into_response();
    };
    let Some(text) = msg.text.clone() else {
        return (StatusCode::OK, "").into_response();
    };
    let from_user_id = msg
        .from
        .as_ref()
        .map(|u| u.id.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Nanobot-style allowFrom (Telegram user IDs).
    let allowed = parse_allow_from(&settings.telegram_allow_from);
    if !allowed.is_empty() && !allowed.contains(from_user_id.as_str()) {
        warn!(user_id = %from_user_id, "telegram user not in allow list; ignoring");
        return (StatusCode::OK, "").into_response();
    }

    // Dedupe (Telegram retries webhooks).
    let processed =
        match db::try_mark_event_processed(&state.pool, "telegram", &update.update_id.to_string())
            .await
        {
            Ok(v) => v,
            Err(err) => {
                error!(error = %err, "failed to dedupe telegram update");
                return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
            }
        };
    if !processed {
        return (StatusCode::OK, "").into_response();
    }

    // Persist minimal local history for context injection.
    let stored = crate::models::TelegramMessage {
        chat_id: msg.chat.id.to_string(),
        message_id: msg.message_id,
        from_user_id: Some(from_user_id.clone()),
        is_bot: msg.from.as_ref().map(|u| u.is_bot).unwrap_or(false),
        text: Some(clamp_chars(text.clone(), 8_000)),
        ts: msg.date,
    };
    if let Err(err) = db::insert_telegram_message(&state.pool, &stored).await {
        warn!(error = %err, "failed to store telegram message");
    }

    let token = match crate::secrets::load_telegram_bot_token_opt(&state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "telegram not configured (missing TELEGRAM_BOT_TOKEN)",
            )
                .into_response();
        }
        Err(err) => {
            warn!(error = %err, "failed to load telegram bot token");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let bot_username = match telegram_bot_username_cached(&state, &token).await {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "failed to resolve telegram bot username");
            None
        }
    };

    let cleaned = clean_telegram_prompt(&text, bot_username.as_deref());

    // Handle approval commands even if the bot isn't explicitly mentioned.
    if let Some((action, approval_id)) = parse_approval_command(&cleaned) {
        if let Ok(Some(a)) = db::get_approval(&state.pool, &approval_id).await {
            if a.status == "pending" {
                if let Ok(Some(msg_text)) =
                    crate::approvals::handle_approval_command(&state, action, &approval_id).await
                {
                    let tg = crate::telegram::TelegramClient::new(state.http.clone(), token);
                    let _ = tg
                        .send_message(&stored.chat_id, Some(msg.message_id), msg_text.trim())
                        .await;
                }
                return (StatusCode::OK, "").into_response();
            }
        }
    }

    // Determine whether the message is directed at the bot.
    let directed = if msg.chat.kind == "private" {
        true
    } else if msg
        .reply_to_message
        .as_ref()
        .and_then(|m| m.from.as_ref())
        .map(|u| u.is_bot)
        .unwrap_or(false)
    {
        true
    } else if let Some(user) = bot_username.as_deref() {
        text.contains(&format!("@{user}"))
            || text.starts_with("/grail")
            || text.starts_with("/microemployee")
            || text.starts_with(&format!("/grail@{user}"))
            || text.starts_with(&format!("/microemployee@{user}"))
    } else {
        text.starts_with("/grail") || text.starts_with("/microemployee")
    };

    if !directed {
        return (StatusCode::OK, "").into_response();
    }

    let prompt = clamp_chars(cleaned, 4_000);
    if prompt.is_empty() {
        return (StatusCode::OK, "").into_response();
    }

    let task_id = match db::enqueue_task(
        &state.pool,
        "telegram",
        "telegram",
        &stored.chat_id,
        &msg.message_id.to_string(),
        &msg.message_id.to_string(),
        &from_user_id,
        &prompt,
    )
    .await
    {
        Ok(id) => id,
        Err(err) => {
            error!(error = %err, "failed to enqueue telegram task");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    let tg = crate::telegram::TelegramClient::new(state.http.clone(), token);
    let chat_id = stored.chat_id.clone();
    let reply_to = msg.message_id;
    tokio::spawn(async move {
        let queued_text = format!("Queued as #{task_id}. I'll start soon.");
        let _ = tg
            .send_message(&chat_id, Some(reply_to), queued_text.trim())
            .await;
    });

    (StatusCode::OK, "").into_response()
}

async fn slack_bot_user_id_cached(
    state: &AppState,
    bot_token: &str,
) -> anyhow::Result<Option<String>> {
    {
        let guard = state.slack_bot_user_id.read().await;
        if let Some(v) = guard.clone() {
            return Ok(Some(v));
        }
    }

    let slack = SlackClient::new(state.http.clone(), bot_token.to_string());
    let user_id = slack.auth_test_bot_user_id().await?;

    let mut guard = state.slack_bot_user_id.write().await;
    *guard = Some(user_id.clone());
    Ok(Some(user_id))
}

async fn telegram_bot_username_cached(
    state: &AppState,
    bot_token: &str,
) -> anyhow::Result<Option<String>> {
    {
        let guard = state.telegram_bot_username.read().await;
        if let Some(v) = guard.clone() {
            return Ok(Some(v));
        }
    }

    let tg = crate::telegram::TelegramClient::new(state.http.clone(), bot_token.to_string());
    let me = tg.get_me().await?;
    let Some(username) = me.username.clone().filter(|u| !u.trim().is_empty()) else {
        return Ok(None);
    };

    let mut guard = state.telegram_bot_username.write().await;
    *guard = Some(username.clone());
    Ok(Some(username))
}

fn clean_telegram_prompt(text: &str, bot_username: Option<&str>) -> String {
    let mut t = text.trim().to_string();

    if t.starts_with('/') {
        let mut parts = t.split_whitespace();
        let first = parts.next().unwrap_or("");
        let first = first.trim();
        if first.starts_with("/grail")
            || first.starts_with("/microemployee")
            || first.starts_with("/start")
        {
            t = parts.collect::<Vec<_>>().join(" ").trim().to_string();
        }
    }

    if let Some(u) = bot_username {
        let needle = format!("@{u}");
        t = t.replace(&needle, "");
    }

    t.trim().to_string()
}

fn parse_allow_from(input: &str) -> std::collections::HashSet<String> {
    input
        .split(|c: char| c == ',' || c == '\n' || c == '\r' || c == '\t' || c == ' ')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn parse_urlencoded_form(body: &Bytes) -> HashMap<String, String> {
    fn decode(s: &str) -> String {
        // application/x-www-form-urlencoded uses '+' for space.
        let s = s.replace('+', " ");
        match urlencoding::decode(&s) {
            Ok(v) => v.into_owned(),
            Err(_) => s,
        }
    }

    let raw = std::str::from_utf8(body).unwrap_or("");
    let mut out: HashMap<String, String> = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        if k.is_empty() {
            continue;
        }
        out.insert(decode(k), decode(v));
    }
    out
}

fn parse_approval_command(text: &str) -> Option<(&'static str, String)> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let mut parts = t.split_whitespace();
    let cmd = parts.next()?.to_ascii_lowercase();
    let id = parts.next()?.trim();
    if id.is_empty() {
        return None;
    }
    match cmd.as_str() {
        "approve" => Some(("approve", id.to_string())),
        "always" => Some(("always", id.to_string())),
        "deny" => Some(("deny", id.to_string())),
        "cancel" => Some(("cancel", id.to_string())),
        _ => None,
    }
}

fn thread_opt(thread_ts: &str) -> Option<&str> {
    let t = thread_ts.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    let mut rng = rand::rng();
    rand::RngCore::fill_bytes(&mut rng, &mut bytes);
    format!("{}_{}", prefix, hex::encode(bytes))
}

pub async fn run_device_login_flow(
    pool: SqlitePool,
    login_id: String,
    codex_home: std::path::PathBuf,
    issuer: String,
    client_id: String,
    device_auth_id: String,
    user_code: String,
    interval_sec: u64,
) -> anyhow::Result<()> {
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;

    let deadline = tokio::time::Instant::now() + crate::codex_login::default_device_login_timeout();
    loop {
        // Check cancellation.
        let status = db::get_codex_device_login(&pool, &login_id)
            .await?
            .map(|l| l.status)
            .unwrap_or_else(|| "missing".to_string());
        if status != "pending" {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            let now = chrono::Utc::now().timestamp();
            db::update_codex_device_login_status(
                &pool,
                &login_id,
                "failed",
                Some("device login timed out"),
                Some(now),
            )
            .await?;
            return Ok(());
        }

        match crate::codex_login::poll_device_auth(&http, &issuer, &device_auth_id, &user_code)
            .await
        {
            Ok(crate::codex_login::DeviceAuthPoll::Pending) => {
                tokio::time::sleep(Duration::from_secs(interval_sec.max(1).min(30))).await;
            }
            Ok(crate::codex_login::DeviceAuthPoll::Success(s)) => {
                let tokens = crate::codex_login::exchange_code_for_tokens(
                    &http,
                    &issuer,
                    &client_id,
                    &s.authorization_code,
                    &s.code_verifier,
                )
                .await?;

                crate::codex_login::write_chatgpt_auth_json(&codex_home, &tokens).await?;
                let now = chrono::Utc::now().timestamp();
                db::update_codex_device_login_status(
                    &pool,
                    &login_id,
                    "completed",
                    None,
                    Some(now),
                )
                .await?;
                return Ok(());
            }
            Err(err) => {
                let now = chrono::Utc::now().timestamp();
                db::update_codex_device_login_status(
                    &pool,
                    &login_id,
                    "failed",
                    Some(&format!("{err:#}")),
                    Some(now),
                )
                .await?;
                return Ok(());
            }
        }
    }
}

fn strip_leading_mentions(text: &str) -> String {
    let mut s = text.trim_start();

    // Remove one or more leading "<@...>" tokens and separators.
    loop {
        if let Some(rest) = s.strip_prefix("<@") {
            if let Some(end) = rest.find('>') {
                s = rest[end + 1..].trim_start();
                continue;
            }
        }
        if let Some(rest) = s.strip_prefix(':') {
            s = rest.trim_start();
            continue;
        }
        if let Some(rest) = s.strip_prefix(',') {
            s = rest.trim_start();
            continue;
        }
        if let Some(rest) = s.strip_prefix(';') {
            s = rest.trim_start();
            continue;
        }
        break;
    }

    s.trim().to_string()
}

fn clamp_chars(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    s.chars().take(max).collect()
}

pub async fn list_context_files(
    root: &std::path::Path,
) -> anyhow::Result<Vec<crate::templates::ContextFileRow>> {
    let mut out: Vec<crate::templates::ContextFileRow> = Vec::new();

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("read_dir {}", dir.display()))?;
        while let Some(ent) = rd.next_entry().await? {
            let path = ent.path();
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                continue;
            }

            let meta = ent.metadata().await?;
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }

            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let edit_url = format!("/admin/context/edit?path={}", urlencoding::encode(&rel));
            let view_url = format!("/admin/context/view?path={}", urlencoding::encode(&rel));
            out.push(crate::templates::ContextFileRow {
                path: rel,
                bytes: format!("{}", meta.len()),
                edit_url,
                view_url,
            });
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub fn sanitize_rel_path(path: &str) -> anyhow::Result<std::path::PathBuf> {
    let p = std::path::PathBuf::from(path.trim());
    anyhow::ensure!(!p.as_os_str().is_empty(), "empty path");
    anyhow::ensure!(!p.is_absolute(), "absolute paths are not allowed");
    for c in p.components() {
        match c {
            std::path::Component::Normal(_) => {}
            _ => anyhow::bail!("invalid path component in {}", path),
        }
    }
    Ok(p)
}

pub async fn resolve_under_root_no_symlinks(
    root: &std::path::Path,
    rel: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let root = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());

    let mut cur = root.clone();
    for comp in rel.components() {
        let std::path::Component::Normal(seg) = comp else {
            anyhow::bail!("invalid path component");
        };
        cur.push(seg);

        match tokio::fs::symlink_metadata(&cur).await {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    anyhow::bail!("symlinks are not allowed in context paths");
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(anyhow::Error::new(err).context("symlink_metadata")),
        }
    }

    // If the path exists, ensure it canonicalizes under root (defense in depth).
    if tokio::fs::metadata(&cur).await.is_ok() {
        let canon = tokio::fs::canonicalize(&cur).await?;
        anyhow::ensure!(canon.starts_with(&root), "context path escapes root");
        return Ok(canon);
    }

    // For new files, check the parent directory is under root.
    if let Some(parent) = cur.parent() {
        let parent_canon = tokio::fs::canonicalize(parent)
            .await
            .unwrap_or_else(|_| parent.to_path_buf());
        anyhow::ensure!(parent_canon.starts_with(&root), "context path escapes root");
    }

    Ok(cur)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum SlackEnvelope {
    #[serde(rename = "url_verification")]
    UrlVerification { challenge: String },

    #[serde(rename = "event_callback")]
    EventCallback {
        #[serde(rename = "team_id")]
        team_id: String,
        #[serde(rename = "event_id")]
        event_id: String,
        event: SlackEvent,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum SlackEvent {
    #[serde(rename = "app_mention")]
    AppMention {
        user: String,
        text: String,
        ts: String,
        channel: String,
        #[serde(default)]
        thread_ts: Option<String>,
        #[serde(default)]
        files: Vec<crate::slack::SlackFile>,
    },

    #[serde(rename = "message")]
    Message {
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        text: Option<String>,
        ts: String,
        channel: String,
        #[serde(default)]
        thread_ts: Option<String>,
        #[serde(default)]
        channel_type: Option<String>, // im | channel | group | mpim
        #[serde(default)]
        subtype: Option<String>,
        #[serde(default)]
        bot_id: Option<String>,
        #[serde(default)]
        files: Vec<crate::slack::SlackFile>,
    },

    #[serde(other)]
    Other,
}
