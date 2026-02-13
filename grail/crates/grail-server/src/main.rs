mod api;
mod approvals;
mod bootstrap;
mod codex;
mod codex_login;
mod config;
mod cron_expr;
mod crypto;
mod db;
mod discord;
mod github_login;
mod guardrails;
mod models;
mod msteams;
mod secrets;
mod slack;
mod telegram;
mod whatsapp;
mod worker;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, get_service, post};
use axum::Router;
use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
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
    brave_search_api_key_configured, github_client_id_configured, github_token_configured,
    openai_api_key_configured, slack_bot_token_configured, slack_signing_secret_configured,
    telegram_bot_token_configured, telegram_webhook_secret_configured,
};
use crate::slack::{verify_slack_signature, SlackClient};

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
    task_notify: Arc<tokio::sync::Notify>,
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
        task_notify: Arc::new(tokio::sync::Notify::new()),
    };

    // Background worker (configurable concurrency).
    tokio::spawn(worker::worker_loop(state.clone()));

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
        .route("/tasks/{id}", get(api::api_task_details))
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
        .route(
            "/auth/github/device/start",
            post(api::api_github_device_start),
        )
        .route(
            "/auth/github/device/cancel",
            post(api::api_github_device_cancel),
        )
        .route("/auth/github/logout", post(api::api_github_logout))
        .route("/diagnostics", get(api::api_diagnostics))
        .route("/diagnostics/codex", post(api::api_diagnostics_codex));

    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/admin/status") }))
        .route("/healthz", get(healthz))
        .route("/slack/events", post(slack_events))
        .route("/slack/actions", post(slack_actions))
        .route("/telegram/webhook", post(telegram_webhook))
        .route("/whatsapp/webhook", get(whatsapp_webhook_verify))
        .route("/whatsapp/webhook", post(whatsapp_webhook))
        .route("/discord/webhook", post(discord_webhook))
        .route("/msteams/webhook", post(msteams_webhook));

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

    let admin_routes = if frontend_dir_env.join("index.html").exists() {
        info!(
            dir = %frontend_dir_env.display(),
            "serving React SPA from frontend-dist"
        );
        let spa = tower_http::services::ServeFile::new(frontend_dir_env.join("index.html"));
        let assets = tower_http::services::ServeDir::new(frontend_dir_env.join("assets"));
        Router::new()
            .route("/admin", get_service(spa.clone()))
            .route("/admin/{*path}", get_service(spa))
            .nest_service("/assets", assets)
            .nest("/api/admin", api_routes)
    } else {
        info!("frontend-dist not found; React admin build is required for /admin");
        Router::new()
            .route("/admin", get(admin_frontend_missing))
            .route("/admin/{*path}", get(admin_frontend_missing))
            .nest("/api/admin", api_routes)
    }
    .layer(middleware::from_fn_with_state(
        state.clone(),
        admin_basic_auth,
    ));

    let app = app.merge(admin_routes);

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

async fn admin_frontend_missing() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Admin frontend not available. Build and mount the React frontend to /admin.",
    )
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
        HeaderValue::from_static("Basic realm=\"FastClaw\""),
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

fn task_trace_url(state: &AppState, task_id: i64) -> String {
    state
        .config
        .base_url
        .as_deref()
        .map(|base| format!("{}/admin/tasks/{}", base.trim_end_matches('/'), task_id))
        .unwrap_or_else(|| format!("/admin/tasks/{task_id}"))
}

fn task_link_message(task_id: i64, task_url: &str) -> String {
    format!("Task queued as #{task_id}. Track progress: {task_url}")
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

    #[test]
    fn parse_task_command_list_running() {
        assert_eq!(
            parse_task_command("running tasks"),
            Some(TaskCommand::ListRunning)
        );
        assert_eq!(
            parse_task_command("What tasks are running?"),
            Some(TaskCommand::ListRunning)
        );
    }

    #[test]
    fn parse_task_command_show() {
        assert_eq!(
            parse_task_command("tell me about task 50"),
            Some(TaskCommand::Show { task_id: 50 })
        );
        assert_eq!(
            parse_task_command("task #51"),
            Some(TaskCommand::Show { task_id: 51 })
        );
    }

    #[test]
    fn parse_task_command_cancel_and_retry() {
        assert_eq!(
            parse_task_command("stop task 52"),
            Some(TaskCommand::Cancel { task_id: 52 })
        );
        assert_eq!(
            parse_task_command("retry task #53"),
            Some(TaskCommand::Retry { task_id: 53 })
        );
    }

    #[test]
    fn parse_task_command_does_not_match_approval() {
        assert_eq!(parse_task_command("cancel appr_123"), None);
    }
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
                _should_post_ack,
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

            // Enforce single-workspace per deployment.
            match db::get_settings(&state.pool).await {
                Ok(settings) => {
                    if is_proactive && !settings.slack_proactive_enabled {
                        warn!(
                            workspace_id = %team_id,
                            channel_id = %channel,
                            user_id = %user,
                            reason = "proactive mode is disabled",
                            "ignored proactive slack message"
                        );
                        if let Err(err) = db::enqueue_ignored_task(
                            &state.pool,
                            "slack",
                            &team_id,
                            &channel,
                            &thread_ts,
                            &ts,
                            &user,
                            &text,
                            "proactive mode is disabled",
                            true,
                        )
                        .await
                        {
                            warn!(error = %err, "failed to log ignored proactive task");
                        }
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
                            if is_proactive {
                                warn!(
                                    workspace_id = %team_id,
                                    channel_id = %channel,
                                    user_id = %user,
                                    reason = "workspace id mismatch",
                                    "ignored proactive slack message"
                                );
                                if let Err(err) = db::enqueue_ignored_task(
                                    &state.pool,
                                    "slack",
                                    &team_id,
                                    &channel,
                                    &thread_ts,
                                    &ts,
                                    &user,
                                    &text,
                                    "workspace id mismatch",
                                    true,
                                )
                                .await
                                {
                                    warn!(error = %err, "failed to log ignored proactive task");
                                }
                            }
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
                        if is_proactive {
                            warn!(
                                workspace_id = %team_id,
                                channel_id = %channel,
                                user_id = %user,
                                reason = "user not in allow list",
                                "ignored proactive slack message"
                            );
                            if let Err(err) = db::enqueue_ignored_task(
                                &state.pool,
                                "slack",
                                &team_id,
                                &channel,
                                &thread_ts,
                                &ts,
                                &user,
                                &text,
                                "user not in allow list",
                                true,
                            )
                            .await
                            {
                                warn!(error = %err, "failed to log ignored proactive task");
                            }
                        }
                        if !is_proactive {
                            if let Ok(Some(token)) =
                                crate::secrets::load_slack_bot_token_opt(&state).await
                            {
                                let slack = SlackClient::new(state.http.clone(), token);
                                let msg =
                                    "Sorry, you're not authorized to use this FastClaw instance.";
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
                            if is_proactive {
                                warn!(
                                    workspace_id = %team_id,
                                    channel_id = %channel,
                                    user_id = %user,
                                    reason = "channel not in allow list",
                                    "ignored proactive slack message"
                                );
                                if let Err(err) = db::enqueue_ignored_task(
                                    &state.pool,
                                    "slack",
                                    &team_id,
                                    &channel,
                                    &thread_ts,
                                    &ts,
                                    &user,
                                    &text,
                                    "channel not in allow list",
                                    true,
                                )
                                .await
                                {
                                    warn!(error = %err, "failed to log ignored proactive task");
                                }
                            }
                            if !is_proactive {
                                if let Ok(Some(token)) =
                                    crate::secrets::load_slack_bot_token_opt(&state).await
                                {
                                    let slack = SlackClient::new(state.http.clone(), token);
                                    let msg =
                                        "Sorry, this FastClaw instance isn't enabled in this channel.";
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
                        warn!(
                            workspace_id = %team_id,
                            channel_id = %channel,
                            user_id = %user,
                            reason = "settings load failed",
                            "ignored proactive slack message"
                        );
                        if let Err(err) = db::enqueue_ignored_task(
                            &state.pool,
                            "slack",
                            &team_id,
                            &channel,
                            &thread_ts,
                            &ts,
                            &user,
                            &text,
                            "settings load failed",
                            true,
                        )
                        .await
                        {
                            warn!(error = %err, "failed to log ignored proactive task");
                        }
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
                                warn!(
                                    workspace_id = %team_id,
                                    channel_id = %channel,
                                    user_id = %user,
                                    reason = "message directly mentioned the bot",
                                    "ignored proactive slack message"
                                );
                                if let Err(err) = db::enqueue_ignored_task(
                                    &state.pool,
                                    "slack",
                                    &team_id,
                                    &channel,
                                    &thread_ts,
                                    &ts,
                                    &user,
                                    &text,
                                    "message directly mentioned the bot",
                                    true,
                                )
                                .await
                                {
                                    warn!(error = %err, "failed to log ignored proactive task");
                                }
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

            let mut prompt = clamp_chars(
                if strip_mentions {
                    strip_leading_mentions(&text)
                } else {
                    text.trim().to_string()
                },
                4_000,
            );

            if allow_approval_commands {
                if let Some(cmd) = parse_task_command(&prompt) {
                    let response = match handle_task_command(&state, cmd).await {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(error = %err, "failed to handle task command");
                            "I couldn't process that task command right now.".to_string()
                        }
                    };
                    let response = redact_user_message(&response);
                    if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(&state).await
                    {
                        let slack = SlackClient::new(state.http.clone(), token);
                        let _ = slack
                            .post_message(&channel, thread_opt(&thread_ts), response.trim())
                            .await;
                    }
                    return (StatusCode::OK, "").into_response();
                }

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

            let _task_id = match db::enqueue_task_with_files(
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

            if is_proactive {
                info!(
                    task_id = _task_id,
                    workspace_id = %team_id,
                    channel_id = %channel,
                    thread_ts = %thread_ts,
                    event_ts = %ts,
                    requested_by = %user,
                    "enqueued proactive slack task"
                );
            }

            if !is_proactive {
                let task_url = task_trace_url(&state, _task_id);
                let task_msg = task_link_message(_task_id, &task_url);
                if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(&state).await {
                    let slack = SlackClient::new(state.http.clone(), token);
                    let _ = slack
                        .post_message(&channel, thread_opt(&thread_ts), task_msg.as_str())
                        .await;
                }
            }

            // Wake the worker immediately (avoid visible "queueing" latency).
            state.task_notify.notify_waiters();

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
            || text.starts_with("/fastclaw")
            || text.starts_with(&format!("/grail@{user}"))
            || text.starts_with(&format!("/fastclaw@{user}"))
    } else {
        text.starts_with("/grail") || text.starts_with("/fastclaw")
    };

    if !directed {
        return (StatusCode::OK, "").into_response();
    }

    let prompt = clamp_chars(cleaned, 4_000);
    if prompt.is_empty() {
        return (StatusCode::OK, "").into_response();
    }

    if let Some(cmd) = parse_task_command(&prompt) {
        let response = match handle_task_command(&state, cmd).await {
            Ok(msg) => msg,
            Err(err) => {
                warn!(error = %err, "failed to handle telegram task command");
                "I couldn't process that task command right now.".to_string()
            }
        };
        let response = redact_user_message(&response);
        let tg = crate::telegram::TelegramClient::new(state.http.clone(), token.clone());
        let _ = tg
            .send_message(&stored.chat_id, Some(msg.message_id), response.trim())
            .await;
        return (StatusCode::OK, "").into_response();
    }

    let _task_id = match db::enqueue_task(
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

    let task_url = task_trace_url(&state, _task_id);
    let task_msg = task_link_message(_task_id, &task_url);
    let tg = crate::telegram::TelegramClient::new(state.http.clone(), token);
    let _ = tg
        .send_message(&stored.chat_id, Some(msg.message_id), task_msg.as_str())
        .await;

    // Wake the worker immediately (avoid visible "queueing" latency).
    state.task_notify.notify_waiters();

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
            || first.starts_with("/fastclaw")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskCommand {
    ListRunning,
    Show { task_id: i64 },
    Cancel { task_id: i64 },
    Retry { task_id: i64 },
}

fn parse_task_command(text: &str) -> Option<TaskCommand> {
    let t = text
        .trim()
        .trim_end_matches(|c: char| c == '?' || c == '!' || c == '.')
        .to_ascii_lowercase();
    if t.is_empty() {
        return None;
    }

    if matches!(
        t.as_str(),
        "tasks"
            | "list tasks"
            | "running tasks"
            | "active tasks"
            | "show tasks"
            | "show running tasks"
            | "show active tasks"
            | "what's running"
            | "what is running"
            | "what tasks are running"
            | "what task is running"
            | "which tasks are running"
    ) {
        return Some(TaskCommand::ListRunning);
    }

    static TASK_ID_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\btask(?:\s+id)?\s*#?\s*(\d+)\b")
            .expect("task command task id regex must compile")
    });
    static TASK_RETRY_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:retry|rerun|re-run)\b")
            .expect("task command retry regex must compile")
    });
    static TASK_CANCEL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:stop|cancel|abort|kill)\b")
            .expect("task command cancel regex must compile")
    });

    let task_id = TASK_ID_RE
        .captures(&t)
        .and_then(|caps| caps.get(1))
        .and_then(|m| i64::from_str(m.as_str()).ok())
        .filter(|id| *id > 0)?;

    if TASK_RETRY_RE.is_match(&t) {
        return Some(TaskCommand::Retry { task_id });
    }

    if TASK_CANCEL_RE.is_match(&t) {
        return Some(TaskCommand::Cancel { task_id });
    }

    Some(TaskCommand::Show { task_id })
}

fn format_unix_ts(ts: i64) -> String {
    match chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => ts.to_string(),
    }
}

fn format_unix_ts_opt(ts: Option<i64>) -> String {
    ts.map(format_unix_ts).unwrap_or_else(|| "n/a".to_string())
}

fn truncate_preview(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out: String = trimmed.chars().take(max_chars).collect();
    if trimmed.chars().count() > max_chars {
        out.push('…');
    }
    out.replace('\n', " ")
}

fn redact_user_message(text: &str) -> String {
    let (redacted, was_redacted) = crate::secrets::redact_secrets(text);
    if was_redacted {
        warn!("redacted secrets from task command response");
    }
    redacted
}

async fn handle_task_command(state: &AppState, cmd: TaskCommand) -> anyhow::Result<String> {
    match cmd {
        TaskCommand::ListRunning => {
            let active = db::list_active_tasks(&state.pool, 20).await?;
            let queued: i64 =
                sqlx::query("SELECT COUNT(*) AS c FROM tasks WHERE status = 'queued'")
                    .fetch_one(&state.pool)
                    .await?
                    .get("c");

            if active.is_empty() {
                return Ok(format!(
                    "No tasks are currently running. Queue depth: {queued}."
                ));
            }

            let mut lines: Vec<String> = Vec::new();
            for (task_id, started_at) in active {
                if let Some(task) = db::get_task(&state.pool, task_id).await? {
                    lines.push(format!(
                        "- #{task_id}: {} via {} (started {})",
                        task.status,
                        task.provider,
                        format_unix_ts(started_at),
                    ));
                } else {
                    lines.push(format!(
                        "- #{task_id}: running (started {})",
                        format_unix_ts(started_at),
                    ));
                }
            }

            Ok(format!(
                "Running tasks:\n{}\nQueue depth: {queued}\nUse `task <id>`, `stop task <id>`, or `retry task <id>`.",
                lines.join("\n")
            ))
        }
        TaskCommand::Show { task_id } => {
            let Some(task) = db::get_task(&state.pool, task_id).await? else {
                return Ok(format!("Task #{task_id} was not found."));
            };

            let mut msg = format!(
                "Task #{}\nStatus: {}\nProvider: {}\nCreated: {}\nStarted: {}\nFinished: {}\nLink: {}",
                task.id,
                task.status,
                task.provider,
                format_unix_ts(task.created_at),
                format_unix_ts_opt(task.started_at),
                format_unix_ts_opt(task.finished_at),
                task_trace_url(state, task.id),
            );
            if let Some(err) = task.error_text.as_deref() {
                let preview = truncate_preview(err, 240);
                if !preview.is_empty() {
                    msg.push_str(&format!("\nError: {preview}"));
                }
            }
            if let Some(result) = task.result_text.as_deref() {
                let preview = truncate_preview(result, 240);
                if !preview.is_empty() {
                    msg.push_str(&format!("\nResult preview: {preview}"));
                }
            }
            Ok(msg)
        }
        TaskCommand::Cancel { task_id } => {
            let Some(task) = db::get_task(&state.pool, task_id).await? else {
                return Ok(format!("Task #{task_id} was not found."));
            };

            if !matches!(task.status.as_str(), "queued" | "running") {
                return Ok(format!(
                    "Task #{task_id} is `{}` and cannot be stopped. Only `queued` and `running` tasks can be stopped.",
                    task.status
                ));
            }

            if db::cancel_task(&state.pool, task_id).await? {
                let next_status = if task.status == "queued" {
                    "cancelled"
                } else {
                    "cancel_requested"
                };
                return Ok(format!(
                    "Task #{task_id} updated: `{}` -> `{next_status}`.\nLink: {}",
                    task.status,
                    task_trace_url(state, task_id),
                ));
            }

            let current = db::get_task_status(&state.pool, task_id)
                .await?
                .unwrap_or_else(|| "missing".to_string());
            Ok(format!(
                "Task #{task_id} could not be stopped because its status is now `{current}`."
            ))
        }
        TaskCommand::Retry { task_id } => {
            let Some(task) = db::get_task(&state.pool, task_id).await? else {
                return Ok(format!("Task #{task_id} was not found."));
            };

            if !matches!(task.status.as_str(), "failed" | "cancelled") {
                return Ok(format!(
                    "Task #{task_id} is `{}` and cannot be retried. Only `failed` or `cancelled` tasks can be retried.",
                    task.status
                ));
            }

            if db::retry_task(&state.pool, task_id).await? {
                state.task_notify.notify_waiters();
                return Ok(format!(
                    "Task #{task_id} has been re-queued.\nLink: {}",
                    task_trace_url(state, task_id),
                ));
            }

            let current = db::get_task_status(&state.pool, task_id)
                .await?
                .unwrap_or_else(|| "missing".to_string());
            Ok(format!(
                "Task #{task_id} could not be retried because its status is now `{current}`."
            ))
        }
    }
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

pub async fn run_github_device_login_flow(
    pool: SqlitePool,
    login_id: String,
    crypto: Option<Arc<Crypto>>,
    data_dir: std::path::PathBuf,
    github_base: String,
    client_id: String,
    device_code: String,
    interval_sec: u64,
    expires_in_sec: u64,
) -> anyhow::Result<()> {
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;

    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(expires_in_sec.max(60).min(60 * 30) + 60);
    let mut interval = interval_sec.max(1).min(30);

    loop {
        // Check cancellation.
        let status = db::get_github_device_login(&pool, &login_id)
            .await?
            .map(|l| l.status)
            .unwrap_or_else(|| "missing".to_string());
        if status != "pending" {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            let now = chrono::Utc::now().timestamp();
            db::update_github_device_login_status(
                &pool,
                &login_id,
                "failed",
                Some("github device login timed out"),
                Some(now),
            )
            .await?;
            return Ok(());
        }

        match crate::github_login::poll_for_token(&http, &github_base, &client_id, &device_code)
            .await
        {
            Ok(crate::github_login::TokenPoll::Pending) => {
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
            Ok(crate::github_login::TokenPoll::SlowDown) => {
                interval = (interval + 5).min(30);
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
            Ok(crate::github_login::TokenPoll::Success { access_token }) => {
                // Clean up any old token artifacts first.
                let _ = db::delete_secret(&pool, "github_token").await;
                let token_path = data_dir.join("github").join("token.txt");
                let _ = tokio::fs::remove_file(&token_path).await;

                if let Some(crypto) = crypto.as_deref() {
                    let (nonce, ciphertext) =
                        crypto.encrypt(b"github_token", access_token.as_bytes())?;
                    db::upsert_secret(&pool, "github_token", &nonce, &ciphertext).await?;
                } else {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    #[cfg(unix)]
                    use std::os::unix::fs::OpenOptionsExt;

                    if let Some(parent) = token_path.parent() {
                        tokio::fs::create_dir_all(parent)
                            .await
                            .with_context(|| format!("create {}", parent.display()))?;
                    }

                    let token = access_token.clone();
                    let token_path2 = token_path.clone();
                    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                        let mut options = OpenOptions::new();
                        options.truncate(true).write(true).create(true);
                        #[cfg(unix)]
                        {
                            options.mode(0o600);
                        }
                        let mut f = options
                            .open(&token_path2)
                            .with_context(|| format!("open {}", token_path2.display()))?;
                        f.write_all(token.as_bytes())
                            .with_context(|| format!("write {}", token_path2.display()))?;
                        f.write_all(b"\n")
                            .with_context(|| format!("write {}", token_path2.display()))?;
                        f.flush()
                            .with_context(|| format!("flush {}", token_path2.display()))?;
                        Ok(())
                    })
                    .await
                    .context("spawn_blocking write github token")??;
                }

                let now = chrono::Utc::now().timestamp();
                db::update_github_device_login_status(
                    &pool,
                    &login_id,
                    "completed",
                    None,
                    Some(now),
                )
                .await?;
                return Ok(());
            }
            Ok(crate::github_login::TokenPoll::Failed { error, description }) => {
                let now = chrono::Utc::now().timestamp();
                let msg = if description.trim().is_empty() {
                    error
                } else {
                    format!("{error}: {description}")
                };
                db::update_github_device_login_status(
                    &pool,
                    &login_id,
                    "failed",
                    Some(&msg),
                    Some(now),
                )
                .await?;
                return Ok(());
            }
            Err(err) => {
                let now = chrono::Utc::now().timestamp();
                db::update_github_device_login_status(
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

pub async fn list_context_files(root: &std::path::Path) -> anyhow::Result<Vec<ContextFileRow>> {
    let mut out: Vec<ContextFileRow> = Vec::new();

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
            out.push(ContextFileRow {
                path: rel,
                bytes: format!("{}", meta.len()),
            });
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[derive(Debug)]
struct ContextFileRow {
    path: String,
    bytes: String,
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

// ---------------------------------------------------------------------------
// WhatsApp webhook
// ---------------------------------------------------------------------------

/// GET handler for WhatsApp webhook verification (subscribe challenge).
async fn whatsapp_webhook_verify(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let mode = params.get("hub.mode").map(|s| s.as_str()).unwrap_or("");
    let token = params
        .get("hub.verify_token")
        .map(|s| s.as_str())
        .unwrap_or("");
    let challenge = params
        .get("hub.challenge")
        .map(|s| s.as_str())
        .unwrap_or("");

    if mode != "subscribe" {
        return (StatusCode::FORBIDDEN, "invalid mode").into_response();
    }

    let verify_token = match crate::secrets::load_whatsapp_verify_token_opt(&state).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::FORBIDDEN, "verify token not configured").into_response(),
    };

    if token != verify_token {
        return (StatusCode::FORBIDDEN, "token mismatch").into_response();
    }

    (StatusCode::OK, challenge.to_string()).into_response()
}

/// POST handler for WhatsApp inbound messages.
async fn whatsapp_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let settings = match db::get_settings(&state.pool).await {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    if !settings.allow_whatsapp {
        return (StatusCode::OK, "whatsapp disabled").into_response();
    }

    let app_secret = match crate::secrets::load_whatsapp_app_secret_opt(&state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                "whatsapp app secret not configured",
            )
                .into_response();
        }
        Err(err) => {
            error!(error = %err, "failed to load whatsapp app secret");
            return (StatusCode::INTERNAL_SERVER_ERROR, "secret error").into_response();
        }
    };
    let signature_header = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::whatsapp::verify_signature(&app_secret, &body, signature_header) {
        return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
    }

    let payload: crate::whatsapp::WhatsAppWebhookPayload = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "invalid whatsapp payload");
            return (StatusCode::BAD_REQUEST, "invalid payload").into_response();
        }
    };

    let entries = match payload.entry {
        Some(e) => e,
        None => return (StatusCode::OK, "").into_response(),
    };

    for entry in entries {
        let changes = match entry.changes {
            Some(c) => c,
            None => continue,
        };
        for change in changes {
            let value = match change.value {
                Some(v) => v,
                None => continue,
            };
            let messages = match value.messages {
                Some(m) => m,
                None => continue,
            };
            for msg in messages {
                if msg.kind != "text" {
                    continue;
                }
                let text = match msg.text {
                    Some(ref t) => t.body.clone(),
                    None => continue,
                };
                let from = &msg.from;

                // Check allow list.
                let allowed = parse_allow_from(&settings.whatsapp_allow_from);
                if !allowed.is_empty() && !allowed.contains(from.as_str()) {
                    warn!(from = %from, "whatsapp user not in allow list");
                    continue;
                }

                // Deduplicate.
                let event_id = format!("whatsapp:{}", msg.id);
                let wid = "whatsapp";
                match db::try_mark_event_processed(&state.pool, wid, &event_id).await {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(err) => {
                        error!(error = %err, "whatsapp dedup check failed");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "dedup error").into_response();
                    }
                }

                let prompt = clamp_chars(text, 4_000);
                if prompt.is_empty() {
                    continue;
                }

                if let Some(cmd) = parse_task_command(&prompt) {
                    let response = match handle_task_command(&state, cmd).await {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(error = %err, "failed to handle whatsapp task command");
                            "I couldn't process that task command right now.".to_string()
                        }
                    };
                    let response = redact_user_message(&response);

                    let access_token = match crate::secrets::load_whatsapp_access_token_opt(&state)
                        .await
                    {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            warn!("WHATSAPP_ACCESS_TOKEN missing for command response");
                            let _ = db::unmark_event_processed(&state.pool, wid, &event_id).await;
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "whatsapp access token missing",
                            )
                                .into_response();
                        }
                        Err(err) => {
                            warn!(error = %err, "failed to load WHATSAPP_ACCESS_TOKEN");
                            let _ = db::unmark_event_processed(&state.pool, wid, &event_id).await;
                            return (StatusCode::INTERNAL_SERVER_ERROR, "secret error")
                                .into_response();
                        }
                    };
                    let phone_id = match crate::secrets::load_whatsapp_phone_number_id_opt(&state)
                        .await
                    {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            warn!("WHATSAPP_PHONE_NUMBER_ID missing for command response");
                            let _ = db::unmark_event_processed(&state.pool, wid, &event_id).await;
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "whatsapp phone id missing",
                            )
                                .into_response();
                        }
                        Err(err) => {
                            warn!(error = %err, "failed to load WHATSAPP_PHONE_NUMBER_ID");
                            let _ = db::unmark_event_processed(&state.pool, wid, &event_id).await;
                            return (StatusCode::INTERNAL_SERVER_ERROR, "secret error")
                                .into_response();
                        }
                    };

                    let wa = crate::whatsapp::WhatsAppClient::new(
                        state.http.clone(),
                        access_token,
                        phone_id,
                    );
                    if let Err(err) = wa.send_message(from, response.trim()).await {
                        error!(
                            error = %err,
                            from = %from,
                            message_id = %msg.id,
                            "failed to send whatsapp task command response"
                        );
                        let _ = db::unmark_event_processed(&state.pool, wid, &event_id).await;
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to send command response",
                        )
                            .into_response();
                    }

                    continue;
                }

                // channel_id = sender phone number (used to reply back).
                if let Err(err) = db::enqueue_task(
                    &state.pool,
                    "whatsapp",
                    wid,
                    from,
                    &msg.id,
                    &msg.id,
                    from,
                    &prompt,
                )
                .await
                {
                    error!(
                        error = %err,
                        from = %from,
                        message_id = %msg.id,
                        "failed to enqueue whatsapp task"
                    );
                    let _ = db::unmark_event_processed(&state.pool, wid, &event_id).await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, "enqueue failed").into_response();
                }

                state.task_notify.notify_waiters();
            }
        }
    }

    (StatusCode::OK, "").into_response()
}

// ---------------------------------------------------------------------------
// Discord webhook
// ---------------------------------------------------------------------------

async fn discord_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Verify Ed25519 signature.
    let public_key = match crate::secrets::load_discord_public_key_opt(&state).await {
        Ok(Some(k)) => k,
        _ => return (StatusCode::UNAUTHORIZED, "public key not configured").into_response(),
    };

    let signature = headers
        .get("X-Signature-Ed25519")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let timestamp = headers
        .get("X-Signature-Timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if signature.is_empty() || timestamp.is_empty() {
        return (StatusCode::UNAUTHORIZED, "missing signature headers").into_response();
    }
    if !crate::discord::is_timestamp_fresh(timestamp, 300) {
        return (StatusCode::UNAUTHORIZED, "stale signature timestamp").into_response();
    }
    if !crate::discord::verify_discord_signature(&public_key, signature, timestamp, &body) {
        return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
    }

    let interaction: crate::discord::DiscordInteraction = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "invalid discord payload");
            return (StatusCode::BAD_REQUEST, "invalid payload").into_response();
        }
    };

    // PING (type 1) — Discord verification handshake.
    if interaction.kind == 1 {
        let pong = serde_json::json!({ "type": 1 });
        return axum::response::Json(pong).into_response();
    }

    let settings = match db::get_settings(&state.pool).await {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    if !settings.allow_discord {
        return (StatusCode::OK, "discord disabled").into_response();
    }

    // Handle APPLICATION_COMMAND (type 2) interactions.
    if interaction.kind == 2 {
        let channel_id = interaction.channel_id.as_deref().unwrap_or("");
        let user_id = interaction
            .member
            .as_ref()
            .and_then(|m| m.user.as_ref())
            .or(interaction.user.as_ref())
            .map(|u| u.id.as_str())
            .unwrap_or("unknown");

        // Check allow list.
        let allowed = parse_allow_from(&settings.discord_allow_from);
        if !allowed.is_empty() && !allowed.contains(user_id) {
            warn!(user = %user_id, "discord user not in allow list");
            let resp = serde_json::json!({
                "type": 4,
                "data": { "content": "You are not authorized to use this bot." }
            });
            return axum::response::Json(resp).into_response();
        }

        // Extract text from the interaction data.
        let text = interaction
            .data
            .as_ref()
            .and_then(|d| d.get("options"))
            .and_then(|o| o.as_array())
            .and_then(|arr| arr.first())
            .and_then(|o| o.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let prompt = clamp_chars(text, 4_000);

        let interaction_id = interaction.id.as_deref().unwrap_or("");

        // Deduplicate.
        let event_id = format!("discord:{}", interaction_id);
        match db::try_mark_event_processed(&state.pool, "discord", &event_id).await {
            Ok(true) => {}
            Ok(false) => {
                let resp = serde_json::json!({
                    "type": 4,
                    "data": { "content": "Already processing this request." }
                });
                return axum::response::Json(resp).into_response();
            }
            Err(err) => {
                error!(error = %err, "discord dedup check failed");
                let resp = serde_json::json!({
                    "type": 4,
                    "data": { "content": "Temporary server error. Please retry." }
                });
                return axum::response::Json(resp).into_response();
            }
        }

        if let Some(cmd) = parse_task_command(&prompt) {
            let response = match handle_task_command(&state, cmd).await {
                Ok(msg) => msg,
                Err(err) => {
                    warn!(error = %err, "failed to handle discord task command");
                    "I couldn't process that task command right now.".to_string()
                }
            };
            let response = redact_user_message(&response);
            let resp = serde_json::json!({
                "type": 4,
                "data": { "content": response }
            });
            return axum::response::Json(resp).into_response();
        }

        if !prompt.is_empty() {
            if let Err(err) = db::enqueue_task(
                &state.pool,
                "discord",
                "discord",
                channel_id,
                interaction_id,
                interaction_id,
                user_id,
                &prompt,
            )
            .await
            {
                error!(
                    error = %err,
                    interaction_id = %interaction_id,
                    user_id = %user_id,
                    "failed to enqueue discord task"
                );
                let _ = db::unmark_event_processed(&state.pool, "discord", &event_id).await;
                let resp = serde_json::json!({
                    "type": 4,
                    "data": { "content": "Failed to queue request. Please retry." }
                });
                return axum::response::Json(resp).into_response();
            }
            state.task_notify.notify_waiters();
        }

        // ACK with deferred response.
        let resp = serde_json::json!({
            "type": 5 // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
        });
        return axum::response::Json(resp).into_response();
    }

    (StatusCode::OK, "").into_response()
}

// ---------------------------------------------------------------------------
// MS Teams webhook
// ---------------------------------------------------------------------------

async fn msteams_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let settings = match db::get_settings(&state.pool).await {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    if !settings.allow_msteams {
        return (StatusCode::OK, "msteams disabled").into_response();
    }

    let app_id = match crate::secrets::load_msteams_app_id_opt(&state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "teams app id not configured").into_response()
        }
        Err(err) => {
            error!(error = %err, "failed to load teams app id");
            return (StatusCode::INTERNAL_SERVER_ERROR, "secret error").into_response();
        }
    };
    let authorization_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Err(err) =
        crate::msteams::verify_incoming_token(&state.http, &app_id, authorization_header).await
    {
        warn!(error = %err, "invalid teams authorization token");
        return (StatusCode::UNAUTHORIZED, "invalid authorization").into_response();
    }

    let activity: crate::msteams::TeamsActivity = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, "invalid teams payload");
            return (StatusCode::BAD_REQUEST, "invalid payload").into_response();
        }
    };

    // Only process "message" activities.
    if activity.kind != "message" {
        return (StatusCode::OK, "").into_response();
    }

    let text = match activity.text.as_deref() {
        Some(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => return (StatusCode::OK, "").into_response(),
    };

    let from_id = activity
        .from
        .as_ref()
        .map(|f| f.id.as_str())
        .unwrap_or("unknown");

    // Check allow list.
    let allowed = parse_allow_from(&settings.msteams_allow_from);
    if !allowed.is_empty() && !allowed.contains(from_id) {
        warn!(from = %from_id, "teams user not in allow list");
        return (StatusCode::OK, "").into_response();
    }

    let conversation_id = activity
        .conversation
        .as_ref()
        .map(|c| c.id.as_str())
        .unwrap_or("");
    let activity_id = activity.id.as_deref().unwrap_or("");
    let service_url = activity.service_url.as_deref().unwrap_or("");

    // Store service_url|activity_id in thread_ts for reply routing.
    let thread_ts = format!("{}|{}", service_url, activity_id);

    // Deduplicate.
    let event_id = format!("teams:{}", activity_id);
    match db::try_mark_event_processed(&state.pool, "msteams", &event_id).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::OK, "").into_response(),
        Err(err) => {
            warn!(error = %err, "teams dedup check failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "dedup error").into_response();
        }
    }

    let prompt = clamp_chars(text, 4_000);
    if prompt.is_empty() {
        return (StatusCode::OK, "").into_response();
    }

    if let Some(cmd) = parse_task_command(&prompt) {
        let response = match handle_task_command(&state, cmd).await {
            Ok(msg) => msg,
            Err(err) => {
                warn!(error = %err, "failed to handle teams task command");
                "I couldn't process that task command right now.".to_string()
            }
        };
        let response = redact_user_message(&response);

        let app_password = match crate::secrets::load_msteams_app_password_opt(&state).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                warn!("MSTEAMS_APP_PASSWORD missing for command response");
                let _ = db::unmark_event_processed(&state.pool, "msteams", &event_id).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "teams app password missing",
                )
                    .into_response();
            }
            Err(err) => {
                warn!(error = %err, "failed to load teams app password");
                let _ = db::unmark_event_processed(&state.pool, "msteams", &event_id).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, "secret error").into_response();
            }
        };

        let teams =
            crate::msteams::TeamsClient::new(state.http.clone(), app_id.clone(), app_password);
        let send_result = if !activity_id.trim().is_empty() {
            teams
                .reply_to_activity(service_url, conversation_id, activity_id, response.trim())
                .await
        } else {
            teams
                .send_message(service_url, conversation_id, response.trim())
                .await
        };

        if let Err(err) = send_result {
            error!(
                error = %err,
                activity_id = %activity_id,
                from_id = %from_id,
                "failed to send teams task command response"
            );
            let _ = db::unmark_event_processed(&state.pool, "msteams", &event_id).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to send command response",
            )
                .into_response();
        }

        return (StatusCode::OK, "").into_response();
    }

    if let Err(err) = db::enqueue_task(
        &state.pool,
        "msteams",
        "msteams",
        conversation_id,
        &thread_ts,
        &thread_ts,
        from_id,
        &prompt,
    )
    .await
    {
        error!(
            error = %err,
            activity_id = %activity_id,
            from_id = %from_id,
            "failed to enqueue teams task"
        );
        let _ = db::unmark_event_processed(&state.pool, "msteams", &event_id).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, "enqueue failed").into_response();
    }

    state.task_notify.notify_waiters();

    (StatusCode::OK, "").into_response()
}
