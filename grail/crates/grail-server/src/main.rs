mod bootstrap;
mod codex;
mod config;
mod crypto;
mod db;
mod models;
mod slack;
mod templates;
mod worker;

	use std::sync::Arc;
	use std::time::Duration;

	use anyhow::Context;
use askama::Template;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Form, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use serde::Deserialize;
use sqlx::{Row, SqlitePool};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::crypto::{Crypto, parse_master_key};
use crate::models::PermissionsMode;
use crate::slack::{verify_slack_signature, SlackClient};
use crate::templates::{SettingsTemplate, StatusTemplate, TasksTemplate};

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
    slack: Option<SlackClient>,
    crypto: Option<Arc<Crypto>>,
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
    let slack = config
        .slack_bot_token
        .clone()
        .map(|t| SlackClient::new(http, t));

    let state = AppState {
        config: config.clone(),
        pool,
        slack,
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
    };

    // Background worker (single concurrency).
    tokio::spawn(worker::worker_loop(state.clone()));

    let admin = Router::new()
        .route("/", get(|| async { Redirect::to("/admin/status") }))
        .route("/status", get(admin_status))
        .route("/settings", get(admin_settings_get).post(admin_settings_post))
        .route("/secrets/openai", post(admin_set_openai_api_key))
        .route("/secrets/openai/delete", post(admin_delete_openai_api_key))
        .route("/tasks", get(admin_tasks))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_basic_auth,
        ));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/slack/events", post(slack_events))
        .nest("/admin", admin)
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
        Ok(true) => next.run(req).await,
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

async fn admin_status(State(state): State<AppState>) -> AppResult<Html<String>> {
    let settings = db::get_settings(&state.pool).await?;
    let queue_depth: i64 = sqlx::query("SELECT COUNT(*) AS c FROM tasks WHERE status = 'queued'")
        .fetch_one(&state.pool)
        .await?
        .get::<i64, _>("c");

    let tpl = StatusTemplate {
        active: "status",
        slack_signing_secret_set: state.config.slack_signing_secret.is_some(),
        slack_bot_token_set: state.config.slack_bot_token.is_some(),
        openai_api_key_set: openai_api_key_configured(&state).await?,
        master_key_set: state.crypto.is_some(),
        queue_depth,
        permissions_mode: settings.permissions_mode.as_db_str().to_string(),
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
        allow_slack_mcp: settings.allow_slack_mcp,
        allow_context_writes: settings.allow_context_writes,
        shell_network_access: settings.shell_network_access,
        master_key_set: state.crypto.is_some(),
        openai_api_key_set: openai_api_key_configured(&state).await?,
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
    allow_slack_mcp: Option<String>,
    allow_context_writes: Option<String>,
    shell_network_access: Option<String>,
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

    settings.allow_slack_mcp = form.allow_slack_mcp.is_some();
    settings.allow_context_writes = form.allow_context_writes.is_some();
    settings.shell_network_access = form.shell_network_access.is_some();

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

fn normalize_optional_string(v: Option<String>) -> Option<String> {
    let Some(s) = v else { return None };
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

async fn openai_api_key_configured(state: &AppState) -> anyhow::Result<bool> {
    if std::env::var("OPENAI_API_KEY").is_ok() {
        return Ok(true);
    }
    Ok(db::read_secret(&state.pool, "openai_api_key")
        .await?
        .is_some())
}

async fn admin_tasks(State(state): State<AppState>) -> AppResult<Html<String>> {
    let tasks = db::list_recent_tasks(&state.pool, 50).await?;
    let tpl = TasksTemplate {
        active: "tasks",
        tasks: tasks.into_iter().map(Into::into).collect(),
    };
    Ok(Html(tpl.render()?))
}

async fn slack_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(secret) = state.config.slack_signing_secret.as_deref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "slack not configured").into_response();
    };

    if let Err(err) = verify_slack_signature(secret, &headers, &body) {
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
            return axum::Json(serde_json::json!({ "challenge": challenge })).into_response();
        }
        SlackEnvelope::EventCallback {
            team_id,
            event_id,
            event,
        } => {
            let SlackEvent::AppMention {
                user,
                text,
                ts,
                channel,
                thread_ts,
            } = event
            else {
                return (StatusCode::OK, "").into_response();
            };

            let processed = match db::try_mark_event_processed(&state.pool, &team_id, &event_id)
                .await
            {
                Ok(v) => v,
                Err(err) => {
                    error!(error = %err, "failed to dedupe event");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
                }
            };

            if !processed {
                return (StatusCode::OK, "").into_response();
            }

            let thread_ts = thread_ts.unwrap_or_else(|| ts.clone());
            let prompt = strip_leading_mentions(&text);

            let task_id = match db::enqueue_task(
                &state.pool,
                &team_id,
                &channel,
                &thread_ts,
                &ts,
                &user,
                &prompt,
            )
            .await
            {
                Ok(id) => id,
                Err(err) => {
                    error!(error = %err, "failed to enqueue task");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
                }
            };

            // Ack immediately, post "Queued" asynchronously.
            if let Some(slack) = state.slack.clone() {
                let queued_text = format!("Queued as #{task_id}. I'll start soon.");
                tokio::spawn(async move {
                    if let Err(err) = slack.post_message(&channel, &thread_ts, &queued_text).await {
                        warn!(error = %err, "failed to post queued message");
                    }
                });
            }

            (StatusCode::OK, "").into_response()
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
    },

    #[serde(other)]
    Other,
}
