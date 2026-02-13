use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::models::{PermissionsMode, Settings, Task};

#[derive(Debug, Clone)]
pub struct CodexTurnOutput {
    pub agent_message_text: String,
}

#[derive(Debug, Clone)]
pub struct CodexTurnEvent {
    pub event_type: String,
    pub level: String,
    pub message: String,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct BrowserEnvConfig {
    pub enabled: bool,
    pub cdp_url: String,
    pub cdp_port: String,
    pub novnc_enabled: bool,
    pub novnc_url: String,
    pub novnc_port: String,
    pub profile_name: String,
    pub home: String,
}

impl BrowserEnvConfig {
    pub fn from_env() -> Self {
        let enabled = env_bool("GRAIL_BROWSER_ENABLED") || env_bool("OPENCLAW_BROWSER_ENABLED");
        let cdp_port = normalize_port(
            env_first_value("GRAIL_BROWSER_CDP_PORT", "OPENCLAW_BROWSER_CDP_PORT"),
            "9222",
        );
        let novnc_enabled = enabled
            && (env_bool("GRAIL_BROWSER_ENABLE_NOVNC")
                || env_bool("OPENCLAW_BROWSER_ENABLE_NOVNC"));
        let novnc_port = normalize_port(
            env_first_value("GRAIL_BROWSER_NOVNC_PORT", "OPENCLAW_BROWSER_NOVNC_PORT"),
            "6080",
        );
        let cdp_url_default = format!("http://127.0.0.1:{cdp_port}");
        let novnc_url_default =
            format!("http://127.0.0.1:{novnc_port}/vnc.html?autoconnect=1&resize=remote");

        Self {
            enabled,
            cdp_url: normalize_http_url(
                env_first_value("GRAIL_BROWSER_CDP_URL", "OPENCLAW_BROWSER_CDP_URL"),
                &cdp_url_default,
            ),
            cdp_port,
            novnc_enabled,
            novnc_port: novnc_port.clone(),
            novnc_url: if novnc_enabled {
                normalize_http_url(
                    env_first_value("GRAIL_BROWSER_NOVNC_URL", "OPENCLAW_BROWSER_NOVNC_URL"),
                    &novnc_url_default,
                )
            } else {
                String::new()
            },
            profile_name: {
                normalize_profile_name(
                    env_first_value(
                        "GRAIL_BROWSER_PROFILE_NAME",
                        "OPENCLAW_BROWSER_PROFILE_NAME",
                    )
                    .unwrap_or_else(|| "default".to_string()),
                    "default",
                )
            },
            home: env_value(
                "GRAIL_BROWSER_HOME",
                &env_value("OPENCLAW_BROWSER_HOME", "/data/browser-profiles"),
            ),
        }
    }
}

fn env_first_value(primary: &str, fallback: &str) -> Option<String> {
    std::env::var(primary)
        .ok()
        .or_else(|| std::env::var(fallback).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn normalize_port(value: Option<String>, default: &str) -> String {
    let candidate = value.unwrap_or_else(|| default.to_string());
    match candidate.parse::<u16>() {
        Ok(port) if port > 0 => port.to_string(),
        _ => default.to_string(),
    }
}

fn normalize_http_url(value: Option<String>, default: &str) -> String {
    let candidate = value
        .unwrap_or_else(|| default.to_string())
        .trim()
        .to_string();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        candidate
    } else {
        default.to_string()
    }
}

fn normalize_profile_name(raw: String, default: &str) -> String {
    let mut cleaned = raw
        .trim()
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();

    while cleaned.contains("--") {
        cleaned = cleaned.replace("--", "-");
    }

    let cleaned = cleaned.trim_matches('-').trim();
    if cleaned.is_empty() {
        default.to_string()
    } else {
        cleaned.to_string()
    }
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

fn env_value(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[derive(Debug)]
struct CodexProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Drop for CodexProc {
    fn drop(&mut self) {
        // If a worker task is aborted/dropped without calling CodexManager::stop(),
        // ensure the subprocess doesn't leak.
        let _ = self.child.start_kill();
    }
}

pub struct CodexManager {
    config: Arc<Config>,
    proc: Option<CodexProc>,
    last_env_fingerprint: Option<String>,
    last_config_fingerprint: Option<String>,
    last_auth_fingerprint: Option<String>,
}

impl CodexManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            proc: None,
            last_env_fingerprint: None,
            last_config_fingerprint: None,
            last_auth_fingerprint: None,
        }
    }

    pub async fn ensure_started(
        &mut self,
        openai_api_key: Option<&str>,
        slack_bot_token: Option<&str>,
        slack_allow_channels: Option<&str>,
        brave_search_api_key: Option<&str>,
        web_allow_domains: Option<&str>,
        web_deny_domains: Option<&str>,
        allow_slack_mcp: bool,
        allow_web_mcp: bool,
        extra_mcp_config: Option<&str>,
        browser: &BrowserEnvConfig,
    ) -> anyhow::Result<()> {
        let codex_home = self.config.effective_codex_home();
        tokio::fs::create_dir_all(&codex_home)
            .await
            .with_context(|| format!("create CODEX_HOME dir {}", codex_home.display()))?;

        // Write a minimal config.toml for Codex (MCP server + no update checks).
        let mut cfg = self.render_codex_config(allow_slack_mcp, allow_web_mcp, extra_mcp_config);
        if let Err(err) = toml::from_str::<toml::Value>(&cfg) {
            warn!(
                error = %err,
                "invalid extra MCP config; ignoring extra_mcp_config"
            );
            cfg = self.render_codex_config(allow_slack_mcp, allow_web_mcp, None);
        }
        let cfg_fp = sha256_hex(cfg.as_bytes());
        let config_changed = self.last_config_fingerprint.as_deref() != Some(&cfg_fp);
        if config_changed {
            let path = codex_home.join("config.toml");
            tokio::fs::write(&path, cfg)
                .await
                .with_context(|| format!("write {}", path.display()))?;
            self.last_config_fingerprint = Some(cfg_fp);
        }

        // Detect auth changes (ChatGPT device login writes CODEX_HOME/auth.json).
        let auth_path = codex_home.join("auth.json");
        let auth_fp = match tokio::fs::read(&auth_path).await {
            Ok(bytes) => sha256_hex(&bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => "missing".to_string(),
            Err(err) => {
                warn!(error = %err, "failed to read auth.json fingerprint; forcing restart");
                "error".to_string()
            }
        };
        let auth_changed = self.last_auth_fingerprint.as_deref() != Some(&auth_fp);

        // Restart the app-server if the auth inputs changed.
        let env_fp = sha256_hex(
            format!(
                "openai_api_key={};slack_bot_token={};slack_allow_channels={};brave_search_api_key={};web_allow_domains={};web_deny_domains={};codex_home={};browser_enabled={};browser_cdp_url={};browser_cdp_port={};browser_profile_name={};browser_home={};browser_novnc_enabled={};browser_novnc_url={};browser_novnc_port={}",
                openai_api_key.unwrap_or(""),
                slack_bot_token.unwrap_or(""),
                slack_allow_channels.unwrap_or(""),
                brave_search_api_key.unwrap_or(""),
                web_allow_domains.unwrap_or(""),
                web_deny_domains.unwrap_or(""),
                codex_home.display(),
                browser.enabled,
                browser.cdp_url,
                browser.cdp_port,
                browser.profile_name,
                browser.home,
                browser.novnc_enabled,
                browser.novnc_url,
                browser.novnc_port
            )
            .as_bytes(),
        );
        let needs_restart = self.last_env_fingerprint.as_deref() != Some(&env_fp);

        // If the process is present but has exited, restart it.
        let proc_exited = match self.proc.as_mut() {
            Some(p) => match p.child.try_wait() {
                Ok(Some(status)) => {
                    warn!(?status, "codex app-server exited; restarting");
                    true
                }
                Ok(None) => false,
                Err(err) => {
                    warn!(error = %err, "failed to poll codex process; restarting");
                    true
                }
            },
            None => false,
        };

        if self.proc.is_none() || needs_restart || config_changed || auth_changed || proc_exited {
            self.stop().await;
            let proc = spawn_codex_app_server(
                &self.config.codex_bin,
                &codex_home,
                openai_api_key,
                slack_bot_token,
                slack_allow_channels,
                brave_search_api_key,
                web_allow_domains,
                web_deny_domains,
                browser,
            )
            .await?;
            self.proc = Some(proc);
            self.last_env_fingerprint = Some(env_fp);
            self.last_auth_fingerprint = Some(auth_fp);
        }

        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(mut p) = self.proc.take() {
            let _ = p.stdin.shutdown().await;
            if let Some(id) = p.child.id() {
                debug!(pid = id, "stopping codex app-server");
            }
            let _ = p.child.kill().await;
            let _ = p.child.wait().await;
        }
    }

    pub async fn resume_or_start_thread(
        &mut self,
        existing_thread_id: Option<&str>,
        settings: &Settings,
        cwd: &Path,
    ) -> anyhow::Result<String> {
        let Some(proc) = self.proc.as_mut() else {
            anyhow::bail!("codex app-server not started");
        };

        let model = settings.model.as_deref();
        let approval_policy = Some("on-request");
        let sandbox_mode = match settings.permissions_mode {
            PermissionsMode::Read => "read-only",
            PermissionsMode::Full => {
                if settings.allow_context_writes {
                    "workspace-write"
                } else {
                    "read-only"
                }
            }
        };

        let params = json!({
            "model": model,
            "cwd": cwd.to_string_lossy(),
            "approvalPolicy": approval_policy,
            "sandbox": sandbox_mode,
            "config": null,
            "baseInstructions": null,
            "developerInstructions": null,
            "personality": "pragmatic",
        });

        if let Some(thread_id) = existing_thread_id {
            let res = proc
                .request(
                    "thread/resume",
                    json!({ "threadId": thread_id }).merge(&params),
                )
                .await?;
            let id = res
                .get("thread")
                .and_then(|t| t.get("id"))
                .and_then(|v| v.as_str())
                .context("thread/resume missing thread.id")?;
            return Ok(id.to_string());
        }

        // thread/start requires experimentalRawEvents.
        let res = proc
            .request(
                "thread/start",
                json!({
                    "experimentalRawEvents": false,
                })
                .merge(&params),
            )
            .await?;
        let id = res
            .get("thread")
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .context("thread/start missing thread.id")?;
        Ok(id.to_string())
    }

    pub async fn run_turn(
        &mut self,
        state: &crate::AppState,
        task: &Task,
        thread_id: &str,
        settings: &Settings,
        cwd: &Path,
        input_text: &str,
        output_schema: serde_json::Value,
        trace_tx: Option<&mpsc::UnboundedSender<CodexTurnEvent>>,
    ) -> anyhow::Result<CodexTurnOutput> {
        let Some(proc) = self.proc.as_mut() else {
            anyhow::bail!("codex app-server not started");
        };

        let sandbox_policy = match settings.permissions_mode {
            PermissionsMode::Read => json!({ "type": "readOnly" }),
            PermissionsMode::Full => {
                if settings.allow_context_writes {
                    json!({
                        "type": "workspaceWrite",
                        // Only allow writes under the context directory.
                        "writableRoots": [cwd.to_string_lossy()],
                        "networkAccess": settings.shell_network_access,
                        "excludeTmpdirEnvVar": false,
                        "excludeSlashTmp": false
                    })
                } else {
                    json!({ "type": "readOnly" })
                }
            }
        };

        let turn_params = json!({
            "threadId": thread_id,
            "input": [{ "type": "text", "text": input_text }],
            "cwd": cwd.to_string_lossy(),
            "approvalPolicy": "on-request",
            "sandboxPolicy": sandbox_policy,
            "model": settings.model.as_deref(),
            "effort": settings.reasoning_effort.as_deref(),
            "summary": settings.reasoning_summary.as_deref(),
            "personality": "pragmatic",
            "outputSchema": output_schema,
        });

        let res = proc.request("turn/start", turn_params).await?;
        let turn_id = res
            .get("turn")
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .context("turn/start missing turn.id")?
            .to_string();

        let mut agent_message_item_id: Option<String> = None;
        let mut agent_message_deltas = String::new();
        let mut agent_message_final: Option<String> = None;
        let mut last_turn_error: Option<String> = None;
        let mut file_change_paths_by_item: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let mut last_cancel_check = Instant::now();

        let emit_trace = |trace_tx: Option<&mpsc::UnboundedSender<CodexTurnEvent>>,
                          event_type: &str,
                          level: &str,
                          message: &str,
                          details: &str| {
            if let Some(tx) = trace_tx {
                let _ = tx.send(CodexTurnEvent {
                    event_type: event_type.to_string(),
                    level: level.to_string(),
                    message: message.to_string(),
                    details: details.to_string(),
                });
            }
        };

        emit_trace(
            trace_tx,
            "turn.start",
            "info",
            "turn-started",
            &format!("thread={thread_id}"),
        );

        loop {
            if last_cancel_check.elapsed() >= std::time::Duration::from_millis(700) {
                match crate::db::is_task_cancel_requested(&state.pool, task.id).await {
                    Ok(true) => {
                        emit_trace(
                            trace_tx,
                            "turn.interrupted",
                            "warning",
                            "task-cancel-requested",
                            "admin requested cancellation",
                        );
                        anyhow::bail!("task cancelled by admin");
                    }
                    Ok(false) => {}
                    Err(err) => {
                        warn!(error = %err, task_id = task.id, "failed to check cancellation status");
                    }
                }
                last_cancel_check = Instant::now();
            }

            let msg = proc.read_next().await?;

            // Server-initiated requests (approvals).
            if is_server_request(&msg) {
                let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = msg.get("id").cloned().unwrap_or(json!(null));
                let params = msg.get("params").cloned().unwrap_or(json!({}));

                match method {
                    "item/commandExecution/requestApproval" => {
                        emit_trace(
                            trace_tx,
                            "approval.request",
                            "debug",
                            "command execution approval requested",
                            &method,
                        );
                        let resp = crate::approvals::handle_command_execution_request(
                            state, settings, cwd, task, &params,
                        )
                        .await?;
                        proc.respond(id, resp).await?;
                    }
                    "item/fileChange/requestApproval" => {
                        emit_trace(
                            trace_tx,
                            "approval.request",
                            "debug",
                            "file change approval requested",
                            &method,
                        );
                        // We intentionally disallow Codex-driven file edits; use context_writes in
                        // the structured Slack reply instead.
                        let _paths = params
                            .get("itemId")
                            .and_then(|v| v.as_str())
                            .and_then(|item_id| file_change_paths_by_item.get(item_id))
                            .cloned()
                            .unwrap_or_default();
                        proc.respond(id, json!({ "decision": "decline" })).await?;
                    }
                    other => {
                        warn!(method = other, "unhandled server request; declining");
                        emit_trace(
                            trace_tx,
                            "approval.request",
                            "warning",
                            "unhandled server request",
                            other,
                        );
                        // Best-effort: many server requests accept {"decision": "..."}.
                        proc.respond(id, json!({ "decision": "decline" })).await?;
                    }
                }
                continue;
            }

            // Notifications.
            let Some(method) = msg.get("method").and_then(|v| v.as_str()) else {
                continue;
            };
            let params = msg.get("params").cloned().unwrap_or(json!({}));

            match method {
                "error" => {
                    emit_trace(
                        trace_tx,
                        "turn.error",
                        "error",
                        "turn error",
                        &params.to_string(),
                    );
                    let p_thread_id = params
                        .get("threadId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id == thread_id && p_turn_id == turn_id {
                        let msg = params
                            .get("error")
                            .and_then(|e| e.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown error");
                        last_turn_error = Some(msg.to_string());
                    }
                }
                "item/started" => {
                    let p_thread_id = params
                        .get("threadId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id != thread_id || p_turn_id != turn_id {
                        continue;
                    }

                    let item = params.get("item").cloned().unwrap_or(json!({}));
                    emit_trace(
                        trace_tx,
                        "item.started",
                        "debug",
                        "item started",
                        &item.to_string(),
                    );
                    let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if item_type == "agentMessage" {
                        if let Some(item_id) = item.get("id").and_then(|v| v.as_str()) {
                            agent_message_item_id = Some(item_id.to_string());
                        }
                    }
                    if item_type == "fileChange" {
                        let item_id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let mut paths: Vec<PathBuf> = Vec::new();
                        if let Some(changes) = item.get("changes").and_then(|v| v.as_array()) {
                            for ch in changes {
                                if let Some(p) = ch.get("path").and_then(|v| v.as_str()) {
                                    paths.push(PathBuf::from(p));
                                }
                            }
                        }
                        if !item_id.is_empty() {
                            file_change_paths_by_item.insert(item_id.to_string(), paths);
                        }
                    }
                }
                "item/agentMessage/delta" => {
                    let p_thread_id = params
                        .get("threadId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    let item_id = params.get("itemId").and_then(|v| v.as_str()).unwrap_or("");
                    let delta = params.get("delta").and_then(|v| v.as_str()).unwrap_or("");
                    emit_trace(
                        trace_tx,
                        "agent.delta",
                        "debug",
                        "agent message delta",
                        &delta,
                    );
                    if p_thread_id == thread_id && p_turn_id == turn_id {
                        if agent_message_item_id.is_none() && !item_id.is_empty() {
                            agent_message_item_id = Some(item_id.to_string());
                        }
                        if let Some(want) = agent_message_item_id.as_deref() {
                            if !item_id.is_empty() && item_id != want {
                                continue;
                            }
                        }
                        agent_message_deltas.push_str(delta);
                    }
                }
                "item/completed" => {
                    let item = params.get("item").cloned().unwrap_or(json!({}));
                    emit_trace(
                        trace_tx,
                        "item.completed",
                        "debug",
                        "item completed",
                        &item.to_string(),
                    );
                    let p_thread_id = params
                        .get("threadId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id != thread_id || p_turn_id != turn_id {
                        continue;
                    }
                    let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if item_type == "agentMessage" {
                        if let Some(item_id) = item.get("id").and_then(|v| v.as_str()) {
                            agent_message_item_id = Some(item_id.to_string());
                        }
                        if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                            agent_message_final = Some(text.to_string());
                        }
                    }
                }
                "turn/completed" => {
                    let p_thread_id = params
                        .get("threadId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let p_turn = params.get("turn").cloned().unwrap_or(json!({}));
                    emit_trace(
                        trace_tx,
                        "turn.completed",
                        "info",
                        "turn completed",
                        &p_turn.to_string(),
                    );
                    let p_turn_id = p_turn.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id != thread_id || p_turn_id != turn_id {
                        continue;
                    }

                    let status = p_turn.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    match status {
                        "completed" => break,
                        "failed" => {
                            let msg = p_turn
                                .get("error")
                                .and_then(|e| e.get("message"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .or_else(|| last_turn_error.clone())
                                .unwrap_or_else(|| "turn failed".to_string());
                            anyhow::bail!("codex turn failed: {msg}");
                        }
                        "interrupted" => {
                            anyhow::bail!("codex turn interrupted");
                        }
                        other => {
                            anyhow::bail!("unexpected codex turn status: {other}");
                        }
                    }
                }
                _ => {}
            }
        }

        let agent_message = agent_message_final.unwrap_or(agent_message_deltas);
        if agent_message.trim().is_empty() {
            warn!("codex returned empty agent message");
        }

        Ok(CodexTurnOutput {
            agent_message_text: agent_message,
        })
    }

    fn render_codex_config(
        &self,
        allow_slack_mcp: bool,
        allow_web_mcp: bool,
        extra_mcp_config: Option<&str>,
    ) -> String {
        // Keep this minimal; we rely primarily on per-turn overrides.
        // Avoid placing secrets in this file.
        let mut out = String::new();
        out.push_str("check_for_update_on_startup = false\n");

        if allow_slack_mcp {
            out.push_str("\n[mcp_servers.slack]\n");
            out.push_str("command = \"grail-slack-mcp\"\n");
            out.push_str("args = []\n");
            out.push_str("env_vars = [\"SLACK_BOT_TOKEN\", \"GRAIL_SLACK_ALLOW_CHANNELS\"]\n");
            out.push_str("startup_timeout_sec = 10\n");
            out.push_str("tool_timeout_sec = 30\n");
        }

        if allow_web_mcp {
            out.push_str("\n[mcp_servers.web]\n");
            out.push_str("command = \"grail-web-mcp\"\n");
            out.push_str("args = []\n");
            out.push_str("env_vars = [\"BRAVE_SEARCH_API_KEY\", \"GRAIL_WEB_ALLOW_DOMAINS\", \"GRAIL_WEB_DENY_DOMAINS\"]\n");
            out.push_str("startup_timeout_sec = 10\n");
            out.push_str("tool_timeout_sec = 45\n");
        }

        if let Some(extra) = extra_mcp_config {
            let extra = extra.trim();
            if !extra.is_empty() {
                out.push_str("\n\n# Extra MCP config (from Settings.extra_mcp_config)\n");
                out.push_str(extra);
                out.push('\n');
            }
        }

        out
    }
}

async fn spawn_codex_app_server(
    codex_bin: &str,
    codex_home: &Path,
    openai_api_key: Option<&str>,
    slack_bot_token: Option<&str>,
    slack_allow_channels: Option<&str>,
    brave_search_api_key: Option<&str>,
    web_allow_domains: Option<&str>,
    web_deny_domains: Option<&str>,
    browser: &BrowserEnvConfig,
) -> anyhow::Result<CodexProc> {
    // Codex CLI argument surface has changed across versions. Some builds accept
    // `--listen stdio://` while others default to stdio and reject `--listen`.
    // To be resilient, try the newer syntax first, then fall back to the minimal
    // invocation.
    // Try the minimal form first. Newer versions that also support `--listen`
    // still default to stdio, while some older builds reject `--listen`.
    for args in [
        vec!["app-server"],
        vec!["app-server", "--listen", "stdio://"],
    ] {
        match spawn_codex_with_args(
            codex_bin,
            &args,
            codex_home,
            openai_api_key,
            slack_bot_token,
            slack_allow_channels,
            brave_search_api_key,
            web_allow_domains,
            web_deny_domains,
            browser,
        )
        .await
        {
            Ok(proc) => return Ok(proc),
            Err(err) => {
                warn!(error = %err, args = ?args, "failed to start codex app-server");
            }
        }
    }

    anyhow::bail!("failed to start codex app-server after trying compatible arg variants")
}

async fn spawn_codex_with_args(
    codex_bin: &str,
    args: &[&str],
    codex_home: &Path,
    openai_api_key: Option<&str>,
    slack_bot_token: Option<&str>,
    slack_allow_channels: Option<&str>,
    brave_search_api_key: Option<&str>,
    web_allow_domains: Option<&str>,
    web_deny_domains: Option<&str>,
    browser: &BrowserEnvConfig,
) -> anyhow::Result<CodexProc> {
    let mut cmd = Command::new(codex_bin);
    cmd.args(args);
    cmd.env("CODEX_HOME", codex_home);
    if let Some(key) = openai_api_key {
        cmd.env("OPENAI_API_KEY", key);
    }
    if let Some(t) = slack_bot_token {
        cmd.env("SLACK_BOT_TOKEN", t);
    }
    if let Some(v) = slack_allow_channels {
        cmd.env("GRAIL_SLACK_ALLOW_CHANNELS", v);
    }
    if let Some(k) = brave_search_api_key {
        cmd.env("BRAVE_SEARCH_API_KEY", k);
    }
    if let Some(v) = web_allow_domains {
        cmd.env("GRAIL_WEB_ALLOW_DOMAINS", v);
    }
    if let Some(v) = web_deny_domains {
        cmd.env("GRAIL_WEB_DENY_DOMAINS", v);
    }
    if browser.enabled {
        cmd.env("GRAIL_BROWSER_ENABLED", "1");
        cmd.env("OPENCLAW_BROWSER_ENABLED", "1");
    } else {
        cmd.env("GRAIL_BROWSER_ENABLED", "0");
        cmd.env("OPENCLAW_BROWSER_ENABLED", "0");
    }
    if !browser.cdp_url.is_empty() {
        cmd.env("GRAIL_BROWSER_CDP_URL", browser.cdp_url.as_str());
        cmd.env("OPENCLAW_BROWSER_CDP_URL", browser.cdp_url.as_str());
    }
    if !browser.cdp_port.is_empty() {
        cmd.env("GRAIL_BROWSER_CDP_PORT", browser.cdp_port.as_str());
        cmd.env("OPENCLAW_BROWSER_CDP_PORT", browser.cdp_port.as_str());
    }
    if browser.novnc_enabled {
        cmd.env("GRAIL_BROWSER_ENABLE_NOVNC", "1");
        cmd.env("OPENCLAW_BROWSER_ENABLE_NOVNC", "1");
        if !browser.novnc_url.is_empty() {
            cmd.env("GRAIL_BROWSER_NOVNC_URL", browser.novnc_url.as_str());
            cmd.env("OPENCLAW_BROWSER_NOVNC_URL", browser.novnc_url.as_str());
        }
        if !browser.novnc_port.is_empty() {
            cmd.env("GRAIL_BROWSER_NOVNC_PORT", browser.novnc_port.as_str());
            cmd.env("OPENCLAW_BROWSER_NOVNC_PORT", browser.novnc_port.as_str());
        }
    } else {
        cmd.env("GRAIL_BROWSER_ENABLE_NOVNC", "0");
        cmd.env("OPENCLAW_BROWSER_ENABLE_NOVNC", "0");
    }
    if !browser.profile_name.is_empty() {
        cmd.env("GRAIL_BROWSER_PROFILE_NAME", browser.profile_name.as_str());
        cmd.env(
            "OPENCLAW_BROWSER_PROFILE_NAME",
            browser.profile_name.as_str(),
        );
    }
    if !browser.home.is_empty() {
        cmd.env("GRAIL_BROWSER_HOME", browser.home.as_str());
        cmd.env("OPENCLAW_BROWSER_HOME", browser.home.as_str());
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn codex app-server (args={:?})", args))?;
    let stdin = child.stdin.take().context("codex stdin missing")?;
    let stdout = child.stdout.take().context("codex stdout missing")?;
    let stderr = child.stderr.take().context("codex stderr missing")?;

    spawn_stderr_logger(stderr);

    let mut proc = CodexProc {
        child,
        stdin,
        stdout: BufReader::new(stdout),
        next_id: 1,
    };

    // Initialize handshake.
    let _init = proc
        .request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "grail",
                    "title": "FastClaw",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": null
            }),
        )
        .await?;
    proc.notify("initialized", None).await?;

    info!(args = ?args, "codex app-server initialized");
    Ok(proc)
}

fn spawn_stderr_logger(stderr: ChildStderr) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let s = line.trim_end();
                    if !s.is_empty() {
                        warn!(target: "codex_stderr", "{s}");
                    }
                }
                Err(_) => break,
            }
        }
    });
}

impl CodexProc {
    async fn write_line(&mut self, value: &serde_json::Value) -> anyhow::Result<()> {
        let mut s = serde_json::to_string(value).context("serialize codex json")?;
        s.push('\n');
        self.stdin
            .write_all(s.as_bytes())
            .await
            .context("write to codex stdin")?;
        self.stdin.flush().await.context("flush codex stdin")?;
        Ok(())
    }

    async fn read_next(&mut self) -> anyhow::Result<serde_json::Value> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .await
                .context("read from codex stdout")?;
            if n == 0 {
                anyhow::bail!("codex app-server exited");
            }
            let s = line.trim();
            if s.is_empty() {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(s) {
                Ok(v) => return Ok(v),
                Err(err) => {
                    warn!(error = %err, line = %s, "invalid json from codex");
                }
            }
        }
    }

    async fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        self.write_line(&json!({
            "id": id,
            "method": method,
            "params": params,
        }))
        .await?;

        loop {
            let msg = self.read_next().await?;
            if msg.get("id").and_then(|v| v.as_u64()) == Some(id) {
                if let Some(err) = msg.get("error") {
                    anyhow::bail!("codex error response: {err}");
                }
                let result = msg.get("result").cloned().unwrap_or_else(|| json!({}));
                return Ok(result);
            }

            // Ignore notifications while waiting for the response, but handle
            // server requests (approvals) so we don't deadlock.
            if is_server_request(&msg) {
                let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = msg.get("id").cloned().unwrap_or(json!(null));
                warn!(method, "received server request outside of turn; declining");
                self.respond(id, json!({ "decision": "decline" })).await?;
            }
        }
    }

    async fn notify(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let mut msg = json!({ "method": method });
        if let Some(p) = params {
            msg.as_object_mut()
                .expect("obj")
                .insert("params".to_string(), p);
        }
        self.write_line(&msg).await
    }

    async fn respond(
        &mut self,
        id: serde_json::Value,
        result: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.write_line(&json!({ "id": id, "result": result }))
            .await
    }
}

fn is_server_request(msg: &serde_json::Value) -> bool {
    msg.get("method").is_some()
        && msg.get("id").is_some()
        && msg.get("result").is_none()
        && msg.get("error").is_none()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

trait JsonMerge {
    fn merge(self, other: &serde_json::Value) -> serde_json::Value;
}

impl JsonMerge for serde_json::Value {
    fn merge(mut self, other: &serde_json::Value) -> serde_json::Value {
        if let (Some(a), Some(b)) = (self.as_object_mut(), other.as_object()) {
            for (k, v) in b {
                a.insert(k.clone(), v.clone());
            }
        }
        self
    }
}
