use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::Context;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::models::{PermissionsMode, Settings};

#[derive(Debug, Clone)]
pub struct CodexTurnOutput {
    pub agent_message_text: String,
}

#[derive(Debug)]
struct CodexProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

pub struct CodexManager {
    config: Arc<Config>,
    proc: Option<CodexProc>,
    last_env_fingerprint: Option<String>,
    last_config_fingerprint: Option<String>,
}

impl CodexManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            proc: None,
            last_env_fingerprint: None,
            last_config_fingerprint: None,
        }
    }

    pub async fn ensure_started(
        &mut self,
        openai_api_key: &str,
        slack_bot_token: Option<&str>,
        allow_slack_mcp: bool,
    ) -> anyhow::Result<()> {
        let codex_home = self.config.effective_codex_home();
        tokio::fs::create_dir_all(&codex_home)
            .await
            .with_context(|| format!("create CODEX_HOME dir {}", codex_home.display()))?;

        // Write a minimal config.toml for Codex (MCP server + no update checks).
        let cfg = self.render_codex_config(allow_slack_mcp);
        let cfg_fp = sha256_hex(cfg.as_bytes());
        let config_changed = self.last_config_fingerprint.as_deref() != Some(&cfg_fp);
        if config_changed {
            let path = codex_home.join("config.toml");
            tokio::fs::write(&path, cfg)
                .await
                .with_context(|| format!("write {}", path.display()))?;
            self.last_config_fingerprint = Some(cfg_fp);
        }

        // Restart the app-server if the auth inputs changed.
        let env_fp = sha256_hex(
            format!(
                "openai_api_key={};slack_bot_token={};codex_home={}",
                openai_api_key,
                slack_bot_token.unwrap_or(""),
                codex_home.display()
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

        if self.proc.is_none() || needs_restart || config_changed || proc_exited {
            self.stop().await;
            let proc = spawn_codex_app_server(
                &self.config.codex_bin,
                &codex_home,
                openai_api_key,
                slack_bot_token,
            )
            .await?;
            self.proc = Some(proc);
            self.last_env_fingerprint = Some(env_fp);
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
                .request("thread/resume", json!({ "threadId": thread_id }).merge(&params))
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
        thread_id: &str,
        settings: &Settings,
        cwd: &Path,
        input_text: &str,
        output_schema: serde_json::Value,
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

        loop {
            let msg = proc.read_next().await?;

            // Server-initiated requests (approvals).
            if is_server_request(&msg) {
                let method = msg
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let id = msg.get("id").cloned().unwrap_or(json!(null));
                let params = msg.get("params").cloned().unwrap_or(json!({}));

                match method {
                    "item/commandExecution/requestApproval" => {
                        let decision = decide_command_approval(settings, &params, cwd);
                        proc.respond(id, json!({ "decision": decision })).await?;
                    }
                    "item/fileChange/requestApproval" => {
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
                    let p_thread_id = params.get("threadId").and_then(|v| v.as_str()).unwrap_or("");
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
                    let p_thread_id = params.get("threadId").and_then(|v| v.as_str()).unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id != thread_id || p_turn_id != turn_id {
                        continue;
                    }

                    let item = params.get("item").cloned().unwrap_or(json!({}));
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
                    let p_thread_id = params.get("threadId").and_then(|v| v.as_str()).unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id == thread_id && p_turn_id == turn_id {
                        let item_id = params.get("itemId").and_then(|v| v.as_str()).unwrap_or("");
                        if agent_message_item_id.is_none() && !item_id.is_empty() {
                            agent_message_item_id = Some(item_id.to_string());
                        }
                        if let Some(want) = agent_message_item_id.as_deref() {
                            if !item_id.is_empty() && item_id != want {
                                continue;
                            }
                        }
                        let delta = params.get("delta").and_then(|v| v.as_str()).unwrap_or("");
                        agent_message_deltas.push_str(delta);
                    }
                }
                "item/completed" => {
                    let p_thread_id = params.get("threadId").and_then(|v| v.as_str()).unwrap_or("");
                    let p_turn_id = params.get("turnId").and_then(|v| v.as_str()).unwrap_or("");
                    if p_thread_id != thread_id || p_turn_id != turn_id {
                        continue;
                    }

                    let item = params.get("item").cloned().unwrap_or(json!({}));
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
                    let p_thread_id = params.get("threadId").and_then(|v| v.as_str()).unwrap_or("");
                    let p_turn = params.get("turn").cloned().unwrap_or(json!({}));
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

    fn render_codex_config(&self, allow_slack_mcp: bool) -> String {
        // Keep this minimal; we rely primarily on per-turn overrides.
        // Avoid placing secrets in this file.
        let mut out = String::new();
        out.push_str("check_for_update_on_startup = false\n");

        if allow_slack_mcp {
            out.push_str("\n[mcp_servers.slack]\n");
            out.push_str("command = \"grail-slack-mcp\"\n");
            out.push_str("args = []\n");
            out.push_str("env_vars = [\"SLACK_BOT_TOKEN\"]\n");
            out.push_str("startup_timeout_sec = 10\n");
            out.push_str("tool_timeout_sec = 30\n");
        }

        out
    }
}

async fn spawn_codex_app_server(
    codex_bin: &str,
    codex_home: &Path,
    openai_api_key: &str,
    slack_bot_token: Option<&str>,
) -> anyhow::Result<CodexProc> {
    let mut cmd = Command::new(codex_bin);
    cmd.arg("app-server");
    cmd.arg("--listen");
    cmd.arg("stdio://");
    cmd.env("CODEX_HOME", codex_home);
    cmd.env("OPENAI_API_KEY", openai_api_key);
    if let Some(t) = slack_bot_token {
        cmd.env("SLACK_BOT_TOKEN", t);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawn codex app-server")?;
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
                    "title": "Grail MicroEmployee",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": null
            }),
        )
        .await?;
    proc.notify("initialized", None).await?;

    info!("codex app-server initialized");
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
                let result = msg
                    .get("result")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
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

    async fn respond(&mut self, id: serde_json::Value, result: serde_json::Value) -> anyhow::Result<()> {
        self.write_line(&json!({ "id": id, "result": result })).await
    }
}

fn is_server_request(msg: &serde_json::Value) -> bool {
    msg.get("method").is_some()
        && msg.get("id").is_some()
        && msg.get("result").is_none()
        && msg.get("error").is_none()
}

fn decide_command_approval(settings: &Settings, params: &serde_json::Value, cwd: &Path) -> &'static str {
    if settings.permissions_mode != PermissionsMode::Full {
        return "decline";
    }

    // Require commands to run under our configured cwd (avoid touching app code).
    let cmd_cwd = params
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.to_path_buf());

    if !cmd_cwd.starts_with(cwd) {
        return "decline";
    }

    // NOTE: We rely on sandboxPolicy.networkAccess for network gating.
    "accept"
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
