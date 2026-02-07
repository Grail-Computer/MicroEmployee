use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use tracing::{info, warn};

use crate::codex::CodexManager;
use crate::db;
use crate::models::Session;
use crate::AppState;

pub async fn worker_loop(state: AppState) {
    let mut codex = CodexManager::new(state.config.clone());

    match db::reset_running_tasks(&state.pool).await {
        Ok(n) if n > 0 => {
            warn!(count = n, "re-queued tasks left in running state after restart");
        }
        Ok(_) => {}
        Err(err) => {
            warn!(error = %err, "failed to reset running tasks on startup");
        }
    }

    loop {
        match db::claim_next_task(&state.pool).await {
            Ok(Some(task)) => {
                let task_id = task.id;
                let result = process_task(&state, &mut codex, &task).await;
                match result {
                    Ok(text) => {
                        if let Err(err) = db::complete_task_success(&state.pool, task_id, &text).await
                        {
                            warn!(error = %err, task_id, "failed to mark task succeeded");
                        }
                    }
                    Err(err) => {
                        let msg = format!("{err:#}");
                        warn!(error = %msg, task_id, "task failed");
                        let _ = db::complete_task_failure(&state.pool, task_id, &msg).await;

                        if let Some(slack) = state.slack.as_ref() {
                            let user_msg = format!(
                                "Task #{task_id} failed. Check /admin/tasks for details.\n\nError: {short}",
                                short = shorten_error(&msg)
                            );
                            let _ = slack
                                .post_message(&task.channel_id, &task.thread_ts, &user_msg)
                                .await;
                        }
                    }
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            Err(err) => {
                warn!(error = %err, "worker loop db error");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn process_task(
    state: &AppState,
    codex: &mut CodexManager,
    task: &crate::models::Task,
) -> anyhow::Result<String> {
    let settings = db::get_settings(&state.pool).await?;

    let Some(slack) = state.slack.as_ref() else {
        anyhow::bail!("SLACK_BOT_TOKEN is not configured");
    };

    let ctx = if task.thread_ts != task.event_ts {
        slack.fetch_thread_replies(
            &task.channel_id,
            &task.thread_ts,
            &task.event_ts,
            settings.context_last_n,
        )
        .await?
    } else {
        slack.fetch_channel_history(&task.channel_id, &task.event_ts, settings.context_last_n)
            .await?
    };

    let openai_api_key = load_openai_api_key(state).await?;

    let allow_slack_mcp = settings.allow_slack_mcp && state.config.slack_bot_token.is_some();
    codex
        .ensure_started(
            &openai_api_key,
            if allow_slack_mcp {
                state.config.slack_bot_token.as_deref()
            } else {
                None
            },
            allow_slack_mcp,
        )
        .await?;

    let conversation_key = conversation_key_for_task(task);
    let mut session = db::get_session(&state.pool, &conversation_key)
        .await?
        .unwrap_or(Session {
            conversation_key: conversation_key.clone(),
            codex_thread_id: None,
            memory_summary: String::new(),
            last_used_at: chrono::Utc::now().timestamp(),
        });

    let cwd = state.config.data_dir.join("context");
    let cwd = tokio::fs::canonicalize(&cwd).await.unwrap_or(cwd);
    let thread_id = codex
        .resume_or_start_thread(session.codex_thread_id.as_deref(), &settings, &cwd)
        .await?;
    session.codex_thread_id = Some(thread_id.clone());

    let slack_context = format_slack_context(&ctx);
    let input = build_turn_input(
        task,
        &settings,
        &session.memory_summary,
        &slack_context,
        allow_slack_mcp,
    );

    let output_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "slack_reply": { "type": "string" },
            "updated_memory_summary": { "type": "string" },
            "context_writes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "content": { "type": "string" }
                    },
                    "required": ["path", "content"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["slack_reply", "updated_memory_summary", "context_writes"],
        "additionalProperties": false
    });

    let out = codex
        .run_turn(&thread_id, &settings, &cwd, &input, output_schema)
        .await?;

    let parsed = match parse_agent_json(&out.agent_message_text) {
        Ok(v) => Some(v),
        Err(err) => {
            warn!(error = %err, "agent output did not match schema; falling back to raw output");
            None
        }
    };

    let slack_reply = if let Some(parsed) = parsed {
        // Apply durable updates.
        if settings.permissions_mode.as_db_str() == "full" && settings.allow_context_writes {
            apply_context_writes(&cwd, &parsed.context_writes).await?;
        }

        session.memory_summary = clamp_len(parsed.updated_memory_summary, 6_000);
        parsed.slack_reply
    } else {
        let raw = out.agent_message_text.trim();
        if raw.is_empty() {
            "I finished, but returned an empty response.".to_string()
        } else {
            let raw = clamp_len(raw.to_string(), 6_000);
            format!(
                "I generated a response, but it did not match the expected JSON format, so I couldn't safely update memory/context.\n\nRaw output:\n{raw}"
            )
        }
    };

    session.last_used_at = chrono::Utc::now().timestamp();
    db::upsert_session(&state.pool, &session).await?;

    // Reply in Slack.
    slack.post_message(&task.channel_id, &task.thread_ts, &slack_reply)
        .await?;

    info!(task_id = task.id, "replied to slack");
    Ok(slack_reply)
}

async fn load_openai_api_key(state: &AppState) -> anyhow::Result<String> {
    if let Ok(v) = std::env::var("OPENAI_API_KEY") {
        if !v.trim().is_empty() {
            return Ok(v);
        }
    }

    let Some(crypto) = state.crypto.as_deref() else {
        anyhow::bail!("OPENAI_API_KEY is not set and GRAIL_MASTER_KEY is missing/invalid");
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "openai_api_key").await? else {
        anyhow::bail!("OpenAI API key not configured. Set OPENAI_API_KEY or configure it in /admin/settings.");
    };
    let plaintext = crypto.decrypt(b"openai_api_key", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("OPENAI_API_KEY not valid utf-8")?;
    Ok(s)
}

fn conversation_key_for_task(task: &crate::models::Task) -> String {
    if task.thread_ts != task.event_ts {
        format!(
            "{}:{}:thread:{}",
            task.workspace_id, task.channel_id, task.thread_ts
        )
    } else {
        format!("{}:{}:main", task.workspace_id, task.channel_id)
    }
}

fn format_slack_context(messages: &[crate::slack::SlackMessage]) -> String {
    let mut out = String::new();
    for (i, m) in messages.iter().enumerate() {
        let who = m.user.as_deref().or(m.bot_id.as_deref()).unwrap_or("unknown");
        let text = m.text.clone().unwrap_or_default().replace('\n', " ");
        out.push_str(&format!("{:02}. {} {}: {}\n", i + 1, m.ts, who, text));
    }
    out
}

fn build_turn_input(
    task: &crate::models::Task,
    settings: &crate::models::Settings,
    memory_summary: &str,
    slack_context: &str,
    allow_slack_mcp: bool,
) -> String {
    let mut s = String::new();
    s.push_str("You are Grail, a Slack micro-employee.\n\n");
    s.push_str("Task:\n");
    s.push_str(&format!("- workspace_id: {}\n", task.workspace_id));
    s.push_str(&format!("- channel_id: {}\n", task.channel_id));
    s.push_str(&format!("- thread_ts: {}\n", task.thread_ts));
    s.push_str(&format!("- requested_by: <@{}>\n", task.requested_by_user_id));
    s.push_str(&format!("- event_ts: {}\n\n", task.event_ts));

    s.push_str("Session memory summary (rolling, durable, no secrets):\n");
    if memory_summary.trim().is_empty() {
        s.push_str("(none)\n\n");
    } else {
        s.push_str(memory_summary.trim());
        s.push_str("\n\n");
    }

    s.push_str("Recent Slack context (oldest -> newest):\n");
    s.push_str(slack_context);
    s.push_str("\n");

    s.push_str("Permissions:\n");
    s.push_str(&format!(
        "- permissions_mode: {}\n",
        settings.permissions_mode.as_db_str()
    ));
    s.push_str(&format!(
        "- allow_context_writes: {}\n\n",
        settings.allow_context_writes
    ));

    if allow_slack_mcp {
        s.push_str("Slack tools are enabled. If you need more context, use the Slack MCP tools.\n\n");
    } else {
        s.push_str("Slack tools are disabled; rely on the provided context.\n\n");
    }

    s.push_str("User request:\n");
    s.push_str(task.prompt_text.trim());
    s.push_str("\n\n");

    s.push_str("Durable knowledge:\n");
    s.push_str("- If you want to write durable notes/docs, return them via `context_writes` with a RELATIVE path under the context directory.\n");
    s.push_str("- When you create a new doc, also update `INDEX.md` with a single-line entry: `<label> - <relative/path.md>`.\n");
    s.push_str("- If context writes are not allowed, set `context_writes` to an empty array.\n\n");

    s.push_str("Return ONLY a single JSON object matching the provided JSON schema.\n");
    s
}

#[derive(Debug, Deserialize)]
struct AgentJson {
    slack_reply: String,
    updated_memory_summary: String,
    context_writes: Vec<ContextWrite>,
}

#[derive(Debug, Deserialize)]
struct ContextWrite {
    path: String,
    content: String,
}

fn parse_agent_json(text: &str) -> anyhow::Result<AgentJson> {
    let t = strip_code_fences(text).trim();
    if t.is_empty() {
        anyhow::bail!("empty agent output");
    }

    // Strict attempt first.
    if let Ok(v) = serde_json::from_str::<AgentJson>(t) {
        return Ok(v);
    }

    // Best-effort: pull out the largest {...} span in case the model wrapped the JSON.
    let Some(start) = t.find('{') else {
        anyhow::bail!("agent output contained no JSON object");
    };
    let Some(end) = t.rfind('}') else {
        anyhow::bail!("agent output contained no JSON object end");
    };
    if end <= start {
        anyhow::bail!("invalid JSON object span");
    }
    let slice = &t[start..=end];
    serde_json::from_str::<AgentJson>(slice).context("parse agent json")
}

fn strip_code_fences(s: &str) -> &str {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("```json") {
        return rest.trim().trim_end_matches("```").trim();
    }
    if let Some(rest) = s.strip_prefix("```") {
        return rest.trim().trim_end_matches("```").trim();
    }
    s
}

async fn apply_context_writes(context_dir: &std::path::Path, writes: &[ContextWrite]) -> anyhow::Result<()> {
    const MAX_WRITES: usize = 20;
    const MAX_TOTAL_CHARS: usize = 300_000;
    const MAX_FILE_CHARS: usize = 200_000;

    let mut remaining = MAX_TOTAL_CHARS;
    for w in writes.iter().take(MAX_WRITES) {
        let rel = sanitize_rel_path(&w.path)?;
        let full = context_dir.join(rel);
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }

        let mut content = w.content.clone();
        if content.len() > MAX_FILE_CHARS {
            content = content.chars().take(MAX_FILE_CHARS).collect();
        }
        if content.len() > remaining {
            content = content.chars().take(remaining).collect();
        }
        remaining = remaining.saturating_sub(content.len());

        tokio::fs::write(&full, content.as_bytes())
            .await
            .with_context(|| format!("write {}", full.display()))?;
        if remaining == 0 {
            break;
        }
    }
    Ok(())
}

fn sanitize_rel_path(path: &str) -> anyhow::Result<std::path::PathBuf> {
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

fn clamp_len(s: String, max: usize) -> String {
    if s.len() <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}

fn shorten_error(s: &str) -> String {
    let s = s.trim().replace('\n', " ");
    if s.len() <= 400 {
        s
    } else {
        format!("{}…", s.chars().take(399).collect::<String>())
    }
}
