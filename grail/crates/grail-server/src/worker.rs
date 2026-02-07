use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use cron::Schedule;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::codex::CodexManager;
use crate::db;
use crate::models::Session;
use crate::slack::SlackClient;
use crate::telegram::TelegramClient;
use crate::AppState;

pub async fn worker_loop(state: AppState) {
    const LEASE_SECONDS: i64 = 60;
    const RENEW_EVERY_SECONDS: u64 = 20;

    let worker_id = random_id("worker");
    let mut codex = CodexManager::new(state.config.clone());

    loop {
        // Acquire the worker lock so only one instance processes tasks at a time.
        loop {
            match db::try_acquire_or_renew_worker_lock(&state.pool, &worker_id, LEASE_SECONDS).await
            {
                Ok(true) => {
                    info!(%worker_id, "acquired worker lock");
                    break;
                }
                Ok(false) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(err) => {
                    warn!(error = %err, "failed to acquire worker lock");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }

        match db::reset_running_tasks(&state.pool).await {
            Ok(n) if n > 0 => {
                warn!(
                    count = n,
                    "re-queued tasks left in running state after worker restart"
                );
            }
            Ok(_) => {}
            Err(err) => {
                warn!(error = %err, "failed to reset running tasks after acquiring lock");
            }
        }

        // Periodic DB hygiene (only the lock-holder runs this).
        match db::cleanup_old_tasks(&state.pool, 30).await {
            Ok(n) if n > 0 => info!(count = n, "cleaned up old tasks"),
            Ok(_) => {}
            Err(err) => warn!(error = %err, "failed to cleanup old tasks"),
        }
        match db::cleanup_old_processed_events(&state.pool, 7).await {
            Ok(n) if n > 0 => info!(count = n, "cleaned up old processed events"),
            Ok(_) => {}
            Err(err) => warn!(error = %err, "failed to cleanup old processed events"),
        }

        let has_lock = Arc::new(AtomicBool::new(true));
        let has_lock2 = has_lock.clone();
        let pool = state.pool.clone();
        let worker_id2 = worker_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(RENEW_EVERY_SECONDS)).await;
                match db::try_acquire_or_renew_worker_lock(&pool, &worker_id2, LEASE_SECONDS).await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!(%worker_id2, "lost worker lock");
                        has_lock2.store(false, Ordering::SeqCst);
                        break;
                    }
                    Err(err) => {
                        warn!(error = %err, %worker_id2, "failed to renew worker lock");
                    }
                }
            }
        });

        let mut last_cleanup = Instant::now();
        let mut last_cron_check = Instant::now();
        while has_lock.load(Ordering::SeqCst) {
            if last_cleanup.elapsed() >= Duration::from_secs(60 * 60) {
                match db::cleanup_old_tasks(&state.pool, 30).await {
                    Ok(n) if n > 0 => info!(count = n, "cleaned up old tasks"),
                    Ok(_) => {}
                    Err(err) => warn!(error = %err, "failed to cleanup old tasks"),
                }
                match db::cleanup_old_processed_events(&state.pool, 7).await {
                    Ok(n) if n > 0 => info!(count = n, "cleaned up old processed events"),
                    Ok(_) => {}
                    Err(err) => warn!(error = %err, "failed to cleanup old processed events"),
                }
                last_cleanup = Instant::now();
            }

            // Enqueue due cron jobs. This is done by the lock-holder so replicas don't duplicate work.
            if last_cron_check.elapsed() >= Duration::from_secs(2) {
                last_cron_check = Instant::now();
                if let Ok(settings) = db::get_settings(&state.pool).await {
                    if settings.allow_cron {
                        if let Err(err) = enqueue_due_cron_jobs(&state).await {
                            warn!(error = %err, "failed to enqueue due cron jobs");
                        }
                    }
                }
            }

            match db::claim_next_task(&state.pool).await {
                Ok(Some(task)) => {
                    let task_id = task.id;
                    if let Err(err) = db::set_runtime_active_task(&state.pool, Some(task_id)).await
                    {
                        warn!(error = %err, "failed to set runtime active task");
                    }
                    let result = process_task(&state, &mut codex, &task).await;
                    match result {
                        Ok(text) => {
                            if let Err(err) =
                                db::complete_task_success(&state.pool, task_id, &text).await
                            {
                                warn!(error = %err, task_id, "failed to mark task succeeded");
                            }
                        }
                        Err(err) => {
                            let msg = format!("{err:#}");
                            warn!(error = %msg, task_id, "task failed");
                            let _ = db::complete_task_failure(&state.pool, task_id, &msg).await;

                            let user_msg = format!(
                                "Task #{task_id} failed. Check /admin/tasks for details.\n\nError: {short}",
                                short = shorten_error(&msg)
                            );
                            let _ = send_user_message(&state, &task, &user_msg).await;
                        }
                    }
                    if let Err(err) = db::set_runtime_active_task(&state.pool, None).await {
                        warn!(error = %err, "failed to clear runtime active task");
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

        // Lock was lost; stop Codex to avoid two workers running at once.
        codex.stop().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn enqueue_due_cron_jobs(state: &AppState) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    let now_ts = now.timestamp();

    // Claim a few jobs at a time to avoid starving the main queue loop.
    let jobs = db::claim_due_cron_jobs(&state.pool, now_ts, 5).await?;
    if jobs.is_empty() {
        return Ok(());
    }

    let slack = match crate::secrets::load_slack_bot_token_opt(state).await {
        Ok(Some(token)) => Some(SlackClient::new(state.http.clone(), token)),
        Ok(None) => None,
        Err(err) => {
            warn!(error = %err, "failed to load SLACK_BOT_TOKEN for cron delivery");
            None
        }
    };
    let telegram = match crate::secrets::load_telegram_bot_token_opt(state).await {
        Ok(Some(token)) => Some(TelegramClient::new(state.http.clone(), token)),
        Ok(None) => None,
        Err(err) => {
            warn!(error = %err, "failed to load TELEGRAM_BOT_TOKEN for cron delivery");
            None
        }
    };

    for job in jobs {
        if job.mode == "message" {
            let (prompt_text, redacted) = crate::secrets::redact_secrets(job.prompt_text.trim());
            if redacted {
                warn!(cron_job_id = %job.id, "redacted secrets from cron delivery prompt_text");
            }
            let delivered = if job.workspace_id == "telegram" {
                if let Some(tg) = telegram.as_ref() {
                    let reply_to = job.thread_ts.parse::<i64>().ok();
                    tg.send_message(&job.channel_id, reply_to, prompt_text.trim())
                        .await
                        .is_ok()
                } else {
                    false
                }
            } else if let Some(slack) = slack.as_ref() {
                slack
                    .post_message(
                        &job.channel_id,
                        thread_opt(&job.thread_ts),
                        prompt_text.trim(),
                    )
                    .await
                    .is_ok()
            } else {
                false
            };

            // Compute next run.
            let next = compute_next_run_at(&job, now);
            match (delivered, next) {
                (true, Ok(Some(next_run_at))) => {
                    db::update_cron_job_next_run_at(
                        &state.pool,
                        &job.id,
                        Some(next_run_at),
                        true,
                        Some("sent"),
                        None,
                    )
                    .await?;
                }
                (true, Ok(None)) => {
                    db::update_cron_job_next_run_at(
                        &state.pool,
                        &job.id,
                        None,
                        false,
                        Some("completed"),
                        None,
                    )
                    .await?;
                }
                (true, Err(err)) => {
                    db::update_cron_job_next_run_at(
                        &state.pool,
                        &job.id,
                        None,
                        false,
                        Some("error"),
                        Some(&format!("{err:#}")),
                    )
                    .await?;
                }
                (false, Ok(Some(next_run_at))) => {
                    db::update_cron_job_next_run_at(
                        &state.pool,
                        &job.id,
                        Some(next_run_at),
                        true,
                        Some("error"),
                        Some("cron delivery failed (missing token or api error)"),
                    )
                    .await?;
                }
                (false, Ok(None)) => {
                    db::update_cron_job_next_run_at(
                        &state.pool,
                        &job.id,
                        None,
                        false,
                        Some("error"),
                        Some("cron delivery failed (missing token or api error)"),
                    )
                    .await?;
                }
                (false, Err(err)) => {
                    db::update_cron_job_next_run_at(
                        &state.pool,
                        &job.id,
                        None,
                        false,
                        Some("error"),
                        Some(&format!(
                            "cron delivery failed; also failed to compute next run: {err:#}"
                        )),
                    )
                    .await?;
                }
            }
            continue;
        }

        let provider = if job.workspace_id == "telegram" {
            "telegram"
        } else {
            "slack"
        };
        let event_ts = if provider == "telegram" {
            // Use a large message_id sentinel so the worker fetches the most recent saved messages.
            format!("{}", i64::MAX)
        } else {
            slack_now_ts_string(now)
        };
        let mut prompt = String::new();
        prompt.push_str("[Scheduled job]\n");
        prompt.push_str(&format!("- job_id: {}\n", job.id));
        prompt.push_str(&format!("- job_name: {}\n\n", job.name));
        prompt.push_str(job.prompt_text.trim());
        prompt.push('\n');

        // Enqueue a regular task so the existing worker pipeline handles it.
        let _task_id = db::enqueue_task(
            &state.pool,
            provider,
            &job.workspace_id,
            &job.channel_id,
            &job.thread_ts,
            &event_ts,
            "cron",
            &prompt,
        )
        .await?;

        // Compute next run.
        match compute_next_run_at(&job, now) {
            Ok(Some(next_run_at)) => {
                db::update_cron_job_next_run_at(
                    &state.pool,
                    &job.id,
                    Some(next_run_at),
                    true,
                    Some("queued"),
                    None,
                )
                .await?;
            }
            Ok(None) => {
                // One-shot completed or invalid schedule; disable.
                db::update_cron_job_next_run_at(
                    &state.pool,
                    &job.id,
                    None,
                    false,
                    Some("completed"),
                    None,
                )
                .await?;
            }
            Err(err) => {
                db::update_cron_job_next_run_at(
                    &state.pool,
                    &job.id,
                    None,
                    false,
                    Some("error"),
                    Some(&format!("{err:#}")),
                )
                .await?;
            }
        }
    }

    Ok(())
}

fn compute_next_run_at(
    job: &crate::models::CronJob,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Option<i64>> {
    match job.schedule_kind.as_str() {
        "every" => {
            let s = job
                .every_seconds
                .context("cron job missing every_seconds")?;
            anyhow::ensure!(s >= 1, "every_seconds too small");
            Ok(Some(now.timestamp() + s))
        }
        "cron" => {
            let expr = job
                .cron_expr
                .as_deref()
                .context("cron job missing cron_expr")?;
            let normalized = crate::cron_expr::normalize_cron_expr(expr)?;
            let schedule = Schedule::from_str(&normalized).context("parse cron expression")?;
            let next = schedule
                .upcoming(chrono::Utc)
                .next()
                .context("cron had no upcoming times")?;
            Ok(Some(next.timestamp()))
        }
        "at" => {
            let at = job.at_ts.context("cron job missing at_ts")?;
            if at > now.timestamp() {
                Ok(Some(at))
            } else {
                Ok(None)
            }
        }
        other => anyhow::bail!("unknown schedule_kind: {other}"),
    }
}

fn slack_now_ts_string(now: chrono::DateTime<chrono::Utc>) -> String {
    // Slack timestamps are strings like "1700000000.000000". Precision isn't critical for our use.
    format!("{}.000000", now.timestamp())
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    let mut rng = rand::rng();
    rand::RngCore::fill_bytes(&mut rng, &mut bytes);
    format!("{}_{}", prefix, hex::encode(bytes))
}

async fn process_task(
    state: &AppState,
    codex: &mut CodexManager,
    task: &crate::models::Task,
) -> anyhow::Result<String> {
    let settings = db::get_settings(&state.pool).await?;

    let provider = task.provider.trim().to_ascii_lowercase();
    let mut slack: Option<SlackClient> = None;
    let mut telegram: Option<TelegramClient> = None;
    let mut slack_bot_token_for_mcp: Option<String> = None;

    let context_text = match provider.as_str() {
        "slack" => {
            let Some(slack_bot_token) = crate::secrets::load_slack_bot_token_opt(state).await?
            else {
                anyhow::bail!("SLACK_BOT_TOKEN is not configured");
            };
            let client = SlackClient::new(state.http.clone(), slack_bot_token.clone());

            let ctx = if !task.thread_ts.is_empty() && task.thread_ts != task.event_ts {
                client
                    .fetch_thread_replies(
                        &task.channel_id,
                        &task.thread_ts,
                        &task.event_ts,
                        settings.context_last_n,
                    )
                    .await?
            } else {
                client
                    .fetch_channel_history(
                        &task.channel_id,
                        &task.event_ts,
                        settings.context_last_n,
                    )
                    .await?
            };

            slack = Some(client);
            slack_bot_token_for_mcp = Some(slack_bot_token);
            format_slack_context(&ctx)
        }
        "telegram" => {
            let Some(token) = crate::secrets::load_telegram_bot_token_opt(state).await? else {
                anyhow::bail!("TELEGRAM_BOT_TOKEN is not configured");
            };
            let client = TelegramClient::new(state.http.clone(), token);

            let before_message_id: i64 = task
                .event_ts
                .parse()
                .context("telegram task event_ts must be a message_id integer")?;
            let ctx = db::fetch_telegram_context(
                &state.pool,
                &task.channel_id,
                before_message_id,
                settings.context_last_n,
            )
            .await?;

            telegram = Some(client);
            format_telegram_context(&ctx)
        }
        other => anyhow::bail!("unknown task provider: {other}"),
    };

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

    let allow_slack_mcp = provider == "slack" && settings.allow_slack_mcp;
    let allow_web_mcp = settings.allow_web_mcp;
    let brave_search_api_key = crate::secrets::load_brave_search_api_key_opt(state).await?;
    codex
        .ensure_started(
            openai_api_key.as_deref(),
            if allow_slack_mcp {
                slack_bot_token_for_mcp.as_deref()
            } else {
                None
            },
            if allow_slack_mcp {
                Some(settings.slack_allow_channels.as_str())
            } else {
                None
            },
            if allow_web_mcp {
                brave_search_api_key.as_deref()
            } else {
                None
            },
            if allow_web_mcp {
                Some(settings.web_allow_domains.as_str())
            } else {
                None
            },
            if allow_web_mcp {
                Some(settings.web_deny_domains.as_str())
            } else {
                None
            },
            allow_slack_mcp,
            allow_web_mcp,
            Some(settings.extra_mcp_config.as_str()),
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

    let input = build_turn_input(
        task,
        &settings,
        &session.memory_summary,
        &context_text,
        allow_slack_mcp,
        allow_web_mcp,
    );

    // NOTE: Codex forwards this schema to the OpenAI "structured outputs" backend.
    // That backend requires that for every object schema:
    // - `required` is present
    // - `required` contains *every* key in `properties`
    // Optional fields must be represented as nullable (e.g., `anyOf: [{...}, {type:null}]`).
    let output_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "reply": { "type": "string" },
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
            },
            "cron_jobs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "mode": {
                            "anyOf": [
                                { "type": "string", "enum": ["agent", "message"] },
                                { "type": "null" }
                            ],
                            "default": "agent"
                        },
                        "schedule_kind": { "type": "string", "enum": ["every", "cron", "at"] },
                        "every_seconds": {
                            "anyOf": [
                                { "type": "integer", "minimum": 1 },
                                { "type": "null" }
                            ]
                        },
                        "cron_expr": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        },
                        "at_ts": {
                            "anyOf": [
                                { "type": "integer" },
                                { "type": "null" }
                            ]
                        },
                        "thread_ts": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ],
                            "description": "Optional override. null => use current thread. Empty string => post in channel (no thread)."
                        },
                        "prompt_text": { "type": "string" }
                    },
                    "required": ["name", "mode", "schedule_kind", "every_seconds", "cron_expr", "at_ts", "thread_ts", "prompt_text"],
                    "additionalProperties": false
                },
                "default": []
            },
            "guardrail_rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "kind": { "type": "string", "enum": ["command"] },
                        "pattern_kind": { "type": "string", "enum": ["regex", "exact", "substring"] },
                        "pattern": { "type": "string" },
                        "action": { "type": "string", "enum": ["allow", "require_approval", "deny"] },
                        "priority": {
                            "anyOf": [
                                { "type": "integer" },
                                { "type": "null" }
                            ],
                            "default": 100
                        },
                        "enabled": {
                            "anyOf": [
                                { "type": "boolean" },
                                { "type": "null" }
                            ],
                            "default": true
                        }
                    },
                    "required": ["name", "kind", "pattern_kind", "pattern", "action", "priority", "enabled"],
                    "additionalProperties": false
                },
                "default": []
            }
        },
        "required": ["reply", "updated_memory_summary", "context_writes", "cron_jobs", "guardrail_rules"],
        "additionalProperties": false
    });

    let out = codex
        .run_turn(
            state,
            task,
            &thread_id,
            &settings,
            &cwd,
            &input,
            output_schema.clone(),
        )
        .await?;

    let mut parsed = match parse_agent_json(&out.agent_message_text) {
        Ok(v) => Some(v),
        Err(err) => {
            warn!(error = %err, "agent output did not match schema; attempting repair");
            None
        }
    };

    if parsed.is_none() {
        if let Ok(v) = repair_agent_output(
            state,
            codex,
            task,
            &thread_id,
            &settings,
            &cwd,
            &out.agent_message_text,
            output_schema,
        )
        .await
        {
            parsed = Some(v);
        }
    }

    let reply_text = if let Some(parsed) = parsed {
        // Apply durable updates.
        if settings.permissions_mode == crate::models::PermissionsMode::Full
            && settings.allow_context_writes
        {
            apply_context_writes(&cwd, &parsed.context_writes).await?;
        }

        let (mem, redacted) = crate::secrets::redact_secrets(&parsed.updated_memory_summary);
        if redacted {
            warn!("redacted secrets from updated_memory_summary");
        }
        session.memory_summary = clamp_len(mem, 6_000);

        if settings.allow_cron {
            if let Err(err) = apply_agent_cron_jobs(state, task, &settings, &parsed.cron_jobs).await
            {
                warn!(error = %err, "failed to apply agent cron jobs");
            }
        }
        if let Err(err) =
            apply_agent_guardrail_rules(state, task, &settings, &parsed.guardrail_rules).await
        {
            warn!(error = %err, "failed to apply agent guardrail rules");
        }
        let (reply, redacted) = crate::secrets::redact_secrets(&parsed.reply);
        if redacted {
            warn!("redacted secrets from reply");
        }
        reply
    } else {
        let raw = out.agent_message_text.trim();
        if raw.is_empty() {
            "I finished, but returned an empty response.".to_string()
        } else {
            let (raw, _) = crate::secrets::redact_secrets(raw);
            let raw = clamp_len(raw, 6_000);
            format!(
                "I generated a response, but it did not match the expected JSON format, so I couldn't safely update memory/context.\n\nRaw output:\n{raw}"
            )
        }
    };

    session.last_used_at = chrono::Utc::now().timestamp();
    db::upsert_session(&state.pool, &session).await?;

    // Reply in the originating channel.
    match provider.as_str() {
        "slack" => {
            let slack = slack.context("slack client missing")?;
            slack
                .post_message(&task.channel_id, thread_opt(&task.thread_ts), &reply_text)
                .await?;
        }
        "telegram" => {
            let tg = telegram.context("telegram client missing")?;
            let reply_to_message_id = task.thread_ts.parse::<i64>().ok();
            let _ids = tg
                .send_message(&task.channel_id, reply_to_message_id, &reply_text)
                .await?;
        }
        _ => {}
    }

    info!(task_id = task.id, provider = %provider, "replied");
    Ok(reply_text)
}

fn conversation_key_for_task(task: &crate::models::Task) -> String {
    if !task.thread_ts.is_empty() && task.thread_ts != task.event_ts {
        format!(
            "{}:{}:thread:{}",
            task.workspace_id, task.channel_id, task.thread_ts
        )
    } else {
        format!("{}:{}:main", task.workspace_id, task.channel_id)
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

async fn send_user_message(
    state: &AppState,
    task: &crate::models::Task,
    text: &str,
) -> anyhow::Result<()> {
    let (text, redacted) = crate::secrets::redact_secrets(text);
    if redacted {
        warn!("redacted secrets from user-facing message");
    }
    match task.provider.as_str() {
        "slack" => {
            let Some(token) = crate::secrets::load_slack_bot_token_opt(state).await? else {
                anyhow::bail!("SLACK_BOT_TOKEN is not configured");
            };
            let slack = SlackClient::new(state.http.clone(), token);
            slack
                .post_message(&task.channel_id, thread_opt(&task.thread_ts), &text)
                .await?;
        }
        "telegram" => {
            let Some(token) = crate::secrets::load_telegram_bot_token_opt(state).await? else {
                anyhow::bail!("TELEGRAM_BOT_TOKEN is not configured");
            };
            let tg = TelegramClient::new(state.http.clone(), token);
            let reply_to_message_id = task.thread_ts.parse::<i64>().ok();
            let _ = tg
                .send_message(&task.channel_id, reply_to_message_id, &text)
                .await?;
        }
        _ => {}
    }
    Ok(())
}

fn format_slack_context(messages: &[crate::slack::SlackMessage]) -> String {
    let mut out = String::new();
    for (i, m) in messages.iter().enumerate() {
        let who = m
            .user
            .as_deref()
            .or(m.bot_id.as_deref())
            .unwrap_or("unknown");
        let text = m.text.clone().unwrap_or_default().replace('\n', " ");
        out.push_str(&format!("{:02}. {} {}: {}\n", i + 1, m.ts, who, text));
    }
    out
}

fn format_telegram_context(messages: &[crate::models::TelegramMessage]) -> String {
    let mut out = String::new();
    for (i, m) in messages.iter().enumerate() {
        let who = if m.is_bot {
            "bot".to_string()
        } else {
            m.from_user_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        };
        let text = m.text.clone().unwrap_or_default().replace('\n', " ");
        out.push_str(&format!("{:02}. {} {}: {}\n", i + 1, m.ts, who, text));
    }
    out
}

fn build_turn_input(
    task: &crate::models::Task,
    settings: &crate::models::Settings,
    memory_summary: &str,
    recent_context: &str,
    allow_slack_mcp: bool,
    allow_web_mcp: bool,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "You are {}, a micro-employee that works inside chat apps (Slack / Telegram).\n\n",
        settings.agent_name
    ));
    if !settings.role_description.trim().is_empty() {
        s.push_str("Role description (authoritative):\n");
        s.push_str(settings.role_description.trim());
        s.push_str("\n\n");
    }
    s.push_str("Task:\n");
    s.push_str(&format!("- provider: {}\n", task.provider));
    s.push_str(&format!("- workspace_id: {}\n", task.workspace_id));
    s.push_str(&format!("- channel_id: {}\n", task.channel_id));
    s.push_str(&format!("- thread_ts: {}\n", task.thread_ts));
    s.push_str(&format!(
        "- requested_by: <@{}>\n",
        task.requested_by_user_id
    ));
    s.push_str(&format!("- event_ts: {}\n\n", task.event_ts));

    s.push_str("Session memory summary (rolling, durable, no secrets):\n");
    if memory_summary.trim().is_empty() {
        s.push_str("(none)\n\n");
    } else {
        s.push_str(memory_summary.trim());
        s.push_str("\n\n");
    }

    s.push_str("Recent chat context (oldest -> newest):\n");
    s.push_str(recent_context);
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
    s.push_str(&format!("- allow_cron: {}\n", settings.allow_cron));
    s.push_str(&format!(
        "- auto_apply_cron_jobs: {}\n",
        settings.auto_apply_cron_jobs
    ));
    s.push_str(&format!(
        "- command_approval_mode: {}\n",
        settings.command_approval_mode
    ));
    s.push_str(&format!(
        "- auto_apply_guardrail_tighten: {}\n\n",
        settings.auto_apply_guardrail_tighten
    ));

    if allow_slack_mcp {
        s.push_str(
            "Slack tools are enabled. If you need more context, use the Slack MCP tools.\n\n",
        );
    } else {
        s.push_str("Slack tools are disabled; rely on the provided context.\n\n");
    }

    if allow_web_mcp {
        s.push_str("Web tools are enabled. Use them for web search/fetch when needed.\n\n");
    } else {
        s.push_str("Web tools are disabled.\n\n");
    }

    s.push_str("User request:\n");
    s.push_str(task.prompt_text.trim());
    s.push_str("\n\n");

    s.push_str("Durable knowledge:\n");
    s.push_str("- If you want to write durable notes/docs, return them via `context_writes` with a RELATIVE path under the context directory.\n");
    s.push_str("- When you create a new doc, also update `INDEX.md` with a single-line entry: `<label> - <relative/path.md>`.\n");
    s.push_str("- If context writes are not allowed, set `context_writes` to an empty array.\n\n");

    s.push_str("Scheduling (cron):\n");
    s.push_str(
        "- If the user asks you to schedule reminders or recurring work, populate `cron_jobs`.\n",
    );
    s.push_str("- Use schedule_kind:\n");
    s.push_str("  - every: set every_seconds\n");
    s.push_str("  - cron: set cron_expr (5-field like \"0 9 * * *\" is OK)\n");
    s.push_str("  - at: set at_ts (unix seconds)\n");
    s.push_str("- IMPORTANT: the JSON schema is strict and requires all keys to be present.\n");
    s.push_str("  - If a field is not applicable, set it to null.\n");
    s.push_str("  - For thread_ts:\n");
    s.push_str("    - null => use the current thread\n");
    s.push_str("    - \"\" (empty string) => post in the channel (no thread)\n\n");

    s.push_str("Guardrails:\n");
    s.push_str("- If the user is onboarding you or setting boundaries, propose guardrail rules via `guardrail_rules`.\n");
    s.push_str("- Prefer tightening rules (require_approval/deny). Only propose allow rules when the user explicitly wants to loosen restrictions.\n\n");

    s.push_str("Return ONLY a single JSON object matching the provided JSON schema.\n");
    s
}

#[derive(Debug, Deserialize)]
struct AgentJson {
    reply: String,
    updated_memory_summary: String,
    #[serde(default)]
    context_writes: Vec<ContextWrite>,
    #[serde(default)]
    cron_jobs: Vec<AgentCronJob>,
    #[serde(default)]
    guardrail_rules: Vec<AgentGuardrailRule>,
}

#[derive(Debug, Deserialize)]
struct ContextWrite {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AgentCronJob {
    name: String,
    #[serde(default)]
    mode: Option<String>, // agent | message
    schedule_kind: String,
    #[serde(default)]
    every_seconds: Option<i64>,
    #[serde(default)]
    cron_expr: Option<String>,
    #[serde(default)]
    at_ts: Option<i64>,
    #[serde(default)]
    thread_ts: Option<String>,
    prompt_text: String,
}

#[derive(Debug, Deserialize)]
struct AgentGuardrailRule {
    name: String,
    kind: String,
    pattern_kind: String,
    pattern: String,
    action: String,
    #[serde(default)]
    priority: Option<i64>,
    #[serde(default)]
    enabled: Option<bool>,
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

async fn repair_agent_output(
    state: &AppState,
    codex: &mut CodexManager,
    task: &crate::models::Task,
    thread_id: &str,
    settings: &crate::models::Settings,
    cwd: &std::path::Path,
    bad_output: &str,
    output_schema: serde_json::Value,
) -> anyhow::Result<AgentJson> {
    let mut last = clamp_len(bad_output.to_string(), 20_000);
    for attempt in 1..=2 {
        let repair_input = format!(
            "Your previous response did not match the required JSON schema.\n\n\
Attempt: {attempt}\n\n\
Previous output:\n```text\n{last}\n```\n\n\
Return ONLY a single JSON object that matches the schema.",
        );
        let out = codex
            .run_turn(
                state,
                task,
                thread_id,
                settings,
                cwd,
                &repair_input,
                output_schema.clone(),
            )
            .await?;
        match parse_agent_json(&out.agent_message_text) {
            Ok(v) => return Ok(v),
            Err(err) => {
                warn!(error = %err, attempt, "repair attempt output still invalid");
                last = clamp_len(out.agent_message_text, 20_000);
            }
        }
    }
    anyhow::bail!("failed to repair agent output")
}

async fn apply_agent_cron_jobs(
    state: &AppState,
    task: &crate::models::Task,
    settings: &crate::models::Settings,
    proposed: &[AgentCronJob],
) -> anyhow::Result<()> {
    const MAX_JOBS_PER_TURN: usize = 5;
    if proposed.is_empty() {
        return Ok(());
    }

    let now_dt = chrono::Utc::now();
    let now = now_dt.timestamp();

    // Only allow cron jobs scoped to the current workspace/channel by default.
    for p in proposed.iter().take(MAX_JOBS_PER_TURN) {
        let name = clamp_len(p.name.trim().to_string(), 80);
        let (prompt_text, redacted) = crate::secrets::redact_secrets(p.prompt_text.trim());
        if redacted {
            warn!(job = %name, "redacted secrets from proposed cron prompt_text");
        }
        let prompt_text = clamp_len(prompt_text, 8_000);
        if name.is_empty() || prompt_text.is_empty() {
            continue;
        }

        let mode = p.mode.as_deref().unwrap_or("agent").trim().to_string();
        if mode != "agent" && mode != "message" {
            continue;
        }

        let schedule_kind = p.schedule_kind.trim().to_string();
        let mut cron_expr = p.cron_expr.as_deref().map(|s| s.trim().to_string());
        let every_seconds = p.every_seconds;
        let at_ts = p.at_ts;

        // Thread override:
        // - If user explicitly set thread_ts to "", post in channel.
        // - Otherwise default to the current task thread.
        let thread_ts = match p.thread_ts.as_deref() {
            Some(v) => v.trim().to_string(),
            None => {
                if task.provider == "slack" {
                    task.thread_ts.clone()
                } else {
                    // Telegram doesn't have Slack-style threads; default to not replying to a specific message.
                    "".to_string()
                }
            }
        };

        let mut job = crate::models::CronJob {
            id: random_id("cron"),
            name,
            enabled: true,
            mode,
            schedule_kind: schedule_kind.clone(),
            every_seconds,
            cron_expr: None,
            at_ts,
            workspace_id: task.workspace_id.clone(),
            channel_id: task.channel_id.clone(),
            thread_ts,
            prompt_text,
            next_run_at: None,
            last_run_at: None,
            last_status: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        };

        job.next_run_at = match schedule_kind.as_str() {
            "every" => {
                let s = job.every_seconds.context("every_seconds is required")?;
                anyhow::ensure!(s >= 1, "every_seconds must be >= 1");
                Some(now + s)
            }
            "cron" => {
                let expr = cron_expr.take().context("cron_expr is required")?;
                let normalized = crate::cron_expr::normalize_cron_expr(&expr)?;
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
                anyhow::ensure!(at > now, "at_ts must be in the future (unix seconds)");
                Some(at)
            }
            _ => continue,
        };

        if settings.auto_apply_cron_jobs {
            let _ = db::insert_cron_job(&state.pool, &job).await?;
            continue;
        }

        // Otherwise, request approval.
        let approval_id = random_id("appr");
        let details = json!({
            "id": job.id,
            "name": job.name,
            "enabled": job.enabled,
            "mode": job.mode,
            "schedule_kind": job.schedule_kind,
            "every_seconds": job.every_seconds,
            "cron_expr": job.cron_expr,
            "at_ts": job.at_ts,
            "workspace_id": job.workspace_id,
            "channel_id": job.channel_id,
            "thread_ts": job.thread_ts,
            "prompt_text": job.prompt_text,
            "next_run_at": job.next_run_at,
        });
        let approval = crate::models::Approval {
            id: approval_id.clone(),
            kind: "cron_job_add".to_string(),
            status: "pending".to_string(),
            decision: None,
            workspace_id: Some(task.workspace_id.clone()),
            channel_id: Some(task.channel_id.clone()),
            thread_ts: Some(task.thread_ts.clone()),
            requested_by_user_id: Some(task.requested_by_user_id.clone()),
            details_json: details.to_string(),
            created_at: now,
            updated_at: now,
            resolved_at: None,
        };
        db::insert_approval(&state.pool, &approval).await?;

        let approve_hint = if task.provider == "slack" {
            format!("@{} approve {}", settings.agent_name, approval_id)
        } else {
            format!("approve {}", approval_id)
        };
        let deny_hint = if task.provider == "slack" {
            format!("@{} deny {}", settings.agent_name, approval_id)
        } else {
            format!("deny {}", approval_id)
        };

        let msg = format!(
            "*Approval required*: add cron job\n\
- name: `{}`\n\
- mode: `{}`\n\
- schedule: `{}`\n\
- target: `{}` {}\n\
\n\
Reply:\n\
- `{}`\n\
- `{}`\n",
            details.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            details
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("agent"),
            match details
                .get("schedule_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
            {
                "every" => format!(
                    "every {}s",
                    details
                        .get("every_seconds")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                ),
                "cron" => format!(
                    "cron {}",
                    details
                        .get("cron_expr")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                ),
                "at" => format!(
                    "at {}",
                    details.get("at_ts").and_then(|v| v.as_i64()).unwrap_or(0)
                ),
                other => other.to_string(),
            },
            details
                .get("channel_id")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            details
                .get("thread_ts")
                .and_then(|v| v.as_str())
                .map(|t| if t.trim().is_empty() {
                    "(no reply)"
                } else {
                    "(reply)"
                })
                .unwrap_or("(reply)"),
            approve_hint,
            deny_hint,
        );
        // Slack: render clickable buttons if interactivity is configured.
        if task.provider == "slack" {
            let (text, _) = crate::secrets::redact_secrets(&msg);
            if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(state).await {
                let slack = SlackClient::new(state.http.clone(), token);
                let blocks = json!([
                    { "type": "section", "text": { "type": "mrkdwn", "text": text.trim() } },
                    { "type": "actions", "elements": [
                        { "type": "button", "text": { "type": "plain_text", "text": "Approve" }, "style": "primary", "action_id": "grail_approve", "value": approval_id.clone() },
                        { "type": "button", "text": { "type": "plain_text", "text": "Deny" }, "style": "danger", "action_id": "grail_deny", "value": approval_id.clone() }
                    ] }
                ]);
                if let Err(err) = slack
                    .post_message_rich(
                        &task.channel_id,
                        thread_opt(&task.thread_ts),
                        text.trim(),
                        blocks,
                    )
                    .await
                {
                    warn!(error = %err, "failed to post rich cron approval; falling back to plain text");
                    let _ = slack
                        .post_message(&task.channel_id, thread_opt(&task.thread_ts), text.trim())
                        .await;
                }
            } else {
                let _ = send_user_message(state, task, &text).await;
            }
        } else {
            let _ = send_user_message(state, task, &msg).await;
        }
    }

    Ok(())
}

async fn apply_agent_guardrail_rules(
    state: &AppState,
    task: &crate::models::Task,
    settings: &crate::models::Settings,
    proposed: &[AgentGuardrailRule],
) -> anyhow::Result<()> {
    const MAX_RULES_PER_TURN: usize = 5;
    if proposed.is_empty() {
        return Ok(());
    }

    let now = chrono::Utc::now().timestamp();

    for p in proposed.iter().take(MAX_RULES_PER_TURN) {
        let rule = crate::models::GuardrailRule {
            id: random_id("gr"),
            name: clamp_len(p.name.trim().to_string(), 120),
            kind: p.kind.trim().to_string(),
            pattern_kind: p.pattern_kind.trim().to_string(),
            pattern: clamp_len(p.pattern.trim().to_string(), 2_000),
            action: p.action.trim().to_string(),
            priority: p.priority.unwrap_or(100),
            enabled: p.enabled.unwrap_or(true),
            created_at: now,
            updated_at: now,
        };
        if rule.name.is_empty()
            || rule.kind.is_empty()
            || rule.pattern_kind.is_empty()
            || rule.pattern.is_empty()
            || rule.action.is_empty()
        {
            continue;
        }

        if let Err(err) = crate::guardrails::validate_rule(&rule) {
            warn!(error = %err, "invalid proposed guardrail rule");
            continue;
        }

        let tightening = rule.action != "allow";
        if tightening && settings.auto_apply_guardrail_tighten {
            let _ = db::insert_guardrail_rule(&state.pool, &rule).await?;
            continue;
        }

        // Otherwise, request approval.
        let approval_id = random_id("appr");
        let details = json!({
            "name": rule.name,
            "kind": rule.kind,
            "pattern_kind": rule.pattern_kind,
            "pattern": rule.pattern,
            "action": rule.action,
            "priority": rule.priority,
            "enabled": rule.enabled,
        });
        let approval = crate::models::Approval {
            id: approval_id.clone(),
            kind: "guardrail_rule_add".to_string(),
            status: "pending".to_string(),
            decision: None,
            workspace_id: Some(task.workspace_id.clone()),
            channel_id: Some(task.channel_id.clone()),
            thread_ts: Some(task.thread_ts.clone()),
            requested_by_user_id: Some(task.requested_by_user_id.clone()),
            details_json: details.to_string(),
            created_at: now,
            updated_at: now,
            resolved_at: None,
        };
        db::insert_approval(&state.pool, &approval).await?;

        let approve_hint = if task.provider == "slack" {
            format!("@{} approve {}", settings.agent_name, approval_id)
        } else {
            format!("approve {}", approval_id)
        };
        let deny_hint = if task.provider == "slack" {
            format!("@{} deny {}", settings.agent_name, approval_id)
        } else {
            format!("deny {}", approval_id)
        };

        let msg = format!(
            "*Approval required*: add guardrail rule\n\
- name: `{}`\n\
- kind: `{}`\n\
- action: `{}`\n\
- pattern_kind: `{}`\n\
- pattern: `{}`\n\
\n\
Reply:\n\
- `{}`\n\
- `{}`\n",
            details.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            details.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
            details.get("action").and_then(|v| v.as_str()).unwrap_or(""),
            details
                .get("pattern_kind")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            details
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            approve_hint,
            deny_hint,
        );
        if task.provider == "slack" {
            let (text, _) = crate::secrets::redact_secrets(&msg);
            if let Ok(Some(token)) = crate::secrets::load_slack_bot_token_opt(state).await {
                let slack = SlackClient::new(state.http.clone(), token);
                let blocks = json!([
                    { "type": "section", "text": { "type": "mrkdwn", "text": text.trim() } },
                    { "type": "actions", "elements": [
                        { "type": "button", "text": { "type": "plain_text", "text": "Approve" }, "style": "primary", "action_id": "grail_approve", "value": approval_id.clone() },
                        { "type": "button", "text": { "type": "plain_text", "text": "Deny" }, "style": "danger", "action_id": "grail_deny", "value": approval_id.clone() }
                    ] }
                ]);
                if let Err(err) = slack
                    .post_message_rich(
                        &task.channel_id,
                        thread_opt(&task.thread_ts),
                        text.trim(),
                        blocks,
                    )
                    .await
                {
                    warn!(error = %err, "failed to post rich guardrail approval; falling back to plain text");
                    let _ = slack
                        .post_message(&task.channel_id, thread_opt(&task.thread_ts), text.trim())
                        .await;
                }
            } else {
                let _ = send_user_message(state, task, &text).await;
            }
        } else {
            let _ = send_user_message(state, task, &msg).await;
        }
    }

    Ok(())
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

async fn apply_context_writes(
    context_dir: &std::path::Path,
    writes: &[ContextWrite],
) -> anyhow::Result<()> {
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

        let (mut content, redacted) = crate::secrets::redact_secrets(&w.content);
        if redacted {
            warn!(path = %w.path, "redacted secrets from context_writes content");
        }
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
    // Treat AGENTS.md as immutable "constitution" unless an admin edits it manually.
    if p.file_name().and_then(|n| n.to_str()) == Some("AGENTS.md") {
        anyhow::bail!("AGENTS.md edits are not allowed via context_writes");
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
