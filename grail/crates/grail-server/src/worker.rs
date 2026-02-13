use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use cron::Schedule;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::codex::CodexManager;
use crate::db;
use crate::models::{ObservationalMemory, Session};
use crate::slack::SlackClient;
use crate::telegram::TelegramClient;
use crate::AppState;

pub async fn worker_loop(state: AppState) {
    const WORKER_LOCK_LEASE_SECONDS: i64 = 60;
    const WORKER_LOCK_RENEW_EVERY_SECONDS: u64 = 20;
    const CONVERSATION_LOCK_LEASE_SECONDS: i64 = 60 * 15;
    const CONVERSATION_LOCK_RENEW_EVERY_SECONDS: u64 = 30;

    let worker_id = random_id("worker");
    let concurrency = std::cmp::max(1, state.config.worker_concurrency);

    loop {
        // Acquire the worker lock so only one instance processes tasks at a time.
        loop {
            match db::try_acquire_or_renew_worker_lock(
                &state.pool,
                &worker_id,
                WORKER_LOCK_LEASE_SECONDS,
            )
            .await
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

        // Reset tasks left in-flight after restart.
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

        // Clear any stale per-conversation locks / runtime state.
        let _ = db::clear_all_conversation_locks(&state.pool).await;
        let _ = db::clear_runtime_active_tasks(&state.pool).await;

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
                tokio::time::sleep(Duration::from_secs(WORKER_LOCK_RENEW_EVERY_SECONDS)).await;
                match db::try_acquire_or_renew_worker_lock(
                    &pool,
                    &worker_id2,
                    WORKER_LOCK_LEASE_SECONDS,
                )
                .await
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

        // Spawn task workers. Each worker keeps its own Codex subprocess.
        let mut workers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for slot in 0..concurrency {
            let st = state.clone();
            let wid = worker_id.clone();
            let has = has_lock.clone();
            workers.push(tokio::spawn(async move {
                task_worker_loop(
                    st,
                    wid,
                    slot,
                    has,
                    CONVERSATION_LOCK_LEASE_SECONDS,
                    CONVERSATION_LOCK_RENEW_EVERY_SECONDS,
                )
                .await;
            }));
        }

        let mut last_cleanup = Instant::now();
        let mut last_cron_check = Instant::now();
        let mut last_conv_lock_cleanup = Instant::now();
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

            // Clear expired conversation locks so backlog doesn't get stuck after crashes.
            if last_conv_lock_cleanup.elapsed() >= Duration::from_secs(30) {
                last_conv_lock_cleanup = Instant::now();
                let _ = db::cleanup_expired_conversation_locks(&state.pool).await;
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

            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Lock was lost; abort workers so no more tasks run in this instance.
        for h in workers {
            h.abort();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn task_worker_loop(
    state: AppState,
    worker_id: String,
    slot: usize,
    has_lock: Arc<AtomicBool>,
    conversation_lease_seconds: i64,
    conversation_renew_every_seconds: u64,
) {
    let mut codex = CodexManager::new(state.config.clone());

    while has_lock.load(Ordering::SeqCst) {
        match db::claim_next_task(&state.pool, &worker_id, conversation_lease_seconds).await {
            Ok(Some(task)) => {
                let task_id = task.id;
                let conversation_key = task.conversation_key.clone();

                if let Err(err) = db::mark_task_active(&state.pool, task_id).await {
                    warn!(error = %err, task_id, "failed to mark task active");
                }

                // Renew the per-conversation lock while processing to avoid expiry mid-turn.
                let keep_renewing = Arc::new(AtomicBool::new(true));
                let keep_renewing2 = keep_renewing.clone();
                let pool = state.pool.clone();
                let worker_id2 = worker_id.clone();
                let conversation_key2 = conversation_key.clone();
                let has_lock2 = has_lock.clone();
                let renew_handle = tokio::spawn(async move {
                    while has_lock2.load(Ordering::SeqCst) && keep_renewing2.load(Ordering::SeqCst)
                    {
                        tokio::time::sleep(Duration::from_secs(conversation_renew_every_seconds))
                            .await;
                        let _ = db::try_renew_conversation_lock(
                            &pool,
                            &conversation_key2,
                            &worker_id2,
                            conversation_lease_seconds,
                        )
                        .await;
                    }
                });

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
                        warn!(error = %msg, task_id, worker_slot = slot, "task failed");

                        let was_cancel_requested =
                            db::is_task_cancel_requested(&state.pool, task_id)
                                .await
                                .unwrap_or(false);
                        if was_cancel_requested {
                            let _ = db::complete_task_cancelled(&state.pool, task_id).await;
                        } else {
                            let _ = db::complete_task_failure(&state.pool, task_id, &msg).await;

                            // Proactive tasks should never spam the channel on failure.
                            if !task.is_proactive {
                                let user_msg = format!(
                                    "Task #{task_id} failed. Check /admin/tasks for details.\n\nError: {short}",
                                    short = shorten_error(&msg)
                                );
                                let _ = send_user_message(&state, &task, &user_msg).await;
                            }
                        }
                    }
                }

                keep_renewing.store(false, Ordering::SeqCst);
                renew_handle.abort();

                let _ =
                    db::release_conversation_lock(&state.pool, &conversation_key, &worker_id).await;
                let _ = db::mark_task_inactive(&state.pool, task_id).await;
            }
            Ok(None) => {
                tokio::select! {
                    _ = state.task_notify.notified() => {},
                    _ = tokio::time::sleep(Duration::from_millis(750)) => {},
                }
            }
            Err(err) => {
                warn!(error = %err, worker_slot = slot, "task worker db error");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    codex.stop().await;
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
        state.task_notify.notify_waiters();

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

#[derive(Debug, Clone)]
struct RepoPrepItem {
    clone_url: String,
    dest_rel: String,
    status: String, // cloned | present | failed
    error: Option<String>,
}

static RE_GITHUB_HTTP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
        .expect("regex")
});
static RE_GITHUB_SSH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)").expect("regex")
});

static REPO_CLONE_LOCKS: Lazy<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn extract_github_repo_pairs(text: &str) -> Vec<(String, String)> {
    const MAX_REPOS_PER_TASK: usize = 5;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<(String, String)> = Vec::new();

    for re in [&*RE_GITHUB_HTTP, &*RE_GITHUB_SSH] {
        for cap in re.captures_iter(text) {
            let owner = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            let mut repo = cap
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if owner.is_empty() || repo.is_empty() {
                continue;
            }
            // Strip trailing ".git" if present.
            if let Some(stripped) = repo.strip_suffix(".git") {
                repo = stripped.to_string();
            }
            let pair = (owner.to_string(), repo);
            if seen.insert(pair.clone()) {
                out.push(pair);
            }
            if out.len() >= MAX_REPOS_PER_TASK {
                return out;
            }
        }
    }

    out
}

async fn repo_lock_for_key(key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = REPO_CLONE_LOCKS.lock().await;
    locks
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

async fn maybe_prepare_github_repos(
    state: &AppState,
    conversation_key: &str,
    cwd: &Path,
    prompt_text: &str,
) -> anyhow::Result<(Vec<RepoPrepItem>, String)> {
    let pairs = extract_github_repo_pairs(prompt_text);
    if pairs.is_empty() {
        return Ok((Vec::new(), String::new()));
    }

    let conv_hash = sha256_hex(conversation_key.as_bytes());
    let repos_root = cwd.join("repos").join(&conv_hash);
    tokio::fs::create_dir_all(&repos_root)
        .await
        .with_context(|| format!("create {}", repos_root.display()))?;

    let token = crate::secrets::load_github_token_opt(state).await?;

    let mut items: Vec<RepoPrepItem> = Vec::new();
    for (owner, repo) in pairs {
        let clone_url = format!("https://github.com/{owner}/{repo}.git");
        let dest_rel = format!("repos/{conv_hash}/{owner}__{repo}");
        let dest_abs = cwd.join(&dest_rel);

        let lock_key = dest_abs.to_string_lossy().to_string();
        let lock = repo_lock_for_key(&lock_key).await;
        let _guard = lock.lock().await;

        // If the directory already looks like a git repo, keep it.
        if dest_abs.join(".git").exists() {
            items.push(RepoPrepItem {
                clone_url,
                dest_rel,
                status: "present".to_string(),
                error: None,
            });
            continue;
        }

        // Clean up partial clones.
        if dest_abs.exists() {
            let _ = tokio::fs::remove_dir_all(&dest_abs).await;
        }

        let dest_parent = dest_abs.parent().unwrap_or(cwd);
        let _ = tokio::fs::create_dir_all(dest_parent).await;

        match git_clone_with_optional_token(token.as_deref(), &clone_url, &dest_abs).await {
            Ok(()) => items.push(RepoPrepItem {
                clone_url,
                dest_rel,
                status: "cloned".to_string(),
                error: None,
            }),
            Err(err) => {
                let msg = shorten_error(&format!("{err:#}"));
                items.push(RepoPrepItem {
                    clone_url,
                    dest_rel,
                    status: "failed".to_string(),
                    error: Some(msg),
                });
            }
        }
    }

    let mut repo_text = String::new();
    repo_text.push_str("Repositories (auto-cloned from your message when possible):\n");
    for it in &items {
        if it.status == "failed" {
            repo_text.push_str(&format!(
                "- {} -> {} ({})\n  error: {}\n",
                it.clone_url,
                it.dest_rel,
                it.status,
                it.error.as_deref().unwrap_or("unknown error")
            ));
        } else {
            repo_text.push_str(&format!(
                "- {} -> {} ({})\n",
                it.clone_url, it.dest_rel, it.status
            ));
        }
    }
    repo_text.push('\n');
    repo_text.push_str("Repo notes:\n");
    repo_text.push_str("- These repos live under the context directory, so you can reference files using the paths above.\n");
    repo_text.push_str("- When you want to modify repo files, return edits via `context_writes` using paths under the repo directory.\n");
    if token.is_none() {
        repo_text.push_str("- No GitHub token is configured; private repo clones will fail. Configure one in /admin/auth (GitHub) or set GITHUB_TOKEN.\n");
    }
    repo_text.push('\n');

    Ok((items, repo_text))
}

async fn git_clone_with_optional_token(
    token: Option<&str>,
    clone_url: &str,
    dest_dir: &Path,
) -> anyhow::Result<()> {
    // Ensure git is available.
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--no-tags")
        .arg("--single-branch")
        .arg("--")
        .arg(clone_url)
        .arg(dest_dir);

    cmd.env("GIT_LFS_SKIP_SMUDGE", "1");
    cmd.env("GIT_TERMINAL_PROMPT", "0");

    let askpass_path: Option<PathBuf> = if let Some(tok) = token {
        let p = write_git_askpass_script().await?;
        cmd.env("GIT_ASKPASS", &p);
        cmd.env("GRAIL_GITHUB_TOKEN", tok);
        Some(p)
    } else {
        None
    };

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let out = cmd.output().await.context("git clone")?;
    if let Some(p) = askpass_path {
        let _ = tokio::fs::remove_file(p).await;
    }
    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let (stderr, _) = crate::secrets::redact_secrets(stderr.trim());
    anyhow::bail!("git clone failed: {}", shorten_error(&stderr))
}

async fn write_git_askpass_script() -> anyhow::Result<PathBuf> {
    use std::fs::OpenOptions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let path = std::env::temp_dir().join(format!("grail-git-askpass-{}.sh", random_id("x")));
    let script = r#"#!/bin/sh
set -eu
prompt="$1"
case "$prompt" in
  *sername*) printf '%s\n' "x-access-token" ;;
  *assword*) printf '%s\n' "${GRAIL_GITHUB_TOKEN:-}" ;;
  *) printf '\n' ;;
esac
"#;

    let path2 = path.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut options = OpenOptions::new();
        options.truncate(true).write(true).create(true);
        #[cfg(unix)]
        {
            options.mode(0o700);
        }
        let mut f = options
            .open(&path2)
            .with_context(|| format!("open {}", path2.display()))?;
        f.write_all(script.as_bytes())
            .with_context(|| format!("write {}", path2.display()))?;
        f.flush()
            .with_context(|| format!("flush {}", path2.display()))?;
        Ok(())
    })
    .await
    .context("spawn_blocking write askpass")??;

    Ok(path)
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
    let mut whatsapp: Option<crate::whatsapp::WhatsAppClient> = None;
    let mut discord: Option<crate::discord::DiscordClient> = None;
    let mut msteams: Option<crate::msteams::TeamsClient> = None;
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
        "whatsapp" => {
            let Some(access_token) = crate::secrets::load_whatsapp_access_token_opt(state).await?
            else {
                anyhow::bail!("WHATSAPP_ACCESS_TOKEN is not configured");
            };
            let Some(phone_id) = crate::secrets::load_whatsapp_phone_number_id_opt(state).await?
            else {
                anyhow::bail!("WHATSAPP_PHONE_NUMBER_ID is not configured");
            };
            whatsapp = Some(crate::whatsapp::WhatsAppClient::new(
                state.http.clone(),
                access_token,
                phone_id,
            ));
            // No context fetching for WhatsApp yet.
            String::new()
        }
        "discord" => {
            let Some(bot_token) = crate::secrets::load_discord_bot_token_opt(state).await? else {
                anyhow::bail!("DISCORD_BOT_TOKEN is not configured");
            };
            discord = Some(crate::discord::DiscordClient::new(
                state.http.clone(),
                bot_token,
            ));
            // No context fetching for Discord yet.
            String::new()
        }
        "msteams" => {
            let Some(app_id) = crate::secrets::load_msteams_app_id_opt(state).await? else {
                anyhow::bail!("MSTEAMS_APP_ID is not configured");
            };
            let Some(app_password) = crate::secrets::load_msteams_app_password_opt(state).await?
            else {
                anyhow::bail!("MSTEAMS_APP_PASSWORD is not configured");
            };
            msteams = Some(crate::msteams::TeamsClient::new(
                state.http.clone(),
                app_id,
                app_password,
            ));
            // No context fetching for MS Teams yet.
            String::new()
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
    let browser = crate::codex::BrowserEnvConfig::from_env();
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
            &browser,
        )
        .await?;

    let conversation_key = if !task.conversation_key.trim().is_empty() {
        task.conversation_key.clone()
    } else {
        conversation_key_for_task(task)
    };
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

    let repo_context_text =
        match maybe_prepare_github_repos(state, &conversation_key, &cwd, task.prompt_text.trim())
            .await
        {
            Ok((_items, txt)) => txt,
            Err(err) => {
                warn!(error = %err, task_id = task.id, "failed to prepare github repos");
                format!(
                    "Repositories:\n- (repo preparation failed: {})\n\n",
                    shorten_error(&format!("{err:#}"))
                )
            }
        };

    let thread_id = codex
        .resume_or_start_thread(session.codex_thread_id.as_deref(), &settings, &cwd)
        .await?;
    session.codex_thread_id = Some(thread_id.clone());

    let thread_mem_key = observational_thread_memory_key(&conversation_key);
    let resource_mem_key = observational_resource_memory_key(task);
    let thread_mem = match db::get_observational_memory(&state.pool, &thread_mem_key).await {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, key = %thread_mem_key, "failed to load thread observational memory");
            None
        }
    };
    let resource_mem = if let Some(k) = resource_mem_key.as_deref() {
        match db::get_observational_memory(&state.pool, k).await {
            Ok(v) => v,
            Err(err) => {
                warn!(error = %err, key = %k, "failed to load resource observational memory");
                None
            }
        }
    } else {
        None
    };
    let observational_memory_text =
        format_observational_memory_for_prompt(thread_mem.as_ref(), resource_mem.as_ref());

    let input = build_turn_input(
        task,
        &settings,
        &observational_memory_text,
        &session.memory_summary,
        &context_text,
        &repo_context_text,
        allow_slack_mcp,
        allow_web_mcp,
        &browser,
    );

    let (trace_tx, mut trace_rx) = mpsc::unbounded_channel::<crate::codex::CodexTurnEvent>();
    let trace_pool = state.pool.clone();
    let trace_task_id = task.id;
    let trace_writer = tokio::spawn(async move {
        while let Some(event) = trace_rx.recv().await {
            if let Err(err) = db::create_task_trace(
                &trace_pool,
                trace_task_id,
                &event.event_type,
                &event.level,
                &event.message,
                &event.details,
            )
            .await
            {
                warn!(
                    error = %err,
                    task_id = trace_task_id,
                    "failed to persist task trace"
                );
            }
        }
    });

    let output_schema = agent_output_schema();

    let out = codex
        .run_turn(
            state,
            task,
            &thread_id,
            &settings,
            &cwd,
            &input,
            output_schema.clone(),
            Some(&trace_tx),
        )
        .await?;
    drop(trace_tx);
    let _ = trace_writer.await;

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

    let mut should_post_message = true;
    let mut should_persist_session = true;

    let reply_text = if let Some(parsed) = parsed {
        let mut should_reply = if task.is_proactive {
            parsed.should_reply.unwrap_or(false)
        } else {
            true
        };
        let is_browser_login_needed = parsed.browser_login_needed;
        if is_browser_login_needed {
            should_reply = true;
        }

        let requested_side_effects = !parsed.context_writes.is_empty()
            || !parsed.upload_files.is_empty()
            || !parsed.cron_jobs.is_empty()
            || !parsed.guardrail_rules.is_empty();
        if is_browser_login_needed && requested_side_effects {
            warn!(
                task_id = task.id,
                "browser-login request included side-effect fields; ignoring for this turn"
            );
        }

        if task.is_proactive && !should_reply {
            should_post_message = false;
            should_persist_session = false;
            "(proactive: skipped)".to_string()
        } else {
            // Apply durable updates.
            if settings.permissions_mode == crate::models::PermissionsMode::Full
                && settings.allow_context_writes
                && !is_browser_login_needed
            {
                apply_context_writes(&cwd, &parsed.context_writes).await?;
            }

            // --- Auto-upload files to Slack ---
            // Upload context_writes + agent-requested upload_files to the originating thread.
            if provider == "slack" && !is_browser_login_needed {
                if let Some(ref sl) = slack {
                    let thread = thread_opt(&task.thread_ts);

                    // Collect unique paths to upload.
                    let mut upload_paths: std::collections::HashSet<std::path::PathBuf> =
                        std::collections::HashSet::new();

                    // context_writes paths (only if context writes were actually applied).
                    if settings.permissions_mode == crate::models::PermissionsMode::Full
                        && settings.allow_context_writes
                    {
                        for cw in &parsed.context_writes {
                            // Source code repos can be large/noisy; don't auto-upload repo files.
                            // The agent can still explicitly request uploads via `upload_files`.
                            if is_under_repos_dir(&cw.path) {
                                continue;
                            }
                            let path = cwd.join(&cw.path);
                            upload_paths.insert(path);
                        }
                    }

                    // Agent-requested uploads.
                    for rel in &parsed.upload_files {
                        let path = cwd.join(rel);
                        upload_paths.insert(path);
                    }

                    for path in &upload_paths {
                        if path.exists() {
                            match tokio::fs::read(path).await {
                                Ok(content) => {
                                    let filename = path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "file".to_string());
                                    if let Err(err) = sl
                                        .upload_file_content(
                                            &task.channel_id,
                                            thread,
                                            &filename,
                                            &content,
                                        )
                                        .await
                                    {
                                        warn!(error = %err, file = %filename, "failed to upload file to slack");
                                    }
                                }
                                Err(err) => {
                                    warn!(error = %err, path = %path.display(), "failed to read file for upload");
                                }
                            }
                        } else {
                            warn!(path = %path.display(), "upload_files path does not exist");
                        }
                    }
                }
            }

            let (mem, redacted) = crate::secrets::redact_secrets(&parsed.updated_memory_summary);
            if redacted {
                warn!("redacted secrets from updated_memory_summary");
            }
            session.memory_summary = clamp_len(mem, 6_000);

            if settings.allow_cron && !is_browser_login_needed {
                if let Err(err) =
                    apply_agent_cron_jobs(state, task, &settings, &parsed.cron_jobs).await
                {
                    warn!(error = %err, "failed to apply agent cron jobs");
                }
            }
            if !is_browser_login_needed {
                if let Err(err) =
                    apply_agent_guardrail_rules(state, task, &settings, &parsed.guardrail_rules)
                        .await
                {
                    warn!(error = %err, "failed to apply agent guardrail rules");
                }
            }
            let (mut reply, redacted) = crate::secrets::redact_secrets(&parsed.reply);
            if redacted {
                warn!("redacted secrets from reply");
            }
            if is_browser_login_needed {
                reply = compose_browser_login_reply(
                    reply,
                    parsed.browser_login_url.as_deref(),
                    parsed.browser_login_instructions.as_deref(),
                    parsed.browser_profile.as_deref(),
                    &browser,
                );
            }
            reply
        }
    } else if task.is_proactive {
        should_post_message = false;
        should_persist_session = false;
        "(proactive: skipped - invalid agent output)".to_string()
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

    if should_persist_session {
        session.last_used_at = chrono::Utc::now().timestamp();
        db::upsert_session(&state.pool, &session).await?;
    }

    if should_post_message {
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
            "whatsapp" => {
                let wa = whatsapp.context("whatsapp client missing")?;
                wa.send_message(&task.channel_id, &reply_text).await?;
            }
            "discord" => {
                let dc = discord.context("discord client missing")?;
                dc.send_message(&task.channel_id, &reply_text).await?;
            }
            "msteams" => {
                let teams = msteams.context("msteams client missing")?;
                // thread_ts stores service_url|activity_id for reply threading.
                let parts: Vec<&str> = task.thread_ts.splitn(2, '|').collect();
                if parts.len() == 2 {
                    teams
                        .reply_to_activity(parts[0], &task.channel_id, parts[1], &reply_text)
                        .await?;
                } else {
                    // Fallback: post to conversation directly.
                    let service_url = if task.thread_ts.starts_with("http") {
                        task.thread_ts.as_str()
                    } else {
                        "https://smba.trafficmanager.net/teams"
                    };
                    teams
                        .send_message(service_url, &task.channel_id, &reply_text)
                        .await?;
                }
            }
            _ => {}
        }
        info!(task_id = task.id, provider = %provider, "replied");
    } else {
        info!(task_id = task.id, provider = %provider, "skipped reply");
    }

    // Best-effort: update observational memory after a successful reply.
    if should_post_message {
        if let Err(err) = update_observational_memory_for_turn(
            state,
            codex,
            task,
            &settings,
            &cwd,
            &context_text,
            &reply_text,
            &thread_mem_key,
            resource_mem_key.as_deref(),
        )
        .await
        {
            warn!(error = %err, task_id = task.id, "failed to update observational memory");
        }
    }

    Ok(reply_text)
}

async fn update_observational_memory_for_turn(
    state: &AppState,
    codex: &mut CodexManager,
    task: &crate::models::Task,
    settings: &crate::models::Settings,
    cwd: &std::path::Path,
    recent_context: &str,
    reply_text: &str,
    thread_memory_key: &str,
    resource_memory_key: Option<&str>,
) -> anyhow::Result<()> {
    // Run memory updates in a read-only sandbox even if the main agent is allowed to write.
    let mut mem_settings = settings.clone();
    mem_settings.permissions_mode = crate::models::PermissionsMode::Read;
    mem_settings.allow_context_writes = false;
    mem_settings.shell_network_access = false;

    observe_and_maybe_reflect(
        state,
        codex,
        task,
        &mem_settings,
        cwd,
        "thread",
        thread_memory_key,
        recent_context,
        reply_text,
    )
    .await?;

    if let Some(k) = resource_memory_key {
        observe_and_maybe_reflect(
            state,
            codex,
            task,
            &mem_settings,
            cwd,
            "resource",
            k,
            recent_context,
            reply_text,
        )
        .await?;
    }

    Ok(())
}

async fn observe_and_maybe_reflect(
    state: &AppState,
    codex: &mut CodexManager,
    task: &crate::models::Task,
    settings: &crate::models::Settings,
    cwd: &std::path::Path,
    scope: &str,
    memory_key: &str,
    recent_context: &str,
    reply_text: &str,
) -> anyhow::Result<()> {
    const REFLECT_AT_CHARS: usize = 30_000;
    const MAX_OBS_LOG_CHARS: usize = 12_000;
    const MAX_REFLECTION_CHARS: usize = 6_000;

    let existing = db::get_observational_memory(&state.pool, memory_key)
        .await?
        .unwrap_or(ObservationalMemory {
            memory_key: memory_key.to_string(),
            scope: scope.to_string(),
            observation_log: String::new(),
            reflection_summary: String::new(),
            updated_at: 0,
        });

    // --- Observer ---
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let observer_input = build_observer_input(
        scope,
        memory_key,
        &existing,
        task,
        recent_context,
        reply_text,
    );
    let observer_schema = observer_output_schema();
    let observer_thread_id = codex.resume_or_start_thread(None, settings, cwd).await?;
    let out = codex
        .run_turn(
            state,
            task,
            &observer_thread_id,
            settings,
            cwd,
            &observer_input,
            observer_schema,
            None,
        )
        .await?;
    let obs = parse_observer_json(&out.agent_message_text)?;
    let mut append = obs.append.trim().to_string();
    if append.is_empty() {
        return Ok(());
    }

    let (next, redacted) = crate::secrets::redact_secrets(&append);
    if redacted {
        warn!(memory_key, "redacted secrets from observer append");
    }
    append = next;

    let wrapped = format!("\nDate: {date}\n{append}\n");
    db::append_observational_memory(&state.pool, memory_key, scope, &wrapped).await?;

    // --- Reflector (optional) ---
    let Some(updated) = db::get_observational_memory(&state.pool, memory_key).await? else {
        return Ok(());
    };
    if updated.observation_log.len() < REFLECT_AT_CHARS {
        return Ok(());
    }

    let reflector_input = build_reflector_input(scope, memory_key, &updated);
    let reflector_schema = reflector_output_schema();
    let reflector_thread_id = codex.resume_or_start_thread(None, settings, cwd).await?;
    let out = codex
        .run_turn(
            state,
            task,
            &reflector_thread_id,
            settings,
            cwd,
            &reflector_input,
            reflector_schema,
            None,
        )
        .await?;
    let mut refl = parse_reflector_json(&out.agent_message_text)?;

    let (rs, redacted) = crate::secrets::redact_secrets(&refl.reflection_summary);
    if redacted {
        warn!(memory_key, "redacted secrets from reflection_summary");
    }
    refl.reflection_summary = clamp_len(rs, MAX_REFLECTION_CHARS);

    let (ol, redacted) = crate::secrets::redact_secrets(&refl.observation_log);
    if redacted {
        warn!(memory_key, "redacted secrets from observation_log");
    }
    refl.observation_log = take_last_chars(ol.trim(), MAX_OBS_LOG_CHARS);

    db::set_observational_memory(
        &state.pool,
        memory_key,
        scope,
        &refl.observation_log,
        &refl.reflection_summary,
    )
    .await?;

    Ok(())
}

fn build_observer_input(
    scope: &str,
    memory_key: &str,
    existing: &ObservationalMemory,
    task: &crate::models::Task,
    recent_context: &str,
    reply_text: &str,
) -> String {
    // Keep the prompt stable and constrained. The observer should produce only new, durable notes.
    let mut s = String::new();
    s.push_str("You are the Observational Memory Observer.\n");
    s.push_str(
        "Your job is to extract durable, useful observations from a single completed chat turn.\n",
    );
    s.push_str("Do NOT include secrets (tokens, API keys, passwords).\n");
    s.push_str("Do NOT restate the whole conversation. Prefer short bullets.\n");
    s.push_str("If there is nothing worth remembering long-term, return an empty string.\n\n");

    s.push_str("Memory target:\n");
    s.push_str(&format!("- scope: {scope}\n"));
    s.push_str(&format!("- memory_key: {memory_key}\n\n"));

    if !existing.reflection_summary.trim().is_empty() {
        s.push_str("Existing reflection summary:\n");
        s.push_str(existing.reflection_summary.trim());
        s.push_str("\n\n");
    }
    if !existing.observation_log.trim().is_empty() {
        s.push_str("Existing observation log (tail):\n");
        s.push_str(tail_chars(existing.observation_log.trim(), 4_000).trim());
        s.push_str("\n\n");
    }

    s.push_str("Turn metadata:\n");
    s.push_str(&format!("- provider: {}\n", task.provider));
    s.push_str(&format!("- workspace_id: {}\n", task.workspace_id));
    s.push_str(&format!("- channel_id: {}\n", task.channel_id));
    s.push_str(&format!("- thread_ts: {}\n", task.thread_ts));
    s.push_str(&format!(
        "- requested_by_user_id: {}\n",
        task.requested_by_user_id
    ));
    s.push_str(&format!("- event_ts: {}\n\n", task.event_ts));

    let (recent_context, rc_redacted) = crate::secrets::redact_secrets(recent_context.trim());
    let (prompt_text, p_redacted) = crate::secrets::redact_secrets(task.prompt_text.trim());
    let (reply_text, r_redacted) = crate::secrets::redact_secrets(reply_text.trim());
    if rc_redacted || p_redacted || r_redacted {
        warn!(memory_key, "redacted secrets from observer input");
    }

    s.push_str("Recent chat context (oldest -> newest):\n");
    s.push_str(recent_context.trim());
    s.push_str("\n\n");

    s.push_str("User request:\n");
    s.push_str(prompt_text.trim());
    s.push_str("\n\n");

    s.push_str("Agent reply:\n");
    s.push_str(reply_text.trim());
    s.push_str("\n\n");

    s.push_str("Return ONLY valid JSON:\n");
    s.push_str("{\"append\":\"<bullets>\"}\n");
    s.push_str("Rules for append:\n");
    s.push_str("- Either empty string, OR a markdown bullet list starting with '- '.\n");
    s.push_str("- Each bullet is a durable fact, preference, decision, or task outcome.\n");
    s
}

fn build_reflector_input(scope: &str, memory_key: &str, mem: &ObservationalMemory) -> String {
    let mut s = String::new();
    s.push_str("You are the Observational Memory Reflector.\n");
    s.push_str("Your job is to condense an observation log into a stable reflection summary and a shorter observation log.\n");
    s.push_str("Do NOT include secrets (tokens, API keys, passwords).\n\n");

    s.push_str("Memory target:\n");
    s.push_str(&format!("- scope: {scope}\n"));
    s.push_str(&format!("- memory_key: {memory_key}\n\n"));

    if !mem.reflection_summary.trim().is_empty() {
        s.push_str("Existing reflection summary:\n");
        s.push_str(mem.reflection_summary.trim());
        s.push_str("\n\n");
    }

    s.push_str("Observation log:\n");
    // We intentionally cap what we send here to keep costs predictable.
    s.push_str(tail_chars(mem.observation_log.trim(), 20_000).trim());
    s.push_str("\n\n");

    s.push_str("Return ONLY valid JSON:\n");
    s.push_str("{\"reflection_summary\":\"<summary>\",\"observation_log\":\"<trimmed_log>\"}\n");
    s.push_str("Rules:\n");
    s.push_str("- reflection_summary: concise markdown bullets of durable patterns/goals/preferences/important facts.\n");
    s.push_str("- observation_log: keep only the most recent raw observations (tail), as markdown, shorter than the input.\n");
    s
}

fn observer_output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "append": { "type": "string" }
        },
        "required": ["append"],
        "additionalProperties": false
    })
}

fn reflector_output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "reflection_summary": { "type": "string" },
            "observation_log": { "type": "string" }
        },
        "required": ["reflection_summary", "observation_log"],
        "additionalProperties": false
    })
}

#[derive(Debug, Deserialize)]
struct ObserverJson {
    append: String,
}

#[derive(Debug, Deserialize)]
struct ReflectorJson {
    reflection_summary: String,
    observation_log: String,
}

fn parse_observer_json(text: &str) -> anyhow::Result<ObserverJson> {
    parse_json_object(text).context("parse observer json")
}

fn parse_reflector_json(text: &str) -> anyhow::Result<ReflectorJson> {
    parse_json_object(text).context("parse reflector json")
}

fn parse_json_object<T: for<'de> Deserialize<'de>>(text: &str) -> anyhow::Result<T> {
    let t = strip_code_fences(text).trim();
    if t.is_empty() {
        anyhow::bail!("empty json");
    }
    if let Ok(v) = serde_json::from_str::<T>(t) {
        return Ok(v);
    }
    let Some(start) = t.find('{') else {
        anyhow::bail!("no json object start");
    };
    let Some(end) = t.rfind('}') else {
        anyhow::bail!("no json object end");
    };
    if end <= start {
        anyhow::bail!("invalid json span");
    }
    let slice = &t[start..=end];
    serde_json::from_str::<T>(slice).context("deserialize json object")
}

fn conversation_key_for_task(task: &crate::models::Task) -> String {
    // Proactive Slack tasks reply in-thread by default, even for "root" messages where
    // Slack sets thread_ts == event_ts. Use a per-thread key so proactive mode doesn't
    // stuff every channel message into the shared ":main" session.
    if task.is_proactive && !task.thread_ts.is_empty() {
        return format!(
            "{}:{}:thread:{}",
            task.workspace_id, task.channel_id, task.thread_ts
        );
    }
    if !task.thread_ts.is_empty() && task.thread_ts != task.event_ts {
        format!(
            "{}:{}:thread:{}",
            task.workspace_id, task.channel_id, task.thread_ts
        )
    } else {
        format!("{}:{}:main", task.workspace_id, task.channel_id)
    }
}

fn observational_thread_memory_key(conversation_key: &str) -> String {
    format!("thread:{conversation_key}")
}

fn observational_resource_memory_key(task: &crate::models::Task) -> Option<String> {
    let provider = task.provider.trim().to_ascii_lowercase();
    let user = task.requested_by_user_id.trim();
    if provider.is_empty() || user.is_empty() || user == "unknown" {
        return None;
    }
    Some(format!("resource:{provider}:{}:{user}", task.workspace_id))
}

fn take_last_chars(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    s.chars()
        .rev()
        .take(max)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn tail_chars(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    format!("...{}", take_last_chars(s, max))
}

fn format_observational_memory_for_prompt(
    thread_mem: Option<&ObservationalMemory>,
    resource_mem: Option<&ObservationalMemory>,
) -> String {
    const MAX_REFLECTION_CHARS: usize = 4_000;
    const MAX_OBSERVATION_TAIL_CHARS: usize = 12_000;

    let mut out = String::new();

    if let Some(m) = resource_mem {
        out.push_str("Resource scope (user):\n");
        if !m.reflection_summary.trim().is_empty() {
            out.push_str("Reflection:\n");
            out.push_str(
                clamp_len(
                    m.reflection_summary.trim().to_string(),
                    MAX_REFLECTION_CHARS,
                )
                .trim(),
            );
            out.push('\n');
        }
        if !m.observation_log.trim().is_empty() {
            out.push_str("Observations (most recent tail):\n");
            out.push_str(tail_chars(m.observation_log.trim(), MAX_OBSERVATION_TAIL_CHARS).trim());
            out.push('\n');
        }
        out.push('\n');
    }

    if let Some(m) = thread_mem {
        out.push_str("Thread scope (conversation):\n");
        if !m.reflection_summary.trim().is_empty() {
            out.push_str("Reflection:\n");
            out.push_str(
                clamp_len(
                    m.reflection_summary.trim().to_string(),
                    MAX_REFLECTION_CHARS,
                )
                .trim(),
            );
            out.push('\n');
        }
        if !m.observation_log.trim().is_empty() {
            out.push_str("Observations (most recent tail):\n");
            out.push_str(tail_chars(m.observation_log.trim(), MAX_OBSERVATION_TAIL_CHARS).trim());
            out.push('\n');
        }
        out.push('\n');
    }

    out.trim().to_string()
}

fn thread_opt(thread_ts: &str) -> Option<&str> {
    let t = thread_ts.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub fn agent_output_schema() -> serde_json::Value {
    // NOTE: Codex forwards this schema to the OpenAI "structured outputs" backend.
    // That backend requires that for every object schema:
    // - `required` is present
    // - `required` contains *every* key in `properties`
    // Optional fields must be represented as nullable (e.g., `anyOf: [{...}, {type:null}]`).
    serde_json::json!({
        "type": "object",
    "properties": {
        "should_reply": { "type": "boolean", "description": "If false, do not reply in chat. Used for proactive Slack mode." },
        "reply": { "type": "string" },
        "browser_login_needed": { "type": "boolean", "default": false },
        "browser_login_url": { "anyOf": [{ "type": "string" }, { "type": "null" }], "default": null },
        "browser_login_instructions": {
            "anyOf": [{ "type": "string" }, { "type": "null" }],
            "default": null
        },
        "browser_profile": {
            "anyOf": [{ "type": "string" }, { "type": "null" }],
            "default": null
        },
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
            },
            "upload_files": {
                "type": "array",
                "items": { "type": "string" },
                "default": []
            }
        },
        "required": [
            "should_reply",
            "reply",
            "browser_login_needed",
            "browser_login_url",
            "browser_login_instructions",
            "browser_profile",
            "updated_memory_summary",
            "context_writes",
            "upload_files",
            "cron_jobs",
            "guardrail_rules"
        ],
        "additionalProperties": false
    })
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
        // Show any file attachments in the context.
        for f in &m.files {
            let fname = f.name.as_deref().unwrap_or("unknown");
            let mime = f.mimetype.as_deref().unwrap_or("");
            out.push_str(&format!("    [file: {} ({})]", fname, mime));
            out.push('\n');
        }
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
    observational_memory: &str,
    memory_summary: &str,
    recent_context: &str,
    repo_context: &str,
    allow_slack_mcp: bool,
    allow_web_mcp: bool,
    browser: &crate::codex::BrowserEnvConfig,
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
    s.push_str(&format!("- is_proactive: {}\n", task.is_proactive));
    s.push_str(&format!("- workspace_id: {}\n", task.workspace_id));
    s.push_str(&format!("- channel_id: {}\n", task.channel_id));
    s.push_str(&format!("- thread_ts: {}\n", task.thread_ts));
    s.push_str(&format!(
        "- requested_by: <@{}>\n",
        task.requested_by_user_id
    ));
    s.push_str(&format!("- event_ts: {}\n\n", task.event_ts));

    if task.is_proactive && task.provider.trim().eq_ignore_ascii_case("slack") {
        s.push_str("Proactive Slack mode:\n");
        s.push_str("- You were triggered by seeing a channel message without being explicitly @mentioned.\n");
        s.push_str("- First decide if you should reply. If not clearly relevant, set `should_reply=false`.\n");
        s.push_str("- If `should_reply=false`, you MUST set:\n");
        s.push_str("  - reply: \"\" (empty)\n");
        s.push_str("  - context_writes: []\n");
        s.push_str("  - upload_files: []\n");
        s.push_str("  - cron_jobs: []\n");
        s.push_str("  - guardrail_rules: []\n");
        s.push_str("  - updated_memory_summary: \"\" (empty)\n");
        if settings.slack_proactive_snippet.trim().is_empty() {
            s.push_str("- No proactive snippet is configured. Default policy: only reply when the message is a high-confidence request for help or contains actionable work for you.\n\n");
        } else {
            s.push_str("Relevance snippet (authoritative):\n");
            s.push_str(settings.slack_proactive_snippet.trim());
            s.push_str("\n\n");
        }
    }

    s.push_str("Observational memory (auto-extracted, long-term, no secrets):\n");
    if observational_memory.trim().is_empty() {
        s.push_str("(none)\n\n");
    } else {
        s.push_str(observational_memory.trim());
        s.push_str("\n\n");
    }

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

    s.push_str("Browser automation:\n");
    if browser.enabled {
        s.push_str("Browser automation is enabled.\n");
        s.push_str(&format!("- CDP URL: {}\n", browser.cdp_url));
        s.push_str(&format!("- CDP port: {}\n", browser.cdp_port));
        s.push_str(&format!("- Profile: {}\n", browser.profile_name));
        s.push_str("- Never ask the user to send passwords, OTP codes, or secrets in chat.\n");
        if browser.novnc_enabled && !browser.novnc_url.is_empty() {
            s.push_str(&format!("- noVNC URL: {}\n", browser.novnc_url));
            s.push_str(
                "If login is blocked by MFA/captcha, request a manual browser handoff by setting `browser_login_needed=true`.\n",
            );
            s.push_str(
                "Include `browser_login_url` (a noVNC URL), `browser_login_instructions`, and `browser_profile` in that reply.\n",
            );
            s.push_str(
                "- For scripted browser automation, use `uv run` (or an equivalent runner) and point your browser tool/driver to the CDP URL above.\n",
            );
        } else {
            s.push_str("- noVNC is not enabled. Manual browser handoff is limited.\n");
        }
        s.push_str("- Do not apply side effects (context_writes/upload_files/cron_jobs/guardrail_rules) when `browser_login_needed=true`.\n\n");
    } else {
        s.push_str("Browser automation is disabled.\n\n");
    }

    s.push_str("User request:\n");
    s.push_str(task.prompt_text.trim());
    s.push_str("\n\n");

    // Include file attachment info if present.
    if !task.files_json.is_empty() {
        if let Ok(files) = serde_json::from_str::<Vec<serde_json::Value>>(&task.files_json) {
            if !files.is_empty() {
                s.push_str("Files attached to this message:\n");
                for f in &files {
                    let name = f["name"].as_str().unwrap_or("unknown");
                    let mime = f["mimetype"].as_str().unwrap_or("");
                    let path = f["local_path"].as_str().unwrap_or("(unavailable)");
                    s.push_str(&format!("- {name} ({mime}) → {path}\n"));
                }
                s.push_str("\n");
            }
        }
    }

    if repo_context.trim().is_empty() {
        s.push_str("Repositories:\n(none)\n\n");
    } else {
        s.push_str(repo_context.trim());
        s.push_str("\n\n");
    }

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

    s.push_str("File uploads:\n");
    s.push_str("- Slack only: files written via `context_writes` are auto-uploaded, except files under `repos/`.\n");
    s.push_str("- To upload specific repo files (or a patch/diff you generated), list them in `upload_files` (relative paths under the context directory).\n\n");

    s.push_str("Reply control:\n");
    s.push_str("- Always include `should_reply`.\n");
    s.push_str("- For normal (non-proactive) tasks, set `should_reply=true`.\n");
    s.push_str("- Only set `should_reply=false` for proactive Slack tasks when you should stay silent.\n\n");

    s.push_str("Return ONLY a single JSON object matching the provided JSON schema.\n");
    s
}

#[derive(Debug, Deserialize)]
struct AgentJson {
    #[serde(default)]
    should_reply: Option<bool>,
    reply: String,
    #[serde(default)]
    browser_login_needed: bool,
    #[serde(default)]
    browser_login_url: Option<String>,
    #[serde(default)]
    browser_login_instructions: Option<String>,
    #[serde(default)]
    browser_profile: Option<String>,
    updated_memory_summary: String,
    #[serde(default)]
    context_writes: Vec<ContextWrite>,
    #[serde(default)]
    upload_files: Vec<String>,
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

fn compose_browser_login_reply(
    reply: String,
    browser_login_url: Option<&str>,
    browser_login_instructions: Option<&str>,
    browser_profile: Option<&str>,
    browser: &crate::codex::BrowserEnvConfig,
) -> String {
    let mut out = String::new();

    let base = reply.trim();
    if base.is_empty() {
        out.push_str("I hit an authentication step that needs manual browser login.");
    } else {
        out.push_str(base);
    }

    let profile_name = browser_profile
        .filter(|p| !p.trim().is_empty())
        .unwrap_or(&browser.profile_name);

    let url = browser_login_url
        .filter(|url| !url.trim().is_empty())
        .or_else(|| {
            if browser.novnc_enabled && !browser.novnc_url.is_empty() {
                Some(browser.novnc_url.as_str())
            } else {
                None
            }
        });

    out.push('\n');
    out.push('\n');
    out.push_str("Manual browser login is needed to continue:");
    match url {
        Some(novnc_url) => {
            out.push_str(&format!("\n- Open: {novnc_url}"));
        }
        None => {
            out.push_str("\n- NoVNC URL is not available in this environment.");
        }
    }
    out.push_str(&format!("\n- Use browser profile: {profile_name}"));
    out.push_str("\n- Finish the authentication flow in the browser and let me continue here when you are signed in.");
    out.push_str(
        "\n- Do not share credentials or OTP codes in chat; log in directly in the browser window.",
    );

    let instructions = browser_login_instructions
        .filter(|text| !text.trim().is_empty())
        .unwrap_or("Keep the browser session active so I can continue with the task.");
    out.push('\n');
    out.push_str(&format!("- Instructions: {instructions}"));

    out
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
                None,
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

fn is_under_repos_dir(path: &str) -> bool {
    use std::path::Component;

    let p = std::path::Path::new(path.trim());
    matches!(
        p.components().next(),
        Some(Component::Normal(os)) if os == std::ffi::OsStr::new("repos")
    )
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
