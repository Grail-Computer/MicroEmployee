use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::models::{
    Approval, CodexDeviceLogin, CronJob, GuardrailRule, PermissionsMode, Session, Settings, Task,
    TelegramMessage,
};

pub async fn init_sqlite(db_path: &Path) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .with_context(|| format!("connect sqlite at {}", db_path.display()))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    Ok(pool)
}

pub async fn get_settings(pool: &SqlitePool) -> anyhow::Result<Settings> {
    let row = sqlx::query(
        r#"
        SELECT
          context_last_n,
          model,
          reasoning_effort,
          reasoning_summary,
          permissions_mode,
          workspace_id,
          slack_allow_from,
          slack_allow_channels,
          slack_proactive_enabled,
          slack_proactive_snippet,
          allow_telegram,
          telegram_allow_from,
          allow_slack_mcp,
          allow_web_mcp,
          extra_mcp_config,
          allow_context_writes,
          shell_network_access,
          allow_cron,
          auto_apply_cron_jobs,
          agent_name,
          role_description,
          command_approval_mode,
          auto_apply_guardrail_tighten,
          web_allow_domains,
          web_deny_domains,
          updated_at
        FROM settings
        WHERE id = 1
        "#,
    )
    .fetch_one(pool)
    .await
    .context("select settings")?;

    Ok(Settings {
        context_last_n: row.get::<i64, _>("context_last_n"),
        model: row.get::<Option<String>, _>("model"),
        reasoning_effort: row.get::<Option<String>, _>("reasoning_effort"),
        reasoning_summary: row.get::<Option<String>, _>("reasoning_summary"),
        permissions_mode: PermissionsMode::from_db_str(
            row.get::<String, _>("permissions_mode").as_str(),
        ),
        workspace_id: row.get::<Option<String>, _>("workspace_id"),
        slack_allow_from: row
            .get::<Option<String>, _>("slack_allow_from")
            .unwrap_or_default(),
        slack_allow_channels: row
            .get::<Option<String>, _>("slack_allow_channels")
            .unwrap_or_default(),
        slack_proactive_enabled: row.get::<i64, _>("slack_proactive_enabled") != 0,
        slack_proactive_snippet: row
            .get::<Option<String>, _>("slack_proactive_snippet")
            .unwrap_or_default(),
        allow_telegram: row.get::<i64, _>("allow_telegram") != 0,
        telegram_allow_from: row
            .get::<Option<String>, _>("telegram_allow_from")
            .unwrap_or_default(),
        allow_slack_mcp: row.get::<i64, _>("allow_slack_mcp") != 0,
        allow_web_mcp: row.get::<i64, _>("allow_web_mcp") != 0,
        extra_mcp_config: row
            .get::<Option<String>, _>("extra_mcp_config")
            .unwrap_or_default(),
        allow_context_writes: row.get::<i64, _>("allow_context_writes") != 0,
        shell_network_access: row.get::<i64, _>("shell_network_access") != 0,
        allow_cron: row.get::<i64, _>("allow_cron") != 0,
        auto_apply_cron_jobs: row.get::<i64, _>("auto_apply_cron_jobs") != 0,
        agent_name: row
            .get::<Option<String>, _>("agent_name")
            .unwrap_or_else(|| "Grail".to_string()),
        role_description: row
            .get::<Option<String>, _>("role_description")
            .unwrap_or_default(),
        command_approval_mode: row
            .get::<Option<String>, _>("command_approval_mode")
            .unwrap_or_else(|| "guardrails".to_string()),
        auto_apply_guardrail_tighten: row.get::<i64, _>("auto_apply_guardrail_tighten") != 0,
        web_allow_domains: row
            .get::<Option<String>, _>("web_allow_domains")
            .unwrap_or_default(),
        web_deny_domains: row
            .get::<Option<String>, _>("web_deny_domains")
            .unwrap_or_default(),
        updated_at: row.get::<i64, _>("updated_at"),
    })
}

pub async fn update_settings(pool: &SqlitePool, settings: &Settings) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE settings
        SET context_last_n = ?,
            model = ?,
            reasoning_effort = ?,
            reasoning_summary = ?,
            permissions_mode = ?,
            slack_allow_from = ?,
            slack_allow_channels = ?,
            slack_proactive_enabled = ?,
            slack_proactive_snippet = ?,
            allow_telegram = ?,
            telegram_allow_from = ?,
            allow_slack_mcp = ?,
            allow_web_mcp = ?,
            extra_mcp_config = ?,
            allow_context_writes = ?,
            shell_network_access = ?,
            allow_cron = ?,
            auto_apply_cron_jobs = ?,
            agent_name = ?,
            role_description = ?,
            command_approval_mode = ?,
            auto_apply_guardrail_tighten = ?,
            web_allow_domains = ?,
            web_deny_domains = ?,
            updated_at = unixepoch()
        WHERE id = 1
        "#,
    )
    .bind(settings.context_last_n)
    .bind(settings.model.as_deref())
    .bind(settings.reasoning_effort.as_deref())
    .bind(settings.reasoning_summary.as_deref())
    .bind(settings.permissions_mode.as_db_str())
    .bind(settings.slack_allow_from.as_str())
    .bind(settings.slack_allow_channels.as_str())
    .bind(if settings.slack_proactive_enabled {
        1
    } else {
        0
    })
    .bind(settings.slack_proactive_snippet.as_str())
    .bind(if settings.allow_telegram { 1 } else { 0 })
    .bind(settings.telegram_allow_from.as_str())
    .bind(if settings.allow_slack_mcp { 1 } else { 0 })
    .bind(if settings.allow_web_mcp { 1 } else { 0 })
    .bind(settings.extra_mcp_config.as_str())
    .bind(if settings.allow_context_writes { 1 } else { 0 })
    .bind(if settings.shell_network_access { 1 } else { 0 })
    .bind(if settings.allow_cron { 1 } else { 0 })
    .bind(if settings.auto_apply_cron_jobs { 1 } else { 0 })
    .bind(settings.agent_name.as_str())
    .bind(settings.role_description.as_str())
    .bind(settings.command_approval_mode.as_str())
    .bind(if settings.auto_apply_guardrail_tighten {
        1
    } else {
        0
    })
    .bind(settings.web_allow_domains.as_str())
    .bind(settings.web_deny_domains.as_str())
    .execute(pool)
    .await
    .context("update settings")?;
    Ok(())
}

pub async fn set_workspace_id_if_missing(
    pool: &SqlitePool,
    workspace_id: &str,
) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE settings
        SET workspace_id = ?1,
            updated_at = unixepoch()
        WHERE id = 1
          AND (workspace_id IS NULL OR workspace_id = '')
        "#,
    )
    .bind(workspace_id)
    .execute(pool)
    .await
    .context("set workspace_id")?;
    Ok(res.rows_affected() == 1)
}

pub async fn upsert_secret(
    pool: &SqlitePool,
    key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO secrets (key, nonce, ciphertext, updated_at)
        VALUES (?1, ?2, ?3, unixepoch())
        ON CONFLICT(key) DO UPDATE SET
          nonce = excluded.nonce,
          ciphertext = excluded.ciphertext,
          updated_at = excluded.updated_at
        "#,
    )
    .bind(key)
    .bind(nonce)
    .bind(ciphertext)
    .execute(pool)
    .await
    .context("upsert secret")?;
    Ok(())
}

pub async fn delete_secret(pool: &SqlitePool, key: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM secrets WHERE key = ?1")
        .bind(key)
        .execute(pool)
        .await
        .context("delete secret")?;
    Ok(())
}

pub async fn read_secret(
    pool: &SqlitePool,
    key: &str,
) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let row = sqlx::query("SELECT nonce, ciphertext FROM secrets WHERE key = ?1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .context("read secret")?;
    Ok(row.map(|r| (r.get::<Vec<u8>, _>(0), r.get::<Vec<u8>, _>(1))))
}

pub async fn try_mark_event_processed(
    pool: &SqlitePool,
    workspace_id: &str,
    event_id: &str,
) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        INSERT INTO processed_events (workspace_id, event_id, processed_at)
        VALUES (?1, ?2, unixepoch())
        ON CONFLICT(workspace_id, event_id) DO NOTHING
        "#,
    )
    .bind(workspace_id)
    .bind(event_id)
    .execute(pool)
    .await
    .context("insert processed event")?;

    Ok(res.rows_affected() == 1)
}

pub async fn enqueue_task(
    pool: &SqlitePool,
    provider: &str,
    workspace_id: &str,
    channel_id: &str,
    thread_ts: &str,
    event_ts: &str,
    requested_by_user_id: &str,
    prompt_text: &str,
) -> anyhow::Result<i64> {
    enqueue_task_with_files(
        pool,
        provider,
        workspace_id,
        channel_id,
        thread_ts,
        event_ts,
        requested_by_user_id,
        prompt_text,
        "",
        false,
    )
    .await
}

pub async fn enqueue_task_with_files(
    pool: &SqlitePool,
    provider: &str,
    workspace_id: &str,
    channel_id: &str,
    thread_ts: &str,
    event_ts: &str,
    requested_by_user_id: &str,
    prompt_text: &str,
    files_json: &str,
    is_proactive: bool,
) -> anyhow::Result<i64> {
    let res = sqlx::query(
        r#"
        INSERT INTO tasks (
          provider,
          status,
          workspace_id,
          channel_id,
          thread_ts,
          event_ts,
          requested_by_user_id,
          prompt_text,
          files_json,
          is_proactive,
          created_at
        )
        VALUES (?1, 'queued', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, unixepoch())
        "#,
    )
    .bind(provider)
    .bind(workspace_id)
    .bind(channel_id)
    .bind(thread_ts)
    .bind(event_ts)
    .bind(requested_by_user_id)
    .bind(prompt_text)
    .bind(files_json)
    .bind(if is_proactive { 1 } else { 0 })
    .execute(pool)
    .await
    .context("insert task")?;

    Ok(res.last_insert_rowid())
}

pub async fn list_cron_jobs(pool: &SqlitePool, limit: i64) -> anyhow::Result<Vec<CronJob>> {
    let rows = sqlx::query(
        r#"
        SELECT
          id,
          name,
          enabled,
          mode,
          schedule_kind,
          every_seconds,
          cron_expr,
          at_ts,
          workspace_id,
          channel_id,
          thread_ts,
          prompt_text,
          next_run_at,
          last_run_at,
          last_status,
          last_error,
          created_at,
          updated_at
        FROM cron_jobs
        ORDER BY created_at DESC
        LIMIT ?1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("list cron jobs")?;

    Ok(rows
        .into_iter()
        .map(|r| CronJob {
            id: r.get::<String, _>("id"),
            name: r.get::<String, _>("name"),
            enabled: r.get::<i64, _>("enabled") != 0,
            mode: r
                .get::<Option<String>, _>("mode")
                .unwrap_or_else(|| "agent".to_string()),
            schedule_kind: r.get::<String, _>("schedule_kind"),
            every_seconds: r.get::<Option<i64>, _>("every_seconds"),
            cron_expr: r.get::<Option<String>, _>("cron_expr"),
            at_ts: r.get::<Option<i64>, _>("at_ts"),
            workspace_id: r.get::<String, _>("workspace_id"),
            channel_id: r.get::<String, _>("channel_id"),
            thread_ts: r.get::<String, _>("thread_ts"),
            prompt_text: r.get::<String, _>("prompt_text"),
            next_run_at: r.get::<Option<i64>, _>("next_run_at"),
            last_run_at: r.get::<Option<i64>, _>("last_run_at"),
            last_status: r.get::<Option<String>, _>("last_status"),
            last_error: r.get::<Option<String>, _>("last_error"),
            created_at: r.get::<i64, _>("created_at"),
            updated_at: r.get::<i64, _>("updated_at"),
        })
        .collect())
}

pub async fn insert_cron_job(pool: &SqlitePool, job: &CronJob) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO cron_jobs (
          id,
          name,
          enabled,
          mode,
          schedule_kind,
          every_seconds,
          cron_expr,
          at_ts,
          workspace_id,
          channel_id,
          thread_ts,
          prompt_text,
          next_run_at,
          last_run_at,
          last_status,
          last_error,
          created_at,
          updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        "#,
    )
    .bind(&job.id)
    .bind(&job.name)
    .bind(if job.enabled { 1 } else { 0 })
    .bind(&job.mode)
    .bind(&job.schedule_kind)
    .bind(job.every_seconds)
    .bind(job.cron_expr.as_deref())
    .bind(job.at_ts)
    .bind(&job.workspace_id)
    .bind(&job.channel_id)
    .bind(&job.thread_ts)
    .bind(&job.prompt_text)
    .bind(job.next_run_at)
    .bind(job.last_run_at)
    .bind(job.last_status.as_deref())
    .bind(job.last_error.as_deref())
    .bind(job.created_at)
    .bind(job.updated_at)
    .execute(pool)
    .await
    .context("insert cron job")?;
    Ok(())
}

pub async fn delete_cron_job(pool: &SqlitePool, id: &str) -> anyhow::Result<bool> {
    let res = sqlx::query("DELETE FROM cron_jobs WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .context("delete cron job")?;
    Ok(res.rows_affected() == 1)
}

pub async fn set_cron_job_enabled(
    pool: &SqlitePool,
    id: &str,
    enabled: bool,
) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE cron_jobs
        SET enabled = ?2,
            updated_at = unixepoch()
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(if enabled { 1 } else { 0 })
    .execute(pool)
    .await
    .context("set cron job enabled")?;
    Ok(res.rows_affected() == 1)
}

pub async fn claim_due_cron_jobs(
    pool: &SqlitePool,
    now_ts: i64,
    limit: i64,
) -> anyhow::Result<Vec<CronJob>> {
    let mut tx = pool.begin().await.context("begin tx")?;

    let rows = sqlx::query(
        r#"
        SELECT
          id,
          name,
          enabled,
          mode,
          schedule_kind,
          every_seconds,
          cron_expr,
          at_ts,
          workspace_id,
          channel_id,
          thread_ts,
          prompt_text,
          next_run_at,
          last_run_at,
          last_status,
          last_error,
          created_at,
          updated_at
        FROM cron_jobs
        WHERE enabled = 1
          AND next_run_at IS NOT NULL
          AND next_run_at <= ?1
        ORDER BY next_run_at ASC
        LIMIT ?2
        "#,
    )
    .bind(now_ts)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .context("select due cron jobs")?;

    // Mark claimed with last_run_at and last_status='queued' (next_run_at will be computed in app code).
    for r in &rows {
        let id = r.get::<String, _>("id");
        sqlx::query(
            r#"
            UPDATE cron_jobs
            SET last_run_at = ?2,
                last_status = 'queued',
                last_error = NULL,
                updated_at = unixepoch()
            WHERE id = ?1
            "#,
        )
        .bind(&id)
        .bind(now_ts)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("mark cron job claimed {id}"))?;
    }

    tx.commit().await.context("commit tx")?;

    Ok(rows
        .into_iter()
        .map(|r| CronJob {
            id: r.get::<String, _>("id"),
            name: r.get::<String, _>("name"),
            enabled: r.get::<i64, _>("enabled") != 0,
            mode: r
                .get::<Option<String>, _>("mode")
                .unwrap_or_else(|| "agent".to_string()),
            schedule_kind: r.get::<String, _>("schedule_kind"),
            every_seconds: r.get::<Option<i64>, _>("every_seconds"),
            cron_expr: r.get::<Option<String>, _>("cron_expr"),
            at_ts: r.get::<Option<i64>, _>("at_ts"),
            workspace_id: r.get::<String, _>("workspace_id"),
            channel_id: r.get::<String, _>("channel_id"),
            thread_ts: r.get::<String, _>("thread_ts"),
            prompt_text: r.get::<String, _>("prompt_text"),
            next_run_at: r.get::<Option<i64>, _>("next_run_at"),
            last_run_at: r.get::<Option<i64>, _>("last_run_at"),
            last_status: r.get::<Option<String>, _>("last_status"),
            last_error: r.get::<Option<String>, _>("last_error"),
            created_at: r.get::<i64, _>("created_at"),
            updated_at: r.get::<i64, _>("updated_at"),
        })
        .collect())
}

pub async fn update_cron_job_next_run_at(
    pool: &SqlitePool,
    id: &str,
    next_run_at: Option<i64>,
    enabled: bool,
    last_status: Option<&str>,
    last_error: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE cron_jobs
        SET next_run_at = ?2,
            enabled = ?3,
            last_status = COALESCE(?4, last_status),
            last_error = ?5,
            updated_at = unixepoch()
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(next_run_at)
    .bind(if enabled { 1 } else { 0 })
    .bind(last_status)
    .bind(last_error)
    .execute(pool)
    .await
    .context("update cron job next_run_at")?;
    Ok(())
}

pub async fn list_guardrail_rules(
    pool: &SqlitePool,
    kind: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<GuardrailRule>> {
    let rows = if let Some(kind) = kind {
        sqlx::query(
            r#"
            SELECT
              id,
              name,
              kind,
              pattern_kind,
              pattern,
              action,
              priority,
              enabled,
              created_at,
              updated_at
            FROM guardrail_rules
            WHERE kind = ?1
            ORDER BY enabled DESC, priority ASC, created_at ASC
            LIMIT ?2
            "#,
        )
        .bind(kind)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("list guardrail rules (kind)")?
    } else {
        sqlx::query(
            r#"
            SELECT
              id,
              name,
              kind,
              pattern_kind,
              pattern,
              action,
              priority,
              enabled,
              created_at,
              updated_at
            FROM guardrail_rules
            ORDER BY kind ASC, enabled DESC, priority ASC, created_at ASC
            LIMIT ?1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("list guardrail rules")?
    };

    Ok(rows
        .into_iter()
        .map(|r| GuardrailRule {
            id: r.get::<String, _>("id"),
            name: r.get::<String, _>("name"),
            kind: r.get::<String, _>("kind"),
            pattern_kind: r.get::<String, _>("pattern_kind"),
            pattern: r.get::<String, _>("pattern"),
            action: r.get::<String, _>("action"),
            priority: r.get::<i64, _>("priority"),
            enabled: r.get::<i64, _>("enabled") != 0,
            created_at: r.get::<i64, _>("created_at"),
            updated_at: r.get::<i64, _>("updated_at"),
        })
        .collect())
}

pub async fn insert_guardrail_rule(pool: &SqlitePool, rule: &GuardrailRule) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO guardrail_rules (
          id,
          name,
          kind,
          pattern_kind,
          pattern,
          action,
          priority,
          enabled,
          created_at,
          updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
    )
    .bind(&rule.id)
    .bind(&rule.name)
    .bind(&rule.kind)
    .bind(&rule.pattern_kind)
    .bind(&rule.pattern)
    .bind(&rule.action)
    .bind(rule.priority)
    .bind(if rule.enabled { 1 } else { 0 })
    .bind(rule.created_at)
    .bind(rule.updated_at)
    .execute(pool)
    .await
    .context("insert guardrail rule")?;
    Ok(())
}

pub async fn delete_guardrail_rule(pool: &SqlitePool, id: &str) -> anyhow::Result<bool> {
    let res = sqlx::query("DELETE FROM guardrail_rules WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .context("delete guardrail rule")?;
    Ok(res.rows_affected() == 1)
}

pub async fn set_guardrail_rule_enabled(
    pool: &SqlitePool,
    id: &str,
    enabled: bool,
) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE guardrail_rules
        SET enabled = ?2,
            updated_at = unixepoch()
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(if enabled { 1 } else { 0 })
    .execute(pool)
    .await
    .context("set guardrail rule enabled")?;
    Ok(res.rows_affected() == 1)
}

pub async fn insert_approval(pool: &SqlitePool, approval: &Approval) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO approvals (
          id,
          kind,
          status,
          decision,
          workspace_id,
          channel_id,
          thread_ts,
          requested_by_user_id,
          details_json,
          created_at,
          updated_at,
          resolved_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&approval.id)
    .bind(&approval.kind)
    .bind(&approval.status)
    .bind(approval.decision.as_deref())
    .bind(approval.workspace_id.as_deref())
    .bind(approval.channel_id.as_deref())
    .bind(approval.thread_ts.as_deref())
    .bind(approval.requested_by_user_id.as_deref())
    .bind(&approval.details_json)
    .bind(approval.created_at)
    .bind(approval.updated_at)
    .bind(approval.resolved_at)
    .execute(pool)
    .await
    .context("insert approval")?;
    Ok(())
}

pub async fn get_approval(pool: &SqlitePool, id: &str) -> anyhow::Result<Option<Approval>> {
    let row = sqlx::query(
        r#"
        SELECT
          id,
          kind,
          status,
          decision,
          workspace_id,
          channel_id,
          thread_ts,
          requested_by_user_id,
          details_json,
          created_at,
          updated_at,
          resolved_at
        FROM approvals
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("get approval")?;

    Ok(row.map(|r| Approval {
        id: r.get::<String, _>("id"),
        kind: r.get::<String, _>("kind"),
        status: r.get::<String, _>("status"),
        decision: r.get::<Option<String>, _>("decision"),
        workspace_id: r.get::<Option<String>, _>("workspace_id"),
        channel_id: r.get::<Option<String>, _>("channel_id"),
        thread_ts: r.get::<Option<String>, _>("thread_ts"),
        requested_by_user_id: r.get::<Option<String>, _>("requested_by_user_id"),
        details_json: r.get::<String, _>("details_json"),
        created_at: r.get::<i64, _>("created_at"),
        updated_at: r.get::<i64, _>("updated_at"),
        resolved_at: r.get::<Option<i64>, _>("resolved_at"),
    }))
}

pub async fn list_recent_approvals(pool: &SqlitePool, limit: i64) -> anyhow::Result<Vec<Approval>> {
    let rows = sqlx::query(
        r#"
        SELECT
          id,
          kind,
          status,
          decision,
          workspace_id,
          channel_id,
          thread_ts,
          requested_by_user_id,
          details_json,
          created_at,
          updated_at,
          resolved_at
        FROM approvals
        ORDER BY created_at DESC
        LIMIT ?1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("list approvals")?;

    Ok(rows
        .into_iter()
        .map(|r| Approval {
            id: r.get::<String, _>("id"),
            kind: r.get::<String, _>("kind"),
            status: r.get::<String, _>("status"),
            decision: r.get::<Option<String>, _>("decision"),
            workspace_id: r.get::<Option<String>, _>("workspace_id"),
            channel_id: r.get::<Option<String>, _>("channel_id"),
            thread_ts: r.get::<Option<String>, _>("thread_ts"),
            requested_by_user_id: r.get::<Option<String>, _>("requested_by_user_id"),
            details_json: r.get::<String, _>("details_json"),
            created_at: r.get::<i64, _>("created_at"),
            updated_at: r.get::<i64, _>("updated_at"),
            resolved_at: r.get::<Option<i64>, _>("resolved_at"),
        })
        .collect())
}

pub async fn resolve_approval(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    decision: &str,
) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE approvals
        SET status = ?2,
            decision = ?3,
            resolved_at = unixepoch(),
            updated_at = unixepoch()
        WHERE id = ?1
          AND status = 'pending'
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(decision)
    .execute(pool)
    .await
    .context("resolve approval")?;
    Ok(res.rows_affected() == 1)
}

pub async fn expire_approval(pool: &SqlitePool, id: &str) -> anyhow::Result<()> {
    let _ = sqlx::query(
        r#"
        UPDATE approvals
        SET status = 'expired',
            decision = NULL,
            resolved_at = unixepoch(),
            updated_at = unixepoch()
        WHERE id = ?1
          AND status = 'pending'
        "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .context("expire approval")?;
    Ok(())
}

pub async fn set_runtime_active_task(
    pool: &SqlitePool,
    task_id: Option<i64>,
) -> anyhow::Result<()> {
    if let Some(id) = task_id {
        sqlx::query(
            r#"
            UPDATE runtime_state
            SET active_task_id = ?1,
                active_task_started_at = unixepoch(),
                updated_at = unixepoch()
            WHERE id = 1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await
        .context("set runtime active task")?;
    } else {
        sqlx::query(
            r#"
            UPDATE runtime_state
            SET active_task_id = NULL,
                active_task_started_at = NULL,
                updated_at = unixepoch()
            WHERE id = 1
            "#,
        )
        .execute(pool)
        .await
        .context("clear runtime active task")?;
    }
    Ok(())
}

pub async fn get_runtime_active_task(pool: &SqlitePool) -> anyhow::Result<Option<(i64, i64)>> {
    let row = sqlx::query(
        r#"
        SELECT active_task_id, active_task_started_at
        FROM runtime_state
        WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .context("get runtime state")?;

    Ok(row.and_then(|r| {
        let id = r.get::<Option<i64>, _>("active_task_id")?;
        let started_at = r.get::<Option<i64>, _>("active_task_started_at")?;
        Some((id, started_at))
    }))
}

pub async fn claim_next_task(pool: &SqlitePool) -> anyhow::Result<Option<Task>> {
    let mut tx = pool.begin().await.context("begin tx")?;

    let row_opt = sqlx::query(
        r#"
        SELECT
          id,
          status,
          provider,
          is_proactive,
          workspace_id,
          channel_id,
          thread_ts,
          event_ts,
          requested_by_user_id,
          prompt_text,
          files_json,
          result_text,
          error_text,
          created_at,
          started_at,
          finished_at
        FROM tasks
        WHERE status = 'queued'
        ORDER BY created_at ASC, id ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(&mut *tx)
    .await
    .context("select next task")?;

    let Some(row) = row_opt else {
        tx.commit().await.context("commit tx")?;
        return Ok(None);
    };

    let id = row.get::<i64, _>("id");
    let updated = sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'running',
            started_at = unixepoch()
        WHERE id = ?1
          AND status = 'queued'
        "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .context("mark task running")?;

    if updated.rows_affected() != 1 {
        tx.commit().await.context("commit tx")?;
        return Ok(None);
    }

    tx.commit().await.context("commit tx")?;

    Ok(Some(Task {
        id,
        status: "running".to_string(),
        provider: row
            .get::<Option<String>, _>("provider")
            .unwrap_or_else(|| "slack".to_string()),
        is_proactive: row.get::<i64, _>("is_proactive") != 0,
        workspace_id: row.get::<String, _>("workspace_id"),
        channel_id: row.get::<String, _>("channel_id"),
        thread_ts: row.get::<String, _>("thread_ts"),
        event_ts: row.get::<String, _>("event_ts"),
        requested_by_user_id: row.get::<String, _>("requested_by_user_id"),
        prompt_text: row.get::<String, _>("prompt_text"),
        files_json: row.get::<String, _>("files_json"),
        result_text: row.get::<Option<String>, _>("result_text"),
        error_text: row.get::<Option<String>, _>("error_text"),
        created_at: row.get::<i64, _>("created_at"),
        started_at: Some(chrono::Utc::now().timestamp()),
        finished_at: row.get::<Option<i64>, _>("finished_at"),
    }))
}

pub async fn reset_running_tasks(pool: &SqlitePool) -> anyhow::Result<u64> {
    let res = sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'queued',
            started_at = NULL
        WHERE status = 'running'
        "#,
    )
    .execute(pool)
    .await
    .context("reset running tasks")?;
    Ok(res.rows_affected())
}

pub async fn cleanup_old_tasks(pool: &SqlitePool, max_age_days: i64) -> anyhow::Result<u64> {
    anyhow::ensure!(max_age_days >= 1, "max_age_days too small");
    let seconds = max_age_days.saturating_mul(86_400);
    let res = sqlx::query(
        r#"
        DELETE FROM tasks
        WHERE status IN ('succeeded', 'failed', 'cancelled')
          AND created_at < unixepoch() - ?1
        "#,
    )
    .bind(seconds)
    .execute(pool)
    .await
    .context("cleanup old tasks")?;
    Ok(res.rows_affected())
}

pub async fn cleanup_old_processed_events(
    pool: &SqlitePool,
    max_age_days: i64,
) -> anyhow::Result<u64> {
    anyhow::ensure!(max_age_days >= 1, "max_age_days too small");
    let seconds = max_age_days.saturating_mul(86_400);
    let res = sqlx::query(
        r#"
        DELETE FROM processed_events
        WHERE processed_at < unixepoch() - ?1
        "#,
    )
    .bind(seconds)
    .execute(pool)
    .await
    .context("cleanup old processed events")?;
    Ok(res.rows_affected())
}

pub async fn try_acquire_or_renew_worker_lock(
    pool: &SqlitePool,
    owner_id: &str,
    lease_seconds: i64,
) -> anyhow::Result<bool> {
    anyhow::ensure!(lease_seconds >= 10, "lease_seconds too small");

    let res = sqlx::query(
        r#"
        UPDATE worker_lock
        SET owner_id = ?1,
            lease_until = unixepoch() + ?2,
            updated_at = unixepoch()
        WHERE id = 1
          AND (owner_id = ?1 OR lease_until < unixepoch())
        "#,
    )
    .bind(owner_id)
    .bind(lease_seconds)
    .execute(pool)
    .await
    .context("acquire worker lock")?;

    Ok(res.rows_affected() == 1)
}

pub async fn get_worker_lock_owner(pool: &SqlitePool) -> anyhow::Result<Option<String>> {
    let row = sqlx::query(
        r#"
        SELECT owner_id, lease_until
        FROM worker_lock
        WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .context("get worker lock")?;

    let Some(row) = row else { return Ok(None) };
    let lease_until = row.get::<i64, _>("lease_until");
    if lease_until <= chrono::Utc::now().timestamp() {
        return Ok(None);
    }
    Ok(row.get::<Option<String>, _>("owner_id"))
}

pub async fn cancel_pending_codex_device_logins(pool: &SqlitePool) -> anyhow::Result<u64> {
    let res = sqlx::query(
        r#"
        UPDATE codex_device_logins
        SET status = 'cancelled',
            completed_at = unixepoch()
        WHERE status = 'pending'
        "#,
    )
    .execute(pool)
    .await
    .context("cancel pending codex device logins")?;
    Ok(res.rows_affected())
}

pub async fn insert_codex_device_login(
    pool: &SqlitePool,
    login: &CodexDeviceLogin,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO codex_device_logins (
          id,
          status,
          verification_url,
          user_code,
          device_auth_id,
          interval_sec,
          error_text,
          created_at,
          completed_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&login.id)
    .bind(&login.status)
    .bind(&login.verification_url)
    .bind(&login.user_code)
    .bind(&login.device_auth_id)
    .bind(login.interval_sec)
    .bind(login.error_text.as_deref())
    .bind(login.created_at)
    .bind(login.completed_at)
    .execute(pool)
    .await
    .context("insert codex device login")?;
    Ok(())
}

pub async fn get_codex_device_login(
    pool: &SqlitePool,
    id: &str,
) -> anyhow::Result<Option<CodexDeviceLogin>> {
    let row = sqlx::query(
        r#"
        SELECT
          id,
          status,
          verification_url,
          user_code,
          device_auth_id,
          interval_sec,
          error_text,
          created_at,
          completed_at
        FROM codex_device_logins
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("select codex device login")?;

    Ok(row.map(|r| CodexDeviceLogin {
        id: r.get::<String, _>("id"),
        status: r.get::<String, _>("status"),
        verification_url: r.get::<String, _>("verification_url"),
        user_code: r.get::<String, _>("user_code"),
        device_auth_id: r.get::<String, _>("device_auth_id"),
        interval_sec: r.get::<i64, _>("interval_sec"),
        error_text: r.get::<Option<String>, _>("error_text"),
        created_at: r.get::<i64, _>("created_at"),
        completed_at: r.get::<Option<i64>, _>("completed_at"),
    }))
}

pub async fn get_latest_codex_device_login(
    pool: &SqlitePool,
) -> anyhow::Result<Option<CodexDeviceLogin>> {
    let row = sqlx::query(
        r#"
        SELECT
          id,
          status,
          verification_url,
          user_code,
          device_auth_id,
          interval_sec,
          error_text,
          created_at,
          completed_at
        FROM codex_device_logins
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .context("select latest codex device login")?;

    Ok(row.map(|r| CodexDeviceLogin {
        id: r.get::<String, _>("id"),
        status: r.get::<String, _>("status"),
        verification_url: r.get::<String, _>("verification_url"),
        user_code: r.get::<String, _>("user_code"),
        device_auth_id: r.get::<String, _>("device_auth_id"),
        interval_sec: r.get::<i64, _>("interval_sec"),
        error_text: r.get::<Option<String>, _>("error_text"),
        created_at: r.get::<i64, _>("created_at"),
        completed_at: r.get::<Option<i64>, _>("completed_at"),
    }))
}

pub async fn update_codex_device_login_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error_text: Option<&str>,
    completed_at: Option<i64>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE codex_device_logins
        SET status = ?2,
            error_text = ?3,
            completed_at = ?4
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(error_text)
    .bind(completed_at)
    .execute(pool)
    .await
    .context("update codex device login status")?;
    Ok(())
}

pub async fn complete_task_success(
    pool: &SqlitePool,
    task_id: i64,
    result_text: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'succeeded',
            result_text = ?2,
            finished_at = unixepoch()
        WHERE id = ?1
        "#,
    )
    .bind(task_id)
    .bind(result_text)
    .execute(pool)
    .await
    .context("complete task success")?;
    Ok(())
}

pub async fn complete_task_failure(
    pool: &SqlitePool,
    task_id: i64,
    error_text: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'failed',
            error_text = ?2,
            finished_at = unixepoch()
        WHERE id = ?1
        "#,
    )
    .bind(task_id)
    .bind(error_text)
    .execute(pool)
    .await
    .context("complete task failure")?;
    Ok(())
}

pub async fn cancel_task(pool: &SqlitePool, task_id: i64) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'cancelled',
            error_text = 'cancelled by admin',
            started_at = NULL,
            finished_at = unixepoch()
        WHERE id = ?1
          AND status = 'queued'
        "#,
    )
    .bind(task_id)
    .execute(pool)
    .await
    .context("cancel task")?;
    Ok(res.rows_affected() == 1)
}

pub async fn retry_task(pool: &SqlitePool, task_id: i64) -> anyhow::Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'queued',
            result_text = NULL,
            error_text = NULL,
            started_at = NULL,
            finished_at = NULL
        WHERE id = ?1
          AND status IN ('failed', 'cancelled')
        "#,
    )
    .bind(task_id)
    .execute(pool)
    .await
    .context("retry task")?;
    Ok(res.rows_affected() == 1)
}

pub async fn list_recent_tasks(pool: &SqlitePool, limit: i64) -> anyhow::Result<Vec<Task>> {
    let rows = sqlx::query(
        r#"
        SELECT
          id,
          status,
          provider,
          is_proactive,
          workspace_id,
          channel_id,
          thread_ts,
          event_ts,
          requested_by_user_id,
          prompt_text,
          files_json,
          result_text,
          error_text,
          created_at,
          started_at,
          finished_at
        FROM tasks
        ORDER BY created_at DESC, id DESC
        LIMIT ?1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("list tasks")?;

    Ok(rows
        .into_iter()
        .map(|row| Task {
            id: row.get::<i64, _>("id"),
            status: row.get::<String, _>("status"),
            provider: row
                .get::<Option<String>, _>("provider")
                .unwrap_or_else(|| "slack".to_string()),
            is_proactive: row.get::<i64, _>("is_proactive") != 0,
            workspace_id: row.get::<String, _>("workspace_id"),
            channel_id: row.get::<String, _>("channel_id"),
            thread_ts: row.get::<String, _>("thread_ts"),
            event_ts: row.get::<String, _>("event_ts"),
            requested_by_user_id: row.get::<String, _>("requested_by_user_id"),
            prompt_text: row.get::<String, _>("prompt_text"),
            files_json: row.get::<String, _>("files_json"),
            result_text: row.get::<Option<String>, _>("result_text"),
            error_text: row.get::<Option<String>, _>("error_text"),
            created_at: row.get::<i64, _>("created_at"),
            started_at: row.get::<Option<i64>, _>("started_at"),
            finished_at: row.get::<Option<i64>, _>("finished_at"),
        })
        .collect())
}

pub async fn get_session(
    pool: &SqlitePool,
    conversation_key: &str,
) -> anyhow::Result<Option<Session>> {
    let row = sqlx::query(
        r#"
        SELECT
          conversation_key,
          codex_thread_id,
          memory_summary,
          last_used_at
        FROM sessions
        WHERE conversation_key = ?1
        "#,
    )
    .bind(conversation_key)
    .fetch_optional(pool)
    .await
    .context("select session")?;

    Ok(row.map(|r| Session {
        conversation_key: r.get::<String, _>("conversation_key"),
        codex_thread_id: r.get::<Option<String>, _>("codex_thread_id"),
        memory_summary: r.get::<String, _>("memory_summary"),
        last_used_at: r.get::<i64, _>("last_used_at"),
    }))
}

pub async fn upsert_session(pool: &SqlitePool, session: &Session) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sessions (
          conversation_key,
          codex_thread_id,
          memory_summary,
          last_used_at
        )
        VALUES (?1, ?2, ?3, unixepoch())
        ON CONFLICT(conversation_key) DO UPDATE SET
          codex_thread_id = excluded.codex_thread_id,
          memory_summary = excluded.memory_summary,
          last_used_at = excluded.last_used_at
        "#,
    )
    .bind(&session.conversation_key)
    .bind(session.codex_thread_id.as_deref())
    .bind(&session.memory_summary)
    .execute(pool)
    .await
    .context("upsert session")?;
    Ok(())
}

pub async fn insert_telegram_message(
    pool: &SqlitePool,
    msg: &TelegramMessage,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO telegram_messages (
          chat_id,
          message_id,
          from_user_id,
          is_bot,
          text,
          ts
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(chat_id, message_id) DO NOTHING
        "#,
    )
    .bind(&msg.chat_id)
    .bind(msg.message_id)
    .bind(msg.from_user_id.as_deref())
    .bind(if msg.is_bot { 1 } else { 0 })
    .bind(msg.text.as_deref())
    .bind(msg.ts)
    .execute(pool)
    .await
    .context("insert telegram message")?;
    Ok(())
}

pub async fn fetch_telegram_context(
    pool: &SqlitePool,
    chat_id: &str,
    before_message_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<TelegramMessage>> {
    let rows = sqlx::query(
        r#"
        SELECT
          chat_id,
          message_id,
          from_user_id,
          is_bot,
          text,
          ts
        FROM telegram_messages
        WHERE chat_id = ?1
          AND message_id < ?2
        ORDER BY message_id DESC
        LIMIT ?3
        "#,
    )
    .bind(chat_id)
    .bind(before_message_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("fetch telegram context")?;

    let mut out: Vec<TelegramMessage> = rows
        .into_iter()
        .map(|r| TelegramMessage {
            chat_id: r.get::<String, _>("chat_id"),
            message_id: r.get::<i64, _>("message_id"),
            from_user_id: r.get::<Option<String>, _>("from_user_id"),
            is_bot: r.get::<i64, _>("is_bot") != 0,
            text: r.get::<Option<String>, _>("text"),
            ts: r.get::<i64, _>("ts"),
        })
        .collect();
    out.reverse(); // oldest -> newest
    Ok(out)
}

pub async fn list_sessions(pool: &SqlitePool, limit: i64) -> anyhow::Result<Vec<Session>> {
    let rows = sqlx::query(
        r#"
        SELECT
          conversation_key,
          codex_thread_id,
          memory_summary,
          last_used_at
        FROM sessions
        ORDER BY last_used_at DESC
        LIMIT ?1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("list sessions")?;

    Ok(rows
        .into_iter()
        .map(|r| Session {
            conversation_key: r.get::<String, _>("conversation_key"),
            codex_thread_id: r.get::<Option<String>, _>("codex_thread_id"),
            memory_summary: r.get::<String, _>("memory_summary"),
            last_used_at: r.get::<i64, _>("last_used_at"),
        })
        .collect())
}

pub async fn delete_session(pool: &SqlitePool, conversation_key: &str) -> anyhow::Result<bool> {
    let res = sqlx::query("DELETE FROM sessions WHERE conversation_key = ?1")
        .bind(conversation_key)
        .execute(pool)
        .await
        .context("delete session")?;
    Ok(res.rows_affected() == 1)
}
