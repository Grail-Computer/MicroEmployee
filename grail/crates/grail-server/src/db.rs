use std::path::Path;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::models::{CodexDeviceLogin, PermissionsMode, Session, Settings, Task};

pub async fn init_sqlite(db_path: &Path) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);

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
          allow_slack_mcp,
          allow_context_writes,
          shell_network_access,
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
        permissions_mode: PermissionsMode::from_db_str(row.get::<String, _>("permissions_mode").as_str()),
        allow_slack_mcp: row.get::<i64, _>("allow_slack_mcp") != 0,
        allow_context_writes: row.get::<i64, _>("allow_context_writes") != 0,
        shell_network_access: row.get::<i64, _>("shell_network_access") != 0,
        updated_at: row.get::<i64, _>("updated_at"),
    })
}

pub async fn update_settings(
    pool: &SqlitePool,
    settings: &Settings,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE settings
        SET context_last_n = ?1,
            model = ?2,
            reasoning_effort = ?3,
            reasoning_summary = ?4,
            permissions_mode = ?5,
            allow_slack_mcp = ?6,
            allow_context_writes = ?7,
            shell_network_access = ?8,
            updated_at = unixepoch()
        WHERE id = 1
        "#,
    )
    .bind(settings.context_last_n)
    .bind(settings.model.as_deref())
    .bind(settings.reasoning_effort.as_deref())
    .bind(settings.reasoning_summary.as_deref())
    .bind(settings.permissions_mode.as_db_str())
    .bind(if settings.allow_slack_mcp { 1 } else { 0 })
    .bind(if settings.allow_context_writes { 1 } else { 0 })
    .bind(if settings.shell_network_access { 1 } else { 0 })
    .execute(pool)
    .await
    .context("update settings")?;
    Ok(())
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

pub async fn read_secret(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
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
    workspace_id: &str,
    channel_id: &str,
    thread_ts: &str,
    event_ts: &str,
    requested_by_user_id: &str,
    prompt_text: &str,
) -> anyhow::Result<i64> {
    let res = sqlx::query(
        r#"
        INSERT INTO tasks (
          status,
          workspace_id,
          channel_id,
          thread_ts,
          event_ts,
          requested_by_user_id,
          prompt_text,
          created_at
        )
        VALUES ('queued', ?1, ?2, ?3, ?4, ?5, ?6, unixepoch())
        "#,
    )
    .bind(workspace_id)
    .bind(channel_id)
    .bind(thread_ts)
    .bind(event_ts)
    .bind(requested_by_user_id)
    .bind(prompt_text)
    .execute(pool)
    .await
    .context("insert task")?;

    Ok(res.last_insert_rowid())
}

pub async fn claim_next_task(pool: &SqlitePool) -> anyhow::Result<Option<Task>> {
    let mut tx = pool.begin().await.context("begin tx")?;

    let row_opt = sqlx::query(
        r#"
        SELECT
          id,
          status,
          workspace_id,
          channel_id,
          thread_ts,
          event_ts,
          requested_by_user_id,
          prompt_text,
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
        workspace_id: row.get::<String, _>("workspace_id"),
        channel_id: row.get::<String, _>("channel_id"),
        thread_ts: row.get::<String, _>("thread_ts"),
        event_ts: row.get::<String, _>("event_ts"),
        requested_by_user_id: row.get::<String, _>("requested_by_user_id"),
        prompt_text: row.get::<String, _>("prompt_text"),
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

pub async fn list_recent_tasks(pool: &SqlitePool, limit: i64) -> anyhow::Result<Vec<Task>> {
    let rows = sqlx::query(
        r#"
        SELECT
          id,
          status,
          workspace_id,
          channel_id,
          thread_ts,
          event_ts,
          requested_by_user_id,
          prompt_text,
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
            workspace_id: row.get::<String, _>("workspace_id"),
            channel_id: row.get::<String, _>("channel_id"),
            thread_ts: row.get::<String, _>("thread_ts"),
            event_ts: row.get::<String, _>("event_ts"),
            requested_by_user_id: row.get::<String, _>("requested_by_user_id"),
            prompt_text: row.get::<String, _>("prompt_text"),
            result_text: row.get::<Option<String>, _>("result_text"),
            error_text: row.get::<Option<String>, _>("error_text"),
            created_at: row.get::<i64, _>("created_at"),
            started_at: row.get::<Option<i64>, _>("started_at"),
            finished_at: row.get::<Option<i64>, _>("finished_at"),
        })
        .collect())
}

pub async fn get_session(pool: &SqlitePool, conversation_key: &str) -> anyhow::Result<Option<Session>> {
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
