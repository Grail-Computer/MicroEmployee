use anyhow::Context;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::db;
use crate::AppState;

fn normalize_nonempty(s: String) -> Option<String> {
    let v = s.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(normalize_nonempty)
}

pub async fn load_openai_api_key_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = env_nonempty("OPENAI_API_KEY") {
        return Ok(Some(v));
    }

    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "openai_api_key").await? else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"openai_api_key", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("OPENAI_API_KEY not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn openai_api_key_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_openai_api_key_opt(state).await?.is_some())
}

pub fn load_github_client_id_from_env() -> Option<String> {
    env_nonempty("GITHUB_CLIENT_ID")
}

pub async fn load_github_client_id_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = load_github_client_id_from_env() {
        return Ok(Some(v));
    }
    let settings = db::get_settings(&state.pool).await?;
    Ok(normalize_nonempty(settings.github_client_id))
}

pub async fn github_client_id_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_github_client_id_opt(state).await?.is_some())
}

pub async fn load_github_token_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    // Common env var names used by gh CLI and CI.
    for key in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Some(v) = env_nonempty(key) {
            return Ok(Some(v));
        }
    }

    // Prefer encrypted secret storage when available.
    if let Some(crypto) = state.crypto.as_deref() {
        if let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "github_token").await? {
            let plaintext = crypto.decrypt(b"github_token", &nonce, &ciphertext)?;
            let s = String::from_utf8(plaintext).context("GITHUB_TOKEN not valid utf-8")?;
            if let Some(v) = normalize_nonempty(s) {
                return Ok(Some(v));
            }
        }
    }

    // Fallback for device login when encrypted secret storage is disabled:
    // store the token in `${GRAIL_DATA_DIR}/github/token.txt` with 0600 perms.
    let token_path = state.config.data_dir.join("github").join("token.txt");
    match tokio::fs::read(&token_path).await {
        Ok(bytes) => {
            let s = String::from_utf8(bytes).context("GitHub token file not valid utf-8")?;
            Ok(normalize_nonempty(s))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {}", token_path.display())),
    }
}

pub async fn github_token_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_github_token_opt(state).await?.is_some())
}

pub async fn load_slack_bot_token_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.slack_bot_token.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }

    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "slack_bot_token").await? else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"slack_bot_token", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("SLACK_BOT_TOKEN not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn slack_bot_token_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_slack_bot_token_opt(state).await?.is_some())
}

pub async fn load_slack_signing_secret_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.slack_signing_secret.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }

    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "slack_signing_secret").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"slack_signing_secret", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("SLACK_SIGNING_SECRET not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn slack_signing_secret_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_slack_signing_secret_opt(state).await?.is_some())
}

pub async fn load_telegram_bot_token_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.telegram_bot_token.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }

    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "telegram_bot_token").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"telegram_bot_token", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("TELEGRAM_BOT_TOKEN not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn telegram_bot_token_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_telegram_bot_token_opt(state).await?.is_some())
}

pub async fn load_telegram_webhook_secret_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.telegram_webhook_secret.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }

    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "telegram_webhook_secret").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"telegram_webhook_secret", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("TELEGRAM_WEBHOOK_SECRET not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn telegram_webhook_secret_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_telegram_webhook_secret_opt(state).await?.is_some())
}

pub async fn load_brave_search_api_key_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = env_nonempty("BRAVE_SEARCH_API_KEY") {
        return Ok(Some(v));
    }
    // Nanobot-compatible name.
    if let Some(v) = env_nonempty("BRAVE_API_KEY") {
        return Ok(Some(v));
    }

    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "brave_search_api_key").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"brave_search_api_key", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("BRAVE_SEARCH_API_KEY not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn brave_search_api_key_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_brave_search_api_key_opt(state).await?.is_some())
}

// --- WhatsApp ---

pub async fn load_whatsapp_access_token_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.whatsapp_access_token.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "whatsapp_access_token").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"whatsapp_access_token", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("WHATSAPP_ACCESS_TOKEN not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn whatsapp_access_token_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_whatsapp_access_token_opt(state).await?.is_some())
}

pub async fn load_whatsapp_verify_token_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.whatsapp_verify_token.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "whatsapp_verify_token").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"whatsapp_verify_token", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("WHATSAPP_VERIFY_TOKEN not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn whatsapp_verify_token_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_whatsapp_verify_token_opt(state).await?.is_some())
}

pub async fn load_whatsapp_phone_number_id_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.whatsapp_phone_number_id.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) =
        db::read_secret(&state.pool, "whatsapp_phone_number_id").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"whatsapp_phone_number_id", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("WHATSAPP_PHONE_NUMBER_ID not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn whatsapp_phone_number_id_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_whatsapp_phone_number_id_opt(state).await?.is_some())
}

// --- Discord ---

pub async fn load_discord_bot_token_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.discord_bot_token.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "discord_bot_token").await? else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"discord_bot_token", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("DISCORD_BOT_TOKEN not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn discord_bot_token_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_discord_bot_token_opt(state).await?.is_some())
}

pub async fn load_discord_public_key_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.discord_public_key.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "discord_public_key").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"discord_public_key", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("DISCORD_PUBLIC_KEY not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn discord_public_key_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_discord_public_key_opt(state).await?.is_some())
}

// --- MS Teams ---

pub async fn load_msteams_app_id_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.msteams_app_id.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "msteams_app_id").await? else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"msteams_app_id", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("MSTEAMS_APP_ID not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn msteams_app_id_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_msteams_app_id_opt(state).await?.is_some())
}

pub async fn load_msteams_app_password_opt(state: &AppState) -> anyhow::Result<Option<String>> {
    if let Some(v) = state.config.msteams_app_password.as_deref() {
        if let Some(v) = normalize_nonempty(v.to_string()) {
            return Ok(Some(v));
        }
    }
    let Some(crypto) = state.crypto.as_deref() else {
        return Ok(None);
    };
    let Some((nonce, ciphertext)) = db::read_secret(&state.pool, "msteams_app_password").await?
    else {
        return Ok(None);
    };
    let plaintext = crypto.decrypt(b"msteams_app_password", &nonce, &ciphertext)?;
    let s = String::from_utf8(plaintext).context("MSTEAMS_APP_PASSWORD not valid utf-8")?;
    Ok(normalize_nonempty(s))
}

pub async fn msteams_app_password_configured(state: &AppState) -> anyhow::Result<bool> {
    Ok(load_msteams_app_password_opt(state).await?.is_some())
}

static SECRET_REDACTIONS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        // OpenAI API keys (including newer sk-proj- style).
        (
            Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{10,}\b").expect("regex"),
            "[REDACTED_OPENAI_KEY]",
        ),
        // Slack tokens.
        (
            Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").expect("regex"),
            "[REDACTED_SLACK_TOKEN]",
        ),
        (
            Regex::new(r"\bxapp-[A-Za-z0-9-]{10,}\b").expect("regex"),
            "[REDACTED_SLACK_APP_TOKEN]",
        ),
        // Telegram bot token.
        (
            Regex::new(r"\b\d{6,}:[A-Za-z0-9_-]{20,}\b").expect("regex"),
            "[REDACTED_TELEGRAM_TOKEN]",
        ),
        // GitHub tokens (classic PAT, fine-grained PAT, OAuth, server tokens).
        (
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b").expect("regex"),
            "[REDACTED_GITHUB_TOKEN]",
        ),
        (
            Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b").expect("regex"),
            "[REDACTED_GITHUB_TOKEN]",
        ),
        // Private keys.
        (
            Regex::new(
                r"(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
            )
            .expect("regex"),
            "-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----",
        ),
    ]
});

/// Best-effort redaction to avoid leaking secrets into Slack/Telegram, memory, or context files.
pub fn redact_secrets(text: &str) -> (String, bool) {
    let mut out = text.to_string();
    let mut changed = false;
    for (re, repl) in SECRET_REDACTIONS.iter() {
        let next = re.replace_all(&out, *repl).to_string();
        if next != out {
            changed = true;
            out = next;
        }
    }
    (out, changed)
}
