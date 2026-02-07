use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use serde_json::json;

pub const DEFAULT_ISSUER: &str = "https://auth.openai.com";
pub const DEFAULT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

#[derive(Debug, Clone)]
pub struct DeviceCode {
    pub verification_url: String,
    pub user_code: String,
    pub device_auth_id: String,
    pub interval_sec: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceAuthSuccess {
    pub authorization_code: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone)]
pub struct ExchangedTokens {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn read_auth_summary(codex_home: &Path) -> anyhow::Result<CodexAuthSummary> {
    let path = codex_home.join("auth.json");
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CodexAuthSummary {
                file_present: false,
                auth_mode: String::new(),
            });
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };

    #[derive(Debug, Deserialize)]
    struct AuthDotJson {
        #[serde(default)]
        auth_mode: Option<String>,
    }

    let parsed: AuthDotJson =
        serde_json::from_slice(&bytes).context("parse CODEX_HOME/auth.json")?;

    Ok(CodexAuthSummary {
        file_present: true,
        auth_mode: parsed.auth_mode.unwrap_or_default(),
    })
}

#[derive(Debug, Clone)]
pub struct CodexAuthSummary {
    pub file_present: bool,
    pub auth_mode: String,
}

pub async fn request_device_code(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
) -> anyhow::Result<DeviceCode> {
    #[derive(Debug, Deserialize)]
    struct UserCodeResp {
        device_auth_id: String,
        #[serde(alias = "user_code", alias = "usercode")]
        user_code: String,
        #[serde(default)]
        interval: serde_json::Value,
    }

    let base = issuer.trim_end_matches('/');
    let url = format!("{base}/api/accounts/deviceauth/usercode");
    let resp = http
        .post(url)
        .json(&json!({ "client_id": client_id }))
        .send()
        .await
        .context("deviceauth usercode request")?;

    if !resp.status().is_success() {
        anyhow::bail!("deviceauth usercode failed: http {}", resp.status());
    }

    let body: UserCodeResp = resp.json().await.context("deviceauth usercode decode")?;
    let interval_sec = match body.interval {
        serde_json::Value::String(s) => s.trim().parse::<u64>().unwrap_or(5),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(5),
        _ => 5,
    };

    Ok(DeviceCode {
        verification_url: format!("{base}/codex/device"),
        user_code: body.user_code,
        device_auth_id: body.device_auth_id,
        interval_sec: interval_sec.max(1).min(30),
    })
}

pub enum DeviceAuthPoll {
    Pending,
    Success(DeviceAuthSuccess),
}

pub async fn poll_device_auth(
    http: &reqwest::Client,
    issuer: &str,
    device_auth_id: &str,
    user_code: &str,
) -> anyhow::Result<DeviceAuthPoll> {
    #[derive(Debug, Deserialize)]
    struct CodeSuccessResp {
        authorization_code: String,
        code_verifier: String,
        #[allow(dead_code)]
        code_challenge: String,
    }

    let base = issuer.trim_end_matches('/');
    let url = format!("{base}/api/accounts/deviceauth/token");
    let resp = http
        .post(url)
        .json(&json!({
            "device_auth_id": device_auth_id,
            "user_code": user_code,
        }))
        .send()
        .await
        .context("deviceauth token poll request")?;

    let status = resp.status();
    if status.is_success() {
        let body: CodeSuccessResp = resp.json().await.context("deviceauth token decode")?;
        return Ok(DeviceAuthPoll::Success(DeviceAuthSuccess {
            authorization_code: body.authorization_code,
            code_verifier: body.code_verifier,
        }));
    }

    // Pending/unauthorized signals.
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
        return Ok(DeviceAuthPoll::Pending);
    }

    anyhow::bail!("deviceauth token poll failed: http {status}");
}

pub async fn exchange_code_for_tokens(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    authorization_code: &str,
    code_verifier: &str,
) -> anyhow::Result<ExchangedTokens> {
    #[derive(Debug, Deserialize)]
    struct TokenResponse {
        id_token: String,
        access_token: String,
        refresh_token: String,
    }

    let base = issuer.trim_end_matches('/');
    let redirect_uri = format!("{base}/deviceauth/callback");
    let url = format!("{base}/oauth/token");

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlencoding::encode(authorization_code),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(client_id),
        urlencoding::encode(code_verifier),
    );

    let resp = http
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .context("exchange code request")?;

    if !resp.status().is_success() {
        anyhow::bail!("exchange code failed: http {}", resp.status());
    }

    let tokens: TokenResponse = resp.json().await.context("exchange code decode")?;
    Ok(ExchangedTokens {
        id_token: tokens.id_token,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    })
}

pub async fn write_chatgpt_auth_json(
    codex_home: &Path,
    tokens: &ExchangedTokens,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;

    tokio::fs::create_dir_all(codex_home)
        .await
        .with_context(|| format!("create {}", codex_home.display()))?;

    let now = chrono::Utc::now().to_rfc3339();
    let payload = json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": serde_json::Value::Null,
        "tokens": {
            "id_token": tokens.id_token,
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "account_id": serde_json::Value::Null
        },
        "last_refresh": now
    });
    let s = serde_json::to_string_pretty(&payload).context("serialize auth.json")?;

    let path = codex_home.join("auth.json");
    let path2 = path.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut options = OpenOptions::new();
        options.truncate(true).write(true).create(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut f = options.open(&path2).with_context(|| format!("open {}", path2.display()))?;
        f.write_all(s.as_bytes())
            .with_context(|| format!("write {}", path2.display()))?;
        f.flush().with_context(|| format!("flush {}", path2.display()))?;
        Ok(())
    })
    .await
    .context("spawn_blocking write auth.json")??;

    Ok(())
}

pub async fn delete_auth_json(codex_home: &Path) -> anyhow::Result<bool> {
    let path = codex_home.join("auth.json");
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub fn default_device_login_timeout() -> Duration {
    Duration::from_secs(15 * 60)
}

