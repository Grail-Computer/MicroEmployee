use anyhow::Context;
use serde::Deserialize;

pub const DEFAULT_GITHUB_BASE: &str = "https://github.com";
pub const DEFAULT_DEVICE_CODE_PATH: &str = "/login/device/code";
pub const DEFAULT_ACCESS_TOKEN_PATH: &str = "/login/oauth/access_token";

#[derive(Debug, Clone)]
pub struct DeviceCode {
    pub verification_url: String,
    pub verification_url_complete: Option<String>,
    pub user_code: String,
    pub device_code: String,
    pub interval_sec: u64,
    pub expires_in_sec: u64,
}

pub async fn request_device_code(
    http: &reqwest::Client,
    base: &str,
    client_id: &str,
    scope: &str,
) -> anyhow::Result<DeviceCode> {
    #[derive(Debug, Deserialize)]
    struct Resp {
        device_code: String,
        user_code: String,
        verification_uri: String,
        #[serde(default)]
        verification_uri_complete: Option<String>,
        expires_in: u64,
        #[serde(default)]
        interval: Option<u64>,
    }

    let base = base.trim_end_matches('/');
    let url = format!("{base}{path}", path = DEFAULT_DEVICE_CODE_PATH);

    let body = format!(
        "client_id={}&scope={}",
        urlencoding::encode(client_id),
        urlencoding::encode(scope)
    );

    let resp = http
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .context("github device code request")?;

    if !resp.status().is_success() {
        anyhow::bail!("github device code failed: http {}", resp.status());
    }

    let body: Resp = resp.json().await.context("github device code decode")?;
    Ok(DeviceCode {
        verification_url: body.verification_uri,
        verification_url_complete: body.verification_uri_complete,
        user_code: body.user_code,
        device_code: body.device_code,
        interval_sec: body.interval.unwrap_or(5).max(1).min(30),
        expires_in_sec: body.expires_in.max(60).min(60 * 30),
    })
}

pub enum TokenPoll {
    Pending,
    SlowDown,
    Success { access_token: String },
    Failed { error: String, description: String },
}

pub async fn poll_for_token(
    http: &reqwest::Client,
    base: &str,
    client_id: &str,
    device_code: &str,
) -> anyhow::Result<TokenPoll> {
    #[derive(Debug, Deserialize)]
    struct Resp {
        #[serde(default)]
        access_token: Option<String>,
        #[serde(default)]
        token_type: Option<String>,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        error_description: Option<String>,
    }

    let base = base.trim_end_matches('/');
    let url = format!("{base}{path}", path = DEFAULT_ACCESS_TOKEN_PATH);
    let body = format!(
        "client_id={}&device_code={}&grant_type={}",
        urlencoding::encode(client_id),
        urlencoding::encode(device_code),
        urlencoding::encode("urn:ietf:params:oauth:grant-type:device_code"),
    );

    let resp = http
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .context("github device token poll request")?;

    if !resp.status().is_success() {
        anyhow::bail!("github device token poll failed: http {}", resp.status());
    }

    let body: Resp = resp
        .json()
        .await
        .context("github device token poll decode")?;

    if let Some(token) = body.access_token {
        // token_type + scope are currently unused, but kept in the response struct for debugging.
        let _ = body.token_type;
        let _ = body.scope;
        return Ok(TokenPoll::Success {
            access_token: token,
        });
    }

    let err = body.error.unwrap_or_else(|| "unknown_error".to_string());
    let desc = body.error_description.unwrap_or_default();
    match err.as_str() {
        "authorization_pending" => Ok(TokenPoll::Pending),
        "slow_down" => Ok(TokenPoll::SlowDown),
        _ => Ok(TokenPoll::Failed {
            error: err,
            description: desc,
        }),
    }
}
