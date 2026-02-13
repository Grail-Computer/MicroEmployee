use anyhow::Context;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Client for the Microsoft Teams Bot Framework.
pub struct TeamsClient {
    http: reqwest::Client,
    app_id: String,
    app_password: String,
    /// Cached bearer token for Bot Framework API calls.
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

struct CachedToken {
    access_token: String,
    expires_at: i64, // unix epoch seconds
}

#[derive(Clone)]
struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenIdConfiguration {
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

const BOTFRAMEWORK_OPENID_CONFIG_URL: &str =
    "https://login.botframework.com/v1/.well-known/openidconfiguration";
const BOTFRAMEWORK_JWKS_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

fn jwks_cache() -> &'static RwLock<Option<CachedJwks>> {
    static CACHE: OnceLock<RwLock<Option<CachedJwks>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}

async fn fetch_botframework_jwks(http: &reqwest::Client) -> anyhow::Result<Vec<Jwk>> {
    let config = http
        .get(BOTFRAMEWORK_OPENID_CONFIG_URL)
        .send()
        .await
        .context("teams openid config request")?
        .error_for_status()
        .context("teams openid config status")?
        .json::<OpenIdConfiguration>()
        .await
        .context("parse teams openid config")?;

    let jwks = http
        .get(&config.jwks_uri)
        .send()
        .await
        .context("teams jwks request")?
        .error_for_status()
        .context("teams jwks status")?
        .json::<JwkSet>()
        .await
        .context("parse teams jwks")?;

    Ok(jwks.keys)
}

async fn load_botframework_jwks(
    http: &reqwest::Client,
    force_refresh: bool,
) -> anyhow::Result<Vec<Jwk>> {
    let cache = jwks_cache();
    if !force_refresh {
        let guard = cache.read().await;
        if let Some(cached) = guard.as_ref() {
            if cached.fetched_at.elapsed() < BOTFRAMEWORK_JWKS_CACHE_TTL {
                return Ok(cached.keys.clone());
            }
        }
    }

    let keys = fetch_botframework_jwks(http).await?;
    {
        let mut guard = cache.write().await;
        *guard = Some(CachedJwks {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
    }
    Ok(keys)
}

fn decoding_key_for_kid(keys: &[Jwk], kid: &str) -> anyhow::Result<DecodingKey> {
    let jwk = keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .with_context(|| format!("teams jwk kid not found: {kid}"))?;
    let n = jwk.n.as_deref().context("teams jwk missing modulus (n)")?;
    let e = jwk.e.as_deref().context("teams jwk missing exponent (e)")?;
    DecodingKey::from_rsa_components(n, e).context("invalid teams jwk rsa components")
}

/// Verify incoming Bot Framework bearer JWT for MS Teams webhooks.
pub async fn verify_incoming_token(
    http: &reqwest::Client,
    app_id: &str,
    authorization_header: &str,
) -> anyhow::Result<()> {
    let token = authorization_header
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| authorization_header.trim().strip_prefix("bearer "))
        .context("missing bearer token")?
        .trim();
    anyhow::ensure!(!token.is_empty(), "empty bearer token");

    let header = decode_header(token).context("decode teams jwt header")?;
    let kid = header.kid.as_deref().context("teams jwt missing kid")?;

    let cached_keys = load_botframework_jwks(http, false).await?;
    let decoding_key = match decoding_key_for_kid(&cached_keys, kid) {
        Ok(key) => key,
        Err(_) => {
            let refreshed_keys = load_botframework_jwks(http, true).await?;
            decoding_key_for_kid(&refreshed_keys, kid)?
        }
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[app_id]);
    validation.set_issuer(&["https://api.botframework.com"]);
    validation.leeway = 60;

    decode::<serde_json::Value>(token, &decoding_key, &validation).context("verify teams jwt")?;
    Ok(())
}

impl TeamsClient {
    pub fn new(http: reqwest::Client, app_id: String, app_password: String) -> Self {
        Self {
            http,
            app_id,
            app_password,
            cached_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Acquire (or reuse cached) bearer token from Microsoft identity platform.
    async fn get_token(&self) -> anyhow::Result<String> {
        // Check cache first.
        {
            let guard = self.cached_token.read().await;
            if let Some(ref cached) = *guard {
                let now = chrono::Utc::now().timestamp();
                // Refresh 60s before expiry.
                if now < cached.expires_at - 60 {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Fetch new token.
        let resp = self
            .http
            .post("https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.app_id),
                ("client_secret", &self.app_password),
                ("scope", "https://api.botframework.com/.default"),
            ])
            .send()
            .await
            .context("teams token request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Teams token error {status}: {body}");
        }

        let token_resp: TokenResponse = resp.json().await.context("parse token response")?;
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + token_resp.expires_in.unwrap_or(3600);

        let access_token = token_resp.access_token.clone();

        // Cache it.
        {
            let mut guard = self.cached_token.write().await;
            *guard = Some(CachedToken {
                access_token: token_resp.access_token,
                expires_at,
            });
        }

        Ok(access_token)
    }

    /// Send a text message reply to an MS Teams conversation.
    ///
    /// `service_url` is the Bot Framework service URL from the inbound activity.
    /// `conversation_id` is the Teams conversation ID.
    pub async fn send_message(
        &self,
        service_url: &str,
        conversation_id: &str,
        text: &str,
    ) -> anyhow::Result<()> {
        let token = self.get_token().await?;
        let base = service_url.trim_end_matches('/');
        let url = format!("{}/v3/conversations/{}/activities", base, conversation_id);

        let body = serde_json::json!({
            "type": "message",
            "text": text
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .context("teams send_message")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Teams API error {status}: {body}");
        }

        Ok(())
    }

    /// Send a reply to a specific activity (threading).
    pub async fn reply_to_activity(
        &self,
        service_url: &str,
        conversation_id: &str,
        activity_id: &str,
        text: &str,
    ) -> anyhow::Result<()> {
        let token = self.get_token().await?;
        let base = service_url.trim_end_matches('/');
        let url = format!(
            "{}/v3/conversations/{}/activities/{}",
            base, conversation_id, activity_id
        );

        let body = serde_json::json!({
            "type": "message",
            "text": text,
            "replyToId": activity_id
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .context("teams reply_to_activity")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Teams reply_to_activity error {status}: {body}");
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
}

// --- Webhook / Activity payload types ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamsActivity {
    #[serde(rename = "type")]
    pub kind: String, // message | conversationUpdate | ...
    pub id: Option<String>,
    pub timestamp: Option<String>,
    pub service_url: Option<String>,
    pub channel_id: Option<String>,
    pub from: Option<TeamsAccount>,
    pub conversation: Option<TeamsConversation>,
    pub recipient: Option<TeamsAccount>,
    pub text: Option<String>,
    pub reply_to_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TeamsAccount {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "aadObjectId")]
    pub aad_object_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamsConversation {
    pub id: String,
    pub tenant_id: Option<String>,
    pub conversation_type: Option<String>,
}
