use anyhow::Context;
use serde::Deserialize;

/// Client for the Discord Bot API (v10).
pub struct DiscordClient {
    http: reqwest::Client,
    bot_token: String,
}

impl DiscordClient {
    pub fn new(http: reqwest::Client, bot_token: String) -> Self {
        Self { http, bot_token }
    }

    /// Send a text message to a Discord channel.
    pub async fn send_message(&self, channel_id: &str, text: &str) -> anyhow::Result<()> {
        let url = format!(
            "https://discord.com/api/v10/channels/{}/messages",
            channel_id
        );

        let body = serde_json::json!({
            "content": text
        });

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bot {}", self.bot_token))
            .json(&body)
            .send()
            .await
            .context("discord send_message")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Discord API error {status}: {text}");
        }

        Ok(())
    }
}

/// Verify the Ed25519 signature on Discord interaction webhooks.
///
/// `public_key_hex` is the hex-encoded public key from the Discord application settings.
/// `signature_hex` is the value of the `X-Signature-Ed25519` header.
/// `timestamp` is the value of the `X-Signature-Timestamp` header.
/// `body` is the raw request body bytes.
pub fn verify_discord_signature(
    public_key_hex: &str,
    signature_hex: &str,
    timestamp: &str,
    body: &[u8],
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let pk_array: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_array) else {
        return false;
    };

    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_array);

    let mut message = Vec::with_capacity(timestamp.len() + body.len());
    message.extend_from_slice(timestamp.as_bytes());
    message.extend_from_slice(body);

    verifying_key.verify(&message, &signature).is_ok()
}

// --- Webhook / Interaction payload types ---

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordInteraction {
    /// 1 = PING, 2 = APPLICATION_COMMAND, etc.
    #[serde(rename = "type")]
    pub kind: u32,
    pub id: Option<String>,
    pub token: Option<String>,
    pub channel_id: Option<String>,
    pub guild_id: Option<String>,
    pub member: Option<DiscordMember>,
    pub user: Option<DiscordUser>,
    pub data: Option<serde_json::Value>,
}

/// Gateway-based message event (for future use when Gateway is implemented).
/// For now, we also parse incoming HTTP-based webhook messages with this struct.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscordMessage {
    pub id: String,
    pub channel_id: String,
    pub content: Option<String>,
    pub author: Option<DiscordUser>,
    pub guild_id: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordMember {
    pub user: Option<DiscordUser>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: Option<String>,
    pub bot: Option<bool>,
}
