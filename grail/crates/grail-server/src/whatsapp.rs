use anyhow::Context;
use serde::Deserialize;

/// Client for the WhatsApp Cloud API (Meta Graph API v21.0).
pub struct WhatsAppClient {
    http: reqwest::Client,
    access_token: String,
    phone_number_id: String,
}

impl WhatsAppClient {
    pub fn new(http: reqwest::Client, access_token: String, phone_number_id: String) -> Self {
        Self {
            http,
            access_token,
            phone_number_id,
        }
    }

    /// Send a text message to a WhatsApp user.
    pub async fn send_message(&self, to: &str, text: &str) -> anyhow::Result<()> {
        let url = format!(
            "https://graph.facebook.com/v21.0/{}/messages",
            self.phone_number_id
        );

        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": { "body": text }
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .context("whatsapp send_message")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("WhatsApp API error {status}: {text}");
        }

        Ok(())
    }
}

/// Verify the X-Hub-Signature-256 header from Meta webhooks.
pub fn verify_signature(app_secret: &str, body: &[u8], signature_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let Some(hex_sig) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

// --- Webhook payload types ---

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppWebhookPayload {
    pub entry: Option<Vec<WhatsAppEntry>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppEntry {
    pub id: String,
    pub changes: Option<Vec<WhatsAppChange>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppChange {
    pub value: Option<WhatsAppChangeValue>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppChangeValue {
    pub messaging_product: Option<String>,
    pub metadata: Option<WhatsAppMetadata>,
    pub messages: Option<Vec<WhatsAppInboundMessage>>,
    pub contacts: Option<Vec<WhatsAppContact>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppMetadata {
    pub display_phone_number: Option<String>,
    pub phone_number_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppInboundMessage {
    pub from: String,
    pub id: String,
    pub timestamp: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub text: Option<WhatsAppTextBody>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppTextBody {
    pub body: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppContact {
    pub profile: Option<WhatsAppProfile>,
    pub wa_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhatsAppProfile {
    pub name: Option<String>,
}
