use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum SlackSignatureError {
    #[error("missing header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("timestamp too old")]
    TimestampTooOld,
    #[error("signature mismatch")]
    SignatureMismatch,
}

pub fn verify_slack_signature(
    signing_secret: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(), SlackSignatureError> {
    let timestamp = headers
        .get("X-Slack-Request-Timestamp")
        .ok_or(SlackSignatureError::MissingHeader(
            "X-Slack-Request-Timestamp",
        ))?
        .to_str()
        .map_err(|_| SlackSignatureError::InvalidHeader("X-Slack-Request-Timestamp"))?;

    let signature = headers
        .get("X-Slack-Signature")
        .ok_or(SlackSignatureError::MissingHeader("X-Slack-Signature"))?
        .to_str()
        .map_err(|_| SlackSignatureError::InvalidHeader("X-Slack-Signature"))?;

    let ts: i64 = timestamp
        .parse()
        .map_err(|_| SlackSignatureError::InvalidHeader("X-Slack-Request-Timestamp"))?;

    // Reject if timestamp is too far from "now" to reduce replay.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64;
    if (now - ts).abs() > 60 * 5 {
        return Err(SlackSignatureError::TimestampTooOld);
    }

    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes()).expect("HMAC key valid");
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    let expected = format!("v0={}", hex::encode(mac.finalize().into_bytes()));

    // Constant-time compare.
    if expected.as_bytes().ct_eq(signature.as_bytes()).unwrap_u8() != 1 {
        return Err(SlackSignatureError::SignatureMismatch);
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SlackClient {
    http: reqwest::Client,
    bot_token: String,
}

impl SlackClient {
    pub fn new(http: reqwest::Client, bot_token: String) -> Self {
        Self { http, bot_token }
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.bot_token))
                .expect("slack token header value"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    pub async fn post_message(
        &self,
        channel: &str,
        thread_ts: Option<&str>,
        text: &str,
    ) -> anyhow::Result<()> {
        const SLACK_TEXT_MAX_BYTES: usize = 35_000;

        #[derive(Serialize)]
        struct Req<'a> {
            channel: &'a str,
            text: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            thread_ts: Option<&'a str>,
        }

        for chunk in split_slack_text(text, SLACK_TEXT_MAX_BYTES) {
            let resp: SlackApiResponse<serde_json::Value> = self
                .http
                .post("https://slack.com/api/chat.postMessage")
                .headers(self.headers())
                .json(&Req {
                    channel,
                    text: &chunk,
                    thread_ts,
                })
                .send()
                .await
                .context("slack chat.postMessage request")?
                .json()
                .await
                .context("slack chat.postMessage decode")?;

            if !resp.ok {
                anyhow::bail!(
                    "slack chat.postMessage failed: {}",
                    resp.error.unwrap_or_else(|| "unknown_error".to_string())
                );
            }
        }
        Ok(())
    }

    pub async fn post_message_rich(
        &self,
        channel: &str,
        thread_ts: Option<&str>,
        text: &str,
        blocks: serde_json::Value,
    ) -> anyhow::Result<()> {
        const SLACK_TEXT_MAX_BYTES: usize = 35_000;

        #[derive(Serialize)]
        struct Req<'a> {
            channel: &'a str,
            text: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            thread_ts: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            blocks: Option<&'a serde_json::Value>,
        }

        let mut t = text.trim().to_string();
        if t.is_empty() {
            t = "(empty)".to_string();
        }
        if t.len() > SLACK_TEXT_MAX_BYTES {
            t = t.chars().take(SLACK_TEXT_MAX_BYTES).collect();
        }

        let resp: SlackApiResponse<serde_json::Value> = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .headers(self.headers())
            .json(&Req {
                channel,
                text: &t,
                thread_ts,
                blocks: Some(&blocks),
            })
            .send()
            .await
            .context("slack chat.postMessage request")?
            .json()
            .await
            .context("slack chat.postMessage decode")?;

        if !resp.ok {
            anyhow::bail!(
                "slack chat.postMessage failed: {}",
                resp.error.unwrap_or_else(|| "unknown_error".to_string())
            );
        }

        Ok(())
    }

    pub async fn fetch_channel_history(
        &self,
        channel: &str,
        latest: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<SlackMessage>> {
        let resp: SlackApiResponse<HistoryResponse> = self
            .http
            .get("https://slack.com/api/conversations.history")
            .headers(self.headers())
            .query(&[
                ("channel", channel),
                ("latest", latest),
                ("limit", &limit.to_string()),
                ("inclusive", "false"),
            ])
            .send()
            .await
            .context("slack conversations.history request")?
            .json()
            .await
            .context("slack conversations.history decode")?;

        if !resp.ok {
            anyhow::bail!(
                "slack conversations.history failed: {}",
                resp.error.unwrap_or_else(|| "unknown_error".to_string())
            );
        }
        Ok(resp
            .data
            .map(|d| d.messages)
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect())
    }

    pub async fn fetch_thread_replies(
        &self,
        channel: &str,
        thread_ts: &str,
        latest: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<SlackMessage>> {
        let resp: SlackApiResponse<RepliesResponse> = self
            .http
            .get("https://slack.com/api/conversations.replies")
            .headers(self.headers())
            .query(&[
                ("channel", channel),
                ("ts", thread_ts),
                ("latest", latest),
                ("limit", &limit.to_string()),
                ("inclusive", "false"),
            ])
            .send()
            .await
            .context("slack conversations.replies request")?
            .json()
            .await
            .context("slack conversations.replies decode")?;

        if !resp.ok {
            anyhow::bail!(
                "slack conversations.replies failed: {}",
                resp.error.unwrap_or_else(|| "unknown_error".to_string())
            );
        }
        Ok(resp.data.map(|d| d.messages).unwrap_or_default())
    }
}

#[derive(Debug, Deserialize)]
pub struct SlackApiResponse<T> {
    pub ok: bool,
    pub error: Option<String>,
    #[serde(flatten)]
    pub data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct HistoryResponse {
    messages: Vec<SlackMessage>,
}

#[derive(Debug, Deserialize)]
struct RepliesResponse {
    messages: Vec<SlackMessage>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlackMessage {
    pub ts: String,
    pub text: Option<String>,
    pub user: Option<String>,
    pub bot_id: Option<String>,
    pub subtype: Option<String>,
    #[serde(default)]
    pub files: Vec<SlackFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlackFile {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mimetype: Option<String>,
    #[serde(default)]
    pub filetype: Option<String>,
    #[serde(default)]
    pub url_private_download: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
}

impl SlackClient {
    /// Download a Slack-hosted file using the bot token for auth.
    /// Returns the local path where the file was saved.
    pub async fn download_file(&self, url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
        let resp = self
            .http
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {}", self.bot_token))
            .send()
            .await
            .context("slack file download request")?;

        if !resp.status().is_success() {
            anyhow::bail!("slack file download failed with status {}", resp.status());
        }

        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("create download directory")?;
        }

        let bytes = resp.bytes().await.context("read file bytes")?;
        tokio::fs::write(dest, &bytes)
            .await
            .context("write downloaded file")?;

        Ok(())
    }

    /// Upload file content to a Slack channel/thread using files.uploadV2 flow:
    /// 1. files.getUploadURLExternal
    /// 2. PUT content to the upload URL
    /// 3. files.completeUploadExternal to share in channel
    pub async fn upload_file_content(
        &self,
        channel: &str,
        thread_ts: Option<&str>,
        filename: &str,
        content: &[u8],
    ) -> anyhow::Result<()> {
        // Step 1: Get upload URL
        #[derive(Deserialize)]
        struct UploadUrlResp {
            ok: bool,
            error: Option<String>,
            upload_url: Option<String>,
            file_id: Option<String>,
        }

        let mut form_parts = vec![
            ("filename", filename.to_string()),
            ("length", content.len().to_string()),
        ];
        // Guess a title from the filename
        form_parts.push(("title", filename.to_string()));

        let resp: UploadUrlResp = self
            .http
            .get("https://slack.com/api/files.getUploadURLExternal")
            .headers(self.headers())
            .query(&form_parts)
            .send()
            .await
            .context("files.getUploadURLExternal request")?
            .json()
            .await
            .context("files.getUploadURLExternal decode")?;

        if !resp.ok {
            anyhow::bail!(
                "files.getUploadURLExternal failed: {}",
                resp.error.unwrap_or_else(|| "unknown_error".to_string())
            );
        }

        let upload_url = resp
            .upload_url
            .context("files.getUploadURLExternal missing upload_url")?;
        let file_id = resp
            .file_id
            .context("files.getUploadURLExternal missing file_id")?;

        // Step 2: PUT content to the upload URL
        let put_resp = self
            .http
            .post(&upload_url)
            .body(content.to_vec())
            .send()
            .await
            .context("file upload PUT request")?;

        if !put_resp.status().is_success() {
            anyhow::bail!("file upload PUT failed with status {}", put_resp.status());
        }

        // Step 3: Complete upload and share in channel
        #[derive(Serialize)]
        struct CompleteReq {
            files: Vec<CompleteFile>,
            #[serde(skip_serializing_if = "Option::is_none")]
            channel_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            thread_ts: Option<String>,
        }
        #[derive(Serialize)]
        struct CompleteFile {
            id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            title: Option<String>,
        }

        let complete_resp: SlackApiResponse<serde_json::Value> = self
            .http
            .post("https://slack.com/api/files.completeUploadExternal")
            .headers(self.headers())
            .json(&CompleteReq {
                files: vec![CompleteFile {
                    id: file_id,
                    title: Some(filename.to_string()),
                }],
                channel_id: Some(channel.to_string()),
                thread_ts: thread_ts.map(|s| s.to_string()),
            })
            .send()
            .await
            .context("files.completeUploadExternal request")?
            .json()
            .await
            .context("files.completeUploadExternal decode")?;

        if !complete_resp.ok {
            anyhow::bail!(
                "files.completeUploadExternal failed: {}",
                complete_resp
                    .error
                    .unwrap_or_else(|| "unknown_error".to_string())
            );
        }

        Ok(())
    }
}

fn split_slack_text(text: &str, max_bytes: usize) -> Vec<String> {
    let t = text.trim();
    if t.is_empty() {
        return vec!["(empty)".to_string()];
    }
    if t.len() <= max_bytes {
        return vec![t.to_string()];
    }

    let mut out = Vec::new();
    let mut start = 0usize;
    while start < t.len() {
        let mut end = (start + max_bytes).min(t.len());
        while end > start && !t.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            break;
        }

        // Prefer splitting at a newline, but don't create tiny chunks.
        if let Some(pos) = t[start..end].rfind('\n') {
            let candidate = start + pos + 1;
            if candidate > start + (max_bytes / 2) {
                end = candidate;
            }
        }

        out.push(t[start..end].trim().to_string());
        start = end;
    }

    if out.is_empty() {
        vec![t.chars().take(1000).collect()]
    } else {
        out
    }
}
