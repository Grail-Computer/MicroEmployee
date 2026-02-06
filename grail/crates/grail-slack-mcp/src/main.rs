use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context;
use rmcp::ErrorData as McpError;
use rmcp::ServiceExt;
use rmcp::handler::server::ServerHandler;
use rmcp::model::CallToolRequestParam;
use rmcp::model::CallToolResult;
use rmcp::model::JsonObject;
use rmcp::model::ListToolsResult;
use rmcp::model::PaginatedRequestParam;
use rmcp::model::ServerCapabilities;
use rmcp::model::ServerInfo;
use rmcp::model::Tool;
use serde::Deserialize;
use serde_json::json;
use tokio::task;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn stdio() -> (tokio::io::Stdin, tokio::io::Stdout) {
    (tokio::io::stdin(), tokio::io::stdout())
}

#[derive(Clone)]
struct SlackMcpServer {
    tools: Arc<Vec<Tool>>,
    http: reqwest::Client,
}

impl SlackMcpServer {
    fn new() -> anyhow::Result<Self> {
        let tools = vec![
            Self::tool_get_channel_history()?,
            Self::tool_get_thread()?,
            Self::tool_get_permalink()?,
            Self::tool_get_user()?,
            Self::tool_list_channels()?,
        ];

        Ok(Self {
            tools: Arc::new(tools),
            http: reqwest::Client::new(),
        })
    }

    fn tool_get_channel_history() -> anyhow::Result<Tool> {
        let schema: JsonObject = serde_json::from_value(json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string", "description": "Slack channel ID (e.g. C123...)." },
                "before_ts": { "type": "string", "description": "Fetch messages earlier than this ts." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 20 }
            },
            "required": ["channel"],
            "additionalProperties": false
        }))
        .context("deserialize get_channel_history schema")?;

        Ok(Tool::new(
            Cow::Borrowed("get_channel_history"),
            Cow::Borrowed("Fetch recent messages from a channel, optionally before a timestamp."),
            Arc::new(schema),
        ))
    }

    fn tool_get_thread() -> anyhow::Result<Tool> {
        let schema: JsonObject = serde_json::from_value(json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "thread_ts": { "type": "string" },
                "before_ts": { "type": "string", "description": "Fetch replies up to this ts (inclusive)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
            },
            "required": ["channel", "thread_ts"],
            "additionalProperties": false
        }))
        .context("deserialize get_thread schema")?;

        Ok(Tool::new(
            Cow::Borrowed("get_thread"),
            Cow::Borrowed("Fetch replies in a Slack thread."),
            Arc::new(schema),
        ))
    }

    fn tool_get_permalink() -> anyhow::Result<Tool> {
        let schema: JsonObject = serde_json::from_value(json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "message_ts": { "type": "string" }
            },
            "required": ["channel", "message_ts"],
            "additionalProperties": false
        }))
        .context("deserialize get_permalink schema")?;

        Ok(Tool::new(
            Cow::Borrowed("get_permalink"),
            Cow::Borrowed("Get a permalink URL for a Slack message."),
            Arc::new(schema),
        ))
    }

    fn tool_get_user() -> anyhow::Result<Tool> {
        let schema: JsonObject = serde_json::from_value(json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "string" }
            },
            "required": ["user_id"],
            "additionalProperties": false
        }))
        .context("deserialize get_user schema")?;

        Ok(Tool::new(
            Cow::Borrowed("get_user"),
            Cow::Borrowed("Fetch a Slack user profile by user ID."),
            Arc::new(schema),
        ))
    }

    fn tool_list_channels() -> anyhow::Result<Tool> {
        let schema: JsonObject = serde_json::from_value(json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 200 }
            },
            "additionalProperties": false
        }))
        .context("deserialize list_channels schema")?;

        Ok(Tool::new(
            Cow::Borrowed("list_channels"),
            Cow::Borrowed("List Slack channels visible to the bot."),
            Arc::new(schema),
        ))
    }

    fn slack_token() -> Result<String, McpError> {
        std::env::var("SLACK_BOT_TOKEN").map_err(|_| {
            McpError::invalid_params("missing SLACK_BOT_TOKEN env var", Some(json!({})))
        })
    }

    async fn slack_api_get<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<T, McpError> {
        let token = Self::slack_token()?;
        let resp = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .query(query)
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let value = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let ok = value
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !ok {
            let err = value
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown_error");
            return Err(McpError::internal_error(
                format!("slack api error: {err}"),
                Some(value),
            ));
        }

        serde_json::from_value(value).map_err(|e| McpError::internal_error(e.to_string(), None))
    }
}

#[derive(Deserialize)]
struct SlackOkWrapper<T> {
    ok: bool,
    #[allow(dead_code)]
    error: Option<String>,
    #[serde(flatten)]
    inner: T,
}

#[derive(Deserialize)]
struct HistoryResponse {
    messages: Vec<serde_json::Value>,
    #[allow(dead_code)]
    has_more: Option<bool>,
}

#[derive(Deserialize)]
struct RepliesResponse {
    messages: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct PermalinkResponse {
    permalink: String,
}

#[derive(Deserialize)]
struct UserInfoResponse {
    user: serde_json::Value,
}

#[derive(Deserialize)]
struct ListChannelsResponse {
    channels: Vec<serde_json::Value>,
    #[allow(dead_code)]
    response_metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ArgsGetChannelHistory {
    channel: String,
    #[serde(default)]
    before_ts: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct ArgsGetThread {
    channel: String,
    thread_ts: String,
    #[serde(default)]
    before_ts: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct ArgsGetPermalink {
    channel: String,
    message_ts: String,
}

#[derive(Deserialize)]
struct ArgsGetUser {
    user_id: String,
}

#[derive(Deserialize)]
struct ArgsListChannels {
    #[serde(default)]
    limit: Option<i64>,
}

impl ServerHandler for SlackMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
            ..ServerInfo::default()
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools = self.tools.clone();
        async move {
            Ok(ListToolsResult {
                tools: (*tools).clone(),
                next_cursor: None,
                meta: None,
            })
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "get_channel_history" => {
                let args = parse_args::<ArgsGetChannelHistory>(&request, "get_channel_history")?;
                let limit = args.limit.unwrap_or(20).clamp(1, 200);
                let mut query = vec![("channel", args.channel.clone()), ("limit", limit.to_string())];
                if let Some(ts) = args.before_ts {
                    query.push(("latest", ts));
                    query.push(("inclusive", "false".to_string()));
                }
                let SlackOkWrapper { inner, .. }: SlackOkWrapper<HistoryResponse> = self
                    .slack_api_get("https://slack.com/api/conversations.history", &query)
                    .await?;

                Ok(CallToolResult {
                    content: Vec::new(),
                    structured_content: Some(json!({
                        "channel": args.channel,
                        "messages": inner.messages,
                    })),
                    is_error: Some(false),
                    meta: None,
                })
            }
            "get_thread" => {
                let args = parse_args::<ArgsGetThread>(&request, "get_thread")?;
                let limit = args.limit.unwrap_or(50).clamp(1, 200);
                let mut query = vec![
                    ("channel", args.channel.clone()),
                    ("ts", args.thread_ts.clone()),
                    ("limit", limit.to_string()),
                    ("inclusive", "true".to_string()),
                ];
                if let Some(ts) = args.before_ts {
                    query.push(("latest", ts));
                }
                let SlackOkWrapper { inner, .. }: SlackOkWrapper<RepliesResponse> = self
                    .slack_api_get("https://slack.com/api/conversations.replies", &query)
                    .await?;

                Ok(CallToolResult {
                    content: Vec::new(),
                    structured_content: Some(json!({
                        "channel": args.channel,
                        "thread_ts": args.thread_ts,
                        "messages": inner.messages,
                    })),
                    is_error: Some(false),
                    meta: None,
                })
            }
            "get_permalink" => {
                let args = parse_args::<ArgsGetPermalink>(&request, "get_permalink")?;
                let query = vec![
                    ("channel", args.channel.clone()),
                    ("message_ts", args.message_ts.clone()),
                ];
                let SlackOkWrapper { inner, .. }: SlackOkWrapper<PermalinkResponse> = self
                    .slack_api_get("https://slack.com/api/chat.getPermalink", &query)
                    .await?;
                Ok(CallToolResult {
                    content: Vec::new(),
                    structured_content: Some(json!({
                        "channel": args.channel,
                        "message_ts": args.message_ts,
                        "permalink": inner.permalink,
                    })),
                    is_error: Some(false),
                    meta: None,
                })
            }
            "get_user" => {
                let args = parse_args::<ArgsGetUser>(&request, "get_user")?;
                let query = vec![("user", args.user_id.clone())];
                let SlackOkWrapper { inner, .. }: SlackOkWrapper<UserInfoResponse> = self
                    .slack_api_get("https://slack.com/api/users.info", &query)
                    .await?;
                Ok(CallToolResult {
                    content: Vec::new(),
                    structured_content: Some(json!({
                        "user_id": args.user_id,
                        "user": inner.user,
                    })),
                    is_error: Some(false),
                    meta: None,
                })
            }
            "list_channels" => {
                let args = parse_args::<ArgsListChannels>(&request, "list_channels")
                    .unwrap_or(ArgsListChannels { limit: None });
                let limit = args.limit.unwrap_or(200).clamp(1, 1000);
                let query = vec![
                    ("limit", limit.to_string()),
                    ("types", "public_channel,private_channel".to_string()),
                    ("exclude_archived", "true".to_string()),
                ];
                let SlackOkWrapper { inner, .. }: SlackOkWrapper<ListChannelsResponse> = self
                    .slack_api_get("https://slack.com/api/conversations.list", &query)
                    .await?;
                Ok(CallToolResult {
                    content: Vec::new(),
                    structured_content: Some(json!({
                        "channels": inner.channels,
                    })),
                    is_error: Some(false),
                    meta: None,
                })
            }
            other => Err(McpError::invalid_params(
                format!("unknown tool: {other}"),
                None,
            )),
        }
    }
}

fn parse_args<T: for<'de> Deserialize<'de>>(
    request: &CallToolRequestParam,
    tool_name: &'static str,
) -> Result<T, McpError> {
    match request.arguments.as_ref() {
        Some(arguments) => serde_json::from_value(serde_json::Value::Object(
            arguments.clone().into_iter().collect(),
        ))
        .map_err(|err| McpError::invalid_params(err.to_string(), None)),
        None => Err(McpError::invalid_params(
            format!("missing arguments for {tool_name} tool"),
            None,
        )),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let service = SlackMcpServer::new()?;
    info!("starting grail-slack-mcp (stdio)");

    let running = service.serve(stdio()).await?;
    if let Err(err) = running.waiting().await {
        error!(error = %err, "mcp server exiting");
        return Err(anyhow::Error::new(err));
    }

    task::yield_now().await;
    Ok(())
}

