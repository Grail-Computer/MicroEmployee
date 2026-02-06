# Grail (MicroEmployee)

Grail is a single-tenant “micro employee” you deploy as a Railway service and connect to a Slack app.

In Slack, you can mention it:

`@Grail do so and so`

Grail will:
- Acknowledge quickly (queues a job).
- Inject the last **N** Slack messages as context (configurable).
- Work through tasks **one-at-a-time** from a SQLite-backed queue.
- Reply back in the Slack thread.
- Optionally use Slack MCP tools to fetch more context beyond the last N messages.
- Persist durable notes under `/data/context/` and a rolling session memory summary.

This repo is Rust-first (server + Slack MCP server), and uses the open-source Codex CLI app-server for the agent runtime.

## Deploy On Railway (Recommended)

1. Create a new Railway project from this repo.
2. Add a **Volume** mounted at `/data` (required for persistence).
3. Set environment variables:
   - `ADMIN_PASSWORD` (required)
   - `SLACK_SIGNING_SECRET` (required)
   - `SLACK_BOT_TOKEN` (required)
   - `OPENAI_API_KEY` (recommended)
   - `GRAIL_MASTER_KEY` (optional; required only if you want to set the OpenAI key via the dashboard and store it encrypted). Generate with: `openssl rand -hex 32`
4. Deploy.

After deploy:
- Slack events endpoint is `POST /slack/events`
- Dashboard is `GET /admin` (Basic Auth: `admin:<ADMIN_PASSWORD>`)

## Slack App Setup (Bring Your Own App)

This template is intentionally “single workspace per deployment”.

1. Create a Slack App in your workspace.
2. Use the provided manifest: `slack-app-manifest.yaml`
3. Set the request URL in the manifest to:
   - `https://<your-railway-domain>/slack/events`
4. Install the app to your workspace.
5. Copy:
   - **Signing Secret** -> `SLACK_SIGNING_SECRET`
   - **Bot User OAuth Token** -> `SLACK_BOT_TOKEN`

## Dashboard

`/admin/settings` lets you configure:
- Slack context size (last N messages)
- model + reasoning knobs
- permissions mode (`read` vs `full`)
- Slack MCP tool enable/disable
- context writes enable/disable
- shell network access toggle (full mode only)

If `GRAIL_MASTER_KEY` is set, you can also store `OPENAI_API_KEY` encrypted in SQLite from the dashboard.

## Persistence Layout

Mount a volume at `/data`.

Grail stores:
- `/data/grail.sqlite` (queue, settings, session mapping)
- `/data/context/` (durable notes)
- `/data/AGENTS.md` (default instruction “constitution” for the agent)
- `/data/codex/` (`CODEX_HOME` for Codex app-server rollouts/state)

## Permissions Model

- `read`: no command execution; no context writes.
- `full`: command execution is allowed (with sandboxing); context writes allowed (restricted to `/data/context`).

Even in `read`, Grail can respond and (optionally) use Slack MCP tools to fetch more Slack context.

## Local Development

You’ll need:
- Rust toolchain
- `codex` on your PATH (or set `CODEX_BIN`)
- Slack + OpenAI credentials

Run:

```bash
cd grail
export ADMIN_PASSWORD=dev
export SLACK_SIGNING_SECRET=...
export SLACK_BOT_TOKEN=...
export OPENAI_API_KEY=...
cargo run -p grail-server
```
