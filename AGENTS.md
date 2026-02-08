# AGENTS.md — Grail (MicroEmployee)

## What This Is

Grail is a **Slack/Telegram bot** backed by an autonomous AI agent (OpenAI Codex CLI). It receives messages from Slack or Telegram, queues them as tasks in a SQLite database, runs Codex in a sandboxed subprocess to produce answers, and posts the results back. It ships with an admin dashboard for configuration, monitoring, and approvals.

**Production deployment**: Railway (Docker).

---

## Repo Layout

```
MicroEmployee/
├── grail/                      # Main Rust workspace (this is the product)
│   ├── Cargo.toml              # Workspace root
│   └── crates/
│       ├── grail-server/       # Core: web server, worker, admin UI, DB
│       │   ├── src/            # All Rust source (see below)
│       │   ├── templates/      # Askama HTML templates (admin panel)
│       │   └── migrations/     # SQLite migrations (applied on startup)
│       ├── grail-slack-mcp/    # MCP tool server for Slack API
│       └── grail-web-mcp/     # MCP tool server for Brave search + web fetch
├── codex/                      # Vendored OpenAI Codex CLI (Git submodule)
├── guardrails/                 # Vendored Guardrails AI library (Git submodule)
├── nanobot/                    # Vendored Nanobot agent (Git submodule)
├── coworker/                   # Coworker agent (Git submodule)
├── Dockerfile                  # Multi-stage: build Rust → Debian slim + Codex CLI
├── entrypoint.sh               # Drops privileges, runs grail-server
├── railway.json                # Railway deploy config (Dockerfile builder, healthcheck)
├── slack-app-manifest.yaml     # Slack app scopes and event subscriptions
└── .env.example                # All supported environment variables
```

---

## Source Files (`grail/crates/grail-server/src/`)

| File             | Purpose                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `main.rs`        | Axum web server, all HTTP routes (admin pages, Slack/Telegram webhooks, health), Slack signature verification                  |
| `worker.rs`      | Background task processor: claims tasks, builds Codex prompts, spawns Codex CLI subprocess, parses agent output, sends replies |
| `db.rs`          | All SQLite operations (settings CRUD, task queue, sessions, cron, guardrails, approvals, secrets)                              |
| `models.rs`      | Shared structs (`Task`, `Session`, `Settings`, etc.)                                                                           |
| `templates.rs`   | Askama template structs for each admin page                                                                                    |
| `slack.rs`       | `SlackClient` — post messages, upload files, download files, fetch channel history                                             |
| `telegram.rs`    | Telegram webhook payload types and message-sending client                                                                      |
| `codex.rs`       | Codex CLI subprocess management: spawn, stream output, parse structured responses                                              |
| `codex_login.rs` | ChatGPT device login / OAuth flow for Codex authentication                                                                     |
| `approvals.rs`   | Approval request lifecycle (create, decide, check)                                                                             |
| `config.rs`      | CLI args via clap (`--port`, `--data-dir`, etc.)                                                                               |
| `crypto.rs`      | AES-GCM encryption/decryption for stored secrets                                                                               |
| `secrets.rs`     | Secret retrieval (env vars → encrypted SQLite fallback)                                                                        |
| `guardrails.rs`  | Apply guardrail rules to shell commands before execution                                                                       |
| `cron_expr.rs`   | Cron expression parsing helpers                                                                                                |
| `bootstrap.rs`   | First-run setup and data directory initialization                                                                              |

---

## Admin UI Templates (`grail/crates/grail-server/templates/`)

All templates use Askama and extend `layout.html` (base layout with nav + CSS).

| Template            | Page                                                                   |
| ------------------- | ---------------------------------------------------------------------- |
| `layout.html`       | Base layout: Inter font, Linear-inspired dark theme, navigation        |
| `status.html`       | System health: env var status, queue depth, active task, endpoints     |
| `settings.html`     | Agent identity, model, permissions, Slack/Telegram/Web config, secrets |
| `tasks.html`        | Task queue: status, prompt, result, cancel/retry actions               |
| `memory.html`       | Session memory: conversation keys, Codex thread IDs, summaries         |
| `cron.html`         | Scheduled tasks: add/enable/disable/delete cron jobs                   |
| `guardrails.html`   | Command guardrails: add/enable/disable/delete rules                    |
| `approvals.html`    | Pending approvals: approve/deny/always-allow                           |
| `auth.html`         | API keys and ChatGPT device login management                           |
| `context.html`      | Durable context files (`/data/context/*`)                              |
| `context_edit.html` | Edit a single context file                                             |
| `diagnostics.html`  | Codex self-test runner                                                 |

---

## Database (SQLite)

- **Location**: `$GRAIL_DATA_DIR/grail.sqlite` (default `/data/grail.sqlite`)
- **Migrations**: `grail/crates/grail-server/migrations/` — auto-applied on startup via `sqlx::migrate!()`
- **Key tables**: `settings`, `tasks`, `sessions`, `cron_jobs`, `guardrail_rules`, `approvals`, `secrets`

When adding new DB fields:

1. Create a new migration file (`NNNN_description.sql`) with `ALTER TABLE` or `CREATE TABLE`
2. Update the corresponding struct in `models.rs`
3. Update queries in `db.rs`

---

## Environment Variables

See `.env.example` for the full list. Key ones:

| Variable                  | Required    | Purpose                                         |
| ------------------------- | ----------- | ----------------------------------------------- |
| `ADMIN_PASSWORD`          | Yes         | Password for `/admin/*` routes                  |
| `SLACK_SIGNING_SECRET`    | Yes (Slack) | Verify incoming Slack webhooks                  |
| `SLACK_BOT_TOKEN`         | Yes (Slack) | Post messages, upload files                     |
| `OPENAI_API_KEY`          | Yes         | Codex CLI API key                               |
| `TELEGRAM_BOT_TOKEN`      | Optional    | Telegram bot integration                        |
| `TELEGRAM_WEBHOOK_SECRET` | Optional    | Telegram webhook verification                   |
| `BRAVE_SEARCH_API_KEY`    | Optional    | Web search MCP tool                             |
| `GRAIL_MASTER_KEY`        | Optional    | Enable encrypted secret storage in SQLite       |
| `GRAIL_DATA_DIR`          | Optional    | Data directory (default: `/data`)               |
| `CODEX_HOME`              | Optional    | Codex config directory (default: `/data/codex`) |
| `CODEX_BIN`               | Optional    | Path to Codex binary (default: `codex`)         |

---

## Building & Running

```bash
# Local development
cd grail
cargo build                    # debug build
cargo run -p grail-server      # run with default settings

# Production (Docker)
docker build -t grail .
docker run -p 3000:3000 --env-file .env grail
```

### Health check

`GET /healthz` — returns 200 when the server is ready.

---

## Architecture Overview

```
Slack/Telegram ──webhook──▶ grail-server (Axum, port 3000)
                                │
                                ├── Verifies signature
                                ├── Enqueues task in SQLite
                                │
                           Background worker loop
                                │
                                ├── Claims next task
                                ├── Builds prompt (role + context + history + files)
                                ├── Spawns: codex --model ... --prompt ...
                                │     └── Codex uses MCP tools:
                                │           ├── grail-slack-mcp (read channels, search)
                                │           └── grail-web-mcp (brave search, fetch)
                                ├── Parses structured JSON output
                                ├── Applies guardrails (if command execution)
                                ├── Posts reply to Slack/Telegram
                                └── Uploads any generated files
```

The worker is **single-instance** — it acquires a distributed lock in SQLite (`worker_lock` table) so only one container processes tasks at a time.

---

## Key Patterns

- **Askama templates** are compiled at build time. Any template syntax error will fail `cargo build`.
- **CSS lives in `layout.html`** — there are no external stylesheets. All page templates inherit from it.
- **Secrets** can come from env vars OR encrypted SQLite (if `GRAIL_MASTER_KEY` is set). Env vars always take precedence.
- **Codex CLI** runs as a subprocess, not a library. Communication is via stdin/stdout JSON.
- **MCP tool servers** (`grail-slack-mcp`, `grail-web-mcp`) are separate binaries invoked by Codex as stdio-based MCP servers.
- **File handling**: Slack files are downloaded to `/tmp/grail-files/`, agent output files are uploaded back via Slack API.

---

## Common Tasks

### Adding a new admin page

1. Add a template struct in `templates.rs`
2. Create a new `.html` template extending `layout.html`
3. Add a route handler in `main.rs`
4. Add a nav link in `layout.html`

### Adding a new setting

1. Add a column via migration in `migrations/`
2. Add the field to the `Settings` struct in `models.rs`
3. Update `load_settings` and `save_settings` in `db.rs`
4. Add the form field in `settings.html`
5. Wire it up in the `POST /admin/settings` handler in `main.rs`

### Adding a new MCP tool

1. Add the tool implementation in either `grail-slack-mcp` or `grail-web-mcp`
2. Or create a new crate in `crates/` and add it to `Cargo.toml` workspace members
3. Update `Dockerfile` to build and copy the new binary
4. Register the tool server in the Codex config generated by `worker.rs`
