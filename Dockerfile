# ── Stage 1: Build React frontend ──────────────────────────────────────
FROM node:22-slim AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --ignore-scripts || npm install
COPY frontend/ .
RUN npm run build

# ── Stage 2: Build Rust backend ────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

# System deps for building (openssl not required because we use rustls, but
# pkg-config is occasionally needed by transitive crates).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY grail /app/grail

WORKDIR /app/grail
RUN cargo build --release -p grail-server -p grail-slack-mcp -p grail-web-mcp

# ── Stage 3: Runtime ───────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gosu \
    tar \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/grail/target/release/grail-server /usr/local/bin/grail-server
COPY --from=builder /app/grail/target/release/grail-slack-mcp /usr/local/bin/grail-slack-mcp
COPY --from=builder /app/grail/target/release/grail-web-mcp /usr/local/bin/grail-web-mcp

# Copy the built React SPA into the runtime image.
COPY --from=frontend-builder /app/frontend/dist /app/frontend-dist

# Install Codex CLI (Linux x86_64 musl) from GitHub releases.
ARG CODEX_VERSION=rust-v0.98.0
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64) COD_ARCH="x86_64" ;; \
    arm64) COD_ARCH="aarch64" ;; \
    *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/openai/codex/releases/download/${CODEX_VERSION}/codex-${COD_ARCH}-unknown-linux-musl.tar.gz" -o /tmp/codex.tgz; \
    tar -xzf /tmp/codex.tgz -C /tmp; \
    mv "/tmp/codex-${COD_ARCH}-unknown-linux-musl" /usr/local/bin/codex; \
    chmod +x /usr/local/bin/codex; \
    rm -f /tmp/codex.tgz

ENV GRAIL_DATA_DIR=/data
ENV CODEX_HOME=/data/codex
ENV CODEX_BIN=/usr/local/bin/codex
ENV GRAIL_FRONTEND_DIR=/app/frontend-dist

RUN useradd -m -u 10001 -s /bin/bash app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
