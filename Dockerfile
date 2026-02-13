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

# Copy manifests first so dependency compilation stays cached when only source changes.
COPY grail/Cargo.toml grail/Cargo.lock /app/grail/
COPY grail/crates/grail-server/Cargo.toml /app/grail/crates/grail-server/Cargo.toml
COPY grail/crates/grail-slack-mcp/Cargo.toml /app/grail/crates/grail-slack-mcp/Cargo.toml
COPY grail/crates/grail-web-mcp/Cargo.toml /app/grail/crates/grail-web-mcp/Cargo.toml

WORKDIR /app/grail
RUN set -eux; \
    mkdir -p crates/grail-server/src crates/grail-slack-mcp/src crates/grail-web-mcp/src; \
    printf 'fn main() {}\n' > crates/grail-server/src/main.rs; \
    printf 'fn main() {}\n' > crates/grail-slack-mcp/src/main.rs; \
    printf 'fn main() {}\n' > crates/grail-web-mcp/src/main.rs; \
    cargo build --release --locked -p grail-server -p grail-slack-mcp -p grail-web-mcp

COPY grail /app/grail
RUN cargo build --release --locked -p grail-server -p grail-slack-mcp -p grail-web-mcp

# ── Stage 3: Runtime ───────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    chromium \
    curl \
    git \
    gosu \
    fonts-liberation \
    fonts-noto-color-emoji \
    python3-pip \
    novnc \
    python3 \
    socat \
    websockify \
    x11vnc \
    xvfb \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install Codex CLI from GitHub releases.
# - CODEX_VERSION=latest (default) tracks the newest release.
# - Set CODEX_VERSION=rust-vX.Y.Z to pin to a specific release.
# - Change CODEX_REFRESH to force this layer to refresh when needed.
ARG CODEX_VERSION=latest
ARG CODEX_REFRESH=static
ARG TARGETARCH
RUN set -eux; \
    echo "codex-refresh=${CODEX_REFRESH}" >/dev/null; \
    case "${TARGETARCH}" in \
    amd64) COD_ARCH="x86_64" ;; \
    arm64) COD_ARCH="aarch64" ;; \
    *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    if [ "${CODEX_VERSION}" = "latest" ]; then \
      COD_URL="https://github.com/openai/codex/releases/latest/download/codex-${COD_ARCH}-unknown-linux-musl.tar.gz"; \
    else \
      COD_URL="https://github.com/openai/codex/releases/download/${CODEX_VERSION}/codex-${COD_ARCH}-unknown-linux-musl.tar.gz"; \
    fi; \
    curl -fsSL "${COD_URL}" -o /tmp/codex.tgz; \
    tar -xzf /tmp/codex.tgz -C /tmp; \
    mv "/tmp/codex-${COD_ARCH}-unknown-linux-musl" /usr/local/bin/codex; \
    chmod +x /usr/local/bin/codex; \
    rm -f /tmp/codex.tgz; \
    codex --version

RUN python3 -m pip install --no-cache-dir --break-system-packages uv
RUN useradd -m -u 10001 -s /bin/bash app

ENV GRAIL_DATA_DIR=/data
ENV CODEX_HOME=/data/codex
ENV CODEX_BIN=/usr/local/bin/codex
ENV GRAIL_FRONTEND_DIR=/app/frontend-dist

COPY entrypoint.sh /entrypoint.sh
COPY grail-browser-service.sh /usr/local/bin/grail-browser-service
RUN chmod +x /entrypoint.sh /usr/local/bin/grail-browser-service

# Copy frequently changing app artifacts last so setup layers stay cached.
COPY --from=builder /app/grail/target/release/grail-server /usr/local/bin/grail-server
COPY --from=builder /app/grail/target/release/grail-slack-mcp /usr/local/bin/grail-slack-mcp
COPY --from=builder /app/grail/target/release/grail-web-mcp /usr/local/bin/grail-web-mcp
COPY --from=frontend-builder /app/frontend/dist /app/frontend-dist

EXPOSE 3000 9222 5900 6080
ENTRYPOINT ["/entrypoint.sh"]
