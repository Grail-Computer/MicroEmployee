FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app

# System deps for building (openssl not required because we use rustls, but
# pkg-config is occasionally needed by transitive crates).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY grail /app/grail

WORKDIR /app/grail
RUN cargo build --release -p grail-server -p grail-slack-mcp


FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gosu \
    tar \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/grail/target/release/grail-server /usr/local/bin/grail-server
COPY --from=builder /app/grail/target/release/grail-slack-mcp /usr/local/bin/grail-slack-mcp

# Install Codex CLI (Linux x86_64 musl) from GitHub releases.
RUN set -eux; \
    curl -fsSL "https://github.com/openai/codex/releases/latest/download/codex-x86_64-unknown-linux-musl.tar.gz" -o /tmp/codex.tgz; \
    tar -xzf /tmp/codex.tgz -C /tmp; \
    mv /tmp/codex-x86_64-unknown-linux-musl /usr/local/bin/codex; \
    chmod +x /usr/local/bin/codex; \
    rm -f /tmp/codex.tgz

ENV GRAIL_DATA_DIR=/data
ENV CODEX_HOME=/data/codex
ENV CODEX_BIN=/usr/local/bin/codex

RUN useradd -m -u 10001 -s /bin/bash app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
