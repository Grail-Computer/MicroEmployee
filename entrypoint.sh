#!/bin/sh
set -eu

DATA_DIR="${GRAIL_DATA_DIR:-/data}"
CODEX_DATA_DIR="${CODEX_HOME:-${DATA_DIR}/codex}"
mkdir -p "$DATA_DIR"
mkdir -p /tmp/grail

is_env_enabled() {
  case "$(printf '%s' "${1:-0}" | tr '[:upper:]' '[:lower:]')" in
    1|true|on|yes) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$(id -u)" = "0" ]; then
  # Keep startup fast: avoid recursive chown of large volumes by default.
  # Enable recursive ownership fix only when explicitly requested.
  chown app:app "$DATA_DIR" || true
  if [ -e "${DATA_DIR}/grail.sqlite" ]; then
    chown app:app "${DATA_DIR}/grail.sqlite" || true
  fi
  if [ -e "${DATA_DIR}/grail.sqlite-wal" ]; then
    chown app:app "${DATA_DIR}/grail.sqlite-wal" || true
  fi
  if [ -e "${DATA_DIR}/grail.sqlite-shm" ]; then
    chown app:app "${DATA_DIR}/grail.sqlite-shm" || true
  fi
  if [ -d "$CODEX_DATA_DIR" ]; then
    chown app:app "$CODEX_DATA_DIR" || true
  fi
  if is_env_enabled "${GRAIL_CHOWN_RECURSIVE:-0}"; then
    chown -R app:app "$DATA_DIR" || true
  fi
  if is_env_enabled "${GRAIL_BROWSER_ENABLED:-0}"; then
    gosu app:app /usr/local/bin/grail-browser-service \
      >>/tmp/grail/browser-service.log 2>&1 &
  fi
  exec gosu app:app /usr/local/bin/grail-server
fi

if is_env_enabled "${GRAIL_BROWSER_ENABLED:-0}"; then
  /usr/local/bin/grail-browser-service >>/tmp/grail/browser-service.log 2>&1 &
fi

exec /usr/local/bin/grail-server
