#!/bin/sh
set -eu

DATA_DIR="${GRAIL_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"
mkdir -p /tmp/grail

is_env_enabled() {
  case "$(printf '%s' "${1:-0}" | tr '[:upper:]' '[:lower:]')" in
    1|true|on|yes) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$(id -u)" = "0" ]; then
  # Railway volumes may mount as root-owned; ensure the app user can write.
  chown -R app:app "$DATA_DIR" || true
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
