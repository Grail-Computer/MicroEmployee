#!/bin/sh
set -eu

DATA_DIR="${GRAIL_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

if [ "$(id -u)" = "0" ]; then
  # Railway volumes may mount as root-owned; ensure the app user can write.
  chown -R app:app "$DATA_DIR" || true
  exec gosu app:app /usr/local/bin/grail-server
fi

exec /usr/local/bin/grail-server

