#!/usr/bin/env bash
set -euo pipefail

APP_MODULE=${APP_MODULE:-"webapp.api:app"}
UVICORN_HOST=${UVICORN_HOST:-"127.0.0.1"}
UVICORN_PORT=${UVICORN_PORT:-8000}
UVICORN_LOG_LEVEL=${UVICORN_LOG_LEVEL:-"info"}
CADDY_CONFIG=${CADDY_CONFIG:-"/deploy/caddy/Caddyfile"}

cd /app

echo "[start.sh] Starting Uvicorn (${APP_MODULE}) on ${UVICORN_HOST}:${UVICORN_PORT}"
uvicorn "$APP_MODULE" \
  --host "$UVICORN_HOST" \
  --port "$UVICORN_PORT" \
  --proxy-headers \
  --forwarded-allow-ips="*" \
  --no-server-header \
  --log-level "$UVICORN_LOG_LEVEL" &
UVICORN_PID=$!

handle_shutdown() {
  echo "[start.sh] Shutting down services"
  if kill -0 "$UVICORN_PID" >/dev/null 2>&1; then
    kill "$UVICORN_PID"
    wait "$UVICORN_PID" || true
  fi
}

trap handle_shutdown EXIT INT TERM

if [[ ! -f /deploy/certs/origin.pem || ! -f /deploy/certs/origin.key ]]; then
  echo "[start.sh] WARNING: Origin certificates not found in /deploy/certs. TLS startup may fail."
fi

echo "[start.sh] Starting Caddy with config ${CADDY_CONFIG}"
exec caddy run --config "$CADDY_CONFIG" --adapter caddyfile
