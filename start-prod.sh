#!/usr/bin/env bash
set -euo pipefail

if [[ "${PWD}" != "/app" ]]; then
  cd /app 2>/dev/null || true
fi

exec /deploy/start.sh
