#!/usr/bin/env bash
set -euo pipefail

echo "Running smoke test against cloud-security-posture service..."
BASE_URL="${BASE_URL:-http://localhost:8000}"

HEALTH_STATUS=$(curl -sf "${BASE_URL}/health" | grep -o "ok" || true)
if [[ "${HEALTH_STATUS}" != "ok" ]]; then
  echo "Smoke test FAILED: /health did not return ok"
  exit 1
fi

echo "Smoke test PASSED: /health responded with ok"
