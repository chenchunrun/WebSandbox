#!/usr/bin/env bash
set -euo pipefail

# Regression suite for security + core functionality.
# Usage:
#   scripts/run_regression_suite.sh
# Optional env:
#   API_PORT=18003
#   API_HOST=127.0.0.1
#   GOVERNANCE_API_KEY=test-key
#   TEST_SYNC_URL=https://example.com
#   EXPECT_ASYNC_UNAVAILABLE=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="${ROOT_DIR}/.venv312/bin/activate"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-18003}"
BASE_URL="http://${API_HOST}:${API_PORT}"
GOV_KEY="${GOVERNANCE_API_KEY:-test-key}"
TEST_SYNC_URL="${TEST_SYNC_URL:-https://example.com}"
EXPECT_ASYNC_UNAVAILABLE="${EXPECT_ASYNC_UNAVAILABLE:-1}"
SQLITE_PATH="${ROOT_DIR}/local_regression.db"
LOG_FILE="/tmp/websandbox_regression_api.log"

if [[ ! -f "$VENV_PATH" ]]; then
  echo "missing virtualenv at $VENV_PATH"
  exit 1
fi

source "$VENV_PATH"

export DATABASE_URL="sqlite:///${SQLITE_PATH}"
export REDIS_URL="redis://127.0.0.1:6379/0"
export MINIO_ENDPOINT="127.0.0.1:9000"
export MINIO_ACCESS_KEY="minioadmin"
export MINIO_SECRET_KEY="minioadmin"
export MINIO_SECURE="false"
export MINIO_BUCKET="sandbox-artifacts"
export ISOLATION_MODE="local"
export GOVERNANCE_API_KEY="$GOV_KEY"
export MODEL_ARTIFACT_DIR="${ROOT_DIR}/models"
export ALLOW_PRIVATE_TARGET_URLS="false"
export ALLOW_PRIVATE_CALLBACK_URLS="false"

cleanup() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" >/dev/null 2>&1; then
    kill "$API_PID" >/dev/null 2>&1 || true
    wait "$API_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

uvicorn app.main:app --host "$API_HOST" --port "$API_PORT" >"$LOG_FILE" 2>&1 &
API_PID=$!

for _ in {1..30}; do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

assert_eq() {
  local got="$1"
  local exp="$2"
  local msg="$3"
  if [[ "$got" != "$exp" ]]; then
    echo "[FAIL] ${msg} (expected=${exp}, got=${got})"
    exit 1
  fi
  echo "[PASS] ${msg}"
}

assert_contains() {
  local text="$1"
  local pat="$2"
  local msg="$3"
  if [[ "$text" != *"$pat"* ]]; then
    echo "[FAIL] ${msg} (missing pattern: ${pat})"
    exit 1
  fi
  echo "[PASS] ${msg}"
}

health="$(curl -sS "${BASE_URL}/health")"
assert_contains "$health" "\"status\":\"ok\"" "health endpoint"

code="$(curl -sS -o /tmp/ws_reg_model_unauth.json -w "%{http_code}" "${BASE_URL}/model/status")"
assert_eq "$code" "401" "governance auth required"
unauth_body="$(cat /tmp/ws_reg_model_unauth.json)"
assert_contains "$unauth_body" "invalid governance api key" "governance error message"

code="$(curl -sS -o /tmp/ws_reg_model_auth.json -w "%{http_code}" -H "X-API-Key: ${GOV_KEY}" "${BASE_URL}/model/status")"
assert_eq "$code" "200" "governance auth success"

code="$(curl -sS -o /tmp/ws_reg_invalid_url.json -w "%{http_code}" -X POST "${BASE_URL}/analyze" -H "Content-Type: application/json" -d '{"url":"not-a-url","depth":"quick","mode":"sync"}')"
assert_eq "$code" "422" "invalid url rejected"

code="$(curl -sS -o /tmp/ws_reg_ssrf.json -w "%{http_code}" -X POST "${BASE_URL}/analyze" -H "Content-Type: application/json" -d "{\"url\":\"http://${API_HOST}:${API_PORT}/health\",\"depth\":\"quick\",\"mode\":\"sync\"}")"
assert_eq "$code" "400" "private target url blocked"
assert_contains "$(cat /tmp/ws_reg_ssrf.json)" "private IP target is not allowed" "ssrf detail"

code="$(curl -sS -o /tmp/ws_reg_callback.json -w "%{http_code}" -X POST "${BASE_URL}/analyze" -H "Content-Type: application/json" -d "{\"url\":\"${TEST_SYNC_URL}\",\"depth\":\"quick\",\"mode\":\"sync\",\"callback_url\":\"http://${API_HOST}:${API_PORT}/health\"}")"
assert_eq "$code" "400" "private callback blocked"
assert_contains "$(cat /tmp/ws_reg_callback.json)" "callback_url private IP target is not allowed" "callback detail"

sync_resp="$(curl -sS -X POST "${BASE_URL}/analyze" -H "Content-Type: application/json" -d "{\"url\":\"${TEST_SYNC_URL}\",\"depth\":\"quick\",\"mode\":\"sync\"}")"
python3 - <<'PY' "$sync_resp"
import json, sys
payload = json.loads(sys.argv[1])
assert payload.get("status") == "done", payload
assert payload.get("verdict", {}).get("label") in {"benign", "phishing", "malware"}, payload
print("[PASS] sync analyze")
PY

code="$(curl -sS -o /tmp/ws_reg_batch.json -w "%{http_code}" -X POST "${BASE_URL}/analyze/batch" -H "Content-Type: application/json" -d "{\"urls\":[\"${TEST_SYNC_URL}\",\"https://www.cmrh.com\"],\"depth\":\"quick\"}")"
batch_body="$(cat /tmp/ws_reg_batch.json)"
if [[ "$EXPECT_ASYNC_UNAVAILABLE" == "1" ]]; then
  assert_eq "$code" "503" "batch async unavailable without celery"
  assert_contains "$batch_body" "async worker unavailable" "batch async unavailable detail"
else
  assert_eq "$code" "200" "batch accepted"
fi

code="$(curl -sS -o /tmp/ws_reg_model_path.json -w "%{http_code}" -X POST "${BASE_URL}/model/promote" -H "X-API-Key: ${GOV_KEY}" -H "Content-Type: application/json" -d '{"challenger_path":"/tmp/evil.joblib"}')"
assert_eq "$code" "400" "model path escape blocked"
assert_contains "$(cat /tmp/ws_reg_model_path.json)" "model artifact path escapes allowed directory" "model path detail"

echo "All regression checks passed."
