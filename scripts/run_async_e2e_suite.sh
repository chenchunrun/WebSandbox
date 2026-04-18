#!/usr/bin/env bash
set -euo pipefail

# Async E2E suite for API + Celery worker + Redis queue.
# Usage:
#   scripts/run_async_e2e_suite.sh
# Optional env:
#   API_BASE_URL=http://127.0.0.1:8000
#   TEST_URL=https://example.com
#   BATCH_URLS=https://example.com,https://example.org
#   POLL_TIMEOUT_SEC=240
#   POLL_INTERVAL_SEC=3
#   AUTO_START_STACK=1
#   AUTO_BUILD=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:8000}"
TEST_URL="${TEST_URL:-https://example.com}"
BATCH_URLS="${BATCH_URLS:-https://example.com,https://example.org}"
POLL_TIMEOUT_SEC="${POLL_TIMEOUT_SEC:-240}"
POLL_INTERVAL_SEC="${POLL_INTERVAL_SEC:-3}"
AUTO_START_STACK="${AUTO_START_STACK:-1}"
AUTO_BUILD="${AUTO_BUILD:-0}"

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

if ! command -v docker >/dev/null 2>&1; then
  echo "[FAIL] docker command not found"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[FAIL] Docker daemon is not running"
  exit 1
fi

if [[ "$AUTO_START_STACK" == "1" ]]; then
  echo "[INFO] ensuring compose stack is up"
  if [[ "$AUTO_BUILD" == "1" ]]; then
    (cd "$ROOT_DIR" && docker compose up -d --build redis postgres minio minio-init api worker)
  else
    if ! (cd "$ROOT_DIR" && docker compose up -d --no-build redis postgres minio minio-init api worker); then
      echo "[FAIL] compose start without build failed."
      echo "       run with AUTO_BUILD=1 only if your network can build images reliably."
      exit 1
    fi
  fi
fi

for _ in {1..60}; do
  if curl -fsS "$API_BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

health="$(curl -sS "$API_BASE_URL/health")"
assert_contains "$health" "\"status\":\"ok\"" "api health"

submit_resp="$(curl -sS -X POST "$API_BASE_URL/analyze" -H 'Content-Type: application/json' -d "{\"url\":\"${TEST_URL}\",\"depth\":\"quick\",\"mode\":\"async\"}")"

task_id="$(python3 - <<'PY' "$submit_resp"
import json,sys
p=json.loads(sys.argv[1])
print(p.get('task_id',''))
PY
)"

if [[ -z "$task_id" ]]; then
  echo "[FAIL] async submit missing task_id"
  echo "$submit_resp"
  exit 1
fi

echo "[PASS] async submit task_id=$task_id"

start_ts="$(date +%s)"
final_resp=""
while true; do
  final_resp="$(curl -sS "$API_BASE_URL/analyze/$task_id")"
  status="$(python3 - <<'PY' "$final_resp"
import json,sys
p=json.loads(sys.argv[1])
print(p.get('status',''))
PY
)"
  if [[ "$status" == "done" || "$status" == "failed" ]]; then
    break
  fi
  now="$(date +%s)"
  if (( now - start_ts > POLL_TIMEOUT_SEC )); then
    echo "[FAIL] async task polling timed out"
    echo "$final_resp"
    exit 1
  fi
  sleep "$POLL_INTERVAL_SEC"
done

if [[ "$status" == "failed" ]]; then
  echo "[FAIL] async task failed"
  echo "$final_resp"
  exit 1
fi

python3 - <<'PY' "$final_resp"
import json,sys
p=json.loads(sys.argv[1])
assert p.get('status')=='done',p
v=(p.get('verdict') or {})
assert v.get('label') in {'benign','phishing','malware'},p
print('[PASS] async task completed with valid verdict')
PY

IFS=',' read -r batch_url1 batch_url2 <<<"$BATCH_URLS"
batch_payload="{\"urls\":[\"${batch_url1}\",\"${batch_url2}\"],\"depth\":\"quick\"}"
batch_resp="$(curl -sS -X POST "$API_BASE_URL/analyze/batch" -H 'Content-Type: application/json' -d "$batch_payload")"

batch_count="$(python3 - <<'PY' "$batch_resp"
import json,sys
p=json.loads(sys.argv[1])
print(p.get('count',''))
PY
)"
assert_eq "$batch_count" "2" "batch async accepted"

echo "All async E2E checks passed."
