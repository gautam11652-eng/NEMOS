#!/usr/bin/env bash
set -euo pipefail

# NEMOS live smoke test. Safe to run against a local NEMOS instance:
# it submits one RFC-5737 documentation-address packet to verify the full
# API -> SQLite -> dashboard telemetry path.
BASE_URL="${NEMOS_URL:-http://127.0.0.1:5000}"
TOKEN="${NEMOS_API_TOKEN:-}"
CURL=(curl -fsS --connect-timeout 3 --max-time 8)
AUTH=()
if [[ -n "$TOKEN" ]]; then
  AUTH=(-H "X-NEMOS-Token: $TOKEN")
fi

json_get() {
  "${CURL[@]}" "${AUTH[@]}" "$1"
}

json_post() {
  "${CURL[@]}" "${AUTH[@]}" -H 'Content-Type: application/json' -X POST --data "$2" "$1"
}

echo "[1/5] health"
health="$(json_get "$BASE_URL/api/health")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="online", d' <<<"$health"

echo "[2/5] dashboard/API access"
status="$(curl -sS -o /tmp/nemos-smoke-status -w '%{http_code}' --connect-timeout 3 --max-time 8 "${AUTH[@]}" "$BASE_URL/api/dashboard?limit=10")"
if [[ "$status" == "401" ]]; then
  echo "ERROR: API token required. Set NEMOS_API_TOKEN and rerun." >&2
  exit 2
fi
[[ "$status" == "200" ]] || { echo "ERROR: dashboard returned HTTP $status" >&2; exit 1; }

before="$(json_get "$BASE_URL/api/stats")"
before_packets="$(python3 -c 'import json,sys; print(int(json.load(sys.stdin).get("packets",0)))' <<<"$before")"

echo "[3/5] synthetic telemetry write"
payload='{"source":"192.0.2.10","destination":"198.51.100.20","protocol":"TCP","destination_port":443,"packet_size":60}'
post="$(json_post "$BASE_URL/api/packet" "$payload")"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d' <<<"$post"

for _ in {1..20}; do
  after="$(json_get "$BASE_URL/api/stats")"
  after_packets="$(python3 -c 'import json,sys; print(int(json.load(sys.stdin).get("packets",0)))' <<<"$after")"
  if (( after_packets > before_packets )); then break; fi
  sleep 0.1
done
(( after_packets > before_packets )) || { echo "ERROR: packet did not reach SQLite telemetry" >&2; exit 1; }

echo "[4/5] status/metrics"
status_json="$(json_get "$BASE_URL/api/status")"
metrics_json="$(json_get "$BASE_URL/api/metrics")"
python3 - "$status_json" "$metrics_json" <<'PY'
import json, sys
status=json.loads(sys.argv[1])
metrics=json.loads(sys.argv[2])
assert status.get("ok") is True, status
assert isinstance(status.get("capture"), dict), status
assert isinstance(metrics.get("writer"), dict), metrics
PY

capture_state="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("capture",{}).get("state",""))' <<<"$status_json")"
if [[ "${NEMOS_REQUIRE_CAPTURE:-false}" == "true" ]]; then
  case "$capture_state" in
    running|starting) ;;
    *) echo "ERROR: capture state is '$capture_state' while NEMOS_REQUIRE_CAPTURE=true" >&2; exit 1 ;;
  esac
fi

echo "[5/5] static dashboard asset"
static_status="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "$BASE_URL/static/app.js")"
[[ "$static_status" == "200" ]] || { echo "ERROR: app.js returned HTTP $static_status" >&2; exit 1; }

echo "NEMOS live smoke test: PASS"
echo "  packets before: $before_packets"
echo "  packets after:  $after_packets"
echo "  capture state:  $capture_state"
