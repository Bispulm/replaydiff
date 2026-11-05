#!/usr/bin/env bash
# Runs the capture-to-replay path against local synthetic fixtures.
# Everything stays on 127.0.0.1, and all data is invented.
set -euo pipefail

cd "$(dirname "$0")/.."
work=.demo
rm -rf "$work"
mkdir -p "$work/bin"
go build -o "$work/bin/" ./cmd/...
bin="$PWD/$work/bin"

PROXY=18200 BASE_A=18201 BASE_B=18202 CANDIDATE=18203 SERVICE=18204
for port in $PROXY $BASE_A $BASE_B $CANDIDATE $SERVICE; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $port is in use; stop whatever holds it and try again" >&2
    exit 2
  fi
done

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

fixture() { # variant instance port
  "$bin/replaydiff-fixture" --variant "$1" --instance "$2" --listen "127.0.0.1:$3" 2>>"$work/fixtures.log" &
  pids+=($!)
}
wait_for() {
  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "http://127.0.0.1:$1/healthz" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "nothing answering on port $1" >&2
  exit 2
}

echo "== Starting fixtures"
fixture baseline capture "$SERVICE"
fixture baseline a "$BASE_A"
fixture baseline b "$BASE_B"
fixture candidate c "$CANDIDATE"
for port in $SERVICE $BASE_A $BASE_B $CANDIDATE; do wait_for "$port"; done

echo "== Starting the capture proxy on :$PROXY"
"$bin/replaydiff" capture --listen "127.0.0.1:$PROXY" --upstream "http://127.0.0.1:$SERVICE" \
  --out "$work/traffic" --redact examples/redact.yaml >"$work/capture-stats.json" 2>"$work/capture.log" &
proxy=$!
wait_for "$PROXY"

echo "== Sending traffic holding synthetic secrets through the proxy"
proxied="http://127.0.0.1:$PROXY"
auth=(-H "Authorization: Bearer demo-secret-authorization" -H "Cookie: sid=demo-secret-cookie")
curl -fsS "${auth[@]}" "$proxied/v1/orders/ord-1?token=demo-secret-query" -o /dev/null
curl -sS  "${auth[@]}" "$proxied/v1/orders/ord-missing" -o /dev/null
for i in 2 3 4 5; do curl -fsS "${auth[@]}" "$proxied/v1/orders/ord-$i" -o /dev/null; done
for i in 1 2 3 4 5; do
  curl -fsS "${auth[@]}" "$proxied/v1/users/usr-$i" -o /dev/null
  curl -fsS "${auth[@]}" "$proxied/v1/inventory/sku$i" -o /dev/null
  curl -fsS "${auth[@]}" "$proxied/v1/catalog" -o /dev/null
done
for _ in $(seq 1 25); do curl -fsS "${auth[@]}" "$proxied/v1/reports/daily" -o /dev/null; done
curl -fsS "${auth[@]}" "$proxied/v1/cart/s1/step/1" -o /dev/null
curl -fsS "${auth[@]}" "$proxied/v1/cart/s1/step/2" -o /dev/null
curl -fsS -H 'Content-Type: application/json' -d '{"username":"u","password":"demo-secret-password"}' "$proxied/v1/login" -o /dev/null
curl -fsS -H 'Content-Type: application/json' -d '{"sku":"sku-1"}' "$proxied/v1/orders" -o /dev/null
kill -INT "$proxy"
wait "$proxy"
echo "capture statistics: $(cat "$work/capture-stats.json")"

echo
echo "== The stored record for the first request, with its body decoded"
"$bin/replaydiff" inspect --traffic "$work/traffic" 2>/dev/null | grep -a '"path":"/v1/orders/ord-1"' | python3 -m json.tool

echo
echo "== Searching every artifact for the planted secrets"
"$bin/replaydiff" inspect --traffic "$work/traffic" >"$work/inspect.jsonl" 2>/dev/null
if grep -arE 'demo-secret-' "$work/traffic" "$work/capture.log" "$work/inspect.jsonl"; then
  echo "FOUND A PLANTED SECRET" >&2
  exit 1
fi
echo "not found in segments, capture logs, or decoded records"

echo
echo "== Replaying against two baselines and a candidate"
base() { echo "http://127.0.0.1:$1"; }
"$bin/replaydiff" run --traffic "$work/traffic" --report "$work/report.json" --redact examples/redact.yaml \
  --baseline-a "$(base $BASE_A)" --baseline-b "$(base $BASE_B)" --candidate "$(base $CANDIDATE)" \
  --allow-origin "$(base $BASE_A)" --allow-origin "$(base $BASE_B)" --allow-origin "$(base $CANDIDATE)" \
  --rps 200

echo
echo "== Findings: deliberate regressions, with timestamps and IDs explained as noise"
set +e
"$bin/replaydiff" report "$work/report.json"
code=$?
set -e
echo "report exit code: $code (2 until a CI policy exists)"

echo
echo "== Refusing a target that isn't on the allowlist"
set +e
"$bin/replaydiff" run --traffic "$work/traffic" --report "$work/refused.json" --redact examples/redact.yaml \
  --baseline-a "$(base $BASE_A)" --baseline-b "$(base $BASE_B)" --candidate "http://127.0.0.1:9" \
  --allow-origin "$(base $BASE_A)" --allow-origin "$(base $BASE_B)"
code=$?
set -e
echo "run exit code: $code"
