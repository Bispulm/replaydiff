#!/usr/bin/env bash
# Proves the CI gate's three outcomes against real processes on 127.0.0.1, using invented
# data: a regression exits 1, the same code exits 0, and a dead baseline exits 2.
# The script fails if any outcome isn't the expected one.
set -euo pipefail

cd "$(dirname "$0")/.."
work="${GATE_DEMO_DIR:-.demo/gate}"
rm -rf "$work"
mkdir -p "$work/bin"
go build -o "$work/bin/" ./cmd/...
bin="$(cd "$work/bin" && pwd)"
policy=examples/redact.yaml

PROXY=18205 SERVICE=18206 BASE_A=18207 BASE_B=18208 CANDIDATE=18209
for port in $PROXY $SERVICE $BASE_A $BASE_B $CANDIDATE; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $port is in use; stop whatever holds it and try again" >&2
    exit 2
  fi
done

pids=()
cleanup() {
  if [ "${#pids[@]}" -gt 0 ]; then kill "${pids[@]}" 2>/dev/null || true; fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

url() { echo "http://127.0.0.1:$1"; }
wait_for() {
  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "$(url "$1")/healthz" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "nothing answering on port $1" >&2
  exit 2
}
fixture() { # variant instance port; sets last_pid
  "$bin/replaydiff-fixture" --variant "$1" --instance "$2" --listen "127.0.0.1:$3" 2>>"$work/fixtures.log" &
  last_pid=$!
  pids+=("$last_pid")
  wait_for "$3"
}

echo "== Capturing traffic"
fixture baseline capture "$SERVICE"
"$bin/replaydiff" capture --listen "127.0.0.1:$PROXY" --upstream "$(url "$SERVICE")" \
  --out "$work/traffic" --redact "$policy" >/dev/null 2>"$work/capture.log" &
proxy=$!
wait_for "$PROXY"
proxied=$(url "$PROXY")
for i in 1 2 3 4 5; do
  curl -fsS "$proxied/v1/orders/ord-$i" -o /dev/null
  curl -fsS "$proxied/v1/users/usr-$i" -o /dev/null
  curl -fsS "$proxied/v1/inventory/sku$i" -o /dev/null
  curl -fsS "$proxied/v1/catalog" -o /dev/null
done
curl -sS "$proxied/v1/orders/ord-missing" -o /dev/null
for _ in $(seq 1 25); do curl -fsS "$proxied/v1/reports/daily" -o /dev/null; done
kill -INT "$proxy"
wait "$proxy"

fixture baseline a "$BASE_A"
fixture baseline b "$BASE_B"
pid_b=$last_pid

# scenario name variant expected
scenario() {
  local name=$1 variant=$2 expected=$3 code=0
  fixture "$variant" c "$CANDIDATE"
  local candidate_pid=$last_pid dir="$work/$name"
  mkdir -p "$dir"
  "$bin/replaydiff" run --traffic "$work/traffic" --redact "$policy" --report "$dir/report.json" --rps 0 \
    --baseline-a "$(url "$BASE_A")" --baseline-b "$(url "$BASE_B")" --candidate "$(url "$CANDIDATE")" \
    --allow-origin "$(url "$BASE_A")" --allow-origin "$(url "$BASE_B")" --allow-origin "$(url "$CANDIDATE")" \
    >"$dir/run.log" 2>&1 || true
  "$bin/replaydiff" report "$dir/report.json" --quiet \
    --markdown "$dir/summary.md" --junit "$dir/junit.xml" --json "$dir/gate.json" || code=$?
  kill "$candidate_pid" 2>/dev/null || true
  wait "$candidate_pid" 2>/dev/null || true
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo "### Scenario: $name (exit $code, expected $expected)"; echo; cat "$dir/summary.md"; echo; } >>"$GITHUB_STEP_SUMMARY"
  fi
  if [ "$code" -ne "$expected" ]; then
    echo "FAILED: $name exited $code, expected $expected" >&2
    exit 1
  fi
  echo "ok: $name exited $code as expected"
}

echo "== Candidate with deliberate regressions must fail"
scenario regression candidate 1

echo "== Candidate running the same code must pass"
scenario clean baseline 0

echo "== A dead baseline must not pass"
kill "$pid_b"
wait "$pid_b" 2>/dev/null || true
scenario dead-baseline baseline 2

echo "== Gate outcomes are as expected"
