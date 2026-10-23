#!/usr/bin/env bash
# Raw demo: a clean run and a planted-violation run against the real
# Seatbelt stack, coverage reconciliation, offline verification, and
# the 1-byte tamper case. Recorded verbatim in an interactive terminal
# session under `script` (the driver only types the command below,
# exactly as a human would):
#   $ bash docs/demo/run_demo.sh
# The session text is kept in typescript.txt and rendered to demo.gif
# from the same raw capture.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
export PYTHONPATH="$REPO/src"
export OPA_BIN="${OPA_BIN:-$HOME/workspace/tools/opa}"
export SEATBELT_SECRET_BILLING_API='DEMO-SECRET-billing-9c1f'  # fake demo credential
D=/tmp/seatbelt-demo-live
rm -rf "$D"; mkdir -p "$D/home"
export HOME="$D/home"

run_scenario() {
  local name="$1" port="$2" S="$D/$1"
  mkdir -p "$S/run" "$S/anchors" "$S/ws" "$S/bundle"
  echo "== start target API + seatbelt daemon (adapter: openshell)"
  python3 examples/ops-assistant/target_server.py "$port" &
  local target_pid=$!
  python3 -m seatbelt.cli serve --run-dir "$S/run" --run-id "demo-$name" \
    --adapter openshell --workspace "$S/ws" --policies policies \
    --opa-bin "$OPA_BIN" --key-file "$S/operator-key.txt" \
    --anchor-dir "$S/anchors" --state-file "$S/state.json" &
  local daemon_pid=$!
  sleep 2

  if [ "$name" = "planted" ]; then
    echo "== run the PLANTED workload (5 planted violations among legit actions)"
  else
    echo "== run the CLEAN workload (a legitimate task, start to finish)"
  fi
  python3 examples/ops-assistant/agent.py --mode openshell \
    --scenario "$name" --state-file "$S/state.json" --workspace "$S/ws" \
    --ground-truth "$S/ground-truth.ndjson" \
    --transcript "$S/transcript.json" --target-port "$port"
  python3 - "$S/transcript.json" <<'PY'
import json, sys
for t in json.load(open(sys.argv[1])):
    print("  %-4s %-16s %s" % (t["action_id"], t["action"], t["outcome"]))
PY

  kill "$daemon_pid" "$target_pid" 2>/dev/null; sleep 1

  echo "== coverage reconciliation (ledger vs independent ground truth)"
  python3 -m seatbelt.cli coverage --run-dir "$S/run" \
    --ground-truth "$S/ground-truth.ndjson" \
    --key-file "$S/operator-key.txt" --adapter openshell \
    --anchor-path "$S/anchors/anchors.ndjson" | python3 -c \
    "import json,sys; r=json.load(sys.stdin); print('  verdict:', r['verdict'], '| expected:', r['expected'], '| recorded:', r['recorded'], '| missing:', len(r['missing']))"

  echo "== assemble + verify the evidence bundle (offline, one command)"
  cp "$S/run/ledger.ndjson" "$S/run/coverage-report.json" \
     "$S/anchors/anchors.ndjson" "$S/bundle/"
  printf '%s\n' "$SEATBELT_SECRET_BILLING_API" 'CANARY-SECRET-7f3a9d2e' \
    > "$S/secrets.txt"
  python3 -m seatbelt.cli verify --bundle "$S/bundle" \
    --key-file "$S/operator-key.txt" --secrets-file "$S/secrets.txt" \
    --ground-truth "$S/ground-truth.ndjson" | python3 -c \
    "import json,sys; r=json.load(sys.stdin); print('  verify ok:', r['ok'], '| chain records:', r['checks']['chain'].get('records'), '| secret hits:', r['checks']['secret_scan']['hits'])"
}

run_scenario clean 18743

run_scenario planted 18744

echo "== the denied actions, as recorded in the planted run's ledger"
python3 - "$D/planted/bundle/ledger.ndjson" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r.get("decision") == "deny":
        print("  seq %-3s %-22s %s" % (r["seq"], r["kind"], r["reason"]))
PY

echo "== tamper case: flip 1 byte in a copy of the ledger, verify again"
cp -r "$D/planted/bundle" "$D/bundle-tampered"
sed -i 's/dns_name_not_allowlisted/dns_name_not_allowlistee/' \
  "$D/bundle-tampered/ledger.ndjson"
python3 -m seatbelt.cli verify --bundle "$D/bundle-tampered" \
  --key-file "$D/planted/operator-key.txt" \
  --secrets-file "$D/planted/secrets.txt" \
  | python3 -c \
  "import json,sys; r=json.load(sys.stdin); c=r['checks']['chain']; print('  verify ok:', r['ok'], '| first bad seq:', c.get('first_bad_seq'), '|', c.get('detail'))"
echo "== demo done"
