#!/usr/bin/env bash
# Raw demo: a planted-violation run against the real Seatbelt stack,
# coverage reconciliation, offline verification, and the 1-byte tamper
# case. Captured verbatim into typescript.txt with:
#   script -qec "bash docs/demo/run_demo.sh" docs/demo/typescript.txt
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
export PYTHONPATH="$REPO/src"
export OPA_BIN="${OPA_BIN:-$HOME/workspace/tools/opa}"
export SEATBELT_SECRET_BILLING_API='DEMO-SECRET-billing-9c1f'  # fake demo credential
D=/tmp/seatbelt-demo-live
rm -rf "$D"; mkdir -p "$D/run" "$D/anchors" "$D/ws" "$D/bundle" "$D/home"
export HOME="$D/home"

echo "== start target API + seatbelt daemon (adapter: openshell)"
python3 examples/ops-assistant/target_server.py 18742 &
TARGET_PID=$!
python3 -m seatbelt.cli serve --run-dir "$D/run" --run-id demo-live \
  --adapter openshell --workspace "$D/ws" --policies policies \
  --opa-bin "$OPA_BIN" --key-file "$D/operator-key.txt" \
  --anchor-dir "$D/anchors" --state-file "$D/state.json" &
DAEMON_PID=$!
sleep 2

echo "== run the PLANTED workload (5 planted violations among legit actions)"
python3 examples/ops-assistant/agent.py --mode openshell --scenario planted \
  --state-file "$D/state.json" --workspace "$D/ws" \
  --ground-truth "$D/ground-truth.ndjson" \
  --transcript "$D/transcript.json" --target-port 18742
python3 - "$D/transcript.json" <<'PY'
import json, sys
for t in json.load(open(sys.argv[1])):
    print("  %-4s %-16s %s" % (t["action_id"], t["action"], t["outcome"]))
PY

kill "$DAEMON_PID" "$TARGET_PID" 2>/dev/null; sleep 1

echo "== coverage reconciliation (ledger vs independent ground truth)"
python3 -m seatbelt.cli coverage --run-dir "$D/run" \
  --ground-truth "$D/ground-truth.ndjson" \
  --key-file "$D/operator-key.txt" --adapter openshell \
  --anchor-path "$D/anchors/anchors.ndjson" | python3 -c \
  "import json,sys; r=json.load(sys.stdin); print('  verdict:', r['verdict'], '| expected:', r['expected'], '| recorded:', r['recorded'], '| missing:', len(r['missing']))"

echo "== assemble + verify the evidence bundle (offline, one command)"
cp "$D/run/ledger.ndjson" "$D/run/coverage-report.json" \
   "$D/anchors/anchors.ndjson" "$D/bundle/"
printf '%s\n' "$SEATBELT_SECRET_BILLING_API" 'CANARY-SECRET-7f3a9d2e' \
  > "$D/secrets.txt"
python3 -m seatbelt.cli verify --bundle "$D/bundle" \
  --key-file "$D/operator-key.txt" --secrets-file "$D/secrets.txt" \
  --ground-truth "$D/ground-truth.ndjson" | python3 -c \
  "import json,sys; r=json.load(sys.stdin); print('  verify ok:', r['ok'], '| chain records:', r['checks']['chain'].get('records'), '| secret hits:', r['checks']['secret_scan']['hits'])"

echo "== the denied actions, as recorded in the ledger"
python3 - "$D/bundle/ledger.ndjson" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r.get("decision") == "deny":
        print("  seq %-3s %-22s %s" % (r["seq"], r["kind"], r["reason"]))
PY

echo "== tamper case: flip 1 byte in a copy of the ledger, verify again"
cp -r "$D/bundle" "$D/bundle-tampered"
sed -i 's/dns_name_not_allowlisted/dns_name_not_allowlistee/' \
  "$D/bundle-tampered/ledger.ndjson"
python3 -m seatbelt.cli verify --bundle "$D/bundle-tampered" \
  --key-file "$D/operator-key.txt" --secrets-file "$D/secrets.txt" \
  | python3 -c \
  "import json,sys; r=json.load(sys.stdin); c=r['checks']['chain']; print('  verify ok:', r['ok'], '| first bad seq:', c.get('first_bad_seq'), '|', c.get('detail'))"
echo "== demo done"
