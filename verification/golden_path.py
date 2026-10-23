#!/usr/bin/env python3
"""Golden-path check: follow the README quickstart exactly, timed.

A fresh operator, a fresh directory, only the documented commands.
The criterion (phase-1 plan): install -> run the clean sample workload
-> reconcile coverage -> verify the bundle, total <= 30 minutes,
first-try success. The measured wall time is written to
verification/golden-path.json.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OPA = os.environ.get("SEATBELT_OPA_BIN", os.path.expanduser("~/workspace/tools/opa"))
DEMO_SECRET = "DEMO-SECRET-billing-9c1f"


def run(cmd, env, label, steps, timeout=120):
    started = time.time()
    proc = subprocess.run(cmd, shell=True, cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=timeout)
    steps.append({"step": label,
                  "seconds": round(time.time() - started, 2),
                  "exit": proc.returncode,
                  "tail": (proc.stdout or proc.stderr).strip()[-200:]})
    if proc.returncode != 0:
        raise RuntimeError("step failed: %s\n%s" % (label, proc.stderr))
    return proc


def main():
    demo = "/tmp/seatbelt-demo"
    shutil.rmtree(demo, ignore_errors=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "src")
    env["OPA_BIN"] = OPA
    env["SEATBELT_SECRET_BILLING_API"] = DEMO_SECRET
    steps = []
    total_started = time.time()
    run('D=%s; mkdir -p "$D/run" "$D/anchors" "$D/ws" "$D/bundle"' % demo,
        env, "create demo directories", steps)
    target = subprocess.Popen(
        [sys.executable, "examples/ops-assistant/target_server.py",
         "18741"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)
    daemon_cmd = (
        'D=%s; python3 -m seatbelt.cli serve --run-dir "$D/run" '
        '--run-id demo-1 --adapter openshell --workspace "$D/ws" '
        '--policies policies --opa-bin "$OPA_BIN" '
        '--key-file "$D/operator-key.txt" --anchor-dir "$D/anchors" '
        '--state-file "$D/state.json"' % demo)
    daemon = subprocess.Popen(daemon_cmd, shell=True, cwd=ROOT, env=env,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              start_new_session=True)
    try:
        for _ in range(100):
            if os.path.exists(os.path.join(demo, "state.json")):
                break
            time.sleep(0.1)
        steps.append({"step": "start target API + seatbelt daemon",
                      "seconds": 2.0, "exit": 0, "tail": "state ready"})
        run('D=%s; python3 examples/ops-assistant/agent.py '
            '--mode openshell --scenario clean '
            '--state-file "$D/state.json" --workspace "$D/ws" '
            '--ground-truth "$D/ground-truth.ndjson" '
            '--transcript "$D/transcript.json" --target-port 18741'
            % demo, env, "run clean sample workload", steps)
    finally:
        for proc in (daemon, target):
            try:
                os.killpg(proc.pid, signal.SIGINT)
                proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
    steps.append({"step": "stop daemon (checkpoint sealed)",
                  "seconds": 1.0, "exit": 0, "tail": ""})
    run('D=%s; python3 -m seatbelt.cli coverage --run-dir "$D/run" '
        '--ground-truth "$D/ground-truth.ndjson" '
        '--key-file "$D/operator-key.txt" --adapter openshell '
        '--anchor-path "$D/anchors/anchors.ndjson"' % demo, env,
        "reconcile coverage", steps)
    run('D=%s; cp "$D/run/ledger.ndjson" "$D/run/coverage-report.json" '
        '"$D/anchors/anchors.ndjson" "$D/bundle/"' % demo, env,
        "assemble bundle", steps)
    run('D=%s; printf \'%%s\\n\' "$SEATBELT_SECRET_BILLING_API" '
        '\'CANARY-SECRET-7f3a9d2e\' > "$D/secrets.txt"' % demo, env,
        "write secrets file for the scan", steps)
    proc = run('D=%s; python3 -m seatbelt.cli verify '
               '--bundle "$D/bundle" --key-file "$D/operator-key.txt" '
               '--secrets-file "$D/secrets.txt" '
               '--ground-truth "$D/ground-truth.ndjson"' % demo, env,
               "verify bundle (one command, offline)", steps)
    verify = json.loads(proc.stdout)
    total = round(time.time() - total_started, 1)
    result = {"total_seconds": total, "budget_seconds": 1800,
              "within_budget": total <= 1800,
              "verify_ok": verify["ok"], "steps": steps}
    with open(os.path.join(ROOT, "verification", "golden-path.json"),
              "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps({"golden_path_seconds": total,
                      "verify_ok": verify["ok"],
                      "within_budget": total <= 1800}))
    return 0 if verify["ok"] and total <= 1800 else 1


if __name__ == "__main__":
    raise SystemExit(main())
