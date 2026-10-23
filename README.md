# Agent Seatbelt

A vendor-neutral policy and tamper-evident evidence layer that sits **above** the agent runtime you already use. Every agent action — tool call, network egress, DNS lookup, file access, credential use — is decided by a deterministic policy engine outside the agent process, and every decision, **including the denied ones**, lands in an append-only, hash-chained evidence ledger you can verify with one offline command.

**An agent action with no evidence record is a system failure, not a detail.** Seatbelt turns evidence coverage into a measured, self-checking property: the ledger reconciles what was expected against what was observed, and a run fails publicly when a record is missing.

![Demo: one real terminal session — a clean run, a planted run with its violations blocked and recorded, offline bundle verification, and the 1-byte tamper case failing verification](docs/demo/demo.gif)

*The demo is one real terminal session, recorded as it ran — nothing staged, nothing retyped. `bash docs/demo/run_demo.sh` runs the clean workload (every action allowed and recorded), then the planted workload (five planted violations blocked **and** recorded), reconciles coverage, verifies the evidence bundle offline, then flips one byte in a copy of the ledger and watches the verifier fail, naming the tampered record. Raw session text: [docs/demo/typescript.txt](docs/demo/typescript.txt).*

## Who hurts, and what this does about it

You run AI agents with real credentials against real systems. Your runtime's sandbox may block a bad action — an independent evaluation of one leading runtime found the blocking held up — but its audit trail had holes: a blocked DNS query left **no event at all**, the audit export silently wrote nothing, and tool calls inside the sandbox were never recorded. When something goes wrong you cannot answer the only question that matters — *what exactly did the agent do, and what did we stop?* — from records you can trust, because the records are scattered across the runtime, the gateway, and a console, and some of them can be edited after the fact.

Seatbelt is the missing layer: one policy point and one evidence ledger across runtimes, with coverage that is **checked, not claimed**.

## What it does

- **Deterministic policy at the boundary.** Tool calls, egress, DNS, file access, budget, and credential grants are decided by OPA/Rego policy packs running outside the agent process. No LLM judges anything in the decision path.
- **Records for both directions.** Allow *and* deny become evidence records carrying the enforcement mode and the hash of the exact policy pack that decided them.
- **Tamper-evident ledger.** Append-only NDJSON with a hash chain, signed checkpoints, and Merkle roots anchored outside the ledger directory. Flip one byte and the verifier names the exact record.
- **Coverage accounting.** Each adapter publishes a coverage manifest. After a run, the accountant reconciles the ledger against an independent ground truth; a missing record fails the run in writing.
- **Credentials per run + per action.** A broker grants credential use for one run, one action, one target. The model never sees the raw secret; the ledger records the grant or the refusal, never a value. Denied DNS names are recorded redacted (digest only) so the ledger can never become a copy of what it blocked.
- **One-command offline verification.** Chain integrity, checkpoint signatures, external anchor, coverage report, and a raw-secret scan of the whole bundle — no server, no trust in the runtime.

## Quickstart (the golden path, ~2 minutes)

Prerequisites: Python ≥ 3.11 and an [OPA](https://www.openpolicyagent.org/) binary (phase 1 is developed against OPA 1.21). Everything else is the Python standard library.

```bash
export PYTHONPATH="$PWD/src"
export OPA_BIN=/path/to/opa
# A FAKE demo credential for the sample workload. Never a real one:
# the broker reads it from the environment, and it must never reach
# the agent or the ledger.
export SEATBELT_SECRET_BILLING_API='DEMO-SECRET-billing-9c1f'
D=/tmp/seatbelt-demo; mkdir -p "$D/run" "$D/anchors" "$D/ws" "$D/bundle"

# 1. Start the sample target API and the Seatbelt daemon
python3 examples/ops-assistant/target_server.py 18741 &
python3 -m seatbelt.cli serve --run-dir "$D/run" --run-id demo-1 \
  --adapter openshell --workspace "$D/ws" --policies policies \
  --opa-bin "$OPA_BIN" --key-file "$D/operator-key.txt" \
  --anchor-dir "$D/anchors" --state-file "$D/state.json" &
sleep 2

# 2. Run the clean sample workload through Seatbelt's boundary points
python3 examples/ops-assistant/agent.py --mode openshell \
  --scenario clean --state-file "$D/state.json" --workspace "$D/ws" \
  --ground-truth "$D/ground-truth.ndjson" \
  --transcript "$D/transcript.json" --target-port 18741

# 3. Stop the daemon, reconcile coverage, assemble + verify the bundle
kill %2; sleep 1
python3 -m seatbelt.cli coverage --run-dir "$D/run" \
  --ground-truth "$D/ground-truth.ndjson" --key-file "$D/operator-key.txt" \
  --adapter openshell --anchor-path "$D/anchors/anchors.ndjson"
cp "$D/run/ledger.ndjson" "$D/run/coverage-report.json" \
   "$D/anchors/anchors.ndjson" "$D/bundle/"
printf '%s\n' "$SEATBELT_SECRET_BILLING_API" 'CANARY-SECRET-7f3a9d2e' \
  > "$D/secrets.txt"
python3 -m seatbelt.cli verify --bundle "$D/bundle" \
  --key-file "$D/operator-key.txt" --secrets-file "$D/secrets.txt" \
  --ground-truth "$D/ground-truth.ndjson"
```

The verifier prints `{"ok": true, ...}` and exits 0. Try the `planted` scenario to watch five planted violations get blocked *and* recorded, then flip any byte in `bundle/ledger.ndjson` and re-run the verify step — it fails, naming the tampered record.

## Adapters (phase 1)

| Adapter | Boundary points | Native signals | Coverage manifest |
|---|---|---|---|
| Claude Code | PreToolUse hook CLI (`seatbelt hook`) + resolver tap + broker/budget via daemon | OpenTelemetry events, ingested into the same ledger | [adapters/claude-code/coverage-manifest.json](adapters/claude-code/coverage-manifest.json) |
| NVIDIA OpenShell | Daemon decision API + MCP proxy + egress proxy + resolver tap | OCSF export, ingested and reconciled against Seatbelt's own records | [adapters/openshell/coverage-manifest.json](adapters/openshell/coverage-manifest.json) |

Status honesty: the hook CLI, MCP proxy, egress proxy, DNS tap, broker, ledger, accountant, and verifier are measured end to end by `verification/run_acceptance.py` (all checks pass; see `verification/results.md`). The OpenShell adapter has also run beside a **live OpenShell 0.1.5**: on a GitHub Actions runner (docker driver) the sandbox booted and executed real commands, a native shorthand event for a DNS denial was captured (`NET:REFUSE … DENIED`, reason `policy_dns_ineligible`), and Seatbelt-side coverage passed 13/13 against independent ground truth (workflow `.github/workflows/openshell-live.yml`; full record in the release dossier). One measured hole remains, and it is the runtime's, not a reconstruction gap: with `ocsf_json_enabled` set exactly as the vendor documents, the runtime's **OCSF-JSON export produced zero records in both live runs**, so the native JSON stream still has nothing to ingest — and the documented supervisor file sink sits on a tmpfs that the vendor's own docs say external tools cannot read. Closing that hole is the boundary recorder's reason to exist. The Claude Code hook path is exercised through the real hook protocol (JSON on stdin, decision JSON on stdout) via subprocess; a live interactive Claude Code session is still pending the owner's Anthropic authentication.

## How it compares — honestly

| | Seatbelt | OpenShell (NVIDIA) | nono | Infisical Agent Vault |
|---|---|---|---|---|
| What it is | Policy + evidence layer above runtimes | Sandbox runtime | Sandbox with tamper-evident audit | Credential broker (commercial, Preview) |
| Runtime-neutral | **Yes** — one ledger across runtimes | No — its own sandbox | No — its own sandbox | Partial — HTTP(S) proxy only |
| Records denied actions | **Yes, by contract, with coverage checks** | Shorthand event exists natively, but the documented OCSF-JSON export measured **0 records** on 0.1.5 — nothing reaches an outside ledger | Yes, inside its sandbox | Audit log for brokered calls |
| Coverage is verified | **Yes** — expected ↔ observed reconciliation, run fails on a gap | No equivalent published | No equivalent published | No |
| Credential grants | Per run + per action, in the same ledger | Injected at egress inside its sandbox | n/a | Per service bundle |
| Isolation / sandboxing | **None — by design** | **Yes, strong, independently evaluated** | Yes | No |

**Where rivals beat us:** OpenShell and nono provide the actual isolation — Seatbelt has none and never will; if you need a sandbox, run one of theirs *under* Seatbelt. nono shipped hash-chained agent audit before us (inside its sandbox). Agent Vault is a polished commercial product with support. Seatbelt's claim is narrower and, we believe, unoccupied: unifying policy, evidence, credential grants, and *verified coverage* on one neutral layer.

## Layout

```
src/seatbelt/     daemon, PDP client, ledger, broker, proxies, verifier
policies/         the Rego policy pack v1 + data (see policies/README.md)
adapters/         claude-code/ and openshell/ adapters + manifests
examples/         the ops-assistant sample workload (clean + planted)
verification/     the phase-1 acceptance harness and its measured results
docs/             architecture, threat model, demo GIF + raw capture
tests/            unit + component + concurrency tests (23 tests)
```

## Documentation

- [Architecture and trust model](docs/architecture.md)
- [Policy pack v1 — every control: what, why, how to fix](policies/README.md)
- [Claude Code adapter](adapters/claude-code/README.md) · [OpenShell adapter](adapters/openshell/README.md)
- [Sample workload](examples/ops-assistant/README.md)
- [Phase-1 acceptance results](verification/results.md) · [Release dossier](release/RELEASE-DOSSIER.md)
- [Security policy](SECURITY.md)

## Roadmap

Phase 2: an E2B adapter; sealing exports from observability tools into verifiable evidence; broker coverage for database/SSH patterns; a coverage re-measurement of OpenShell on its remaining Linux drivers (the docker driver was measured live in phase 1), published; richer alerting. Phase 3: more runtimes, public transparency anchoring, CI mode as an agent-testing gate.

## License

Apache-2.0 — see [LICENSE](LICENSE).
