# Adapter: NVIDIA OpenShell

## How it attaches

Seatbelt does not replace OpenShell's sandbox — independently evaluated, its blocking is strong. The adapter stands at OpenShell's evidence gaps:

1. **Independent egress recorder.** The agent's HTTP traffic goes through Seatbelt's egress proxy and its DNS through Seatbelt's resolver tap, so every egress/DNS *attempt* — allowed or denied — has a Seatbelt record that does not depend on the runtime's export pipeline working.
2. **OCSF ingest.** `seatbelt ingest --format ocsf` folds OpenShell's OCSF export into the same ledger, source-tagged `openshell-ocsf`, unifying the picture the evaluation found fragmented across sandbox logs, gateway logs, rule history, and the VM console.
3. **Two-source reconciliation.** `reconcile.py` compares the two sources inside the sealed ledger for the classes both can see (egress, DNS): what matched, what the native stream is missing, and what the boundary is missing (which must be zero for manifest classes).

Plus the shared boundary points: MCP calls through the proxy interceptor, tool/file decisions through the daemon, credentials through the broker, budget through the meter.

## What the reconciliation shows (phase-1 measurement)

On the phase-1 reconciliation streams (a faithful reconstruction — see Status), the clean run reconciles completely: both network events appear in both sources. The planted run's reconciliation reports `native_missing` = exactly one event — the blocked DNS exfiltration query, present at Seatbelt's boundary (record seq 3) and absent natively — reproducing, mechanically, the central finding of the independent OpenShell evaluation: *blocked UDP DNS left no event*. `boundary_missing` is empty in both runs.

## Guarantees and limits

Guaranteed (measured): boundary coverage reconciles to **0 missing records** against independent ground truth on both scenarios; two-source reconciliation runs over the sealed ledger and its report is machine-generated. Limits: a process that escapes the sandbox *and* avoids the proxy/tap is outside the manifest — Seatbelt claims coverage only where its boundary points are the path of egress, and says so; the runtime's own in-sandbox tool calls are visible only through Seatbelt's interceptors, not through the native stream.

## Status — read this before quoting any number

A live OpenShell has now been run. On a GitHub Actions runner, OpenShell 0.1.5-1 booted under its docker driver (sandbox Ready, real commands executed), driven by `.github/workflows/openshell-live.yml`; the run evidence is archived as a CI artifact and recorded in the release dossier. Measured on the real runtime:

- A native shorthand event for a denied DNS lookup exists (`NET:REFUSE … DENIED`, reason `policy_dns_ineligible`) — the supervisor does see the denial and logs it in shorthand form.
- The documented **OCSF-JSON export produced zero records in both live runs**, with `ocsf_json_enabled` set exactly per the vendor's documentation. Per those same docs, the supervisor's file sink lives on a tmpfs that external tooling cannot read, so the export could not be inspected out of band either. Native-side ingest therefore still has no real stream to consume, and two-source reconciliation against the native JSON degenerates to the boundary side alone — now a *measured* property of the vendor's current build, not an artifact of our test environment.
- Seatbelt-side coverage on the runner reconciled **13/13** against independent ground truth.
- The original independent-evaluation case (blocked UDP DNS exfiltration) could not be re-run on the runner: the default sandbox image ships no `dig`, `curl`, or `python3`.

The OCSF stream used for the local ingest + reconciliation acceptance remains a **faithful reconstruction** (`make_ocsf_sample.py`) from the vendor's documented OCSF observability schema and the event inventory in Sorami's independent evaluation of OpenShell v0.1.2 — because the real runtime exported nothing to capture. What is live-measured: the Seatbelt side end to end (proxy, tap, ingest, reconciliation, ledger, verifier), plus the live facts above. No acceptance claim in this repository rests on the native JSON stream being available.
