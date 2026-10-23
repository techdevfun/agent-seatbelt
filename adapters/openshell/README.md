# Adapter: NVIDIA OpenShell

## How it attaches

Seatbelt does not replace OpenShell's sandbox — independently evaluated, its blocking is strong. The adapter stands at OpenShell's evidence gaps:

1. **Independent egress recorder.** The agent's HTTP traffic goes through Seatbelt's egress proxy and its DNS through Seatbelt's resolver tap, so every egress/DNS *attempt* — allowed or denied — has a Seatbelt record that does not depend on the runtime's export pipeline working.
2. **OCSF ingest.** `seatbelt ingest --format ocsf` folds OpenShell's OCSF export into the same ledger, source-tagged `openshell-ocsf`, unifying the picture the evaluation found fragmented across sandbox logs, gateway logs, rule history, and the VM console.
3. **Two-source reconciliation.** `reconcile.py` compares the two sources inside the sealed ledger for the classes both can see (egress, DNS): what matched, what the native stream is missing, and what the boundary is missing (which must be zero for manifest classes).

Plus the shared boundary points: MCP calls through the proxy interceptor, tool/file decisions through the daemon, credentials through the broker, budget through the meter.

## What the reconciliation shows (phase-1 measurement)

On the reconstructed streams (see Status), the clean run reconciles completely: both network events appear in both sources. The planted run's reconciliation reports `native_missing` = exactly one event — the blocked DNS exfiltration query, present at Seatbelt's boundary (record seq 3) and absent natively — reproducing, mechanically, the central finding of the independent OpenShell evaluation: *blocked UDP DNS left no event*. `boundary_missing` is empty in both runs.

## Guarantees and limits

Guaranteed (measured): boundary coverage reconciles to **0 missing records** against independent ground truth on both scenarios; two-source reconciliation runs over the sealed ledger and its report is machine-generated. Limits: a process that escapes the sandbox *and* avoids the proxy/tap is outside the manifest — Seatbelt claims coverage only where its boundary points are the path of egress, and says so; the runtime's own in-sandbox tool calls are visible only through Seatbelt's interceptors, not through the native stream.

## Status — read this before quoting any number

No OpenShell runtime is installed in the build environment. The OCSF stream used for ingest + reconciliation is a **faithful reconstruction** (`make_ocsf_sample.py`) from the vendor's documented OCSF observability schema and the event inventory in Sorami's independent evaluation of OpenShell v0.1.2 — including its measured gaps (no event for blocked UDP DNS; no native tool-call events). It is **not** a live capture. What is live-measured: the Seatbelt side end to end (proxy, tap, ingest, reconciliation, ledger, verifier). What is pending: running the adapter beside a real OpenShell, including the Linux-driver coverage re-measurement the blueprint schedules — the dossier records this as an open item, and no acceptance claim in this repository rests on the native side being live.
