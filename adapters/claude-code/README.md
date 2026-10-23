# Adapter: Claude Code

## How it attaches

Claude Code invokes hooks as external commands — and hooks run **outside** its sandbox, which is exactly where a policy boundary belongs. The adapter is the `seatbelt hook` executable registered as a `PreToolUse` hook (see `settings-snippet.json`):

- `Bash` → policy class *tool* (`shell.run`)
- `Read` / `Write` / `Edit` → policy class *file*, scoped to the run workspace
- `WebFetch` → policy class *tool* (`http.fetch`)
- `mcp__<server>__<tool>` → policy class *tool* (`mcp.call`), per-server allowlist
- anything else → the pack's default: deny

The hook receives the event JSON on stdin and answers with the documented decision JSON on stdout (`permissionDecision: allow|deny` + reason). The daemon it calls holds the ledger; the hook itself is stateless.

Two more boundary points complete the manifest: the agent host's resolver of record is the Seatbelt DNS tap, and credential use / budget metering go through the daemon's broker and meter endpoints (in the sample harness these are driven by the workload; in a Claude Code deployment they attach through MCP tooling and OTEL usage events respectively).

## Native signals

Claude Code's documented audit source is OpenTelemetry events. `seatbelt ingest --format otel` folds an OTEL log export into the same ledger as source `claude-code-otel` — supplementary evidence and a cross-check, never the coverage basis: OTEL content is opt-in, truncated by the vendor, and mutable at the receiving backend, which is the gap this adapter exists to close.

## Guarantees and limits

Guaranteed (measured in phase-1 acceptance): every tool call the harness routes through the hook is decided before it runs and recorded either way; DNS through the tap is recorded either way; broker grants/refusals and budget events are recorded; coverage is reconciled against independent ground truth with **0 missing records** on both sample scenarios.

Limits, stated next to the claim: actions a user takes outside the harness are out of scope; a developer who can edit the hook registration can remove the boundary (managed settings are the vendor's mitigation, and the absence of records is itself detectable by the coverage accountant when a run is expected); network egress performed *inside* an allowed shell command is governed by the shell command policy, not the egress proxy — the manifest does not claim the proxy class for this adapter.

## Status

Hook protocol exercised end-to-end via subprocess against the real daemon in `verification/run_acceptance.py` (clean + planted, all checks pass). A live interactive Claude Code session has not been run in the build environment; the OTEL sample in this repository is reconstructed from the vendor's documented monitoring schema and labeled as such (`make_otel_sample.py`).
