# Changelog

All notable changes to Agent Seatbelt are recorded here. The policy pack is versioned separately (see `POLICY_PACK_VERSION` in `src/seatbelt/__init__.py`); pack changes are called out explicitly.

## [0.1.0] — 2026-10-23 — Phase 1

Initial phase-1 build (local; not yet published — repository creation and release are a separate maintainer decision).

### Added
- Evidence ledger: append-only NDJSON with a SHA-256 hash chain, HMAC-signed checkpoints over Merkle roots, an anchor file outside the ledger directory, and resume support for post-run appends (ingest, coverage).
- Policy Decision Point: OPA server integration; deterministic decisions; fail-closed on PDP malfunction; the policy pack hash is stamped into every decision record.
- Policy pack v1.0.0: tool allowlists (incl. per-server MCP allowlists and a shell command policy), file path scope with credential-directory denies, egress host/method allowlist, DNS suffix allowlist, per-run budget caps, credential grants per run + action with raw-read always refused, an approval list (`require-approval`), and a default-deny posture.
- Enforcement points: MCP proxy interceptor (denied calls never reach the server), Claude Code PreToolUse hook CLI, egress HTTP recorder-proxy, DNS resolver tap on UDP and TCP transports (identical decision path; denied names recorded redacted by digest), credential broker with response redaction, budget meter with run-halt.
- Runtime-signal ingest for OCSF (OpenShell) and OTEL (Claude Code) exports into the same ledger, source-tagged.
- Coverage accountant: mechanical reconciliation of the ledger against independent harness ground truth; seals a coverage-report record; a run with a missing record reports FAIL.
- One-command offline verifier: chain integrity (names the first bad record), checkpoint signature + anchor verification, whole-bundle secret scan, optional coverage re-reconciliation.
- Adapters: Claude Code (hooks + tap + broker/meter; OTEL ingest) and OpenShell (decision API + MCP proxy + egress recorder + OCSF ingest + two-source reconciliation), each with a published coverage manifest.
- Sample workload `ops-assistant` (clean + planted scenarios, five planted violations) with an independent ground-truth log.
- Phase-1 acceptance harness (`verification/run_acceptance.py`) with measured results in `verification/results.md`: all checks pass on both adapters and both scenarios; decision latency probe median p95 22.5 ms against a 50 ms budget; the 1-byte tamper case fails verification at exactly the tampered record.

### Known limits recorded at release of this version
- No live OpenShell or interactive Claude Code session exists in the build environment: native-side streams are faithful reconstructions from the vendors' documented schemas (see the adapters' READMEs and the release dossier). The Seatbelt side is measured end to end.
- Loopback UDP is blocked in the build VM's sandbox, so the acceptance runs exercised the DNS tap over its TCP transport; the UDP transport shares the same decision path and is unit-covered at the message level.
