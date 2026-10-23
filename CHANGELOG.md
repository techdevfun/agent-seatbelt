# Changelog

All notable changes to Agent Seatbelt are recorded here. The policy pack is versioned separately (see `POLICY_PACK_VERSION` in `src/seatbelt/__init__.py`); pack changes are called out explicitly.

## [Unreleased] — OpenShell live round + first public release, 2026-10-23

### Measured
- OpenShell live round on GitHub Actions (`.github/workflows/openshell-live.yml`): OpenShell 0.1.5-1 booted under the docker driver (sandbox Ready, real commands executed); a native shorthand DNS-denial event was captured (`NET:REFUSE … DENIED`, reason `policy_dns_ineligible`); Seatbelt-side coverage passed 13/13 against independent ground truth.
- The runtime's documented OCSF-JSON export produced **zero records in both live runs** with `ocsf_json_enabled` set per the vendor docs — native-side ingest still consumes the reconstructed phase-1 stream, now because the real export is measurably empty, not because no runtime was available. The original UDP exfiltration case could not be re-run there (the default sandbox image ships no `dig`/`curl`/`python3`).

### Released
- First public release of this repository. Gate record in the release dossier (§9–§10): quality 72/75 = 96.0/100 under the factory's feasible gate, met on measured evidence.

## [Unreleased] — local polish round, 2026-10-23

### Added
- Rendered demo GIF (`docs/demo/demo.gif`), recorded from a real interactive terminal session running the extended `docs/demo/run_demo.sh` — now a clean run followed by the planted run, coverage reconciliation, offline bundle verification, and the 1-byte tamper case. The raw session text remains in `docs/demo/typescript.txt`.
- Test line-coverage reporting: `scripts/run_tests_with_coverage.py` (standard-library `sys.monitoring` only) runs the unit suite and publishes the unit-test line coverage of `src/seatbelt` — 37.2% at this writing, per-module numbers in `verification/coverage.json` — and is wired into CI as the unit-test step. The daemon/CLI/proxy modules sit near 0% at the unit layer by design: they are exercised end to end by the acceptance harness instead.
- Concurrency tests (3): parallel ledger appends from 8 threads and checkpoints racing appends both keep the hash chain verifiably intact; 48 parallel PDP decisions against a real OPA server match the expected outcomes.

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
