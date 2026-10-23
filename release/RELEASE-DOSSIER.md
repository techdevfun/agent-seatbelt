# RELEASE DOSSIER — agent-seatbelt, phase 1 (local)

Status: **phase-1 build complete locally; NOT published.** No GitHub repository has been created — repository creation and any release action are a separate owner order at the live-measurement milestone, per the phase-1 plan. This dossier records what was built, what was measured, what is still pending, and the self-score against the factory's feasible gate.

## 1. What was built (M1–M5)

- **M1 — Frame + workload.** Repository skeleton; architecture doc; the `ops-assistant` sample workload (clean + planted) whose harness writes an independent ground-truth log of every attempted action.
- **M2 — Policy pack v1.0.0.** Rego pack + data covering all nine phase-1 mapping rows of the blueprint (tool, file, egress, DNS, credential, budget, approval, lifecycle/integrity), each with a "what / why / how to fix" doc section in `policies/README.md`. Verified against a real OPA 1.21.3: an 18-case decision matrix (allow/deny/require-approval per class) returns the designed decision and reason code for every case.
- **M3 — Enforcement points.** MCP proxy interceptor (denied calls never reach the server), Claude Code PreToolUse hook CLI, egress HTTP recorder-proxy, DNS resolver tap (UDP + TCP transports, one decision path), credential broker with response redaction, budget meter with run-halt. All decisions come from the PDP (OPA server) — deterministic, outside the agent process.
- **M4 — Evidence automation.** Hash-chained NDJSON ledger with HMAC-signed checkpoints over Merkle roots and an anchor file outside the ledger directory; OCSF + OTEL ingest into the same ledger; coverage accountant reconciling against independent ground truth; one-command offline verifier (chain, signatures, anchor, secret scan, coverage).
- **M5 — Adapters + acceptance + dossier.** Claude Code and OpenShell adapter packages with published coverage manifests; OpenShell two-source reconciliation tool; full acceptance run; golden path; raw demo capture; risk sweep (`release/risk-sweep.md`).

## 2. Acceptance criteria — measured results

Source: `verification/results.json` / `results.md` (final run 2026-10-23, wall 26.5 s, **all checks pass**), `verification/golden-path.json`, unit suite 20/20 (`python3 -m unittest discover -s tests`).

| # | Criterion | Result |
|---|---|---|
| 1 | **0 actions without a record**, mechanically reconciled vs independent ground truth, both adapters × both scenarios | **PASS** — claude-code clean 11/11, planted 13/13; openshell clean 11/11, planted 13/13; missing = 0 everywhere |
| 2 | V1–V5 blocked **and** recorded; clean variant 0 false blocks | **PASS** — planted: V1 DNS denied + redacted record (seq 3), V2 shell + MCP denied pre-execution, V3 denied exactly at the cap + `run-halt`, V4 file denied, V5 two `credential-refusal` records; legitimate interleaved actions (incl. a legitimate broker use) allowed; clean: 0 blocked steps, 0 deny records |
| 3 | V6 verifier: 1-byte tamper FAILs naming the exact record; intact bundle PASSes | **PASS** — tampered record seq 3 → verifier `first_bad_seq: 3` ("record hash does not recompute"); all four intact bundles verify (chain + 3 checkpoints + anchor + secret scan + coverage) |
| 4 | Decision latency p95 ≤ 50 ms (policy preloaded), median of 3 probe runs | **PASS** — probe rounds p95 = 31.2 / 27.5 / 26.2 ms (n=200 each), **median p95 = 27.5 ms**; across the acceptance runs themselves: n=28, p50 15.5 ms, p95 28.1 ms |
| 5 | Golden path ≤ 30 min, first try, from the README | **PASS** — **1.7 s** total, following the documented quickstart commands verbatim (`verification/golden_path.py`) |
| 6 | Docs: per-policy explanations, per-adapter manifests, README with raw demo + honest comparison, all-English sweep | **PASS** — raw terminal capture of a real planted run in `docs/demo/typescript.txt`; scripted sweep: 0 Vietnamese-diacritic lines, 0 internal names; gitleaks: no leaks |

**OpenShell two-source reconciliation** (over the sealed ledgers): clean run — matched 2/2 network events, native missing 0, boundary missing 0. Planted run — `native_missing` = exactly 1 event: the blocked DNS exfiltration attempt, present at Seatbelt's boundary (seq 3) and absent from the native stream; `boundary_missing` = 0.

**Notable acceptance incident (kept, not hidden):** the first acceptance run FAILED coverage on the OpenShell clean run — the sample harness's high-level HTTP client silently bypassed the egress proxy for a `no_proxy`-listed host, so one fetch had no record. The coverage accountant caught a real silent-bypass bug in our own harness; the harness now speaks to the proxy explicitly, and the incident is documented in the harness source. This is the coverage mechanism working as designed, and it is the strongest single piece of evidence in this dossier.

## 3. Live-measured vs pending — stated plainly

| Item | Status |
|---|---|
| OPA decisions, daemon, MCP proxy, hook CLI (real subprocess, real hook protocol), egress proxy, DNS tap decision path, broker, ledger, accountant, verifier | **Live-measured** end to end in this VM |
| DNS tap UDP transport | Implemented; loopback UDP is blocked by this VM's sandbox (bare-socket `PermissionError` reproduced), so acceptance exercised the identical decision path over the tap's TCP transport. UDP live re-measurement pending an unrestricted host |
| OpenShell native OCSF stream | **Reconstructed, not captured** — no OpenShell in the build environment; sample built from the vendor's documented schema + the Sorami evaluation's measured event inventory, gaps included, and labeled as reconstructed everywhere it is used |
| Interactive Claude Code session | **Pending** — the adapter is exercised through the real hook executable and protocol; no live session was run |
| GitHub CI, public repo display, dev.to, landing | **Not started** — repository creation is a separate owner order |

## 4. Blueprint risk register outcomes

- **R1 (scope):** the narrowing condition did **not** trigger — two-source reconciliation for the OpenShell adapter was achieved on the Seatbelt side (ingest + independent recorder + reconciliation over the sealed ledger). Phase 1 kept both adapters. The live-capture half of EP-3 remains pending per §3, which is an environment limit, not a reconciliation failure.
- **R3 (latency):** inside budget with headroom; no synchronous-scope narrowing needed.
- **R4 (no runtime):** no isolation code exists in the tree.
- **R5 (competitor movement):** no change observed during the build window; the verification-first fallback remains on record.
- **R6/R7:** limits are published next to the claims (adapter manifests, architecture doc, SECURITY.md).

## 5. Self-score against the factory rubric + FEASIBLE GATE

Quality boards (feasible gate: quality ≥ 95/100 **and** floors HM1 ≥ 18/20, HM2 ≥ 18/20, HM3 ≥ 13.5/15, HM4 ≥ 13.5/15, HM7 = 5/5):

| Board | Score | Basis |
|---|---|---|
| HM1 Pain & differentiation | **18/20** | Sourced, measured pain (independent evaluation's evidence gaps); wedge = verified coverage on a neutral cross-runtime layer. −2: no external user validation yet (the standing factory deduction) |
| HM2 Runs for real & e2e | **18/20** | Every phase-1 acceptance criterion measured on real processes, both adapters × both scenarios. −2: live OpenShell capture and a live Claude Code session still pending (§3) |
| HM3 Code & test quality | **13.5/15** | Stdlib-only, single-writer design, 20 unit/component tests incl. real-OPA decisions, acceptance harness as regression. −1.5: no CI run yet (no repo), no coverage-% metric, daemon concurrency lightly tested |
| HM4 Demo + README | **14/15** | Clean English hero, who-hurts, raw real-run capture, honest comparison, machine-verified quickstart; language/internal-name sweep passes. −1: demo is a raw text capture, no rendered GIF/video asset yet |
| HM7 Safety & compliance | **5/5** | gitleaks clean; Apache-2.0 LICENSE; no secrets (fake canaries labeled); risk sweep done; claims discipline documented |
| **QUALITY total** | **68.5/75 = 91.3/100** | All five per-board floors met; the ≥95 gate itself **not yet met** |

Distribution boards (tracked separately; completed *by* release actions): HM5 0/15, HM6 0/10 — no repository, landing, or article exists yet, by the owner's sequencing.

The 5 hard conditions all pass: working end-to-end code with a green e2e; no secrets; no copyright violations (all code original to this project); LICENSE present (Apache-2.0); no fake engagement of any kind.

**Gate conclusion, stated plainly:** phase 1's build scope is complete and every acceptance criterion in the plan is measured PASS, but the feasible gate's quality bar (≥95/100) is **not** met at this local ceiling — 91.3/100 with all floors green. The remaining 3.7 points are itemized and locked behind owner-ordered stages, not behind more local code: live-environment measurement (HM2 +2: real OpenShell capture + live Claude Code session), external user validation (HM1 +2), a rendered demo asset (HM4 +1), and CI on the created repository (HM3). **Do not publish from this dossier.** The next step is the owner's live-measurement milestone decision — the same pattern flagship #2 followed from its local ceiling to its release.

## 6. Waiting on the owner

1. Order to create the GitHub repository `agent-seatbelt` (private-first for live measurement, per the flagship #2 precedent) — or keep the tree local.
2. Live-measurement milestone: a host with a real OpenShell (Linux driver) and an interactive Claude Code session, plus a loopback-UDP-unrestricted environment for the tap's UDP path.
3. After live measurement closes the HM2 gap and the gate is re-scored ≥95 with floors green: the release package (public flip, techdev.fun landing card, dev.to article with the honest comparison) as a separate approval.
