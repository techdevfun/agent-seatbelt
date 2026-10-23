# Pre-release risk sweep — agent-seatbelt phase 1 (2026-10-23)

Performed locally before the phase-1 dossier (STANDING RULE 5). No GitHub repository exists yet; publishing is a separate owner decision, and this sweep must be re-run against the final tree at that point.

## Secrets and tree hygiene
- `gitleaks detect` over the whole tree: **no leaks found** (~832 KB scanned). The only credential-shaped strings in the product are the documented **fake** demo canary (`DEMO-SECRET-billing-9c1f`) and the exfiltration canary (`CANARY-SECRET-7f3a9d2e`), both labeled as fake wherever they appear; real operator keys are generated outside the tree at runtime and `operator-key.txt` / `*.key` are gitignored.
- Acceptance work directories (`verification/work/`) are gitignored; demo and golden-path state live under `/tmp`, never in the tree.

## Language and internal-name sweep (STANDING RULE 7)
- Scripted scan of every text file in the tree: **0 lines** with Vietnamese diacritics; **0 hits** for internal names/identifiers (owner name, company names/domains, internal project codenames). All product content — code, comments, policy messages, docs, README — is English from the first line.

## Claim discipline
- No performance or coverage claim appears in public docs without a measurement behind it in `verification/results.md` or an adapter README.
- The OpenShell adapter's native side was labeled **reconstructed, not captured** in the adapter README, the sample generator's docstring, the CHANGELOG, and the dossier. After the 2026-10-23 live round (dossier §9) the labels were updated to the measured state: live boot under the docker driver and a native shorthand denial event verified; the documented OCSF-JSON export measured empty (0 records in both runs), so the local ingest stream remains the reconstruction — for a measured reason. The one remaining pending live item (an interactive Claude Code session) is recorded in the dossier.
- Competitor statements in the README comparison trace to the blueprint's sourced scan (vendor docs + the Sorami independent evaluation); "where rivals beat us" is stated in the README itself.
- Compliance-framework mentions are labeled "reference only, not a certification" in `policies/README.md`.

## Product risks reviewed (blueprint §7)
- R1 scope creep: phase 1 stayed frozen at 2 adapters + the manifest classes; two-source reconciliation was achieved on the Seatbelt side, so the narrowing condition did not trigger. Recorded in the dossier.
- R3 latency: measured probe median p95 is inside the 50 ms budget (see results); no synchronous-scope narrowing was needed.
- R4 no-runtime rule: no isolation/sandbox code exists in the tree.
- R6 coverage overclaiming: manifests publish limits next to guarantees; the one real bypass found during acceptance (a high-level HTTP client silently skipping the proxy due to `no_proxy`) was caught by the coverage accountant, fixed in the harness, and is documented in `examples/ops-assistant/agent.py` and the dossier — the mechanism working as designed.
- R7 broker as a high-value target: phase-1 broker is in-memory, per-run grants, no long-term secret storage; threat model and the KMS/HSM roadmap are documented in `docs/architecture.md` and `SECURITY.md`.

## Residual risks accepted for phase 1 (documented, not hidden)
- Loopback UDP is blocked in the build VM: the DNS tap's UDP transport is implemented and message-level tested, but the live acceptance exercised the identical decision path over DNS-over-TCP. Re-measure on an unrestricted host before release claims about the UDP path.
- Checkpoint signing is HMAC with a local operator key (documented limit; KMS/HSM is phase 3).

## Re-run at release (2026-10-23)

The Standing Rule 7 sweep was re-run against the final tree before the public flip: 0 Vietnamese-diacritic lines and 0 internal-name hits (word-boundary scan) across all public text files; the release scans job (sweep + gitleaks) runs in CI on the release commit. The live-round facts were folded into the README, the OpenShell adapter README, the coverage manifest, the CHANGELOG, and the dossier before the flip — no public text still describes the native side as merely "pending a host".
