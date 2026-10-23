# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers before any public disclosure. Do not open a public issue for a security report. Include the affected component, a minimal reproduction, and the impact you believe it has; you can expect an acknowledgement and a fix-or-explanation in return.

## Security model in one page

- Policy decisions are deterministic (OPA/Rego) and made **outside** the agent process. There is no LLM in the decision path.
- Evidence integrity rests on three layers — hash chain, HMAC-signed checkpoints (operator key held outside the repository and the ledger directory), and a Merkle-root anchor written outside the ledger directory. The properties and their limits are documented in `docs/architecture.md`. No layer is claimed to be "absolutely immutable."
- Secrets are held only in the credential broker's process memory, loaded from the operator's environment. They are never written to the ledger, never returned to the agent, and brokered responses are redacted before the agent sees them. The verifier scans finished bundles for known secret values.
- The demo credential used by the sample workload (`DEMO-SECRET-billing-9c1f`) is a fake canary value, not a real credential; it exists so the redaction and secret-scan behavior can be measured.

## Known limits (phase 1)

- Checkpoint signing is HMAC with a local operator key; KMS/HSM-backed signing is a roadmap item. An operator holding the key can re-sign a rewritten history — the external anchor should live on infrastructure the ledger operator cannot rewrite (see `docs/architecture.md`).
- Coverage claims apply only inside each adapter's published coverage manifest. Actions outside the manifest are documented limits, not silent gaps.
- The broker in phase 1 is a single-process, in-memory design for single-operator use; it does not claim multi-tenant hardening.
