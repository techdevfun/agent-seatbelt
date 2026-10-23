# Architecture and trust model

## Components

| # | Component | Code | Role |
|---|---|---|---|
| 1 | Tool-call interceptor | `src/seatbelt/mcp_proxy.py` | MCP proxy: every `tools/call` is decided before it reaches the server; denials never reach the server |
| 2 | Harness hook adapter | `src/seatbelt/hook.py` | Claude Code PreToolUse hook executable (JSON in on stdin, decision JSON on stdout) |
| 3 | Egress recorder-proxy | `src/seatbelt/serve.py` | HTTP forward proxy + DNS resolver tap (UDP and TCP transports); records **every attempt**, allowed or denied |
| 4 | Policy Decision Point | `src/seatbelt/pdp.py` + `policies/` | OPA server with the Rego pack preloaded; deterministic; outside the agent process |
| 5 | Credential broker | `src/seatbelt/serve.py` | Per-run + per-action grants for HTTP and MCP-surfaced APIs; injects the credential into the brokered request; returns a redacted result |
| 6 | Evidence ledger | `src/seatbelt/ledger.py` | Append-only NDJSON, hash chain, signed checkpoints, external anchor |
| 7 | Runtime-signal ingest | `src/seatbelt/ingest.py` | Normalizes OCSF / OTEL native signals into the same ledger, source-tagged |
| 8 | Coverage accountant | `src/seatbelt/coverage.py` | Expected ↔ observed reconciliation against independent ground truth; seals a coverage-report record |
| 9 | Verifier CLI | `src/seatbelt/verify.py` | One-command, offline: chain, checkpoint signatures, anchor, secret scan, coverage |

The daemon (`seatbelt serve`) hosts components 3–6 in one process so the ledger has a single writer. The PDP is a separate OPA process. The agent talks to the daemon; it never writes to the ledger and holds no keys.

## Evidence record

Each NDJSON line is one record:

| Field | Meaning |
|---|---|
| `seq` | Monotonic sequence number within the run |
| `ts` | UTC timestamp (millisecond precision) |
| `run_id`, `agent`, `adapter` | Run identity |
| `source` | `seatbelt` for boundary records, or the native source tag for ingested signals |
| `class` | Action class: tool, file, egress, dns, credential, budget, approval, lifecycle, integrity, native |
| `kind` | Record kind: `tool-decision`, `file-event`, `egress-decision`, `dns-event`, `credential-issuance`, `credential-refusal`, `budget-event`, `run-halt`, `approval-decision`, `run-start`, `run-end`, `coverage-report`, `checkpoint`, `native-signal` |
| `action_id` | Correlation id supplied by the harness (absent for DNS, which is matched by name digest) |
| `decision`, `reason` | The PDP outcome and its stable reason code |
| `enforcement` | `enforce` for boundary records, `native` for ingested signals |
| `policy_hash`, `policy_version` | Hash of the exact policy pack that decided, and its version |
| `subject` | Digests and identifiers of the action — never raw secret values |
| `prev_hash`, `hash` | The chain: `hash = SHA-256(prev_hash ‖ canonical_json(record without hash))` |

## Tamper evidence: three layers, honestly bounded

1. **Hash chain** — detects edits to record contents or order inside the ledger.
2. **Signed checkpoints** — every checkpoint seals the Merkle root of all records so far with an HMAC-SHA-256 signature under an operator key stored outside the repository tree and outside the ledger directory.
3. **External anchor** — each checkpoint's root + signature is appended to an anchor file in a separate directory the agent's file scope cannot reach.

No single layer is called "absolutely immutable": an operator holding the key can re-sign a rewritten history, which is why the anchor should live on infrastructure the operator of the *ledger* cannot rewrite (a git remote, WORM storage, or a transparency log — the public-transparency anchor is a phase-3 item). What the three layers guarantee is that *silent* edits — by the agent, by the runtime, or by accident — are detected, and the verifier names the first bad record.

## Redaction rules

- Credential values exist only in the broker process's memory (loaded from the operator's environment). Brokered responses are redacted before the agent sees them.
- The ledger records grants and refusals (service, host, method, path) — never values.
- A **denied** DNS query name is recorded redacted: registrable suffix plus `SHA-256(full name)`, because an exfiltration attempt encodes its payload in the name itself. Allowed names are recorded in full. Reconciliation matches denied names by digest.
- The verifier scans a finished bundle for the operator's known secret values and fails if any appear anywhere.

## Threat model (summary)

In scope: a prompt-injected or malfunctioning agent attempting actions outside its policy (data exfiltration over DNS, forbidden tools, budget exhaustion, out-of-scope file writes, credential misuse); a runtime whose native audit stream silently drops events; after-the-fact edits to evidence.

Out of scope, by design: sandbox escape and isolation (Seatbelt is not a sandbox — pair it with one); a compromised Seatbelt daemon host or a stolen operator signing key (the broker's own threat model and KMS/HSM-backed signing are documented limits — see the blueprint risks R6/R7); covert channels outside an adapter's published coverage manifest. Coverage claims apply **only** inside the manifest, and each adapter's documentation lists its limits next to the claim.
