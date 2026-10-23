# Policy pack v1

The pack is data + Rego (`seatbelt.rego`, `data.json`), versioned as a unit. The PDP (OPA) loads it at daemon start; the pack's SHA-256 over all its files is stamped into every decision record, so any evidence record can be traced to the exact policy that produced it. Default posture is **deny**: anything the pack does not explicitly allow is denied with reason `no_matching_allow_rule`. Every decision is deterministic — the same action input and pack always produce the same decision and reason code.

| # | Action class | Control | Evidence record |
|---|---|---|---|
| 1 | Tool call (MCP) | Server/tool allowlist + argument constraints | `tool-decision` |
| 2 | Tool call (harness) | Same pack, harness tool names mapped by the adapter | `tool-decision` |
| 3 | Egress HTTP/TCP | Host + method allowlist, evaluated at the proxy for **every attempt** | `egress-decision` |
| 4 | DNS / UDP+TCP | Resolver allowlist (domain suffixes) at the resolver tap | `dns-event` |
| 5 | File read/write | Path scope: inside the run workspace, never credential directories | `file-event` |
| 6 | Credential | Grant per run + action (service, host, method, path prefix); raw reads always refused | `credential-issuance` / `credential-refusal` |
| 7 | Budget | Per-run token/cost caps evaluated at each meter event | `budget-event`, `run-halt` |
| 8 | Approval | Actions on the approval list return `require-approval`; unattended runs block and record | `approval-decision` |
| 9 | Lifecycle + integrity | Coverage manifest, checkpoints, anchor | `run-start` / `run-end` / `coverage-report` / `checkpoint` |

## The controls — what, why, and how to fix a violation

**Tool allowlist (`tool_not_allowlisted`, `mcp_tool_not_allowlisted`).**
What: only tools on the allowlist may run; MCP tools are allowlisted per server. Why: an agent's tool surface is its blast radius; a tool that exists on a server is not a tool the agent was granted. Fix: add the tool to `data.json` (`tools.allowlist` / `tools.mcp_allowlist`) if the grant is intended — or treat the attempt as an incident: the record shows which policy hash decided.

**Shell command policy (`shell_command_denied`).**
What: shell commands must match an allowed prefix and contain no denied substring (destructive commands, credential paths, network tools that would bypass the egress proxy). Why: the shell is the classic escape hatch around per-tool policy. Fix: run the operation through a mediated tool (fetch through the proxy, files through the file tools) instead of a raw shell command.

**File scope (`file_outside_scope`, `file_path_denied`).**
What: file tools may only touch paths under the run workspace; credential directories (`.ssh`, `.aws`, `.gnupg`, `/etc/shadow`, `/etc/passwd`, `/proc`) are denied even inside the workspace. Why: the highest-value files on a developer machine are credential stores, and agent frameworks' own sandboxes often still read most of the home directory. Fix: move the working file into the workspace, or widen the workspace deliberately at daemon start — never by editing policy mid-run (the policy hash in earlier records would no longer match the pack).

**Egress allowlist (`egress_host_not_allowlisted`, `egress_method_not_allowlisted`).**
What: the proxy forwards only to allowlisted hosts with allowlisted methods; every attempt is recorded, including the denied ones. Why: exfiltration needs a destination; recording *attempts* (not just successes) is what makes a blocked exfiltration provable. Fix: allowlist the destination in `data.json` if the traffic is legitimate.

**DNS allowlist (`dns_name_not_allowlisted`).**
What: the resolver tap resolves only allowlisted suffixes; other queries get NXDOMAIN and a redacted record. Why: DNS is the quiet exfiltration channel — an independent evaluation of a major runtime found blocked DNS queries left no event at all; here the blocked query is the best-evidenced event in the run. Fix: allowlist the domain suffix if the lookup is legitimate. Payload-bearing labels are never written to the ledger (digest only).

**Budget caps (`budget_cap_exceeded`).**
What: each meter event is decided against the run's cumulative usage plus the new request; exceeding either the cost or token cap denies the event and seals a `run-halt` record. Why: runaway loops are a cost and safety incident class of their own, and "we stopped at the cap" should be provable, not asserted. Fix: raise the run's caps at daemon start (`--cap-cost`, `--cap-tokens`) if the workload legitimately needs more.

**Credential grants (`credential_no_grant_for_target`, `credential_raw_disclosure_forbidden`).**
What: the broker grants a credential's use only for the service, host, method, and path prefix in `data.json`; a request to *read* a raw secret value is always refused, for every service, with no configuration that enables it. Why: a secret the model can read is a secret a prompt injection can exfiltrate; a secret it can only *use* through the broker, for one action, is a bounded grant. Fix: there is no fix that exposes the value — grant a brokered use for the intended target instead.

**Approval list (`approval_required`).**
What: tools on the approval list (phase 1: `shell.deploy`) return `require-approval`. Unattended runs treat that as blocked and record an `approval-decision`. Why: some actions should have a human in the loop, and the *request* is itself evidence. Fix: run attended (interactive approval UX is a phase-2 item) or remove the action from the workload.

## Changing the pack

Edit `data.json` for lists and caps; edit `seatbelt.rego` for decision logic. Bump the pack version in `src/seatbelt/__init__.py` (`POLICY_PACK_VERSION`), note the change in `CHANGELOG.md`, and re-run `verification/run_acceptance.py` — decision changes are behavior changes and the acceptance matrix is the regression test. Control-framework mapping (reference only, **not** a compliance certification): rows 1–8 map to the logging/monitoring and access-control families of NIST CSF 2.0 (DE.CM, PR.AA), ISO/IEC 27001:2022 (A.8.15, A.8.16, A.5.17), and OWASP LLM Top 10 (LLM06 excessive agency, LLM02 sensitive information disclosure).
