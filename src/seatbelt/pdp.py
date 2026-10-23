"""Policy Decision Point client.

Decisions are made by OPA (Open Policy Agent) running as a local server
with the Seatbelt Rego policy pack preloaded. The PDP is deliberately
outside the agent process: the agent cannot edit, restart, or bypass it,
and no LLM sits anywhere in the decision path. Every decision is a pure
function of (action input, policy pack, run state such as budget usage),
so the same input always yields the same decision — and the decision,
the policy pack hash, and the pack version are stamped into the evidence
record the caller writes.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request


def policy_bundle_hash(policies_dir: str) -> str:
    """SHA-256 over every policy file (path + content), sorted by path."""
    h = hashlib.sha256()
    for root, _dirs, files in os.walk(policies_dir):
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, policies_dir)
            h.update(rel.encode("utf-8"))
            with open(path, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


class PDP:
    def __init__(self, opa_url: str, policies_dir: str, pack_version: str):
        self.opa_url = opa_url.rstrip("/")
        self.bundle_hash = policy_bundle_hash(policies_dir)
        self.pack_version = pack_version

    def decide(self, action: dict) -> dict:
        """Ask OPA for a decision on one action.

        Returns {"decision": "allow"|"deny"|"require-approval",
                 "reason": <stable reason code>}.
        """
        body = json.dumps({"input": action}).encode("utf-8")
        req = urllib.request.Request(
            self.opa_url + "/v1/data/seatbelt/decision",
            data=body, headers={"Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        result = payload.get("result")
        if not isinstance(result, dict) or "decision" not in result:
            # Fail closed: a PDP malfunction must never become an allow.
            return {"decision": "deny", "reason": "pdp_no_decision"}
        return {"decision": result["decision"],
                "reason": result.get("reason", "no_reason")}

    def healthy(self) -> bool:
        try:
            req = urllib.request.Request(self.opa_url + "/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status == 200
        except Exception:
            return False
