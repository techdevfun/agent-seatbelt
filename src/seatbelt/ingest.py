"""Runtime-signal ingest (component 6).

Native signals from a runtime (OpenShell's OCSF export, Claude Code's
OpenTelemetry events) are normalized into the same evidence ledger,
tagged with their source. They are *supplementary*: the coverage
guarantee rests on Seatbelt's own boundary records, because a native
stream can be silently incomplete — an independent evaluation of
OpenShell found its OCSF JSON export writing nothing at all in the
tested configuration while blocked DNS queries produced no event.
Ingest exists so the two sources can be reconciled against each other
(see adapters/openshell/reconcile.py).
"""

from __future__ import annotations

import json

from .ledger import Ledger

OCSF_CLASS_TO_ACTION_CLASS = {
    1001: "file",       # File System Activity
    1007: "lifecycle",  # Process Activity
    4001: "egress",     # Network Activity
    4003: "dns",        # DNS Activity
}

OCSF_DISPOSITION = {1: "allow", 2: "deny", 0: "unknown"}


def normalize_ocsf(event: dict) -> dict:
    action_class = OCSF_CLASS_TO_ACTION_CLASS.get(
        event.get("class_uid"), "native")
    subject = {"native_source": "openshell-ocsf"}
    if action_class == "egress":
        dst = event.get("dst_endpoint", {})
        subject.update({"host": dst.get("ip") or dst.get("hostname"),
                        "port": dst.get("port")})
    elif action_class == "dns":
        subject.update({"qname": (event.get("dns_query") or {}).get("name")})
    elif action_class == "file":
        subject.update({"path": (event.get("file") or {}).get("path")})
    elif action_class == "lifecycle":
        subject.update({"process": (event.get("process") or {}).get("name")})
    decision = OCSF_DISPOSITION.get(event.get("disposition_id"))
    return {"kind": "native-signal", "class": action_class,
            "subject": subject, "decision": decision,
            "reason": "native_disposition",
            "source": "openshell-ocsf"}


def normalize_otel(record: dict) -> dict:
    attrs = record.get("attributes", {})
    body = record.get("body", "")
    if "tool" in str(body):
        return {"kind": "native-signal", "class": "tool",
                "subject": {"native_source": "claude-code-otel",
                            "tool": attrs.get("tool_name")},
                "decision": attrs.get("decision"),
                "reason": "native_otel_event",
                "source": "claude-code-otel"}
    return {"kind": "native-signal", "class": "budget",
            "subject": {"native_source": "claude-code-otel",
                        "cost_usd": attrs.get("cost_usd"),
                        "tokens": attrs.get("tokens")},
            "decision": None, "reason": "native_otel_event",
            "source": "claude-code-otel"}


def ingest_file(ledger: Ledger, path: str, fmt: str) -> int:
    count = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            norm = normalize_ocsf(raw) if fmt == "ocsf" \
                else normalize_otel(raw)
            ledger.append(norm["kind"], norm["class"], norm["subject"],
                          decision=norm["decision"], reason=norm["reason"],
                          source=norm["source"], enforcement="native")
            count += 1
    return count
