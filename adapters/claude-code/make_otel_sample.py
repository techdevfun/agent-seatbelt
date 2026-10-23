#!/usr/bin/env python3
"""Generate a reconstructed Claude Code OpenTelemetry log export for a
sample run.

Claude Code's documented audit source is OpenTelemetry events exported
over OTLP (tool decisions/results and API request usage). No Claude
Code session runs in the build environment, so — exactly as with the
OpenShell sample — this file is a faithful reconstruction from the
vendor's documented monitoring schema, used to prove the ingest path
and the single-ledger property. It is never presented as a capture
from a live Claude Code session; the dossier records that status.
"""

import argparse
import json
import time

BASE = int(time.time() * 1000)


def rec(body, attrs):
    return {"body": body, "timestamp": BASE, "attributes": attrs}


def clean_events():
    return [
        rec("claude_code.tool_decision",
            {"tool_name": "Read", "decision": "accept"}),
        rec("claude_code.tool_decision",
            {"tool_name": "Bash", "decision": "accept"}),
        rec("claude_code.api_request",
            {"cost_usd": 0.05, "tokens": 500}),
        rec("claude_code.tool_decision",
            {"tool_name": "Write", "decision": "accept"}),
    ]


def planted_events():
    return [
        rec("claude_code.tool_decision",
            {"tool_name": "Read", "decision": "accept"}),
        rec("claude_code.tool_decision",
            {"tool_name": "Bash", "decision": "accept"}),
        rec("claude_code.api_request",
            {"cost_usd": 0.40, "tokens": 4000}),
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["clean", "planted"],
                        required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    events = clean_events() if args.scenario == "clean" \
        else planted_events()
    with open(args.out, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    print(json.dumps({"wrote": len(events), "out": args.out}))


if __name__ == "__main__":
    main()
