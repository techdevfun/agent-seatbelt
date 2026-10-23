"""Claude Code hook adapter (EP-2): a PreToolUse hook executable.

Claude Code invokes hooks as external commands: the hook event arrives
as JSON on stdin, and the hook answers with a JSON decision on stdout.
Hooks run outside the Claude Code sandbox — which is exactly where a
policy boundary belongs.

Mapping (harness tool -> Seatbelt decision):
  Bash                -> class "tool", tool "shell.run"
  Write / Edit        -> class "file", op "write"
  Read                -> class "file", op "read"
  mcp__<srv>__<tool>  -> class "tool", tool "mcp.call"

The payload may carry two Seatbelt fields the harness's own tooling
adds: "seatbelt_action_id" (correlation id for coverage accounting)
and "seatbelt_workspace" (the run's file scope root). Unknown tools are
decided by the policy pack's default: deny.
"""

from __future__ import annotations

import json
import os
import sys

from .client import Client


def map_event(event: dict, workspace: str) -> tuple[dict, dict]:
    """Return (PDP action, ledger subject) for a hook event."""
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        return ({"class": "tool", "tool": "shell.run", "command": command},
                {"tool": "shell.run", "command": command})
    if tool_name in ("Write", "Edit", "Read"):
        path = tool_input.get("file_path", "")
        op = "read" if tool_name == "Read" else "write"
        return ({"class": "file", "op": op, "path": path,
                 "workspace": workspace},
                {"tool": "file." + op, "path": path})
    if tool_name == "WebFetch":
        from urllib.parse import urlparse
        url = tool_input.get("url", "")
        host = urlparse(url).hostname or ""
        return ({"class": "tool", "tool": "http.fetch", "host": host},
                {"tool": "http.fetch", "url": url})
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        server = parts[1] if len(parts) > 1 else ""
        mcp_tool = parts[2] if len(parts) > 2 else ""
        return ({"class": "tool", "tool": "mcp.call",
                 "mcp_server": server, "mcp_tool": mcp_tool},
                {"tool": "mcp.call", "mcp_server": server,
                 "mcp_tool": mcp_tool})
    return ({"class": "tool", "tool": "harness." + tool_name},
            {"tool": tool_name})


def main(argv=None) -> int:
    state_file = os.environ.get("SEATBELT_STATE_FILE", "")
    raw = sys.stdin.read()
    event = json.loads(raw) if raw.strip() else {}
    with open(state_file, encoding="utf-8") as fh:
        state = json.load(fh)
    workspace = event.get("seatbelt_workspace") or os.environ.get(
        "SEATBELT_WORKSPACE", "")
    action, subject = map_event(event, workspace)
    client = Client(state["api_url"])
    out = client.decide(action, event.get("seatbelt_action_id"), subject)
    decision = out["decision"]
    permission = "deny" if decision != "allow" else "allow"
    answer = {
        "hookSpecificOutput": {
            "hookEventName": event.get("hook_event_name", "PreToolUse"),
            "permissionDecision": permission,
            "permissionDecisionReason":
                "seatbelt policy: %s (%s)" % (decision, out["reason"]),
        }
    }
    sys.stdout.write(json.dumps(answer) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
