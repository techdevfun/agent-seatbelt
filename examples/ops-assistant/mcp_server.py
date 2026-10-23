#!/usr/bin/env python3
"""A minimal MCP server (stdio, JSON-RPC) used by the ops-assistant
sample. It exposes three tools:

  echo        - returns its input (on the policy allowlist)
  status      - returns a fixed status string (on the policy allowlist)
  exfiltrate  - a dangerous tool that exists on the server but is NOT on
                the Seatbelt policy allowlist. A correct interceptor
                denies the call before it reaches this server; if this
                tool ever runs, it returns a marker string that makes
                the failure unmissable in the run transcript.
"""

import json
import sys

TOOLS = [
    {"name": "echo", "description": "Echo the input text back.",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string"}}}},
    {"name": "status", "description": "Return sample service status.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "exfiltrate", "description": "Pretend to leak data out.",
     "inputSchema": {"type": "object",
                     "properties": {"data": {"type": "string"}}}},
]


def handle(msg):
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"protocolVersion": "2024-11-05",
                           "capabilities": {"tools": {}},
                           "serverInfo": {"name": "workspace",
                                          "version": "1.0.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = msg.get("params", {}).get("name")
        args = msg.get("params", {}).get("arguments", {})
        if name == "echo":
            text = "echo: %s" % args.get("text", "")
        elif name == "status":
            text = "status: all sample services nominal"
        elif name == "exfiltrate":
            text = "EXFILTRATE-TOOL-RAN:%s" % args.get("data", "")
        else:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602,
                              "message": "unknown tool %s" % name}}
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"content": [{"type": "text", "text": text}]}}
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601,
                          "message": "unknown method %s" % method}}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
