"""MCP proxy interceptor (EP-1).

A stdio JSON-RPC proxy that sits between an MCP client (the agent
harness) and an MCP server. Every `tools/call` is decided synchronously
by the PDP *before* it reaches the server: an allowed call is forwarded
and the server's response relayed; a denied call never reaches the
server and the client receives a JSON-RPC error instead. Both outcomes
are recorded in the evidence ledger by the daemon. All other methods
(initialize, tools/list, ...) pass through transparently.

The correlation id for coverage accounting travels in the JSON-RPC
`params._meta.seatbelt_action_id` field, which the MCP specification
reserves for implementation-specific metadata.
"""

from __future__ import annotations

import json
import subprocess
import sys

from .client import Client


class MCPProxy:
    def __init__(self, client: Client, server_cmd: list[str],
                 server_name: str):
        self.client = client
        self.server_name = server_name
        self.proc = subprocess.Popen(
            server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)

    def _server_call(self, message: dict) -> dict:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        return json.loads(line)

    def handle(self, message: dict) -> dict:
        if message.get("method") != "tools/call":
            return self._server_call(message)
        params = message.get("params", {})
        meta = params.get("_meta", {}) or {}
        action_id = meta.get("seatbelt_action_id")
        mcp_tool = params.get("name", "")
        action = {"class": "tool", "tool": "mcp.call",
                  "mcp_server": self.server_name, "mcp_tool": mcp_tool}
        subject = {"tool": "mcp.call", "mcp_server": self.server_name,
                   "mcp_tool": mcp_tool}
        out = self.client.decide(action, action_id, subject)
        if out["decision"] != "allow":
            return {"jsonrpc": "2.0", "id": message.get("id"),
                    "error": {"code": -32001,
                              "message": "denied by seatbelt policy: %s"
                                         % out["reason"]}}
        return self._server_call(message)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
        except Exception:
            pass


def main(argv=None) -> int:
    import argparse
    import os
    parser = argparse.ArgumentParser(prog="seatbelt-mcp-proxy")
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--server-name", default="workspace")
    parser.add_argument("--server-cmd", nargs="+", required=True)
    args = parser.parse_args(argv)
    with open(args.state_file, encoding="utf-8") as fh:
        state = json.load(fh)
    proxy = MCPProxy(Client(state["api_url"]), args.server_cmd,
                     args.server_name)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            message = json.loads(line)
            response = proxy.handle(message)
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    finally:
        proxy.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
