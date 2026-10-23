"""Agent Seatbelt command line.

  seatbelt serve     run the daemon (PDP + ledger + broker + proxy + DNS tap)
  seatbelt hook      Claude Code PreToolUse hook executable
  seatbelt mcp-proxy MCP interceptor proxy (stdio)
  seatbelt ingest    fold a native-signal export (OCSF / OTEL) into a ledger
  seatbelt coverage  reconcile a run's ledger against independent ground truth
  seatbelt verify    one-command offline verification of an evidence bundle
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__


def _cmd_serve(args) -> int:
    from .serve import serve
    run_dir = args.run_dir
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(args.anchor_dir, exist_ok=True)
    cfg = {
        "run_id": args.run_id,
        "agent": args.agent,
        "adapter": args.adapter,
        "workspace": os.path.abspath(args.workspace),
        "policies_dir": args.policies,
        "opa_bin": args.opa_bin,
        "opa_port": args.opa_port,
        "key_file": args.key_file,
        "ledger_path": os.path.join(run_dir, "ledger.ndjson"),
        "anchor_path": os.path.join(args.anchor_dir, "anchors.ndjson"),
        "state_file": args.state_file,
        "api_port": args.api_port,
        "proxy_port": args.proxy_port,
        "dns_port": args.dns_port,
        "cap_cost": args.cap_cost,
        "cap_tokens": args.cap_tokens,
    }
    serve(cfg)
    return 0


def _cmd_verify(args) -> int:
    from .ledger import load_signing_key
    from .verify import verify_bundle
    key = load_signing_key(args.key_file)
    secrets = []
    if args.secrets_file:
        with open(args.secrets_file, encoding="utf-8") as fh:
            secrets = [l.strip() for l in fh if l.strip()]
    result = verify_bundle(args.bundle, key, secrets,
                           args.ground_truth)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def _cmd_coverage(args) -> int:
    from .coverage import run_coverage
    report = run_coverage(args.run_dir, args.ground_truth, args.key_file,
                          args.agent, args.adapter,
                          anchor_path=args.anchor_path)
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


def _cmd_ingest(args) -> int:
    from .ingest import ingest_file
    from .ledger import Ledger, load_signing_key
    ledger_path = os.path.join(args.run_dir, "ledger.ndjson")
    anchor_path = args.anchor_path or os.path.join(args.run_dir,
                                                   "anchors.ndjson")
    key = load_signing_key(args.key_file)
    ledger = Ledger(ledger_path, anchor_path, key, "ingest",
                    args.agent, args.adapter, resume=True)
    count = ingest_file(ledger, args.file, args.format)
    ledger.checkpoint()
    ledger.close()
    print(json.dumps({"ingested": count, "format": args.format}))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="seatbelt")
    parser.add_argument("--version", action="version",
                        version="agent-seatbelt %s" % __version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--agent", default="ops-assistant")
    p.add_argument("--adapter", required=True)
    p.add_argument("--workspace", required=True)
    p.add_argument("--policies", required=True)
    p.add_argument("--opa-bin", required=True)
    p.add_argument("--opa-port", type=int, default=18181)
    p.add_argument("--key-file", required=True)
    p.add_argument("--anchor-dir", required=True)
    p.add_argument("--state-file", required=True)
    p.add_argument("--api-port", type=int, default=0)
    p.add_argument("--proxy-port", type=int, default=0)
    p.add_argument("--dns-port", type=int, default=0)
    p.add_argument("--cap-cost", type=float, default=0.50)
    p.add_argument("--cap-tokens", type=int, default=20000)
    p.set_defaults(fn=_cmd_serve)

    p = sub.add_parser("hook")
    p.set_defaults(fn=lambda a: __import__(
        "seatbelt.hook", fromlist=["main"]).main())

    p = sub.add_parser("mcp-proxy")
    p.add_argument("--state-file", required=True)
    p.add_argument("--server-name", default="workspace")
    p.add_argument("--server-cmd", nargs="+", required=True)
    p.set_defaults(fn=lambda a: __import__(
        "seatbelt.mcp_proxy", fromlist=["main"]).main(
            ["--state-file", a.state_file, "--server-name", a.server_name,
             "--server-cmd"] + a.server_cmd))

    p = sub.add_parser("verify")
    p.add_argument("--bundle", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--secrets-file")
    p.add_argument("--ground-truth")
    p.set_defaults(fn=_cmd_verify)

    p = sub.add_parser("coverage")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--ground-truth", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--agent", default="ops-assistant")
    p.add_argument("--adapter", required=True)
    p.add_argument("--anchor-path")
    p.set_defaults(fn=_cmd_coverage)

    p = sub.add_parser("ingest")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--anchor-path")
    p.add_argument("--format", choices=["ocsf", "otel"], required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--agent", default="ops-assistant")
    p.add_argument("--adapter", required=True)
    p.set_defaults(fn=_cmd_ingest)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
