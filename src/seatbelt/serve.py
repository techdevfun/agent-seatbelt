"""The Seatbelt daemon: one local process that hosts every enforcement
point for a run, so the evidence ledger has a single writer.

Listeners (all bound to 127.0.0.1):
  * API HTTP server   - /decide, /meter, /broker/use, /broker/read,
                        /run/start, /run/end, /checkpoint, /stats
  * Egress proxy      - HTTP forward proxy; every attempt is decided by
                        the PDP and recorded, allowed or denied alike
  * DNS/UDP tap       - a resolver that decides every query against the
                        DNS allowlist and records every attempt,
                        including denied ones (the exact event class an
                        independent evaluation found missing from a
                        major runtime's audit export)

Policy decisions come from the PDP (OPA). Credential values live only in
this process's memory (loaded from the operator's environment at start)
and are injected into the brokered request itself; the agent receives a
redacted result, and the ledger records the grant/refusal, never a value.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import POLICY_PACK_VERSION
from .ledger import Ledger, load_signing_key, utcnow
from .pdp import PDP

KIND_BY_CLASS = {
    "tool": "tool-decision",
    "file": "file-event",
    "egress": "egress-decision",
    "dns": "dns-event",
    "budget": "budget-event",
}


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dns_subject(qname: str, allowed: bool) -> dict:
    """Ledger subject for a DNS event.

    Allowed names are recorded in full. A denied name is recorded
    redacted: an exfiltration attempt encodes its payload in the query
    name itself, and the ledger must never become a copy of the data it
    exists to prove was blocked. The full name's digest keeps the record
    mechanically reconcilable with the harness ground truth.
    """
    if allowed:
        return {"qname": qname}
    labels = qname.rstrip(".").split(".")
    suffix = ".".join(labels[-2:]) if len(labels) > 2 else qname
    return {"qname_redacted": "*." + suffix, "qname_sha256": digest(qname),
            "label_count": len(labels)}


class Daemon:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.pdp = PDP(cfg["opa_url"], cfg["policies_dir"],
                       POLICY_PACK_VERSION)
        key = load_signing_key(cfg["key_file"])
        self.ledger = Ledger(cfg["ledger_path"], cfg["anchor_path"], key,
                             cfg["run_id"], cfg["agent"], cfg["adapter"])
        self.workspace = cfg["workspace"]
        self.budget_used_cost = 0.0
        self.budget_used_tokens = 0
        self.cap_cost = float(cfg.get("cap_cost", 0.50))
        self.cap_tokens = int(cfg.get("cap_tokens", 20000))
        self.halted = False
        # Demo credential values: operator-supplied via environment only.
        self.secrets = {}
        for env_name, service in (("SEATBELT_SECRET_BILLING_API",
                                   "billing-api"),):
            value = os.environ.get(env_name)
            if value:
                self.secrets[service] = value
        self.decision_latencies_ms: list[float] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------- PDP
    def decide(self, action: dict, action_id: str | None,
               subject: dict) -> dict:
        started = time.perf_counter()
        result = self.pdp.decide(action)
        kind = KIND_BY_CLASS[action["class"]]
        rec = self.ledger.append(
            kind, action["class"], subject,
            decision=result["decision"], reason=result["reason"],
            action_id=action_id,
            policy_hash=self.pdp.bundle_hash,
            policy_version=self.pdp.pack_version)
        if result["decision"] == "require-approval":
            self.ledger.append(
                "approval-decision", "approval",
                {"action_id": action_id,
                 "outcome": "blocked_unattended"},
                decision="require-approval", reason=result["reason"],
                action_id=action_id,
                policy_hash=self.pdp.bundle_hash,
                policy_version=self.pdp.pack_version)
        elapsed = (time.perf_counter() - started) * 1000.0
        with self._lock:
            self.decision_latencies_ms.append(elapsed)
        return {"decision": result["decision"], "reason": result["reason"],
                "record_seq": rec["seq"], "latency_ms": round(elapsed, 3)}

    # ----------------------------------------------------------- broker
    def broker_use(self, req: dict) -> dict:
        action = {"class": "credential", "service": req["service"],
                  "host": req["host"], "method": req["method"],
                  "path": req["path"], "raw_read": False}
        result = self.pdp.decide(action)
        subject = {"service": req["service"], "host": req["host"],
                   "method": req["method"], "path": req["path"]}
        if result["decision"] != "allow":
            self.ledger.append(
                "credential-refusal", "credential", subject,
                decision="deny", reason=result["reason"],
                action_id=req.get("action_id"),
                policy_hash=self.pdp.bundle_hash,
                policy_version=self.pdp.pack_version)
            return {"decision": "deny", "reason": result["reason"]}
        self.ledger.append(
            "credential-issuance", "credential", subject,
            decision="allow", reason=result["reason"],
            action_id=req.get("action_id"),
            policy_hash=self.pdp.bundle_hash,
            policy_version=self.pdp.pack_version)
        secret = self.secrets.get(req["service"])
        if secret is None:
            return {"decision": "allow", "reason": result["reason"],
                    "error": "no_credential_configured"}
        url = "http://%s%s" % (req["host"], req["path"])
        if ":" not in req["host"] and req.get("port"):
            url = "http://%s:%d%s" % (req["host"], req["port"], req["path"])
        http_req = urllib.request.Request(
            url, method=req["method"],
            headers={"Authorization": "Bearer " + secret})
        try:
            with urllib.request.urlopen(http_req, timeout=5) as resp:
                body = resp.read().decode("utf-8", "replace")
                status = resp.status
        except Exception as exc:  # target error is data, not a crash
            return {"decision": "allow", "reason": result["reason"],
                    "error": "target_error: %s" % exc}
        # The agent sees the result, never the credential that made it.
        redacted = body.replace(secret, "[redacted]")
        return {"decision": "allow", "reason": result["reason"],
                "status": status, "body": redacted}

    def broker_read(self, req: dict) -> dict:
        action = {"class": "credential", "service": req["service"],
                  "host": req.get("host", ""), "method": "READ",
                  "path": "/", "raw_read": True}
        result = self.pdp.decide(action)
        self.ledger.append(
            "credential-refusal", "credential",
            {"service": req["service"], "raw_read": True},
            decision="deny", reason=result["reason"],
            action_id=req.get("action_id"),
            policy_hash=self.pdp.bundle_hash,
            policy_version=self.pdp.pack_version)
        return {"decision": "deny", "reason": result["reason"]}

    # ------------------------------------------------------------ meter
    def meter(self, req: dict) -> dict:
        action = {"class": "budget",
                  "used_cost": self.budget_used_cost,
                  "add_cost": float(req["add_cost"]),
                  "cap_cost": self.cap_cost,
                  "used_tokens": self.budget_used_tokens,
                  "add_tokens": int(req["add_tokens"]),
                  "cap_tokens": self.cap_tokens}
        out = self.decide(action, req.get("action_id"),
                          {"add_cost": action["add_cost"],
                           "add_tokens": action["add_tokens"],
                           "used_cost": self.budget_used_cost,
                           "used_tokens": self.budget_used_tokens})
        if out["decision"] == "allow":
            self.budget_used_cost += action["add_cost"]
            self.budget_used_tokens += action["add_tokens"]
        else:
            self.halted = True
            self.ledger.append(
                "run-halt", "lifecycle",
                {"cause": "budget_cap_exceeded",
                 "used_cost": self.budget_used_cost,
                 "used_tokens": self.budget_used_tokens},
                decision="deny", reason=out["reason"],
                action_id=req.get("action_id"),
                policy_hash=self.pdp.bundle_hash,
                policy_version=self.pdp.pack_version)
        return out


# ------------------------------------------------------------ API server

def make_api_handler(daemon: Daemon):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep stdout clean
            pass

        def _reply(self, obj, status=200):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._reply({"ok": True, "pdp": daemon.pdp.healthy(),
                             "halted": daemon.halted})
            elif self.path == "/stats":
                lat = sorted(daemon.decision_latencies_ms)
                self._reply({"decisions": len(lat),
                             "latencies_ms": lat})
            else:
                self._reply({"error": "not_found"}, 404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length) or b"{}")
            try:
                if self.path == "/decide":
                    action = req["action"]
                    out = daemon.decide(action, req.get("action_id"),
                                        req.get("subject", {}))
                elif self.path == "/meter":
                    out = daemon.meter(req)
                elif self.path == "/broker/use":
                    out = daemon.broker_use(req)
                elif self.path == "/broker/read":
                    out = daemon.broker_read(req)
                elif self.path == "/run/start":
                    rec = daemon.ledger.append(
                        "run-start", "lifecycle",
                        {"workspace": daemon.workspace})
                    out = {"record_seq": rec["seq"]}
                elif self.path == "/run/end":
                    daemon.ledger.append("run-end", "lifecycle",
                                         {"halted": daemon.halted})
                    rec = daemon.ledger.checkpoint()
                    out = {"record_seq": rec["seq"]}
                elif self.path == "/checkpoint":
                    rec = daemon.ledger.checkpoint()
                    out = {"record_seq": rec["seq"]}
                else:
                    self._reply({"error": "not_found"}, 404)
                    return
                self._reply(out)
            except Exception as exc:
                self._reply({"error": "daemon_error: %s" % exc}, 500)

    return Handler


# ---------------------------------------------------------- egress proxy

def make_proxy_handler(daemon: Daemon):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _handle(self):
            action_id = self.headers.get("X-Seatbelt-Action-Id")
            target = self.path  # absolute URI for proxied requests
            if not target.startswith("http://"):
                body = b"proxy expects an absolute http:// URI"
                self.send_response(400)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            rest = target[len("http://"):]
            hostport, _, path = rest.partition("/")
            host, _, port = hostport.partition(":")
            action = {"class": "egress", "host": host,
                      "method": self.command}
            out = daemon.decide(action, action_id,
                                {"host": host, "method": self.command,
                                 "path": "/" + path})
            if out["decision"] != "allow":
                body = ("egress denied by seatbelt policy: %s"
                        % out["reason"]).encode("utf-8")
                self.send_response(403)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length) if length else None
            fwd_headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in
                           ("host", "proxy-connection",
                            "x-seatbelt-action-id", "content-length")}
            url = "http://%s/%s" % (hostport, path)
            fwd = urllib.request.Request(url, data=data,
                                         headers=fwd_headers,
                                         method=self.command)
            try:
                with urllib.request.urlopen(fwd, timeout=10) as resp:
                    body = resp.read()
                    status = resp.status
                    ctype = resp.headers.get("Content-Type",
                                             "application/octet-stream")
            except Exception as exc:
                body = ("upstream error: %s" % exc).encode("utf-8")
                status = 502
                ctype = "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _handle
        do_POST = _handle
        do_HEAD = _handle
        do_PUT = _handle
        do_DELETE = _handle

    return Handler


# --------------------------------------------------------------- DNS tap

def parse_dns_question(packet: bytes):
    qdcount = struct.unpack(">H", packet[4:6])[0]
    if qdcount < 1:
        return None, None
    offset = 12
    labels = []
    while True:
        ln = packet[offset]
        offset += 1
        if ln == 0:
            break
        labels.append(packet[offset:offset + ln].decode("ascii", "replace"))
        offset += ln
    qtype, _qclass = struct.unpack(">HH", packet[offset:offset + 4])
    return ".".join(labels), qtype


def build_dns_response(packet: bytes, rcode: int, answer_ip: str | None):
    qname, qtype = parse_dns_question(packet)
    flags = 0x8180 | rcode  # response, recursion available, rcode
    ancount = 1 if (rcode == 0 and answer_ip and qtype == 1) else 0
    header = packet[:2] + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    question = packet[12:]
    # our requests carry exactly one question and nothing after it
    response = header + question
    if ancount:
        response += (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                     + socket.inet_aton(answer_ip))
    return response


def handle_dns_query(daemon: Daemon, packet: bytes) -> bytes | None:
    """Decide + record one DNS query (transport-agnostic).

    Every query — allowed or denied — produces a dns-event record
    before the response is built. Denied names are answered NXDOMAIN.
    """
    qname, _qtype = parse_dns_question(packet)
    if qname is None:
        return None
    action = {"class": "dns", "qname": qname}
    result = daemon.pdp.decide(action)
    allowed = result["decision"] == "allow"
    daemon.ledger.append(
        "dns-event", "dns", dns_subject(qname, allowed),
        decision=result["decision"], reason=result["reason"],
        policy_hash=daemon.pdp.bundle_hash,
        policy_version=daemon.pdp.pack_version)
    if allowed:
        return build_dns_response(packet, 0, "127.0.0.1")
    return build_dns_response(packet, 3, None)


class DNSTap(threading.Thread):
    """UDP transport for the resolver tap (the standard DNS transport;
    the tap also serves TCP, RFC 7766, through DNSTCPServer — some
    sandboxes block loopback UDP, and the decision path is identical)."""

    def __init__(self, daemon: Daemon, port: int):
        super().__init__(daemon=True)
        self.daemon = daemon
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            self.sock.settimeout(0.5)
            try:
                packet, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                resp = handle_dns_query(self.daemon, packet)
                if resp is not None:
                    self.sock.sendto(resp, addr)
            except Exception:
                continue

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def make_dns_tcp_handler(daemon: Daemon):
    import socketserver

    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                header = self._read_exact(2)
                if header is None:
                    return
                length = struct.unpack(">H", header)[0]
                packet = self._read_exact(length)
                if packet is None:
                    return
                resp = handle_dns_query(daemon, packet)
                if resp is None:
                    return
                self.request.sendall(struct.pack(">H", len(resp)) + resp)

        def _read_exact(self, n):
            data = b""
            while len(data) < n:
                chunk = self.request.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

    return DNSHandler


# -------------------------------------------------------------- lifecycle

def start_opa(opa_bin: str, policies_dir: str, port: int):
    proc = subprocess.Popen(
        [opa_bin, "run", "--server", "--addr", "127.0.0.1:%d" % port,
         policies_dir],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = "http://127.0.0.1:%d" % port
    for _ in range(100):
        try:
            req = urllib.request.Request(url + "/health")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    return proc, url
        except Exception:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("OPA server did not become healthy")


def serve(cfg: dict):
    opa_proc = None
    if cfg.get("start_opa", True):
        opa_proc, opa_url = start_opa(cfg["opa_bin"], cfg["policies_dir"],
                                      cfg.get("opa_port", 0) or 18181)
        cfg["opa_url"] = opa_url
    daemon = Daemon(cfg)
    api = ThreadingHTTPServer(("127.0.0.1", cfg.get("api_port", 0)),
                              make_api_handler(daemon))
    proxy = ThreadingHTTPServer(("127.0.0.1", cfg.get("proxy_port", 0)),
                                make_proxy_handler(daemon))
    dns = DNSTap(daemon, cfg.get("dns_port", 0))
    import socketserver
    dns_tcp = socketserver.ThreadingTCPServer(
        ("127.0.0.1", cfg.get("dns_tcp_port", 0)),
        make_dns_tcp_handler(daemon))
    state = {
        "run_id": cfg["run_id"],
        "api_url": "http://127.0.0.1:%d" % api.server_address[1],
        "proxy_url": "http://127.0.0.1:%d" % proxy.server_address[1],
        "dns_port": dns.port,
        "dns_tcp_port": dns_tcp.server_address[1],
        "pid": os.getpid(),
        "policy_hash": daemon.pdp.bundle_hash,
        "started": utcnow(),
    }
    with open(cfg["state_file"], "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    threads = [threading.Thread(target=api.serve_forever, daemon=True),
               threading.Thread(target=proxy.serve_forever, daemon=True),
               threading.Thread(target=dns_tcp.serve_forever,
                                daemon=True)]
    for t in threads:
        t.start()
    dns.start()
    sys.stderr.write("seatbelt daemon ready: %s\n"
                     % json.dumps(state))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        dns.stop()
        dns_tcp.shutdown()
        api.shutdown()
        proxy.shutdown()
        daemon.ledger.close()
        if opa_proc:
            opa_proc.terminate()
