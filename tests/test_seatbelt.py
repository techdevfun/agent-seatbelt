"""Unit + component tests for Agent Seatbelt.

Run from the repository root:
    PYTHONPATH=src python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from seatbelt.coverage import reconcile  # noqa: E402
from seatbelt.hook import map_event  # noqa: E402
from seatbelt.ingest import normalize_ocsf, normalize_otel  # noqa: E402
from seatbelt.ledger import (Ledger, load_signing_key, merkle_root,  # noqa: E402
                             read_records)
from seatbelt.serve import dns_subject, start_opa  # noqa: E402
from seatbelt.pdp import PDP  # noqa: E402
from seatbelt.verify import verify_bundle  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OPA = os.environ.get("SEATBELT_OPA_BIN", os.path.expanduser("~/workspace/tools/opa"))
SECRET = "UNIT-TEST-SECRET-0000"


def make_ledger(tmp, records=5):
    key_file = os.path.join(tmp, "key.txt")
    key = load_signing_key(key_file)
    ledger_path = os.path.join(tmp, "ledger.ndjson")
    anchor_path = os.path.join(tmp, "anchors.ndjson")
    ledger = Ledger(ledger_path, anchor_path, key, "run-test",
                    "ops-assistant", "test")
    for i in range(records):
        ledger.append("tool-decision", "tool",
                      {"tool": "shell.run", "command": "ls"},
                      decision="allow", reason="tool_allowlisted",
                      action_id="a%d" % i)
    ledger.checkpoint()
    ledger.close()
    return key, ledger_path, anchor_path


class LedgerTests(unittest.TestCase):
    def test_chain_checkpoint_anchor_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, ledger_path, _ = make_ledger(tmp)
            result = verify_bundle(tmp, key, [SECRET])
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["checks"]["chain"]["records"], 6)

    def test_one_byte_tamper_fails_at_exact_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, ledger_path, _ = make_ledger(tmp)
            lines = open(ledger_path).read().splitlines()
            lines[2] = lines[2].replace('"ls"', '"lx"', 1)
            open(ledger_path, "w").write("\n".join(lines) + "\n")
            result = verify_bundle(tmp, key, [])
            self.assertFalse(result["ok"])
            self.assertEqual(
                result["checks"]["chain"]["first_bad_seq"], 3)

    def test_anchor_removal_fails_checkpoint_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, ledger_path, anchor_path = make_ledger(tmp)
            open(anchor_path, "w").write("")
            result = verify_bundle(tmp, key, [])
            self.assertFalse(result["ok"])
            self.assertFalse(result["checks"]["checkpoints"]["ok"])

    def test_resume_continues_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, ledger_path, anchor_path = make_ledger(tmp, records=2)
            ledger = Ledger(ledger_path, anchor_path, key, "run-test",
                            "ops-assistant", "test", resume=True)
            ledger.append("run-end", "lifecycle", {})
            ledger.checkpoint()
            ledger.close()
            result = verify_bundle(tmp, key, [])
            self.assertTrue(result["ok"], result)

    def test_merkle_root(self):
        self.assertEqual(merkle_root([]),
                         hashlib.sha256(b"").hexdigest())
        one = ["ab" * 32]
        self.assertEqual(merkle_root(one), one[0])
        three = ["aa" * 32, "bb" * 32, "cc" * 32]
        self.assertEqual(len(merkle_root(three)), 64)
        self.assertNotEqual(merkle_root(three),
                            merkle_root(list(reversed(three))))


class SubjectTests(unittest.TestCase):
    def test_denied_dns_name_is_redacted_with_digest(self):
        qname = "deadbeef.exfil.attacker.test"
        subj = dns_subject(qname, allowed=False)
        self.assertNotIn(qname, json.dumps(subj))
        self.assertEqual(subj["qname_sha256"],
                         hashlib.sha256(qname.encode()).hexdigest())
        self.assertEqual(subj["qname_redacted"], "*.attacker.test")

    def test_allowed_dns_name_recorded_in_full(self):
        subj = dns_subject("api.internal.test", allowed=True)
        self.assertEqual(subj["qname"], "api.internal.test")


class CoverageTests(unittest.TestCase):
    def test_reconcile_matches_and_reports_missing(self):
        records = [
            {"kind": "tool-decision", "action_id": "a1", "subject": {}},
            {"kind": "dns-event", "action_id": None,
             "subject": {"qname_sha256": hashlib.sha256(
                 b"x.exfil.attacker.test").hexdigest()}},
        ]
        gt = [
            {"action_id": "a1", "class": "tool"},
            {"action_id": "a2", "class": "dns",
             "qname": "x.exfil.attacker.test"},
            {"action_id": "a3", "class": "file"},
        ]
        out = reconcile(records, gt)
        self.assertEqual(out["recorded"], 2)
        self.assertEqual(len(out["missing"]), 1)
        self.assertEqual(out["verdict"], "FAIL")


class HookMappingTests(unittest.TestCase):
    def test_bash_maps_to_shell_run(self):
        action, _ = map_event({"tool_name": "Bash",
                               "tool_input": {"command": "ls"}}, "/ws")
        self.assertEqual(action["tool"], "shell.run")

    def test_write_maps_to_file_class_with_workspace(self):
        action, _ = map_event({"tool_name": "Write",
                               "tool_input": {"file_path": "/ws/a.txt"}},
                              "/ws")
        self.assertEqual(action["class"], "file")
        self.assertEqual(action["workspace"], "/ws")

    def test_mcp_name_maps_to_mcp_call(self):
        action, _ = map_event({"tool_name": "mcp__workspace__echo",
                               "tool_input": {}}, "/ws")
        self.assertEqual(action["mcp_server"], "workspace")
        self.assertEqual(action["mcp_tool"], "echo")

    def test_unknown_tool_falls_to_default_deny_shape(self):
        action, _ = map_event({"tool_name": "Teleport",
                               "tool_input": {}}, "/ws")
        self.assertEqual(action["tool"], "harness.Teleport")


class IngestTests(unittest.TestCase):
    def test_ocsf_network_normalization(self):
        out = normalize_ocsf({"class_uid": 4001, "disposition_id": 2,
                              "dst_endpoint": {"ip": "10.0.0.9",
                                               "port": 443}})
        self.assertEqual(out["class"], "egress")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["source"], "openshell-ocsf")

    def test_otel_tool_normalization(self):
        out = normalize_otel({"body": "claude_code.tool_decision",
                              "attributes": {"tool_name": "Bash",
                                             "decision": "accept"}})
        self.assertEqual(out["class"], "tool")
        self.assertEqual(out["source"], "claude-code-otel")


class SecretScanTests(unittest.TestCase):
    def test_secret_in_bundle_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, ledger_path, _ = make_ledger(tmp, records=1)
            with open(os.path.join(tmp, "coverage-report.json"),
                      "w") as fh:
                fh.write(json.dumps({"leak": SECRET}) + "\n")
            result = verify_bundle(tmp, key, [SECRET])
            self.assertFalse(result["ok"])
            self.assertFalse(result["checks"]["secret_scan"]["ok"])


class PDPTests(unittest.TestCase):
    """Decisions against a real OPA server with the shipped pack."""

    @classmethod
    def setUpClass(cls):
        cls.proc, url = start_opa(OPA, os.path.join(ROOT, "policies"),
                                  18299)
        cls.pdp = PDP(url, os.path.join(ROOT, "policies"), "1.0.0")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()

    def decide(self, action):
        return self.pdp.decide(action)

    def test_shell_allow_and_deny(self):
        self.assertEqual(self.decide(
            {"class": "tool", "tool": "shell.run",
             "command": "ls"})["decision"], "allow")
        self.assertEqual(self.decide(
            {"class": "tool", "tool": "shell.run",
             "command": "cat ~/.ssh/id_rsa"})["reason"],
            "shell_command_denied")

    def test_require_approval(self):
        out = self.decide({"class": "tool", "tool": "shell.deploy"})
        self.assertEqual(out["decision"], "require-approval")

    def test_budget_boundary_is_deterministic(self):
        base = {"class": "budget", "cap_cost": 0.5, "cap_tokens": 100,
                "used_cost": 0.4, "used_tokens": 0, "add_tokens": 1}
        self.assertEqual(self.decide(
            {**base, "add_cost": 0.1})["decision"], "allow")
        self.assertEqual(self.decide(
            {**base, "add_cost": 0.11})["reason"], "budget_cap_exceeded")

    def test_credential_raw_read_always_denied(self):
        out = self.decide({"class": "credential",
                           "service": "billing-api", "host": "127.0.0.1",
                           "method": "GET", "path": "/v1/x",
                           "raw_read": True})
        self.assertEqual(out["reason"],
                         "credential_raw_disclosure_forbidden")

    def test_unknown_class_defaults_to_deny(self):
        out = self.decide({"class": "teleport"})
        self.assertEqual(out["decision"], "deny")


class ConcurrencyTests(unittest.TestCase):
    """Light concurrency: the ledger is single-writer by design, with
    every append serialized through one lock inside the daemon. These
    tests prove that parallel callers (worker threads appending,
    checkpoints racing appends, parallel PDP decisions against the
    real OPA server) can neither corrupt the hash chain nor change a
    decision."""

    def test_parallel_appends_keep_chain_intact(self):
        threads, per_thread = 8, 25
        with tempfile.TemporaryDirectory() as tmp:
            key = load_signing_key(os.path.join(tmp, "key.txt"))
            ledger = Ledger(os.path.join(tmp, "ledger.ndjson"),
                            os.path.join(tmp, "anchors.ndjson"),
                            key, "run-conc", "ops-assistant", "test")

            def worker(tid):
                for i in range(per_thread):
                    ledger.append(
                        "tool-decision", "tool",
                        {"tool": "shell.run", "command": "ls"},
                        decision="allow", reason="tool_allowlisted",
                        action_id="t%d-%d" % (tid, i))

            with ThreadPoolExecutor(max_workers=threads) as pool:
                list(pool.map(worker, range(threads)))
            ledger.checkpoint()
            ledger.close()
            records = read_records(os.path.join(tmp, "ledger.ndjson"))
            total = threads * per_thread + 1  # + the checkpoint record
            self.assertEqual([r["seq"] for r in records],
                             list(range(1, total + 1)))
            self.assertEqual(
                len({r["action_id"] for r in records
                     if r["action_id"]}), threads * per_thread)
            result = verify_bundle(tmp, key, [])
            self.assertTrue(result["ok"], result)

    def test_checkpoints_racing_appends_stay_valid(self):
        writers, per_writer = 4, 20
        with tempfile.TemporaryDirectory() as tmp:
            key = load_signing_key(os.path.join(tmp, "key.txt"))
            ledger = Ledger(os.path.join(tmp, "ledger.ndjson"),
                            os.path.join(tmp, "anchors.ndjson"),
                            key, "run-race", "ops-assistant", "test")
            stop = threading.Event()

            def writer(tid):
                for i in range(per_writer):
                    ledger.append(
                        "tool-decision", "tool",
                        {"tool": "shell.run", "command": "true"},
                        decision="allow", reason="tool_allowlisted",
                        action_id="w%d-%d" % (tid, i))

            def sealer():
                while not stop.is_set():
                    ledger.checkpoint()

            seal_thread = threading.Thread(target=sealer)
            seal_thread.start()
            with ThreadPoolExecutor(max_workers=writers) as pool:
                list(pool.map(writer, range(writers)))
            stop.set()
            seal_thread.join()
            ledger.checkpoint()
            ledger.close()
            records = read_records(os.path.join(tmp, "ledger.ndjson"))
            self.assertEqual([r["seq"] for r in records],
                             list(range(1, len(records) + 1)))
            self.assertGreater(
                len([r for r in records if r["kind"] == "checkpoint"]), 1)
            result = verify_bundle(tmp, key, [])
            self.assertTrue(result["ok"], result)

    def test_parallel_decisions_match_expected(self):
        proc, url = start_opa(OPA, os.path.join(ROOT, "policies"), 18311)
        try:
            pdp = PDP(url, os.path.join(ROOT, "policies"), "1.0.0")
            budget = {"class": "budget", "cap_cost": 0.5,
                      "cap_tokens": 100, "used_cost": 0.4,
                      "used_tokens": 0, "add_tokens": 1}
            cases = [
                ({"class": "tool", "tool": "shell.run", "command": "ls"},
                 ("allow", None)),
                ({"class": "tool", "tool": "shell.run",
                  "command": "cat ~/.ssh/id_rsa"},
                 (None, "shell_command_denied")),
                ({"class": "tool", "tool": "shell.deploy"},
                 ("require-approval", None)),
                ({**budget, "add_cost": 0.1}, ("allow", None)),
                ({**budget, "add_cost": 0.11},
                 (None, "budget_cap_exceeded")),
                ({"class": "teleport"}, ("deny", None)),
            ]
            jobs = [cases[i % len(cases)] for i in range(48)]

            def run(job):
                action, (want_decision, want_reason) = job
                out = pdp.decide(action)
                if want_decision is not None:
                    self.assertEqual(out["decision"], want_decision)
                if want_reason is not None:
                    self.assertEqual(out["reason"], want_reason)

            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(run, jobs))
        finally:
            proc.terminate()


if __name__ == "__main__":
    unittest.main()
