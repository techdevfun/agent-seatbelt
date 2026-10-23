"""Unit + component tests for Agent Seatbelt.

Run from the repository root:
    PYTHONPATH=src python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
