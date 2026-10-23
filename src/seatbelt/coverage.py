"""Coverage accountant (component 7).

The accountant reconciles the evidence ledger against ground truth that
was produced *independently of Seatbelt*: the sample harness writes its
own log of every action it attempts, before and regardless of any
Seatbelt decision. For each ground-truth action the accountant looks
for the corresponding boundary record in the ledger:

  tool       -> a tool-decision record with the same action_id
  file       -> a file-event record with the same action_id
  egress     -> an egress-decision record with the same action_id
  dns        -> a dns-event whose recorded name (or, for denied names,
                the digest of the recorded redacted name) matches
  credential -> a credential-issuance or credential-refusal record
  budget     -> a budget-event record with the same action_id
  lifecycle  -> run-start / run-end records exist

Any ground-truth action without a matching record is listed in the
coverage report and makes the run FAIL — publicly, in the report file
and in a coverage-report record sealed into the ledger itself. Silence
is a failure, never an assumption of success.
"""

from __future__ import annotations

import hashlib
import json
import os

from .ledger import Ledger, load_signing_key, read_records, utcnow

KIND_FOR_CLASS = {
    "tool": ("tool-decision",),
    "file": ("file-event",),
    "egress": ("egress-decision",),
    "credential": ("credential-issuance", "credential-refusal"),
    "budget": ("budget-event",),
}


def _matches(rec: dict, gt: dict) -> bool:
    cls = gt["class"]
    if cls == "dns":
        if rec["kind"] != "dns-event":
            return False
        subj = rec.get("subject", {})
        if subj.get("qname") == gt["qname"]:
            return True
        digest = hashlib.sha256(gt["qname"].encode("utf-8")).hexdigest()
        return subj.get("qname_sha256") == digest
    if cls == "lifecycle":
        want = "run-start" if gt["event"] == "run-start" else "run-end"
        return rec["kind"] == want
    kinds = KIND_FOR_CLASS.get(cls, ())
    return rec["kind"] in kinds and rec.get("action_id") == gt["action_id"]


def reconcile(records: list[dict], ground_truth: list[dict]) -> dict:
    missing = []
    matched = 0
    for gt in ground_truth:
        if any(_matches(rec, gt) for rec in records):
            matched += 1
        else:
            missing.append(gt)
    return {"expected": len(ground_truth), "recorded": matched,
            "missing": missing,
            "verdict": "PASS" if not missing else "FAIL"}


def load_ground_truth(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def run_coverage(run_dir: str, ground_truth_path: str, key_file: str,
                 agent: str, adapter: str,
                 anchor_path: str | None = None) -> dict:
    ledger_path = os.path.join(run_dir, "ledger.ndjson")
    if anchor_path is None:
        anchor_path = os.path.join(run_dir, "anchors.ndjson")
    records = read_records(ledger_path)
    ground_truth = load_ground_truth(ground_truth_path)
    result = reconcile(records, ground_truth)
    key = load_signing_key(key_file)
    ledger = Ledger(ledger_path, anchor_path, key,
                    records[0]["run_id"] if records else "unknown",
                    agent, adapter, resume=True)
    rec = ledger.append(
        "coverage-report", "integrity",
        {"expected": result["expected"], "recorded": result["recorded"],
         "missing_count": len(result["missing"]),
         "verdict": result["verdict"]},
        decision="allow" if result["verdict"] == "PASS" else "deny",
        reason="coverage_complete" if result["verdict"] == "PASS"
               else "coverage_gap")
    ledger.checkpoint()
    head = ledger.head_hash
    ledger.close()
    report = {"run_id": rec["run_id"], "adapter": adapter,
              "generated": utcnow(), **result,
              "coverage_record_seq": rec["seq"], "head_hash": head}
    with open(os.path.join(run_dir, "coverage-report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report
