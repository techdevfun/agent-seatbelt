"""One-command offline verifier (component 8, EP-6).

    seatbelt verify --bundle DIR --key-file KEY [--secrets-file FILE]
                    [--ground-truth FILE]

Checks, in order:
  1. Hash chain: sequence numbers are monotonic from 1, every prev_hash
     links to the previous record's hash, and every record hash
     recomputes exactly. The first failing record is named by seq.
  2. Checkpoints: for each checkpoint record, the Merkle root over the
     covered record hashes recomputes, the HMAC-SHA-256 signature
     verifies under the operator key, and the external anchor file
     carries the same root + signature.
  3. Secret scan: no configured secret value appears anywhere in the
     bundle (ledger, anchors, coverage report).
  4. Coverage (when ground truth is supplied): mechanical reconciliation
     of the ground truth against the ledger finds zero missing records,
     and a sealed coverage-report record agrees.

Exit code 0 = PASS, 1 = FAIL. Runs fully offline; trusts nothing but
the operator key and the files in the bundle.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

from .coverage import load_ground_truth, reconcile
from .ledger import GENESIS_HASH, merkle_root, read_records, record_hash


def _check_chain(records):
    prev = GENESIS_HASH
    for i, rec in enumerate(records, start=1):
        if not isinstance(rec, dict) or "seq" not in rec \
                or "hash" not in rec or "prev_hash" not in rec:
            return {"ok": False, "first_bad_seq": i,
                    "detail": "malformed record at position %d" % i}
        if rec["seq"] != i:
            return {"ok": False, "first_bad_seq": rec["seq"],
                    "detail": "sequence gap at record %d" % i}
        if rec["prev_hash"] != prev:
            return {"ok": False, "first_bad_seq": rec["seq"],
                    "detail": "prev_hash link broken"}
        payload = {k: v for k, v in rec.items() if k != "hash"}
        if record_hash(prev, payload) != rec["hash"]:
            return {"ok": False, "first_bad_seq": rec["seq"],
                    "detail": "record hash does not recompute"}
        prev = rec["hash"]
    return {"ok": True, "records": len(records)}


def _check_checkpoints(records, anchors, key):
    checkpoints = [r for r in records if r["kind"] == "checkpoint"]
    if not checkpoints:
        return {"ok": False, "detail": "no checkpoint in ledger"}
    anchor_by_seq = {a["checkpoint_seq"]: a for a in anchors}
    for cp in checkpoints:
        covers = cp["subject"]["covers_to_seq"]
        hashes = [r["hash"] for r in records if r["seq"] <= covers]
        root = merkle_root(hashes)
        if root != cp["subject"]["merkle_root"]:
            return {"ok": False, "first_bad_seq": cp["seq"],
                    "detail": "merkle root mismatch"}
        sig = (cp.get("extra") or {}).get("signature", "")
        expect = hmac.new(key, root.encode("ascii"),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return {"ok": False, "first_bad_seq": cp["seq"],
                    "detail": "checkpoint signature invalid"}
        anchor = anchor_by_seq.get(cp["seq"])
        if not anchor or anchor["merkle_root"] != root \
                or anchor["signature"] != sig:
            return {"ok": False, "first_bad_seq": cp["seq"],
                    "detail": "external anchor missing or mismatched"}
    return {"ok": True, "checkpoints": len(checkpoints)}


def _check_secrets(bundle_dir, secrets):
    hits = []
    for root, _dirs, files in os.walk(bundle_dir):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as fh:
                data = fh.read()
            for secret in secrets:
                if secret and secret.encode("utf-8") in data:
                    hits.append({"file": os.path.relpath(path, bundle_dir),
                                 "secret_sha256":
                                     hashlib.sha256(
                                         secret.encode("utf-8")
                                     ).hexdigest()[:12]})
    return {"ok": not hits, "hits": hits}


def verify_bundle(bundle_dir: str, key: bytes, secrets: list[str],
                  ground_truth_path: str | None = None) -> dict:
    ledger_path = os.path.join(bundle_dir, "ledger.ndjson")
    anchor_path = os.path.join(bundle_dir, "anchors.ndjson")
    records = read_records(ledger_path)
    anchors = []
    if os.path.exists(anchor_path):
        with open(anchor_path, encoding="utf-8") as fh:
            anchors = [json.loads(l) for l in fh if l.strip()]
    checks = {}
    checks["chain"] = _check_chain(records)
    if checks["chain"]["ok"]:
        checks["checkpoints"] = _check_checkpoints(records, anchors, key)
    else:
        checks["checkpoints"] = {"ok": False,
                                 "detail": "skipped: chain broken"}
    if secrets:
        checks["secret_scan"] = _check_secrets(bundle_dir, secrets)
    if ground_truth_path:
        gt = load_ground_truth(ground_truth_path)
        result = reconcile(records, gt)
        sealed = [r for r in records if r["kind"] == "coverage-report"]
        agree = bool(sealed) and \
            sealed[-1]["subject"]["missing_count"] == len(result["missing"])
        checks["coverage"] = {"ok": result["verdict"] == "PASS" and agree,
                              "expected": result["expected"],
                              "recorded": result["recorded"],
                              "missing": result["missing"]}
    ok = all(c.get("ok") for c in checks.values())
    return {"ok": ok, "checks": checks}
