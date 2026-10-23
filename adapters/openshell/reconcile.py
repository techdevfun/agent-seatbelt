#!/usr/bin/env python3
"""Two-source reconciliation for the OpenShell adapter.

Compares, inside one sealed ledger, the records Seatbelt's own
boundary points wrote (source "seatbelt") against the records ingested
from the runtime's native OCSF stream (source "openshell-ocsf"), for
the two network classes both sources can see: egress and DNS.

  matched          - present in both sources
  native_missing   - at Seatbelt's boundary but absent natively
                     (evidence the native stream silently dropped)
  boundary_missing - native but absent at the boundary; for classes in
                     the adapter's coverage manifest this must be zero

Exit code 0 when boundary_missing is empty. The report is written as
JSON so the numbers in the dossier are machine-produced, not narrated.
"""

import argparse
import hashlib
import json
import sys

sys.path.insert(0, __file__.rsplit("/adapters/", 1)[0] + "/src")
from seatbelt.ledger import read_records  # noqa: E402


def boundary_keys(records):
    keys = {}
    for rec in records:
        if rec["source"] != "seatbelt":
            continue
        subj = rec.get("subject", {})
        if rec["kind"] == "egress-decision":
            keys[("egress", subj.get("host"))] = rec["seq"]
        elif rec["kind"] == "dns-event":
            if "qname" in subj:
                keys[("dns", subj["qname"])] = rec["seq"]
            else:
                keys[("dns-digest", subj.get("qname_sha256"))] = rec["seq"]
    return keys


def native_keys(records):
    keys = {}
    for rec in records:
        if rec["source"] != "openshell-ocsf":
            continue
        subj = rec.get("subject", {})
        if rec["class"] == "egress":
            keys[("egress", subj.get("host"))] = rec["seq"]
        elif rec["class"] == "dns":
            keys[("dns", subj.get("qname"))] = rec["seq"]
    return keys


def reconcile(records):
    boundary = boundary_keys(records)
    native = native_keys(records)
    matched, native_missing = [], []
    for key, seq in sorted(boundary.items()):
        if key[0] == "dns-digest":
            # a denied (redacted) DNS record matches natively only if a
            # native event carries the same full query name
            digest = key[1]
            hit = any(k[0] == "dns" and hashlib.sha256(
                k[1].encode("utf-8")).hexdigest() == digest
                for k in native)
            (matched if hit else native_missing).append(
                {"key": "dns:<redacted-denied>", "boundary_seq": seq})
        elif key in native:
            matched.append({"key": ":".join(map(str, key)),
                            "boundary_seq": seq,
                            "native_seq": native[key]})
        else:
            native_missing.append({"key": ":".join(map(str, key)),
                                   "boundary_seq": seq})
    boundary_missing = [{"key": ":".join(map(str, k)), "native_seq": s}
                        for k, s in sorted(native.items())
                        if k not in boundary and k[0] != "dns"]
    return {"matched": matched, "native_missing": native_missing,
            "boundary_missing": boundary_missing,
            "ok": not boundary_missing}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    report = reconcile(read_records(args.ledger))
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
