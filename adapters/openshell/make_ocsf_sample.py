#!/usr/bin/env python3
"""Generate a reconstructed OpenShell OCSF export for a sample run.

IMPORTANT — what this file is and is not: no OpenShell runtime is
installed in the build environment, so this is NOT a captured export.
It is a faithful reconstruction of the event stream OpenShell's
documented OCSF export would contain for the ops-assistant workload,
built from (a) the vendor's published OCSF observability schema
(network / DNS / file / process activity classes) and (b) the event
inventory measured by the independent Sorami evaluation of OpenShell
v0.1.2 — including its three measured evidence gaps:

  * a blocked UDP DNS query leaves NO event in the native stream;
  * tool calls inside the sandbox are not recorded natively;
  * filesystem (Landlock) events surface only on the VM console.

The planted-scenario sample therefore deliberately contains no DNS
event for the blocked exfiltration query. The reconciliation script
(reconcile.py) then proves mechanically that Seatbelt's own boundary
records contain exactly the event the native stream is missing.
A live capture against a real OpenShell on Linux remains pending and
is recorded as such in the release dossier.
"""

import argparse
import json
import time

BASE_TIME_MS = int(time.time() * 1000)

META = {"version": "1.1.0",
        "product": {"name": "OpenShell", "vendor_name": "NVIDIA",
                    "version": "0.1.2"}}


def event(class_uid, type_uid, activity_id, disposition_id, **kw):
    ev = {"class_uid": class_uid, "category_uid": class_uid // 1000,
          "type_uid": type_uid, "activity_id": activity_id,
          "severity_id": 1, "time": BASE_TIME_MS,
          "disposition_id": disposition_id, "metadata": META,
          "status": "Success" if disposition_id == 1 else "Failure"}
    ev.update(kw)
    return ev


def clean_events(target_port):
    return [
        event(1007, 100701, 1, 1, process={"name": "agent-harness"}),
        event(1001, 100101, 1, 1, file={"path": "input.txt"}),
        event(4003, 400301, 1, 1,
              dns_query={"name": "api.internal.test", "type": "A"}),
        event(4001, 400101, 1, 1,
              dst_endpoint={"ip": "127.0.0.1", "port": target_port},
              connection_info={"protocol_num": 6}),
    ]


def planted_events(target_port):
    # Native stream for the planted run, per the measured inventory:
    # the file read and a process event appear; the blocked DNS
    # exfiltration query produces NO event (the Sorami gap); tool
    # calls (shell/MCP) are not native events at all.
    return [
        event(1007, 100701, 1, 1, process={"name": "agent-harness"}),
        event(1001, 100101, 1, 1, file={"path": "input.txt"}),
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["clean", "planted"],
                        required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    events = clean_events(args.target_port) \
        if args.scenario == "clean" else planted_events(args.target_port)
    with open(args.out, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    print(json.dumps({"wrote": len(events), "out": args.out}))


if __name__ == "__main__":
    main()
