#!/usr/bin/env python3
"""Run the unit suite under line tracing and publish line coverage.

Uses only the standard library (PEP 669 `sys.monitoring`, Python
>= 3.12), so the published number is produced by the exact same code
locally and in CI — no coverage.py dependency to drift.

What it does:
  1. Computes the executable-line set of every module in src/seatbelt
     from the compiled code objects' line tables.
  2. Runs the full unittest suite in-process with LINE events enabled,
     recording every executed line in those modules.
  3. Prints a per-module table plus the TOTAL line-coverage percentage
     and writes the same numbers as JSON (default:
     verification/coverage.json).

Exit code is 0 only if the suite passes; the coverage percentage is a
published metric, not a gate.

Usage: python3 scripts/run_tests_with_coverage.py [--json PATH]
"""

import argparse
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT, "src")
PKG_DIR = os.path.join(SRC_DIR, "seatbelt")
TOOL_ID = 2  # sys.monitoring free tool id (0=debugger, 1=coverage tool)


def executable_lines(path):
    """All line numbers that carry bytecode in a module, recursively."""
    with open(path, "rb") as fh:
        code = compile(fh.read(), path, "exec")
    lines = set()
    stack = [code]
    while stack:
        co = stack.pop()
        for _start, _end, lineno in co.co_lines():
            if lineno is not None:
                lines.add(lineno)
        for const in co.co_consts:
            if hasattr(const, "co_lines"):
                stack.append(const)
    return lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default=os.path.join(
        ROOT, "verification", "coverage.json"))
    args = parser.parse_args()

    targets = {}
    for name in sorted(os.listdir(PKG_DIR)):
        if name.endswith(".py"):
            path = os.path.join(PKG_DIR, name)
            targets[os.path.normpath(path)] = executable_lines(path)
    covered = {path: set() for path in targets}

    def on_line(code, lineno):
        filename = code.co_filename
        if "seatbelt" in filename and filename.endswith(".py"):
            path = os.path.normpath(filename)
            if path in covered:
                covered[path].add(lineno)
        return None

    sys.monitoring.use_tool_id(TOOL_ID, "seatbelt-coverage")
    sys.monitoring.register_callback(
        TOOL_ID, sys.monitoring.events.LINE, on_line)
    sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.LINE)
    try:
        if SRC_DIR not in sys.path:
            sys.path.insert(0, SRC_DIR)
        suite = unittest.TestLoader().discover(os.path.join(ROOT, "tests"))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
    finally:
        sys.monitoring.set_events(TOOL_ID, 0)
        sys.monitoring.free_tool_id(TOOL_ID)

    modules = {}
    total_exec = total_hit = 0
    print("\nLine coverage for src/seatbelt (measured, not a gate):")
    for path in sorted(targets):
        executable = targets[path]
        hit = executable & covered[path]
        pct = 100.0 * len(hit) / len(executable) if executable else 100.0
        modules[os.path.basename(path)] = {
            "executable_lines": len(executable),
            "covered_lines": len(hit),
            "coverage_pct": round(pct, 1),
        }
        total_exec += len(executable)
        total_hit += len(hit)
        print("  %-16s %5d/%-5d %6.1f%%" % (
            os.path.basename(path), len(hit), len(executable), pct))
    total_pct = 100.0 * total_hit / total_exec if total_exec else 100.0
    print("  %-16s %5d/%-5d %6.1f%%" % ("TOTAL", total_hit, total_exec,
                                        total_pct))

    report = {
        "tool": "scripts/run_tests_with_coverage.py (stdlib sys.monitoring)",
        "scope": "src/seatbelt/*.py",
        "tests_run": result.testsRun,
        "tests_passed": result.wasSuccessful(),
        "total": {
            "executable_lines": total_exec,
            "covered_lines": total_hit,
            "coverage_pct": round(total_pct, 1),
        },
        "modules": modules,
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("coverage report written to", args.json)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
