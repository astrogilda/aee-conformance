#!/usr/bin/env python3
"""Fail if any Go source file in a coverage profile is below a threshold.

Go's `go test -cover` reports per-package coverage; this script enforces a
stricter per-FILE threshold instead.
This parses one or more `go test -coverprofile` outputs, aggregates covered vs
total statements per file, and exits non-zero if any file is below the
threshold. Test files and anything under an excluded path (e.g. runnable demo
commands, whose lifecycle is covered by the attestor tests) are skipped.

Usage: coverage-gate.py [--threshold 80] [--exclude <path> ...] profile.out [...]
"""

from __future__ import annotations

import argparse
import collections
import sys


def per_file(paths: list[str]) -> dict[str, list[int]]:
    files: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            first = True
            for line in handle:
                if first:  # "mode: set" header
                    first = False
                    continue
                parts = line.split()
                if len(parts) != 3:
                    continue
                fq = parts[0].split(":")[0]  # full import path + filename
                numstmt, count = int(parts[1]), int(parts[2])
                files[fq][1] += numstmt
                if count > 0:
                    files[fq][0] += numstmt
    return files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=80.0)
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("profiles", nargs="+")
    args = ap.parse_args()

    failures = []
    for fq, (cov, tot) in sorted(per_file(args.profiles).items()):
        if any(ex in fq for ex in args.exclude):
            continue
        pct = 100.0 * cov / tot if tot else 100.0
        mark = "" if pct >= args.threshold else "  BELOW"
        print(f"{pct:6.1f}%  {fq}  ({cov}/{tot}){mark}")
        if pct < args.threshold:
            failures.append((fq, pct))

    if failures:
        print(f"\nFAIL: {len(failures)} file(s) below {args.threshold:.0f}% coverage:")
        for fq, pct in failures:
            print(f"  {pct:.1f}%  {fq}")
        return 1
    print(f"\nOK: every file is at or above {args.threshold:.0f}% coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
