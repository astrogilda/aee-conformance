#!/usr/bin/env python3
"""Accepted-complexity table gate.

``docs/architecture/DESIGN_DECISIONS.md`` carries a table of the Go functions
whose cyclomatic complexity is accepted as inherent, each with a measured number
and a hand-written rationale. The rationale is the point of the table: it is the
argument that a branch-heavy function mirrors a branch-heavy specification
rather than tangled structure. That argument is only worth reading if the number
attached to it is the number a reader gets when they measure.

The numbers drifted because nothing checked them. The Python side already has
this covered -- ruff's C901 fails the build and ``docs/complexity-rationales.toml``
carries the rationales -- but the Go side had a hand-maintained table and no
linter, so ``Gate0`` grew from 33 to 34 and ``evaluateKind`` from 24 to 28
without a single check going red, and two functions crossed the inclusion
threshold without ever being written down. This gate is the missing half.

It fails closed on all three ways the table can go out of sync with the source:

  - a row whose number no longer matches what gocyclo measures;
  - a function at or above the inclusion threshold with no row (an unreviewed
    accepted-complexity function, which is exactly what the table exists to
    prevent);
  - a row for a function that no longer exists, or that has been refactored back
    below the threshold (a rationale for complexity that is no longer there).

Scope and threshold are stated here rather than inferred from the table, so the
rule is checkable instead of archaeological:

  - SCOPE -- every non-test Go function in the three source trees. Test helpers
    are excluded: they are not the shipped verifier, and their branch count is
    driven by the number of cases they enumerate.
  - THRESHOLD -- complexity 18 and above. Below that, a function is ordinary and
    needs no defence.

``--sync`` rewrites the numeric column from a fresh measurement and touches
nothing else, so a legitimate complexity change is one command rather than a
hand edit that can typo a digit. It deliberately cannot add or remove a row:
a new accepted-complexity function needs a rationale a script has no way to
write, and inventing a placeholder would defeat the table. Membership stays a
human decision; only the arithmetic is automated.

Note the argument convention is the majority one in this directory (bare run =
check, fail closed), not ``coverage-matrix-gate.py``'s (bare run = regenerate),
because this is a gate that can regenerate rather than a generator that can
check.

Usage: python3 scripts/complexity-table-gate.py [--sync] [--gocyclo PATH]
Exit 0 when the table matches the source; 1 on any drift.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "architecture" / "DESIGN_DECISIONS.md"

# Every Go source tree in the repository: the stdlib-only core, the fixture
# builder, the commands, and the separate go-witness attestor module. gocyclo is
# purely syntactic, so the second module needs no separate invocation. aeetest/
# is included deliberately -- its files are not `_test.go`, so they are ordinary
# compiled source, and `Build` sits at 17, one step below the threshold.
SCOPE = ("aee", "aeetest", "cmd", "witnessattestor")
THRESHOLD = 18

# Pinned to the version CI installs. Complexity counting is the tool's whole
# output and it is committed in the table, so a local/CI version skew would show
# up as a table that passes on one machine and fails on the other.
INSTALL_HINT = "go install github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0"

# `37 aee checkSubstrateRow aee/validity.go:456:1`
STAT_RE = re.compile(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+):(\d+):(\d+)$")
# `| `aee/validity.go` `checkSubstrateRow` | 37 | Per-row coverage: ... |`
ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s+`([^`]+)`\s*\|\s*(\d+)\s*\|")
HEADER = "| Function | Cyclo | Why it is inherent |"

Key = tuple[str, str]  # (file path relative to repo root, function name)


def resolve_gocyclo(explicit: str | None) -> str:
    """Locate the gocyclo binary, or exit non-zero saying how to install it.

    A missing analyzer must never degrade into a pass. An unmeasured table is
    exactly the state this gate exists to end, so absence of the tool is a
    failure of the gate, not an excuse to skip it.
    """
    for candidate in (explicit, os.environ.get("GOCYCLO")):
        if candidate:
            if Path(candidate).is_file():
                return candidate
            print(f"FAIL: gocyclo not found at {candidate}", file=sys.stderr)
            raise SystemExit(1)

    found = shutil.which("gocyclo")
    if found:
        return found

    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    fallback = Path(gopath) / "bin" / "gocyclo"
    if fallback.is_file():
        return str(fallback)

    print(
        "FAIL: gocyclo is not installed, so the accepted-complexity table "
        "cannot be checked.\n"
        f"  install it with: {INSTALL_HINT}\n"
        "  or point the gate at it with --gocyclo PATH / GOCYCLO=PATH\n"
        "This gate does not skip when the analyzer is missing: an unchecked "
        "table is the defect it exists to catch.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def measure(binary: str) -> dict[Key, int]:
    """Cyclomatic complexity of every in-scope non-test Go function."""
    paths = [str(REPO_ROOT / d) for d in SCOPE]
    proc = subprocess.run(
        [binary, *paths],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    if proc.returncode != 0:
        print(
            f"FAIL: gocyclo exited {proc.returncode}:\n{proc.stderr.strip()}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    out: dict[Key, int] = {}
    for line in proc.stdout.splitlines():
        m = STAT_RE.match(line.strip())
        if not m:
            continue
        complexity, _pkg, func, path = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        rel = str(Path(path).resolve().relative_to(REPO_ROOT))
        if rel.endswith("_test.go"):
            continue
        out[(rel, func)] = complexity
    if not out:
        print(
            "FAIL: gocyclo reported no functions; the scope paths "
            f"{list(SCOPE)} are wrong or the trees are empty.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return out


def parse_table(lines: list[str]) -> dict[Key, tuple[int, int]]:
    """Map each table row to its (line index, recorded complexity)."""
    try:
        start = lines.index(HEADER)
    except ValueError:
        print(
            f"FAIL: {DOC.relative_to(REPO_ROOT)} has no accepted-complexity "
            f"table (expected a header line {HEADER!r}).",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    rows: dict[Key, tuple[int, int]] = {}
    for idx in range(start + 2, len(lines)):  # +2 skips the |---| separator
        m = ROW_RE.match(lines[idx])
        if not m:
            break
        rows[(m.group(1), m.group(2))] = (idx, int(m.group(3)))
    return rows


def drift(
    measured: dict[Key, int], rows: dict[Key, tuple[int, int]]
) -> list[str]:
    """Every disagreement between the table and the source, worst first."""
    accepted = {k: c for k, c in measured.items() if c >= THRESHOLD}
    errors: list[tuple[int, str]] = []

    for key, complexity in accepted.items():
        recorded = rows.get(key)
        if recorded is None:
            errors.append(
                (
                    complexity,
                    f"`{key[0]}` `{key[1]}`: measures {complexity} "
                    f"(>= {THRESHOLD}) but has no table row -- add one with a "
                    "rationale, or refactor it below the threshold",
                )
            )
        elif recorded[1] != complexity:
            errors.append(
                (
                    complexity,
                    f"`{key[0]}` `{key[1]}`: table says {recorded[1]}, "
                    f"gocyclo measures {complexity}",
                )
            )

    for key in rows:
        if key in accepted:
            continue
        now = measured.get(key)
        why = (
            "the function no longer exists"
            if now is None
            else f"it now measures {now}, below the {THRESHOLD} threshold"
        )
        errors.append((0, f"`{key[0]}` `{key[1]}`: has a table row but {why} -- drop the row"))

    return [msg for _, msg in sorted(errors, key=lambda e: (-e[0], e[1]))]


def sync(lines: list[str], measured: dict[Key, int], rows: dict[Key, tuple[int, int]]) -> int:
    """Rewrite the numeric column of existing rows in place. Returns the count."""
    changed = 0
    for key, (idx, recorded) in rows.items():
        now = measured.get(key)
        if now is None or now == recorded:
            continue
        # `| `file` `func` | 37 | prose |` splits into
        # ['', ' `file` `func` ', ' 37 ', ' prose ', ''] -- only field 2 moves,
        # so the rationale survives byte for byte.
        fields = lines[idx].split("|")
        fields[2] = f" {now} "
        lines[idx] = "|".join(fields)
        changed += 1
    return changed


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Gate the accepted-complexity table.")
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the numeric column from a fresh measurement (prose untouched)",
    )
    ap.add_argument("--gocyclo", default=None, help="path to the gocyclo binary")
    args = ap.parse_args(argv[1:])

    measured = measure(resolve_gocyclo(args.gocyclo))
    text = DOC.read_text(encoding="utf-8")
    lines = text.splitlines()
    rows = parse_table(lines)

    if args.sync:
        changed = sync(lines, measured, rows)
        if changed:
            DOC.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"synced {changed} complexity value(s) in {DOC.relative_to(REPO_ROOT)}")
        else:
            print(f"no numeric drift to sync in {DOC.relative_to(REPO_ROOT)}")
        rows = parse_table(lines)

    errors = drift(measured, rows)
    if errors:
        print(
            f"FAIL: the accepted-complexity table in "
            f"{DOC.relative_to(REPO_ROOT)} has drifted from the source "
            f"({len(errors)} disagreement(s)):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nRun `python3 scripts/complexity-table-gate.py --sync` to rewrite "
            "the numbers; add or drop a row by hand, because a row's rationale "
            "is the part of the table worth having and no script can write it.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(rows)} accepted-complexity row(s) match gocyclo, and no "
        f"non-test function in {'/'.join(SCOPE)} reaches {THRESHOLD} unrecorded."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
