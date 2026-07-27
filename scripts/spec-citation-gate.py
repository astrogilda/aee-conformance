#!/usr/bin/env python3
"""Spec line-citation gate.

The Go and Python sources cite the vendored specification by line number
(``spec:NNN``, ``spec:NNN-MMM``, ``spec:N,M-P``) so a reader can go from a rule
to the passage that requires it. Those citations are the repository's own claim
that each rule was implemented against a specific piece of normative text, and
a wrong one is worse than none: it reads as evidence and points at the wrong
prose.

Line numbers into a periodically re-vendored file rot by construction. The spec
gains a paragraph upstream and every pointer below it silently addresses the
wrong line. ``scripts/vendor-spec.py`` now remaps them automatically at vendor
time, so the ordinary case is handled; this gate is the check that the remap
actually worked, and it catches the cases the remap cannot fix on its own --
a citation written by hand against the wrong line, or one pointing past the end
of the file, or one landing on a blank line, which carries no information at
all and is how a subtly wrong pointer hides.

Usage: python3 scripts/spec-citation-gate.py
Exit 0 when every citation resolves to a non-blank in-range line.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"

CITING_GLOBS = (
    "aee/*.go",
    "cmd/*/*.go",
    "witnessattestor/*.go",
    "packaging/*.py",
    "vectors/*/*.py",
)
CITATION_RE = re.compile(r"spec:(\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*)")


def endpoints(token: str) -> list[int]:
    """Every line number named by one citation token."""
    out: list[int] = []
    for part in (p.strip() for p in token.split(",")):
        out.extend(int(x) for x in part.split("-"))
    return out


def main() -> int:
    spec_lines = (REPO_ROOT / SPEC_REL).read_text(encoding="utf-8").splitlines()
    total = len(spec_lines)
    failures: list[str] = []
    checked = 0

    for pattern in CITING_GLOBS:
        for path in sorted(REPO_ROOT.glob(pattern)):
            rel = path.relative_to(REPO_ROOT)
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                for token in CITATION_RE.findall(line):
                    for n in endpoints(token):
                        checked += 1
                        if n < 1 or n > total:
                            failures.append(
                                f"{rel}:{lineno}: spec:{token} names line {n}, "
                                f"but the spec has {total} lines"
                            )
                        elif not spec_lines[n - 1].strip():
                            failures.append(
                                f"{rel}:{lineno}: spec:{token} names line {n}, "
                                "which is blank"
                            )

    if failures:
        print(
            f"FAIL: {len(failures)} spec citation(s) do not resolve "
            f"(of {checked} checked):",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nRe-vendor with scripts/vendor-spec.py to remap citations "
            "automatically, or correct the citation by hand if it was written "
            "against the wrong line.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {checked} spec citation endpoint(s) resolve to non-blank lines.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
