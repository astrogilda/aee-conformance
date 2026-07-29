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
wrong line. ``scripts/vendor-spec.py`` remaps them automatically at vendor time,
so the ordinary case is handled, and this gate is the check that the remap
actually worked.

Two questions have to stay answered, and they need different checks.

*Does the citation resolve?* Every span must be inside the file, ordered, and
open and close on lines that carry text. That catches a pointer past the end of
the file and one landing on a blank line, which carries no information at all.

*Does the citation still address the text it was written for?* Resolution cannot
answer that, and the difference is not academic. Measured on this repository:
one amendment moved thirty-two citation spans across ten files, and reverting
those files to their pre-amendment state left the resolution check green on
thirty-one of them, because a stale number lands on prose as readily as a
current one. The thirty-second was reported, and reported for the wrong reason,
as an endpoint that had landed on a blank line rather than as a citation that
had stopped describing its subject. That is the same defect the ``Lnnn`` anchors
were found full of, and it went unasked here for as long as it went unasked
there.

So ``spec/CITATION-PINS.json`` records, for every citation, a digest of the text
it addresses plus the opening and closing lines in plain sight, and this gate
recomputes and fails when a citation comes to address different bytes. The
record is keyed by the citing site rather than by the line range, which is the
property the check rests on and which ``scripts/specpins.py`` explains: keyed by
the range it could only restate the number it had just looked up.

A citation naming several disjoint spans is pinned one span at a time. A remap
can carry one part of a citation off its subject and leave the rest alone, and a
single record over the parts together would report that as one opaque change
with nothing to say about which part moved.

What this does not do is decide whether a freshly written citation names the
right rule. Nothing mechanical can read a claim and judge which paragraph
settles it. The gate makes that a review question with the prose attached, and
it makes the systematic failure, every citation below an inserted paragraph
going quietly wrong at once, impossible to commit.

Usage:
    python3 scripts/spec-citation-gate.py           # check
    python3 scripts/spec-citation-gate.py --sync    # rewrite the pin ledger
    python3 scripts/spec-citation-gate.py --sync --accept-reaim <citation-key>
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from specpins import (
    REPO_ROOT,
    Cited,
    Ledger,
    orphan_failures,
    pinned_failures,
    read_pins,
    report,
    spec_state,
    sync,
)

SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"

LEDGER = Ledger(
    path=REPO_ROOT / "spec" / "CITATION-PINS.json",
    spec_rel=SPEC_REL,
    token_field="cites",
    noun="citation",
    article="a",
    token_re=re.compile(r"spec:(\d+)(?:-(\d+))?"),
)

CITING_GLOBS = (
    "aee/*.go",
    "cmd/*/*.go",
    "witnessattestor/*.go",
    "packaging/*.py",
    "vectors/*/*.py",
)
CITATION_RE = re.compile(r"spec:(\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*)")

REMEDY = (
    "A citation that no longer addresses the text it was pinned to is pointing "
    "a reader at prose the rule was not written against. Re-vendor with "
    "scripts/vendor-spec.py, which remaps the citations and re-pins them, or "
    "correct the citation by hand and run this gate with --sync, reading the "
    "excerpt it records against the claim beside it."
)

# What a citation belongs to. The pin has to be found again after the spec has
# moved under it, so it is filed under the thing doing the citing rather than
# under a line number: this function, this type, this package-level binding.
# Adding a rule then disturbs one entry instead of shifting every entry below
# it, and a key that does shift fails loudly as a citation with no recorded
# text, which is the safe direction for it to fail in.
DECLARATIONS = (
    re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)"),  # a Go function or method
    re.compile(r"^(?:type|var|const)\s+(\w+)"),     # a Go type or package binding
    re.compile(r"^(?:def|class)\s+(\w+)"),          # a Python function or class
    re.compile(r"^(\w+)\s*(?::[^=]+)?=\s*\S"),      # a Python module-level binding
)
COMMENT_RE = re.compile(r"^\s*(?://|#)")


def declared(line: str) -> str | None:
    for pattern in DECLARATIONS:
        m = pattern.match(line)
        if m:
            return m.group(1)
    return None


def owners(lines: list[str]) -> list[str]:
    """The declaration each line of a source file belongs to.

    Most citations sit in the doc comment above the thing they describe rather
    than inside it, so a nearest-preceding rule alone would file half of them
    under whatever declaration happened to end just before the comment began.
    A comment run sitting directly above a declaration is therefore attributed
    forward to that declaration, and everything else to the declaration it is
    inside. A file's opening prose, which precedes every declaration, is filed
    under a placeholder.
    """
    owner = ["-"] * (len(lines) + 1)
    current = "-"
    for i, line in enumerate(lines, start=1):
        named = declared(line)
        if named:
            current = named
        owner[i] = current
    for i, line in enumerate(lines, start=1):
        named = declared(line)
        if named is None:
            continue
        j = i - 1
        while j >= 1 and COMMENT_RE.match(lines[j - 1]):
            owner[j] = named
            j -= 1
    return owner


def spans(token: str) -> list[tuple[str, int, int]]:
    """The disjoint spans one citation token names, each with the text it is
    written as, so a failure can name the part rather than the whole."""
    out: list[tuple[str, int, int]] = []
    for part in (p.strip() for p in token.split(",")):
        lo, _, hi = part.partition("-")
        out.append((part, int(lo), int(hi or lo)))
    return out


def citing_paths() -> list[Path]:
    return [p for glob in CITING_GLOBS for p in sorted(REPO_ROOT.glob(glob))]


def collect() -> list[Cited]:
    found: list[Cited] = []
    for path in citing_paths():
        rel = str(path.relative_to(REPO_ROOT))
        lines = path.read_text(encoding="utf-8").splitlines()
        owner = owners(lines)
        seen: dict[str, int] = {}
        for lineno, line in enumerate(lines, start=1):
            for token in CITATION_RE.findall(line):
                for part, lo, hi in spans(token):
                    base = f"{rel}::{owner[lineno]}"
                    seen[base] = seen.get(base, -1) + 1
                    found.append(
                        Cited(
                            key=f"{base}#{seen[base]}",
                            token=f"spec:{part}",
                            lo=lo,
                            hi=hi,
                            site=f"{rel}:{lineno}",
                        )
                    )
    return found


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the pin ledger from the citations as they now stand",
    )
    ap.add_argument(
        "--accept-reaim",
        action="append",
        default=[],
        metavar="KEY",
        help="one citation key whose move onto different prose is intended",
    )
    args = ap.parse_args(argv[1:])
    cites = collect()
    if args.sync:
        return sync(LEDGER, cites, set(args.accept_reaim))

    if not LEDGER.path.is_file():
        print(
            f"FAIL: {LEDGER.path.relative_to(REPO_ROOT)} is missing; create it "
            "with python3 scripts/spec-citation-gate.py --sync",
            file=sys.stderr,
        )
        return 1
    spec, _digest = spec_state(SPEC_REL)
    pins, _pinned_against = read_pins(LEDGER)
    failures = pinned_failures(cites, pins, spec, LEDGER)
    failures += orphan_failures(pins, cites, LEDGER)
    return report(failures, len(cites), LEDGER, REMEDY)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
