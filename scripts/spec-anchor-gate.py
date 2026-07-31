#!/usr/bin/env python3
"""Spec anchor gate.

The corpus cites the vendored predicate specification two ways. Code comments
use ``spec:NNN``, which ``scripts/spec-citation-gate.py`` checks. Tables a reader
scans -- the vector generator, the interpretation registries, and the documents
generated from them -- use ``Lnnn`` and ``Lnnn-mmm`` anchors, and until this gate
existed nothing checked those at all.

They rotted, exactly as line numbers into a periodically re-vendored file always
will. The anchors were migrated by hand once and then left behind by eleven
successive re-vendorings, so by the time anyone looked they addressed prose
hundreds of lines away from the rules they claimed to cite. A wrong anchor is
worse than no anchor, because it reads as evidence that a vector was written
against a passage it was never written against.

Two questions have to stay answered, and they need different checks.

*Does the anchor resolve?* Every endpoint must be inside the file, ordered, and
on a line that carries text. This is cheap and catches the crude failures, and
it is nowhere near sufficient: a line-range check passes for any number that
happens to land on prose, which is why anchors sat hundreds of lines wrong
while the sibling citation gate ran green on every build.

*Does the anchor still address the text it was recorded against?* This is the
question that catches the rot, and answering it needs something committed to
compare with. ``spec/ANCHOR-PINS.json`` records, for every citation, a digest of
the span's text plus its opening and closing lines in plain sight. The gate
recomputes and fails, naming the citation and printing both excerpts, the moment
an anchor addresses different bytes than the ones it was pinned to.

The pin machinery lives in ``scripts/specpins.py``, because the ``spec:NNN``
spelling needs the same record for the same reason and a second copy of the rule
would be free to drift from this one. What stays here is what is genuinely
particular to the anchors: which files carry them, what a citation belongs to,
and the generated tables that must be regenerated when the anchors move. The
shared module documents why the pin is keyed by the citing site rather than by
the line range, which is the property the whole check rests on.

Why this is the right strength. It is deliberately weaker than checking the
anchor against the wording of the claim beside it: it never requires the cited
passage to contain particular words, so upstream may rewrite that passage freely
and ``scripts/vendor-spec.py`` re-pins in the same pass that remaps the anchors,
which keeps an ordinary re-vendor a one-command operation. It is much stronger
than a range check, because it fails on precisely the event that defines the
defect, an anchor coming to address prose it was not drawn around. And because
the pin carries readable excerpts rather than a bare digest, a changed anchor
shows up in review as the prose it now points at, sitting next to the claim it
is supposed to support, which is the one part of the judgement a numeric gate
cannot make on anyone's behalf.

An anchor may also shrink, and that is the same defect wearing a friendlier
shape. A range that still opens on its subject and now closes before prose it
used to cover asserts the same claim over less of the document than it was drawn
around, so ``--sync`` refuses it and prints the lines it dropped, whether they
were lost by a remap or removed by hand. Narrowing an anchor onto the paragraph
that actually states a rule is a correction and stays available, by name, one
key at a time. The point is only that it is said rather than assumed.

What it does not do is decide whether a freshly written anchor cites the right
rule. Nothing mechanical can read a claim and judge which paragraph settles it.
The gate makes that a review question with the evidence attached rather than an
invisible one, and it makes the systematic failure, hundreds of anchors going
quietly wrong at once because a re-vendor moved the prose, impossible to commit.

Usage:
    python3 scripts/spec-anchor-gate.py           # check
    python3 scripts/spec-anchor-gate.py --sync    # rewrite the pin ledger
    python3 scripts/spec-anchor-gate.py --sync --accept-reaim <citation-key>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

from specpins import (
    REPO_ROOT,
    Cited,
    Ledger,
    orphan_failures,
    pinned_failures,
    report,
    resolution_failures,
    spec_state,
    sync,
)

SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"

LEDGER = Ledger(
    path=REPO_ROOT / "spec" / "ANCHOR-PINS.json",
    spec_rel=SPEC_REL,
    token_field="anchor",
    noun="anchor",
    article="an",
    token_re=re.compile(r"L(\d+)(?:-(\d+))?"),
)

# Files whose anchors are written by hand. The pin ledger is synced from these
# and from nothing else, so a generated file that was not regenerated after a
# re-vendor still carries the old anchors, finds no pin for them, and fails.
AUTHORED = (
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/interpretation-decisions.json",
    "vectors/coverage-unforced.json",
    "vectors/CHANGES.md",
    "docs/interpretation-decisions-open.md",
)

# Files generated from those. Their anchors are checked but never pinned.
GENERATED = (
    "vectors/reject/INDEX.md",
    "docs/COVERAGE-MATRIX.md",
)

ANCHOR_RE = re.compile(r"\bL(\d+)(?:-(\d+))?\b")

REMEDY = (
    "An anchor that no longer addresses the text it was pinned to is citing "
    "prose it was not drawn around. Re-vendor with scripts/vendor-spec.py, "
    "which remaps the anchors and re-pins them, or correct the anchor by hand "
    "and run this gate with --sync. Regenerate the corpus and the coverage "
    "matrix so the generated tables carry the corrected anchors too."
)

# What a citation belongs to. A pin has to be found again after the spec has
# moved under it, so it is filed under the thing doing the citing rather than
# under a line number: this vector, this condition, this registry decision, this
# section of prose. Adding a vector then disturbs one entry instead of shifting
# every entry below it.
OWNERS = (
    re.compile(r'^vec\("([a-z0-9-]+)"'),                 # a reject vector
    # A condition table row. The anchor cell is matched loosely because a row may
    # carry several anchors; requiring a single one filed the extra anchors of a
    # multi-anchor condition under whichever row happened to precede it.
    re.compile(r'^\s*(\d+): \("L'),
    re.compile(r'^\s*"id":\s*"?([^",]+)"?,'),            # a registry entry
    re.compile(r"^#{1,6}\s+(.+?)\s*$"),                  # a prose section
    re.compile(r"^def (\w+)"),                           # generator prose
)


@dataclass(frozen=True)
class Anchor(Cited):
    """A citation plus the row it belongs to, which only the generated tables
    need: a generated row is compared against the row its own source records."""

    owner: str


# The row a generated table line belongs to. A generated table is checked against
# the source it was generated from, and that comparison is only meaningful per
# row: asking whether an anchor appears anywhere in the authored set passes for a
# stale row whenever the number it carries is still cited by some unrelated
# entry, which is common here because neighbouring rules share spans.
GENERATED_ROWS = (
    re.compile(r"^\|\s*`?(bad-\d[a-z0-9-]*)`?\s*\|"),  # a reject-index vector row
    re.compile(r"^\|\s*aee-c-(\d+)\s*\|"),             # a reject-index condition row
    re.compile(r"^\|\s*(D\d+|U\d+)\s"),                # a coverage-matrix row
)


def owner_of(line: str) -> str | None:
    for pattern in OWNERS:
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return None


def row_owner(line: str) -> str | None:
    """The identifier in a generated table row's first cell, in the spelling the
    authored source files it under. The matrix prints a registry decision as
    ``D13`` where the registry itself records the id ``13``."""
    for pattern in GENERATED_ROWS:
        m = pattern.match(line)
        if m:
            name = m.group(1)
            return name[1:] if name[0] == "D" and name[1:].isdigit() else name
    return None


def collect(paths: tuple[str, ...]) -> list[Anchor]:
    found: list[Anchor] = []
    for rel in paths:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        owner = "-"
        seen: dict[str, int] = {}
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            named = owner_of(line)
            if named:
                owner = named
            for m in ANCHOR_RE.finditer(line):
                lo = int(m.group(1))
                hi = int(m.group(2)) if m.group(2) else lo
                base = f"{rel}::{owner}"
                seen[base] = seen.get(base, -1) + 1
                found.append(
                    Anchor(
                        key=f"{base}#{seen[base]}",
                        token=m.group(0),
                        lo=lo,
                        hi=hi,
                        site=f"{rel}:{lineno}",
                        owner=row_owner(line) or owner,
                    )
                )
    return found


def generated_failures(
    generated: list[Anchor], authored: list[Anchor], spec: list[str]
) -> list[str]:
    """A generated table carries the anchors its source carries, so a row naming
    an anchor its own source does not is a row that was written before the
    anchors moved and never regenerated, leaving a reader a stale table and no
    warning.

    The question is asked per row. Asking whether the anchor appears anywhere in
    the authored set is this same check with the row thrown away, and it passes
    for a stale row whenever the number it carries is still cited by some other
    entry. Neighbouring rules here share spans constantly, so that is the common
    case rather than the exotic one, and the check was answering a question
    nobody had asked.
    """
    live_rows: dict[str, set[str]] = {}
    for cite in authored:
        live_rows.setdefault(cite.owner, set()).add(cite.token)
    live = {c.token for c in authored}
    failures: list[str] = []
    for cite in generated:
        failures.extend(
            f"{cite.site}: {cite.token} {b}"
            for b in resolution_failures(cite, spec)
        )
        row = live_rows.get(cite.owner)
        if row is not None and cite.token not in row:
            failures.append(
                f"{cite.site}: {cite.token} is not among the anchors the source "
                f"records for {cite.owner} ({', '.join(sorted(row))}), so this "
                "generated row was not regenerated after the anchors moved."
            )
        # An anchor in a generated file's prose rather than in one of its rows
        # has no row to key on, so it keeps the weaker whole-file question.
        elif row is None and cite.token not in live:
            failures.append(
                f"{cite.site}: {cite.token} is cited by no source file, so this "
                "generated table was not regenerated after the anchors moved."
            )
    return failures


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the pin ledger from the anchors as they now stand",
    )
    ap.add_argument(
        "--accept-reaim",
        action="append",
        default=[],
        metavar="KEY",
        help="one citation key whose move onto different prose is intended",
    )
    args = ap.parse_args(argv[1:])
    if args.sync:
        return sync(LEDGER, list(collect(AUTHORED)), set(args.accept_reaim))

    spec, _digest = spec_state(SPEC_REL)
    if not LEDGER.path.is_file():
        print(
            f"FAIL: {LEDGER.path.relative_to(REPO_ROOT)} is missing; create it "
            "with python3 scripts/spec-anchor-gate.py --sync",
            file=sys.stderr,
        )
        return 1
    pins: dict[str, dict[str, str]] = json.loads(
        LEDGER.path.read_text(encoding="utf-8")
    ).get("citations", {})
    authored = collect(AUTHORED)
    generated = collect(GENERATED)
    failures = pinned_failures(list(authored), pins, spec, LEDGER)
    failures += generated_failures(generated, authored, spec)
    failures += orphan_failures(pins, list(authored), LEDGER)
    return report(failures, len(authored) + len(generated), LEDGER, REMEDY)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
