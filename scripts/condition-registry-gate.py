#!/usr/bin/env python3
"""Condition-registry gate.

A vector cites the specification rules it forces as ``aee-c-NN`` condition ids.
The id is the normative link between the vector and the rule: it is how a reader
gets from "this statement must be rejected" to the sentence that says so. An id
that resolves to no registry row is a rule reference nobody can follow, and it
fails silently, because a citation that points nowhere looks exactly like a
citation that points somewhere until someone tries to follow it.

Both index files said the registry lived in the repository README. It never did,
in any revision of this repository, and the table that does exist -- the
condition table in ``vectors/reject/INDEX.md`` -- was generated from the ids the
REJECT set happened to use. Every id carried only by an accept vector was
therefore cited by a live vector and registered nowhere: 17 of them, including
several that also sit on the separately measured weak-forcing list, which is how
a condition ends up existing in name only.

This gate asks both halves of the question, because a registry with dead rows
misleads a reader exactly as much as one with missing rows:

  - every condition id any vector in ``vectors/MANIFEST.json`` cites has a row in
    the registry;
  - every registry row names a condition at least one vector cites;
  - no id is registered twice, since two rows for one id can disagree;
  - every row carries a resolvable ``Lnnn`` spec anchor and a condition text, so
    a row cannot be present-but-empty, which reads as registered while resolving
    to nothing;
  - a row may be marked ``UNRESOLVED`` when the condition's meaning could not be
    established from the specification and the rails. Those rows are counted and
    printed on every run rather than passing quietly, because the marker exists
    to keep a guess out of the table, not to hide one.

It also refuses to pass on an empty reading of either side. A registry the gate
parsed no rows out of, or a manifest naming no conditions, fails rather than
being vacuously consistent: a check that enforces nothing must not report
success, and every way this file could stop seeing its inputs ends in the same
empty-set reading that would otherwise be indistinguishable from a clean run.

Usage:
    python3 scripts/condition-registry-gate.py
    python3 scripts/condition-registry-gate.py --manifest P --registry P
Exit 0 when the registry and the corpus agree; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
REGISTRY = REPO_ROOT / "vectors" / "reject" / "INDEX.md"

# A condition id as a vector cites it. Anchored and zero-intolerant: `aee-c-07`
# and `aee-c-3x` are not this id in another spelling, they are an id nothing can
# resolve, and a lenient parse would file them under a row they do not name.
CONDITION_RE = re.compile(r"^aee-c-([1-9][0-9]*)$")

# A registry row: `| aee-c-3 | L393-395 | ... |`. Matched on the first cell so
# the vector table below it, whose rows carry condition ids in a later cell,
# cannot be read as registry rows.
ROW_RE = re.compile(r"^\|\s*aee-c-([0-9]+)\s*\|([^|]*)\|(.*)\|\s*$")

# What a spec anchor cell must contain at least one of. A row may carry several
# (`L3; L286`), and scripts/spec-anchor-gate.py is what checks that each one
# still addresses the prose it was drawn around; all this gate asks is that the
# cell cites something at all.
ANCHOR_RE = re.compile(r"\bL[0-9]+(?:-[0-9]+)?\b")

UNRESOLVED = "UNRESOLVED"

REMEDY = (
    "The registry is the condition table in vectors/reject/INDEX.md, generated "
    "from COND in vectors/reject/gen_invalid_vectors.py. Add or remove the row "
    "there and regenerate with `python3 gen_invalid_vectors.py`. A condition "
    "whose meaning cannot be established from the specification and the rails "
    "is registered with the UNRESOLVED marker and its candidate reading, never "
    "with a guess written as a resolved rule."
)


def cited_conditions(manifest_path: Path) -> tuple[dict[str, list[str]], list[str]]:
    """Every condition id the corpus cites, mapped to the vectors citing it."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cited: dict[str, list[str]] = {}
    errors: list[str] = []
    for vector in manifest.get("vectors", []):
        vid = str(vector.get("id", "<unnamed>"))
        for cond in vector.get("conditions", []):
            if not CONDITION_RE.match(str(cond)):
                errors.append(
                    f"vector {vid} cites {cond!r}, which is not a condition id "
                    "(aee-c-N, N a positive integer with no leading zero), so "
                    "no registry row can name it"
                )
                continue
            cited.setdefault(str(cond), []).append(vid)
    return cited, errors


def registry_rows(registry_path: Path) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Every registered id, mapped to its (spec anchor, condition) cells."""
    rows: dict[str, tuple[str, str]] = {}
    errors: list[str] = []
    for lineno, line in enumerate(
        registry_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = ROW_RE.match(line)
        if not match:
            continue
        cid = f"aee-c-{match.group(1)}"
        anchor, condition = match.group(2).strip(), match.group(3).strip()
        site = f"{registry_path.name}:{lineno}"
        if cid in rows:
            errors.append(
                f"{site}: {cid} is registered twice; two rows for one id can "
                "disagree, and a reader has no way to tell which is the rule"
            )
            continue
        errors.extend(_row_content_failures(cid, anchor, condition, site))
        rows[cid] = (anchor, condition)
    return rows, errors


def _row_content_failures(
    cid: str, anchor: str, condition: str, site: str
) -> list[str]:
    """A row that is present but says nothing resolves to nothing while reading,
    to anything that only counts rows, as registered."""
    failures: list[str] = []
    if not ANCHOR_RE.search(anchor):
        failures.append(
            f"{site}: {cid} carries no Lnnn spec anchor (cell: {anchor!r}), so "
            "the row registers an id without naming the rule it stands for"
        )
    if len(condition.replace(UNRESOLVED, "").strip(" -.?")) < 8:
        failures.append(
            f"{site}: {cid} carries no condition text (cell: {condition!r}); a "
            "placeholder row is worse than a missing one because it looks "
            "resolved"
        )
    return failures


def reconcile(
    cited: dict[str, list[str]], rows: dict[str, tuple[str, str]]
) -> list[str]:
    """Both directions. A dead row misleads a reader as much as a missing one."""
    errors: list[str] = []
    for cid in sorted(set(cited) - set(rows), key=_order):
        vectors = ", ".join(sorted(cited[cid]))
        errors.append(
            f"{cid} is cited by {vectors} and has no registry row, so the rule "
            "those vectors force resolves to nothing"
        )
    for cid in sorted(set(rows) - set(cited), key=_order):
        errors.append(
            f"{cid} has a registry row ({rows[cid][0]}) and is cited by no "
            "vector, so the registry advertises a condition the corpus does "
            "not exercise"
        )
    return errors


def _order(cid: str) -> int:
    return int(cid.rsplit("-", 1)[1])


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    args = parser.parse_args(argv[1:])

    for path in (args.manifest, args.registry):
        if not path.is_file():
            print(f"FAIL: {path} does not exist", file=sys.stderr)
            return 1

    cited, errors = cited_conditions(args.manifest)
    rows, row_errors = registry_rows(args.registry)
    errors += row_errors

    # An empty reading of either side is a broken check, never a clean one.
    if not cited:
        errors.append(
            f"{args.manifest} names no condition ids at all; a corpus citing "
            "nothing cannot be reconciled against a registry, and reporting "
            "that as consistent would be a gate enforcing nothing"
        )
    if not rows:
        errors.append(
            f"{args.registry} yielded no registry rows; the table was renamed, "
            "emptied or reshaped, and every id the corpus cites is unresolvable"
        )
    if cited and rows:
        errors += reconcile(cited, rows)

    if errors:
        print("FAIL: condition registry and corpus disagree.", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(f"\n{REMEDY}", file=sys.stderr)
        return 1

    unresolved = sorted(
        (cid for cid, (_, text) in rows.items() if UNRESOLVED in text), key=_order
    )
    print(
        f"OK: {len(rows)} registered conditions, all cited; "
        f"{len(cited)} cited conditions, all registered."
    )
    if unresolved:
        print(
            f"    {len(unresolved)} marked UNRESOLVED (candidate reading "
            f"recorded, not asserted): {', '.join(unresolved)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
