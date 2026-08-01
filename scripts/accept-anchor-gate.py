#!/usr/bin/env python3
"""Accept-anchor gate: every refusal in this corpus is paired with a vector
that must be accepted.

Why a reject corpus alone proves nothing
----------------------------------------
A verifier that rejects its input unconditionally passes every reject vector
ever written. Scored against a reject-only corpus it looks perfect, and the
score is the exact inverse of the truth. The cure is a paired accept anchor:
for each refusal, one statement a conforming verifier MUST accept, so that the
reject-everything rail is caught by the pair rather than by anybody's judgement.

The corpus already says this about itself in one place -- ok-047's index row
notes that the three attribution refusals need it beside them "because a rail
that rejects every pinned row satisfies each refusal and is wrong" -- and
nothing checked that the property held anywhere else. This gate checks it, at
two granularities, because they fail differently.

Check 1: every reject vector's parent is a shipped accept vector
----------------------------------------------------------------
Each reject vector is a fully valid parent statement plus exactly one mutation.
When that parent is itself shipped in ``vectors/accept/``, the pair is the
strongest anchor available: two statements one mutation apart, one accepted and
one refused, so a rail cannot satisfy the refusal by refusing the shape. When
the parent is built only in the generator's memory, the refusal ships without
its anchor and a third party running the corpus never sees the accepted half.

This check is binding and is currently satisfied for every reject vector. It is
here to keep it that way: a new reject vector derived from an in-memory-only
parent fails, and the fix is to ship the parent.

Check 2: every condition a refusal cites is cited by an accepting vector
------------------------------------------------------------------------
Vectors cite the rules they exercise as ``aee-c-NN`` ids. When only reject
vectors cite an id, a reader following that id from the registry reaches the
refusals and never reaches a vector showing the satisfied side of the same
rule. That is a traceability gap rather than a coverage hole -- most such
conditions ARE satisfied by accept vectors that simply do not cite them -- and
saying which it is matters, because overstating it would be its own defect.

So check 2 is a measured ratchet, not a pass/fail on zero. The count is printed
on every run and held against ``docs/ACCEPT-ANCHOR-BASELINE.json``: a condition
the baseline records as anchored may not become unanchored, and the unanchored
list may shrink freely. ``--sync`` rewrites the baseline and refuses to write
one in which an anchored condition regressed.

Check 3: the sentences that publish these two figures still say them
--------------------------------------------------------------------
Both numbers appear in prose in ``vectors/CHANGES.md``, and the count census
skips them because it records this script as their owner. An owner that
computes a figure and never reads the sentence quoting it is not an owner: the
delegation would be the one place in the corpus where a published number has no
check behind it, which is the shape of defect the census exists to catch. So
each figure is matched against its own sentence here, and a sentence that has
been reworded away fails as loudly as one carrying a stale value -- a claim
nobody can find is not a claim that passed.

Usage:
    scripts/accept-anchor-gate.py
    scripts/accept-anchor-gate.py --sync
    scripts/accept-anchor-gate.py --manifest P --reject-index P --baseline P
    scripts/accept-anchor-gate.py --changes P
Exit 0 when all three checks hold; 1 otherwise. Inputs that cannot be read, or
that yield nothing, are failures and never a quiet pass: a gate that enforces
nothing must not report success.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
DEFAULT_REJECT_INDEX = REPO_ROOT / "vectors" / "reject" / "INDEX.md"
DEFAULT_BASELINE = REPO_ROOT / "docs" / "ACCEPT-ANCHOR-BASELINE.json"
DEFAULT_CHANGES = REPO_ROOT / "vectors" / "CHANGES.md"

# The published sentences this gate owns, and the values they must carry. The
# patterns are anchored on the prose either side of each number so a reworded
# sentence fails as a missing claim rather than silently stopping being checked.
PARENT_CLAIM = re.compile(
    r"all\s+(\d+)\s+reject\s+vectors\s+declare\s+a\s+parent")
TRACEABILITY_CLAIM = re.compile(
    r"That\s+second\s+number\s+is\s+(\d+)\s+of\s+(\d+)\s+today,")

BASELINE_COMMENT = (
    "Which conditions the reject set cites and no accepting vector does. A "
    "traceability measurement, ratcheted: anchored may not become unanchored, "
    "and the unanchored list may shrink. Regenerate with "
    "scripts/accept-anchor-gate.py --sync -- never by hand, because a list "
    "typed here rather than measured records an intention instead of a fact."
)

# A reject-index vector row: `| `bad-101-refs-empty` | ok-001 | ... `.
# Matched on the first two cells only; the prose in the rest of the row may
# contain anything, including pipes inside code spans.
_ROW = re.compile(r"^\|\s*`(bad-[^`]+)`\s*\|\s*`?([^|`]+?)`?\s*\|")
_PARENT_ID = re.compile(r"^(ok-\d+)")


def load_manifest(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    vectors = data.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise SystemExit(
            f"{path} lists no vectors. A corpus that names nothing cannot be "
            "checked for anchors, and reporting that as a clean run would be "
            "the failure this gate exists to prevent."
        )
    return data


def parent_rows(path: Path) -> dict[str, str]:
    """Vector id -> declared parent, off the reject index's own table."""
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _ROW.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip()
    if not out:
        raise SystemExit(
            f"{path} yielded no vector rows; the table was renamed or its "
            "shape changed. A parse that sees nothing reports every anchor as "
            "present, which is indistinguishable from a corpus that has them."
        )
    return out


def check_parents(manifest: dict[str, Any],
                  parents: dict[str, str]) -> list[str]:
    accept_ids = {v["id"] for v in manifest["vectors"] if v["kind"] == "accept"}
    accept_short = {m.group(1) for i in accept_ids
                    if (m := _PARENT_ID.match(i))}
    reject_ids = [v["id"] for v in manifest["vectors"] if v["kind"] == "reject"]
    errors: list[str] = []
    for vid in reject_ids:
        declared = parents.get(vid)
        if declared is None:
            errors.append(
                f"{vid} is in the manifest and has no row in the reject index, "
                "so its paired accept anchor cannot be named"
            )
            continue
        m = _PARENT_ID.match(declared)
        if m is None or m.group(1) not in accept_short:
            errors.append(
                f"{vid} declares parent {declared!r}, which is not a shipped "
                "accept vector. The refusal ships without the accepted half of "
                "its pair, so a rail that refuses the shape satisfies it"
            )
    return errors


def condition_sides(manifest: dict[str, Any]) -> tuple[set[str], set[str]]:
    """(cited by a reject vector, cited by an accepting vector)."""
    rejected: set[str] = set()
    accepted: set[str] = set()
    for v in manifest["vectors"]:
        conds = {c for c in v.get("conditions", []) if isinstance(c, str)}
        if v["kind"] == "reject":
            rejected |= conds
        else:
            # accept and indeterminate alike: an indeterminate vector is one a
            # conforming rail may accept, so it anchors the satisfied side too.
            accepted |= conds
    if not rejected:
        raise SystemExit(
            "no reject vector cites any condition; the manifest's condition "
            "lists are empty or renamed, and there is nothing to anchor"
        )
    return rejected, accepted


def sort_conditions(ids: set[str]) -> list[str]:
    def key(cid: str) -> tuple[int, str]:
        m = re.match(r"^aee-c-(\d+)$", cid)
        return (int(m.group(1)), "") if m else (10**9, cid)
    return sorted(ids, key=key)


def load_baseline(path: Path, allow_absent: bool) -> dict[str, Any]:
    if not path.is_file():
        if allow_absent:
            return {"anchored": [], "unanchored": []}
        raise SystemExit(
            f"no accept-anchor baseline at {path}; create it with --sync. A "
            "missing baseline is not an empty one: an empty one would record "
            "that nothing is anchored, which is a claim, and an absent file "
            "records nothing at all."
        )
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def check_published(changes: Path, reject_count: int, unanchored: int,
                    cited: int) -> list[str]:
    """The prose quoting these figures still quotes the measured ones."""
    text = changes.read_text(encoding="utf-8")
    errors: list[str] = []

    found = PARENT_CLAIM.search(text)
    if found is None:
        errors.append(
            f"{changes}: the sentence publishing how many reject vectors "
            "declare a shipped parent is gone or reworded, and the count "
            "census skips this span because it records this gate as its owner. "
            "Restore the sentence or move the delegation")
    elif int(found.group(1)) != reject_count:
        errors.append(
            f"{changes}: publishes {found.group(1)} reject vectors declaring a "
            f"shipped parent; the manifest holds {reject_count}")

    found = TRACEABILITY_CLAIM.search(text)
    if found is None:
        errors.append(
            f"{changes}: the sentence publishing the traceability figure is "
            "gone or reworded, and nothing else checks it")
    elif (int(found.group(1)), int(found.group(2))) != (unanchored, cited):
        errors.append(
            f"{changes}: publishes {found.group(1)} of {found.group(2)} "
            f"conditions cited only by refusals; the measurement is "
            f"{unanchored} of {cited}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(
        description="every refusal is paired with a vector that must be accepted")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--reject-index", type=Path, default=DEFAULT_REJECT_INDEX)
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--changes", type=Path, default=DEFAULT_CHANGES,
                    help="the document publishing these figures in prose")
    ap.add_argument("--sync", action="store_true",
                    help="rewrite the baseline from the measurement")
    args = ap.parse_args()

    for path in (args.manifest, args.reject_index, args.changes):
        if not path.is_file():
            print(f"FAIL: {path} does not exist", file=sys.stderr)
            return 1

    manifest = load_manifest(args.manifest)
    parents = parent_rows(args.reject_index)

    errors = check_parents(manifest, parents)
    reject_count = sum(1 for v in manifest["vectors"] if v["kind"] == "reject")
    print(f"check 1: {reject_count - len(errors)} of {reject_count} reject "
          "vectors declare a parent that ships as an accept vector")

    rejected, accepted = condition_sides(manifest)
    anchored = sort_conditions(rejected & accepted)
    unanchored = sort_conditions(rejected - accepted)
    print(f"check 2: {len(anchored)} of {len(rejected)} conditions cited by a "
          f"refusal are also cited by an accepting vector; "
          f"{len(unanchored)} are not")
    if unanchored:
        print("         unanchored: " + " ".join(unanchored))
        print("         (a traceability gap: a reader following one of these "
              "ids from the registry reaches only refusals. Most are satisfied "
              "by accept vectors that do not cite them, which is why this is "
              "measured and ratcheted rather than failed on zero.)")

    errors += check_published(args.changes, reject_count, len(unanchored),
                              len(rejected))

    baseline = load_baseline(args.baseline, allow_absent=args.sync)
    was_anchored = set(baseline.get("anchored", []))
    regressed = sort_conditions(was_anchored & set(unanchored))
    for cid in regressed:
        errors.append(
            f"{cid} was anchored by an accepting vector in the baseline and is "
            "now cited only by refusals; the anchor was removed or its citation "
            "was dropped"
        )

    if args.sync:
        if regressed:
            print("FAIL: refusing to write a baseline in which an anchored "
                  "condition regressed:", file=sys.stderr)
            for e in errors:
                print(f"  {e}", file=sys.stderr)
            return 1
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(
            json.dumps({"$comment": BASELINE_COMMENT,
                        "anchored": anchored,
                        "unanchored": unanchored},
                       indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"wrote {args.baseline}: {len(anchored)} anchored, "
              f"{len(unanchored)} unanchored")
        return 0

    if errors:
        print("FAIL: a refusal is missing the vector that pairs with it, or a "
              "published figure no longer follows from the corpus.",
              file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print("OK: every reject vector ships beside the accept vector it was "
          "derived from, no anchored condition regressed, and the prose "
          "publishing both figures carries the measured ones.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
