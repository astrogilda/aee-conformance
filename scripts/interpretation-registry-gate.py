#!/usr/bin/env python3
"""Interpretation-decision registry gate.

``vectors/interpretation-decisions.json`` records, for each interpretation
decision a from-spec AEE v0.6 verifier must make, whether the spec FORCES the
reading or merely PERMITS it, and names the corpus vectors that lock every
forced reading. This gate asserts the registry stays honest:

  - every decision classified ``forced`` names at least one forcing vector;
  - every named forcing vector is a live vector -- its file exists under
    ``vectors/accept/`` or ``vectors/reject/`` AND it appears in
    ``vectors/MANIFEST.json`` (so it is actually replayed, not orphaned);
  - a ``permitted`` decision names no forcing vector (a permitted reading must
    not be silently locked; contested corners live in ``openCorners`` and are
    documented in ``docs/interpretation-decisions-open.md``);
  - an entry's ``specAnchors`` covers every line reference the entry's own prose
    makes, so the machine-readable citation and the quotation beside it cannot
    name different passages.

Usage: python3 scripts/interpretation-registry-gate.py
Exit 0 when the registry is consistent with the live corpus; 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = REPO_ROOT / "vectors" / "interpretation-decisions.json"
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"


def _live_vector_ids() -> set[str]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {v["id"] for v in manifest.get("vectors", [])}


def _vector_file_exists(vid: str) -> bool:
    return (REPO_ROOT / "vectors" / "accept" / f"{vid}.json").is_file() or (
        REPO_ROOT / "vectors" / "reject" / f"{vid}.json"
    ).is_file()


def _check_decision(
    dec: dict[str, Any], live: set[str], errors: list[str]
) -> None:
    did = dec.get("id")
    classification = dec.get("classification")
    vectors = dec.get("forcingVectors", [])
    if classification == "forced":
        if not vectors:
            errors.append(f"decision {did}: forced but names no forcing vector")
            return
        for vid in vectors:
            if not _vector_file_exists(vid):
                errors.append(f"decision {did}: forcing vector {vid} has no file")
            elif vid not in live:
                errors.append(
                    f"decision {did}: forcing vector {vid} is not in MANIFEST.json "
                    "(orphaned, would not be replayed)"
                )
    elif classification == "permitted":
        if vectors:
            errors.append(
                f"decision {did}: permitted readings must not be locked, but it "
                f"names forcing vectors {vectors}"
            )
    else:
        errors.append(
            f"decision {did}: classification must be forced|permitted, got "
            f"{classification!r}"
        )


ANCHOR_RE = re.compile(r"\bL(\d+)(?:-(\d+))?\b")


def _span(token: re.Match[str]) -> tuple[int, int]:
    lo = int(token.group(1))
    return lo, int(token.group(2)) if token.group(2) else lo


def _check_anchors_cover_prose(dec: dict[str, Any], errors: list[str]) -> None:
    """An entry's ``specAnchors`` must cover every line reference the entry's own
    prose makes.

    The two fields are one citation written twice: ``specAnchors`` is what the
    tools read and publish, and the reading quotes the spec and names the lines
    the quotation came from. Nothing compared them, and four entries drifted
    apart, each with an anchor sitting exactly two lines above the prose the
    same entry quotes. In every case the anchor stopped short of the words the
    reading puts in quotation marks, so the machine-readable field pointed at
    text that does not contain the rule the entry is about.

    The anchor gate cannot see this. It asks whether an anchor still addresses
    the text it was recorded against, which a wrong anchor does perfectly well,
    and both fields are pinned, so it will preserve the disagreement
    indefinitely. Comparing the pair is the only thing that catches it, and it
    catches the class rather than the four instances that were found by eye.
    """
    anchors = [
        _span(m)
        for a in dec.get("specAnchors", [])
        if (m := ANCHOR_RE.fullmatch(str(a)))
    ]
    for field in ("title", "reading"):
        for m in ANCHOR_RE.finditer(str(dec.get(field, ""))):
            lo, hi = _span(m)
            if not any(a <= lo and hi <= b for a, b in anchors):
                errors.append(
                    f"decision {dec.get('id')}: the {field} cites {m.group(0)}, "
                    f"which no entry of specAnchors {dec.get('specAnchors')} "
                    "covers, so the two disagree about which lines carry the "
                    "rule"
                )


def main() -> int:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    live = _live_vector_ids()
    errors: list[str] = []

    decisions = registry.get("decisions", [])
    if not decisions:
        print("FAIL: registry names no decisions", file=sys.stderr)
        return 1
    for dec in decisions:
        _check_decision(dec, live, errors)
        _check_anchors_cover_prose(dec, errors)

    # Open corners must be permitted and carry no forcing vector.
    for corner in registry.get("openCorners", []):
        _check_decision(corner, live, errors)
        _check_anchors_cover_prose(corner, errors)

    if errors:
        print("FAIL: interpretation-decision registry drift.", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    forced = sum(1 for d in decisions if d.get("classification") == "forced")
    print(
        f"OK: {len(decisions)} decisions ({forced} forced) consistent with the "
        f"live corpus ({len(live)} vectors)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
