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
    documented in ``docs/interpretation-decisions-open.md``).

Usage: python3 scripts/interpretation-registry-gate.py
Exit 0 when the registry is consistent with the live corpus; 1 otherwise.
"""

from __future__ import annotations

import json
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

    # Open corners must be permitted and carry no forcing vector.
    for corner in registry.get("openCorners", []):
        _check_decision(corner, live, errors)

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
