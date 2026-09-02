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
  - every decision classified ``forced`` either carries a ``discrimination``
    witness or is named in the registry's ``unwitnessedForced`` declaration --
    EXISTENCE IS NOT DISCRIMINATION, and this gate used to conflate them;
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
    # One directory. A vector used to be looked for under the verdict it
    # carried, which meant this helper had to know the answer before it could
    # find the question.
    return (REPO_ROOT / "vectors" / "statements" / f"{vid}.json").is_file()


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


def _check_discrimination(
    dec: dict[str, Any], declared_unwitnessed: set[Any], live: set[str],
    errors: list[str],
) -> None:
    """A ``forced`` claim must be backed by a vector that can TELL THE READINGS
    APART, not merely by a vector that exists.

    THE DEFECT THIS EXISTS FOR, established by attacking this gate rather than
    reading it. A twenty-first decision was injected carrying a question the
    review thread had left genuinely open -- the constraint set of the sealed
    existential -- classified ``forced`` and citing ``bad-1003`` through
    ``bad-1007``. Those five vectors
    provably cannot discriminate that reading: instrumenting both loops returns
    zero verdict flips, because every dirty seal in the corpus is paired with a
    clean witness. This gate exited 0 on it, and regenerating the coverage
    matrix once publishes it in ``docs/COVERAGE-MATRIX.md`` under
    ``forced-by-vector``.

    So the existence check was real and the discrimination check did not exist,
    while the surface that publishes the result could not tell the difference.
    A vector that runs is evidence the rule is EXERCISED. Only a vector whose
    observable moves when the reading changes is evidence the rule is FORCED.

    The declaration, and why it is not an exemption list. No differential
    harness exists yet, so no decision in this registry can carry a witness
    today. Failing all twenty would say the registry is broken when what is
    true is narrower: the claims are unproven. ``unwitnessedForced`` therefore
    names every such decision explicitly, its count is reported separately so
    the summary line can never again present unproven claims as consistent, and
    -- the clause that stops it becoming permanent -- a decision named there
    that HAS gained a witness is an error. The declaration must retire itself
    per decision as witnesses land, exactly as the coverage exemptions do.
    """
    did = dec.get("id")
    if dec.get("classification") != "forced":
        if dec.get("discrimination") is not None:
            errors.append(
                f"decision {did}: only a forced decision may carry a "
                "discrimination witness; a permitted reading has nothing to "
                "discriminate against"
            )
        return

    witness = dec.get("discrimination")
    declared = did in declared_unwitnessed

    if witness is None:
        if not declared:
            errors.append(
                f"decision {did}: classified forced with no discrimination "
                "witness and no entry in unwitnessedForced. A named vector "
                "proves the rule is exercised, never that the reading is "
                "forced -- declare the rival reading and the observable that "
                "moves, or name the decision in unwitnessedForced"
            )
        return

    if declared:
        errors.append(
            f"decision {did}: named in unwitnessedForced but now carries a "
            "discrimination witness -- remove it from the declaration. A "
            "declaration that no longer flags anything is a stale claim about "
            "what is unproven"
        )

    errors.extend(_witness_faults(did, witness, live))



def _witness_faults(
    did: Any, witness: dict[str, Any], live: set[str]
) -> list[str]:
    """Everything that can be wrong with a discrimination witness.

    Split out from the caller so each half stays readable: the caller decides
    WHETHER a decision owes a witness, and this decides whether the witness it
    carries actually witnesses anything.
    """
    faults: list[str] = []
    required = ("rivalReading", "witnessVector", "observable", "underReading", "underRival")
    for field in required:
        if not str(witness.get(field, "")).strip():
            faults.append(f"decision {did}: discrimination witness is missing {field!r}")
    observable = witness.get("observable")
    if observable not in (None, "verdict", "codes"):
        faults.append(
            f"decision {did}: discrimination observable must be verdict|codes, "
            f"got {observable!r}"
        )
    if witness.get("underReading") == witness.get("underRival"):
        faults.append(
            f"decision {did}: discrimination witness records the same result "
            "under both readings, which is the definition of NOT "
            "discriminating -- this is the shape that must never pass"
        )
    vid = witness.get("witnessVector")
    if vid:
        if not _vector_file_exists(vid):
            faults.append(f"decision {did}: witness vector {vid} has no file")
        elif vid not in live:
            faults.append(
                f"decision {did}: witness vector {vid} is not in MANIFEST.json "
                "(orphaned, would not be replayed)"
            )
    return faults


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

    declaration = registry.get("unwitnessedForced", {})
    declared_ids = {entry.get("id") for entry in declaration.get("decisions", [])}
    known_ids = {d.get("id") for d in decisions}
    for stale in sorted(declared_ids - known_ids, key=str):
        errors.append(
            f"unwitnessedForced names decision {stale}, which is not in the "
            "registry -- a declaration about a decision that does not exist "
            "cannot retire itself"
        )
    if declared_ids and not str(declaration.get("reason", "")).strip():
        errors.append(
            "unwitnessedForced names decisions but states no reason; an "
            "undeclared reason is an exemption wearing a declaration's clothes"
        )

    for dec in decisions:
        _check_decision(dec, live, errors)
        _check_anchors_cover_prose(dec, errors)
        _check_discrimination(dec, declared_ids, live, errors)

    # Open corners must be permitted and carry no forcing vector.
    for corner in registry.get("openCorners", []):
        _check_decision(corner, live, errors)
        _check_anchors_cover_prose(corner, errors)
        _check_discrimination(corner, declared_ids, live, errors)

    if errors:
        print("FAIL: interpretation-decision registry drift.", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    forced = [d for d in decisions if d.get("classification") == "forced"]
    witnessed = [d for d in forced if d.get("discrimination") is not None]
    # Sort numerically when the ids are numbers: a published list reading
    # "1, 10, 11, ... 2, 20" is a lexicographic sort leaking into an artifact
    # a human is expected to scan for a missing id.
    unwitnessed = sorted(
        (d.get("id") for d in forced if d.get("discrimination") is None),
        key=lambda i: (0, i, "") if isinstance(i, int) else (1, 0, str(i)),
    )
    # The summary NEVER again presents an unproven forced claim as consistent:
    # the two populations are counted apart and the unproven ids are named on
    # every run, so the debt is visible rather than folded into one total.
    print(
        f"OK: {len(decisions)} decisions consistent with the live corpus "
        f"({len(live)} vectors). Forced: {len(forced)}, of which "
        f"{len(witnessed)} carry a discrimination witness."
    )
    if unwitnessed:
        print(
            f"    {len(unwitnessed)} forced decision(s) are declared UNWITNESSED "
            "-- exercised by a vector, not yet shown to be forced by one: "
            + ", ".join(str(i) for i in unwitnessed)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
