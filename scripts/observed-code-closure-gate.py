#!/usr/bin/env python3
"""Observed-code closure: the reference rail may not emit a code nobody declared.

Why this exists, stated as what actually happened rather than as a principle.

`v4ff6cb70764bf703` declares two codes -- `record-undecodable`
in its expectation and `observed-set-mismatch` in its `also carries` clause --
and the reference rail emits FOUR. The other two, `payload-not-canonical` and
`reconstructed-row-uncovered`, were declared nowhere at all. During the
corpus-wide rewrite of suiteRevision 27 the vector's declared parent moved from
a caught row to a reconstructed one, and one of those two undeclared codes moved
with it, from `caught-row-uncovered` to `reconstructed-row-uncovered`. The change
was correct. Nothing in this repository refused, and nothing could have: a reject
vector is graded by INTERSECTING the emitted set with the declared one, so an
emitted code outside the declared set is compared against nothing whatsoever.

That is a hole in a suite whose purpose is forcing two implementers to agree. A
rail could emit different secondary codes on every release and pass every gate.
Measured over the whole corpus on the day this gate was written, and before the
same revision added `ok-055` and `bad-986`, nineteen of the vectors then shipped
were in that state -- 17 reject and both indeterminate members -- with 24
undeclared emissions between them, `caught-row-uncovered` accounting for ten.
`bad-817` was neither typical nor alone.

WHAT THIS GATE IS NOT. It is not part of the comparison surface, and no third
party's obligations change because it exists. `vectors/MANIFEST.json` declares
the verdict and an accepted statement's result token normative and the condition
codes measured, and README says in as many words that "a strict single-code
implementation and a superset-emitting one certify against one manifest". A
second rail is still neither required to emit what this rail emits nor failed for
emitting more. That is exactly why this check is a gate over the REFERENCE rail
and not a rule inside `packaging/run_vectors.py`: the replay runs over external
rails too, and a closure rule added there would have promoted this repository's
private vocabulary into an obligation on everyone who replays the corpus, which
is the one thing the manifest promises not to do.

WHAT IT IS. `expected.alsoEmits` in the manifest, written from an `(also emits:
...)` clause in the index row, pins what the reference rail reports beyond the
codes the vector declares. The pin is checked in both directions:

- an emitted code declared in no field is a refusal, naming the vector and the
  code, because the corpus is then carrying observable output nobody wrote down;
- a code pinned in `alsoEmits` that the rail no longer emits is also a refusal,
  because a pin that has stopped describing the vector is what hides the next
  change to it.

Sibling of `scripts/expectation-slack-gate.py`, which measures the opposite
error: that one refuses an expectation satisfied by more than one code the
statement emits, this one refuses a code the statement emits that no expectation
mentions. Between them the declared set and the emitted set are pinned from both
ends.

Usage: python3 scripts/observed-code-closure-gate.py
Exit 0 when every emitted code is declared and every pinned code is emitted;
1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402


def declared_codes(expected: dict[str, Any]) -> set[str]:
    """Every code any field of one manifest entry names.

    The union deliberately spans fields that mean different things -- an
    expectation, a deliberate companion fault, a declared reading, a recorded
    emission -- because the question this gate asks is not what a code MEANS but
    whether anybody wrote it down at all.
    """
    named: set[str] = set()
    for field in ("codes", "alsoCarries", "alsoEmits"):
        named |= {str(c) for c in (expected.get(field) or [])}
    named |= {str(v) for v in (expected.get("readings") or {}).values()}
    return named


def observed_codes(verifier: Any, path: Path) -> tuple[str, ...]:
    """The codes the reference rail reports for one vector.

    Read through the harness's own loader rather than a plain json.loads, so a
    byte-level vector -- whose whole fault is that it is not JSON -- is observed
    here exactly as the replay observes it instead of being skipped. The verifier
    answers from the raw bytes when there is no faithful value, which is the case
    this gate most wants to cover: several of the unpinned emissions found on the
    day it was written are on vectors of exactly that shape.
    """
    raw = path.read_bytes()
    stmt, _faithful = run_vectors._load_statement(raw)
    return tuple(sorted(str(c) for c in verifier.verify(stmt, raw).codes))


class Findings:
    """What one pass over the corpus learned.

    `emitting` is the positive control and not a decoration. Every refusal here
    is an assertion about a set the rail produced, so a run in which the rail
    produced nothing at all would report a clean corpus for a check that never
    reached a single code. The count is asserted below rather than printed.
    """

    def __init__(self) -> None:
        self.unpinned: list[tuple[str, tuple[str, ...]]] = []
        self.dead: list[tuple[str, tuple[str, ...]]] = []
        self.unreadable: list[str] = []
        self.examined = 0
        self.emitting = 0

    def visit(self, verifier: Any, entry: dict[str, Any]) -> None:
        vid = str(entry.get("id"))
        rel = entry.get("file")
        path = REPO_ROOT / "vectors" / str(rel)
        if not rel or not path.is_file():
            self.unreadable.append(f"{vid} names {rel!r}, which is not on disk")
            return
        expected = entry.get("expected")
        if not isinstance(expected, dict):
            self.unreadable.append(f"{vid} carries no expected object")
            return
        try:
            observed = observed_codes(verifier, path)
        except (OSError, ValueError, RecursionError) as exc:
            # Never a finding about the vector: a read that did not complete and
            # a vector that emits nothing are different states, and only one of
            # them is a fact about the corpus.
            self.unreadable.append(f"{vid} could not be observed: {exc}")
            return
        self.examined += 1
        if observed:
            self.emitting += 1
        named = declared_codes(expected)
        if unpinned := tuple(sorted(set(observed) - named)):
            self.unpinned.append((vid, unpinned))
        pinned = {str(c) for c in (expected.get("alsoEmits") or [])}
        if dead := tuple(sorted(pinned - set(observed))):
            self.dead.append((vid, dead))


def report(found: Findings) -> int:
    if not (found.unpinned or found.dead or found.unreadable):
        print(
            f"OK: {found.examined} vectors replayed on the reference rail, "
            f"{found.emitting} of them emitting at least one code — every emitted "
            "code is declared and every code declared as emitted is still emitted."
        )
        return 0
    print(
        "FAIL: the reference rail's own output is not pinned by the corpus that "
        "publishes it:",
        file=sys.stderr,
    )
    for vid, codes in sorted(found.unpinned):
        print(
            f"  - {vid} emits {list(codes)}, which no field of its manifest entry "
            "names. A reject vector is graded by intersecting the emitted set with "
            "the declared one, so this code is compared against nothing and may "
            "change without any gate refusing. Add it to the row's `(also emits: "
            "...)` clause in the index, which records what this rail reports "
            "without obliging any other rail to report it.",
            file=sys.stderr,
        )
    for vid, codes in sorted(found.dead):
        print(
            f"  - {vid} pins {list(codes)} as also emitted and the rail no longer "
            "emits them. A pin that has stopped describing the vector is what "
            "hides the next change to it; drop the code from the clause in the "
            "same change that stopped emitting it.",
            file=sys.stderr,
        )
    for line in found.unreadable:
        print(f"  - {line}", file=sys.stderr)
    return 1


def main() -> int:
    if not MANIFEST.is_file():
        print(
            f"FAIL: {MANIFEST} is absent, so no expectation was read and nothing "
            "here is a statement about any vector.",
            file=sys.stderr,
        )
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        print(
            "FAIL: the manifest lists no vectors, so the check did not run.",
            file=sys.stderr,
        )
        return 1

    keys = run_vectors.derive_test_keys()
    # The pinned key, matching the rail the replay scores and the report records.
    # Observed with no key the substrate rows would tier differently and the code
    # sets this gate pins would be a different rail's, which is the "gate sees a
    # different tree" failure with a green tick on it.
    verifier = run_vectors.ReferenceVerifier([keys[run_vectors.PINNED_ROLE]["public"]])
    found = Findings()
    for entry in entries:
        if isinstance(entry, dict):
            found.visit(verifier, entry)

    if found.emitting == 0:
        # The count comes off the manifest rather than out of this sentence: a
        # figure typed here would be a copy that goes stale on the next corpus
        # change, and the whole point of the branch is that the reader can see
        # the two numbers disagree.
        rejects = sum(1 for e in entries if isinstance(e, dict) and e.get("kind") == "reject")
        print(
            "FAIL: not one of the vectors replayed emitted a single code. The "
            f"manifest lists {rejects} reject vectors, so this is a broken read "
            "path and not a clean corpus; a closure check that reached no code "
            "cannot report closure.",
            file=sys.stderr,
        )
        return 1
    return report(found)


if __name__ == "__main__":
    raise SystemExit(main())
