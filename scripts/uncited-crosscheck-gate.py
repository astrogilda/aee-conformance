#!/usr/bin/env python3
"""Crosscheck the uncited-obligation ledger against the document about it.

Two artifacts describe the same population of normative sentences, and they are
deliberately NOT merged:

  * ``spec/READINGS.toml`` ``[[uncited]]`` rows are the ENFORCED ledger. They
    carry a pinned sentence digest, and ``reading-differential.py`` refuses a
    declaration whose sentence has since gained a citation. Only sentences that
    are STILL uncited appear.
  * ``docs/UNCITED-OBLIGATIONS.md`` is the document a person reads. It covers
    every sentence the sweep examined, INCLUDING the ones since closed by a new
    citation, and carries the remedy and the evidence for each -- content the
    ledger has nowhere to put.

Merging them was proposed and would have lost the closed dispositions, which are
the record of what the sweep actually achieved. Keeping two copies with nothing
comparing them is the other failure, and this repository has been burned by it
often enough to have a name for the shape: two documents, each internally
correct, drifting until they disagree about the size of the thing they describe.

So both stand and this gate holds them together. It refuses when:

  - a ledger row names a sentence the document does not list;
  - the document rules a sentence still-uncited (disposition ``(b)`` or ``(c)``)
    and the ledger does not carry it;
  - the document rules a sentence CLOSED by a citation (disposition ``(a)``)
    while the ledger still declares it uncited -- the direction that would let a
    closed obligation keep counting as open;
  - the two disagree about the line a sentence sits on.

Usage: python3 scripts/uncited-crosscheck-gate.py
Exit 0 when the two agree; 1 when they disagree; 2 when the question could not
be asked, because a parse that found nothing must never report agreement.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
READINGS = REPO_ROOT / "spec" / "READINGS.toml"
DOCUMENT = REPO_ROOT / "docs" / "UNCITED-OBLIGATIONS.md"

# "| L210 | ... | **(a) already satisfied** | ..."
#
# The table is keyed by the line reference and carries no ordinal column. A row
# number is positional -- it renumbers whenever a row is inserted, it is what
# every other document would have to cite the row by, and as a bare integer it
# collides with the corpus census by construction. The line reference is the
# key everything already uses, and it is stable.
#
# THE FOURTH DISPOSITION EXISTS BECAUSE THREE WERE NOT ENOUGH. The vocabulary
# began as (a) a citation now covers it, (b) structurally untestable, (c) it
# should not be normative -- and a real row fitted none of them: a vector was
# written and proved, and the citation STILL cannot be recorded, because the
# accept index carries no spec-anchor column to record it in. Labelled (a), it
# claimed an obligation was closed while the enforced ledger correctly went on
# declaring it uncited, and the two documents disagreed for a reason neither was
# wrong about. (d) names that state: forced by a vector, citation blocked, and
# therefore STILL UNCITED until the blocker is cleared.
ROW = re.compile(r"^\|\s*(L\d+)([^|]*)\|[^|]*\|\s*\*\*\(([abcd])\)")
# A ledger row's sentence field is a bare line reference.
LINE = re.compile(r"^L(\d+)$")


def _fail(msg: str) -> None:
    print(f"  - {msg}", file=sys.stderr)


class Refused(Exception):
    """The question could not be asked. Distinct from a disagreement, and it
    exits 2, because a reader that parsed nothing and two documents that agree
    are the same clean run from outside."""


def read_ledger() -> dict[str, str]:
    """The enforced declarations, keyed by sentence."""
    ledger = tomllib.loads(READINGS.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for row in ledger.get("uncited", []):
        sentence = str(row.get("sentence", "")).strip()
        if not LINE.fullmatch(sentence):
            raise Refused(
                f"ledger row carries sentence {sentence!r}, which is not a bare "
                "line reference this gate can compare"
            )
        out[sentence] = str(row.get("class", ""))
    if not out:
        raise Refused("the ledger parsed to zero uncited rows")
    return out


def read_document() -> dict[str, str]:
    """The documented dispositions, keyed by sentence."""
    out: dict[str, str] = {}
    for line in DOCUMENT.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            out[m.group(1)] = m.group(3)
    if not out:
        raise Refused(
            "the document parsed to zero rows -- the row format changed and this "
            "gate is reading nothing"
        )
    return out


def disagreements(ledger: dict[str, str], document: dict[str, str]) -> list[str]:
    """Every way the two records can contradict each other, in both directions.

    Both directions matter and they fail differently. A ledger row the document
    does not list is an enforced declaration whose reasoning is unrecorded. A
    document row ruled closed while the ledger still declares it uncited is an
    obligation counted as open after it was closed, which is the direction that
    quietly inflates the coverage debt.
    """
    out: list[str] = []
    for sentence in sorted(ledger, key=lambda s: int(s[1:])):
        if sentence not in document:
            out.append(
                f"{sentence}: the ledger declares it uncited and the document "
                "does not list it, so the reasoning behind an enforced "
                "declaration is unrecorded"
            )
        elif document[sentence] == "a":
            out.append(
                f"{sentence}: the document rules it CLOSED by a citation while "
                "the ledger still declares it uncited -- an obligation counted "
                "as open after it was closed"
            )
    for sentence, disposition in sorted(document.items(), key=lambda kv: int(kv[0][1:])):
        if disposition in ("b", "c", "d") and sentence not in ledger:
            out.append(
                f"{sentence}: the document rules it still uncited (disposition "
                f"{disposition}) and no ledger row declares it, so nothing "
                "enforces the declaration"
            )
    return out


def main() -> int:
    for path in (READINGS, DOCUMENT):
        if not path.is_file():
            print(f"REFUSED: {path} is absent", file=sys.stderr)
            return 2
    try:
        ledger = read_ledger()
        document = read_document()
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    problems = disagreements(ledger, document)
    if problems:
        print(
            f"FAIL: the uncited ledger and the document about it disagree on "
            f"{len(problems)} sentence(s).",
            file=sys.stderr,
        )
        for problem in problems:
            _fail(problem)
        return 1

    print(
        f"OK: {len(ledger)} enforced uncited declaration(s) agree with "
        f"{len(document)} documented disposition(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
