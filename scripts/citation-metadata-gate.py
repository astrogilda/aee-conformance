#!/usr/bin/env python3
"""Citation-metadata gate: the two files that decide how this corpus is cited
must parse, must agree with each other, and must carry an identifier that is
arithmetically well-formed.

Why this exists. `.zenodo.json` and `CITATION.cff` are the entire citation
identity of a repository whose stated purpose is to be cited by a conformance
requirement. Nothing checked them. They were correct on the day they were
written and checked by nothing on any day after, which is the same shape as a
gate that has never been watched to fail: it reads as a safeguard and holds
nothing up.

The failure modes this refuses, each of which is silent without it:

1. `CITATION.cff` stops being valid YAML. GitHub's "Cite this repository" panel
   then disappears with no error anywhere a maintainer would look, so the
   repository loses its citation affordance and still looks fine.
2. The two files DRIFT. They carry the author independently, so an edit to one
   is not an edit to the other, and a citation generated from the archive would
   then disagree with a citation generated from the repository.
3. The identifier acquires a typo. An ORCID is not an opaque string: its final
   character is an ISO 7064 MOD 11-2 check digit over the first fifteen, so a
   transposed or altered digit is DETECTABLE arithmetic rather than a thing
   somebody has to notice by eye. A wrong-but-plausible identifier resolves to
   the wrong person or to nothing, and does so quietly.

Usage: uv run python scripts/citation-metadata-gate.py
Exit 0 when both files parse, agree, and are well-formed; 1 on any disagreement.
Needs pyyaml, which is in the dev extra. A missing parser is a FAILURE, not a
skip: a gate that skips when its parser is absent is how an unparsed file gets
called checked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ZENODO = REPO_ROOT / ".zenodo.json"
CFF = REPO_ROOT / "CITATION.cff"

ORCID_PREFIX = "https://orcid.org/"


def orcid_check_digit_ok(identifier: str) -> bool:
    """ISO 7064 MOD 11-2 over the first fifteen digits, as ORCID specifies.

    Returns False for anything malformed rather than raising, because the caller
    reports; a checksum routine that throws on bad input turns a finding into a
    traceback.
    """
    digits = identifier.replace("-", "")
    if len(digits) != 16:
        return False
    body, check = digits[:15], digits[15].upper()
    if not body.isdigit():
        return False
    total = 0
    for ch in body:
        total = (total + int(ch)) * 2
    remainder = total % 11
    result = (12 - remainder) % 11
    expected = "X" if result == 10 else str(result)
    return check == expected


def read_zenodo() -> tuple[dict[str, Any] | None, list[str]]:
    if not ZENODO.is_file():
        return None, [f"{ZENODO.name} is absent; the archive deposit has no metadata"]
    try:
        data: dict[str, Any] = json.loads(ZENODO.read_text(encoding="utf-8"))
    except ValueError as e:
        return None, [f"{ZENODO.name} is not valid JSON: {e}"]
    return data, []


def read_cff() -> tuple[dict[str, Any] | None, list[str]]:
    if not CFF.is_file():
        return None, [f"{CFF.name} is absent; the repository has no citation affordance"]
    try:
        import yaml  # noqa: PLC0415
    except ImportError as e:
        return None, [
            f"pyyaml is not installed, so {CFF.name} could not be parsed ({e}). "
            "This gate fails rather than skips: an unparsed file must never be "
            "reported as a checked one."
        ]
    try:
        data: dict[str, Any] = yaml.safe_load(CFF.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return None, [
            f"{CFF.name} is not valid YAML: {e}. GitHub's citation panel "
            "disappears silently when this happens."
        ]
    if not isinstance(data, dict):
        return None, [f"{CFF.name} does not parse to a mapping"]
    return data, []


def _zenodo_people(data: dict[str, Any]) -> list[dict[str, Any]]:
    creators = data.get("creators")
    return [c for c in creators if isinstance(c, dict)] if isinstance(creators, list) else []


def _cff_people(data: dict[str, Any]) -> list[dict[str, Any]]:
    authors = data.get("authors")
    return [a for a in authors if isinstance(a, dict)] if isinstance(authors, list) else []


def check_identifiers(
    zenodo: dict[str, Any], cff: dict[str, Any]
) -> list[str]:
    """Every identifier present is well-formed, and the two files agree."""
    errors: list[str] = []

    z_people = _zenodo_people(zenodo)
    c_people = _cff_people(cff)
    if not z_people:
        errors.append(".zenodo.json declares no creators")
    if not c_people:
        errors.append("CITATION.cff declares no authors")
    if errors:
        return errors

    if len(z_people) != len(c_people):
        errors.append(
            f"the two files name a different number of people "
            f"({len(z_people)} in .zenodo.json, {len(c_people)} in CITATION.cff); "
            "a citation from the archive would not match one from the repository"
        )

    z_ids = sorted(str(c["orcid"]) for c in z_people if c.get("orcid"))
    c_ids = sorted(
        str(a["orcid"]).removeprefix(ORCID_PREFIX) for a in c_people if a.get("orcid")
    )
    if z_ids != c_ids:
        errors.append(
            f"the identifiers disagree: .zenodo.json has {z_ids or 'none'}, "
            f"CITATION.cff has {c_ids or 'none'} (compared with the URL prefix "
            "removed, which is the form each format wants)"
        )

    for ident in set(z_ids) | set(c_ids):
        if not orcid_check_digit_ok(ident):
            errors.append(
                f"{ident!r} fails the ISO 7064 MOD 11-2 check digit an ORCID "
                "carries, so it is a typo rather than an identifier"
            )

    # The URL form is what CITATION.cff wants; a bare identifier there is
    # accepted by some readers and dropped by others.
    for a in c_people:
        raw = a.get("orcid")
        if raw is not None and not str(raw).startswith(ORCID_PREFIX):
            errors.append(
                f"CITATION.cff carries {raw!r} without the {ORCID_PREFIX} prefix; "
                "that form is silently dropped by some readers"
            )
    return errors


def main() -> int:
    zenodo, errors = read_zenodo()
    cff, cff_errors = read_cff()
    errors = errors + cff_errors
    if zenodo is not None and cff is not None:
        errors += check_identifiers(zenodo, cff)

    if errors:
        print(
            f"FAIL: the citation metadata is not self-consistent "
            f"({len(errors)} problem(s)):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(
        "OK: both citation files parse, name the same people, and every "
        "identifier passes its check digit."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
