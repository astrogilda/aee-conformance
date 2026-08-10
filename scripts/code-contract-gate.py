#!/usr/bin/env python3
"""Failure-code contract gate.

The README's failure-code section makes two kinds of claim, and this gate exists
because both had gone unchecked and one of them had gone wrong.

The first kind is behavioural: a statement about what the suite requires of a
verifier under test. The runner's own module docstring used to say that a
third-party rail emitting no codes would be checked on its verdict alone, while
the evaluator it described has always compared a reject vector against the
manifest's expected code set and an accept vector against the manifest's result.
A rail answering with an exit status and nothing else fails every vector in the
suite. Nothing disagreed with the prose because nothing read it. So the checks
below drive the runner's own ``evaluate_vector`` with each response shape a
third-party rail can produce, against real manifest entries rather than
fixtures, and assert the outcome the README states. Loosening the evaluator now
turns this gate red.

The second kind is registry: the codes are this suite's, not the
specification's, which says nothing about what a verifier should call the
conditions it defines. A registry whose only guarantee is that someone counted
the entries is worth nothing, so the assertions here are about membership and
provenance instead. Every code the corpus names must exist in the enumerated
set -- named anywhere a manifest entry can name one, which includes the values of
an indeterminate vector's declared readings, and which the gate enumerates over a
closed classification of the ``expected`` schema so that a field added later
cannot leave the subject quietly; every validity code in that set must be
exercised by at least one vector and known to the Python rail as well as the Go
one, so the two first-party rails carry one vocabulary rather than two that
happen to agree today; and the
consumer-policy codes, which are consumer-relative admission facts and never
validity conditions, must be exercised by no vector at all, because a
single-statement corpus cannot pin a consumer's policy and a vector claiming to
would be asserting something it cannot see.

Usage:
    python3 scripts/code-contract-gate.py
    python3 scripts/code-contract-gate.py --manifest P --codes P --rail P
Exit 0 when the documented contract holds; 1 on any disagreement. The three
inputs are overridable so scripts/code-contract-gate-test.py can break one of
them at a time and require this file to notice; the behavioural half still
drives the real runner, because a fixture rail would only prove that a fixture
agrees with itself.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CODES_GO = REPO_ROOT / "aee" / "codes.go"
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
PY_RAIL = REPO_ROOT / "packaging" / "run_vectors.py"

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402

# `	CodeRefsEmpty                      Code = "refs-empty"`
CONST_RE = re.compile(r'^Code[A-Za-z0-9]+\s+Code\s*=\s*"([a-z0-9-]+)"')
# The comment that opens the consumer-policy const block. Matched on text rather
# than on the constant names, so rewording the block heading fails loudly here
# instead of silently reclassifying its codes as validity codes.
POLICY_HEADING = "Consumer-policy stage codes"

# Every field a manifest entry's ``expected`` object may carry, split by whether
# it names failure codes. The split is CLOSED, and that is the point: a field in
# neither list is a schema this gate has not been taught, and it fails below
# rather than narrowing the vocabulary it checks without saying so.
#
# ``readings`` is why. The runner treats each declared reading's value as a
# failure code -- ``run_vectors.py`` folds them into the expected code set of an
# indeterminate vector -- and this gate read ``codes`` and ``alsoCarries`` only.
# A code named by a reading and by nothing else therefore sat in the manifest,
# in the published indeterminate index and in no registry at all, with this gate,
# the regenerability gate and a 248-of-248 replay all green. The subject of a
# membership check cannot be a hand-listed subset of the schema it checks, so it
# is enumerated here and the leftovers are a failure.
CODE_LIST_FIELDS = ("codes", "alsoCarries")
CODE_MAP_FIELDS = ("readings",)
NON_CODE_FIELDS = (
    "verdict",
    "result",
    "tierWithPinnedKey",
    "tierWithoutKey",
    "family",
)


def _rel(path: Path) -> Path:
    """A path as a reader of this repository would name it, if it is in one."""
    try:
        return path.relative_to(REPO_ROOT)
    except ValueError:
        return path


def parse_codes(codes_go: Path) -> tuple[set[str], set[str]]:
    """Split ``aee/codes.go`` into (validity codes, consumer-policy codes)."""
    validity: set[str] = set()
    policy: set[str] = set()
    target = validity
    comment: list[str] = []
    in_block = False

    for raw in codes_go.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("//"):
            comment.append(line)
            continue
        if line.startswith("const ("):
            target = policy if POLICY_HEADING in " ".join(comment) else validity
            in_block, comment = True, []
            continue
        if in_block and line == ")":
            in_block, comment = False, []
            continue
        match = CONST_RE.match(line)
        if in_block and match:
            target.add(match.group(1))
        if not line:
            comment = []

    if not validity or not policy:
        print(
            f"FAIL: {_rel(codes_go)} did not yield both code "
            f"classes (validity {len(validity)}, consumer-policy {len(policy)}); "
            f"the const blocks or the {POLICY_HEADING!r} heading have moved.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return validity, policy


def manifest_codes(manifest: dict[str, Any]) -> tuple[set[str], list[str]]:
    """Every code the corpus names, and every field it names one in unread.

    A code is named by a declared code list, by a deliberate companion, or by
    the value of a declared reading. Any other ``expected`` field is reported
    rather than skipped: an unclassified field is a field whose codes, if it
    carries any, would be outside this gate's subject, and a subject that shrinks
    when the schema grows is the shape of every check in this repository that
    ran green while enforcing nothing.
    """
    named: set[str] = set()
    unknown: dict[str, str] = {}
    for entry in manifest["vectors"]:
        expected = entry.get("expected") or {}
        for field in CODE_LIST_FIELDS:
            named |= {str(code) for code in expected.get(field) or []}
        for field in CODE_MAP_FIELDS:
            named |= {str(code) for code in (expected.get(field) or {}).values()}
        for field in expected:
            if field not in CODE_LIST_FIELDS + CODE_MAP_FIELDS + NON_CODE_FIELDS:
                unknown.setdefault(field, str(entry.get("id", "<unnamed>")))
    errors = [
        f"`expected.{field}` (first on {vid}) is a manifest field this gate "
        "does not classify. Add it to CODE_LIST_FIELDS, CODE_MAP_FIELDS or "
        "NON_CODE_FIELDS in scripts/code-contract-gate.py: a field left "
        "unclassified is one whose codes are checked against no registry"
        for field, vid in sorted(unknown.items())
    ]
    return named, errors


def rail_vocabulary(rail: Path) -> set[str]:
    """Every string the Python rail carries as a literal.

    Read off the parsed module rather than by scanning its text for a quoted
    token. A code is known to the rail when the rail spells it as a value; a
    substring scan cannot tell that from a docstring that happens to mention it,
    and this file's prose mentions several.
    """
    tree = ast.parse(rail.read_text(encoding="utf-8"))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def check_registry(manifest: dict[str, Any], paths: argparse.Namespace) -> list[str]:
    """Membership and provenance of every code, both directions."""
    validity, policy = parse_codes(paths.codes)
    named, errors = manifest_codes(manifest)
    rail = rail_vocabulary(paths.rail)

    if not named:
        print(
            f"FAIL: {_rel(paths.manifest)} names no failure codes at all. "
            "Every code-bearing field is empty or renamed, so the membership "
            "check below would quantify over nothing and report success.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    for code in sorted(named - (validity | policy)):
        errors.append(
            f"`{code}`: named by the corpus but absent from "
            f"{_rel(paths.codes)}"
        )
    for code in sorted(validity - named):
        errors.append(
            f"`{code}`: defined as a validity code but no vector emits it -- add "
            "a vector, or move it to the consumer-policy block if no single "
            "statement can exercise it"
        )
    for code in sorted(validity):
        if code not in rail:
            errors.append(
                f"`{code}`: defined in the Go rail but absent from "
                f"{_rel(paths.rail)}, so the two first-party rails "
                "no longer share one vocabulary"
            )
    for code in sorted(policy & named):
        errors.append(
            f"`{code}`: a consumer-policy code, which is never a validity "
            "condition, but a vector declares it"
        )
    return errors


def _entry(manifest: dict[str, Any], kind: str, member: str) -> dict[str, Any]:
    """The first live manifest entry of ``kind`` declaring ``member``."""
    for entry in manifest["vectors"]:
        typed: dict[str, Any] = entry
        if typed.get("kind") == kind and (typed.get("expected") or {}).get(member):
            return typed
    print(
        f"FAIL: no {kind} vector in the manifest declares {member!r}, so the "
        "documented contract cannot be exercised against a real entry.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _observed(verdict: str, codes: list[str], result: str | None) -> dict[str, Any]:
    """A third-party rail's answer in the shape the runner builds for one."""
    return {
        "verdict": verdict,
        "codes": codes,
        "result": result,
        "tiers_with_key": None,
        "tiers_without_key": None,
        "result_without_key": None,
    }


def _verdict_of(kind: str, entry: dict[str, Any], observed: dict[str, Any]) -> bool:
    passed, _gates, _reasons = run_vectors.evaluate_vector(kind, entry, observed, None)
    return bool(passed)


def check_behaviour(manifest: dict[str, Any]) -> list[str]:
    """Drive the runner's evaluator with each shape a third-party rail emits."""
    reject = _entry(manifest, "reject", "codes")
    accept = _entry(manifest, "accept", "result")
    declared = list(reject["expected"]["codes"])
    result = accept["expected"]["result"]

    cases = [
        (
            "a reject vector answered with a verdict and no codes must fail",
            "reject",
            reject,
            _observed("invalid", [], None),
            False,
        ),
        (
            "a reject vector answered with one declared code must pass",
            "reject",
            reject,
            _observed("invalid", declared[:1], None),
            True,
        ),
        (
            "codes are a set: reversed order plus an extra code must still pass",
            "reject",
            reject,
            _observed("invalid", [*reversed(declared), "record-undecodable"], None),
            True,
        ),
        (
            "a reject vector answered valid must fail",
            "reject",
            reject,
            _observed("valid", [], None),
            False,
        ),
        (
            "an accept vector answered with a verdict and no result must fail",
            "accept",
            accept,
            _observed("valid", [], None),
            False,
        ),
        (
            "an accept vector answered with the expected result must pass",
            "accept",
            accept,
            _observed("valid", [], result),
            True,
        ),
    ]

    errors: list[str] = []
    for claim, kind, entry, observed, want in cases:
        got = _verdict_of(kind, entry, observed)
        if got is not want:
            errors.append(
                f"{claim} -- against `{entry['id']}` the evaluator "
                f"{'passed' if got else 'failed'} it"
            )
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="failure-code contract gate")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--codes", type=Path, default=CODES_GO,
                        help="the enumerated code set the corpus draws from")
    parser.add_argument("--rail", type=Path, default=PY_RAIL,
                        help="the Python rail whose vocabulary must match")
    return parser.parse_args(argv[1:])


def main(argv: list[str]) -> int:
    paths = parse_args(argv)
    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))
    errors = check_registry(manifest, paths) + check_behaviour(manifest)
    if errors:
        print(
            f"FAIL: the documented failure-code contract and the code disagree "
            f"({len(errors)} disagreement(s)):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nThe contract is stated in the README's failure-code section and "
            "in the run_vectors.py module docstring. Whichever side moved, both "
            "have to say the same thing before this gate goes green.",
            file=sys.stderr,
        )
        return 1

    validity, policy = parse_codes(paths.codes)
    print(
        f"OK: the evaluator behaves as the failure-code contract documents, and "
        f"{len(validity)} validity code(s) are exercised by the corpus and known "
        f"to both rails ({len(policy)} consumer-policy code(s) exercised by none)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
