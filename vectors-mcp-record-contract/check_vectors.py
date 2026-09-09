#!/usr/bin/env python3
"""Self-check the run-record contract suite: python3 check_vectors.py

Two jobs, and the second is the one that matters. The first is the ordinary
corpus check: the manifest agrees with the files, every condition is carried,
every rejecting condition also accepts. The second runs `check_run_record.py`
over every member and compares its three answers against the ones the member
declares, so the criterion is measured against the corpus rather than asserted
beside it.

That second job is why the criterion lives in code at all. A criterion stated
only in prose is satisfied by whatever a reader takes it to mean, and the two
readings that matter here differ on a record that is fully re-checkable and
carries a figure nobody should quote.

Exit 0 when every member does what its manifest entry says it does, and the
checker answers each member the way the member says it must be answered.
"""

from __future__ import annotations

import hashlib
import json
import os

from check_run_record import check_record

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []

AXES = ("recheckable", "figureMeansWhatItSays", "independence")
#: The two axes a member can fail, plus the one value of the third that is a
#: failure. Independence is otherwise a fact the record states rather than a
#: score, and treating a declared self-report as a failure would push records
#: towards leaving it out.
PASS_FAIL = ("recheckable", "figureMeansWhatItSays")

#: The four conditions a re-run needs, and the two that decide what a result
#: means. Held here as well as in the generator on purpose: this file is the
#: thing that would catch the generator agreeing with itself.
FOUR_INPUTS = frozenset({"mrc-c-1", "mrc-c-2", "mrc-c-3", "mrc-c-4"})
MEANING = {"mrc-c-5": "figureMeansWhatItSays", "mrc-c-6": "independence"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return handle.read()


def fail(vid: str, why: str) -> None:
    FAILURES.append(f"{vid}: {why}")


def check_declared_axes(vid: str, entry: dict) -> None:
    """A reject member fails exactly one axis, and its condition says which."""
    expected = entry["expected"]
    condition = entry["conditions"][0]
    failing = [axis for axis in PASS_FAIL if not expected[axis]]
    if expected["independence"] == "undeclared":
        failing.append("independence")
    if entry["kind"] == "accept":
        if failing:
            fail(vid, f"is an accept member declaring a failure on {failing}")
        return
    if len(failing) != 1:
        fail(
            vid,
            f"is a reject member declaring failures on {failing}. One member "
            "failing two axes cannot tell you which rule caught it, which is "
            "the property the whole reason column exists for.",
        )
        return
    axis = failing[0]
    wanted = "recheckable" if condition in FOUR_INPUTS else MEANING.get(condition)
    if axis != wanted:
        fail(vid, f"cites {condition} and declares its failure on {axis}, not on {wanted}")


def check_member_against_checker(vid: str, entry: dict) -> None:
    """The criterion, run. This is the check the prose cannot do."""
    record = json.loads(read(entry["record"]))
    observed = check_record(record)
    for axis in AXES:
        if observed[axis] != entry["expected"][axis]:
            fail(
                vid,
                f"declares {axis}={entry['expected'][axis]} and the checker "
                f"answers {observed[axis]}. "
                + (
                    "; ".join(observed["missing"] + observed["notes"])[:200]
                    or "the checker gave no reason, which is its own defect"
                ),
            )
    if entry["kind"] == "reject" and not (observed["missing"] or observed["notes"]):
        fail(vid, "is a reject member the checker had nothing at all to say about")


def check_member(entry: dict, manifest: dict) -> None:
    """One member's declaration, then the criterion run against it."""
    vid = entry["id"]
    if entry["kind"] not in ("accept", "reject"):
        fail(vid, f"declares kind {entry['kind']!r}")
    if not entry["conditions"]:
        fail(vid, "cites no condition")
        return
    for condition in entry["conditions"]:
        if condition not in manifest["conditions"]:
            fail(vid, f"cites condition {condition} the manifest does not define")
    if not os.path.exists(os.path.join(HERE, entry["record"])):
        fail(vid, "the manifest names a record file that does not exist")
        return
    for axis in AXES:
        if axis not in entry["expected"]:
            fail(vid, f"declares no expectation on {axis}")
    if any(axis not in entry["expected"] for axis in AXES):
        return
    check_declared_axes(vid, entry)
    check_member_against_checker(vid, entry)


def main() -> int:
    manifest = json.loads(read("MANIFEST.json"))

    seen: set[str] = set()
    for entry in manifest["vectors"]:
        if entry["id"] in seen:
            fail(entry["id"], "duplicate identifier")
        seen.add(entry["id"])
        check_member(entry, manifest)

    accepted = {c for e in manifest["vectors"] if e["kind"] == "accept" for c in e["conditions"]}
    rejected = {c for e in manifest["vectors"] if e["kind"] == "reject" for c in e["conditions"]}
    orphan = sorted(rejected - accepted)
    if orphan:
        FAILURES.append(
            f"conditions that reject and never accept: {orphan}. A checker that "
            "refuses every record would score full marks on them."
        )
    idle = sorted(set(manifest["conditions"]) - (accepted | rejected))
    if idle:
        FAILURES.append(f"conditions declared and carried by no member: {idle}")

    if not os.path.exists(os.path.join(HERE, "..", manifest["criterion"])):
        FAILURES.append(
            f"the manifest names the criterion at {manifest['criterion']} and no "
            "such file is there, so the corpus measures a rule nobody can read"
        )

    counts = {
        kind: sum(1 for e in manifest["vectors"] if e["kind"] == kind)
        for kind in ("accept", "reject")
    }
    if counts != manifest["counts"]:
        FAILURES.append(f"counts disagree: manifest {manifest['counts']}, measured {counts}")

    ordered = sorted(manifest["vectors"], key=lambda entry: entry["id"])
    corpus = sha(b"".join(read(entry["record"]) for entry in ordered))
    if corpus != manifest["corpusDigest"]:
        FAILURES.append("corpusDigest does not match the record files on disk")

    if FAILURES:
        for line in FAILURES:
            print("FAIL", line)
        return 1
    print(
        f"OK {counts['accept']} accept, {counts['reject']} reject, "
        f"{len(accepted | rejected)} conditions, corpus {corpus[:12]}, "
        "and the checker answered every member as declared"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
