#!/usr/bin/env python3
"""Check that the artifact-binding corpus behaves as its manifest claims.

A different question from regenerability. That gate asks whether the committed
bytes are the bytes the generator emits; this asks whether those bytes BEHAVE as
declared: that the member claiming a digest mismatch actually mismatches, that
the member claiming not-established reaches neither neighbour, and that the
regrade member really shares an archive with the record it derives from.

It also asks the question a corpus of rejections cannot answer about itself. A
verifier that refuses everything scores full marks on a suite of failures alone,
so this checker refuses a corpus with no ``verified`` member and refuses one
whose ``not-established`` members could be satisfied by answering ``failed``.

    python3 vectors-artifact-binding/check_vectors.py

Exits 0 clean, 1 with one line per divergence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools" / "artifact-binding"))

import jcs  # noqa: E402
import sign  # noqa: E402
import verify as verify_mod  # noqa: E402

FAILURES: list[str] = []


def fail(line: str) -> None:
    FAILURES.append(line)


def check_member(entry: dict[str, object], public_key: bytes) -> None:
    identifier = str(entry["id"])
    trial = HERE / str(entry["trial"])
    manifest_path = HERE / str(entry["manifest"])
    signature_path = HERE / str(entry["signature"])
    expected = entry["expected"]
    if not isinstance(expected, dict):
        fail(f"{identifier}: the manifest entry declares no expected verdict")
        return
    if not manifest_path.is_file():
        fail(f"{identifier}: {manifest_path} is missing")
        return

    outcome = verify_mod.verify(trial, manifest_path, signature_path, public_key)
    if outcome.verdict != expected["verdict"]:
        fail(
            f"{identifier}: the manifest expects {expected['verdict']!r} and the "
            f"reference verifier answered {outcome.verdict!r} "
            f"(codes: {sorted(set(outcome.codes))})"
        )
        return
    declared = expected.get("codes")
    wanted = set(declared) if isinstance(declared, list) else set()
    missing = wanted - set(outcome.codes)
    if missing:
        fail(f"{identifier}: expected code(s) {sorted(missing)} were not emitted")
    if outcome.verdict != verify_mod.VERIFIED and not outcome.messages:
        fail(f"{identifier}: a non-verified verdict named nothing")


def check_lineage_member(entry: dict[str, object]) -> None:
    """The regrade member really derives from a record over the same archive."""
    record = verify_mod.read_record(HERE / str(entry["manifest"]))
    if record is None:
        fail(f"{entry['id']}: the regrade record is not a JSON object")
        return
    source = HERE / str(entry["case"]) / "source" / "binding" / "manifest.json"
    if not source.is_file():
        fail(f"{entry['id']}: the record it derives from is not in the case directory")
        return
    parent = verify_mod.read_record(source)
    if parent is None:
        fail(f"{entry['id']}: the source record is not a JSON object")
        return
    if record.get("source_record_digest") != verify_mod.manifest_digest(source):
        fail(f"{entry['id']}: source_record_digest does not resolve to the source record")
    if record.get("source_archive_digest") != parent.get("source_archive_digest"):
        fail(f"{entry['id']}: the two records do not share one source_archive_digest")
    graded = record.get("graded_outcome")
    parent_graded = parent.get("graded_outcome")
    if isinstance(graded, dict) and isinstance(parent_graded, dict):
        if graded.get("reward") == parent_graded.get("reward"):
            fail(
                f"{entry['id']}: the changed verifier produced the same reward, so the "
                "member does not demonstrate two preserved outcomes"
            )


def check_published_key(vectors: list[dict[str, object]], public_key: bytes) -> None:
    """The published key is the key the passing member names.

    A corpus whose published key is not the one its passing member was signed
    with would report every member as a signer mismatch while looking like a
    signing bug rather than a manifest defect.
    """
    intact = next(
        (
            entry
            for entry in vectors
            if entry["expected"]["verdict"] == "verified"  # type: ignore[index]
            and "regrade" not in str(entry["case"])
        ),
        None,
    )
    if intact is None:
        fail("the corpus has no plain verified member to anchor the published key against")
        return
    record = verify_mod.read_record(HERE / str(intact["manifest"]))
    named = record.get("signer_key_id") if record is not None else None
    if named != sign.key_id(public_key):
        fail(
            f"MANIFEST.json publishes a key whose id is {sign.key_id(public_key)} and "
            f"the intact member names {named}"
        )


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    vectors = manifest["vectors"]
    public_key = bytes.fromhex(manifest["publicKey"])
    # The corpus publishes the key its members were signed with, and a corpus
    # whose published key is not the key its passing member names would report
    # every member as a signer mismatch while looking like a signing bug.
    check_published_key(vectors, public_key)

    for entry in vectors:
        check_member(entry, public_key)
        if entry["expected"]["verdict"] == "verified" and "regrade" in entry["case"]:
            check_lineage_member(entry)

    verdicts = {entry["expected"]["verdict"] for entry in vectors}
    if "verified" not in verdicts:
        fail(
            "the corpus contains no verified member, so a verifier that refuses "
            "everything would score full marks"
        )
    if "not-established" not in verdicts:
        fail("the corpus contains no not-established member, so the third outcome is untested")

    counts = manifest["counts"]
    actual = {
        "verified": sum(1 for e in vectors if e["expected"]["verdict"] == "verified"),
        "failed": sum(1 for e in vectors if e["expected"]["verdict"] == "failed"),
        "notEstablished": sum(
            1 for e in vectors if e["expected"]["verdict"] == "not-established"
        ),
    }
    if counts != actual:
        fail(f"MANIFEST.json declares counts {counts} and the entries are {actual}")
    if manifest["corpusDigest"] != jcs.digest(vectors):
        fail("corpusDigest does not match the vectors it names")

    if FAILURES:
        for line in FAILURES:
            print(f"FAIL {line}")
        return 1
    print(
        f"artifact-binding corpus: {len(vectors)} vectors behave as MANIFEST.json claims "
        f"({actual['verified']} verified, {actual['failed']} failed, "
        f"{actual['notEstablished']} not-established)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
