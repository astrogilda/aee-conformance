#!/usr/bin/env python3
"""Self-check the ACS-Core negative suite: python3 check_vectors.py

Nothing here has been run against an implementation, which makes the internal
checks the only thing standing between this corpus and a set of files that
merely look like one. So each is a property recomputed from the bytes: a
requirement identifier resolves to a sentence that is still in the vendored
copy at the digest the manifest pins, a member citing a code names one the
specification's own registry defines, a sequenced member carries more than one
step, and every family that rejects also accepts.

Exit 0 when every member does what its manifest entry says it does.
"""

from __future__ import annotations

import hashlib
import json
import os
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []

VERDICTS = {"allow", "deny", "unmeasurable"}
KINDS = {"accept", "reject", "indeterminate"}
BASES = {"substrate", "artifact"}
SCOPES = {"SELF", "PEER", "EXTERNAL"}
#: The four rungs a coverage claim can stand on. Declared support and effective
#: enforcement are different properties, and a corpus that does not separate
#: them scores a deployment on what it says.
COVERAGE = {"supported", "configured", "effective", "observed"}

#: The single-step payload subjects a member may carry. Enumerated rather than
#: left to a truthiness test, because a member with no subject at all is a
#: member an implementation cannot answer about, and that is the shape this
#: check exists to catch.
SUBJECTS = {"request", "record", "action", "context_entry"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return handle.read()


def fail(vid: str, why: str) -> None:
    FAILURES.append(f"{vid}: {why}")


def check_requirements(manifest: dict) -> set[str]:
    """Each identifier still names the sentence it was minted against."""
    known: set[str] = set()
    for row in manifest["requirements"]:
        rid = row["id"]
        if rid in known:
            fail(rid, "duplicate requirement identifier")
        known.add(rid)
        rel = row["vendored"]
        if not os.path.exists(os.path.join(HERE, rel)):
            fail(rid, f"names a vendored file {rel} that is not here")
            continue
        text = read(rel).decode("utf-8")
        digest = sha(unicodedata.normalize("NFC", row["sentence"]).encode("utf-8"))
        if digest != row["sentenceDigest"]:
            fail(rid, "the pinned sentence digest does not recompute from the sentence")
        index = text.find(row["sentence"])
        if index < 0:
            fail(
                rid,
                "quotes a sentence the vendored copy no longer carries. A reworded "
                "requirement is a different requirement and this identifier is not "
                "reusable for it.",
            )
            continue
        if text.find(row["sentence"], index + 1) >= 0:
            fail(rid, "quotes a sentence that appears more than once, so it identifies nothing")
        line = text.count("\n", 0, index) + 1
        if line != row["line"]:
            fail(rid, f"records line {row['line']} and the sentence sits on line {line}")
    return known


def check_vocabulary(entry: dict, manifest: dict, known: set[str]) -> None:
    """Every closed field a member declares, against the set it is drawn from."""
    vid = entry["id"]
    if entry["kind"] not in KINDS:
        fail(vid, f"declares kind {entry['kind']!r}")
    if entry["evidenceBasis"] not in BASES:
        fail(vid, f"declares evidence basis {entry['evidenceBasis']!r}")
    if entry["witnessScope"] not in SCOPES:
        fail(vid, f"declares witness scope {entry['witnessScope']!r}")
    if entry["coverage"] not in COVERAGE:
        fail(vid, f"declares coverage {entry['coverage']!r}")
    if entry["family"] not in manifest["families"]:
        fail(vid, f"cites family {entry['family']} the manifest does not define")
    for rid in entry["requirements"]:
        if rid not in known:
            fail(vid, f"cites requirement {rid} the manifest does not carry")
    if not entry["requirements"]:
        fail(vid, "cites no requirement, so a specification change cannot tell it broke")
    if entry["specVersion"] != manifest["specVersion"]:
        fail(vid, "declares a specification version the manifest does not pin")


def check_verdict(entry: dict, manifest: dict) -> None:
    """The verdict, its code, and the third bucket's own obligations."""
    vid = entry["id"]
    expected = entry["expected"]
    if expected["verdict"] not in VERDICTS:
        fail(vid, f"declares verdict {expected['verdict']!r}")
    if expected["code"] is not None:
        if expected["code"] not in manifest["codeRegistry"]:
            fail(
                vid,
                f"asserts code {expected['code']!r}, which the specification's own "
                "registry does not define. A member asserting a code outside the "
                "registry is asserting prose with a different shape.",
            )
        elif manifest["codeRegistry"][expected["code"]] != expected["codeValue"]:
            fail(vid, "carries a code value the registry does not pair with that name")
    check_third_bucket(entry)
    if entry["kind"] == "accept" and expected["verdict"] != "allow":
        fail(vid, "is an accept member that does not expect an allow")
    if entry["kind"] == "reject" and expected["verdict"] != "deny":
        fail(vid, "is a reject member that does not expect a deny")


def check_third_bucket(entry: dict) -> None:
    """The bucket for a property the specification cannot express, both ways.

    Both directions matter. A member that expects no answer and sits outside
    the bucket is scored as though an answer were required; a member inside the
    bucket that expects one is a rejection wearing the bucket's exemption.
    """
    vid = entry["id"]
    expected = entry["expected"]
    if expected["verdict"] == "unmeasurable":
        if entry["kind"] != "indeterminate":
            fail(vid, "expects an unmeasurable verdict and is not in the indeterminate bucket")
        if not expected["unmeasurableBecause"]:
            fail(
                vid,
                "is unmeasurable and records no reason, which makes it "
                "indistinguishable from a member nobody finished",
            )
        if expected["code"] is not None:
            fail(vid, "is unmeasurable and asserts a code, so it expects an answer after all")
    else:
        if entry["kind"] == "indeterminate":
            fail(vid, "sits in the indeterminate bucket and expects a scorable verdict")
        if expected["unmeasurableBecause"]:
            fail(vid, "expects a scorable verdict and carries a reason it cannot be scored")


def check_member(entry: dict, manifest: dict, known: set[str]) -> None:
    """One member: its vocabulary, its verdict, and the file behind it."""
    vid = entry["id"]
    check_vocabulary(entry, manifest, known)
    check_verdict(entry, manifest)
    path = os.path.join(HERE, entry["file"])
    if not os.path.exists(path):
        fail(vid, "the manifest names a vector file that does not exist")
        return
    document = json.loads(read(entry["file"]))
    for field in ("kind", "family", "requirements", "expected", "specVersion"):
        if document[field] != entry[field]:
            fail(vid, f"the vector file and the manifest disagree about {field}")
    if document["id"] != vid:
        fail(vid, "the vector file carries a different identifier")

    payload = document["payload"]
    steps = payload.get("steps")
    if steps is not None:
        if len(steps) < 2:
            fail(
                vid,
                "is a sequenced member with fewer than two steps, so nothing about "
                "the sequence is under test",
            )
        if entry["kind"] == "accept" and len(steps) < 2:
            fail(vid, "is a sequenced family's control and is not itself sequenced")
    elif not SUBJECTS & set(payload):
        fail(
            vid,
            "carries neither steps nor any of the single-step subjects this suite "
            f"recognises ({', '.join(sorted(SUBJECTS))}), so there is nothing for "
            "an implementation to answer about",
        )


def main() -> int:
    manifest = json.loads(read("MANIFEST.json"))
    known = check_requirements(manifest)

    seen: set[str] = set()
    for entry in manifest["vectors"]:
        if entry["id"] in seen:
            fail(entry["id"], "duplicate identifier")
        seen.add(entry["id"])
        check_member(entry, manifest, known)

    check_corpus(manifest, known)

    if FAILURES:
        for line in FAILURES:
            print("FAIL", line)
        return 1
    counts = {
        kind: sum(1 for e in manifest["vectors"] if e["kind"] == kind) for kind in KINDS
    }
    print(
        f"OK {counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['indeterminate']} indeterminate, {len(known)} requirements, "
        f"corpus {manifest['corpusDigest'][:12]}"
    )
    return 0


def check_corpus(manifest: dict, known: set[str]) -> None:
    """The invariants that are about the corpus rather than about one member."""
    # Every rejecting family accepts something, or a deployment that denies
    # every input scores full marks on it. That deployment governs nothing.
    accepted = {e["family"] for e in manifest["vectors"] if e["kind"] == "accept"}
    rejected = {e["family"] for e in manifest["vectors"] if e["kind"] == "reject"}
    orphan = sorted(rejected - accepted)
    if orphan:
        FAILURES.append(f"families that reject and never accept: {orphan}")

    cited = {r for e in manifest["vectors"] for r in e["requirements"]}
    idle = sorted(known - cited)
    if idle:
        FAILURES.append(
            f"requirements minted and cited by no member: {idle}. An identifier "
            "with no falsifying vector is a row that proves the requirement was "
            "named, which is a different property from its being forced."
        )
    unused = sorted(set(manifest["families"]) - (accepted | rejected))
    if unused:
        FAILURES.append(f"families declared and carried by no member: {unused}")

    for key, entry in manifest["specVendored"].items():
        if not os.path.exists(os.path.join(HERE, entry["path"])):
            FAILURES.append(f"the vendored file {entry['path']} for {key} is missing")
        elif sha(read(entry["path"])) != entry["sha256"]:
            FAILURES.append(
                f"the vendored file {entry['path']} does not match its pinned digest. "
                "Re-vendor from upstream instead of editing the copy, or the corpus "
                "cites text nobody published."
            )

    if manifest["observedRuns"]:
        FAILURES.append(
            "the manifest records an observed run and this corpus has never been "
            "run against an implementation. A run row is added by whoever ran it, "
            "with what they ran and against what."
        )

    counts = {
        kind: sum(1 for e in manifest["vectors"] if e["kind"] == kind) for kind in KINDS
    }
    if counts != manifest["counts"]:
        FAILURES.append(f"counts disagree: manifest {manifest['counts']}, measured {counts}")

    ordered = sorted(manifest["vectors"], key=lambda entry: entry["id"])
    corpus = sha(b"".join(read(entry["file"]) for entry in ordered))
    if corpus != manifest["corpusDigest"]:
        FAILURES.append("corpusDigest does not match the vector files on disk")


if __name__ == "__main__":
    raise SystemExit(main())
