#!/usr/bin/env python3
"""Self-check the anchor-stream suite: python3 check_vectors.py

A corpus that only claims things is worth nothing. A member declaring a
standalone separator inside its attested prefix has to carry that byte at that
offset; a member declaring a JSON boolean where an integer belongs has to carry
a boolean and not the string "true"; a member declaring an unreachable witness
commit has to name that commit and carry the platform's answer beside it. Every
declaration below is recomputed from the files, so a generator bug fails here
instead of shipping a corpus that measures nothing.

Exit 0 when every member does what its manifest entry says it does.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []

#: The stop reasons this corpus is entitled to declare. A reject member naming
#: something outside this set has invented a vocabulary nobody can score
#: against, which is the failure the whole reason column exists to prevent.
STOP_REASONS = frozenset(
    {
        "digest-mismatch",
        "sidecar-coverage",
        "witness-unreachable",
        "malformed-row",
        "unknown-rule-version",
        "invalid-line-count",
        "invalid-byte-length",
        "binding-repo-absent",
        "truncation",
    }
)

#: Every outcome the vendored contract's table defines, and nothing else.
OUTCOMES = {
    "VERIFY OK": 0,
    "VERIFY FAILED": 1,
    "VERIFY UNATTESTED": 2,
    "VERIFY PARTIAL": 3,
    "VERIFY UNPINNED": 4,
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return handle.read()


def fail(vid: str, why: str) -> None:
    FAILURES.append(f"{vid}: {why}")


def split_lines(raw: bytes) -> list[bytes]:
    parts = raw.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def check_separator_member(vid: str, entry: dict, stream: bytes) -> None:
    """The declared code point is at the declared offset, and nothing else moved."""
    properties = entry["properties"]
    codepoint = properties["insertedCodepoint"]
    offset = properties["insertedAtByteOffset"]
    char = chr(int(codepoint[2:], 16))
    encoded = char.encode("utf-8")
    if stream[offset : offset + len(encoded)] != encoded:
        fail(vid, f"declares {codepoint} at byte {offset} and does not carry it there")
        return
    if char == "\n":
        fail(vid, "declares the JSONL delimiter as a separator-only byte")
    rest = stream[:offset] + stream[offset + len(encoded) :]
    if sha(rest) != sha(read("baseline/ANCHORS.jsonl")):
        fail(
            vid,
            "removing the declared code point does not restore the baseline "
            "stream, so the member carries a second change nobody declared",
        )
    if properties["sidecarRegenerated"]:
        fail(vid, "declares a regenerated sidecar and this family does not regenerate one")


def check_sidecar_coverage(vid: str, entry: dict, stream: bytes, sidecar: bytes) -> None:
    entries = len(json.loads(sidecar)["line_sha256"])
    lines = len(split_lines(stream))
    if entries != entry["properties"]["sidecarEntries"]:
        declared = entry["properties"]["sidecarEntries"]
        fail(vid, f"declares {declared} sidecar entries and carries {entries}")
    if lines != entry["properties"]["streamLines"]:
        fail(vid, f"declares {entry['properties']['streamLines']} lines and carries {lines}")
    if entry["kind"] == "reject" and entries >= lines:
        fail(vid, "is a coverage-gap reject member whose sidecar covers every line")
    if entry["kind"] == "accept" and entries != lines:
        fail(vid, "is the covered twin and its sidecar does not cover every line")


def check_boolean_field(vid: str, entry: dict, stream: bytes) -> None:
    """A boolean member carries a JSON boolean, not a string and not 1."""
    field = entry["properties"]["field"]
    want_boolean = entry["properties"]["jsonType"] == "boolean"
    found = False
    for line in split_lines(stream):
        row = json.loads(line)
        prefix = row.get("attestation", {}).get("prefix") if isinstance(row, dict) else None
        if not isinstance(prefix, dict) or field not in prefix:
            continue
        value = prefix[field]
        if isinstance(value, bool) == want_boolean:
            found = True
    if not found:
        fail(
            vid,
            f"declares {field} carrying a JSON {entry['properties']['jsonType']} "
            "and no row in the stream carries one",
        )


def check_reachability(vid: str, entry: dict, stream: bytes, witness: dict) -> None:
    commit = entry["properties"]["witnessCommit"]
    declared = entry["properties"]["reachableFromDefaultBranch"]
    served = {ref["commit"]: bool(ref["reachableFromDefaultBranch"]) for ref in witness["byRef"]}
    if commit not in served:
        fail(vid, f"names witness commit {commit[:12]} and the platform file serves no such commit")
        return
    if served[commit] != declared:
        fail(vid, f"declares reachable={declared} and the platform file says {served[commit]}")
    if commit.encode("ascii") not in stream:
        fail(vid, f"declares witness commit {commit[:12]} and the stream does not name it")
    if entry["kind"] == "reject":
        forged = entry["properties"]["forgedRowsInsidePrefix"]
        if forged < 1:
            fail(
                vid,
                "is the unreachable-witness reject member and forges nothing "
                "inside the prefix",
            )


def check_event_collision(vid: str, entry: dict, stream: bytes) -> None:
    record_fields = {"asset_id", "sha256", "size_bytes"}
    collides = False
    for line in split_lines(stream):
        row = json.loads(line)
        if isinstance(row, dict) and "event" in row and record_fields & set(row):
            collides = True
    if collides != entry["properties"]["carriesRecordFields"]:
        fail(
            vid,
            "declares carriesRecordFields="
            f"{entry['properties']['carriesRecordFields']} and measures {collides}",
        )


def check_rule_version(vid: str, entry: dict, stream: bytes) -> None:
    known = {"witness-ref-v1", "signature-suite-v1", "position-binding-v1"}
    seen = {
        json.loads(line).get("rule_version")
        for line in split_lines(stream)
        if isinstance(json.loads(line), dict) and "rule_version" in json.loads(line)
    }
    if entry["kind"] == "reject":
        declared = entry["properties"]["ruleVersion"]
        if declared not in seen:
            fail(vid, f"declares rule_version {declared!r} and the stream carries {sorted(seen)}")
        if declared in known:
            fail(
                vid,
                f"declares {declared!r} unrecognised and it is one of the three "
                "the format defines",
            )
    elif seen - known:
        fail(vid, f"is the known-rule-set twin and carries {sorted(seen - known)}")


def check_terminator(vid: str, entry: dict, stream: bytes) -> None:
    ends = stream.endswith(b"\n")
    if ends != entry["properties"]["endsWithNewline"]:
        want = entry["properties"]["endsWithNewline"]
        fail(vid, f"declares endsWithNewline={want} and measures {ends}")
    if entry["kind"] == "reject" and sha(stream + b"\n") != sha(read("baseline/ANCHORS.jsonl")):
        fail(
            vid,
            "is the missing-terminator member and adding the byte back does not "
            "restore the baseline, so it carries a second change",
        )


def check_binding_repo(vid: str, entry: dict, stream: bytes) -> None:
    declared = entry["properties"]["bindingRepo"]
    found = []
    for line in split_lines(stream):
        row = json.loads(line)
        witness = row.get("attestation", {}).get("witness") if isinstance(row, dict) else None
        if isinstance(witness, dict) and "repo" in witness:
            found.append(witness["repo"])
    if declared not in found:
        fail(vid, f"declares a binding repo of {declared!r} and the stream carries {found}")


def check_default_branch(vid: str, entry: dict, witness: dict) -> None:
    branch = base64.b64decode(witness["defaultBranch"]["bytesBase64"])
    measured = len(split_lines(branch))
    declared = entry["properties"]["defaultBranchLines"]
    if measured != declared:
        fail(vid, f"declares a default branch of {declared} lines and carries {measured}")


CHECKS = {
    "ans-c-1": lambda vid, entry, stream, sidecar, witness: (
        check_separator_member(vid, entry, stream) if entry["kind"] == "reject" else None
    ),
    "ans-c-2": lambda vid, entry, stream, sidecar, witness: check_terminator(vid, entry, stream),
    "ans-c-3": lambda vid, entry, stream, sidecar, witness: check_sidecar_coverage(
        vid, entry, stream, sidecar
    ),
    "ans-c-5": lambda vid, entry, stream, sidecar, witness: check_reachability(
        vid, entry, stream, witness
    ),
    "ans-c-6": lambda vid, entry, stream, sidecar, witness: check_event_collision(
        vid, entry, stream
    ),
    "ans-c-7": lambda vid, entry, stream, sidecar, witness: check_rule_version(vid, entry, stream),
    "ans-c-8": lambda vid, entry, stream, sidecar, witness: (
        check_boolean_field(vid, entry, stream) if entry["kind"] == "reject" else None
    ),
    "ans-c-9": lambda vid, entry, stream, sidecar, witness: check_binding_repo(vid, entry, stream),
    "ans-c-10": lambda vid, entry, stream, sidecar, witness: (
        check_default_branch(vid, entry, witness)
        if "defaultBranchLines" in entry["properties"]
        else None
    ),
}


def check_expectation(vid: str, kind: str, expected: dict) -> None:
    """The declared outcome, its exit code and its stop reason, against the contract."""
    if expected["outcome"] not in OUTCOMES:
        fail(vid, f"declares an outcome {expected['outcome']!r} the contract does not define")
    elif OUTCOMES[expected["outcome"]] != expected["exit"]:
        fail(
            vid,
            f"declares outcome {expected['outcome']} with exit {expected['exit']}, "
            f"and the contract pairs it with {OUTCOMES[expected['outcome']]}",
        )
    if kind == "reject":
        if expected["outcome"] != "VERIFY FAILED":
            fail(vid, "is a reject member that does not expect the failing outcome")
        if expected["stopReason"] not in STOP_REASONS:
            fail(
                vid,
                f"declares stop reason {expected['stopReason']!r}, which is not "
                "in the corpus vocabulary",
            )
    elif expected["stopReason"] is not None:
        fail(vid, "is an accept member carrying a stop reason")


def check_member(entry: dict, manifest: dict) -> None:
    """One member, against everything it declares about itself."""
    vid, kind = entry["id"], entry["kind"]
    if kind not in ("accept", "reject"):
        fail(vid, f"unknown kind {kind}")
    for key in ("stream", "sidecar", "witness"):
        if not os.path.exists(os.path.join(HERE, entry[key])):
            fail(vid, f"manifest names a {key} file that does not exist")
            return

    stream = read(entry["stream"])
    sidecar = read(entry["sidecar"])
    witness = json.loads(read(entry["witness"]))
    if sha(stream) != entry["streamSha256"]:
        fail(vid, "declared streamSha256 does not recompute from the file")
    # The identifier is a digest of the member's own three files, so an edit to
    # any one of them without regenerating leaves a name describing bytes that
    # are no longer there.
    payload = (
        stream
        + sidecar
        + json.dumps(witness, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if vid != "v" + sha(payload)[:16]:
        fail(vid, "identifier does not recompute from the member's own bytes")

    check_expectation(vid, kind, entry["expected"])
    declared_basis = entry.get("contractBasis")
    for condition in entry["conditions"]:
        if condition not in manifest["conditions"]:
            fail(vid, f"cites condition {condition} the manifest does not define")
            continue
        if declared_basis != manifest["conditions"][condition]["basis"]:
            fail(
                vid,
                f"declares contractBasis {declared_basis!r} and cites {condition}, "
                f"whose basis is {manifest['conditions'][condition]['basis']!r}",
            )
        check = CHECKS.get(condition)
        if check is not None:
            check(vid, entry, stream, sidecar, witness)


def check_vendored_contract(manifest: dict) -> None:
    """The pin a run acts on, and the two halves of it that can disagree."""
    spec_rel = manifest["specVendored"]
    if manifest.get("specAuthority") != "specDigest":
        FAILURES.append(
            "specAuthority names something other than specDigest. A tag is a "
            "name the upstream project can re-point, and this one has published "
            "a tag against the wrong commit already; the digest is the only pin "
            "this corpus can enforce."
        )
    stem = os.path.splitext(os.path.basename(spec_rel))[0]
    short = str(manifest.get("targetCommit", ""))[:7]
    if short and not stem.endswith(short):
        FAILURES.append(
            f"the vendored contract is named {stem!r} while the manifest pins "
            f"commit {short}, so the file name and the pin disagree"
        )
    if not os.path.exists(os.path.join(HERE, spec_rel)):
        FAILURES.append(
            f"the vendored contract {spec_rel} is missing, so nothing records "
            "what this corpus certifies against"
        )
    elif sha(read(spec_rel)) != manifest["specDigest"]:
        FAILURES.append(
            f"the vendored contract {spec_rel} does not match its pinned digest. "
            "Re-vendor from upstream instead of editing the copy, or the corpus "
            "certifies against text nobody published."
        )


def main() -> int:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)

    seen: set[str] = set()
    for entry in manifest["vectors"]:
        if entry["id"] in seen:
            fail(entry["id"], "duplicate id")
        seen.add(entry["id"])
        check_member(entry, manifest)

    # Every reject condition needs an accepting twin, or a verifier that fails
    # everything scores full marks. That verifier is the one that verifies
    # nothing.
    accepted = {c for e in manifest["vectors"] if e["kind"] == "accept" for c in e["conditions"]}
    rejected = {c for e in manifest["vectors"] if e["kind"] == "reject" for c in e["conditions"]}
    orphan = sorted(rejected - accepted)
    if orphan:
        FAILURES.append(f"reject conditions with no accepting twin: {orphan}")

    ordered = sorted(manifest["vectors"], key=lambda entry: entry["id"])
    corpus = sha(b"".join(read(entry["stream"]) for entry in ordered))
    if corpus != manifest["corpusDigest"]:
        FAILURES.append("corpusDigest does not match the streams on disk")

    check_vendored_contract(manifest)

    counts = {
        kind: sum(1 for e in manifest["vectors"] if e["kind"] == kind)
        for kind in ("accept", "reject")
    }
    if counts != manifest["counts"]:
        FAILURES.append(f"counts disagree: manifest {manifest['counts']}, measured {counts}")

    declared_conditions = set(manifest["conditions"])
    used = accepted | rejected
    if declared_conditions - used:
        FAILURES.append(
            f"conditions declared and carried by no member: {sorted(declared_conditions - used)}"
        )

    if FAILURES:
        for line in FAILURES:
            print("FAIL", line)
        return 1
    print(
        f"OK {counts['accept']} accept, {counts['reject']} reject, "
        f"{len(used)} conditions, corpus {corpus[:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
