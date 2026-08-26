#!/usr/bin/env python3
"""Self-check the AI Agent Action suite: python3 check_vectors.py

This is the mutation check the corpus needs to be worth anything. A vector
that claims a chain-hash divergence has to actually diverge, and a vector
that claims conformance has to actually recompute. Without this, a generator
bug produces a corpus that passes every rail and measures nothing.

Exit 0 when every member behaves as its manifest entry claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def depth(node, level: int = 1) -> int:
    if isinstance(node, dict):
        return max([level] + [depth(v, level + 1) for v in node.values()])
    if isinstance(node, list):
        return max([level] + [depth(v, level + 1) for v in node])
    return level - 1


def fail(vid: str, why: str) -> None:
    FAILURES.append(f"{vid}: {why}")


def check_chain_members(vid: str, kind: str, lines: list[bytes]) -> None:
    """Each line's declared previousHash must resolve, or must not."""
    canonical: list[bool] = []
    for ln in lines:
        try:
            canonical.append(sha(jcs(json.loads(ln))) == sha(ln))
        except UnicodeEncodeError:
            # The line carries an unpaired surrogate, so it has no UTF-8
            # encoding at all and cannot be canonical. bad-113 is exactly
            # this member; an accept member reaching here is a real failure.
            canonical.append(False)
            if kind == "accept":
                fail(vid, "an accept member carries an unencodable string")
    if kind == "accept" and not all(canonical):
        fail(vid, "an accept member carries a non-canonical log line")
    if vid.startswith("bad-10") and vid[:7] in (
            "bad-101", "bad-102", "bad-103", "bad-104") and all(canonical):
        fail(vid, "a canonicalization reject member is already canonical, "
                  "so it demonstrates nothing")


def main() -> None:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)

    seen_ids: set[str] = set()
    for entry in manifest["vectors"]:
        vid, kind = entry["id"], entry["kind"]
        if vid in seen_ids:
            fail(vid, "duplicate id")
        seen_ids.add(vid)

        path = os.path.join(HERE, entry["file"])
        if not os.path.exists(path):
            fail(vid, "manifest names a file that does not exist")
            continue
        with open(path, encoding="utf-8") as fh:
            stmt = json.load(fh)
        if stmt["predicateType"] != manifest["predicateType"]:
            fail(vid, "predicateType does not match the suite")
        if kind not in ("accept", "reject"):
            fail(vid, f"unknown kind {kind}")

        if "records" in entry:
            rp = os.path.join(HERE, entry["records"])
            if not os.path.exists(rp):
                fail(vid, "manifest names a records sidecar that does not exist")
                continue
            with open(rp, "rb") as fh:
                lines = [ln for ln in fh.read().split(b"\n") if ln]
            check_chain_members(vid, kind, lines)
            declared = entry["expected"].get("chainHash")
            if declared and kind == "accept":
                if sha(lines[-1]) != declared:
                    fail(vid, "declared chainHash does not recompute from the "
                              "last record line")
            if declared and kind == "reject" and sha(lines[-1]) == declared:
                fail(vid, "a reject member's subject digest recomputes "
                          "cleanly, so nothing is being caught")

        ext = stmt["predicate"].get("extensions")
        if vid == "ok-010-extensions-depth-128" and depth(ext) != 128:
            fail(vid, f"claims depth 128, measured {depth(ext)}")
        if vid == "bad-114-extensions-depth-129" and depth(ext) != 129:
            fail(vid, f"claims depth 129, measured {depth(ext)}")
        if vid == "bad-115-unsafe-integer-durationms":
            d = stmt["predicate"]["action"]["durationMs"]
            if abs(d) < 2 ** 53:
                fail(vid, "claims an unsafe integer and carries a safe one")

    # Every reject condition needs an accepting twin, or a rail that rejects
    # everything scores full marks.
    acc = {c for e in manifest["vectors"] if e["kind"] == "accept"
           for c in e["conditions"]}
    rej = {c for e in manifest["vectors"] if e["kind"] == "reject"
           for c in e["conditions"]}
    orphan = sorted(rej - acc)
    if orphan:
        FAILURES.append(f"reject conditions with no accepting twin: {orphan}")

    corpus = sha(b"".join(
        open(os.path.join(HERE, e["file"]), "rb").read()
        for e in sorted(manifest["vectors"], key=lambda e: e["id"])))
    if corpus != manifest["corpusDigest"]:
        FAILURES.append("corpusDigest does not match the files on disk")

    counts = {k: sum(1 for e in manifest["vectors"] if e["kind"] == k)
              for k in ("accept", "reject")}
    if counts != manifest["counts"]:
        FAILURES.append(f"counts disagree: manifest {manifest['counts']}, "
                        f"measured {counts}")

    if FAILURES:
        for f in FAILURES:
            print("FAIL", f)
        sys.exit(1)
    print(f"OK {counts['accept']} accept, {counts['reject']} reject, "
          f"{len(acc | rej)} conditions, corpus {corpus[:12]}")


if __name__ == "__main__":
    main()
