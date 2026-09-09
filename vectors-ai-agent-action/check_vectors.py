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
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def jcs_utf16(obj) -> bytes:
    """RFC 8785 with member names sorted by UTF-16 code unit, as the RFC says.

    ``jcs`` above sorts Python strings, which compares code points. The two
    agree on every BMP-only record and part on a supplementary-plane member
    name. Recomputing both is how the ok-013 / bad-116 pair is measured rather
    than asserted.
    """
    def enc(node) -> str:
        if isinstance(node, dict):
            members = sorted(node.items(),
                             key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(
                json.dumps(name, ensure_ascii=False) + ":" + enc(value)
                for name, value in members) + "}"
        if isinstance(node, list):
            return "[" + ",".join(enc(value) for value in node) + "]"
        return json.dumps(node, ensure_ascii=False, separators=(",", ":"))
    return enc(obj).encode("utf-8")


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


def check_chain_members(vid: str, kind: str, entry: dict,
                        lines: list[bytes]) -> None:
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
    if kind == "reject" and CANONICAL_BYTES_CONDITIONS & set(
            entry.get("conditions", [])) and all(canonical):
        fail(vid, "a canonicalization reject member is already canonical, "
                  "so it demonstrates nothing")


# The conditions whose reject members exist to carry NON-canonical bytes. This
# used to be a list of four identifiers matched by prefix, which stopped being
# expressible the moment identifiers stopped carrying a family in their spelling
# -- and which was the wrong question anyway. Whether a member must be
# non-canonical is a property of the rule it forces, not of what it is called,
# and reading it off the declared conditions asks the vector rather than its
# name. The set is exactly the conditions those four members declared.
CANONICAL_BYTES_CONDITIONS = {"aia-c-1", "aia-c-3", "aia-c-4"}


def check_member_name_orders(vid: str, kind: str, stmt: dict, entry: dict,
                             lines: list[bytes]) -> None:
    """The ok-013 / bad-116 pair, recomputed rather than taken on trust.

    An accept member must carry only BMP member names, and the two sort orders
    must agree on them. A reject member must carry a supplementary-plane member
    name, and the two orders must actually disagree -- a pair whose orders
    happened to coincide would prove nothing while reading exactly the same.
    Both declared digests are recomputed from the sidecar record, so a
    generator that wrote the wrong bytes fails here instead of shipping.
    """
    ext = stmt["predicate"].get("extensions")
    if not isinstance(ext, dict) or not ext:
        fail(vid, "carries no extensions object, so there are no member "
                  "names to sort")
        return
    names = list(ext)
    astral = [n for n in names if any(ord(c) > 0xFFFF for c in n)]
    diverges = (sorted(names) != sorted(names, key=lambda s: s.encode("utf-16-be")))

    if kind == "accept" and astral:
        fail(vid, f"an accept member carries a supplementary-plane member "
                  f"name {astral!r}")
    if kind == "reject" and not astral:
        fail(vid, "claims a supplementary-plane member name and carries none")
    if kind == "accept" and diverges:
        fail(vid, "the two sort orders disagree on an accept member, so it is "
                  "not the admissible side of the boundary")
    if kind == "reject" and not diverges:
        fail(vid, "code-point order and UTF-16 code-unit order agree on these "
                  "member names, so the member demonstrates no divergence")

    if not lines:
        fail(vid, "declares ordering digests with no record sidecar to "
                  "recompute them from")
        return
    record = json.loads(lines[-1])
    for key, form in (("chainHashCodePoint", jcs),
                      ("chainHashUtf16", jcs_utf16)):
        declared = entry["expected"].get(key)
        if declared is None:
            fail(vid, f"declares no {key}")
            continue
        if declared != sha(form(record)):
            fail(vid, f"{key} does not recompute from the sidecar record")

    # The sidecar must carry the bytes RFC 8785 requires, which is the
    # UTF-16-code-unit ordering. Recomputing the digests above cannot see this,
    # because parsing discards member order: without this comparison a sidecar
    # written in the wrong order would pass every other check in the file.
    if lines[-1] != jcs_utf16(record):
        fail(vid, "the sidecar line is not the RFC 8785 canonical bytes, "
                  "which are sorted by UTF-16 code unit")
    if diverges and lines[-1] == jcs(record):
        fail(vid, "the sidecar line is in code-point order, so the corpus "
                  "ships the divergent reading as though it were canonical")

    same = (entry["expected"].get("chainHashUtf16")
            == entry["expected"].get("chainHashCodePoint"))
    if diverges and same:
        fail(vid, "declares one chain hash for a record whose two orderings "
                  "produce different bytes")
    if not diverges and not same:
        fail(vid, "declares two chain hashes for a record whose two orderings "
                  "produce identical bytes")


def check_appendix_b(vid: str, stmt: dict, entry: dict) -> None:
    """Check an Appendix B row without reusing the generator's serializer.

    Recomputing the canonical bytes with the same function that wrote them
    would only prove the generator agrees with itself, so neither step below
    calls it. Instead the declared text is parsed back to a double and the
    digest is taken over the declared text directly, which together force the
    vector's digest to be over exactly the bytes the RFC prints for exactly
    the bit pattern the vector names.

    The family test lives here rather than in the caller's branch chain so
    that adding this check costs `main` no extra path.
    """
    if "appendix-b" not in vid:
        return
    want = entry["expected"]["canonicalNumber"]
    hexpat = entry["expected"]["ieee754"]

    # 1. The declared text denotes the declared IEEE value. Both zeros print
    #    as "0", which is the lossy step Appendix B row 2 exists to pin, so
    #    either zero pattern satisfies the zero text and nothing else does.
    parsed = float(want)
    if parsed == 0:
        if hexpat not in ("0000000000000000", "8000000000000000"):
            FAILURES.append(f"{vid}: canonicalNumber {want!r} is zero and "
                            f"ieee754 {hexpat} is not a zero pattern")
    elif struct.pack(">d", parsed).hex() != hexpat:
        FAILURES.append(
            f"{vid}: canonicalNumber {want!r} parses to "
            f"{struct.pack('>d', parsed).hex()}, not the declared {hexpat}")

    # 2. The digest the statement carries is over those exact bytes.
    canonical = ('{"value":' + want + "}").encode("utf-8")
    declared = entry["expected"]["requestDigest"]
    if sha(canonical) != declared:
        FAILURES.append(f"{vid}: requestDigest is not the digest of "
                        f"{canonical!r}")
    carried = stmt["predicate"]["contentDigest"]["request"]["sha256"]
    if carried != declared:
        FAILURES.append(f"{vid}: the statement carries request digest "
                        f"{carried[:12]} and the manifest declares "
                        f"{declared[:12]}")


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

        lines: list[bytes] = []
        if "records" in entry:
            rp = os.path.join(HERE, entry["records"])
            if not os.path.exists(rp):
                fail(vid, "manifest names a records sidecar that does not exist")
                continue
            with open(rp, "rb") as fh:
                lines = [ln for ln in fh.read().split(b"\n") if ln]
            check_chain_members(vid, kind, entry, lines)
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
        if vid in ("ok-013-bmp-extension-member-names",
                   "bad-116-astral-extension-member-name"):
            check_member_name_orders(vid, kind, stmt, entry, lines)
        check_appendix_b(vid, stmt, entry)

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

    # The vendored specification copy, against its pinned digest. The suite
    # certifies against that text as it read at the recorded commit PLUS the
    # proposed canonicalization strengthening (docs/ai-agent-action-
    # canonicalization.md): the accept members are conformant under #588 as it
    # stands, the reject members are rejectable only under the proposal, and a
    # claim of "certifies against #588" without that half overstates what the
    # pull request requires today. This file is the only evidence on disk of
    # what the upstream text said. A commit id in the manifest is a name anyone can write; the digest
    # is the thing an edit in place cannot survive.
    # The provenance half. The digest below is the pin a verifier acts on; these
    # fields are what lets a reader find the text upstream, and they were not
    # checked at all. specUpstreamCommit alone read as an address, and it is not
    # one: the pull request is opened from a fork branch that has since been
    # rewritten, so a plain clone of the review venue, of our fork, and of the
    # head fork all exit 128 on that commit. Naming the fork and branch does not
    # make the commit fetchable again; it makes the pin say what it is, so the
    # next reader spends the time on the vendored bytes rather than on a clone
    # that cannot succeed.
    for field in ("specUpstreamRepo", "specUpstreamRef", "specAuthority",
                  "specProvenanceNote"):
        if not manifest.get(field):
            FAILURES.append(
                f"the manifest carries no {field}, so it does not say where "
                "the vendored text came from or which pin is load-bearing")
    if manifest.get("specAuthority") != "specDigest":
        FAILURES.append(
            "specAuthority names something other than specDigest. The commit "
            "is orphaned upstream, so a pin on it is a pin on nothing; the "
            "digest is the only one this suite can enforce.")

    spec_rel = manifest["specVendored"]
    # The vendored filename carries the commit's short sha, so re-pinning the
    # commit without re-vendoring, or re-vendoring without re-pinning, leaves a
    # filename that contradicts the manifest beside it. Both halves currently
    # agree; nothing made them.
    stem = os.path.splitext(os.path.basename(spec_rel))[0]
    short = str(manifest.get("specUpstreamCommit", ""))[:7]
    if short and not stem.endswith(short):
        FAILURES.append(
            f"the vendored copy is named {stem!r} while the manifest pins "
            f"commit {short}, so the file name and the pin disagree about "
            "which revision is on disk")

    spec_path = os.path.join(HERE, spec_rel)
    if not os.path.exists(spec_path):
        FAILURES.append(f"the vendored specification {spec_rel} is missing, so "
                        "nothing records what this corpus certifies against")
    else:
        with open(spec_path, "rb") as fh:
            got = sha(fh.read())
        if got != manifest["specDigest"]:
            FAILURES.append(
                f"the vendored specification {spec_rel} does not match its "
                f"pinned digest (pinned {manifest['specDigest'][:12]}, on disk "
                f"{got[:12]}). Re-vendor from upstream rather than editing the "
                "copy, or the corpus certifies against text nobody published.")

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
