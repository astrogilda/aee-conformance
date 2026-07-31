#!/usr/bin/env python3
"""Generate MANIFEST.json for the AEE v0.7 conformance vector suite.

Derives the machine-readable expectations from the three human-authored
index tables (accept/INDEX.md, reject/INDEX.md and indeterminate/INDEX.md),
which remain the prose source of truth. The MANIFEST is what the differential
harness (packaging/run_vectors.py) consumes: per-vector expected verdict, the
expected failure-code set for reject vectors, any conditions a reject
vector carries deliberately beyond the one it pins (the two together are
the second-fault self-check's exemption key), the expected recomputed
result for accept vectors, the declared readings of each indeterminate
vector, and the expected per-row evidence tiers where
the index pins them. Regenerate byte-identically: python3 gen_manifest.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))

# The vendored predicate spec the corpus certifies against. Its content digest
# is recorded in the MANIFEST and re-checked in CI (scripts/spec-drift-gate.py)
# so an edit to the spec without a corpus regeneration fails closed instead of
# drifting silently.
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"
SPEC_PATH = os.path.normpath(os.path.join(HERE, "..", SPEC_REL))
# Upstream provenance is read from the vendor pin, never restated here. The pin
# is written by scripts/vendor-spec.py from git at vendor time, so the commit
# the corpus certifies against cannot disagree with the bytes it certifies.
PIN_PATH = os.path.normpath(os.path.join(HERE, "..", "spec", "VENDOR-PIN.json"))

# Tier expectations explicitly pinned by the accept/INDEX.md rows that state a
# tier in prose. Each entry is derivable from the vector's own bytes and the
# tier rule (spec:726-735, spec:1074-1075) without running any rail: a
# basis: substrate row is attested exactly when a covering record's signature
# verifies under a policy-named key, every other row is declared, and no key
# policy promotes a row when none is pinned.
#
# GATE 2 is the one output a vector count cannot stand in for. The harness
# compares a tier column only where the MANIFEST states one, so a column no
# vector states is checked against nothing on every rail but this suite's own,
# and for a long time ok-024 was the only row here -- which left the whole of
# tier.go forced by a single vector, and would have let a retitle of that one
# row retire five rules at once with every gate still green.
#
# This table is deliberately not the whole accept set. A column pinned on every
# vector is a recording of what some rail did rather than a claim anybody made,
# and it goes stale on the next regeneration; a column pinned where the index
# already makes the claim in prose is the same claim, machine-checked. The
# property that holds over every accept vector -- that the column partitions on
# the row's basis -- is asserted as an invariant instead, in the runners.
TIER_EXPECTATIONS = {
    # Substrate row, both covering records verify under the pinned key despite a
    # garbage keyid on one and an absent keyid on the other: keyid is a lookup
    # hint and never the check.
    "ok-019-wrong-keyid-sig-verifies": {
        "tierWithPinnedKey": ["attested"],
        "tierWithoutKey": ["unattested"],
    },
    # Substrate row whose covering record is signed over the raw payload rather
    # than the DSSE PAE, so it verifies under no key: the tier's fail-closed
    # path, and a tier fault rather than a validity fault.
    "ok-020-non-pae-signature": {
        "tierWithPinnedKey": ["unattested"],
        "tierWithoutKey": ["unattested"],
    },
    # The payload embeds a tempting public key. Pinned out of band the row is
    # attested; with nothing pinned it stays unattested, because the substrate
    # root is never inferred from the predicate.
    "ok-023-no-tofu-embedded-key": {
        "tierWithPinnedKey": ["attested"],
        "tierWithoutKey": ["unattested"],
    },
    "ok-024-mixed-basis-rows": {
        "tierWithPinnedKey": ["attested", "unattested", "declared"],
        "tierWithoutKey": ["unattested", "unattested", "declared"],
    },
    # An artifact row with two records and a correct batchRoot sitting right
    # beside it: verifiable material is present and the row is still declared
    # under every policy, because basis and not availability is what decides.
    "ok-029-artifact-with-records": {
        "tierWithPinnedKey": ["declared"],
        "tierWithoutKey": ["declared"],
    },
    # One substrate row covered by verifying records and one artifact row, so
    # the mixed-basis column does not rest on ok-024 alone.
    "ok-045-mixed-clean-rows-indirect": {
        "tierWithPinnedKey": ["attested", "declared"],
        "tierWithoutKey": ["unattested", "declared"],
    },
}


def table_rows(md_path: str) -> list[list[str]]:
    rows = []
    with open(md_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and re.match(r"^`?(ok|bad|ind)-\d", cells[0]):
                rows.append(cells)
    return rows


_IND_FAMILY = re.compile(r"^### Family `([^`]+)`")
_IND_READING = re.compile(r"reading `([a-z0-9-]+)`")


def indeterminate_rows(md_path: str) -> list[tuple[str, list[str], list[str]]]:
    """Return (family, reading names in column order, row cells) per vector.

    The reading names come off each family table's own header row rather than
    from a list in this file. A second copy here could disagree with the table a
    reviewer reads, and the thing an indeterminate vector exists to publish is
    exactly which readings were declared.
    """
    out: list[tuple[str, list[str], list[str]]] = []
    family = ""
    readings: list[str] = []
    with open(md_path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if match := _IND_FAMILY.match(line):
                family, readings = match.group(1), []
                continue
            if not line.startswith("|"):
                continue
            if found := _IND_READING.findall(line):
                readings = found
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and re.match(r"^`?ind-\d", cells[0]):
                if not family or not readings:
                    raise SystemExit(
                        f"{cells[0]}: a vector row with no '### Family' heading or "
                        "no reading columns above it. The family and the readings "
                        "are the whole of what this row declares."
                    )
                out.append((family, readings, cells))
    return out


_ALSO_CARRIES = "(also carries:"


def codes_of(cell: str) -> list[str]:
    """The expected-rejection code set: a rail conforms when its code is in it.

    A cell may append an "also carries" clause naming conditions the statement
    carries deliberately but that a conforming rail is not expected to report as
    its primary. Those are split off by also_carries_of below and never widen the
    expectation, since widening it is exactly what a precedence pin must not do.
    """
    return re.findall(r"`([a-z0-9-]+)`", cell.split(_ALSO_CARRIES)[0])


def also_carries_of(cell: str) -> list[str]:
    """Conditions the vector carries on purpose beyond the one it pins.

    They are the second-fault self-check's exemption key in the differential
    harness, and nothing else: declaring one does not make a rail reporting it
    conformant.
    """
    parts = cell.split(_ALSO_CARRIES)
    return re.findall(r"`([a-z0-9-]+)`", parts[1]) if len(parts) > 1 else []


def conditions_of(cell: str) -> list[str]:
    return re.findall(r"aee-c-\d+", cell)


def indeterminate_entries(md_path: str) -> list[dict[str, Any]]:
    """The manifest entries for the indeterminate bucket.

    Each row's expectation is a DETERMINED verdict plus one condition per
    declared reading. Exactly one condition per column is required rather than a
    set, because a reading that predicted several conditions could not be told
    apart from a widened expectation, which is the thing this bucket exists so
    that nobody has to write.
    """
    entries: list[dict[str, Any]] = []
    for family, readings, cells in indeterminate_rows(md_path):
        vid = cells[0].strip("`")
        # cells: id | parent | mutation | conditions | <one per reading> | spec
        predicted = [codes_of(c) for c in cells[4:4 + len(readings)]]
        if any(len(p) != 1 for p in predicted):
            raise SystemExit(
                f"{vid}: each reading column names exactly one condition; got "
                f"{predicted}"
            )
        entries.append(
            {
                "id": vid,
                "kind": "indeterminate",
                "file": f"indeterminate/{vid}.json",
                "conditions": conditions_of(cells[3]),
                "expected": {
                    "verdict": "invalid",
                    "family": family,
                    "readings": dict(
                        zip(readings, (p[0] for p in predicted), strict=True)
                    ),
                },
            }
        )
    return entries


def main() -> int:
    vectors: list[dict[str, Any]] = []

    for cells in table_rows(os.path.join(HERE, "accept", "INDEX.md")):
        vid = cells[0].strip("`")
        result = cells[1]
        expected: dict[str, Any] = {"verdict": "valid", "result": result}
        expected.update(TIER_EXPECTATIONS.get(vid, {}))
        vectors.append(
            {
                "id": vid,
                "kind": "accept",
                "file": f"accept/{vid}.json",
                "conditions": conditions_of(cells[2]),
                "expected": expected,
            }
        )

    for cells in table_rows(os.path.join(HERE, "reject", "INDEX.md")):
        vid = cells[0].strip("`")
        codes = codes_of(cells[5])
        if not codes:
            raise SystemExit(f"no expected codes parsed for {vid}")
        expected_reject: dict[str, Any] = {"verdict": "invalid", "codes": codes}
        if also := also_carries_of(cells[5]):
            expected_reject["alsoCarries"] = also
        vectors.append(
            {
                "id": vid,
                "kind": "reject",
                "file": f"reject/{vid}.json",
                "conditions": conditions_of(cells[4]),
                "expected": expected_reject,
            }
        )

    vectors.extend(
        indeterminate_entries(os.path.join(HERE, "indeterminate", "INDEX.md"))
    )

    # Closure check: every vector file must have exactly one INDEX row and vice
    # versa. Without this a malformed INDEX row is silently skipped by table_rows
    # and its vector is omitted from the manifest -- silently untested in
    # MANIFEST-mode replay.
    for kind in ("accept", "reject", "indeterminate"):
        files = {
            f[: -len(".json")]
            for f in os.listdir(os.path.join(HERE, kind))
            if f.endswith(".json")
        }
        indexed = {v["id"] for v in vectors if v["kind"] == kind}
        if missing := files - indexed:
            raise SystemExit(
                f"{kind}: vector file(s) with no INDEX.md row (would be silently "
                f"untested): {sorted(missing)}"
            )
        if extra := indexed - files:
            raise SystemExit(f"{kind}: INDEX.md row(s) with no vector file: {sorted(extra)}")

    ok = sum(1 for v in vectors if v["kind"] == "accept")
    bad = sum(1 for v in vectors if v["kind"] == "reject")
    undecided = sum(1 for v in vectors if v["kind"] == "indeterminate")
    spec_digest = hashlib.sha256(
        open(SPEC_PATH, "rb").read()  # noqa: SIM115 -- one-shot read
    ).hexdigest()
    with open(PIN_PATH, encoding="utf-8") as f:
        pin = json.load(f)
    if pin["specDigest"] != spec_digest:
        raise SystemExit(
            "spec/VENDOR-PIN.json describes different bytes than the vendored "
            f"spec ({pin['specDigest'][:12]}... vs {spec_digest[:12]}...); "
            "re-vendor with scripts/vendor-spec.py before regenerating"
        )
    manifest = {
        "suite": "adversarial-execution-evidence-conformance",
        "predicateType": (
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
        ),
        "specPath": SPEC_REL,
        "specDigest": spec_digest,
        "tracksUpstream": f"{pin['upstreamRepo']}#{pin['upstreamPullRequest']}",
        "specUpstreamCommit": pin["commit"],
        "counts": {"accept": ok, "reject": bad, "indeterminate": undecided},
        "vectors": vectors,
    }
    out = os.path.join(HERE, "MANIFEST.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote {out}: {ok} accept + {bad} reject + {undecided} indeterminate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
