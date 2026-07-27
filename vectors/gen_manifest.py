#!/usr/bin/env python3
"""Generate MANIFEST.json for the AEE v0.6 conformance vector suite.

Derives the machine-readable expectations from the two human-authored
index tables (accept/INDEX.md and reject/INDEX.md), which remain the
prose source of truth. The MANIFEST is what the differential harness
(packaging/run_vectors.py) consumes: per-vector expected verdict, the
expected failure-code set for reject vectors (also the second-fault
self-check exemption key), the expected recomputed result for accept
vectors, and the expected per-row evidence tiers where the index pins
them. Regenerate byte-identically: python3 gen_manifest.py
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

# Tier expectations explicitly pinned by accept/INDEX.md (ok-024 row).
TIER_EXPECTATIONS = {
    "ok-024-mixed-basis-rows": {
        "tierWithPinnedKey": ["attested", "unattested", "declared"],
        "tierWithoutKey": ["unattested", "unattested", "declared"],
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
            if cells and re.match(r"^`?(ok|bad)-\d", cells[0]):
                rows.append(cells)
    return rows


def codes_of(cell: str) -> list[str]:
    return re.findall(r"`([a-z0-9-]+)`", cell)


def conditions_of(cell: str) -> list[str]:
    return re.findall(r"aee-c-\d+", cell)


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
        vectors.append(
            {
                "id": vid,
                "kind": "reject",
                "file": f"reject/{vid}.json",
                "conditions": conditions_of(cells[4]),
                "expected": {"verdict": "invalid", "codes": codes},
            }
        )

    # Closure check: every vector file must have exactly one INDEX row and vice
    # versa. Without this a malformed INDEX row is silently skipped by table_rows
    # and its vector is omitted from the manifest -- silently untested in
    # MANIFEST-mode replay.
    for kind in ("accept", "reject"):
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

    ok = sum(1 for v in vectors if v["id"].startswith("ok-"))
    bad = len(vectors) - ok
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
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"
        ),
        "specPath": SPEC_REL,
        "specDigest": spec_digest,
        "tracksUpstream": f"{pin['upstreamRepo']}#{pin['upstreamPullRequest']}",
        "specUpstreamCommit": pin["commit"],
        "counts": {"accept": ok, "reject": bad},
        "vectors": vectors,
    }
    out = os.path.join(HERE, "MANIFEST.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote {out}: {ok} accept + {bad} reject")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
