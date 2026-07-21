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

import json
import os
import re
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))

# Tier expectations explicitly pinned by accept/INDEX.md (ok-024 row).
TIER_EXPECTATIONS = {
    "ok-024-mixed-basis-rows": {
        "tierWithPinnedKey": ["attested", "unattested", "declared"],
        "tierWithoutKey": ["unattested", "unattested", "declared"],
    },
}


def table_rows(md_path: str) -> list[list[str]]:
    rows = []
    with open(md_path, "r", encoding="utf-8") as f:
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
                "file": "accept/%s.json" % vid,
                "conditions": conditions_of(cells[2]),
                "expected": expected,
            }
        )

    for cells in table_rows(os.path.join(HERE, "reject", "INDEX.md")):
        vid = cells[0].strip("`")
        codes = codes_of(cells[5])
        if not codes:
            raise SystemExit("no expected codes parsed for %s" % vid)
        vectors.append(
            {
                "id": vid,
                "kind": "reject",
                "file": "reject/%s.json" % vid,
                "conditions": conditions_of(cells[4]),
                "expected": {"verdict": "invalid", "codes": codes},
            }
        )

    ok = sum(1 for v in vectors if v["id"].startswith("ok-"))
    bad = len(vectors) - ok
    manifest = {
        "suite": "adversarial-execution-evidence-conformance",
        "predicateType": (
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"
        ),
        "counts": {"accept": ok, "reject": bad},
        "vectors": vectors,
    }
    out = os.path.join(HERE, "MANIFEST.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
        f.write("\n")
    print("wrote %s: %d accept + %d reject" % (out, ok, bad))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
