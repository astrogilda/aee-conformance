#!/usr/bin/env python3
"""Vector-distinctness gate: two identifiers may never address one statement.

Why this exists, stated as what actually happened rather than as a principle.

`bad-707-sealed-stillarmed-false` and `bad-713-only-sealed-ref-noncovering` were
BYTE-IDENTICAL, sha256 `80f1d055…` for both, while the manifest credited them to
different conditions -- `aee-c-65` and `aee-c-68`. So `aee-c-68`'s only reject
vector was a copy of another condition's, and the corpus credited a condition
with a discriminator it did not have. The cause was not a stray copy: `_seal_mut`
deliberately appends an unreferenced covering seal, and `bad-713`'s hand-written
builder reconstructed exactly that shape, so a design decision in one builder
retroactively made a different vector redundant. Nothing could see it.

The thing worth noticing is WHICH check failed to notice. `docs/FORCING-HONESTY.md`
is this corpus's own published weakness report and it counts, per condition, how
many vectors force it -- and it counted two for `aee-c-68`, because it counts
DECLARED CONDITIONS and never DISTINCT STATEMENTS. A report that exists to say
where the suite is weak could not see that two of its inputs were one artifact.
That is the gap this gate closes, and it closes it at the only place the question
is cheap: the bytes.

The manifest carries no per-vector digest, so before this gate nothing in the
repository pinned vector content at all. A vector could be silently replaced by a
copy of its neighbour and every count would still add up.

Usage: python3 scripts/vector-distinctness-gate.py
Exit 0 when every vector file is a distinct statement; 1 when two share a digest.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"


def main() -> int:
    if not MANIFEST.is_file():
        print(f"FAIL: {MANIFEST} is absent", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        print("FAIL: the manifest lists no vectors", file=sys.stderr)
        return 1

    by_digest: dict[str, list[str]] = defaultdict(list)
    missing: list[str] = []
    for entry in entries:
        vid = str(entry.get("id"))
        rel = entry.get("file")
        if not rel:
            missing.append(f"{vid} declares no file")
            continue
        path = REPO_ROOT / "vectors" / str(rel)
        if not path.is_file():
            path = REPO_ROOT / str(rel)
        if not path.is_file():
            missing.append(f"{vid} names {rel}, which is not on disk")
            continue
        by_digest[hashlib.sha256(path.read_bytes()).hexdigest()].append(vid)

    collisions = {d: ids for d, ids in by_digest.items() if len(ids) > 1}

    if missing or collisions:
        print(
            "FAIL: the corpus does not address one statement per identifier "
            f"({len(collisions)} collision(s), {len(missing)} unreadable):",
            file=sys.stderr,
        )
        for d, ids in sorted(collisions.items()):
            print(
                f"  - {', '.join(sorted(ids))} are byte-identical (sha256 {d[:16]}…). "
                "Every condition these are credited to shares one discriminator, so "
                "the coverage figures count a vector that does not exist separately.",
                file=sys.stderr,
            )
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(entries)} vectors, {len(by_digest)} distinct statements — "
        "no identifier shares a statement with another."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
