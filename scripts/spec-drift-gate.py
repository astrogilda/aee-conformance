#!/usr/bin/env python3
"""Spec/corpus non-drift gate.

The vendored predicate spec (``spec/predicates/adversarial-execution-evidence.md``)
is the authority the conformance corpus certifies against. ``gen_manifest.py``
records its SHA-256 in ``vectors/MANIFEST.json`` (``specDigest``) at every
regeneration. This gate recomputes that digest and fails closed if the vendored
spec has changed without a corpus regeneration, so spec/corpus drift cannot land
silently.

Discipline it enforces: edit the spec -> regenerate the vectors -> regenerate
the manifest (which re-pins ``specDigest``) -> bump ``suiteRevision``. Skipping
the regeneration trips this gate.

Usage: python3 scripts/spec-drift-gate.py
Exit 0 when the recorded digest matches the vendored spec; 1 on drift.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    recorded = manifest.get("specDigest")
    spec_rel = manifest.get("specPath")
    if not recorded or not spec_rel:
        print(
            "FAIL: MANIFEST.json is missing specDigest/specPath; "
            "regenerate it with python3 vectors/gen_manifest.py",
            file=sys.stderr,
        )
        return 1

    spec_path = REPO_ROOT / spec_rel
    if not spec_path.is_file():
        print(f"FAIL: vendored spec not found at {spec_rel}", file=sys.stderr)
        return 1

    actual = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    if actual != recorded:
        print(
            "FAIL: spec/corpus drift.\n"
            f"  vendored spec:   {spec_rel}\n"
            f"  recorded digest: {recorded}\n"
            f"  actual digest:   {actual}\n"
            "The vendored spec changed without a corpus regeneration. Run the "
            "vector generators + python3 vectors/gen_manifest.py and bump "
            "suiteRevision, then commit the regenerated corpus.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: vendored spec matches MANIFEST specDigest ({recorded[:12]}...).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
