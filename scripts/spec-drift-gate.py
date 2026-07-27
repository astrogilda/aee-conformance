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
PIN = REPO_ROOT / "spec" / "VENDOR-PIN.json"


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

    # The provenance half of the same question. MANIFEST.specDigest says the
    # corpus was regenerated against these bytes; VENDOR-PIN.json says which
    # upstream commit these bytes came from. Both must agree with what is on
    # disk, because an outside implementer diffs the vendored copy against the
    # pinned commit to certify no version skew, and a pin naming the wrong
    # commit reports a drift that does not exist or hides one that does.
    if not PIN.is_file():
        print(
            f"FAIL: {PIN.relative_to(REPO_ROOT)} is missing; re-vendor with "
            "python3 scripts/vendor-spec.py --from <attestation checkout>",
            file=sys.stderr,
        )
        return 1
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    if pin.get("specDigest") != actual:
        print(
            "FAIL: vendor pin does not describe the vendored bytes.\n"
            f"  pinned commit:  {pin.get('commit')}\n"
            f"  pinned digest:  {pin.get('specDigest')}\n"
            f"  actual digest:  {actual}\n"
            "The vendored spec was edited in place instead of re-vendored. Edit "
            "the spec upstream, then run scripts/vendor-spec.py so the pin names "
            "a commit that actually contains these bytes.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: vendored spec matches MANIFEST specDigest ({recorded[:12]}...) "
        f"and VENDOR-PIN commit {str(pin.get('commit'))[:12]}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
