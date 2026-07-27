#!/usr/bin/env python3
"""Re-vendor the predicate specification from an upstream checkout.

The vendored copy at ``spec/predicates/adversarial-execution-evidence.md`` is a
byte-verbatim copy of the specification the standards body reviews, and the
whole point of vendoring it is that a relying party can implement from this
repository alone and get the same answers. That guarantee only holds if the
copy is honestly labelled with where it came from.

It was not. The commit the copy tracked lived as a sentence in
``spec/README.md``, typed by hand at vendor time, and it went stale the first
time the upstream branch moved: the README claimed ``4a36b19`` while the
vendored bytes were those of ``83da03e``, three normative revisions later.
That is not a cosmetic error. An independent implementer fetched exactly that
commit from the URL the README implies in order to diff the vendored copy
against branch head and certify no version skew -- so a stale pin either
manufactures a drift report that does not exist or hides one that does, and
either way it corrupts the only external evidence we have that the
specification is unambiguous.

So the pin is derived, never typed. This script resolves the commit with git,
copies the bytes, and writes ``spec/VENDOR-PIN.json``; the drift gate then
checks the vendored bytes against that record on every run, and the README
states no constant of its own.

Usage:
    python3 scripts/vendor-spec.py --from ~/path/to/attestation [--ref HEAD]

Re-vendoring is a normative change. Regenerate the corpus and bump
``suiteRevision`` in vectors/CHANGES.md afterwards; the drift gate fails until
vectors/gen_manifest.py has re-pinned the digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"
PIN_PATH = REPO_ROOT / "spec" / "VENDOR-PIN.json"

# The upstream pull request this predicate is proposed in. The commit is
# resolved from the checkout; only the PR identity is a constant, and it is a
# constant because a new PR number is a new vendoring relationship, not a drift.
UPSTREAM_REPO = "in-toto/attestation"
UPSTREAM_PR = 570


def git(checkout: Path, *args: str) -> str:
    """Run git in checkout and return stripped stdout, or exit with its error."""
    proc = subprocess.run(
        ["git", "-C", str(checkout), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"FAIL: git {' '.join(args)} in {checkout}: {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--from",
        dest="checkout",
        required=True,
        type=Path,
        help="path to an in-toto/attestation checkout on the predicate branch",
    )
    ap.add_argument(
        "--ref",
        default="HEAD",
        help="ref to vendor from (default HEAD; pass the remote ref to avoid "
        "vendoring from a stale local clone)",
    )
    args = ap.parse_args()

    checkout: Path = args.checkout.expanduser().resolve()
    if not (checkout / ".git").exists():
        raise SystemExit(f"FAIL: {checkout} is not a git checkout")

    commit = git(checkout, "rev-parse", args.ref)
    branch = git(checkout, "rev-parse", "--abbrev-ref", args.ref)

    # Read the bytes from the ref itself rather than the working tree, so an
    # uncommitted local edit can never be vendored under a commit that does not
    # contain it.
    proc = subprocess.run(
        ["git", "-C", str(checkout), "show", f"{commit}:{SPEC_REL}"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"FAIL: {SPEC_REL} not present at {commit[:12]}: "
            f"{proc.stderr.decode().strip()}"
        )
    spec_bytes = proc.stdout
    digest = hashlib.sha256(spec_bytes).hexdigest()

    dest = REPO_ROOT / SPEC_REL
    previous = dest.read_bytes() if dest.exists() else b""
    dest.write_bytes(spec_bytes)

    PIN_PATH.write_text(
        json.dumps(
            {
                "upstreamRepo": UPSTREAM_REPO,
                "upstreamPullRequest": UPSTREAM_PR,
                "ref": branch,
                "commit": commit,
                "specPath": SPEC_REL,
                "specDigest": digest,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if previous == spec_bytes:
        print(f"vendored spec unchanged at {commit[:12]} ({digest[:12]}...)")
        print("pin refreshed; no corpus regeneration needed")
        return 0

    print(f"vendored {SPEC_REL} at {commit[:12]} ({digest[:12]}...)")
    print("NORMATIVE CHANGE: regenerate the corpus, then run")
    print("  python3 vectors/gen_manifest.py")
    print("and add a suiteRevision section to vectors/CHANGES.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
