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
import re
import subprocess
import sys
from difflib import SequenceMatcher
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

    moved = remap_citations(previous, spec_bytes)

    print(f"vendored {SPEC_REL} at {commit[:12]} ({digest[:12]}...)")
    if moved:
        print(f"remapped {moved} spec:NNN line citation(s) onto the new line numbers")
    print("NORMATIVE CHANGE: regenerate the corpus, then run")
    print("  python3 vectors/gen_manifest.py")
    print("and add a suiteRevision section to vectors/CHANGES.md.")
    return 0


# Source files carrying `spec:NNN` citations into the vendored copy.
CITING_GLOBS = (
    "aee/*.go",
    "cmd/*/*.go",
    "witnessattestor/*.go",
    "packaging/*.py",
    "vectors/*/*.py",
)
CITATION_RE = re.compile(r"spec:(\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*)")


def line_map(old: bytes, new: bytes) -> dict[int, int]:
    """Map 1-based line numbers in `old` to their new position in `new`.

    The diff is computed over NON-BLANK lines only, then blank lines are
    interpolated back in. A blank line is not an anchor: it is identical to
    every other blank line in the document, so a sequence matcher pairs it with
    whichever one balances the alignment, and a citation whose endpoint lands on
    one gets carried hundreds of lines away from its subject. Matching on
    content and interpolating the gaps keeps every citation attached to the
    prose it cites.

    Lines the edit deleted or replaced map to the start of the block that
    replaced them, which is the closest honest answer for a citation pointing
    into prose that no longer exists.
    """
    a = old.decode("utf-8", "replace").splitlines()
    b = new.decode("utf-8", "replace").splitlines()
    ai = [i for i, ln in enumerate(a) if ln.strip()]
    bi = [j for j, ln in enumerate(b) if ln.strip()]
    sm = SequenceMatcher(None, [a[i] for i in ai], [b[j] for j in bi], autojunk=False)

    mapping: dict[int, int] = {}
    for tag, i1, i2, j1, _j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                mapping[ai[i1 + k] + 1] = bi[j1 + k] + 1
        elif tag in ("replace", "delete"):
            target = bi[j1] + 1 if j1 < len(bi) else len(b)
            for k in range(i1, i2):
                mapping[ai[k] + 1] = target

    # Interpolate the blank lines: carry each one the same distance its nearest
    # preceding non-blank neighbour moved, so a range endpoint on a blank line
    # stays adjacent to its own paragraph.
    delta = 0
    for i in range(1, len(a) + 1):
        if i in mapping:
            delta = mapping[i] - i
        else:
            mapping[i] = min(max(i + delta, 1), len(b))
    return mapping


def remap_citations(old: bytes, new: bytes) -> int:
    """Rewrite every `spec:NNN` citation in the citing sources onto the new
    line numbers, and report how many tokens moved.

    Line-number citations into a file that is periodically re-vendored rot by
    construction: the spec gains a paragraph upstream and every pointer below it
    silently addresses the wrong prose. Nothing in this repository checked them,
    and a wrong pointer is worse than none, because it reads as evidence that a
    rule was implemented against a passage it was not. Remapping here makes the
    citations follow the content they cite, so re-vendoring cannot rot them; the
    rewrite lands in the same commit as the spec change and is reviewed as a
    diff like anything else.
    """
    mapping = line_map(old, new)
    lines = new.decode("utf-8", "replace").splitlines()
    moved = 0

    for pattern in CITING_GLOBS:
        for path in sorted(REPO_ROOT.glob(pattern)):
            text = path.read_text(encoding="utf-8")

            def sub(m: re.Match[str]) -> str:
                nonlocal moved
                token = remap_token(m.group(1), mapping, lines)
                if token != m.group(1):
                    moved += 1
                return f"spec:{token}"

            updated = CITATION_RE.sub(sub, text)
            if updated != text:
                path.write_text(updated, encoding="utf-8")
    return moved


def snap(n: int, lines: list[str], *, forward: bool) -> int:
    """Move a citation endpoint off a blank line onto real prose.

    A blank line carries nothing, so an endpoint on one is either a range that
    overshot its paragraph or a pointer that was always slightly wrong. A range
    start snaps forward to the first line with content and a range end snaps
    back to the last, which keeps the range covering exactly the prose it was
    drawn around.
    """
    total = len(lines)
    n = min(max(n, 1), total)
    step = 1 if forward else -1
    while 1 <= n <= total and not lines[n - 1].strip():
        n += step
    return min(max(n, 1), total)


def remap_token(token: str, mapping: dict[int, int], lines: list[str]) -> str:
    """Rewrite one citation token (`115`, `115-118`, `67-70,627`) onto the new
    line numbers, preserving the token's own comma spacing."""
    total = len(lines)
    parts: list[str] = []
    for part in (p.strip() for p in token.split(",")):
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            nlo = snap(min(mapping.get(lo, lo), total), lines, forward=True)
            nhi = max(snap(min(mapping.get(hi, hi), total), lines, forward=False), nlo)
            parts.append(f"{nlo}-{nhi}" if nhi != nlo else str(nlo))
        else:
            n = int(part)
            parts.append(str(snap(min(mapping.get(n, n), total), lines, forward=True)))
    return ", ".join(parts) if ", " in token else ",".join(parts)


if __name__ == "__main__":
    sys.exit(main())
