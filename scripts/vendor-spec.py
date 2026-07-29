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

    mapping = line_map(previous, spec_bytes)
    lines = spec_bytes.decode("utf-8", "replace").splitlines()
    moved = remap_citations(mapping, lines)
    moved_anchors = remap_anchors(mapping, lines)

    print(f"vendored {SPEC_REL} at {commit[:12]} ({digest[:12]}...)")
    if moved:
        print(f"remapped {moved} spec:NNN line citation(s) onto the new line numbers")
    if moved_anchors:
        print(f"remapped {moved_anchors} Lnnn anchor(s) onto the new line numbers")

    # Re-pin here rather than leaving it to the operator. The anchors rotted in
    # the first place because keeping them current was a manual step beside an
    # automatic one, and a ledger that has to be refreshed by hand is the same
    # bet with an extra file in it.
    #
    # The sync is allowed to refuse. It compares each moved anchor against the
    # revision the ledger was pinned to and will not write an anchor that came
    # off prose still present in the document, which is the shape a mis-aimed
    # remap has. When it refuses, the spec is already vendored and the citations
    # are already remapped; the anchors it names are corrected by hand and the
    # sync run again, so re-vendoring stays one command in the ordinary case and
    # stops at the point of doubt in the case that matters.
    synced = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "spec-anchor-gate.py"), "--sync"],
        check=False,
    )
    if synced.returncode != 0:
        print(
            "\nFAIL: the spec is vendored and the citations are remapped, but the "
            "anchor ledger was not written. Correct the anchors named above, then "
            "run scripts/spec-anchor-gate.py --sync.",
            file=sys.stderr,
        )
        return synced.returncode

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

# The corpus cites the same file a second way, as `Lnnn` and `Lnnn-mmm` anchors
# in the vector generator, the interpretation registries and the prose that
# reads them. The two spellings are one citation with two audiences: `spec:NNN`
# sits in code comments, `Lnnn` sits in tables a reader scans. Only the first
# was remapped for a while, and the second rotted at the first re-vendor that
# inserted a paragraph, which is how thirty-one anchors came to address prose
# they were never drawn against. Anything carrying an anchor is listed here.
ANCHOR_PATHS = (
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/interpretation-decisions.json",
    "vectors/coverage-unforced.json",
    "vectors/CHANGES.md",
    "docs/interpretation-decisions-open.md",
)
ANCHOR_RE = re.compile(r"\bL(\d+(?:-\d+)?)\b")


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


def rewrite(
    paths: list[Path],
    pattern: re.Pattern[str],
    prefix: str,
    mapping: dict[int, int],
    lines: list[str],
) -> int:
    """Rewrite every citation of one spelling in `paths`, and report how many
    tokens moved."""
    moved = 0
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")

        def sub(m: re.Match[str]) -> str:
            nonlocal moved
            token = remap_token(m.group(1), mapping, lines)
            if token != m.group(1):
                moved += 1
            return f"{prefix}{token}"

        updated = pattern.sub(sub, text)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
    return moved


def remap_citations(mapping: dict[int, int], lines: list[str]) -> int:
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
    paths = [p for g in CITING_GLOBS for p in sorted(REPO_ROOT.glob(g))]
    return rewrite(paths, CITATION_RE, "spec:", mapping, lines)


def remap_anchors(mapping: dict[int, int], lines: list[str]) -> int:
    """Rewrite every `Lnnn` anchor onto the new line numbers.

    The anchors address the vendored copy exactly as the `spec:NNN` citations
    do, so they move with the prose for exactly the same reason. Remapping keeps
    the corpus in the coordinate frame of the commit the vendor pin names: the
    anchors and the pin describe one revision, and neither is free to drift from
    the other between re-vendorings.

    Generated files are not listed and are not rewritten here. They carry the
    anchors their sources carry, so regenerating them after this runs is what
    moves them, and ``scripts/spec-anchor-gate.py`` fails if that regeneration
    was skipped.
    """
    paths = [REPO_ROOT / p for p in ANCHOR_PATHS]
    return rewrite(paths, ANCHOR_RE, "L", mapping, lines)


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
