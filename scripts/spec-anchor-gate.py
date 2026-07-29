#!/usr/bin/env python3
"""Spec anchor gate.

The corpus cites the vendored predicate specification two ways. Code comments
use ``spec:NNN``, which ``scripts/spec-citation-gate.py`` checks. Tables a reader
scans -- the vector generator, the interpretation registries, and the documents
generated from them -- use ``Lnnn`` and ``Lnnn-mmm`` anchors, and until this gate
existed nothing checked those at all.

They rotted, exactly as line numbers into a periodically re-vendored file always
will. The anchors were migrated by hand once and then left behind by eleven
successive re-vendorings, so by the time anyone looked they addressed prose
hundreds of lines away from the rules they claimed to cite. A wrong anchor is
worse than no anchor, because it reads as evidence that a vector was written
against a passage it was never written against.

Two questions have to stay answered, and they need different checks.

*Does the anchor resolve?* Every endpoint must be inside the file, ordered, and
on a line that carries text. This is cheap and catches the crude failures, and
it is nowhere near sufficient: a line-range check passes for any number that
happens to land on prose, which is why anchors sat hundreds of lines wrong
while the sibling citation gate ran green on every build.

*Does the anchor still address the text it was recorded against?* This is the
question that catches the rot, and answering it needs something committed to
compare with. ``spec/ANCHOR-PINS.json`` records, for every citation, a digest of
the span's text plus its opening and closing lines in plain sight. The gate
recomputes and fails, naming the citation and printing both excerpts, the moment
an anchor addresses different bytes than the ones it was pinned to.

The pin is keyed by the citation, not by the line range. Keying it by the range
would make the record a pure function of the range and the spec, so the digest
could only ever restate the number it was looking up, and the check could never
fail. Keyed by the thing doing the citing -- this vector, this condition, this
registry decision -- the record survives the line numbers moving underneath it,
which is the whole point: after a re-vendor that did not remap, the citation is
still there, its pin still describes the old prose, and the recomputed text no
longer matches.

Why this is the right strength. It is deliberately weaker than checking the
anchor against the wording of the claim beside it: it never requires the cited
passage to contain particular words, so upstream may rewrite that passage freely
and ``scripts/vendor-spec.py`` re-pins in the same pass that remaps the anchors,
which keeps an ordinary re-vendor a one-command operation. It is much stronger
than a range check, because it fails on precisely the event that defines the
defect, an anchor coming to address prose it was not drawn around. And because
the pin carries readable excerpts rather than a bare digest, a changed anchor
shows up in review as the prose it now points at, sitting next to the claim it
is supposed to support, which is the one part of the judgement a numeric gate
cannot make on anyone's behalf.

What it does not do is decide whether a freshly written anchor cites the right
rule. Nothing mechanical can read a claim and judge which paragraph settles it.
The gate makes that a review question with the evidence attached rather than an
invisible one, and it makes the systematic failure, hundreds of anchors going
quietly wrong at once because a re-vendor moved the prose, impossible to commit.

Usage:
    python3 scripts/spec-anchor-gate.py           # check
    python3 scripts/spec-anchor-gate.py --sync    # rewrite the pin ledger
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"
PINS = REPO_ROOT / "spec" / "ANCHOR-PINS.json"

# Files whose anchors are written by hand. The pin ledger is synced from these
# and from nothing else, so a generated file that was not regenerated after a
# re-vendor still carries the old anchors, finds no pin for them, and fails.
AUTHORED = (
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/interpretation-decisions.json",
    "vectors/coverage-unforced.json",
    "vectors/CHANGES.md",
    "docs/interpretation-decisions-open.md",
)

# Files generated from those. Their anchors are checked but never pinned.
GENERATED = (
    "vectors/reject/INDEX.md",
    "docs/COVERAGE-MATRIX.md",
)

ANCHOR_RE = re.compile(r"\bL(\d+)(?:-(\d+))?\b")

EXCERPT_MAX = 96

# What a citation belongs to. A pin has to be found again after the spec has
# moved under it, so it is filed under the thing doing the citing rather than
# under a line number: this vector, this condition, this registry decision, this
# section of prose. Adding a vector then disturbs one entry instead of shifting
# every entry below it.
OWNERS = (
    re.compile(r'^vec\("([a-z0-9-]+)"'),                 # a reject vector
    re.compile(r'^\s*(\d+): \("L[\d-]+"'),               # a condition table row
    re.compile(r'^\s*"id":\s*"?([^",]+)"?,'),            # a registry entry
    re.compile(r"^#{1,6}\s+(.+?)\s*$"),                  # a prose section
    re.compile(r"^def (\w+)"),                           # generator prose
)


def normalize(line: str) -> str:
    """Collapse runs of whitespace, so a reflow that does not change a word does
    not read as a changed citation."""
    return " ".join(line.split())


def excerpt(line: str) -> str:
    text = normalize(line)
    return text if len(text) <= EXCERPT_MAX else text[: EXCERPT_MAX - 3] + "..."


class Citation:
    """One `Lnnn` or `Lnnn-mmm` token where it is written."""

    def __init__(self, key: str, token: str, lo: int, hi: int, site: str) -> None:
        self.key = key
        self.token = token
        self.lo = lo
        self.hi = hi
        self.site = site


def owner_of(line: str) -> str | None:
    for pattern in OWNERS:
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return None


def collect(paths: tuple[str, ...]) -> list[Citation]:
    found: list[Citation] = []
    for rel in paths:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        owner = "-"
        seen: dict[str, int] = {}
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            named = owner_of(line)
            if named:
                owner = named
            for m in ANCHOR_RE.finditer(line):
                lo = int(m.group(1))
                hi = int(m.group(2)) if m.group(2) else lo
                base = f"{rel}::{owner}"
                seen[base] = seen.get(base, -1) + 1
                found.append(
                    Citation(
                        f"{base}#{seen[base]}",
                        m.group(0),
                        lo,
                        hi,
                        f"{rel}:{lineno}",
                    )
                )
    return found


def resolution_failures(cite: Citation, spec: list[str]) -> list[str]:
    total = len(spec)
    out = []
    if cite.lo < 1 or cite.hi > total:
        out.append(f"names line(s) outside the spec, which has {total} lines")
        return out
    if cite.hi < cite.lo:
        out.append("range runs backwards")
        return out
    for n in (cite.lo, cite.hi):
        if not spec[n - 1].strip():
            out.append(f"endpoint line {n} is blank, so it cites nothing")
    return out


def pin_of(cite: Citation, spec: list[str]) -> dict[str, str]:
    body = "\n".join(normalize(x) for x in spec[cite.lo - 1 : cite.hi])
    return {
        "anchor": cite.token,
        "digest": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "opens": excerpt(spec[cite.lo - 1]),
        "closes": excerpt(spec[cite.hi - 1]),
    }


def spec_state() -> tuple[list[str], str]:
    raw = (REPO_ROOT / SPEC_REL).read_bytes()
    return (
        raw.decode("utf-8").splitlines(),
        hashlib.sha256(raw).hexdigest(),
    )


def sync() -> int:
    spec, digest = spec_state()
    cites = collect(AUTHORED)
    broken = [
        f"{c.site}: {c.token} {'; '.join(resolution_failures(c, spec))}"
        for c in cites
        if resolution_failures(c, spec)
    ]
    if broken:
        print(
            "FAIL: refusing to pin anchors that do not resolve; fix these first:",
            file=sys.stderr,
        )
        for b in sorted(broken):
            print(f"  {b}", file=sys.stderr)
        return 1
    PINS.write_text(
        json.dumps(
            {
                "specPath": SPEC_REL,
                "specDigest": digest,
                "citations": {c.key: pin_of(c, spec) for c in cites},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {PINS.relative_to(REPO_ROOT)}: {len(cites)} citation(s) pinned")
    return 0


def report(failures: list[str], checked: int) -> int:
    if not failures:
        print(f"OK: {checked} spec anchor(s) resolve and match their recorded text.")
        return 0
    print(
        f"FAIL: {len(failures)} spec anchor(s) do not hold (of {checked} checked):",
        file=sys.stderr,
    )
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    print(
        "\nAn anchor that no longer addresses the text it was pinned to is "
        "citing prose it was not drawn around. Re-vendor with "
        "scripts/vendor-spec.py, which remaps the anchors and re-pins them, or "
        "correct the anchor by hand and run this gate with --sync. Regenerate "
        "the corpus and the coverage matrix so the generated tables carry the "
        "corrected anchors too.",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the pin ledger from the anchors as they now stand",
    )
    args = ap.parse_args(argv[1:])
    if args.sync:
        return sync()

    spec, _digest = spec_state()
    if not PINS.is_file():
        print(
            f"FAIL: {PINS.relative_to(REPO_ROOT)} is missing; create it with "
            "python3 scripts/spec-anchor-gate.py --sync",
            file=sys.stderr,
        )
        return 1
    pins: dict[str, dict[str, str]] = json.loads(
        PINS.read_text(encoding="utf-8")
    ).get("citations", {})
    failures: list[str] = []

    authored = collect(AUTHORED)
    generated = collect(GENERATED)

    for cite in authored:
        broken = resolution_failures(cite, spec)
        if broken:
            failures.extend(f"{cite.site}: {cite.token} {b}" for b in broken)
            continue
        recorded = pins.get(cite.key)
        if recorded is None:
            failures.append(
                f"{cite.site}: {cite.token} has no recorded text. It was just "
                "written or its claim was rewritten, so run --sync and read the "
                "excerpt it records against the claim beside it."
            )
            continue
        actual = pin_of(cite, spec)
        if actual["digest"] != recorded["digest"]:
            failures.append(
                f"{cite.site}: {cite.token} no longer addresses the text it was "
                f"pinned to (it was pinned as {recorded.get('anchor')}).\n"
                f"      pinned: {recorded.get('opens')}\n"
                f"          ... {recorded.get('closes')}\n"
                f"      actual: {actual['opens']}\n"
                f"          ... {actual['closes']}"
            )

    # Generated tables carry the anchors their sources carry. One that names an
    # anchor no source names was written before the anchors moved and never
    # regenerated, which leaves a reader with a stale table and no warning.
    live = {c.token for c in authored}
    for cite in generated:
        failures.extend(
            f"{cite.site}: {cite.token} {b}"
            for b in resolution_failures(cite, spec)
        )
        if cite.token not in live:
            failures.append(
                f"{cite.site}: {cite.token} is cited by no source file, so this "
                "generated table was not regenerated after the anchors moved."
            )

    for key in sorted(set(pins) - {c.key for c in authored}):
        failures.append(
            f"spec/ANCHOR-PINS.json: {key} is pinned but nothing cites it; "
            "run --sync to drop it"
        )

    return report(failures, len(authored) + len(generated))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
