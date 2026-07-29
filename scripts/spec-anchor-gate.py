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

What --sync has to assert, and why it is not a receipt
------------------------------------------------------

The ledger is refreshed by ``--sync``, and ``scripts/vendor-spec.py`` calls it as
the last step of a re-vendor. So on the one operation that moves anchors, the
record this gate checks is rewritten from whatever the remap produced, and the
check that follows can only ever agree with it. A re-vendor is exactly when
anchors move, which left the gate armed everywhere except where it was needed.
It is not a hypothetical: nine anchors came out of one remap addressing the
wrong text and were written down as correct, and the only thing that caught them
was a person reading the excerpt diff.

A sync cannot simply refuse to move anchors, because anchors must move when the
document moves. So it asserts something narrower and mechanical: **a sync may
not move an anchor off text that still exists.** For every citation whose span
text changed, the previously pinned text is looked for in the new document,
ignoring line breaks. If it is still there, then the remap had somewhere correct
to land and did not, so the sync fails, names the citation, and prints where the
text now lives. If it is not there, upstream genuinely rewrote that prose and the
excerpt change is legitimate; those are listed for review rather than blocked.

That separation is what keeps this useful. The obvious alternative, emitting
every changed excerpt as a receipt and requiring an acknowledgement, fires on
every ordinary re-vendor -- thirty-five excerpts moved on the last one -- so the
acknowledgement degrades into a reflex, and a check that fires on everything
tells a reader nothing about the case that matters. This one fires only on the
shape the defect had, and it fires without needing anybody to be attentive.

A person may still deliberately re-aim an anchor onto different prose, and that
is indistinguishable from a bad remap by looking at files alone. So it is
allowed, one citation at a time and by name, with ``--accept-reaim <key>``. The
automatic path cannot use it, because nothing generates those keys; a person has
to read the failure, decide the move is intended, and type it.

Usage:
    python3 scripts/spec-anchor-gate.py           # check
    python3 scripts/spec-anchor-gate.py --sync    # rewrite the pin ledger
    python3 scripts/spec-anchor-gate.py --sync --accept-reaim <citation-key>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
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
    # A condition table row. The anchor cell is matched loosely because a row may
    # carry several anchors; requiring a single one filed the extra anchors of a
    # multi-anchor condition under whichever row happened to precede it.
    re.compile(r'^\s*(\d+): \("L'),
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

    def __init__(
        self, key: str, token: str, lo: int, hi: int, site: str, owner: str
    ) -> None:
        self.key = key
        self.token = token
        self.lo = lo
        self.hi = hi
        self.site = site
        self.owner = owner


# The row a generated table line belongs to. A generated table is checked against
# the source it was generated from, and that comparison is only meaningful per
# row: asking whether an anchor appears anywhere in the authored set passes for a
# stale row whenever the number it carries is still cited by some unrelated
# entry, which is common here because neighbouring rules share spans.
GENERATED_ROWS = (
    re.compile(r"^\|\s*`?(bad-\d[a-z0-9-]*)`?\s*\|"),  # a reject-index vector row
    re.compile(r"^\|\s*aee-c-(\d+)\s*\|"),             # a reject-index condition row
    re.compile(r"^\|\s*(D\d+|U\d+)\s"),                # a coverage-matrix row
)


def owner_of(line: str) -> str | None:
    for pattern in OWNERS:
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return None


def row_owner(line: str) -> str | None:
    """The identifier in a generated table row's first cell, in the spelling the
    authored source files it under. The matrix prints a registry decision as
    ``D13`` where the registry itself records the id ``13``."""
    for pattern in GENERATED_ROWS:
        m = pattern.match(line)
        if m:
            name = m.group(1)
            return name[1:] if name[0] == "D" and name[1:].isdigit() else name
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
                        row_owner(line) or owner,
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


def flatten(spec: list[str]) -> tuple[str, list[int], list[int]]:
    """The document as one string with every line break gone, plus the character
    range each line occupies in it.

    Line breaks are what a re-vendor moves most and means least: a paragraph
    rewrapped upstream is the same prose. Comparing spans this way is what lets
    the sync tell "upstream rewrote this passage" apart from "the remap lost
    track of a passage that is still there", and those two need opposite
    answers.
    """
    parts: list[str] = []
    starts = [0] * (len(spec) + 2)
    ends = [0] * (len(spec) + 2)
    pos = 0
    for i, line in enumerate(spec, 1):
        starts[i] = pos
        words = " ".join(line.split())
        if words:
            parts.append(words)
            pos += len(words) + 1
        ends[i] = pos
    return "".join(p + " " for p in parts), starts, ends


def occurrences(haystack: str, needle: str) -> list[tuple[int, int]]:
    """Every place the text still sits, because a passage may appear twice and
    the anchor only has to be on one of them."""
    spans, at = [], haystack.find(needle)
    while at >= 0:
        spans.append((at, at + len(needle)))
        at = haystack.find(needle, at + 1)
    return spans


def old_span(recorded: dict[str, str], base: list[str]) -> tuple[int, int] | None:
    m = ANCHOR_RE.fullmatch(str(recorded.get("anchor", "")))
    if not m:
        return None
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    return (lo, hi) if 1 <= lo <= hi <= len(base) else None


def reaimed(
    old: dict[str, dict[str, str]],
    new: dict[str, dict[str, str]],
    spec: list[str],
    base: list[str],
    cites: list[Citation],
    accepted: set[str],
) -> tuple[list[str], list[str]]:
    """Split the citations whose span text changed into the ones that moved off
    prose that is still in the document and the ones whose prose was rewritten.

    Only the first is a defect. The second is what an ordinary amendment does,
    and blocking on it would make every re-vendor a negotiation. A key named in
    ``accepted`` is a move a person has read and intends, so it is neither.
    """
    doc, starts, ends = flatten(spec)
    base_doc, base_starts, base_ends = flatten(base)
    moved_off: list[str] = []
    rewritten: list[str] = []
    for c in cites:
        recorded = old.get(c.key)
        if c.key in accepted or not recorded:
            continue
        if recorded["digest"] == new[c.key]["digest"]:
            continue
        was = old_span(recorded, base)
        body = base_doc[base_starts[was[0]] : base_ends[was[1]]].strip() if was else ""
        found = occurrences(doc, body) if body else []
        if not found:
            rewritten.append(f"{c.key} ({c.site}) -> {new[c.key]['opens']}")
            continue
        here = (starts[c.lo], ends[c.hi])
        if any(a < here[1] and here[0] < b for a, b in found):
            continue
        moved_off.append(
            f"{c.key} ({c.site}): {c.token} addresses different prose, but the "
            f"text it was pinned to is still in the document.\n"
            f"      pinned: {recorded.get('opens')}\n"
            f"          ... {recorded.get('closes')}\n"
            f"      actual: {new[c.key]['opens']}\n"
            f"          ... {new[c.key]['closes']}"
        )
    return moved_off, rewritten


def spec_state() -> tuple[list[str], str]:
    raw = (REPO_ROOT / SPEC_REL).read_bytes()
    return (
        raw.decode("utf-8").splitlines(),
        hashlib.sha256(raw).hexdigest(),
    )


def recorded_ledger() -> tuple[dict[str, dict[str, str]], str]:
    if not PINS.is_file():
        return {}, ""
    ledger = json.loads(PINS.read_text(encoding="utf-8"))
    pins: dict[str, dict[str, str]] = ledger.get("citations", {})
    return pins, str(ledger.get("specDigest", ""))


def committed_spec(want_digest: str) -> list[str] | None:
    """The vendored specification as the last commit has it, when that is the
    revision the current ledger was pinned against.

    The before-image is taken from git rather than carried in the ledger. The
    ledger already records which revision it describes, and git already holds
    that revision's bytes, so copying the prose into a third place would be one
    more copy to keep in step. It is only ever consulted when a pin moved, which
    is when the question "was this text still there" arises.
    """
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"HEAD:{SPEC_REL}"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout
    if hashlib.sha256(raw).hexdigest() != want_digest:
        return None
    return raw.decode("utf-8").splitlines()


def no_before_image() -> int:
    print(
        "FAIL: pinned anchors moved, and the revision the ledger was pinned "
        "against is not the one the last commit carries, so there is no "
        "trustworthy before-image to judge the move against.\n"
        "This happens when a second re-vendor runs on top of an uncommitted "
        "first one. Commit the first, or reset the working tree, and run the "
        "sync again. Writing the ledger from here would record whatever the "
        "remap produced as correct, which is the one thing this gate exists to "
        "stop.",
        file=sys.stderr,
    )
    return 1


def refuse_reaim(moved_off: list[str]) -> int:
    print(
        f"FAIL: refusing to re-pin {len(moved_off)} anchor(s) that moved off text "
        "which is still in the document:",
        file=sys.stderr,
    )
    for m in moved_off:
        print(f"  {m}", file=sys.stderr)
    print(
        "\nA remap that leaves an anchor addressing prose it was not drawn around "
        "is the defect this ledger exists to make visible, and writing the ledger "
        "from that remap would record it as correct. Point each anchor at the "
        "lines named above, or, if the move is deliberate, re-run with "
        "--accept-reaim <key> for each one and say in the commit message why the "
        "citation belongs on its new subject.",
        file=sys.stderr,
    )
    return 1


def sync(accepted: set[str]) -> int:
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

    fresh = {c.key: pin_of(c, spec) for c in cites}
    old, pinned_against = recorded_ledger()
    rewritten: list[str] = []
    if any(k in old and old[k]["digest"] != v["digest"] for k, v in fresh.items()):
        base = committed_spec(pinned_against)
        if base is None:
            return no_before_image()
        moved_off, rewritten = reaimed(old, fresh, spec, base, cites, accepted)
        if moved_off:
            return refuse_reaim(moved_off)

    PINS.write_text(
        json.dumps(
            {"specPath": SPEC_REL, "specDigest": digest, "citations": fresh},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {PINS.relative_to(REPO_ROOT)}: {len(cites)} citation(s) pinned")
    if rewritten:
        print(
            f"{len(rewritten)} citation(s) address prose upstream rewrote, so their "
            "excerpts changed. Read each against the claim beside it:"
        )
        for r in sorted(rewritten):
            print(f"  {r}")
    if accepted:
        print(f"{len(accepted)} deliberate re-aim(s) accepted: {', '.join(sorted(accepted))}")
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


def authored_failures(
    authored: list[Citation], pins: dict[str, dict[str, str]], spec: list[str]
) -> list[str]:
    """Every hand-written anchor must resolve and still address its pinned text."""
    failures: list[str] = []
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
    return failures


def generated_failures(
    generated: list[Citation], authored: list[Citation], spec: list[str]
) -> list[str]:
    """A generated table carries the anchors its source carries, so a row naming
    an anchor its own source does not is a row that was written before the
    anchors moved and never regenerated, leaving a reader a stale table and no
    warning.

    The question is asked per row. Asking whether the anchor appears anywhere in
    the authored set is this same check with the row thrown away, and it passes
    for a stale row whenever the number it carries is still cited by some other
    entry. Neighbouring rules here share spans constantly, so that is the common
    case rather than the exotic one, and the check was answering a question
    nobody had asked.
    """
    live_rows: dict[str, set[str]] = {}
    for cite in authored:
        live_rows.setdefault(cite.owner, set()).add(cite.token)
    live = {c.token for c in authored}
    failures: list[str] = []
    for cite in generated:
        failures.extend(
            f"{cite.site}: {cite.token} {b}" for b in resolution_failures(cite, spec)
        )
        row = live_rows.get(cite.owner)
        if row is not None and cite.token not in row:
            failures.append(
                f"{cite.site}: {cite.token} is not among the anchors the source "
                f"records for {cite.owner} ({', '.join(sorted(row))}), so this "
                "generated row was not regenerated after the anchors moved."
            )
        # An anchor in a generated file's prose rather than in one of its rows
        # has no row to key on, so it keeps the weaker whole-file question.
        elif row is None and cite.token not in live:
            failures.append(
                f"{cite.site}: {cite.token} is cited by no source file, so this "
                "generated table was not regenerated after the anchors moved."
            )
    return failures


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the pin ledger from the anchors as they now stand",
    )
    ap.add_argument(
        "--accept-reaim",
        action="append",
        default=[],
        metavar="KEY",
        help="one citation key whose move onto different prose is intended",
    )
    args = ap.parse_args(argv[1:])
    if args.sync:
        return sync(set(args.accept_reaim))

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
    authored = collect(AUTHORED)
    generated = collect(GENERATED)
    failures = authored_failures(authored, pins, spec)
    failures += generated_failures(generated, authored, spec)
    failures += [
        f"spec/ANCHOR-PINS.json: {key} is pinned but nothing cites it; "
        "run --sync to drop it"
        for key in sorted(set(pins) - {c.key for c in authored})
    ]
    return report(failures, len(authored) + len(generated))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
