#!/usr/bin/env python3
"""Content pins for citations into the vendored specification.

This repository cites the vendored predicate specification in two spellings.
``Lnnn`` anchors sit in the tables a reader scans; ``spec:NNN`` citations sit in
the Go and Python sources beside the rule each one implements. The two
spellings have different syntax, different owners and different audiences, but
they have the same defect and therefore need the same check, so the part that is
genuinely common lives here and each gate supplies its own collector.

What is common is the pin itself. A line number into a file that is
periodically re-vendored rots by construction: the specification gains a
paragraph upstream, every pointer below it addresses different prose, and
nothing about the pointer looks wrong afterwards. Asking whether a citation
resolves cannot see that, because a stale number lands on prose just as readily
as a current one. So each citation is recorded against a digest of the text it
was written for, and the gate recomputes that digest and fails when it moves.

The pin is keyed by the citing site and never by the line range. Keyed by the
range, the record would be a pure function of the range and the document, so the
digest could only ever restate the number it had just looked up and the check
could never fail. Keyed by the thing doing the citing, this function, this
vector, this registry decision, the record survives the line numbers moving
underneath it, which is the entire point: after a re-vendor that did not remap,
the citation is still there, its pin still describes the old prose, and the
recomputed text no longer matches.

The ledger is refreshed by a synchronise, which ``scripts/vendor-spec.py`` runs
as the last step of a re-vendor. That is the one operation during which
citations move, so a synchronise that simply wrote down whatever the remap
produced would leave both gates armed everywhere except where they were needed.
A synchronise cannot refuse to move citations, because citations must move when
the document moves, so it asserts something narrower and mechanical: a
synchronise may not move a citation off text that still exists. For every
citation whose text changed, the previously pinned prose is reconstructed from
the revision the ledger names and looked for in the new document, ignoring line
breaks. Still there means the remap had somewhere correct to land and did not,
which is a defect and is refused by name. Gone means upstream rewrote that
passage, which is what an ordinary amendment does, and is listed for review.

A person may still deliberately re-aim a citation onto different prose, and
that is indistinguishable from a bad remap by looking at files alone. So it is
allowed one citation at a time, by name, with ``--accept-reaim``. The automatic
path cannot use it, because nothing generates those keys: a person has to read
the failure, decide the move is intended, and type it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXCERPT_MAX = 96


@dataclass(frozen=True)
class Ledger:
    """Where one spelling's pins live, and how that spelling is written down.

    The two ledgers are separate files rather than one, because they are
    refreshed from different sources and read by different reviewers, and a
    single file would make an anchor change and a citation change
    indistinguishable in a diff.
    """

    path: Path
    spec_rel: str
    # The field a pin records its citation under. The two spellings name
    # different things and a reader of the ledger should see the word that
    # belongs to the spelling in front of them.
    token_field: str
    noun: str
    article: str
    # How to read a recorded token back into a line range, so a moved citation
    # can be compared against the span it used to address.
    token_re: re.Pattern[str]


@dataclass(frozen=True)
class Cited:
    """One citation, at the place it is written.

    ``token`` is the citation as it appears, and it is exactly one span. A
    ``spec:NNN`` citation may name several disjoint spans in one token, and each
    of those is recorded separately: a remap can carry one part of a citation
    off its subject while leaving the others alone, and a pin over the parts
    together would report that as a single opaque change with nothing to say
    about which part moved.
    """

    key: str
    token: str
    lo: int
    hi: int
    site: str


def normalize(line: str) -> str:
    """Collapse runs of whitespace, so a reflow that does not change a word does
    not read as a changed citation."""
    return " ".join(line.split())


def excerpt(line: str) -> str:
    text = normalize(line)
    return text if len(text) <= EXCERPT_MAX else text[: EXCERPT_MAX - 3] + "..."


def resolution_failures(cite: Cited, spec: list[str]) -> list[str]:
    """The cheap question: is this a range inside the document at all.

    It catches the crude failures and it is nowhere near sufficient, because a
    range check passes for any number that happens to land on prose. That is
    precisely how citations of both spellings sat hundreds of lines wrong while
    a resolution check ran green on every build.
    """
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


def pin_of(cite: Cited, spec: list[str], ledger: Ledger) -> dict[str, str]:
    """The record for one citation: a digest of the text it addresses, plus the
    first and last lines in plain sight.

    The excerpts are what make a changed pin reviewable. A bare digest tells a
    reader that something moved; the excerpts show the prose the citation now
    points at, sitting next to the claim it is supposed to support, which is the
    one part of the judgement no numeric gate can make on anyone's behalf.
    """
    body = "\n".join(normalize(x) for x in spec[cite.lo - 1 : cite.hi])
    return {
        ledger.token_field: cite.token,
        "digest": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "opens": excerpt(spec[cite.lo - 1]),
        "closes": excerpt(spec[cite.hi - 1]),
    }


def spec_state(spec_rel: str) -> tuple[list[str], str]:
    raw = (REPO_ROOT / spec_rel).read_bytes()
    return raw.decode("utf-8").splitlines(), hashlib.sha256(raw).hexdigest()


def read_pins(ledger: Ledger) -> tuple[dict[str, dict[str, str]], str]:
    if not ledger.path.is_file():
        return {}, ""
    recorded = json.loads(ledger.path.read_text(encoding="utf-8"))
    pins: dict[str, dict[str, str]] = recorded.get("citations", {})
    return pins, str(recorded.get("specDigest", ""))


def flatten(spec: list[str]) -> tuple[str, list[int], list[int]]:
    """The document as one string with every line break gone, plus the character
    range each line occupies in it.

    Line breaks are what a re-vendor moves most and means least: a paragraph
    rewrapped upstream is the same prose. Comparing spans this way is what lets
    the synchronise tell "upstream rewrote this passage" apart from "the remap
    lost track of a passage that is still there", and those two need opposite
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
    the citation only has to be on one of them."""
    spans, at = [], haystack.find(needle)
    while at >= 0:
        spans.append((at, at + len(needle)))
        at = haystack.find(needle, at + 1)
    return spans


def old_span(
    recorded: dict[str, str], base: list[str], ledger: Ledger
) -> tuple[int, int] | None:
    m = ledger.token_re.fullmatch(str(recorded.get(ledger.token_field, "")))
    if not m:
        return None
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    return (lo, hi) if 1 <= lo <= hi <= len(base) else None


def committed_spec(spec_rel: str, want_digest: str) -> list[str] | None:
    """The vendored specification as the last commit has it, when that is the
    revision the current ledger was pinned against.

    The before-image is taken from git rather than carried in the ledger. The
    ledger already records which revision it describes, and git already holds
    that revision's bytes, so copying the prose into a third place would be one
    more copy to keep in step. It is only ever consulted when a pin moved, which
    is when the question "was this text still there" arises.
    """
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"HEAD:{spec_rel}"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout
    if hashlib.sha256(raw).hexdigest() != want_digest:
        return None
    return raw.decode("utf-8").splitlines()


def no_before_image(ledger: Ledger) -> int:
    print(
        f"FAIL: pinned {ledger.noun}s moved, and the revision the ledger was "
        "pinned against is not the one the last commit carries, so there is no "
        "trustworthy before-image to judge the move against.\n"
        "This happens when a second re-vendor runs on top of an uncommitted "
        "first one. Commit the first, or reset the working tree, and run the "
        "sync again. Writing the ledger from here would record whatever the "
        "remap produced as correct, which is the one thing this gate exists to "
        "stop.",
        file=sys.stderr,
    )
    return 1


def refuse_reaim(moved_off: list[str], ledger: Ledger) -> int:
    print(
        f"FAIL: refusing to re-pin {len(moved_off)} {ledger.noun}(s) that moved "
        "off text which is still in the document:",
        file=sys.stderr,
    )
    for m in moved_off:
        print(f"  {m}", file=sys.stderr)
    print(
        f"\nA remap that leaves {ledger.article} {ledger.noun} addressing prose "
        "it was not drawn around is the defect this ledger exists to make "
        "visible, and writing the ledger from that remap would record it as "
        f"correct. Point each {ledger.noun} at the lines named above, or, if "
        "the move is deliberate, re-run with --accept-reaim <key> for each one "
        "and say in the commit message why the citation belongs on its new "
        "subject.",
        file=sys.stderr,
    )
    return 1


def reaimed(
    old: dict[str, dict[str, str]],
    new: dict[str, dict[str, str]],
    spec: list[str],
    base: list[str],
    cites: list[Cited],
    accepted: set[str],
    ledger: Ledger,
) -> tuple[list[str], list[str], list[str]]:
    """Split the citations whose text changed into the ones that moved off prose
    that is still in the document, the ones this check cannot read at all, and
    the ones whose prose was rewritten.

    Only the first is a defect. The last is what an ordinary amendment does, and
    blocking on it would make every re-vendor a negotiation. A key named in
    ``accepted`` is a move a person has read and intends, so it is neither.

    The middle case is separated because folding it into the last one is how
    this check silently stopped working once already. A recorded citation that
    cannot be parsed back into a line range leaves nothing to look for, an empty
    search finds nothing, and finding nothing is the signature of a legitimate
    rewrite, so every move on every citation was waved through as an amendment
    and the synchronise could not refuse anything. An instrument that cannot be
    evaluated has to say so rather than return the answer a caller is free to
    read as good news.
    """
    doc, starts, ends = flatten(spec)
    base_doc, base_starts, base_ends = flatten(base)
    moved_off: list[str] = []
    unreadable: list[str] = []
    rewritten: list[str] = []
    for c in cites:
        recorded = old.get(c.key)
        if c.key in accepted or not recorded:
            continue
        if recorded["digest"] == new[c.key]["digest"]:
            continue
        was = old_span(recorded, base, ledger)
        if was is None:
            unreadable.append(
                f"{c.key} ({c.site}): the ledger records "
                f"{recorded.get(ledger.token_field)!r}, which is not a line "
                "range in the revision the ledger names."
            )
            continue
        body = base_doc[base_starts[was[0]] : base_ends[was[1]]].strip()
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
    return moved_off, unreadable, rewritten


def refuse_unreadable(unreadable: list[str], ledger: Ledger) -> int:
    print(
        f"FAIL: {len(unreadable)} recorded {ledger.noun}(s) cannot be read back "
        "as a line range, so whether they moved off text that still exists "
        "cannot be decided:",
        file=sys.stderr,
    )
    for u in unreadable:
        print(f"  {u}", file=sys.stderr)
    print(
        "\nThis is a defect in the ledger or in the gate that writes it, not in "
        "the specification. Writing the ledger from here would record the "
        "remap as correct without ever having checked it, which is the one "
        "thing this gate exists to stop.",
        file=sys.stderr,
    )
    return 1


def refuse_unresolved(broken: list[str], ledger: Ledger) -> int:
    print(
        f"FAIL: refusing to pin {ledger.noun}s that do not resolve; fix these "
        "first:",
        file=sys.stderr,
    )
    for b in sorted(broken):
        print(f"  {b}", file=sys.stderr)
    return 1


def sync(ledger: Ledger, cites: list[Cited], accepted: set[str]) -> int:
    """Rewrite one ledger from the citations as they now stand, refusing any
    that came off text the document still carries."""
    spec, digest = spec_state(ledger.spec_rel)
    broken = [
        f"{c.site}: {c.token} {'; '.join(resolution_failures(c, spec))}"
        for c in cites
        if resolution_failures(c, spec)
    ]
    if broken:
        return refuse_unresolved(broken, ledger)

    fresh = {c.key: pin_of(c, spec, ledger) for c in cites}
    old, pinned_against = read_pins(ledger)
    rewritten: list[str] = []
    if any(k in old and old[k]["digest"] != v["digest"] for k, v in fresh.items()):
        base = committed_spec(ledger.spec_rel, pinned_against)
        if base is None:
            return no_before_image(ledger)
        moved_off, unreadable, rewritten = reaimed(
            old, fresh, spec, base, cites, accepted, ledger
        )
        if unreadable:
            return refuse_unreadable(unreadable, ledger)
        if moved_off:
            return refuse_reaim(moved_off, ledger)

    ledger.path.write_text(
        json.dumps(
            {"specPath": ledger.spec_rel, "specDigest": digest, "citations": fresh},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {ledger.path.relative_to(REPO_ROOT)}: {len(cites)} citation(s) pinned"
    )
    if rewritten:
        print(
            f"{len(rewritten)} citation(s) address prose upstream rewrote, so their "
            "excerpts changed. Read each against the claim beside it:"
        )
        for r in sorted(rewritten):
            print(f"  {r}")
    if accepted:
        print(
            f"{len(accepted)} deliberate re-aim(s) accepted: "
            f"{', '.join(sorted(accepted))}"
        )
    return 0


def pinned_failures(
    cites: list[Cited], pins: dict[str, dict[str, str]], spec: list[str], ledger: Ledger
) -> list[str]:
    """Every citation must resolve and still address its pinned text."""
    failures: list[str] = []
    for cite in cites:
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
        actual = pin_of(cite, spec, ledger)
        if actual["digest"] != recorded["digest"]:
            failures.append(
                f"{cite.site}: {cite.token} no longer addresses the text it was "
                f"pinned to (it was pinned as {recorded.get(ledger.token_field)}).\n"
                f"      pinned: {recorded.get('opens')}\n"
                f"          ... {recorded.get('closes')}\n"
                f"      actual: {actual['opens']}\n"
                f"          ... {actual['closes']}"
            )
    return failures


def orphan_failures(
    pins: dict[str, dict[str, str]], cites: list[Cited], ledger: Ledger
) -> list[str]:
    """A pin nothing cites any more. It is dropped by --sync; leaving it would
    let a deleted citation keep a record that quietly stops describing anything.
    """
    live = {c.key for c in cites}
    label = ledger.path.relative_to(REPO_ROOT)
    return [
        f"{label}: {key} is pinned but nothing cites it; run --sync to drop it"
        for key in sorted(set(pins) - live)
    ]


def report(failures: list[str], checked: int, ledger: Ledger, remedy: str) -> int:
    if not failures:
        print(
            f"OK: {checked} spec {ledger.noun}(s) resolve and match their "
            "recorded text."
        )
        return 0
    print(
        f"FAIL: {len(failures)} spec {ledger.noun}(s) do not hold "
        f"(of {checked} checked):",
        file=sys.stderr,
    )
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    print(f"\n{remedy}", file=sys.stderr)
    return 1
