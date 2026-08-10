#!/usr/bin/env python3
"""Tests for scripts/spec-anchor-gate.py and the pin machinery under it.

Most of what follows asserts a REFUSAL, for the reason every other gate test
here gives: this repository has a documented history of checks that ran green
while enforcing nothing, and the anchor gate has now been one of them twice.

The first time, resolution was the only question asked, so anchors sat hundreds
of lines from the rules they named while a range check passed on every build.
The second time is the reason this file exists. A synchronise would refuse a
citation that moved off text still in the document, which is the right rule, but
it asked the question in a place that could not reach the plainest way of
breaking it. If the pinned prose was still there word for word, a citation that
merely TOUCHED it was waved through, so an anchor could be cut from two hundred
and sixty-eight lines to six -- over prose nobody had edited -- and the
synchronise wrote the new range and printed nothing. Both halves of that were
proved by hand before the fix and neither had a test behind it, which is why
this file leads with them.

The last two refusals are a different failure and the worse one. When the
collector stopped matching the files it reads, the old check reported "0
checked" and told the reader to run --sync; --sync then exited zero and wrote an
EMPTY ledger; and the check after that printed "OK: 0 spec anchor(s) resolve"
and went on printing it. A gate cannot report on a set it never gathered, so an
empty subject set is refused at both doors rather than described.

The accepting cases matter as much. A gate that refuses every move is a gate
that gets bypassed, and two of the four are moves this repository makes
routinely: an ordinary re-vendor moves every anchor in the tree, and a
deliberate narrowing onto the paragraph that actually states a rule is a
correction, not a defect. The narrowing is accepted only when it is said out
loud, one key at a time, which is the whole difference between the case that
must pass and the case that must fail.

Every case runs against a STAGED COPY of this repository, never against
fixtures and never against the repository itself. The pins are digests of real
prose in the real vendored specification, so a fixture tree would fail every
case for the wrong reason and prove nothing about whether the gate is pointed at
anything. The copy is a real git checkout with a real commit in it, because the
before-image the synchronise judges a move against is read from git.

Usage: python3 scripts/spec-anchor-gate-test.py [all|pin|aim]
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

Mutation = Callable[[Path], None]
# name, mutation, extra arguments to the gate, phrases the output must carry
Case = tuple[str, Mutation, tuple[str, ...], tuple[str, ...]]

# The anchor these cases move. It spans a hundred and twenty-five lines, which
# leaves room to narrow it a long way, and it is written in exactly one authored
# file, so a mutation that matched anything else would be measuring two things.
WIDE = "L431-555"
KEY = "vectors/coverage-unforced.json::U5#1"
CARRIES_WIDE = "vectors/coverage-unforced.json"

# Files that carry hand-written anchors, plus the tables generated from them. A
# re-vendor moves the anchors in all of them at once, so the case that simulates
# one has to move them all or it is simulating a broken re-vendor instead.
ANCHORED = (
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/interpretation-decisions.json",
    "vectors/coverage-unforced.json",
    "vectors/CHANGES.md",
    "docs/interpretation-decisions-open.md",
    "vectors/reject/INDEX.md",
    "docs/COVERAGE-MATRIX.md",
)

SPEC = "spec/predicates/adversarial-execution-evidence.md"

# A line inside the cited span, sitting in the part a narrowing to L431-436
# drops. Rewriting it is what makes the search for the whole span fail, which is
# the state where a truncation used to read as an ordinary amendment.
INSIDE = "and a `degraded` whose clean rows are all `artifact` carry the same token."


def stage(destination: Path) -> None:
    """Copy the tracked tree into a fresh git checkout, and commit it.

    The commit is not ceremony. A synchronise that finds a citation addressing
    different text reconstructs the prose it used to address from the revision
    the ledger names, and it reads that revision out of git. Without a commit
    there is no before-image, the synchronise refuses for that reason instead of
    the one under test, and every case here would pass while asserting nothing.
    """
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    for rel in listed.stdout.split():
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "-A"],
        [
            "git",
            "-c",
            "user.email=gate@example.invalid",
            "-c",
            "user.name=gate",
            "commit",
            "-q",
            "-m",
            "staged",
        ],
    ):
        subprocess.run(command, cwd=destination, check=True, capture_output=True)


def run(root: Path, arguments: tuple[str, ...]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "spec-anchor-gate.py"), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def edit(root: Path, rel: str, old: str, new: str, expect: int = 1) -> None:
    """Replace exactly ``expect`` occurrences, or refuse to run the case.

    A mutation that silently matched nothing leaves the copy correct, the gate
    green, and the case recorded as a passing refusal test. That is the shape
    this whole file exists to keep out of the repository.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    if text.count(old) != expect:
        raise SystemExit(
            f"test setup: {rel} carries {text.count(old)} copies of {old[:48]!r}, "
            f"expected {expect}, so this case would assert nothing. Fix the "
            "case, never the gate."
        )
    replaced = text.replace(old, new)
    # And the bytes have to have moved. A count check catches a pattern that
    # matched nothing; it does not catch a substitution of a value for itself,
    # which reads as a mutation in the case list, leaves the file identical, and
    # records the gate as refusing something it was never shown. Neither does a
    # line count, which cannot see one value swapped for another of the same
    # length. Only the digest can.
    if hashlib.sha256(replaced.encode("utf-8")).hexdigest() == hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest():
        raise SystemExit(
            f"test setup: replacing {old[:48]!r} with {new[:48]!r} in {rel} "
            "leaves the file byte-identical, so this case mutates nothing and "
            "asserts nothing. Fix the case, never the gate."
        )
    path.write_text(replaced, encoding="utf-8")


def revendor(root: Path, at: int, added: int) -> None:
    """Insert prose upstream and remap every anchor below it, faithfully.

    This is the ordinary event: the document gains a paragraph and
    scripts/vendor-spec.py shifts every pointer under it by the same amount. On
    its own it must be silent, and half of these cases exist to show that a
    narrowing hidden inside one is not.
    """
    spec = root / SPEC
    lines = spec.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[at - 1 : at - 1] = ["\n"] + [f"Inserted upstream line {i}.\n" for i in range(added - 1)]
    spec.write_text("".join(lines), encoding="utf-8")

    def shift(match: re.Match[str]) -> str:
        lo = int(match.group(1))
        lo += added if lo >= at else 0
        if match.group(2) is None:
            return f"L{lo}"
        hi = int(match.group(2))
        return f"L{lo}-{hi + (added if hi >= at else 0)}"

    for rel in ANCHORED:
        path = root / rel
        path.write_text(
            re.sub(r"\bL(\d+)(?:-(\d+))?\b", shift, path.read_text(encoding="utf-8")),
            encoding="utf-8",
        )


def blind(root: Path) -> None:
    """Leave the collector's pattern matching nothing any file contains.

    Which is what a collector looks like from the outside after the files it
    reads are renamed, or after a table it scans changes the spelling of its
    anchor column. It is indistinguishable, from the gate's own output, from a
    repository that cites the specification nowhere.
    """
    edit(
        root,
        "scripts/spec-anchor-gate.py",
        r'ANCHOR_RE = re.compile(r"\bL(\d+)(?:-(\d+))?\b")',
        r'ANCHOR_RE = re.compile(r"\bLINE(\d+)(?:-(\d+))?\b")',
    )


def narrowed_by_a_revendor(root: Path) -> None:
    """A narrowing hidden inside an ordinary re-vendor, which is where one would
    actually arrive: the remapper moves every anchor, and one of them comes out
    shorter than it went in."""
    revendor(root, 400, 3)
    edit(root, CARRIES_WIDE, "L434-558", "L434-439")


def narrowed_where_the_passage_changed(root: Path) -> None:
    """A narrowing whose span upstream also edited, so the search for the whole
    passage fails. This is the case the line-by-line question was written for,
    and it is here to stay caught now that the question runs everywhere."""
    edit(root, SPEC, INSIDE, "This sentence replaces the one that was here.")
    edit(root, CARRIES_WIDE, WIDE, "L431-436")


def unchanged(root: Path) -> None:
    """No mutation: the case is about the arguments, or about the tree as it is."""


# --------------------------------------------------------------------------
# The refusals
# --------------------------------------------------------------------------

REFUSALS: list[Case] = [
    (
        "an anchor is narrowed onto part of prose nobody edited",
        lambda root: edit(root, CARRIES_WIDE, WIDE, "L431-436"),
        ("--sync",),
        (
            KEY,
            "no longer covers text that upstream left in place",
            "dropped:",
        ),
    ),
    (
        "the same narrowing arrives inside an otherwise faithful re-vendor",
        narrowed_by_a_revendor,
        ("--sync",),
        (KEY, "no longer covers text that upstream left in place"),
    ),
    (
        "an anchor leaves its subject for unrelated prose",
        lambda root: edit(root, CARRIES_WIDE, WIDE, "L200-205"),
        ("--sync",),
        (KEY, "addresses different prose, but the text it was pinned to is still"),
    ),
    (
        "an anchor is cut short where upstream also rewrote the passage",
        narrowed_where_the_passage_changed,
        ("--sync",),
        (KEY, "no longer covers text that upstream left in place"),
    ),
    (
        "an acceptance names an anchor this run did not refuse",
        unchanged,
        ("--sync", "--accept-reaim", KEY),
        (KEY, "did not refuse"),
    ),
    (
        "the collector matches nothing, so a synchronise would pin an empty set",
        blind,
        ("--sync",),
        ("no anchors were collected, so there is nothing to pin",),
    ),
    (
        "the collector matches nothing, so a check would examine an empty set",
        blind,
        (),
        ("checked nothing and its result means nothing",),
    ),
    (
        "an anchor names a line past the end of the document",
        lambda root: edit(root, CARRIES_WIDE, WIDE, "L431-99999"),
        ("--sync",),
        ("names line(s) outside the spec",),
    ),
]

# --------------------------------------------------------------------------
# The moves that must stay possible
# --------------------------------------------------------------------------

ACCEPTS: list[Case] = [
    (
        "the repository as it stands",
        unchanged,
        (),
        ("resolve and match their recorded text",),
    ),
    (
        "an anchor widened over the same subject",
        lambda root: edit(root, CARRIES_WIDE, WIDE, "L425-560"),
        ("--sync",),
        ("still covering every line that survived",),
    ),
    (
        "a narrowing onto the paragraph that states the rule, cleared by name",
        lambda root: edit(root, CARRIES_WIDE, WIDE, "L431-436"),
        ("--sync", "--accept-reaim", KEY),
        ("1 cleared by name", KEY),
    ),
    (
        "an ordinary re-vendor that moves every anchor and drops nothing",
        lambda root: revendor(root, 400, 3),
        ("--sync",),
        ("citation(s) pinned",),
    ),
]


# --------------------------------------------------------------------------
# Aim: is the anchor drawn around the rule the decision is about?
# --------------------------------------------------------------------------
#
# The pin cases above all ask whether an anchor still addresses the text it was
# recorded against. An anchor recorded a sentence early addresses that text
# perfectly, so none of them can see the defect these cases are about, and the
# pins preserved a live one -- registry decision 8, twelve forcing vectors,
# pointed at a field label with its rule eight lines below -- for as long as the
# ledger existed.
#
# The mutations come in two kinds and both are needed. Three move an anchor and
# assert the gate refuses it, which is the ordinary direction. Three break the
# gate's own instruments -- the sentence splitter, the controlled vocabulary,
# the collector -- and assert it says so, because each of those failures looks
# from outside exactly like a corpus with nothing wrong with it, and this
# repository has shipped that green line before.

REGISTRY = "vectors/interpretation-decisions.json"
GATE = "scripts/spec-anchor-gate.py"

# Decision 8's anchor, as this change corrected it: the whole issuedAt field
# definition, whose MUST sentences carry the timestamp profile the decision
# interprets. Every aim mutation moves this one anchor, so a mutation that
# matched something else would be measuring two things at once.
AIMED = '"L1672-1690"'
# Where it used to point: the tail of the doesNotAssert paragraph and the field
# label. Three lines, no rule of any kind, and the rule it names starting at
# L1680.
OFF_BY_A_SENTENCE = '"L1670-1672"'
# A real rule, stated with two MUSTs, about strict I-JSON string literals --
# which is nothing decision 8 is about.
WRONG_RULE = '"L110-137"'
# The same anchor stretched past the "## Example" heading, so that it contains
# rules by width rather than by aim.
WIDENED_PAST_A_HEADING = '"L1672-1700"'
# The same anchor stretched the other way, back over the label that opens it and
# into the doesNotAssert definition above. It still covers the issuedAt rules, so
# every question about the rule it names is answered; what it has stopped doing
# is citing one member.
WIDENED_INTO_THE_MEMBER_ABOVE = '"L1666-1690"'

# Decision 6's anchor, the coverage field definition, and the same anchor widened
# upward until it collects a rule about `manifest` ninety lines above it. That
# widening crosses no heading -- this document defines coverage and attackResults
# a hundred lines apart under one heading -- and it is how three of the four
# defects this gate was built for pass a check that asks only about headings.
COVERAGE_FIELD = '"L879-890"'
WIDENED_INTO_THE_MEMBER_BELOW = '"L795-886"'
# Decision 14's anchor, narrowed so that it opens exactly ON the coverage label.
# The refusal above must not reach this: opening on a field definition is how
# every corrected anchor in the registry is drawn, and a rule that refused it
# would refuse the corrections it exists to protect.
OPENS_ON_THE_LABEL = ('"L881-890"', '"L879-890"')


AIM_REFUSALS: list[Case] = [
    (
        "an anchor sits a sentence above its rule, on the field label",
        lambda root: edit(root, REGISTRY, AIMED, OFF_BY_A_SENTENCE),
        ("--aim-only",),
        (
            "decision 8",
            "covers no sentence that states a rule",
            "states a rule this decision names begins at L1680",
        ),
    ),
    (
        "an anchor covers a rule, but one the decision is not about",
        lambda root: edit(root, REGISTRY, AIMED, WRONG_RULE),
        ("--aim-only",),
        ("decision 8", "not one this decision is about"),
    ),
    (
        "an anchor is widened across a heading until it contains some rule",
        lambda root: edit(root, REGISTRY, AIMED, WIDENED_PAST_A_HEADING),
        ("--aim-only",),
        ("decision 8", "crosses the heading", "## Example"),
    ),
    (
        "the sentence splitter stops finding any rule in the document",
        lambda root: edit(
            root,
            GATE,
            "for candidate in (sentence.text, sentence.stem):",
            "for candidate in ():",
        ),
        ("--aim-only",),
        ("no sentence in the specification states a rule",),
    ),
    (
        "the controlled vocabulary stops matching, so nothing can be aimed",
        lambda root: edit(
            root,
            GATE,
            "return frozenset(words | {f\"rfc{number}\"",
            "return frozenset() or frozenset({f\"rfc{number}\"",
        ),
        ("--aim-only",),
        ("cannot be tested for aim", "not a passing one"),
    ),
    (
        "an anchor is widened into the next member until it contains some rule",
        lambda root: edit(root, REGISTRY, COVERAGE_FIELD, WIDENED_INTO_THE_MEMBER_BELOW),
        ("--aim-only",),
        (
            "decision 6",
            "runs past the field definition that opens at L879",
            "`coverage` _object, required_",
        ),
    ),
    (
        "an anchor is widened back over its own label into the member above",
        lambda root: edit(root, REGISTRY, AIMED, WIDENED_INTO_THE_MEMBER_ABOVE),
        ("--aim-only",),
        (
            "decision 8",
            "runs past the field definition that opens at L1672",
            "`issuedAt` _Timestamp, required_",
        ),
    ),
    (
        "an anchor is written in a spelling the gate cannot read",
        lambda root: edit(root, REGISTRY, AIMED, '"L1672\\u20131690"'),
        ("--aim-only",),
        ("decision 8", "not a line anchor this gate can read", "not a passing one"),
    ),
    (
        "a forced decision records no anchor at all",
        lambda root: edit(
            root,
            REGISTRY,
            '"specAnchors": [\n        "L1638-1640"\n      ],',
            '"specAnchors": [],',
        ),
        ("--aim-only",),
        ("decision 3", "records no anchor", "cites nothing"),
    ),
    (
        "the field-label pattern stops finding the definitions that bound a span",
        lambda root: edit(
            root,
            GATE,
            r'FIELD_LABEL_RE = re.compile(r"^`[A-Za-z][A-Za-z0-9_.\[\]]*`\s+_[^_]+_\s*$")',
            r'FIELD_LABEL_RE = re.compile(r"^MEMBER `[A-Za-z][A-Za-z0-9_.\[\]]*`_$")',
        ),
        ("--aim-only",),
        ("no field definition was found", "lost the pattern"),
    ),
    (
        "the collector stops recognising a forced decision",
        lambda root: edit(
            root,
            GATE,
            'if entry.get("classification") != "forced":',
            'if entry.get("classification") != "forced-by-vector":',
        ),
        ("--aim-only",),
        ("no anchors were collected", "means nothing"),
    ),
]

AIM_ACCEPTS: list[Case] = [
    (
        "the repository as it stands, asked only about aim",
        unchanged,
        ("--aim-only",),
        ("drawn around a rule the decision names",),
    ),
    (
        "an anchor on a rule this document states without an RFC 2119 keyword",
        lambda root: edit(root, REGISTRY, '"L881-890"', '"L886-890"'),
        ("--aim-only",),
        ("drawn around a rule the decision names",),
    ),
    (
        "an anchor on a bare list item whose rule is stated in the list stem",
        lambda root: edit(root, REGISTRY, '"L542-567"', '"L561-564"'),
        ("--aim-only",),
        ("drawn around a rule the decision names",),
    ),
    (
        "an anchor drawn from a field's own label to the end of its rules",
        lambda root: edit(root, REGISTRY, *OPENS_ON_THE_LABEL),
        ("--aim-only",),
        ("drawn around a rule the decision names",),
    ),
]


def check(group: str, cases: list[Case], want_refusal: bool, tmp: Path) -> list[str]:
    failures: list[str] = []
    for index, (name, mutate, arguments, phrases) in enumerate(cases):
        root = tmp / f"{group}{index}"
        root.mkdir()
        stage(root)
        mutate(root)
        code, output = run(root, arguments)
        if want_refusal and code == 0:
            failures.append(f"{name}: the gate accepted it:\n{output}")
            continue
        if not want_refusal and code != 0:
            failures.append(f"{name}: the gate refused it:\n{output}")
            continue
        missing = [phrase for phrase in phrases if phrase not in output]
        if missing:
            failures.append(
                f"{name}: the right exit status, and the output does not carry "
                f"{missing!r}. A refusal that names the wrong thing sends the "
                f"next person to the wrong file.\n{output}"
            )
    return failures


def main(argv: list[str]) -> int:
    """Run every case, or one named group of them.

    The group argument exists because the pin cases and the aim cases fail for
    different reasons and one of those reasons is the state of the tree rather
    than the state of the gate: a citation written but not yet synced makes the
    whole-repository control case fail, correctly, and would otherwise hide
    whether the aim cases hold. Selecting a group is a way to read one answer,
    never a substitute for the default run, which is what CI runs.
    """
    group = argv[1] if len(argv) > 1 else "all"
    if group not in ("all", "pin", "aim"):
        print(f"unknown group {group!r}; expected all, pin or aim", file=sys.stderr)
        return 2
    pin = group in ("all", "pin")
    aim = group in ("all", "aim")
    REFUSALS_RUN = REFUSALS if pin else []
    ACCEPTS_RUN = ACCEPTS if pin else []
    AIM_REFUSALS_RUN = AIM_REFUSALS if aim else []
    AIM_ACCEPTS_RUN = AIM_ACCEPTS if aim else []
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("refuse", REFUSALS_RUN, True, tmp))
        failures.extend(check("accept", ACCEPTS_RUN, False, tmp))
        failures.extend(check("aimrefuse", AIM_REFUSALS_RUN, True, tmp))
        failures.extend(check("aimaccept", AIM_ACCEPTS_RUN, False, tmp))
    refusals = len(REFUSALS_RUN) + len(AIM_REFUSALS_RUN)
    accepts = len(ACCEPTS_RUN) + len(AIM_ACCEPTS_RUN)
    total = refusals + accepts
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {refusals} assert a refusal the gate "
        f"makes and {accepts} a move it must not block."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
