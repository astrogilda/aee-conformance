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

Usage: python3 scripts/spec-anchor-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

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
    path.write_text(text.replace(old, new), encoding="utf-8")


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


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("refuse", REFUSALS, True, tmp))
        failures.extend(check("accept", ACCEPTS, False, tmp))
    total = len(REFUSALS) + len(ACCEPTS)
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS)} assert a refusal the gate "
        f"makes and {len(ACCEPTS)} a move it must not block."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
