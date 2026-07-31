#!/usr/bin/env python3
"""Tests for scripts/count-gate.py.

Almost every case below asserts a REFUSAL, and that is the point. This
repository has a documented history of checks that ran green while enforcing
nothing -- a shipped verifier that scored zero against the whole corpus while its
own unit test passed, a drop count that was a hardcoded literal, a conformance
oracle that recorded a crashed evaluation as a denial, and a ground-truth
comparison that agreed with itself because both sides shared a blind spot. A
count gate that could not go red would be the next one, and it would be worse
than the others, because the thing it exists to catch is precisely a number that
looks right.

Every case runs against a STAGED COPY of this repository rather than fixtures,
and never against the repository itself. Fixtures would prove the decision
functions and nothing about whether the gate is pointed at anything: the claims
are declared against real prose in real files, so a fixture tree would fail every
one of them for the wrong reason and a green fixture run would say nothing. The
copy is a real git checkout of the tracked files, one file in it is broken in
exactly one way, and the gate is asked.

The two accepting cases are there to show the refusals are not a gate that
refuses everything, and one of them is the case that matters most: a NEW count,
written today, with its revision attributed in the prose, is accepted. If that
failed, the only way to satisfy this gate would be to never write a number, and
a gate nobody can satisfy gets deleted.

Usage: python3 scripts/count-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "count-gate.py"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    """Copy the tracked tree into a fresh git checkout.

    The gate enumerates what it reads with `git ls-files`, which is deliberate --
    a census that walked the filesystem would scan build output and a stale
    working copy and report a coverage it never had. So the copy has to be a git
    repository too, and staging it is what makes the copy's file list the same
    list the real gate would see.
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
    ):
        subprocess.run(command, cwd=destination, check=True, capture_output=True)


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def edit(root: Path, rel: str, old: str, new: str) -> None:
    """Replace exactly one occurrence, or refuse to run a case that asserts nothing.

    A mutation that silently matched nothing would leave the copy correct, the
    gate green, and the case recorded as a passing refusal test. That is the
    shape this whole file exists to keep out of the repository.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(
            f"test setup: {rel} carries {text.count(old)} copies of {old[:48]!r}, so "
            "this case would assert nothing. Fix the case, never the gate."
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def append(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def create(root: Path, rel: str, text: str) -> None:
    (root / rel).write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------
# Half one: a published count drifts, is reworded, or is duplicated
# --------------------------------------------------------------------------

CLAIM_CASES: list[Case] = [
    (
        "a published count drifts from the corpus",
        lambda root: edit(
            root,
            "README.md",
            "conformance%20vectors-226-e8951c",
            "conformance%20vectors-179-e8951c",
        ),
        ("says '179' where the sources say '226'",),
    ),
    (
        "a forcing count drifts from the baseline",
        lambda root: edit(
            root, "README.md", "ratchet: **417 rules forced", "ratchet: **416 rules forced"
        ),
        ("the four forcing outcomes says",),
    ),
    (
        "a claim is reworded, so the check would silently stop running",
        lambda root: edit(
            root, "README.md", "sweeps all 745 sites nightly", "covers 745 sites nightly"
        ),
        ("the nightly sweep's size was found 0 time(s), expected 1",),
    ),
    (
        "a claim is duplicated into a second paragraph that will rot on its own",
        lambda root: append(
            root,
            "docs/IMPLEMENTATION-REPORT.md",
            "\nNor does agreement on 186 vectors say anything about tomorrow.\n",
        ),
        (
            "the scoping paragraph on what agreement does not say was found 2 "
            "time(s), expected 1",
        ),
    ),
    (
        "a delegated span is reworded, leaving it owned by nobody",
        lambda root: edit(
            root,
            "docs/IMPLEMENTATION-REPORT.md",
            "and replays the full 226.",
            "and replays every one of the 226 vectors of suiteRevision 15.",
        ),
        ("is delegated to scripts/consumer-lag-gate.py and no longer appears",),
    ),
    (
        "a frozen incident figure is quietly made to track the corpus",
        lambda root: edit(
            root, "README.md", "it scored\n0 of 186.", "it scored\n0 of 190."
        ),
        (
            "the frozen figure \"the external-rail contract, the shipped CLI's "
            "score\" was found 0 time(s)",
        ),
    ),
]

# --------------------------------------------------------------------------
# Half two: a NEW hand-written count appears where nothing declared one
# --------------------------------------------------------------------------

CENSUS_CASES: list[Case] = [
    (
        "a new paragraph states today's corpus size",
        lambda root: append(
            root, "BUILD-NOTES.md", "\nThe corpus holds 226 files as this is written.\n"
        ),
        ("'226' is an integer equal to the corpus total",),
    ),
    (
        "a new paragraph states today's accept count",
        lambda root: append(
            root, "BUILD-NOTES.md", "\nOf those, 52 are statements a verifier accepts.\n"
        ),
        ("'52' is an integer equal to the accept count",),
    ),
    (
        "a new paragraph counts vectors at a size the corpus has never had",
        lambda root: append(
            root, "BUILD-NOTES.md", "\nThe suite ships 192 vectors in total.\n"
        ),
        ("'192' is an integer counting vectors",),
    ),
    (
        "a new paragraph states a score",
        lambda root: append(
            root, "BUILD-NOTES.md", "\nAn outside rail scored 200/200 against it.\n"
        ),
        ("'200/200' is a ratio",),
    ),
    (
        "a small forcing count is written next to the word it counts",
        lambda root: append(
            root, "BUILD-NOTES.md", "\nThe ratchet records 26 rules as tolerated.\n"
        ),
        ("'26' is an integer equal to the count of seen-but-tolerated rules",),
    ),
    (
        "a count is attributed to a revision whose ledger row does not carry it",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            "\nThe corpus of suiteRevision 3 held 226 vectors.\n",
        ),
        ("'226' is an integer counting vectors",),
    ),
    (
        "a count appears in a Go comment",
        lambda root: append(
            root, "cmd/mutgen/main.go", "\n// The corpus this walks holds 226 vectors.\n"
        ),
        ("cmd/mutgen/main.go:", "'226' is an integer counting vectors"),
    ),
    (
        "a count appears in a Python docstring",
        lambda root: append(
            root,
            "scripts/coverage-gate.py",
            '\ndef _note() -> None:\n    """It is replayed over 226 vectors."""\n',
        ),
        ("scripts/coverage-gate.py:", "'226' is an integer counting vectors"),
    ),
    (
        "a count appears in a CI step name",
        lambda root: append(
            root,
            ".github/workflows/ci.yml",
            "\n# A later note: the nightly sweep covers 745 sites.\n",
        ),
        ("'745' is an integer equal to the count of mutation sites",),
    ),
    (
        "a changelog entry cites a size the corpus did not have by then",
        lambda root: edit(
            root,
            "vectors/CHANGES.md",
            "## suiteRevision 1 (first public release)",
            "## suiteRevision 1 (first public release)\n\n- A note added later: 226 vectors.",
        ),
        ("'226' is an integer counting vectors",),
    ),
]

# --------------------------------------------------------------------------
# The sources themselves
# --------------------------------------------------------------------------

SOURCE_CASES: list[Case] = [
    (
        "the manifest's declared count disagrees with the entries it carries",
        lambda root: edit(
            root, "vectors/MANIFEST.json", '"accept": 52', '"accept": 51'
        ),
        ("it declares 51 accept vector(s), carries 52",),
    ),
    (
        "a vector file is added without the manifest hearing about it",
        lambda root: create(root, "vectors/accept/ok-999-invented.json", "{}\n"),
        ("vectors/accept/ holds 53 file(s)",),
    ),
    (
        "the changelog's newest row drifts from the manifest",
        lambda root: edit(
            root,
            "vectors/CHANGES.md",
            # Anchored on the newest entry's own wording. Two revisions can carry
            # the same three counts -- 16 and 15 do -- so the row text alone stops
            # identifying which row is being edited, and edit() refuses an
            # ambiguous match rather than mutating whichever one it finds first.
            "- Corpus: **226 vectors (52 accept, 172 reject, 2 indeterminate)**, up from 221.",
            "- Corpus: **185 vectors (50 accept, 133 reject, 2 indeterminate)**, up from 221.",
        ),
        ("declares 185 vectors (50 accept, 133 reject, 2 indeterminate)",),
    ),
    (
        "a vector index heading drifts from the corpus",
        lambda root: edit(
            root, "vectors/reject/INDEX.md", "## Vectors (172)", "## Vectors (138)"
        ),
        (
            "the vector-table heading says 138 and vectors/MANIFEST.json carries "
            "172 reject vector(s)",
        ),
    ),
    (
        # The third family gets the same closure, in both directions, because a
        # bucket whose table nothing reconciles against the manifest is exactly
        # how five vectors once sat in a directory with no row behind them.
        "the indeterminate index heading drifts from the corpus",
        lambda root: edit(
            root, "vectors/indeterminate/INDEX.md", "## Vectors (2)", "## Vectors (3)"
        ),
        (
            "the vector-table heading says 3 and vectors/MANIFEST.json carries "
            "2 indeterminate vector(s)",
        ),
    ),
    (
        "an indeterminate vector file is added without the manifest hearing about it",
        lambda root: create(
            root, "vectors/indeterminate/ind-999-invented.json", "{}\n"
        ),
        ("vectors/indeterminate/ holds 3 file(s)",),
    ),
    # The case the old heading check could not make. Its two sides lived in one
    # file, so a table short of the corpus and a heading agreeing with that short
    # table passed, which is what five vectors did until the manifest generator
    # refused to run. Deleting a row now leaves the heading untouched and fails
    # anyway, because the row is compared with the corpus and not with the
    # heading above it.
    (
        "an index table loses a row while its heading still agrees with it",
        lambda root: edit(
            root,
            "vectors/reject/INDEX.md",
            "| `bad-906-corpus-manifest-absent` |",
            "| skipped-bad-906-corpus-manifest-absent |",
        ),
        (
            "the corpus carries ['bad-906-corpus-manifest-absent'] and this table "
            "has no row for them",
        ),
    ),
    (
        "an index table carries a row for a vector the corpus does not have",
        lambda root: edit(
            root,
            "vectors/accept/INDEX.md",
            "| ok-901-row-missing-basis |",
            "| ok-901-row-missing-basis |\n| ok-902-invented | fail | aee-c-1 | none |",
        ),
        ("['ok-902-invented'] have a row here and no entry",),
    ),
    (
        "one vector is given two index rows, which are then free to disagree",
        lambda root: edit(
            root,
            "vectors/accept/INDEX.md",
            "| ok-901-row-missing-basis |",
            "| ok-901-row-missing-basis | fail | aee-c-1 | a second row |\n"
            "| ok-901-row-missing-basis |",
        ),
        ("['ok-901-row-missing-basis'] each carry more than one row",),
    ),
]

# --------------------------------------------------------------------------
# The accepting cases
# --------------------------------------------------------------------------

ACCEPT_CASES: list[Case] = [
    (
        "the repository as it stands",
        lambda root: None,
        ("are accounted for",),
    ),
    (
        "a new count whose revision is attributed in the prose",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            "\nThe checker cleared all 140 vectors of suiteRevision 3.\n",
        ),
        ("are accounted for",),
    ),
    (
        "ordinary numbers that stand for nothing about the corpus",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            "\nThe timeout is 900 seconds and the read buffer is 4096 bytes.\n",
        ),
        ("are accounted for",),
    ),
]


def check(group: str, cases: list[Case], want_refusal: bool, tmp: Path) -> list[str]:
    failures: list[str] = []
    for index, (name, mutate, phrases) in enumerate(cases):
        root = tmp / f"{group}{index}"
        root.mkdir()
        stage(root)
        mutate(root)
        code, output = run(root)
        if want_refusal and code == 0:
            failures.append(f"{name}: the gate accepted it")
            continue
        if not want_refusal and code != 0:
            failures.append(f"{name}: the gate refused it:\n{output}")
            continue
        missing = [phrase for phrase in phrases if phrase not in output]
        if missing:
            failures.append(
                f"{name}: the right exit status, and the output does not carry "
                f"{missing!r}. A refusal that names the wrong thing sends the next "
                f"person to the wrong file.\n{output}"
            )
    return failures


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("claim", CLAIM_CASES, True, tmp))
        failures.extend(check("census", CENSUS_CASES, True, tmp))
        failures.extend(check("source", SOURCE_CASES, True, tmp))
        failures.extend(check("accept", ACCEPT_CASES, False, tmp))
    total = len(CLAIM_CASES) + len(CENSUS_CASES) + len(SOURCE_CASES) + len(ACCEPT_CASES)
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    refusals = total - len(ACCEPT_CASES)
    print(
        f"OK: {total} case(s), of which {refusals} assert a refusal the gate makes "
        "and name the sentence it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
