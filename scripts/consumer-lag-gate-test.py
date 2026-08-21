#!/usr/bin/env python3
"""Tests for scripts/consumer-lag-gate.py.

This gate had a defect a passing run could not show, because it was not a
missing refusal. It refused correctly and it refused too early: it compared the
vendored copies against the CHECKED-OUT tree, so a branch that added vectors was
required to have already been vendored into rails that had no way to fetch it.
The branch could not be pushed until the rails carried it, the rails could only
carry a published corpus, and the corpus could not be published because the push
was refused. Every run of that gate was correct in isolation and the state it
produced was unreachable, which is why the cases below come in pairs: the same
staged repository, checked once while the change is a branch and once after it
has landed, asserting green and then red. Neither half is a result on its own.
One is the deadlock and the other is the gate not enforcing anything.

Every case runs against a STAGED COPY of this repository, never against the
repository itself. The claims this gate checks are declared against real prose
in real files and its subject is a real corpus, so a fixture tree would fail
every case for the wrong reason and prove nothing about whether the gate is
pointed at anything. The copy is a real git repository with a real commit,
because the reference the gate measures against is a ref, and a copy that was
not a git repository would present it with no reference at all -- which the last
case asserts is reported as a check that did not run, and never as copies that
are current.

Usage: python3 scripts/consumer-lag-gate-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "consumer-lag-gate.py"
PUBLISHED_BRANCH = "published"

# The digest definition is the corpus generator's, imported rather than
# restated, for the reason the gate under test imports it: a second definition
# of "the same corpus" would let this test agree with itself while disagreeing
# with the thing it is testing.
sys.path.insert(0, str(REPO_ROOT / "vectors"))
from gen_manifest import corpus_digest  # noqa: E402

Mutation = Callable[[Path], None]
# name, what the default branch publishes, what the checked-out tree is,
# the ref to measure against, whether the gate must accept, and words its
# output must carry.
Case = tuple[str, Mutation, Mutation, str, bool, tuple[str, ...]]


# ------------------------------------------------------------------- staging

def stage(destination: Path, publish: Mutation, tree: Mutation) -> None:
    """Build a repository whose default branch publishes one corpus and whose
    working tree may carry another.

    The published half is committed and the branch half is not, because that is
    the shape the gate has to tell apart: a change that exists here and nowhere a
    consumer rail could fetch it.
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
    publish(destination)
    for command in (
        ["git", "init", "-q", "-b", PUBLISHED_BRANCH],
        ["git", "add", "-A"],
        ["git", "-c", "user.email=gate@test", "-c", "user.name=gate",
         "commit", "-q", "-m", "published"],
    ):
        subprocess.run(command, cwd=destination, check=True, capture_output=True)
    tree(destination)


def run(root: Path, ref: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "consumer-lag-gate.py"),
         "--check", "--published-ref", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


# ------------------------------------------------------- corpus manipulation

def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def dump(path: Path, obj: dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def revision_of(root: Path) -> int:
    changes = (root / "vectors" / "CHANGES.md").read_text(encoding="utf-8")
    return max(int(n) for n in re.findall(r"^## suiteRevision (\d+)\b", changes,
                                          re.MULTILINE))


def vectors_in(root: Path) -> int:
    counts: dict[str, int] = load(root / "vectors" / "MANIFEST.json")["counts"]
    return sum(counts.values())


def bump_corpus(root: Path) -> None:
    """Add a vector and republish everything a corpus change republishes.

    Not a plausible vector and not meant to be: this gate reads the corpus as a
    set of bytes with a digest over it, so what makes this a corpus change is
    that the digest moves. The manifest, the counts and the changelog move with
    it exactly as a real regeneration moves them, because a change that moved
    the digest and nothing else would be caught by a different gate and would
    tell this one nothing.
    """
    vectors = root / "vectors"
    (vectors / "accept" / "zz-a-vector-this-test-adds.json").write_text(
        json.dumps({"_comment": "staged by scripts/consumer-lag-gate-test.py"}) + "\n",
        encoding="utf-8",
    )
    manifest = load(vectors / "MANIFEST.json")
    manifest["counts"]["accept"] += 1
    manifest["corpusDigest"] = corpus_digest(str(vectors))
    dump(vectors / "MANIFEST.json", manifest)
    changes = vectors / "CHANGES.md"
    changes.write_text(
        changes.read_text(encoding="utf-8")
        + f"\n## suiteRevision {revision_of(root) + 1} (staged by the lag-gate test)\n"
        + "\nOne vector added, so the corpus digest moves.\n",
        encoding="utf-8",
    )


def refresh_ledger(root: Path) -> None:
    """What --sync writes after every rail has actually been re-vendored."""
    ledger = root / "vectors" / "CONSUMERS.json"
    recorded = load(ledger)
    for entry in recorded["copies"]:
        entry["corpusDigest"] = corpus_digest(str(root / "vectors"))
    dump(ledger, recorded)


def rewrite_report(root: Path) -> None:
    """Rewrite the four published sentences about what the rails carry."""
    report = root / "docs" / "IMPLEMENTATION-REPORT.md"
    vectors, revision = str(vectors_in(root)), str(revision_of(root))
    text = report.read_text(encoding="utf-8")
    # Every literal space is `\s+` and every one of them sits INSIDE a captured
    # group, because this prose is hard-wrapped in the file and normalised only
    # in the gate. A pattern written with single spaces matches nothing across a
    # line break, and a replacement written with them would reflow the paragraph
    # it was asked to correct.
    for pattern, replacement in (
        (r"(\*\*The\s+consumer\s+rails\s+carry\s+the\s+suiteRevision-)\d+"
         r"(\s+corpus\.\*\*)", rf"\g<1>{revision}\g<2>"),
        (r"(each\s+vendor\s+all\s+)\d+(\s+vectors\s+of\s+suiteRevision\s+)\d+"
         r"(\s+byte-for-byte)", rf"\g<1>{vectors}\g<2>{revision}\g<3>"),
        (r"(and\s+replays\s+the\s+full\s+)\d+(\.)", rf"\g<1>{vectors}\g<2>"),
        (r"(its\s+vendored\s+set\s+\()\d+(\s+vectors\))", rf"\g<1>{vectors}\g<2>"),
    ):
        text = re.sub(pattern, replacement, text)
    report.write_text(text, encoding="utf-8")


def landed(root: Path) -> None:
    """The bump, as the default branch carries it once the merge is in."""
    bump_corpus(root)


def unchanged(_root: Path) -> None:
    """Nothing. Either the default branch is where it was, or the branch is."""


def refreshed_after_landing(root: Path) -> None:
    refresh_ledger(root)


def followed_after_landing(root: Path) -> None:
    refresh_ledger(root)
    rewrite_report(root)


def foreign_digest(root: Path) -> None:
    """Point one recorded copy at a corpus that is neither the old nor the new.

    The digest of a rail that was vendored from something nobody here published.
    It has to be red on a branch and red after the merge, because a reference
    that made this pass in either state would be a reference the ledger could be
    made to agree with by accident.
    """
    ledger = root / "vectors" / "CONSUMERS.json"
    recorded = load(ledger)
    recorded["copies"][0]["corpusDigest"] = "f" * len(
        recorded["copies"][0]["corpusDigest"]
    )
    dump(ledger, recorded)


def foreign_digest_after_landing(root: Path) -> None:
    refresh_ledger(root)
    rewrite_report(root)
    foreign_digest(root)


def regenerated_after_landing(root: Path) -> None:
    """Re-derive everything this repository can re-derive, and change no copy.

    The one thing that must not clear a real lag. Every count, digest and
    published sentence here is recomputed from the corpus, which is what a
    regeneration does, and the ledger still says what the rails said, because
    the ledger is read from them and nothing in this tree can write it.
    """
    rewrite_report(root)


def dropped_a_row(root: Path) -> None:
    """Delete a recorded copy while the report still advertises its rail."""
    ledger = root / "vectors" / "CONSUMERS.json"
    recorded = load(ledger)
    recorded["copies"] = recorded["copies"][:-1]
    dump(ledger, recorded)


def stale_published_manifest(root: Path) -> None:
    """The default branch's manifest stops describing the default branch's files.

    The state that would let a stale reference be handed to this gate, agreed
    with by every stale copy, and reported as three current rails.
    """
    manifest = root / "vectors" / "MANIFEST.json"
    recorded = load(manifest)
    recorded["corpusDigest"] = "0" * len(recorded["corpusDigest"])
    dump(manifest, recorded)


def repaired_manifest(root: Path) -> None:
    """Put the checked-out tree's manifest back, leaving only the commit wrong.

    Without this the tree would carry the same broken manifest and the gate would
    stop at its own publication check, which is a different refusal about a
    different file. The case is about the branch being measured AGAINST.
    """
    manifest = root / "vectors" / "MANIFEST.json"
    recorded = load(manifest)
    recorded["corpusDigest"] = corpus_digest(str(root / "vectors"))
    dump(manifest, recorded)


# --------------------------------------------------------------------- cases

CASES: tuple[Case, ...] = (
    (
        "the tree is the default branch and every copy carries it",
        unchanged, unchanged, PUBLISHED_BRANCH, True,
        ("carry the corpus the default branch publishes",),
    ),
    (
        "a branch adds vectors and the copies still carry what was published",
        unchanged, bump_corpus, PUBLISHED_BRANCH, True,
        ("carry the corpus the default branch publishes",),
    ),
    (
        "that same branch, once it has landed, with no rail refreshed",
        landed, unchanged, PUBLISHED_BRANCH, False,
        ("do not carry the corpus the default branch publishes",
         "typescript-consumer-rail", "python-consumer-rail",
         "mcp-server-consumer-rail"),
    ),
    (
        "landed, every rail refreshed, and the report still describing the old corpus",
        landed, refreshed_after_landing, PUBLISHED_BRANCH, False,
        ("the report", "vendoring sentence"),
    ),
    (
        "landed, every rail refreshed, and the report rewritten to match",
        landed, followed_after_landing, PUBLISHED_BRANCH, True,
        ("carry the corpus the default branch publishes",),
    ),
    (
        "landed, nothing refreshed, and everything re-derivable re-derived",
        landed, regenerated_after_landing, PUBLISHED_BRANCH, False,
        ("do not carry the corpus the default branch publishes",
         "typescript-consumer-rail"),
    ),
    (
        "a copy carrying a corpus nobody published, while the change is a branch",
        unchanged, foreign_digest, PUBLISHED_BRANCH, False,
        ("do not carry the corpus the default branch publishes",
         "typescript-consumer-rail"),
    ),
    (
        "a copy carrying a corpus nobody published, after the change has landed",
        landed, foreign_digest_after_landing, PUBLISHED_BRANCH, False,
        ("do not carry the corpus the default branch publishes",
         "typescript-consumer-rail"),
    ),
    (
        "a rail the report advertises with no copy recorded behind it",
        unchanged, dropped_a_row, PUBLISHED_BRANCH, False,
        ("one verified-against cell per rail",),
    ),
    (
        "the default branch publishing a digest its own vectors do not hash to",
        stale_published_manifest, repaired_manifest, PUBLISHED_BRANCH, False,
        ("does not publish the corpus it has",),
    ),
    (
        "no reference to measure against at all",
        unchanged, unchanged, "refs/heads/a-branch-this-repository-has-not-got",
        False,
        # Both halves, because two guards refuse this and only one of them says
        # anything a reader can act on. Dropping the ref check leaves the archive
        # read to fail on an empty revision, which is still a refusal and still
        # says the check did not run -- and says nothing about which ref was
        # missing or how to get it, which is the whole content of the refusal.
        ("DID NOT RUN", "does not resolve to a commit"),
    ),
)


def main() -> int:
    failures: list[str] = []
    for name, publish, tree, ref, must_pass, needles in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "aee-conformance"
            root.mkdir()
            stage(root, publish, tree)
            code, output = run(root, ref)
        passed = code == 0
        if passed != must_pass:
            failures.append(
                f"{name}: the gate {'accepted' if passed else 'refused'} "
                f"(exit {code}) where it had to "
                f"{'accept' if must_pass else 'refuse'}.\n{output}"
            )
            continue
        silent = [needle for needle in needles if needle not in output]
        for needle in silent:
            failures.append(
                f"{name}: the gate reached the right verdict without saying "
                f"{needle!r}, so its output does not name what it found.\n{output}"
            )
        if not silent:
            print(f"  ok  {name}")
    if failures:
        print(f"\nFAIL: {len(failures)} case(s) did not hold:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}\n", file=sys.stderr)
        return 1
    print(f"\nOK: {len(CASES)} case(s) held.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
