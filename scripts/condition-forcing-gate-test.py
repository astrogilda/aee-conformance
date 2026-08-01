#!/usr/bin/env python3
"""Tests for scripts/condition-forcing-gate.py, and they are mostly refusals.

A gate evidenced only by a green run is the shape every pass-while-enforcing-
nothing check in this repository had before somebody looked. This one publishes
a figure a standards reader is invited to rely on, so the path from a moved
corpus, a broken input or an unresolvable attribution to a non-zero exit is
exercised here rather than argued in the docstring.

Every case runs against a STAGED COPY of the tree, rigged one file at a time.
Nothing here writes to the repository under test.

Nine cases drive `--verify-prior`, which reads two objects out of git history,
and a shallow clone cannot run them. It does not merely fail them: it answers
exit 2 to all nine, and two of the nine WANT exit 2, so they would pass in a
clone that can read nothing. `--without-history` runs the rest and reports how
many it left, and a default run that cannot reach the pinned objects refuses
rather than calling a smaller suite green.

Usage:
    python3 scripts/condition-forcing-gate-test.py                    # all of it
    python3 scripts/condition-forcing-gate-test.py --without-history  # shallow clones
Exit 0 when every case behaves; 1 naming each that did not; 2 when the run
could not cover what it was asked to cover.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "condition-forcing-gate.py"
MANIFEST = "vectors/MANIFEST.json"
BASELINE = "docs/FORCING-BASELINE.json"
REGISTRY = "vectors/reject/INDEX.md"
CODES_GO = "aee/codes.go"
OUTPUT = "docs/FORCING-HONESTY.md"
PRIOR = "docs/PRIOR-FORCING.json"

# The tree the gate reads. Copied rather than linked: a case that rigs an input
# must not be able to reach the repository it is testing.
#
# The pinned earlier figure is the one input whose OWN source is outside the
# staged tree: `--verify-prior` re-derives it from git objects, which are read
# from the repository under test and cannot be rigged here. That asymmetry is
# what the prior cases below exercise -- a rigged record against real history.
STAGED = (
    MANIFEST,
    BASELINE,
    REGISTRY,
    CODES_GO,
    OUTPUT,
    PRIOR,
    "vectors/CHANGES.md",
    "vectors/coverage-unforced.json",
)


def stage(root: Path) -> None:
    for rel in STAGED:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, target)


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- running this repository's own gate is the point
        [sys.executable, str(GATE), "--root", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def rig_json(root: Path, rel: str, mutate: Callable[[dict[str, object]], None]) -> None:
    path = root / rel
    loaded = json.loads(path.read_text(encoding="utf-8"))
    mutate(loaded)
    path.write_text(json.dumps(loaded, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# the cases
# ---------------------------------------------------------------------------


def case_current_tree_passes(root: Path) -> str | None:
    """The live inputs generate the live document. This is the only green case."""
    result = run(root, "--check")
    if result.returncode:
        return f"the unrigged tree failed --check: {result.stdout}{result.stderr}"
    return None


def case_stale_document_fails(root: Path) -> str | None:
    """A published figure that no longer follows from its data is the whole point."""
    path = root / OUTPUT
    path.write_text(path.read_text(encoding="utf-8").replace("weak", "strong"), encoding="utf-8")
    result = run(root, "--check")
    if result.returncode != 1:
        return f"an edited document did not fail --check (exit {result.returncode})"
    return None


def case_absent_document_fails(root: Path) -> str | None:
    """An absent document must fail rather than read as nothing to check."""
    (root / OUTPUT).unlink()
    result = run(root, "--check")
    if result.returncode != 1:
        return f"an absent document did not fail --check (exit {result.returncode})"
    return None


def case_moved_corpus_fails(root: Path) -> str | None:
    """A vector added without regenerating moves the figure and must be caught."""

    def add_vector(manifest: dict[str, object]) -> None:
        vectors = manifest["vectors"]
        assert isinstance(vectors, list)
        first = dict(vectors[0])
        first["id"] = "ok-000-staged-for-this-test"
        vectors.append(first)

    rig_json(root, MANIFEST, add_vector)
    result = run(root, "--check")
    if result.returncode != 1:
        return f"a corpus that moved did not fail --check (exit {result.returncode})"
    return None


def case_empty_manifest_refuses(root: Path) -> str | None:
    """An input the gate cannot read is never a clean reading of an empty corpus."""
    rig_json(root, MANIFEST, lambda m: m.__setitem__("vectors", []))
    result = run(root, "--check")
    if result.returncode != 2:
        return f"an empty manifest did not stop the run (exit {result.returncode})"
    return None


def case_empty_baseline_refuses(root: Path) -> str | None:
    """A baseline with no sites would classify every condition as unforced."""
    rig_json(root, BASELINE, lambda b: b.__setitem__("sites", {}))
    result = run(root, "--check")
    if result.returncode != 2:
        return f"a baseline with no sites did not stop the run (exit {result.returncode})"
    return None


def case_unknown_killer_refuses(root: Path) -> str | None:
    """A killer no vector carries makes every attribution below it unsound."""

    def rename_a_killer(baseline: dict[str, object]) -> None:
        sites = baseline["sites"]
        assert isinstance(sites, dict)
        for site in sites.values():
            if site.get("class") == "KILLED":
                site["killers"] = ["ok-000-no-such-vector"]
                return
        raise AssertionError("the staged baseline records no KILLED site to rig")

    rig_json(root, BASELINE, rename_a_killer)
    result = run(root, "--check")
    if result.returncode != 2:
        return f"an unknown killer did not stop the run (exit {result.returncode})"
    return None


def case_unregistered_condition_refuses(root: Path) -> str | None:
    """A cited condition with no registry row cannot be named, so it is not rendered."""
    path = root / REGISTRY
    text = path.read_text(encoding="utf-8")
    marker = "| aee-c-3 |"
    if marker not in text:
        return "the staged registry has no row to remove; the test cannot run"
    kept = [line for line in text.splitlines() if not line.startswith(marker)]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    result = run(root, "--check")
    if result.returncode != 2:
        return f"a condition with no registry row did not stop the run (exit {result.returncode})"
    return None


def case_unresolvable_code_refuses(root: Path) -> str | None:
    """A snippet naming a code the rail does not declare must never be guessed at.

    This is the defect that made the code axis worth writing carefully: resolving
    an unrecognised identifier by nearest match is how a published weak spot turns
    into a claim of coverage.
    """

    def rename_an_emission(baseline: dict[str, object]) -> None:
        sites = baseline["sites"]
        assert isinstance(sites, dict)
        for key, site in sites.items():
            if key.split("::")[2] == "CODE_OFF" and "Code" in str(site.get("snippet", "")):
                site["snippet"] = "appendCode(codes, CodeNoSuchCodeAtAll)"
                return
        raise AssertionError("the staged baseline records no emission site to rig")

    rig_json(root, BASELINE, rename_an_emission)
    result = run(root, "--check")
    if result.returncode != 2:
        return f"an undeclared code did not stop the run (exit {result.returncode})"
    return None


def case_prior_reconstruction_passes(root: Path) -> str | None:
    """The pinned earlier figure is what its two git objects still yield."""
    result = run(root, "--verify-prior")
    if result.returncode:
        return f"the unrigged record failed --verify-prior: {result.stdout}{result.stderr}"
    return None


def case_absent_prior_refuses(root: Path) -> str | None:
    """Without the pinned record there is no earlier figure, and no page either."""
    (root / PRIOR).unlink()
    result = run(root, "--check")
    if result.returncode != 2:
        return f"an absent prior record did not stop the run (exit {result.returncode})"
    return None


def case_retyped_prior_figure_fails(root: Path) -> str | None:
    """The defect this whole reconstruction exists for: a figure typed, not derived."""

    def retype(record: dict[str, object]) -> None:
        derived = record["derived"]
        assert isinstance(derived, dict)
        derived["weak"] = int(derived["weak"]) + 1

    rig_json(root, PRIOR, retype)
    result = run(root, "--verify-prior")
    if result.returncode != 1:
        return f"a retyped earlier figure passed --verify-prior (exit {result.returncode})"
    return None


def case_moved_prior_pin_fails(root: Path) -> str | None:
    """A pin naming bytes history no longer holds is not a pin."""

    def move_it(record: dict[str, object]) -> None:
        pins = record["pins"]
        assert isinstance(pins, dict)
        pins["baselineBlob"] = "0" * 40

    rig_json(root, PRIOR, move_it)
    result = run(root, "--verify-prior")
    if result.returncode != 1:
        return f"a moved blob pin passed --verify-prior (exit {result.returncode})"
    return None


def case_rewritten_campaign_note_fails(root: Path) -> str | None:
    """The released note's own figures are cited here, so a rewrite of them fails."""

    def restate(record: dict[str, object]) -> None:
        pins = record["pins"]
        assert isinstance(pins, dict)
        note = pins["campaignNote"]
        assert isinstance(note, dict)
        note["killed"] = 987654

    rig_json(root, PRIOR, restate)
    result = run(root, "--verify-prior")
    if result.returncode != 1:
        return f"a figure absent from the note passed --verify-prior (exit {result.returncode})"
    return None


def case_absent_campaign_note_refuses(root: Path) -> str | None:
    """A cited source the gate never read is not a source the gate checked."""

    def drop_it(record: dict[str, object]) -> None:
        pins = record["pins"]
        assert isinstance(pins, dict)
        del pins["campaignNote"]

    rig_json(root, PRIOR, drop_it)
    result = run(root, "--verify-prior")
    if result.returncode != 2:
        return f"a record with no campaign note did not stop the run (exit {result.returncode})"
    return None


def case_absent_instrument_delta_refuses(root: Path) -> str | None:
    """The page publishes this reconciliation, so a record without it is unchecked."""

    def drop_it(record: dict[str, object]) -> None:
        pins = record["pins"]
        assert isinstance(pins, dict)
        del pins["instrumentDelta"]

    rig_json(root, PRIOR, drop_it)
    result = run(root, "--verify-prior")
    if result.returncode != 2:
        return f"a record with no instrument delta did not stop the run ({result.returncode})"
    return None


def case_wrong_instrument_sites_fail(root: Path) -> str | None:
    """The named set and the derived set are two handles; disagreement is a refusal."""

    def rename_one(record: dict[str, object]) -> None:
        pins = record["pins"]
        assert isinstance(pins, dict)
        delta = pins["instrumentDelta"]
        assert isinstance(delta, dict)
        sites = delta["sites"]
        assert isinstance(sites, list)
        sites[0] = "tier.go::NoSuchFunction::IF_OFF::0000deadbeef"

    rig_json(root, PRIOR, rename_one)
    result = run(root, "--verify-prior")
    if result.returncode != 1:
        return f"a misnamed instrument site passed --verify-prior ({result.returncode})"
    return None


def case_residue_that_does_not_close_fails(root: Path) -> str | None:
    """The subtraction itself, isolated from every other check that could catch it.

    Retyping `campaignNote.killed` alone does NOT exercise this: the note check
    reads the figure back out of `vectors/CHANGES.md` and refuses first, so the
    case passes for a reason that has nothing to do with the arm it claims to
    test. This case restates the released note in BOTH places and holds the class
    census at its total, leaving the subtraction as the only thing that can
    notice. Confirmed by switching the arm off, where this case goes green.
    """
    changes = root / "vectors/CHANGES.md"
    text = changes.read_text(encoding="utf-8")
    before = "316 were killed, 250 were byte-identical"
    if before not in text:
        return "the staged changelog no longer carries the note this case restates"
    changes.write_text(
        text.replace(before, "317 were killed, 249 were byte-identical"), encoding="utf-8"
    )

    def restate(record: dict[str, object]) -> None:
        pins = record["pins"]
        assert isinstance(pins, dict)
        note = pins["campaignNote"]
        assert isinstance(note, dict)
        note["killed"], note["dead"] = 317, 249

    rig_json(root, PRIOR, restate)
    result = run(root, "--verify-prior")
    if result.returncode != 1:
        return f"a residue that does not close passed --verify-prior ({result.returncode})"
    return None


def case_note_census_that_misses_sites_fails(root: Path) -> str | None:
    """Without this, the subtraction above could close on two errors that cancel."""
    changes = root / "vectors/CHANGES.md"
    text = changes.read_text(encoding="utf-8")
    before = "316 were killed, 250 were byte-identical"
    if before not in text:
        return "the staged changelog no longer carries the note this case restates"
    changes.write_text(
        text.replace(before, "316 were killed, 251 were byte-identical"), encoding="utf-8"
    )
    rig_json(
        root,
        PRIOR,
        lambda record: record["pins"]["campaignNote"].__setitem__("dead", 251),  # type: ignore[index]
    )
    result = run(root, "--verify-prior")
    if result.returncode != 1:
        return f"a note whose classes miss a site passed --verify-prior ({result.returncode})"
    return None


# Cases that drive `--verify-prior`, which reads two objects out of history.
#
# They are listed rather than detected because a shallow clone answers exit 2 to
# every one of them, and exit 2 is what two of these cases WANT. Those two
# would pass in a clone that cannot read a thing, for a reason that has nothing
# to do with what they test -- right for the wrong reason, which fails the next
# time. So the split is explicit: `--without-history` runs the rest and says how
# many it did not run, and a default run in a clone that cannot read the pinned
# objects refuses instead of reporting a smaller suite as a green one.
NEEDS_HISTORY = frozenset({
    "case_prior_reconstruction_passes",
    "case_retyped_prior_figure_fails",
    "case_moved_prior_pin_fails",
    "case_rewritten_campaign_note_fails",
    "case_absent_campaign_note_refuses",
    "case_absent_instrument_delta_refuses",
    "case_wrong_instrument_sites_fail",
    "case_residue_that_does_not_close_fails",
    "case_note_census_that_misses_sites_fails",
})

HISTORY_RUNS_IN = ".github/workflows/forcing-nightly.yml, which checks out at fetch-depth: 0"


def history_is_readable() -> bool:
    """Can this clone read the objects the prior record pins? Not a guess."""
    record = json.loads((REPO_ROOT / PRIOR).read_text(encoding="utf-8"))
    for pin in ("baselineBlob", "manifestBlob"):
        done = subprocess.run(  # noqa: S603 -- fixed argv against this repository
            ["git", "-C", str(REPO_ROOT), "cat-file", "-e", str(record["pins"][pin])],
            capture_output=True,
            check=False,
        )
        if done.returncode:
            return False
    return True


CASES = (
    case_current_tree_passes,
    case_absent_instrument_delta_refuses,
    case_wrong_instrument_sites_fail,
    case_residue_that_does_not_close_fails,
    case_note_census_that_misses_sites_fails,
    case_absent_campaign_note_refuses,
    case_prior_reconstruction_passes,
    case_absent_prior_refuses,
    case_retyped_prior_figure_fails,
    case_moved_prior_pin_fails,
    case_rewritten_campaign_note_fails,
    case_stale_document_fails,
    case_absent_document_fails,
    case_moved_corpus_fails,
    case_empty_manifest_refuses,
    case_empty_baseline_refuses,
    case_unknown_killer_refuses,
    case_unregistered_condition_refuses,
    case_unresolvable_code_refuses,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--without-history",
        action="store_true",
        help="run only the cases that need no git history, and say how many were left",
    )
    args = parser.parse_args()

    if not args.without_history and not history_is_readable():
        print(
            "FAIL: this clone cannot read the objects docs/PRIOR-FORCING.json pins, so the "
            f"{len(NEEDS_HISTORY)} cases that drive --verify-prior cannot run. A shallow "
            "clone answers exit 2 to all of them and two of them want exit 2, so running "
            "them here would report a pass nobody earned. Run this in a full clone, or run "
            f"--without-history on the push path; the full suite runs in {HISTORY_RUNS_IN}.",
            file=sys.stderr,
        )
        return 2

    selected = [c for c in CASES if not (args.without_history and c.__name__ in NEEDS_HISTORY)]
    failures: list[str] = []
    for case in selected:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage(root)
            if problem := case(root):
                failures.append(f"{case.__name__}: {problem}")
    for problem in failures:
        print(f"FAIL: {problem}", file=sys.stderr)
    if failures:
        return 1
    left = len(CASES) - len(selected)
    tail = f"; {left} needing git history were NOT run here, and run in {HISTORY_RUNS_IN}"
    print(f"condition-forcing-gate: {len(selected)} cases behaved{tail if left else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
