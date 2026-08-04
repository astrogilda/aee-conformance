#!/usr/bin/env python3
"""Tests for scripts/condition-forcing-crosscheck.py, and all but one are refusals.

The crosscheck exists because a figure confirmed by the program that wrote it is
not confirmed. A crosscheck evidenced only by a green run has exactly the same
defect one level up, so every path from a retyped number, a dropped table row, a
mismatched pair of inputs and a pin history no longer holds to a non-zero exit is
exercised here.

Two exit codes are distinguished on purpose and the cases assert which one they
get: 1 means the page and the data disagree, 2 means an input could not be read.
Collapsing them would let a broken input read as a disagreement, and a
disagreement read as a broken input.

Every case runs against a STAGED COPY of the tree, rigged one file at a time.
Nothing here writes to the repository under test.

Ten cases pass `--with-prior`, which reads two blobs out of git history. A
shallow clone answers exit 2 to all ten, and two of them want exit 2, so they
would pass in a clone that can read nothing. `--without-history` runs the rest
and says how many it left; a default run that cannot reach the pinned blobs
refuses rather than calling a smaller suite green.

Usage:
    python3 scripts/condition-forcing-crosscheck-test.py                    # all of it
    python3 scripts/condition-forcing-crosscheck-test.py --without-history  # shallow
Exit 0 when every case behaves; 1 naming each that did not; 2 when the run could
not cover what it was asked to cover.
"""

from __future__ import annotations

import argparse
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
CHECK = REPO_ROOT / "scripts" / "condition-forcing-crosscheck.py"

MANIFEST = "vectors/MANIFEST.json"
BASELINE = "docs/FORCING-BASELINE.json"
PAGE = "docs/FORCING-HONESTY.md"
PRIOR = "docs/PRIOR-FORCING.json"

STAGED = (MANIFEST, BASELINE, PAGE, PRIOR)


def stage(root: Path) -> None:
    for rel in STAGED:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, target)


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- running this repository's own check is the point
        [sys.executable, str(CHECK), "--root", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def rig_json(root: Path, rel: str, mutate: Callable[[dict[str, Any]], None]) -> None:
    path = root / rel
    loaded = json.loads(path.read_text(encoding="utf-8"))
    mutate(loaded)
    path.write_text(json.dumps(loaded, indent=2), encoding="utf-8")


def rig_text(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"the fixture cannot rig {rel}: {old!r} is not in it")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def rig_retype(root: Path, rel: str, pattern: str) -> None:
    """Add one to the number `pattern` captures, so the page states a wrong figure.

    A fixture that names the RIGHT value in order to replace it restates a measured
    number in a second place, and then goes stale the moment the measurement moves:
    both of the rigs below did, one when the corpus gained a vector and one when the
    campaign gained a site, and a rig that no longer matches raises instead of
    proving anything. Matching the row and perturbing whatever it currently says
    keeps the case pinned to the shape it is testing rather than to the reading of
    the day.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    found = re.search(pattern, text)
    if found is None:
        raise AssertionError(f"the fixture cannot rig {rel}: nothing matches {pattern!r}")
    start, end = found.span(1)
    path.write_text(text[:start] + str(int(found.group(1)) + 1) + text[end:], encoding="utf-8")


# ---------------------------------------------------------------------------
# the cases. Each returns None when it behaved, or a sentence saying what it did.


def case_clean(root: Path) -> str | None:
    done = run(root)
    if done.returncode != 0:
        return f"the unrigged tree was refused: {done.stderr.strip()}"
    return None


def case_clean_with_prior(root: Path) -> str | None:
    done = run(root, "--with-prior")
    if done.returncode != 0:
        return f"the unrigged tree was refused with --with-prior: {done.stderr.strip()}"
    if "the earlier figure follows from its pinned objects" not in done.stdout:
        return "--with-prior did not report on the earlier figure"
    return None


def case_headline_retyped(root: Path) -> str | None:
    rig_retype(root, PAGE, r"(\d+) are forced")
    done = run(root)
    if done.returncode != 1:
        return f"a retyped headline exited {done.returncode}, wanted 1"
    return None


def case_weak_count_retyped(root: Path) -> str | None:
    rig_retype(root, PAGE, r"(\d+) are covered only redundantly")
    done = run(root)
    if done.returncode != 1:
        return f"a retyped weak count exited {done.returncode}, wanted 1"
    return None


def case_weak_row_dropped(root: Path) -> str | None:
    path = root / PAGE
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if not line.startswith("| `aee-c-3` |")]
    if len(kept) == len(lines):
        return "the fixture found no aee-c-3 row to drop"
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    done = run(root)
    if done.returncode != 1:
        return f"a dropped weak row exited {done.returncode}, wanted 1"
    return None


def case_weak_row_shares_retyped(root: Path) -> str | None:
    rig_text(root, PAGE, "| 2 | 101 |", "| 2 | 102 |")
    done = run(root)
    if done.returncode != 1:
        return f"a retyped shares column exited {done.returncode}, wanted 1"
    if "shares" not in done.stderr:
        return "the refusal did not name the shares column"
    return None


def case_corpus_row_retyped(root: Path) -> str | None:
    rig_retype(root, PAGE, r"\|\s*corpus\s*\|\s*suiteRevision \d+, (\d+) vectors")
    done = run(root)
    if done.returncode != 1:
        return f"a retyped corpus row exited {done.returncode}, wanted 1"
    return None


def case_campaign_row_retyped(root: Path) -> str | None:
    rig_retype(root, PAGE, r"\|\s*campaign\s*\|\s*\d+ single-site weakenings: (\d+) KILLED")
    done = run(root)
    if done.returncode != 1:
        return f"a retyped campaign row exited {done.returncode}, wanted 1"
    return None


def case_weak_section_gone(root: Path) -> str | None:
    rig_text(
        root,
        PAGE,
        "## The conditions nothing uniquely attributes to their own vectors",
        "## Some conditions",
    )
    done = run(root)
    if done.returncode != 1:
        return f"a page with no weak section exited {done.returncode}, wanted 1"
    return None


def case_page_absent(root: Path) -> str | None:
    (root / PAGE).unlink()
    done = run(root)
    if done.returncode != 2:
        return f"an absent page exited {done.returncode}, wanted 2"
    return None


def case_baseline_has_no_sites(root: Path) -> str | None:
    rig_json(root, BASELINE, lambda loaded: loaded.__setitem__("sites", {}))
    done = run(root)
    if done.returncode != 2:
        return f"an empty baseline exited {done.returncode}, wanted 2"
    return None


def case_manifest_has_no_vectors(root: Path) -> str | None:
    rig_json(root, MANIFEST, lambda loaded: loaded.__setitem__("vectors", []))
    done = run(root)
    if done.returncode != 2:
        return f"an empty manifest exited {done.returncode}, wanted 2"
    return None


def case_killer_no_vector_carries(root: Path) -> str | None:
    def mutate(loaded: dict[str, Any]) -> None:
        for site in loaded["sites"].values():
            if site.get("killers"):
                site["killers"] = [*site["killers"], "bad-000-no-such-vector"]
                return
        raise AssertionError("the fixture found no killed site")

    rig_json(root, BASELINE, mutate)
    done = run(root)
    if done.returncode != 2:
        return f"a killer no vector carries exited {done.returncode}, wanted 2"
    if "does not carry" not in done.stderr:
        return "the refusal did not say the manifest does not carry it"
    return None


def case_killed_count_disagrees(root: Path) -> str | None:
    rig_json(root, BASELINE, lambda loaded: loaded["counts"].__setitem__("KILLED", 999))
    done = run(root)
    if done.returncode != 1:
        return f"a baseline whose own count disagrees exited {done.returncode}, wanted 1"
    return None


def case_prior_retyped(root: Path) -> str | None:
    rig_json(root, PRIOR, lambda loaded: loaded["derived"].__setitem__("weak", 23))
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a retyped earlier figure exited {done.returncode}, wanted 1"
    return None


def case_prior_blob_not_in_history(root: Path) -> str | None:
    rig_json(
        root,
        PRIOR,
        lambda loaded: loaded["pins"].__setitem__("baselineBlob", "0" * 40),
    )
    done = run(root, "--with-prior")
    if done.returncode != 2:
        return f"a pin history does not hold exited {done.returncode}, wanted 2"
    if "shallow clone" not in done.stderr:
        return "the refusal did not distinguish an absent object from a disagreeing one"
    return None


def case_reconciliation_retyped(root: Path) -> str | None:
    """The page's own identity, retyped so it still adds up. Only the data can tell."""
    rig_text(
        root,
        PAGE,
        "**331 killed in\n"
        "the pinned baseline = 316 in the released note + 12 killed only by vectors added\n"
        "afterwards + 3 the earlier instrument could not observe.**",
        "**332 killed in\n"
        "the pinned baseline = 317 in the released note + 12 killed only by vectors added\n"
        "afterwards + 3 the earlier instrument could not observe.**",
    )
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a retyped reconciliation exited {done.returncode}, wanted 1"
    return None


def case_reconciliation_final_term_retyped(root: Path) -> str | None:
    """The third term alone, which is the one the derivation supplies."""
    rig_text(root, PAGE, "+ 3 the earlier instrument", "+ 4 the earlier instrument")
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a retyped final term exited {done.returncode}, wanted 1"
    return None


def case_residue_that_does_not_close(root: Path) -> str | None:
    """The subtraction itself: the record's note moves, so only the arithmetic notices.

    Retyping the PAGE cannot reach this -- the four published integers are
    compared first and refuse. What reaches it is the record restating the
    released note, which is exactly the case the arithmetic exists for.
    """
    rig_json(
        root,
        PRIOR,
        lambda loaded: loaded["pins"]["campaignNote"].__setitem__("killed", 317),
    )
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a residue that does not close exited {done.returncode}, wanted 1"
    if "reachable kills less" not in done.stderr:
        return f"the refusal did not come from the subtraction: {done.stderr.strip()}"
    return None


def case_reconciliation_absent(root: Path) -> str | None:
    """The reconciliation removed from the page, which must never read as agreement.

    The stderr assertion is load-bearing. Without it a crash on the missing
    match exits 1 as well, and the case would pass while the refusal it claims
    to test was gone.
    """
    rig_text(root, PAGE, "killed in\nthe pinned baseline =", "killed in the pinned baseline was")
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a page stating no reconciliation exited {done.returncode}, wanted 1"
    if "states no reconciliation" not in done.stderr:
        return f"the refusal was not the one this case tests: {done.stderr.strip()[:200]}"
    return None


def case_instrument_site_renamed_on_the_page(root: Path) -> str | None:
    """The page's site list is read back too, not just the four integers."""
    rig_text(
        root,
        PAGE,
        "-   `verify.go::anchorPolicyCodes::IF_OFF::ed58b9be9c83`",
        "-   `verify.go::anchorPolicyCodes::IF_OFF::000000000000`",
    )
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a renamed site on the page exited {done.returncode}, wanted 1"
    return None


def case_instrument_site_renamed_in_the_record(root: Path) -> str | None:
    """And the record's list, which the derivation has to agree with independently."""

    def mutate(loaded: dict[str, Any]) -> None:
        loaded["pins"]["instrumentDelta"]["sites"][0] = "tier.go::Nope::IF_OFF::000000000000"

    rig_json(root, PRIOR, mutate)
    done = run(root, "--with-prior")
    if done.returncode != 1:
        return f"a renamed site in the record exited {done.returncode}, wanted 1"
    return None


def case_instrument_delta_absent(root: Path) -> str | None:
    """A record with no reconciliation block cannot be read as one that reconciles."""
    rig_json(root, PRIOR, lambda loaded: loaded["pins"].pop("instrumentDelta"))
    done = run(root, "--with-prior")
    if done.returncode != 2:
        return f"a record with no instrumentDelta exited {done.returncode}, wanted 2"
    return None


CASES: tuple[tuple[str, Callable[[Path], str | None]], ...] = (
    ("the unrigged tree passes", case_clean),
    ("the unrigged tree passes with --with-prior", case_clean_with_prior),
    ("a retyped headline forced count", case_headline_retyped),
    ("a retyped headline weak count", case_weak_count_retyped),
    ("a weak row dropped from the table", case_weak_row_dropped),
    ("a retyped shares column", case_weak_row_shares_retyped),
    ("a retyped corpus provenance row", case_corpus_row_retyped),
    ("a retyped campaign provenance row", case_campaign_row_retyped),
    ("the weak section renamed away", case_weak_section_gone),
    ("an absent page", case_page_absent),
    ("a baseline with no sites", case_baseline_has_no_sites),
    ("a manifest with no vectors", case_manifest_has_no_vectors),
    ("a killer no vector carries", case_killer_no_vector_carries),
    ("a baseline whose own KILLED count disagrees", case_killed_count_disagrees),
    ("a retyped earlier figure", case_prior_retyped),
    ("a pin this history no longer holds", case_prior_blob_not_in_history),
    ("a retyped reconciliation that still adds up", case_reconciliation_retyped),
    ("a retyped final term in the reconciliation", case_reconciliation_final_term_retyped),
    ("a residue that does not close", case_residue_that_does_not_close),
    ("a page that states no reconciliation", case_reconciliation_absent),
    ("an instrument-only site renamed on the page", case_instrument_site_renamed_on_the_page),
    ("an instrument-only site renamed in the record", case_instrument_site_renamed_in_the_record),
    ("a record with no reconciliation block", case_instrument_delta_absent),
)


# Every case that passes --with-prior, which reads two blobs out of history.
#
# Named rather than detected, for the reason the sibling suite names its own: a
# shallow clone answers exit 2 to all of them, and two of them want exit 2, so
# they would pass in a clone that can read nothing at all.
NEEDS_HISTORY = frozenset({
    "the unrigged tree passes with --with-prior",
    "a retyped earlier figure",
    "a pin this history no longer holds",
    "a retyped reconciliation that still adds up",
    "a retyped final term in the reconciliation",
    "a residue that does not close",
    "a page that states no reconciliation",
    "an instrument-only site renamed on the page",
    "an instrument-only site renamed in the record",
    "a record with no reconciliation block",
})

HISTORY_RUNS_IN = ".github/workflows/forcing-nightly.yml, which checks out at fetch-depth: 0"


def history_is_readable() -> bool:
    """Can this clone read the blobs the prior record pins? Asked, not assumed."""
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
            "FAIL: this clone cannot read the blobs docs/PRIOR-FORCING.json pins, so the "
            f"{len(NEEDS_HISTORY)} cases that pass --with-prior cannot run. All of them "
            "would exit 2 here and two of them want exit 2, so running them would report "
            "a pass nobody earned. Use --without-history on the push path; the full suite "
            f"runs in {HISTORY_RUNS_IN}.",
            file=sys.stderr,
        )
        return 2

    selected = [
        (name, case)
        for name, case in CASES
        if not (args.without_history and name in NEEDS_HISTORY)
    ]
    failures: list[str] = []
    for name, case in selected:
        with tempfile.TemporaryDirectory(prefix="aee-crosscheck-") as raw:
            root = Path(raw)
            stage(root)
            try:
                complaint = case(root)
            except AssertionError as exc:
                complaint = str(exc)
        if complaint:
            failures.append(f"  - {name}: {complaint}")
    if failures:
        print(f"FAIL: {len(failures)} case(s).", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    left = len(CASES) - len(selected)
    tail = f"; {left} needing git history were NOT run here, and run in {HISTORY_RUNS_IN}"
    print(f"condition-forcing-crosscheck: {len(selected)} cases behaved{tail if left else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
