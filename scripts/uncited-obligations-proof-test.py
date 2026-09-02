#!/usr/bin/env python3
"""Mutation proof for the coverage ratchet in ``uncited-obligations-proof.py``.

The ratchet exists because a citation is free text. Adding a line range to an
anchor column raises the measured obligation coverage the instant it is typed,
and before the ratchet nothing in the corpus checked it: an anchor reading
``L1725-1748`` appended to ``v03547f8918e0d7dc`` -- a vector about
a dropped corpus manifest, naming two consumer obligations the corpus itself
rules structurally untestable -- moved the measurement from 55 obligations cited
to 57 while the anchor gate, its ``--sync``, the condition registry gate, the
distinctness gate, the regenerability gate and both rails all stayed green.

So the ratchet is the only thing standing between that anchor and a published
number, and a ratchet nobody has shown to catch anything is worth nothing. Each
case below mutates a COPY of the corpus and asserts the ratchet goes red with a
NAMED phrase. Three guards make the cases mean something:

  * a mutation that leaves the file byte-identical is a hard failure, not a
    pass -- every case hashes the text before and after, because a line count
    cannot see one line range swapped for another;
  * the control asserts the UNMUTATED copy passes, so a ratchet that refuses
    everything cannot masquerade as one that catches these;
  * the copy carries only what the ratchet reads, and the ratchet is imported
    from inside it, so a case cannot accidentally be answered by the live tree.

Usage: python3 scripts/uncited-obligations-proof-test.py
Exit 0 when every case behaves; 1 otherwise.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROOF_REL = Path("scripts") / "uncited-obligations-proof.py"
SPEC_REL = Path("spec") / "predicates" / "adversarial-execution-evidence.md"
REJECT_REL = Path("vectors") / "reject" / "INDEX.md"
ACCEPT_REL = Path("vectors") / "accept" / "INDEX.md"
READS = (PROOF_REL, SPEC_REL, REJECT_REL, ACCEPT_REL)

# Every mutation names the vectors it kills, so a ratchet run inside the test
# is handed the same set the real run proves rather than an invented one.
ALL_PROVED = {"scoped_refs", "ranking_cap", "precondition", "uncoverable", "timestamp"}


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def staged_copy(tmp: Path, name: str) -> Path:
    """A copy holding exactly the four files the ratchet reads."""
    root = tmp / name
    for relative in READS:
        (root / relative.parent).mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, root / relative)
    return root


def run_ratchet(root: Path, proved: set[str]) -> tuple[bool, str]:
    """Import the copied proof and ask it the coverage question. Importing from
    inside the copy is what binds its ROOT to the copy: a ratchet that read the
    live tree would answer every case identically and pass this test while
    checking nothing."""
    location = root / PROOF_REL
    spec = importlib.util.spec_from_file_location(f"proof_{root.name}", location)
    if spec is None or spec.loader is None:
        return False, "the copied proof did not load"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            spec.loader.exec_module(module)
            healthy = bool(module.coverage_ratchet(proved))
    except Exception as failure:  # a ratchet that raises has not answered
        return False, f"{captured.getvalue()}{failure!r}"
    return healthy, captured.getvalue()


def edit(root: Path, relative: Path, before: str, after: str) -> str | None:
    """Replace one occurrence, refusing anything that does not change bytes."""
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if text.count(before) != 1:
        return f"the mutation site is present {text.count(before)} times, not once"
    was = digest(text)
    path.write_text(text.replace(before, after), encoding="utf-8")
    if digest(path.read_text(encoding="utf-8")) == was:
        return "the mutation left the file byte-identical"
    return None


def case_fabricated_anchor(root: Path) -> str | None:
    """The attack itself: a vector about a dropped corpus manifest, cited
    against two consumer obligations no vector can decide."""
    return edit(root, REJECT_REL,
                "| `v03547f8918e0d7dc` | ok-033 | drop corpus.manifest, "
                "keeping the corpus name, uri and digest | - | aee-c-78 | "
                "`environment-incomplete` | L757-767 |",
                "| `v03547f8918e0d7dc` | ok-033 | drop corpus.manifest, "
                "keeping the corpus name, uri and digest | - | aee-c-78 | "
                "`environment-incomplete` | L757-767; L1725-1748 |")


def case_widened_anchor(root: Path) -> str | None:
    """The lazier shape of the same thing: widening an anchor already on record
    until it swallows a sentence nobody proved."""
    return edit(root, REJECT_REL, "| aee-c-10 | L552 |", "| aee-c-10 | L552-1164 |")


def case_deleted_citation(root: Path) -> str | None:
    """A citation on record that a re-vendor or a hand edit dropped. It reads
    exactly like one that was never there, which is why the ratchet is a set
    comparison in both directions rather than a floor."""
    return edit(root, REJECT_REL,
                "| aee-c-85 | L1672; L1680-1683 |", "| aee-c-85 | L1672 |")


def case_resplit_spec(root: Path) -> str | None:
    """A specification that no longer splits into the pinned number of
    sentences. Every line number in the ratchet is an offset into the pinned
    document, so comparing sets across two different documents is the one
    outcome worse than not checking."""
    path = root / SPEC_REL
    text = path.read_text(encoding="utf-8")
    was = digest(text)
    path.write_text(text + "\n\nA consumer MUST NOT read this sentence.\n",
                    encoding="utf-8")
    if digest(path.read_text(encoding="utf-8")) == was:
        return "the mutation left the file byte-identical"
    return None


CASES: tuple[tuple[str, Callable[[Path], str | None], str, set[str]], ...] = (
    ("fabricated_anchor", case_fabricated_anchor,
     "is newly cited by a vector anchor and nothing in this file pays for it",
     ALL_PROVED),
    ("widened_anchor", case_widened_anchor,
     "is newly cited by a vector anchor and nothing in this file pays for it",
     ALL_PROVED),
    ("deleted_citation", case_deleted_citation,
     "is on record as cited and no vector anchor covers it any more",
     ALL_PROVED),
    ("resplit_spec", case_resplit_spec,
     "Every line number in this file is an offset into the pinned document",
     ALL_PROVED),
    ("unpaid_mutation", lambda root: None,
     "did not run or did not kill the vectors it named",
     ALL_PROVED - {"timestamp"}),
)


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        tmp = Path(scratch)

        control_root = staged_copy(tmp, "control")
        healthy, output = run_ratchet(control_root, ALL_PROVED)
        print(f"  control          : healthy={healthy}")
        if not healthy:
            failures.append("the unmutated copy does not pass, so no case below "
                            f"means anything:\n{output}")

        for name, mutate, phrase, proved in CASES:
            root = staged_copy(tmp, name)
            refusal = mutate(root)
            if refusal is not None:
                failures.append(f"{name}: {refusal}")
                print(f"  {name:17s}: GUARD {refusal}")
                continue
            healthy, output = run_ratchet(root, proved)
            named = phrase in output
            print(f"  {name:17s}: healthy={healthy} named={named}")
            if healthy:
                failures.append(f"{name}: the ratchet passed a corpus it should refuse")
            elif not named:
                failures.append(f"{name}: the ratchet refused, but for the wrong "
                                f"reason -- {phrase!r} is not in its output:\n{output}")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    print("RATCHET TEST:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
