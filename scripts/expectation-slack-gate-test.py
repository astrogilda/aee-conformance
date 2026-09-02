#!/usr/bin/env python3
"""Mutation proof for ``expectation-slack-gate.py``.

The gate exists because an edit of one clause silently disarmed the corpus's
only reading-discriminator while every other check stayed green, so the one
thing this test has to establish is that the gate sees that exact edit. Case one
is therefore the attack verbatim: `bad-1017`'s companion condition moved out of
the `also carries` clause and into the expected-code cell, which is the change
a well-meaning editor makes when they notice the statement carries two faults
and think the manifest should say so.

The remaining cases attack the gate's own escape hatch. A frozen entry is a
place a future finding can hide, so a freeze that stops describing its vector
and a freeze whose overlap changes shape both have to be refusals rather than
quiet passes, and a vector the gate could not read has to be a refusal rather
than a vector counted as clean.

Two guards make the cases mean something: each hashes the manifest text before
and after and refuses when they match, so a mutation that silently missed cannot
report success; and the control asserts the unmutated corpus passes, so a gate
that fails on everything cannot masquerade as a gate that catches these.

Usage: python3 scripts/expectation-slack-gate-test.py
Exit 0 when every case behaves; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_REL = Path("scripts") / "expectation-slack-gate.py"
MANIFEST_REL = Path("vectors") / "MANIFEST.json"
PIN = "vd538496f284b4761"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run_gate(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(root / GATE_REL)],
        capture_output=True,
        text=True,
        cwd=str(root),
    )
    return proc.returncode, proc.stdout + proc.stderr


def _staged_copy(tmp: Path) -> Path:
    """A copy holding everything the gate reads: itself, the reference rail it
    drives, the manifest and the vector trees."""
    root = tmp / "corpus"
    (root / "scripts").mkdir(parents=True)
    (root / "vectors").mkdir(parents=True)
    (root / "packaging").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / GATE_REL, root / GATE_REL)
    shutil.copy2(REPO_ROOT / "packaging" / "run_vectors.py",
                 root / "packaging" / "run_vectors.py")
    shutil.copy2(REPO_ROOT / MANIFEST_REL, root / MANIFEST_REL)
    for sub in ("accept", "reject", "indeterminate"):
        src = REPO_ROOT / "vectors" / sub
        if src.is_dir():
            shutil.copytree(src, root / "vectors" / sub)
    return root


def _entry(manifest: dict[str, Any], vid: str) -> dict[str, Any]:
    for entry in manifest["vectors"]:
        if entry.get("id") == vid:
            assert isinstance(entry, dict)
            return entry
    raise AssertionError(f"{vid} is not in the manifest, so the case addresses nothing")


def _apply(root: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    """Apply a mutation and REFUSE when the file is byte-identical afterwards.

    A mutation that matched nothing leaves the copy correct, the gate green and
    the case passing for the wrong reason. Hash the text: a line count cannot
    detect a one-value-for-one-value swap.
    """
    path = root / MANIFEST_REL
    before = path.read_text(encoding="utf-8")
    manifest = json.loads(before)
    mutate(manifest)
    after = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if _digest(before) == _digest(after):
        raise AssertionError(
            "mutation applied nothing -- the manifest is byte-identical, so "
            "the case would have proven nothing"
        )
    path.write_text(after, encoding="utf-8")


# --- the cases -------------------------------------------------------------

def case_pin_widened(manifest: dict[str, Any]) -> None:
    """The attack that motivated the gate, verbatim in shape.

    The companion condition moves out of `also carries` and into the expected
    codes. The statement is unchanged, the replay stays green, and the vector
    stops separating the two readings of the sealed existential because either
    one now satisfies it.
    """
    entry = _entry(manifest, PIN)
    expected = entry["expected"]
    expected["codes"] = sorted(set(expected["codes"]) | set(expected.pop("alsoCarries")))


def case_frozen_entry_no_longer_overlaps(manifest: dict[str, Any]) -> None:
    """A frozen vector narrowed to a single code.

    Correct as an edit and still a refusal, because the freeze that covered it
    now describes nothing and would cover the NEXT widening of that vector in
    silence.
    """
    _entry(manifest, "vf35474dd75d6b14a")["expected"]["codes"] = ["result-vocabulary"]


def case_frozen_entry_changes_shape(manifest: dict[str, Any]) -> None:
    """A frozen vector whose overlap becomes a different pair.

    The identifier is on the list, so a freeze keyed by identifier alone would
    pass this. It is a new finding: the vector now fails to pin a condition it
    was never recorded as failing to pin.
    """
    entry = _entry(manifest, "vb704d6c2420a1c43")
    entry["expected"]["codes"] = ["arming-covers-nothing", "sealed-record-absent"]


def case_declared_twice(manifest: dict[str, Any]) -> None:
    """One condition named in the expected codes AND in `also carries`.

    The second-fault exemption and the measurement then name the same thing, so
    the clause that is supposed to hold a condition out of the expectation is
    putting it back in.
    """
    entry = _entry(manifest, PIN)
    entry["expected"]["alsoCarries"] = list(entry["expected"]["codes"])


def case_vector_file_missing(manifest: dict[str, Any]) -> None:
    """A manifest row pointing at a file that is not there.

    An unreadable vector must never be counted as one that pins its condition:
    that is the shape in which a check reports a clean result for work it did
    not do.
    """
    _entry(manifest, PIN)["file"] = "reject/bad-1017-not-on-disk.json"


def case_manifest_empty(manifest: dict[str, Any]) -> None:
    """No vectors at all. A gate with nothing to read has not passed."""
    manifest["vectors"] = []


CASES: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
    ("the discrimination pin widened to both conditions",
     case_pin_widened, "cannot force a reading"),
    ("a frozen entry that no longer overlaps",
     case_frozen_entry_no_longer_overlaps, "no longer overlaps"),
    ("a frozen entry whose overlap changed shape",
     case_frozen_entry_changes_shape, "cannot force a reading"),
    ("one condition declared as both the measurement and the exemption",
     case_declared_twice, "cannot force a reading"),
    ("a manifest row naming a vector that is not on disk",
     case_vector_file_missing, "is not on disk"),
    ("a manifest listing no vectors at all",
     case_manifest_empty, "the check did not run"),
]


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        root = _staged_copy(Path(td))
        rc, out = _run_gate(root)
        if rc != 0:
            print(f"CONTROL FAILED: the unmutated corpus exits {rc}\n{out}",
                  file=sys.stderr)
            return 1
        print("  control: unmutated corpus passes (rc=0)")

    for name, mutate, phrase in CASES:
        with tempfile.TemporaryDirectory() as td:
            root = _staged_copy(Path(td))
            try:
                _apply(root, mutate)
            except AssertionError as exc:
                failures.append(f"{name}: {exc}")
                continue
            rc, out = _run_gate(root)
            if rc == 0:
                failures.append(f"{name}: gate ACCEPTED the mutation (rc=0)")
            elif phrase not in out:
                failures.append(
                    f"{name}: gate failed but never said {phrase!r}; a red run "
                    f"with the wrong reason is not the catch. Output:\n{out}"
                )
            else:
                print(f"  caught: {name}")

    if failures:
        print("\nFAIL: the gate did not catch every mutation.", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"\nOK: control passes and all {len(CASES)} mutations go red with a "
          "named reason.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
