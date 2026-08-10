#!/usr/bin/env python3
"""Mutation proof for ``interpretation-registry-gate.py``.

A gate that has never been shown to catch anything is a gate nobody has any
reason to believe. This one had no test at all, and the defect it now refuses
was found by attacking it rather than by reading it: a twenty-first decision
carrying a genuinely open question, classified ``forced`` and citing five
vectors that provably cannot discriminate the reading, made the gate exit 0.
Regenerating the coverage matrix once would have published that as
``forced-by-vector``.

Every case below mutates a COPY of the live registry and asserts the gate goes
red with a NAMED phrase. Two guards make the cases mean something:

  * a mutation that changes nothing is a hard failure, not a pass -- each case
    hashes the registry text before and after and refuses when they match, so a
    case whose edit silently missed cannot report success;
  * the control asserts the UNMUTATED registry passes, so a gate that fails on
    everything cannot masquerade as a gate that catches these.

Usage: python3 scripts/interpretation-registry-gate-test.py
Exit 0 when every case behaves; 1 otherwise.
"""

from __future__ import annotations

import copy
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
GATE_REL = Path("scripts") / "interpretation-registry-gate.py"
REGISTRY_REL = Path("vectors") / "interpretation-decisions.json"


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
    """A copy holding everything the gate reads: the registry, the manifest,
    the vector trees and the gate itself."""
    root = tmp / "corpus"
    (root / "scripts").mkdir(parents=True)
    (root / "vectors").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / GATE_REL, root / GATE_REL)
    shutil.copy2(REPO_ROOT / REGISTRY_REL, root / REGISTRY_REL)
    shutil.copy2(REPO_ROOT / "vectors" / "MANIFEST.json", root / "vectors" / "MANIFEST.json")
    for sub in ("accept", "reject"):
        src = REPO_ROOT / "vectors" / sub
        if src.is_dir():
            shutil.copytree(src, root / "vectors" / sub)
    return root


def _apply(root: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    """Apply a mutation and REFUSE when the file is byte-identical afterwards.

    A mutation that matched nothing leaves the copy correct, the gate green and
    the case passing for the wrong reason. Hash the text: a line count cannot
    detect a one-value-for-one-value swap.
    """
    path = root / REGISTRY_REL
    before = path.read_text(encoding="utf-8")
    registry = json.loads(before)
    mutate(registry)
    after = json.dumps(registry, indent=2, ensure_ascii=False) + "\n"
    if _digest(before) == _digest(after):
        raise AssertionError(
            "mutation applied nothing -- the registry is byte-identical, so the "
            "case would have proven nothing"
        )
    path.write_text(after, encoding="utf-8")


# --- the cases -------------------------------------------------------------

def case_false_forced_claim(registry: dict[str, Any]) -> None:
    """The attack that motivated the fix, verbatim in shape.

    A genuinely open question -- the constraint set of the sealed existential --
    asserted as forced, citing vectors an instrumented run measured at zero
    verdict flips. It is NOT added to unwitnessedForced, because an author
    making this claim believes it is proven.
    """
    template = copy.deepcopy(registry["decisions"][0])
    victim = registry["decisions"][0]["forcingVectors"][0]
    template.update(
        id=9021,
        title="Constraint set of the sealed existential bullet",
        classification="forced",
        specAnchors=["L1275-1278"],
        reading=(
            "The existential bullet reads on the clean-row conjuncts, not only "
            "the structural members."
        ),
        forcingVectors=[victim],
    )
    template.pop("discrimination", None)
    registry["decisions"].append(template)


def case_declaration_not_retired(registry: dict[str, Any]) -> None:
    """A decision named in the declaration that HAS gained a witness.

    Without this clause the declaration becomes permanent: witnesses land, the
    list keeps naming them, and the count of unproven claims stops falling
    while everything still reads correct.
    """
    dec = registry["decisions"][0]
    dec["discrimination"] = {
        "rivalReading": "kind-constraint violations invalidate directly",
        "witnessVector": dec["forcingVectors"][0],
        "observable": "verdict",
        "underReading": "invalid",
        "underRival": "valid",
    }


def case_non_discriminating_witness(registry: dict[str, Any]) -> None:
    """A witness recording the SAME result under both readings.

    This is a near-miss from the review thread made mechanical: an instrumented
    run mutated the sealed existential to the broad reading, returned zero
    per-vector differences, and that result was very nearly reported as
    confirmation. It confirms nothing, and a witness of this shape must never
    pass.
    """
    dec = registry["decisions"][1]
    dec["discrimination"] = {
        "rivalReading": "the broad reading",
        "witnessVector": dec["forcingVectors"][0],
        "observable": "verdict",
        "underReading": "invalid",
        "underRival": "invalid",
    }
    registry["unwitnessedForced"]["decisions"] = [
        e for e in registry["unwitnessedForced"]["decisions"] if e.get("id") != dec["id"]
    ]


def case_witness_vector_orphaned(registry: dict[str, Any]) -> None:
    """A witness naming a vector that is not replayed."""
    dec = registry["decisions"][2]
    dec["discrimination"] = {
        "rivalReading": "the rival reading",
        "witnessVector": "bad-9999-not-a-real-vector",
        "observable": "codes",
        "underReading": "sealed-record-absent",
        "underRival": "carried-record-invalid",
    }
    registry["unwitnessedForced"]["decisions"] = [
        e for e in registry["unwitnessedForced"]["decisions"] if e.get("id") != dec["id"]
    ]


def case_declaration_without_reason(registry: dict[str, Any]) -> None:
    """A declaration that names decisions but states no reason is an exemption
    list wearing a declaration's clothes."""
    registry["unwitnessedForced"]["reason"] = "   "


def case_permitted_carrying_witness(registry: dict[str, Any]) -> None:
    """A permitted reading has nothing to discriminate against."""
    dec = registry["decisions"][3]
    dec["classification"] = "permitted"
    dec["forcingVectors"] = []
    dec["discrimination"] = {
        "rivalReading": "x",
        "witnessVector": "y",
        "observable": "verdict",
        "underReading": "a",
        "underRival": "b",
    }
    registry["unwitnessedForced"]["decisions"] = [
        e for e in registry["unwitnessedForced"]["decisions"] if e.get("id") != dec["id"]
    ]


CASES: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
    ("false forced claim citing a non-discriminating vector",
     case_false_forced_claim, "no discrimination witness"),
    ("declaration not retired after a witness landed",
     case_declaration_not_retired, "remove it from the declaration"),
    ("witness records the same result under both readings",
     case_non_discriminating_witness, "NOT discriminating"),
    ("witness names a vector that is not replayed",
     case_witness_vector_orphaned, "has no file"),
    ("declaration names decisions but states no reason",
     case_declaration_without_reason, "states no reason"),
    ("permitted decision carrying a discrimination witness",
     case_permitted_carrying_witness, "only a forced decision"),
]


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        root = _staged_copy(Path(td))
        rc, out = _run_gate(root)
        if rc != 0:
            print(f"CONTROL FAILED: unmutated registry exits {rc}\n{out}", file=sys.stderr)
            return 1
        print("  control: unmutated registry passes (rc=0)")

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
    print(f"\nOK: control passes and all {len(CASES)} mutations go red with a named reason.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
