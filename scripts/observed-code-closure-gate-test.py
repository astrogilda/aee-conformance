#!/usr/bin/env python3
"""Mutation proof for ``observed-code-closure-gate.py``.

The gate exists because a code the reference rail emits was compared against
nothing, so the case that matters most is the drift that actually happened,
reconstructed exactly: `bad-817`'s undeclared companion changed from
`caught-row-uncovered` to `reconstructed-row-uncovered` when its parent moved,
and every gate stayed green. Case one puts the old spelling back and requires
the gate to refuse from both ends at once -- the code the rail now emits is
declared nowhere, and the code the row still claims is emitted no longer is.

The remaining cases attack the two directions separately, the rail rather than
the index, and the two shapes in which a check reports a clean result for work
it did not do: a vector it could not read, and a manifest with nothing in it.

Two guards make the cases mean something. Each mutation hashes the file it edits
before and after and refuses when they match, so a mutation that silently missed
cannot report success; and the control asserts the unmutated corpus passes, so a
gate that fails on everything cannot masquerade as a gate that catches these.

Usage: python3 scripts/observed-code-closure-gate-test.py
Exit 0 when every case behaves; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_REL = Path("scripts") / "observed-code-closure-gate.py"
MANIFEST_REL = Path("vectors") / "MANIFEST.json"
RAIL_REL = Path("packaging") / "run_vectors.py"
DRIFTED = "v4ff6cb70764bf703"

# The line the rail mutation patches, and what it becomes. Kept as constants so
# a rail edit that moves this text fails the case loudly rather than leaving a
# mutation that quietly applied nothing.
RAIL_ANCHOR = (
    "    def verify(self, stmt: Any, raw: bytes | None = None) -> Outcome:\n"
    "        out = Outcome()\n"
)
RAIL_PATCHED = RAIL_ANCHOR + '        out.add("synthetic-rail-drift")\n'


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
    shutil.copy2(REPO_ROOT / RAIL_REL, root / RAIL_REL)
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


def _edit(path: Path, rewrite: Callable[[str], str]) -> None:
    """Rewrite a file and REFUSE when it is byte-identical afterwards.

    A mutation that matched nothing leaves the copy correct, the gate green and
    the case passing for the wrong reason. Hash the text: a line count cannot
    detect a one-value-for-one-value swap, and this suite's first case is
    exactly such a swap.
    """
    before = path.read_text(encoding="utf-8")
    after = rewrite(before)
    if _digest(before) == _digest(after):
        raise AssertionError(
            f"mutation applied nothing -- {path.name} is byte-identical, so the "
            "case would have proven nothing"
        )
    path.write_text(after, encoding="utf-8")


def _manifest_case(mutate: Callable[[dict[str, Any]], None]) -> Callable[[Path], None]:
    def apply(root: Path) -> None:
        def rewrite(before: str) -> str:
            manifest = json.loads(before)
            mutate(manifest)
            return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"

        _edit(root / MANIFEST_REL, rewrite)

    return apply


# --- the cases -------------------------------------------------------------

def case_pin_carries_the_old_spelling(manifest: dict[str, Any]) -> None:
    """The drift that motivated the gate, verbatim in shape.

    `bad-817` moved to a reconstructed parent and its undeclared companion moved
    with it. Put the pre-move spelling back: the row now claims a code the rail
    does not emit, and the code the rail does emit is claimed by nothing. Both
    arms must fire on this one mutation.
    """
    entry = _entry(manifest, DRIFTED)
    emits = entry["expected"]["alsoEmits"]
    if "reconstructed-row-uncovered" not in emits:
        raise AssertionError(
            f"{DRIFTED} no longer pins reconstructed-row-uncovered, so this case "
            "reconstructs a drift that is not the one it names"
        )
    entry["expected"]["alsoEmits"] = sorted(
        c for c in emits if c != "reconstructed-row-uncovered"
    ) + ["caught-row-uncovered"]


def case_clause_deleted(manifest: dict[str, Any]) -> None:
    """The whole clause dropped, which is the state the corpus was in before.

    Two emitted codes go back to being declared nowhere. This is what an editor
    does when the clause looks like noise.
    """
    _entry(manifest, DRIFTED)["expected"].pop("alsoEmits")


def case_dead_pin_added(manifest: dict[str, Any]) -> None:
    """A code pinned as emitted that the rail does not emit.

    Correct-looking and still a refusal: a pin that describes nothing is a place
    the next real change hides, and it is the shape a copy-paste between rows
    produces.
    """
    _entry(manifest, DRIFTED)["expected"]["alsoEmits"] = ["vocabulary-missing"]


def case_vector_file_missing(manifest: dict[str, Any]) -> None:
    """A manifest row pointing at a file that is not there.

    An unreadable vector must never be counted as one whose emissions are
    pinned: that is the shape in which a check reports a clean result for work
    it did not do.
    """
    _entry(manifest, DRIFTED)["file"] = "reject/bad-817-not-on-disk.json"


def case_manifest_empty(manifest: dict[str, Any]) -> None:
    """No vectors at all. A gate with nothing to read has not passed."""
    manifest["vectors"] = []


def case_rail_emits_a_new_code(root: Path) -> None:
    """The rail itself grows a code, which is the drift the index cannot show.

    Every case above edits the manifest, so every one of them would be caught by
    a gate that only ever compared the manifest against itself. This one changes
    what the VERIFIER emits and leaves the corpus untouched, which is the half
    the corpus has no way to notice on its own.
    """

    def rewrite(before: str) -> str:
        if RAIL_ANCHOR not in before:
            raise AssertionError(
                "the rail's verify entry point no longer reads as this case "
                "expects, so the patch would apply nothing; re-anchor it"
            )
        return before.replace(RAIL_ANCHOR, RAIL_PATCHED, 1)

    _edit(root / RAIL_REL, rewrite)


CASES: list[tuple[str, Callable[[Path], None], Sequence[str]]] = [
    (
        "the drifted vector still pinned to its pre-move spelling",
        _manifest_case(case_pin_carries_the_old_spelling),
        ("reconstructed-row-uncovered", "no longer emits them"),
    ),
    (
        "the also-emits clause deleted outright",
        _manifest_case(case_clause_deleted),
        ("no field of its manifest entry names",),
    ),
    (
        "a pinned code the rail does not emit",
        _manifest_case(case_dead_pin_added),
        ("no longer emits them",),
    ),
    (
        "the reference rail grows a code the corpus never declared",
        case_rail_emits_a_new_code,
        ("synthetic-rail-drift",),
    ),
    (
        "a manifest row naming a vector that is not on disk",
        _manifest_case(case_vector_file_missing),
        ("is not on disk",),
    ),
    (
        "a manifest listing no vectors at all",
        _manifest_case(case_manifest_empty),
        ("the check did not run",),
    ),
]


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        root = _staged_copy(Path(td))
        rc, out = _run_gate(root)
        if rc != 0:
            print(
                f"CONTROL FAILED: the unmutated corpus exits {rc}\n{out}",
                file=sys.stderr,
            )
            return 1
        print("  control: unmutated corpus passes (rc=0)")

    for name, apply, phrases in CASES:
        with tempfile.TemporaryDirectory() as td:
            root = _staged_copy(Path(td))
            try:
                apply(root)
            except AssertionError as exc:
                failures.append(f"{name}: {exc}")
                continue
            rc, out = _run_gate(root)
            if rc == 0:
                failures.append(f"{name}: gate ACCEPTED the mutation (rc=0)")
                continue
            missing = [p for p in phrases if p not in out]
            if missing:
                failures.append(
                    f"{name}: gate failed but never said {missing!r}; a red run "
                    f"with the wrong reason is not the catch. Output:\n{out}"
                )
            else:
                print(f"  caught: {name}")

    if failures:
        print("\nFAIL: the gate did not catch every mutation.", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(
        f"\nOK: control passes and all {len(CASES)} mutations go red with a "
        "named reason."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
