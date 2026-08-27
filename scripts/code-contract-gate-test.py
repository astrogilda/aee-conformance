#!/usr/bin/env python3
"""Tests for scripts/code-contract-gate.py.

Every case but two asserts a REFUSAL. That ratio is the point: this gate ran
green for the whole life of the corpus while a failure code named by an
indeterminate vector's declared reading -- a code the runner folds into that
vector's expected code set, and which a reader meets in the published
indeterminate index -- was outside its subject entirely. A code in no registry
at all could be written into the generator, regenerate byte-identically, replay
the whole corpus without a failure, and report every validity code as exercised
by the corpus and known to both rails on the way past. The gate was not wrong
about anything it looked at. It looked at two fields of a five-field schema.

So the cases here break one input at a time and require the exit code and the
sentence that names the break. The two acceptances are what stop the fix from
becoming a gate that refuses everything: the real repository must still pass,
and a manifest field that carries no codes must not be mistaken for one that
does.

Each case runs the real gate against COPIES of its three inputs -- the manifest,
the enumerated code set, and the Python rail whose vocabulary must match it.
Copies of the real files rather than fixtures, because a fixture corpus would
say nothing about whether the gate is pointed at this one.

Usage: python3 scripts/code-contract-gate-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "code-contract-gate.py"
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
CODES_GO = REPO_ROOT / "aee" / "codes.go"
PY_RAIL = REPO_ROOT / "packaging" / "run_vectors.py"

# A token no registry can hold and no rail can emit. Spelled as a near-miss of a
# real code because that is how the defect arrives: not as an invention, but as
# `record-undecodeable` beside `record-undecodable` in a generator argument.
FOREIGN = "record-undecodeable"

Mutation = Callable[[Path, Path, Path], None]
Case = tuple[str, Mutation, bool, tuple[str, ...]]


def run_gate(manifest: Path, codes: Path, rail: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--manifest", str(manifest),
         "--codes", str(codes), "--rail", str(rail)],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def dump(path: Path, obj: dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _first(manifest: dict[str, Any], kind: str) -> dict[str, Any]:
    for vector in manifest["vectors"]:
        entry: dict[str, Any] = vector
        if entry["kind"] == kind:
            return entry
    raise SystemExit(
        f"code-contract-gate-test: the manifest ships no {kind} vector, so a "
        f"case that plants its fault on one cannot run. A case that could not "
        "run is not a case that passed.")


# --------------------------------------------------------------------- cases

def untouched(_m: Path, _c: Path, _r: Path) -> None:
    """The real corpus, unmodified. The one case that must pass outright."""


def foreign_code_in_a_reading(manifest: Path, _c: Path, _r: Path) -> None:
    """The defect this gate was blind to, planted where it was blind.

    An indeterminate vector declares, per reading, the code a rail applying that
    reading reports. The runner treats each of those values as a failure code.
    This gate did not, so a value naming nothing was a published claim about
    what a conforming rail may answer, resolvable against no registry.
    """
    data = load(manifest)
    entry = _first(data, "indeterminate")
    readings = dict(entry["expected"]["readings"])
    readings[sorted(readings)[0]] = FOREIGN
    entry["expected"]["readings"] = readings
    dump(manifest, data)


def foreign_code_in_a_declared_set(manifest: Path, _c: Path, _r: Path) -> None:
    """The same token in the field the gate always read.

    The control for the case above: same token, same manifest, same read, one
    field to the left. If this refuses and that one does not, the difference is
    the subject and not the check.
    """
    data = load(manifest)
    _first(data, "reject")["expected"]["codes"].append(FOREIGN)
    dump(manifest, data)


def unclassified_expected_field(manifest: Path, _c: Path, _r: Path) -> None:
    """A field the gate's schema split does not name.

    Not a defect in itself -- it is how the readings hole opened. A field the
    gate cannot classify may or may not carry codes, and guessing that it does
    not is what left one outside the subject for the life of the corpus.
    """
    data = load(manifest)
    _first(data, "reject")["expected"]["alsoRejectsUnder"] = [FOREIGN]
    dump(manifest, data)


def code_bearing_fields() -> tuple[str, ...]:
    """The code-bearing manifest fields, read off the gate rather than listed.

    Listed, this went stale the moment a field was added: the case below emptied
    `codes`, `alsoCarries` and `readings`, `alsoEmits` arrived, and the corpus
    the case handed the gate still named plenty of codes -- so the gate refused
    for a different reason, the case's phrase never appeared, and a mutation
    proof reported a miss where the gate was working correctly. Deriving the
    list means a field added to the gate is emptied here without anybody
    remembering to.
    """
    spec = importlib.util.spec_from_file_location("code_contract_gate", GATE)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {GATE} to read its field classification")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fields: tuple[str, ...] = tuple(module.CODE_LIST_FIELDS) + tuple(module.CODE_MAP_FIELDS)
    if not fields:
        raise AssertionError(
            f"{GATE} classifies no code-bearing field, so this case empties nothing")
    return fields


def no_codes_anywhere(manifest: Path, _c: Path, _r: Path) -> None:
    """Every code-bearing field emptied.

    A membership check over an empty subject holds vacuously, and an emptied
    corpus and a renamed field read identically from here.
    """
    data = load(manifest)
    fields = code_bearing_fields()
    for vector in data["vectors"]:
        expected = vector.get("expected") or {}
        for field in fields:
            expected.pop(field, None)
    dump(manifest, data)


def rail_forgets_a_code(_m: Path, _c: Path, rail: Path) -> None:
    """Drop one validity code from the Python rail's vocabulary.

    The two first-party rails must carry one vocabulary rather than two that
    happen to agree today.
    """
    text = rail.read_text(encoding="utf-8")
    rail.write_text(text.replace('"refs-empty"', '"refs-empty-renamed"'),
                    encoding="utf-8")


def rail_mentions_a_code_only_in_prose(_m: Path, _c: Path, rail: Path) -> None:
    """Leave the code in a comment and take it out of the rail's values.

    The vocabulary check used to scan the rail's text for a quoted token, which
    a docstring satisfies as readily as an implementation. Reading the parsed
    module instead is what makes the check about what the rail does.
    """
    text = rail.read_text(encoding="utf-8")
    rail.write_text(
        text.replace('"refs-empty"', '"refs-empty-renamed"')
        + '\n# the rail no longer emits "refs-empty" and only says so here\n',
        encoding="utf-8")


def policy_heading_reworded(_m: Path, codes: Path, _r: Path) -> None:
    """Reword the heading that separates the two code classes.

    With the heading gone the consumer-policy codes read as validity codes, and
    the reverse-direction check would then demand a vector for each of them.
    """
    text = codes.read_text(encoding="utf-8")
    codes.write_text(text.replace("Consumer-policy stage codes",
                                  "Codes for the admission stage"),
                     encoding="utf-8")


def non_code_field_added(manifest: Path, _c: Path, _r: Path) -> None:
    """A classified field that carries no codes must not be read as one.

    The acceptance that keeps the closed classification honest: `family` names a
    grouping and not a condition, and a fix that treated every string under
    `expected` as a code would refuse the corpus it ships with.
    """
    data = load(manifest)
    entry = _first(data, "indeterminate")
    entry["expected"]["family"] = "a-family-name-that-is-not-a-failure-code"
    dump(manifest, data)


CASES: list[Case] = [
    ("the real corpus", untouched, True, ("known to both rails",)),
    ("a code named only by a declared reading", foreign_code_in_a_reading,
     False, (FOREIGN, "absent from")),
    ("the same code in a declared code set", foreign_code_in_a_declared_set,
     False, (FOREIGN, "absent from")),
    ("an `expected` field the gate does not classify",
     unclassified_expected_field, False, ("does not classify",)),
    ("a corpus naming no failure codes at all", no_codes_anywhere, False,
     ("names no failure codes at all",)),
    ("a validity code the Python rail no longer carries", rail_forgets_a_code,
     False, ("no longer share one vocabulary",)),
    ("a validity code the rail mentions only in prose",
     rail_mentions_a_code_only_in_prose, False,
     ("no longer share one vocabulary",)),
    ("the consumer-policy heading reworded away", policy_heading_reworded,
     False, ("did not yield both code classes",)),
    ("a classified field that carries no code", non_code_field_added, True,
     ("known to both rails",)),
]


def main() -> int:
    for path in (GATE, MANIFEST, CODES_GO, PY_RAIL):
        if not path.is_file():
            print(f"missing input: {path}", file=sys.stderr)
            return 1

    failures: list[str] = []
    for name, mutate, want_pass, expect in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "MANIFEST.json"
            codes = root / "codes.go"
            rail = root / "run_vectors.py"
            shutil.copy2(MANIFEST, manifest)
            shutil.copy2(CODES_GO, codes)
            shutil.copy2(PY_RAIL, rail)
            mutate(manifest, codes, rail)
            code, output = run_gate(manifest, codes, rail)
            if (code == 0) != want_pass:
                failures.append(
                    f"{name}: expected {'pass' if want_pass else 'fail'}, "
                    f"got exit {code}\n{output}")
                continue
            for fragment in expect:
                if fragment not in output:
                    failures.append(
                        f"{name}: output does not name the fault "
                        f"({fragment!r})\n{output}")
            print(f"  ok  {name}")

    if failures:
        print(f"\nFAIL: {len(failures)} case(s)", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    refusals = sum(1 for case in CASES if not case[2])
    print(f"\nall {len(CASES)} cases hold ({refusals} assert a refusal)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
