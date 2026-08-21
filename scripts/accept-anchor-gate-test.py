#!/usr/bin/env python3
"""Tests for scripts/accept-anchor-gate.py.

Almost every case asserts a REFUSAL, and one asserts an acceptance. The
refusals matter because the failure this gate exists to catch -- a corpus of
refusals with nothing that must be accepted -- looks exactly like a healthy
corpus from the pass/fail line alone, and a gate that could not go red would
be one more green check enforcing nothing. The acceptance matters because a
gate that refuses every input is the same defect one level up: it would be a
reject-everything rail sitting in the scripts directory, which is the thing
under test.

Each case runs the real gate against COPIES of its four real inputs -- the
manifest, the reject index, the baseline and the document publishing the two
figures -- with one of them broken in exactly one way. Copies of the real files
rather than fixtures, because a fixture manifest would fail every case for the
wrong reason and a green fixture run would say nothing about whether the gate is
pointed at the corpus.

Usage: python3 scripts/accept-anchor-gate-test.py
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
GATE = REPO_ROOT / "scripts" / "accept-anchor-gate.py"
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
REJECT_INDEX = REPO_ROOT / "vectors" / "reject" / "INDEX.md"
BASELINE = REPO_ROOT / "docs" / "ACCEPT-ANCHOR-BASELINE.json"
CHANGES = REPO_ROOT / "vectors" / "CHANGES.md"

Mutation = Callable[[Path, Path, Path, Path], None]
Case = tuple[str, Mutation, bool, tuple[str, ...]]


def run_gate(manifest: Path, index: Path, baseline: Path,
             changes: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--manifest", str(manifest),
         "--reject-index", str(index), "--baseline", str(baseline),
         "--changes", str(changes)],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def dump(path: Path, obj: dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


# --------------------------------------------------------------------- cases

def untouched(_m: Path, _i: Path, _b: Path, _c: Path) -> None:
    """The real corpus, unmodified. The one case that must pass."""


def parent_not_shipped(_m: Path, index: Path, _b: Path, _c: Path) -> None:
    """Repoint one reject vector at a parent no accept vector carries.

    This is the shape the check exists for: the refusal ships and the accepted
    half of its pair does not, so a rail that refuses the whole shape satisfies
    it and nothing in the corpus notices.
    """
    text = index.read_text(encoding="utf-8")
    text = re.sub(r"^(\| `bad-001[^|]*\|)([^|]*)\|",
                  r"\1 ok-899 |", text, count=1, flags=re.M)
    index.write_text(text, encoding="utf-8")


def parent_names_a_vector_that_was_never_shipped(
        _m: Path, index: Path, _b: Path, _c: Path) -> None:
    """Declare a parent whose number is real and whose id is not.

    The shape check 1 accepted for the life of this gate. A parent used to be
    resolved on the number its opening characters spelled, so `ok-002-...`
    followed by anything at all resolved to `ok-002` and passed while naming a
    vector no reader can open. The claim the check publishes is that the refusal
    ships beside the accept vector it names, and a string that names nothing
    satisfied it.
    """
    text = index.read_text(encoding="utf-8")
    text = re.sub(r"^(\| `bad-001[^|]*\|)([^|]*)\|",
                  r"\1 ok-002-a-vector-that-was-never-shipped |",
                  text, count=1, flags=re.M)
    index.write_text(text, encoding="utf-8")


def parent_number_with_trailing_junk(_m: Path, index: Path, _b: Path,
                                     _c: Path) -> None:
    """The same defect with no separator, so a prefix match cannot see it."""
    text = index.read_text(encoding="utf-8")
    text = re.sub(r"^(\| `bad-001[^|]*\|)([^|]*)\|", r"\1 ok-002xyz |",
                  text, count=1, flags=re.M)
    index.write_text(text, encoding="utf-8")


def parent_given_as_the_full_id(manifest: Path, index: Path, _b: Path,
                                _c: Path) -> None:
    """An over-reach control: the full accept id is a legitimate citation.

    Every row in the corpus today names its parent by number. Naming it by its
    whole id resolves to the same shipped vector and must keep passing, or the
    anchoring above would be a fix that starts refusing correct input -- and a
    gate that does that is switched off within a day.
    """
    data = load(manifest)
    full = next(v["id"] for v in data["vectors"]
                if v["kind"] == "accept" and v["id"].startswith("ok-002"))
    text = index.read_text(encoding="utf-8")
    text = re.sub(r"^(\| `bad-001[^|]*\|)([^|]*)\|", rf"\1 {full} |",
                  text, count=1, flags=re.M)
    index.write_text(text, encoding="utf-8")


def index_row_for_a_refusal_nobody_ships(_m: Path, index: Path, _b: Path,
                                         _c: Path) -> None:
    """Add an index row naming a reject vector the manifest does not carry.

    Check 1 ran in one direction only: every manifest refusal had a row. A row
    with no refusal behind it was invisible, and it is the same defect the
    condition registry refuses in both directions -- a table advertising a pair
    the corpus has not got.
    """
    text = index.read_text(encoding="utf-8")
    ghost = ("| `bad-999-a-refusal-that-is-not-in-the-manifest` | ok-002 | "
             "nothing | - | aee-c-1 | `result-vocabulary` | L435 |\n")
    index.write_text(re.sub(r"^\| `bad-001", ghost + "| `bad-001", text,
                            count=1, flags=re.M), encoding="utf-8")


def accept_vectors_share_a_number(manifest: Path, _i: Path, _b: Path,
                                  _c: Path) -> None:
    """Two accept vectors under one number, so a parent citing it names neither."""
    data = load(manifest)
    victim = next(v for v in data["vectors"]
                  if v["kind"] == "accept" and not v["id"].startswith("ok-002"))
    victim["id"] = "ok-002-a-second-vector-under-one-number"
    dump(manifest, data)


def baseline_emptied(_m: Path, _i: Path, baseline: Path, _c: Path) -> None:
    """A baseline that has lost the key the ratchet reads.

    An absent baseline was already refused, on the reasoning that an empty one
    would be a claim and an absent one records nothing. A present one that has
    been emptied got neither treatment: the held set came back empty, every
    condition was held to nothing, and the gate printed the OK line it prints
    over a real baseline.
    """
    baseline.write_text("{}\n", encoding="utf-8")


def baseline_anchored_list_emptied(_m: Path, _i: Path, baseline: Path,
                                   _c: Path) -> None:
    """The key is there and the list under it is not."""
    dump(baseline, {"anchored": [], "unanchored": []})


def parent_row_missing(_m: Path, index: Path, _b: Path, _c: Path) -> None:
    """Delete one reject vector's index row while it stays in the manifest."""
    kept = [ln for ln in index.read_text(encoding="utf-8").splitlines()
            if not ln.startswith("| `bad-001")]
    index.write_text("\n".join(kept) + "\n", encoding="utf-8")


def anchor_citation_dropped(manifest: Path, _i: Path, _b: Path,
                            _c: Path) -> None:
    """Strip an anchored condition from every accepting vector that cites it.

    The regression the ratchet is for: the reject vector still cites the rule,
    the accept vector that showed its satisfied side no longer does, and the
    count moves in the direction a reader would never see.
    """
    data = load(manifest)
    baseline = load(BASELINE)
    target = baseline["anchored"][0]
    for v in data["vectors"]:
        if v["kind"] != "reject" and target in v.get("conditions", []):
            v["conditions"] = [c for c in v["conditions"] if c != target]
    dump(manifest, data)


def manifest_has_no_vectors(manifest: Path, _i: Path, _b: Path,
                            _c: Path) -> None:
    """An input that yields nothing must fail rather than pass vacuously."""
    dump(manifest, {"vectors": []})


def index_table_renamed(_m: Path, index: Path, _b: Path, _c: Path) -> None:
    """A parse that sees no rows reports every anchor present. Refuse it.

    Every row has to break, and the break is keyed on the row's SHAPE rather
    than on an id prefix. This rewrote the literal ``| `bad-``, which was every
    row for as long as every refusal was named ``bad-NNN``. It stopped being
    every row when ``vate-`` refusals shipped: three rows survived, the parse
    returned them instead of nothing, the guard under test never fired, and the
    gate answered with the missing anchors of the rows that had been broken --
    a refusal, so the case still looked like a refusal, but not this one's. A
    case that asserts a specific fault has to reach that fault, and keying on
    the shape means the next id prefix cannot quietly walk out from under it.
    """
    text = index.read_text(encoding="utf-8")
    index.write_text(
        re.sub(r"^\|\s*`([^`]+)`", r"| BROKEN \1", text, flags=re.MULTILINE),
        encoding="utf-8",
    )


def baseline_absent(_m: Path, _i: Path, baseline: Path, _c: Path) -> None:
    """A missing baseline is not an empty one."""
    baseline.unlink()


def published_figure_stale(_m: Path, _i: Path, _b: Path,
                           changes: Path) -> None:
    """Leave the prose quoting a traceability figure the corpus outgrew.

    The census does not read this span because it records this gate as its
    owner, so if the owner does not read it either the number is published with
    nothing behind it at all.

    The drift is applied by incrementing whatever the prose currently says,
    rather than by writing a chosen pair of numbers here. A literal ratio typed
    into a test is a count-shaped integer like any other, and it would have to
    be accounted for by the very census this case exists to backstop.
    """
    pattern = re.compile(r"(That second number is )(\d+)( of \d+ today,)")

    def drift(m: re.Match[str]) -> str:
        return f"{m.group(1)}{int(m.group(2)) + 1}{m.group(3)}"

    text = changes.read_text(encoding="utf-8")
    mutated, count = pattern.subn(drift, text, count=1)
    if count != 1:
        raise SystemExit(
            "accept-anchor-gate-test: vectors/CHANGES.md no longer carries the "
            "traceability sentence, so this case cannot plant its fault. A "
            "case that could not run is not a case that passed.")
    changes.write_text(mutated, encoding="utf-8")


def published_sentence_reworded(_m: Path, _i: Path, _b: Path,
                                changes: Path) -> None:
    """Reword the sentence away entirely.

    A claim nobody can find must fail like a stale one. Silently dropping the
    check when the prose moves is how a delegation turns into an exemption.
    """
    text = changes.read_text(encoding="utf-8")
    changes.write_text(
        text.replace("reject vectors declare a parent",
                     "refusals name an origin"),
        encoding="utf-8")


CASES: list[Case] = [
    ("the real corpus", untouched, True, ()),
    ("a reject vector whose parent ships nowhere", parent_not_shipped, False,
     ("not a shipped",)),
    ("a parent whose number is real and whose id is not",
     parent_names_a_vector_that_was_never_shipped, False, ("not a shipped",)),
    ("a parent that is a shipped number with junk after it",
     parent_number_with_trailing_junk, False, ("not a shipped",)),
    ("a parent named by its whole id", parent_given_as_the_full_id, True, ()),
    ("an index row for a refusal the manifest does not ship",
     index_row_for_a_refusal_nobody_ships, False, ("does not ship",)),
    ("two accept vectors under one number", accept_vectors_share_a_number,
     False, ("share the number",)),
    ("a baseline that has lost its anchored list", baseline_emptied, False,
     ("carries no `anchored` list",)),
    ("a baseline recording nothing as anchored",
     baseline_anchored_list_emptied, False, ("records no anchored condition",)),
    ("a reject vector with no index row", parent_row_missing, False,
     ("has no row in the reject index",)),
    ("an anchored condition dropped from the accept side",
     anchor_citation_dropped, False, ("was anchored",)),
    ("a manifest listing no vectors", manifest_has_no_vectors, False,
     ("lists no vectors",)),
    ("a reject index whose vector table no longer parses", index_table_renamed,
     False, ("yielded no vector rows",)),
    ("a baseline that does not exist", baseline_absent, False,
     ("no accept-anchor baseline",)),
    ("prose quoting a traceability figure the corpus outgrew",
     published_figure_stale, False, ("the measurement is",)),
    ("prose that no longer contains the sentence at all",
     published_sentence_reworded, False, ("gone or reworded",)),
]


def main() -> int:
    for path in (GATE, MANIFEST, REJECT_INDEX, BASELINE, CHANGES):
        if not path.is_file():
            print(f"missing input: {path}", file=sys.stderr)
            return 1

    failures: list[str] = []
    for name, mutate, want_pass, expect in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "MANIFEST.json"
            index = root / "INDEX.md"
            baseline = root / "BASELINE.json"
            changes = root / "CHANGES.md"
            shutil.copy2(MANIFEST, manifest)
            shutil.copy2(REJECT_INDEX, index)
            shutil.copy2(BASELINE, baseline)
            shutil.copy2(CHANGES, changes)
            mutate(manifest, index, baseline, changes)
            code, output = run_gate(manifest, index, baseline, changes)
            passed = code == 0
            if passed != want_pass:
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
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"\nall {len(CASES)} cases hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
