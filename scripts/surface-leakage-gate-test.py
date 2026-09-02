#!/usr/bin/env python3
"""Tests for scripts/surface-leakage-gate.py.

A leakage measurement is the easiest kind of check to ship broken, because the
number it prints looks like evidence whichever way the code is wired. A gate
measuring nothing reports a low figure and passes. A gate measuring the labels it
was handed reports a high one and passes too, once the baseline is written from
the same broken run. Neither can be told from a working gate by reading its
output, so every case here breaks a staged copy of the corpus in one way and
requires the refusal.

Two of the cases carry most of the weight.

`a giveaway member on every reject vector` is the defect the gate exists for,
built by hand: it puts one member into every reject statement and nowhere else,
which is exactly what an accidentally leaky generator does. If that case does not
refuse, the gate is not measuring the corpus.

`de-leaking the identifiers retires their declaration` runs the fix the baseline
says is blocked -- it content-addresses every vector filename -- and requires the
gate to refuse the declarations that are now stale. It proves the ratchet turns
downward as well as upward, so slack a corpus no longer needs cannot be kept, and
it doubles as a live check that the figure recorded as the counterfactual is
reachable rather than asserted.

The two acceptance cases are the control. Without them every case here would be
satisfied by a gate that refuses everything, which is the same non-evidence in the
other direction.

Usage: python3 scripts/surface-leakage-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
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
GATE = REPO_ROOT / "scripts" / "surface-leakage-gate.py"
BASELINE_REL = "docs/SURFACE-LEAKAGE-BASELINE.json"
STAGED = ("vectors/", "vectors-ai-agent-action/", BASELINE_REL)

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    copied = 0
    for rel in listed.stdout.split():
        if not any(rel == p or rel.startswith(p) for p in STAGED):
            continue
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied += 1
    if copied < 2:
        raise SystemExit(
            f"test setup: staged {copied} file(s), so every case below would be "
            "asking the gate about an empty tree. Fix the case, never the gate."
        )


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def manifest(root: Path, corpus: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (root / corpus / "MANIFEST.json").read_text(encoding="utf-8")
    )
    return loaded


def write_manifest(root: Path, corpus: str, data: dict[str, Any]) -> None:
    (root / corpus / "MANIFEST.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )


def baseline(root: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (root / BASELINE_REL).read_text(encoding="utf-8")
    )
    return loaded


def write_baseline(root: Path, data: dict[str, Any]) -> None:
    (root / BASELINE_REL).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --- corpus mutations ------------------------------------------------------


def giveaway_member(root: Path) -> None:
    """One member, present on every reject statement and no accept one.

    The shape an accidentally leaky generator produces: a field added while
    building the invalid side and never added to the valid side. A rail could
    then answer the whole corpus by looking for it.
    """
    corpus = "vectors"
    touched = 0
    for entry in manifest(root, corpus)["vectors"]:
        if entry["kind"] != "reject":
            continue
        path = root / corpus / str(entry["file"])
        try:
            statement = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue  # the deliberately undecodable vectors stay undecodable
        if not isinstance(statement, dict):
            continue
        statement["_buildTag"] = "invalid-side"
        path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
        touched += 1
    if touched < 2:
        raise SystemExit("test setup: no reject statement was tagged.")


def giveaway_depth(root: Path) -> None:
    """Every reject statement nested one level deeper than every accept one.

    Aimed at the `shape` surface, which is under target today, so this case fails
    only if the gate is reading structure at all.
    """
    corpus = "vectors"
    touched = 0
    for entry in manifest(root, corpus)["vectors"]:
        if entry["kind"] != "reject":
            continue
        path = root / corpus / str(entry["file"])
        try:
            statement = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if not isinstance(statement, dict):
            continue
        statement["_pad"] = {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}
        path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
        touched += 1
    if touched < 2:
        raise SystemExit("test setup: no reject statement was padded.")


def content_address_identifiers(root: Path) -> None:
    """Run the fix the baseline records as blocked, and leave the rows behind.

    The fix is TWO changes and this case performs both, because performing only
    the first measures almost nothing. Content-addressing the filename while the
    file stays in `accept/` or `reject/` leaves the directory naming the label,
    and the whole-surface figure of the larger corpus moves by about two
    hundredths -- from near-certainty to near-certainty. So the vectors are also
    flattened into one directory per corpus, which is what actually removes the
    label from the path.
    """
    for corpus in ("vectors", "vectors-ai-agent-action"):
        data = manifest(root, corpus)
        for entry in data["vectors"]:
            source = root / corpus / str(entry["file"])
            if not source.is_file():
                continue
            digest = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
            new_rel = f"statements/v{digest}.json"
            (root / corpus / new_rel).parent.mkdir(parents=True, exist_ok=True)
            source.rename(root / corpus / new_rel)
            entry["file"] = new_rel
        write_manifest(root, corpus, data)


def one_more_reject_vector(root: Path) -> None:
    """The ordinary way this corpus grows: a parent, plus one mutation.

    A gate that refused here would refuse every future vector, so this is the
    case that keeps the whole file from being satisfiable by refusing everything.
    """
    corpus = "vectors"
    data = manifest(root, corpus)
    parent = next(e for e in data["vectors"] if e["kind"] == "accept")
    statement = json.loads(
        (root / corpus / str(parent["file"])).read_text(encoding="utf-8")
    )
    statement["predicate"]["result"] = "PASS"
    rel = "reject/bad-9990-example-added-by-a-test.json"
    (root / corpus / rel).write_text(
        json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    data["vectors"].append(
        {
            "id": "bad-9990-example-added-by-a-test",
            "kind": "reject",
            "file": rel,
            "conditions": ["aee-c-1"],
            "expected": {"verdict": "invalid", "codes": ["result-not-lowercase"]},
        }
    )
    write_manifest(root, corpus, data)


# --- baseline mutations ----------------------------------------------------


def surfaces_of(data: dict[str, Any], corpus: str) -> dict[str, Any]:
    rows: dict[str, Any] = data["corpora"][corpus]["surfaces"]
    return rows


def lower_a_recorded_figure(root: Path) -> None:
    data = baseline(root)
    surfaces_of(data, "vectors")["paths"]["separability"] = 0.30
    write_baseline(root, data)


def raise_a_recorded_figure(root: Path) -> None:
    data = baseline(root)
    surfaces_of(data, "vectors")["paths"]["separability"] = 0.90
    write_baseline(root, data)


def drop_a_blocker(root: Path) -> None:
    data = baseline(root)
    del surfaces_of(data, "vectors")["identifier"]["blockedBy"]
    write_baseline(root, data)


def declare_a_surface_inside_its_null(root: Path) -> None:
    """A blocker on a surface that shuffling the labels already explains."""
    data = baseline(root)
    surfaces_of(data, "vectors")["shape"]["blockedBy"] = "nothing at all"
    write_baseline(root, data)


def drop_a_surface_row(root: Path) -> None:
    data = baseline(root)
    del surfaces_of(data, "vectors")["lexicon"]
    write_baseline(root, data)


def sink_a_recorded_null(root: Path) -> None:
    """Pretend a surface's noise floor is lower than it is.

    The null is the threshold, so understating it turns ordinary sampling spread
    into a reported leak. This is the case that stops the null being a number
    somebody can quietly tune to make a corpus look dirty or clean.
    """
    data = baseline(root)
    surfaces_of(data, "vectors")["paths"]["null"] = 0.30
    write_baseline(root, data)


def move_the_fingerprint(root: Path) -> None:
    """Claim the null was calibrated over a corpus of a different shape.

    The class counts set the null's level, so a null carried across a change in
    them is a threshold describing some other corpus. Without this the gate would
    keep applying a stale noise floor after the corpus grew.
    """
    data = baseline(root)
    data["corpora"]["vectors"]["fingerprint"]["accept"] += 21
    write_baseline(root, data)


def remove_the_baseline(root: Path) -> None:
    (root / BASELINE_REL).unlink()


def sync_after_a_giveaway(root: Path) -> tuple[int, str]:
    """--sync must not be the way out of a refusal it just made.

    Run with the gate's own sync argument rather than through `run`, because the
    property under test is that the escape hatch refuses too. A gate whose fix
    command silently records the leak has a bypass with no diff behind it.
    """
    giveaway_member(root)
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root), "--sync"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


SYNC_CASES: list[tuple[str, Callable[[Path], tuple[int, str]], tuple[str, ...]]] = [
    (
        "--sync refuses to write down a leak it just refused",
        sync_after_a_giveaway,
        ("will not raise a figure",),
    ),
]

REFUSALS: list[Case] = [
    (
        "a giveaway member on every reject vector",
        giveaway_member,
        ("lexicon", "more predictable"),
    ),
    (
        "every reject vector nested one level deeper",
        giveaway_depth,
        ("shape", "more predictable"),
    ),
    (
        "de-leaking the identifiers retires their declaration",
        content_address_identifiers,
        ("identifier", "outlived its subject"),
    ),
    (
        "a recorded figure edited below what the corpus measures",
        lower_a_recorded_figure,
        ("more predictable",),
    ),
    (
        "a recorded figure holding slack the corpus does not need",
        raise_a_recorded_figure,
        ("--sync",),
    ),
    (
        "a surface outside its null with no blocker named",
        drop_a_blocker,
        ("outside its own null",),
    ),
    (
        "a surface inside its null still naming a blocker",
        declare_a_surface_inside_its_null,
        ("outlived its subject",),
    ),
    (
        "a recorded null edited below the corpus's real noise floor",
        sink_a_recorded_null,
        ("outside its own null",),
    ),
    (
        "a null calibrated over a corpus of another shape",
        move_the_fingerprint,
        ("describe a different corpus",),
    ),
    ("a surface the baseline records nothing for", drop_a_surface_row, ("records nothing",)),
    ("no baseline at all", remove_the_baseline, ("is absent",)),
]

ACCEPTANCES: list[Case] = [
    ("the corpus as it stands", lambda root: None, ()),
    ("one more reject vector, built the ordinary way", one_more_reject_vector, ()),
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
            failures.append(f"{name}: the gate accepted it:\n{output}")
            continue
        if not want_refusal and code != 0:
            failures.append(f"{name}: the gate refused it:\n{output}")
            continue
        missing = [phrase for phrase in phrases if phrase not in output]
        if missing:
            failures.append(
                f"{name}: the right exit status, and the output does not carry "
                f"{missing!r}. A refusal that names the wrong surface sends the next "
                f"person to the wrong corpus.\n{output}"
            )
    return failures


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("refuse", REFUSALS, True, tmp))
        failures.extend(check("accept", ACCEPTANCES, False, tmp))
        for index, (name, drive, phrases) in enumerate(SYNC_CASES):
            root = tmp / f"sync{index}"
            root.mkdir()
            stage(root)
            code, output = drive(root)
            if code == 0:
                failures.append(f"{name}: --sync accepted it:\n{output}")
            else:
                missing = [phrase for phrase in phrases if phrase not in output]
                if missing:
                    failures.append(f"{name}: the refusal omits {missing!r}\n{output}")
    total = len(REFUSALS) + len(ACCEPTANCES) + len(SYNC_CASES)
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS) + len(SYNC_CASES)} assert a "
        "refusal the gate makes and name the surface it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
