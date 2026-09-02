#!/usr/bin/env python3
"""Surface-leakage gate: a conformance corpus may not be scoreable without the
specification.

The question, and why it is worth a gate
----------------------------------------

Every other check in this directory asks whether a particular vector forces a
particular rule. None of them asks the question a corpus can fail as a whole:
CAN A CONSUMER GET THE ANSWERS RIGHT WITHOUT IMPLEMENTING ANYTHING? If the label
of a vector is predictable from its surface -- what it is called, how long it is,
which members it happens to carry -- then a rail can post a good score while
having read the specification not at all, and every figure this suite publishes
about that rail means less than it appears to.

The surface is measured rather than argued about. A cheap classifier is trained
on features drawn from the corpus and asked to predict accept-or-reject, and the
figure reported is the area under its ROC curve out of sample. Chance is 0.5. The
target here is 0.55, which is close enough to chance that a rail scoring on
surface alone would gain almost nothing, and far enough from it that a real
regularity shows up.

That figure is a property of the CORPUS, not of any rail, which is what makes it
worth having: it generalises across every corpus this repository ships and across
every corpus it ever will, and it goes red for a leak nobody has thought of yet.
The two specific defects that motivated it -- an identifier namespace that names
the answer, and two differently-labelled vectors decoding to one statement -- are
each closed by their own check. This one is quantified over the whole surface, so
it does not need to be told what to look for.

What counts as the surface
--------------------------

Five groups, kept separate so a refusal names which one leaks rather than
reporting one number nobody can act on.

  identifier  the tokens of the vector's own name. This is where the largest leak
              in this repository lives and it is not subtle: identifiers carry an
              `ok-`/`bad-` prefix, so the name alone is very nearly the label.
  file        byte length and line count, bucketed. Reading a file's size is not
              reading the file.
  shape       node count, maximum depth, member count, and whether the file
              decodes at all.
  paths       the set of member paths present, with array positions collapsed.
              A vector that drops a required member is visible here.
  lexicon     member names and short string values. This is where a marker value
              or a giveaway field name would show up.

None of the five requires knowing what the predicate MEANS, which is the whole
point: everything measured here is available to a consumer who has not read the
specification, so a figure well above chance says the specification is optional.

How it is measured, and why this estimator
------------------------------------------

Bernoulli naive Bayes with Laplace smoothing, scored under stratified five-fold
cross-validation, averaged over a fixed list of seeds. Each choice is answering a
way the measurement could lie.

Cross-validated, because an in-sample classifier memorises a few hundred vectors
perfectly and reports a leak that does not exist. Out of fold, a feature seen in
one vector helps with nothing.

Averaged over a list of seeds rather than measured at one, because a single fold
split moves the figure by several hundredths on a corpus this size, which would
put the choice of seed in charge of whether the gate passes. The seeds are
literal constants, so the estimator is deterministic: same corpus, same number,
every run, on every machine, with no network and nothing to install.

Naive Bayes rather than anything fitted iteratively, because it trains by
counting. The whole measurement is a few seconds, and a gate slow enough to be
worth skipping is a gate that gets skipped.

The figure the gate compares is SEPARABILITY, `max(auc, 1 - auc)`, and not the
AUC. A classifier that is reliably wrong is a classifier: invert it and it is
reliably right. Reporting the AUC alone would let a corpus leak in the one
direction the threshold cannot see.

Baseline, target, and why both
------------------------------

`docs/SURFACE-LEAKAGE-BASELINE.json` records what each surface of each corpus
currently measures, and the gate refuses on two different things.

A measurement ABOVE ITS OWN BASELINE is a new leak, and it fails whether or not
the surface was already over target. This is the half that works today: it holds
every surface at the level it has reached and makes any corpus change that adds
predictability fail on the change that added it.

A measurement above TARGET must additionally be declared in the baseline with the
constraint that blocks it, and the reasons are recorded there rather than here. A
declaration is not a permanent allowance: when a surface comes under target the
declaration is stale and the gate refuses until it is removed, so the ratchet
turns in both directions and slack that is no longer needed cannot be kept.

`--sync` re-records what is measured and will LOWER a figure, never raise one. A
sync that adopted whatever it found would be this gate's own bypass -- the refusal
names the surface, and one command would write the leak down rather than remove
it. Recording a rise means editing the file by hand and putting the reason beside
it, which leaves a diff somebody reviews.

Usage:
    python3 scripts/surface-leakage-gate.py
    python3 scripts/surface-leakage-gate.py --report   (every figure, no refusal)
    python3 scripts/surface-leakage-gate.py --sync     (rewrite the baseline)
    python3 scripts/surface-leakage-gate.py --root <tree>   (for its own tests)
Exit 0 when no surface has gained predictability and every over-target surface is
declared; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_REL = "docs/SURFACE-LEAKAGE-BASELINE.json"

CORPORA = ("vectors", "vectors-ai-agent-action")

SURFACES = ("identifier", "file", "shape", "paths", "lexicon", "all")

# Chance is 0.5. A corpus at or under this is one a rail cannot score on surface
# alone to any useful degree.
TARGET = 0.55

# The estimator is deterministic, so this band is not measurement noise: it is
# how much a legitimate corpus edit may move a figure before somebody has to look
# at it. Small enough that adding a family of vectors that all share a giveaway
# is caught; large enough that adding one vector is not a gate failure.
TOLERANCE = 0.02

# Literal constants, which is what makes the whole measurement reproducible.
FOLD_SEEDS = (11, 22, 33, 44, 55, 66, 77, 88, 99, 110)
FOLDS = 5


# --- features --------------------------------------------------------------


def bucket(n: int) -> int:
    return int(math.log2(n)) if n > 0 else -1


class Walked:
    """What one pass over a decoded statement collects.

    Array positions collapse to `[]` deliberately. A path carrying an index
    describes where a member sits in one particular vector, so indexed paths
    would make almost every vector unique and the paths surface would measure
    nothing but its own resolution.
    """

    def __init__(self) -> None:
        self.nodes = 0
        self.depth = 0
        self.names: set[str] = set()
        self.paths: set[str] = set()
        self.strings: set[str] = set()

    def walk(self, value: Any, path: str, depth: int) -> None:
        self.nodes += 1
        self.depth = max(self.depth, depth)
        if isinstance(value, dict):
            for key, child in value.items():
                self.names.add(key)
                self.walk(child, f"{path}/{key}", depth + 1)
        elif isinstance(value, list):
            for child in value:
                self.walk(child, f"{path}/[]", depth + 1)
        else:
            self.paths.add(path)
            # A long string is a payload or a digest: unique to its vector, so it
            # is never seen in training and contributes nothing out of fold.
            if isinstance(value, str) and len(value) <= 64:
                self.strings.add(value)


def features(stem: str, raw: bytes) -> dict[str, set[str]]:
    """Every surface of one vector, as sets of binary feature names."""
    lines = raw.count(b"\n") + 1
    groups: dict[str, set[str]] = {
        "identifier": {
            f"id.tok={t}" for t in stem.replace("_", "-").lower().split("-") if t
        },
        "file": {
            f"file.bytes={bucket(len(raw))}",
            f"file.lines={bucket(lines)}",
        },
    }
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        # Not decoding is itself a surface fact, and the only one available.
        groups["shape"] = {"shape.undecodable"}
        groups["paths"] = set()
        groups["lexicon"] = set()
        return groups
    seen = Walked()
    seen.walk(decoded, "", 0)
    groups["shape"] = {
        f"shape.nodes={bucket(seen.nodes)}",
        f"shape.depth={seen.depth}",
        f"shape.names={bucket(len(seen.names))}",
    }
    groups["paths"] = {f"path={p}" for p in seen.paths}
    groups["lexicon"] = {f"name={n}" for n in seen.names} | {
        f"str={s}" for s in seen.strings
    }
    return groups


# --- estimator -------------------------------------------------------------


def auc(labelled: list[tuple[int, float]]) -> float:
    """Area under the ROC curve, by the rank statistic, ties averaged."""
    positives = sum(1 for y, _ in labelled if y == 1)
    negatives = len(labelled) - positives
    if positives == 0 or negatives == 0:
        return float("nan")
    ordered = sorted(labelled, key=lambda t: t[1])
    rank_sum = 0.0
    index = 0
    rank = 1
    while index < len(ordered):
        last = index
        while last + 1 < len(ordered) and ordered[last + 1][1] == ordered[index][1]:
            last += 1
        average = (rank + rank + (last - index)) / 2
        for position in range(index, last + 1):
            if ordered[position][0] == 1:
                rank_sum += average
        rank += last - index + 1
        index = last + 1
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def score_fold(
    train: list[tuple[int, frozenset[str]]], test: list[tuple[int, frozenset[str]]]
) -> list[float]:
    counts: list[dict[str, int]] = [defaultdict(int), defaultdict(int)]
    totals = [0, 0]
    for label, feats in train:
        totals[label] += 1
        for name in feats:
            counts[label][name] += 1
    prior = math.log((totals[1] + 1) / (totals[0] + 1))
    scores = []
    for _, feats in test:
        value = prior
        for name in feats:
            seen = counts[1][name] + counts[0][name]
            if seen == 0:
                continue  # never observed in training: says nothing out of fold
            value += math.log(
                ((counts[1][name] + 1) / (totals[1] + 2))
                / ((counts[0][name] + 1) / (totals[0] + 2))
            )
        scores.append(value)
    return scores


def cross_validated_auc(rows: list[tuple[int, frozenset[str]]], seed: int) -> float:
    by_label: dict[int, list[tuple[int, frozenset[str]]]] = {0: [], 1: []}
    for row in rows:
        by_label[row[0]].append(row)
    rng = random.Random(seed)
    folds: list[list[tuple[int, frozenset[str]]]] = [[] for _ in range(FOLDS)]
    for label in (0, 1):
        members = by_label[label][:]
        rng.shuffle(members)
        for position, row in enumerate(members):
            folds[position % FOLDS].append(row)
    labelled: list[tuple[int, float]] = []
    for index in range(FOLDS):
        test = folds[index]
        train = [r for other in range(FOLDS) if other != index for r in folds[other]]
        if not test or not train:
            continue
        for row, value in zip(test, score_fold(train, test), strict=True):
            labelled.append((row[0], value))
    return auc(labelled)


def separability(rows: list[tuple[int, frozenset[str]]]) -> float:
    """How far from chance the surface is, in whichever direction it leans.

    A classifier that is reliably wrong is a classifier inverted, so the distance
    from 0.5 is the quantity a consumer could exploit, not the AUC itself.
    """
    measured = [cross_validated_auc(rows, seed) for seed in FOLD_SEEDS]
    mean = sum(measured) / len(measured)
    return round(max(mean, 1.0 - mean), 4)


# --- corpus ----------------------------------------------------------------


def load(tree: Path, corpus: str) -> list[tuple[int, dict[str, set[str]]]]:
    base = tree / corpus
    manifest = json.loads((base / "MANIFEST.json").read_text(encoding="utf-8"))
    rows: list[tuple[int, dict[str, set[str]]]] = []
    for entry in manifest["vectors"]:
        kind = str(entry.get("kind"))
        if kind not in ("accept", "reject"):
            continue  # an indeterminate vector carries no binary label to predict
        path = base / str(entry["file"])
        stem = path.stem
        rows.append((1 if kind == "reject" else 0, features(stem, path.read_bytes())))
    return rows


def measure(tree: Path) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for corpus in CORPORA:
        rows = load(tree, corpus)
        per_surface: dict[str, float] = {}
        for surface in SURFACES:
            if surface == "all":
                selected = [g for g in SURFACES if g != "all"]
            else:
                selected = [surface]
            prepared = [
                (label, frozenset().union(*(groups[g] for g in selected)))
                for label, groups in rows
            ]
            per_surface[surface] = separability(prepared)
        out[corpus] = per_surface
    return out


# --- gate ------------------------------------------------------------------


def read_baseline(tree: Path) -> dict[str, Any]:
    path = tree / BASELINE_REL
    if not path.is_file():
        return {}
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def judge(measured: dict[str, dict[str, float]], baseline: dict[str, Any]) -> list[str]:
    recorded = baseline.get("surfaces", {})
    problems: list[str] = []
    for corpus, per_surface in measured.items():
        for surface, value in per_surface.items():
            row = recorded.get(corpus, {}).get(surface)
            if row is None:
                problems.append(
                    f"{corpus}/{surface} measures {value:.4f} and the baseline "
                    "records nothing for it. A surface with no recorded figure is "
                    "a surface nothing is holding, so it is refused rather than "
                    "adopted at whatever it happens to be today."
                )
                continue
            was = float(row.get("separability", 0.0))
            blocked = str(row.get("blockedBy", "")).strip()
            if value > was + TOLERANCE:
                problems.append(
                    f"{corpus}/{surface} measures {value:.4f}, up from {was:.4f}. "
                    "Something in this change made the label more predictable from "
                    "the surface than it was, which is a rail scoring without "
                    "reading the specification."
                )
            if value > TARGET and not blocked:
                problems.append(
                    f"{corpus}/{surface} measures {value:.4f}, over the {TARGET} "
                    "target, and declares no constraint blocking it. Fix the leak, "
                    "or record what stops it being fixed."
                )
            if value <= TARGET and blocked:
                problems.append(
                    f"{corpus}/{surface} measures {value:.4f}, at or under the "
                    f"{TARGET} target, while still declaring {blocked!r} as its "
                    "blocker. The declaration has outlived its subject; remove it."
                )
            if was > value + TOLERANCE:
                problems.append(
                    f"{corpus}/{surface} measures {value:.4f} against a recorded "
                    f"{was:.4f}. The baseline is holding slack the corpus no longer "
                    "needs; re-record it with --sync so the ratchet keeps its grip."
                )
    return problems


def render(measured: dict[str, dict[str, float]], baseline: dict[str, Any]) -> str:
    recorded = baseline.get("surfaces", {})
    lines = []
    for corpus, per_surface in measured.items():
        lines.append(f"  {corpus}")
        for surface in SURFACES:
            value = per_surface[surface]
            row = recorded.get(corpus, {}).get(surface, {})
            note = ""
            if row.get("blockedBy"):
                note = f"  blocked by {row['blockedBy']}"
            flag = "  OVER TARGET" if value > TARGET else ""
            lines.append(f"    {surface:12s} {value:.4f}{flag}{note}")
    return "\n".join(lines)


def sync(tree: Path, measured: dict[str, dict[str, float]]) -> list[str]:
    """Re-record the baseline. It may lower a figure and it may not raise one.

    A sync that adopted whatever it measured would be the gate's own bypass: the
    refusal names the surface, the fix is one command away, and the command
    writes down the leak instead of removing it. So a rise beyond tolerance is
    refused here as well, and the only way to record one is to edit the file by
    hand and write the reason next to it -- which is a deliberate act that leaves
    a diff somebody reviews, rather than a command that leaves nothing.
    """
    existing = read_baseline(tree)
    kept = existing.get("surfaces", {})
    refused: list[str] = []
    surfaces: dict[str, dict[str, dict[str, Any]]] = {}
    for corpus, per_surface in measured.items():
        surfaces[corpus] = {}
        for surface, value in per_surface.items():
            previous = kept.get(corpus, {}).get(surface, {})
            recorded = previous.get("separability")
            if recorded is not None and value > float(recorded) + TOLERANCE:
                refused.append(
                    f"{corpus}/{surface} measures {value:.4f} against a recorded "
                    f"{float(recorded):.4f}. --sync will not raise a figure: that "
                    "would be writing the leak down instead of removing it. Fix it, "
                    "or record the rise by hand with the reason beside it."
                )
                continue
            row: dict[str, Any] = {"separability": value}
            if value > TARGET and previous.get("blockedBy"):
                row["blockedBy"] = previous["blockedBy"]
                row["reason"] = previous.get("reason", "")
            surfaces[corpus][surface] = row
    if refused:
        return refused
    payload = {
        "$comment": existing.get("$comment", ""),
        "target": TARGET,
        "tolerance": TOLERANCE,
        "surfaces": surfaces,
    }
    (tree / BASELINE_REL).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--report", action="store_true", help="print every figure")
    parser.add_argument("--sync", action="store_true", help="rewrite the baseline")
    args = parser.parse_args()

    measured = measure(args.root)
    if args.sync:
        refused = sync(args.root, measured)
        if refused:
            print(
                f"FAIL: --sync will not record {len(refused)} rise(s):", file=sys.stderr
            )
            for problem in refused:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print("baseline rewritten:")
        print(render(measured, read_baseline(args.root)))
        return 0

    baseline = read_baseline(args.root)
    if args.report:
        print(render(measured, baseline))
        return 0

    if not baseline:
        print(
            f"FAIL: {BASELINE_REL} is absent, so nothing records what any surface "
            "used to measure and no increase can be detected.",
            file=sys.stderr,
        )
        return 1

    problems = judge(measured, baseline)
    if problems:
        print(f"FAIL: the corpus is scoreable from its surface ({len(problems)}):",
              file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(render(measured, baseline), file=sys.stderr)
        return 1

    over = [
        f"{c}/{s}"
        for c, per in measured.items()
        for s in SURFACES
        if per[s] > TARGET
    ]
    print(
        f"OK: {len(CORPORA) * len(SURFACES)} surface measurements, none above its "
        f"recorded figure"
        + (f"; {len(over)} declared over the {TARGET} target: {', '.join(over)}." if over
           else f"; all at or under the {TARGET} target.")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
