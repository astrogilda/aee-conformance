#!/usr/bin/env python3
"""Tests for scripts/forcing-gate.py.

Almost every case below asserts a REFUSAL, and that is the point. This
repository has a documented history of checks that ran green while enforcing
nothing -- a shipped verifier that scored 0 of 186 while its own unit test
passed, a drop count that was a hardcoded literal, a conformance oracle that
recorded a crashed evaluation as a denial -- and a forcing gate that could not go
red would be the fourth. A green run proves the happy path; only a refusal proves
the check.

Two of the cases are LIVE: they build the tooling, run the ground-truth gate, and
rebuild and replay one real mutant against a real baseline. One of the two is
rigged to regress, so the end-to-end path from a weakened rail to a non-zero exit
is exercised rather than argued. They are slower than the rest and they are not
optional: the unit cases prove the decision functions, and only a live run proves
they are wired to anything.

Usage: python3 scripts/forcing-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "forcing-gate.py"
LIVE_BASELINE = REPO_ROOT / "docs" / "FORCING-BASELINE.json"


def load_gate() -> Any:
    spec = importlib.util.spec_from_file_location("forcing_gate", GATE)
    if spec is None or spec.loader is None:
        raise SystemExit(f"test setup: {GATE} is not importable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fg = load_gate()

Failures = list[str]


def refuses(call: Any, phrase: str, what: str) -> Failures:
    """Assert that `call` exits non-zero AND says why.

    stderr is captured rather than let through, because a refusal these cases
    provoke on purpose reads exactly like a real failure in the test log.
    """
    captured = io.StringIO()
    try:
        with contextlib.redirect_stderr(captured):
            call()
    except SystemExit as exc:
        if exc.code == 0:
            return [f"{what}: exited 0"]
        if phrase not in captured.getvalue():
            return [
                f"{what}: refused, but the message does not carry {phrase!r}: "
                f"{captured.getvalue()}"
            ]
        return []
    return [f"{what}: was accepted"]


def site(key: str, snippet: str = "if a { return b }") -> dict[str, Any]:
    file_name = key.split("::")[0]
    return {
        "key": key,
        "file": file_name,
        "line": 10,
        "func": "f",
        "op": key.split("::")[2],
        "snippet": snippet,
    }


K1 = "validity.go::checkSubstrateRow::IF_OFF::aaaaaaaaaaaa"
K2 = "statement.go::Gate0::CODE_OFF::bbbbbbbbbbbb"
K3 = "jcs.go::hex4::CASE_DEL::cccccccccccc"


def baseline(rows: dict[str, Any], annotations: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"sites": rows, "annotations": annotations or {}, "counts": {}}


# ---------------------------------------------------------------------------
# structural: a baseline that does not describe the rail in front of it
# ---------------------------------------------------------------------------


def structural_cases() -> Failures:
    failures: Failures = []
    base = baseline({K1: {"class": "KILLED", "snippet": "x", "killers": ["bad-101"]}})

    retired = fg.structural_errors(base, [site(K2)])
    if not any("RETIRED" in e and K1 in e for e in retired):
        failures.append(
            f"a baseline row whose site the rail no longer has was not refused: {retired}"
        )
    if not any("UNRECORDED" in e and K2 in e for e in retired):
        failures.append(f"a mutation site with no baseline row was not refused: {retired}")

    annotated = baseline(
        {K1: {"class": "DEAD", "snippet": "x"}},
        {K3: {"status": "unkillable", "reason": "equivalent"}},
    )
    stale = fg.structural_errors(annotated, [site(K1)])
    if not any("STALE ANNOTATION" in e and K3 in e for e in stale):
        failures.append(f"an annotation for a site that does not exist was not refused: {stale}")

    agreed = fg.structural_errors(base, [site(K1)])
    if agreed:
        failures.append(f"a baseline that matches the rail was refused: {agreed}")
    return failures


# ---------------------------------------------------------------------------
# the ratchet itself
# ---------------------------------------------------------------------------


def ratchet_cases() -> Failures:
    failures: Failures = []
    forced = baseline({K1: {"class": "KILLED", "snippet": "x", "killers": ["bad-101"]}})

    gone = fg.ratchet_errors(forced, {K1: {"key": K1, "class": "DEAD"}})
    if not any("no longer does" in e for e in gone.regressions):
        failures.append(f"KILLED -> DEAD was not reported as a regression: {gone.regressions}")
    if gone.regressed_keys != {K1}:
        failures.append("the regressed site was not named, so --sync could not refuse it")

    silent = {K1: {"key": K1, "class": "SILENT", "changed": ["bad-101"]}}
    if not fg.ratchet_errors(forced, silent).regressions:
        failures.append(
            "KILLED -> SILENT was not reported as a regression; the corpus sees the "
            "change and no longer fails on it"
        )

    same = {K1: {"key": K1, "class": "KILLED", "killers": ["bad-101"]}}
    if fg.ratchet_errors(forced, same).any():
        failures.append("an unchanged measurement was refused")

    moved = {K1: {"key": K1, "class": "KILLED", "killers": ["bad-101", "bad-102"]}}
    drift = fg.ratchet_errors(forced, moved).drift
    if not any("vectors that force it changed" in e for e in drift):
        failures.append(f"a change in WHICH vectors force a rule went unrecorded: {drift}")

    dead = baseline({K1: {"class": "DEAD", "snippet": "x"}})
    now_silent = {K1: {"key": K1, "class": "SILENT", "changed": ["x"]}}
    if not fg.ratchet_errors(dead, now_silent).drift:
        failures.append("DEAD -> SILENT left the baseline stale with no complaint")

    improved = fg.ratchet_errors(dead, {K1: {"key": K1, "class": "KILLED", "killers": ["bad-900"]}})
    if improved.regressions:
        failures.append(f"a newly forced rule was called a regression: {improved.regressions}")
    if not improved.drift:
        failures.append("a newly forced rule did not ask for the baseline to be updated")
    return failures


def sync_refusal_cases() -> Failures:
    """--sync is the only way the record moves, and it may not move it downhill."""
    failures: Failures = []
    forced = baseline({K1: {"class": "KILLED", "snippet": "x", "killers": ["bad-101"]}})
    regressed = fg.ratchet_errors(forced, {K1: {"key": K1, "class": "DEAD"}})
    failures += refuses(
        lambda: fg.refuse_unrecordable(regressed, ""),
        "how a ratchet becomes a log",
        "--sync writing a forcing regression into the baseline",
    )
    fg.refuse_unrecordable(regressed, K1)  # named one at a time, it is allowed

    annotated = baseline(
        {K1: {"class": "DEAD", "snippet": "x"}},
        {K1: {"status": "unkillable", "reason": "argued"}},
    )
    falsified = fg.ratchet_errors(annotated, {K1: {"key": K1, "class": "KILLED", "killers": ["b"]}})
    failures += refuses(
        lambda: fg.refuse_unrecordable(falsified, ""),
        "not a number a script may adjust",
        "--sync rewriting past a disproved annotation",
    )
    failures += refuses(
        lambda: fg.refuse_unrecordable(falsified, K1),
        "not a number a script may adjust",
        "--accept-unforced being used to wave through a disproved annotation",
    )
    return failures


def annotation_cases() -> Failures:
    failures: Failures = []
    for status in fg.ANNOTATIONS:
        annotated = baseline(
            {K1: {"class": "DEAD", "snippet": "x"}},
            {K1: {"status": status, "reason": "argued"}},
        )
        killed = {K1: {"key": K1, "class": "KILLED", "killers": ["bad-900"]}}
        verdict = fg.ratchet_errors(annotated, killed)
        if not any("annotation is wrong" in e for e in verdict.falsified):
            failures.append(
                f"a site annotated {status!r} was KILLED and the annotation was not "
                f"falsified: {verdict.falsified}. An annotation that cannot be wrong "
                "is a suppression."
            )
        if fg.ratchet_errors(annotated, {K1: {"key": K1, "class": "DEAD"}}).any():
            failures.append("an annotated site that stayed unkilled was refused")
    return failures


def baseline_loading_cases(tmp: Path) -> Failures:
    failures: Failures = []
    fg.BASELINE = tmp / "no-such-baseline.json"
    failures += refuses(
        lambda: fg.load_baseline(allow_absent=False),
        "A missing baseline is not an empty one",
        "a missing baseline was read as an empty ratchet that passes everything",
    )
    created = fg.load_baseline(allow_absent=True)
    if created.get("sites") != {}:
        failures.append("--sync's bootstrap did not start from an empty baseline")

    bad = tmp / "bad-annotation.json"
    invented = baseline({}, {K1: {"status": "wontfix", "reason": "r"}})
    bad.write_text(json.dumps(invented), encoding="utf-8")
    fg.BASELINE = bad
    failures += refuses(
        lambda: fg.load_baseline(allow_absent=False),
        "expected one of",
        "an annotation with an invented status",
    )
    fg.BASELINE = LIVE_BASELINE
    return failures


# ---------------------------------------------------------------------------
# ground truth: the fast path against the real one
# ---------------------------------------------------------------------------


def observation(**overrides: Any) -> dict[str, Any]:
    base = {
        "verdict": "valid",
        "codes": [],
        "result": "pass",
        "tiers_with_key": ["attested"],
        "tiers_without_key": ["unattested"],
        "result_without_key": "pass",
    }
    return {**base, **overrides}


def ground_truth_cases() -> Failures:
    failures: Failures = []
    truth = {"ok-1": observation()}

    if fg.compare_observations({"ok-1": observation()}, truth):
        failures.append("two identical observations were reported as a disagreement")

    tofu = {"ok-1": observation(tiers_without_key=["attested"])}
    if not fg.compare_observations(tofu, truth):
        failures.append(
            "a fast path that answered the no-key tier column with the pinned-key "
            "answer was accepted; that is the exact defect the shim had"
        )
    if not fg.compare_observations({}, truth):
        failures.append("a vector missing from the fast path was accepted")

    rows = {"ok-1": {"status": "PASS", "gates": {"gate0": "PASS"}, "observed": observation()}}
    def scored(status: str, gate: str) -> dict[str, Any]:
        return {
            "vectors": [
                {
                    "id": "ok-1",
                    "status": status,
                    "gates": {"gate0": gate},
                    "observed": {"codes": []},
                }
            ]
        }

    report = scored("PASS", "PASS")
    if fg.compare_report(rows, report):
        failures.append("an agreeing report was reported as a disagreement")
    flipped = scored("FAIL", "PASS")
    if not fg.compare_report(rows, flipped):
        failures.append("a status disagreement with the real harness was accepted")
    gates = scored("PASS", "FAIL")
    if not fg.compare_report(rows, gates):
        failures.append("a per-gate disagreement with the real harness was accepted")
    if not fg.compare_report(rows, {"vectors": []}):
        failures.append("a vector the harness never scored was accepted")
    return failures


def shape_cases() -> Failures:
    """The CLI emits no empty result and no empty tier column, so neither may the
    fast path: a `[]` where the real rail reports nothing is a disagreement the
    evaluator branches on."""
    failures: Failures = []
    observed = fg.as_observed({"id": "x", "verdict": "invalid", "codes": ["a"]})
    for field in ("result", "tiers_with_key", "tiers_without_key", "result_without_key"):
        if observed[field] is not None:
            failures.append(f"an absent {field} became {observed[field]!r} rather than None")
    tofu = observation(tiers_without_key=["attested"])
    if fg.observation_key(observation()) == fg.observation_key(tofu):
        failures.append(
            "the observation key ignores the no-key tier column, so a change there reads as DEAD"
        )
    if fg.observation_key(observation()) != fg.observation_key(observation(codes=[])):
        failures.append("the observation key is unstable on equal observations")
    return failures


# ---------------------------------------------------------------------------
# scope, and saying what a subset dropped
# ---------------------------------------------------------------------------


def scope_cases() -> Failures:
    failures: Failures = []
    sites = [site(K1), site(K2), site(K3)]
    base = baseline(
        {
            K1: {"class": "KILLED", "snippet": "x", "killers": ["bad-1"]},
            K2: {"class": "DEAD", "snippet": "x"},
            K3: {"class": "INCONCLUSIVE", "snippet": "x", "reason": "TIMEOUT"},
        }
    )
    forced = [s["key"] for s in fg.select_sites("forced", sites, base, "")]
    if forced != [K1]:
        failures.append(f"the forced scope selected {forced}, not the sites recorded as KILLED")
    if K3 in forced:
        failures.append(
            "the forced scope included a non-terminating site, which would hold the run open"
        )
    if len(fg.select_sites("all", sites, base, "")) != 3:
        failures.append("the full scope did not select every site")
    if [s["key"] for s in fg.select_sites("all", sites, base, K2)] != [K2]:
        failures.append("--only did not restrict the campaign")
    failures += refuses(
        lambda: fg.select_sites("all", sites, base, "no.go::x::IF_OFF::000000000000"),
        "the rail does not have",
        "--only naming a key the rail does not have",
    )

    failures += refuses(
        lambda: fg.require_nonempty([], "forced", ""),
        "passes by measuring nothing",
        "a run that selected no site at all",
    )
    fg.require_nonempty([site(K1)], "forced", "")

    summary = fg.dropped_summary(base, {K1})
    for phrase in ("2 NOT run", "DEAD 1", "INCONCLUSIVE 1"):
        if phrase not in summary:
            failures.append(f"the subset summary does not say {phrase!r}: {summary}")
    if "every enumerated site" not in fg.dropped_summary(base, {K1, K2, K3}):
        failures.append("a full run did not say so")
    return failures


def corpus_pin_cases(tmp: Path) -> Failures:
    """A campaign is a measurement of ONE corpus, and it has to prove it was.

    The published baseline once recorded a rule as forced by two vectors that
    cannot reach it, because the corpus was regenerated while the campaign was
    running: the worker trees symlink the corpus, so every mutant re-reads it,
    while the observations they are diffed against were taken once at the start.
    """
    failures: Failures = []
    root = tmp / "corpus-pin"
    for sub in ("accept", "reject", "indeterminate"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "MANIFEST.json").write_text('{"vectors": []}', encoding="utf-8")
    (root / "reject" / "bad-1.json").write_text('{"a": 1}', encoding="utf-8")

    first = fg.corpus_fingerprint(root)
    if first != fg.corpus_fingerprint(root):
        failures.append("the corpus fingerprint is not stable over an unchanged tree")
    fg.refuse_moved_corpus(first, first)

    (root / "reject" / "bad-1.json").write_text('{"a": 2}', encoding="utf-8")
    edited = fg.corpus_fingerprint(root)
    failures += refuses(
        lambda: fg.refuse_moved_corpus(first, edited),
        "changed while the campaign was running",
        "a vector rewritten mid-campaign",
    )

    (root / "reject" / "bad-1.json").write_text('{"a": 1}', encoding="utf-8")
    (root / "reject" / "bad-2.json").write_text('{"a": 1}', encoding="utf-8")
    failures += refuses(
        lambda: fg.refuse_moved_corpus(first, fg.corpus_fingerprint(root)),
        "changed while the campaign was running",
        "a vector added mid-campaign",
    )
    # A rename that keeps every byte is still a different corpus: the manifest is
    # keyed on file names and a replay globs them, so two trees with the same
    # contents under different names do not answer the same question.
    (root / "reject" / "bad-2.json").unlink()
    (root / "reject" / "bad-1.json").rename(root / "reject" / "bad-3.json")
    failures += refuses(
        lambda: fg.refuse_moved_corpus(first, fg.corpus_fingerprint(root)),
        "changed while the campaign was running",
        "a vector renamed mid-campaign",
    )
    return failures


def coverage_cases() -> Failures:
    """never-taken, taken and unknown must stay three answers, not two."""
    failures: Failures = []
    blocks = {"validity.go": [(10, 12, 0), (20, 22, 7)]}
    guard = {"file": "validity.go", "line": 9, "op": "IF_OFF"}
    body = {"file": "validity.go", "line": 20, "op": "CODE_OFF"}
    absent = {"file": "other.go", "line": 1, "op": "CODE_OFF"}
    if fg.branch_taken(blocks, guard) != "never-taken":
        failures.append("a guard whose body no vector entered was not reported never-taken")
    if fg.branch_taken(blocks, body) != "taken":
        failures.append("an executed body was not reported taken")
    if fg.branch_taken(blocks, absent) != "unknown":
        failures.append("a site with no coverage block was folded into taken or never-taken")
    return failures


def row_cases() -> Failures:
    """A baseline row carries nothing that moves under an unrelated edit."""
    failures: Failures = []
    killed = fg.site_row(site(K1), {"class": "KILLED", "killers": ["bad-1"]}, "taken")
    if "line" in killed or "branch" in killed:
        failures.append(f"a KILLED row carries volatile or irrelevant fields: {killed}")
    dead = fg.site_row(site(K1), {"class": "DEAD"}, "never-taken")
    if dead.get("branch") != "never-taken":
        failures.append(
            "a DEAD row lost the evidence separating a mintable gap from an unreachable branch"
        )
    inconclusive = fg.site_row(site(K1), {"class": "INCONCLUSIVE", "reason": "TIMEOUT"}, None)
    if inconclusive.get("reason") != "TIMEOUT":
        failures.append("an INCONCLUSIVE row did not record why it was inconclusive")
    return failures


# ---------------------------------------------------------------------------
# live: the whole pipeline, once green and once rigged to go red
# ---------------------------------------------------------------------------


def run_gate(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def pick(rows: dict[str, Any], wanted: str) -> str:
    for key, row in sorted(rows.items()):
        if row["class"] == wanted:
            return key
    raise SystemExit(
        f"test setup: the committed baseline records no {wanted} site to drive a live case with"
    )


def live_cases(tmp: Path) -> Failures:
    if not LIVE_BASELINE.is_file():
        raise SystemExit(
            "test setup: no committed forcing baseline, so the live cases would "
            "assert nothing. Create it with scripts/forcing-gate.py --scope all --sync."
        )
    committed = json.loads(LIVE_BASELINE.read_text(encoding="utf-8"))
    rows = committed["sites"]
    failures: Failures = []

    forced_key = pick(rows, "KILLED")
    code, output = run_gate(
        ["--scope", "all", "--only", forced_key, "--baseline", str(LIVE_BASELINE)]
    )
    if code != 0:
        failures.append(
            f"live-still-forced: the gate refused a rule the baseline records as "
            f"forced:\n{output}"
        )
    elif "ground truth" not in output:
        failures.append(f"live-still-forced: the ground-truth gate did not run:\n{output}")

    unforced_key = pick(rows, "DEAD")
    rigged = json.loads(json.dumps(committed))
    rigged["sites"][unforced_key] = {
        "class": "KILLED",
        "snippet": rows[unforced_key]["snippet"],
        "killers": ["bad-000-invented"],
    }
    rigged_path = tmp / "rigged-baseline.json"
    rigged_path.write_text(json.dumps(rigged), encoding="utf-8")
    code, output = run_gate(
        ["--scope", "all", "--only", unforced_key, "--baseline", str(rigged_path)]
    )
    if code == 0:
        failures.append(
            "live-regression: a baseline claiming a rule is forced that measurably "
            f"is not was accepted. The gate cannot fail.\n{output}"
        )
    elif "no longer does" not in output:
        failures.append(f"live-regression: refused, but not as a forcing regression:\n{output}")

    code, output = run_gate(["--scope", "forced", "--sync"])
    if code == 0 or "cannot rewrite rows it did not measure" not in output:
        failures.append(f"a subset run was allowed to rewrite the whole baseline:\n{output}")
    return failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="forcing-gate-test-") as raw:
        tmp = Path(raw)
        failures = (
            structural_cases()
            + ratchet_cases()
            + annotation_cases()
            + sync_refusal_cases()
            + baseline_loading_cases(tmp)
            + ground_truth_cases()
            + shape_cases()
            + scope_cases()
            + corpus_pin_cases(tmp)
            + coverage_cases()
            + row_cases()
            + live_cases(tmp)
        )
    if failures:
        print(f"FAIL: {len(failures)} case(s).", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        "OK: the forcing gate refuses a regression, a falsified annotation, a "
        "baseline that does not describe the rail, a fast path that disagrees with "
        "the real harness, and a subset run that tries to rewrite what it did not "
        "measure -- proven once end to end against a real mutant."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
