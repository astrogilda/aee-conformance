#!/usr/bin/env python3
"""Tests for scripts/liveness-probe.py.

Two jobs, and the second is the one that matters.

First, it pins every per-channel verdict the documentation publishes. The
tables in ``docs/DETECTOR-LIVENESS.md`` say which vector reports which verdict
on which channel, and a table of verdicts typed by hand is a claim about a
computation rather than a reading of one. Every cell in those tables appears
below as an expected value, recomputed from the shipped vectors on every run,
so a corpus that moves without the prose moving fails here.

Second, it plants faults the probe MUST notice. A detector-liveness report that
cannot go red is the exact defect the report exists to catch, one level up: a
probe hard-wired to answer "demonstrated" would clear the corpus and mean
nothing. So each arm of the construction is switched off in turn against a copy
of ok-052 and the verdict on the affected channel is required to degrade, and
to degrade to the named state rather than merely to something worse.

The planted faults break the enclosing statement in ways a conforming producer
never would -- a manifest edited without its digest, a signature replaced by
zeroes -- and that is deliberate and is not a claim about validity. The probe
is not a validity gate and running it is not verification, so what is under
test is only whether its per-channel answer depends on the value being
switched off. The reachable, fully-valid forms of three of these faults ship as
`bad-983`, `bad-984` and `bad-985`, whose verdicts are pinned above them.

Signature checking is the point of the ``--key`` cases, so this test requires
the cryptography package and refuses to run without it rather than reporting
the structural subset as a pass: a check that did not run is not a result.

Usage: uv run --extra dev python scripts/liveness-probe-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PROBE = REPO_ROOT / "scripts" / "liveness-probe.py"
ACCEPT = REPO_ROOT / "vectors" / "accept"
REJECT = REPO_ROOT / "vectors" / "reject"

# The suite's own signing key, whose seed is the published constant
# SHA-256("in-toto-aee-test-key/substrate-observation-test/v1"); the derivation
# being open is what makes it a test key. Recipe in vectors/reject/INDEX.md.
KEY = "496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62"
# A second key from the same scheme at role `liveness-probe-test-nonsigner`,
# which signed nothing in this corpus. It exists so one case can ask the probe
# a question only a real signature check can answer.
OTHER_KEY = "76fcffb8ad34381d915b530b16b8d2935d94dfddf785dc4239a3a71ca634de34"

LIVE = ACCEPT / "ok-052-liveness-probe-per-channel.json"

# A valid base64 field whose bytes are an ed25519 signature length and are not
# a signature. Replacing a `sig` with this leaves the record parseable and
# leaves nothing for the key to verify, which separates "the value is wrong"
# from "the record could not be read".
DEAD_SIG = base64.b64encode(b"\x00" * 64).decode("ascii")

Channels = dict[str, str]


# ------------------------------------------------------- verdicts as published

# Every cell of the two tables in docs/DETECTOR-LIVENESS.md, plus the two
# vectors its "what forced each arm" table names as the separators for the
# attribution arm and the seal arm.
PINNED: tuple[tuple[Path, Channels], ...] = (
    # The satisfied form on every claimed channel at once.
    (LIVE, {"XA": "demonstrated", "XB": "demonstrated", "XC": "demonstrated"}),
    # The honest report of a detector that did not fire on the middle channel.
    # It is an ACCEPT vector and its middle channel is not demonstrated, which
    # is the whole distinction: valid, honest, and not a demonstration.
    (ACCEPT / "ok-053-liveness-probe-uncaught-on-one-channel.json",
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    # The three refusals, each faulted on a channel that is not the first.
    (REJECT / "bad-983-liveness-middle-channel-commitment-unmatched.json",
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    (REJECT / "bad-984-liveness-last-channel-unpinnable.json",
     {"XA": "demonstrated", "XB": "demonstrated", "XC": "unprobed"}),
    (REJECT / "bad-985-liveness-middle-channel-probe-uncaught.json",
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    # The seal arm: a matched probe whose run-end seal names nothing.
    (ACCEPT / "ok-047-attribution-pinned.json", {"XA": "unsealed"}),
    # The attribution arm: the same run declaring the weaker of the two values.
    (ACCEPT / "ok-048-attribution-paired-despite-expectation.json",
     {"XA": "not-demonstrated"}),
)


# ------------------------------------------------------------- planted faults

def manifest_of(stmt: dict[str, Any]) -> dict[str, Any]:
    env = stmt["predicate"]["observationEnvironment"]
    man: dict[str, Any] = env["corpus"]["manifest"]
    return man


def row_for(stmt: dict[str, Any], attack: str) -> dict[str, Any]:
    for row in stmt["predicate"]["attackResults"]:
        if row["attackId"] == attack:
            out: dict[str, Any] = row
            return out
    raise SystemExit(f"ok-052 carries no row for {attack}; the fixture moved")


def record_of(stmt: dict[str, Any], kind: str, commitment: str | None
              ) -> dict[str, Any]:
    """The record of one kind, optionally the one committing to a value."""
    for rec in stmt["predicate"]["observationRecords"]:
        payload = json.loads(base64.b64decode(rec["payload"]))
        if payload.get("aeeKind") != kind:
            continue
        if commitment is None or commitment in (
                payload.get("aeePayloadCommitment") or []):
            out: dict[str, Any] = rec
            return out
    raise SystemExit(f"ok-052 carries no {kind} record; the fixture moved")


def xb_commitment(stmt: dict[str, Any]) -> str:
    val: str = manifest_of(stmt)["expectedPayloads"]["XB-EXAMPLE-1"][0]
    return val


def no_probe_planted(stmt: dict[str, Any]) -> None:
    """The corpus predicted nothing for the middle channel's attack.

    Without a planted stimulus there is no question to answer, so the channel
    is unprobed: not a pass and not a failure, the absence of the only evidence
    that could settle it. This is bad-984's fault moved to the middle channel.
    """
    del manifest_of(stmt)["expectedPayloads"]["XB-EXAMPLE-1"]


def prediction_does_not_match(stmt: dict[str, Any]) -> None:
    """The corpus predicted a value the substrate did not commit to."""
    manifest_of(stmt)["expectedPayloads"]["XB-EXAMPLE-1"] = ["0" * 64]


def attribution_weakened(stmt: dict[str, Any]) -> None:
    """The row drops to the floor value, which asserts no comparability."""
    row_for(stmt, "XB-EXAMPLE-1")["attribution"] = "paired"


def not_caught(stmt: dict[str, Any]) -> None:
    """The row reports the middle channel clean, so nothing was caught."""
    row_for(stmt, "XB-EXAMPLE-1")["containmentObserved"] = "no_egress"


def resolves_nothing(stmt: dict[str, Any]) -> None:
    """The row resolves no record, so no commitment is reachable from it."""
    row_for(stmt, "XB-EXAMPLE-1")["observationRefs"] = []


def interception_unsigned(stmt: dict[str, Any]) -> None:
    """The middle channel's interception no longer verifies under the key.

    Everything else lines up, which is exactly when a structural reading would
    report a demonstration off content nobody signed for.
    """
    rec = record_of(stmt, "interception", xb_commitment(stmt))
    rec["signatures"] = [{"keyid": rec["signatures"][0]["keyid"],
                          "sig": DEAD_SIG}]


def seal_unsigned(stmt: dict[str, Any]) -> None:
    """The run-end seal no longer verifies, so it attributes nothing.

    Every channel falls to unsealed together: each probe still matches, and no
    seal a consumer can trust says the substrate ever attributed it.
    """
    rec = record_of(stmt, "sealed", None)
    rec["signatures"] = [{"keyid": rec["signatures"][0]["keyid"],
                          "sig": DEAD_SIG}]


DEMONSTRATED_ALL = {"XA": "demonstrated", "XB": "demonstrated",
                    "XC": "demonstrated"}

Fault = Callable[[dict[str, Any]], None]
FAULTS: tuple[tuple[str, Fault, Channels], ...] = (
    ("no stimulus planted on the middle channel", no_probe_planted,
     {"XA": "demonstrated", "XB": "unprobed", "XC": "demonstrated"}),
    ("the corpus predicted a value nothing committed to",
     prediction_does_not_match,
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    ("the middle row declares the weaker attribution", attribution_weakened,
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    ("the middle row reports its channel clean", not_caught,
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    ("the middle row resolves no record", resolves_nothing,
     {"XA": "demonstrated", "XB": "not-demonstrated", "XC": "demonstrated"}),
    ("the middle interception does not verify", interception_unsigned,
     {"XA": "demonstrated", "XB": "unverified", "XC": "demonstrated"}),
    ("the run-end seal does not verify", seal_unsigned,
     {"XA": "unsealed", "XB": "unsealed", "XC": "unsealed"}),
)


# --------------------------------------------------------------------- runner

def run_probe(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(PROBE), *args],
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def channels_of(args: list[str]) -> tuple[Channels, str]:
    """Per-channel verdicts for a single statement, and the report's mode."""
    code, out = run_probe([*args, "--json"])
    if code != 0:
        raise AssertionError(f"probe exited {code}\n{out}")
    data = json.loads(out)
    statements = data["statements"]
    if len(statements) != 1:
        raise AssertionError(f"expected one statement, got {len(statements)}")
    chans = {name: cell["verdict"]
             for name, cell in statements[0].get("channels", {}).items()}
    mode: str = data["mode"]
    return chans, mode


def require_cryptography() -> None:
    code, out = run_probe(["--key", KEY, str(LIVE)])
    if "cryptography package is not importable" in out:
        raise SystemExit(
            "liveness-probe-test: the probe cannot check a signature in this "
            "environment, so the cases that matter here would not run. "
            "Refusing to report the structural subset as a pass. Run this as:\n"
            "  uv run --extra dev python scripts/liveness-probe-test.py"
        )
    if code != 0:
        raise SystemExit(f"liveness-probe-test: probe failed to start\n{out}")


Outcome = tuple[int, list[str]]


def check_published_verdicts() -> Outcome:
    """Every cell of the documentation's tables, recomputed."""
    failures: list[str] = []
    for path, want in PINNED:
        try:
            got, _ = channels_of(["--key", KEY, str(path)])
        except AssertionError as exc:
            failures.append(f"{path.name}: {exc}")
            continue
        if got != want:
            failures.append(f"{path.name}: published {want}, computed {got}")
            continue
        print(f"  ok  {path.name} reports {want}")
    return len(PINNED), failures


def check_planted_faults(tmp: Path) -> Outcome:
    """Each arm switched off in turn against a copy of ok-052."""
    live = json.loads(LIVE.read_text(encoding="utf-8"))
    failures: list[str] = []
    for name, fault, want in FAULTS:
        stmt = json.loads(json.dumps(live))
        fault(stmt)
        broken = tmp / "faulted.json"
        broken.write_text(json.dumps(stmt), encoding="utf-8")
        try:
            got, _ = channels_of(["--key", KEY, str(broken)])
        except AssertionError as exc:
            failures.append(f"{name}: {exc}")
            continue
        if got == DEMONSTRATED_ALL:
            failures.append(
                f"{name}: the fault was planted and every channel still "
                "reports demonstrated, so this arm of the construction is not "
                "read at all")
        elif got != want:
            failures.append(f"{name}: expected {want}, computed {got}")
        else:
            print(f"  ok  {name} -> {want}")
    return len(FAULTS), failures


def check_key_is_read() -> Outcome:
    """The key is read rather than decorative, and its absence is declared."""
    failures: list[str] = []
    got, mode = channels_of(["--key", OTHER_KEY, str(LIVE)])
    want_unverified = dict.fromkeys(DEMONSTRATED_ALL, "unverified")
    if mode != "verified" or got != want_unverified:
        failures.append(
            f"a key that signed nothing here: expected {want_unverified} in "
            f"verified mode, computed {got} in {mode} mode")
    else:
        print("  ok  a key that signed nothing here -> every channel "
              "unverified")

    got, mode = channels_of([str(LIVE)])
    if mode != "structural" or got != DEMONSTRATED_ALL:
        failures.append(
            f"no key: expected structural mode, got {mode} and {got}")
    else:
        print("  ok  no key -> the report calls itself structural")
    return 2, failures


def check_exit_codes(tmp: Path) -> Outcome:
    """The two places the probe's exit status is load-bearing."""
    failures: list[str] = []
    # --require-demonstrated has to cut both ways, or CI's use of it as a gate
    # is one more green check enforcing nothing.
    code, out = run_probe(["--require-demonstrated", "--key", KEY, str(LIVE)])
    if code != 0:
        failures.append(f"--require-demonstrated refused ok-052\n{out}")
    else:
        print("  ok  --require-demonstrated clears ok-052")

    code, out = run_probe([
        "--require-demonstrated", "--key", KEY,
        str(ACCEPT / "ok-053-liveness-probe-uncaught-on-one-channel.json")])
    if code == 0:
        failures.append(
            "--require-demonstrated cleared ok-053, whose middle channel is "
            "not demonstrated, so the flag gates nothing")
    else:
        print("  ok  --require-demonstrated refuses ok-053")

    # A file that cannot be parsed exits non-zero and names the read failure.
    # Reporting it as a channel that is not live would turn a check that did
    # not run into a finding.
    junk = tmp / "not-json.json"
    junk.write_text("{ this is not a statement", encoding="utf-8")
    code, out = run_probe(["--key", KEY, str(junk)])
    if code == 0 or "COULD NOT READ" not in out:
        failures.append(
            f"an unparseable file exited {code} without naming the read "
            f"failure\n{out}")
    else:
        print("  ok  an unparseable file is a read error, not a verdict")
    return 3, failures


def main() -> int:
    for path in (PROBE, LIVE):
        if not path.is_file():
            print(f"missing input: {path}", file=sys.stderr)
            return 1
    require_cryptography()

    cases = 0
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for count, found in (check_published_verdicts(),
                             check_planted_faults(tmp),
                             check_key_is_read(),
                             check_exit_codes(tmp)):
            cases += count
            failures += found

    if failures:
        print(f"\nFAIL: {len(failures)} case(s)", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"\nall {cases} cases hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
