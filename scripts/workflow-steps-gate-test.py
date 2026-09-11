#!/usr/bin/env python3
"""Tests for scripts/workflow-steps-gate.py.

The gate exists to run every workflow shell step locally so a push does not go
out against a red remote. It had a hole of exactly the kind it was written to
close, and the hole is the subject of this file.

GitHub Actions runs each `run:` block under `bash -e {0}` and prints that line
above the step in its own logs. The gate ran the block under a plain `bash`. In
a step with one command the two agree, so the divergence is invisible on most of
the workflow; in a step with several, the shell without `-e` keeps going after a
failure and the block reports the LAST command's status. On 2026-08-07 the
four-command forcing step failed its first command, passed the other three,
reported 0, and the gate passed a push whose CI went red four minutes later.

That is worse than an absent check. An absent check is known to be absent; this
one printed "workflow steps passed" over a step it had watched fail, which is
the same shape as the incident recorded at the top of the gate itself, one level
up. So the cases below assert the failing halves first: a multi-command step
whose FIRST command fails must be caught, and it must be caught by the shell
rather than by anything the gate parses out of the block, because the gate does
not read the block's contents and must not start.

The last case is the balance: a block whose commands all succeed still passes,
and a mirror that failed everything would be deleted rather than trusted.

Usage: python3 scripts/workflow-steps-gate-test.py
Exit 0 when every case holds; 1 on a summary of failures.
"""

from __future__ import annotations

import contextlib
import importlib.util
import pathlib
import sys
from collections.abc import Callable

HERE = pathlib.Path(__file__).resolve().parent


def load_gate() -> object:
    """Import the gate by path, since its filename is not an identifier."""
    path = HERE / "workflow-steps-gate.py"
    spec = importlib.util.spec_from_file_location("workflow_steps_gate", path)
    if spec is None or spec.loader is None:
        sys.exit(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load_gate()
FAILURES: list[str] = []


@contextlib.contextmanager
def installed(version: str):
    """Answer the version probe with `version` for the duration of the block.

    The three golangci-lint branches are decided by what is on PATH, and PATH is
    not the same on a runner as on a workstation: CI runs this file in a job that
    installs no Go linter, so a case that read the real binary would assert one
    thing here and the opposite there. Substituting the probe tests the branch
    the gate actually takes, in both places, and an empty string is the honest
    spelling of "no binary".
    """
    original = GATE.installed_golangci_version  # type: ignore[attr-defined]
    GATE.installed_golangci_version = lambda: version  # type: ignore[attr-defined]
    try:
        yield
    finally:
        GATE.installed_golangci_version = original  # type: ignore[attr-defined]


def check(name: str, fn: Callable[[], None]) -> None:
    try:
        fn()
    except AssertionError as exc:
        FAILURES.append(f"{name}: {exc}")


def run(block: str) -> int:
    return GATE.run_step(block, {"PATH": "/usr/bin:/bin"}).returncode  # type: ignore[attr-defined]


def first_command_failing_is_caught() -> None:
    """The regression. Without `-e` this block exits 0 and the push goes out."""
    rc = run("false\ntrue\n")
    assert rc != 0, (
        "a block whose first command fails and whose last succeeds reported "
        f"exit {rc}. The shell is not running with -e, so this gate mirrors a "
        "workflow GitHub Actions would fail."
    )


def middle_command_failing_is_caught() -> None:
    """The four-command shape the incident actually had."""
    rc = run("true\nfalse\ntrue\ntrue\n")
    assert rc != 0, f"a failure in the middle of a four-command block reported exit {rc}"


def failure_stops_the_block() -> None:
    """`-e` aborts rather than running on, which is what Actions does.

    Asserted through an observable side effect rather than the exit status,
    because a block that ran every command and returned the first failure would
    satisfy the two cases above while still diverging from the remote on any
    step whose later commands are not safe to run after an earlier one failed.
    """
    proc = GATE.run_step("false\necho REACHED\n", {"PATH": "/usr/bin:/bin"})  # type: ignore[attr-defined]
    assert "REACHED" not in proc.stdout, (
        "the block continued past a failed command; Actions would have stopped, "
        f"so a later command ran here that never runs on the remote: {proc.stdout!r}"
    )


def a_passing_block_still_passes() -> None:
    """The mirror must not be stricter than the thing it mirrors."""
    rc = run("true\ntrue\ntrue\n")
    assert rc == 0, f"an all-succeeding block reported exit {rc}"


def pipefail_is_not_set() -> None:
    """Deliberately absent: Actions does not set it, and matching is the job.

    A mirror stricter than the remote fails pushes the remote would accept, and
    the cost lands on whoever cannot tell the two apart.
    """
    rc = run("false | true\n")
    assert rc == 0, (
        "a failing left-hand side of a pipe was reported as a step failure, so "
        "pipefail is set. Actions does not set it; this gate would now refuse "
        f"pushes the remote accepts (exit {rc})"
    )


def an_unclassified_action_is_a_fault() -> None:
    """An action nobody has classified must not drop out of coverage quietly.

    This is the second hole, found the same way as the first: a marketplace step
    was printed SKIP and passed over, so `golangci-lint (core module)` was never
    run here and the remote failed it on three pushes in a row. Silence about a
    step is now reserved for steps somebody wrote down a reason for.
    """
    local = GATE.local_equivalent("some/brand-new-action@v1", {})  # type: ignore[attr-defined]
    assert local.run is None, "an unknown action must not resolve to something runnable"
    assert local.fault, (
        "an unclassified action was reported as an ordinary NOT RUN. Adding an "
        "action to a workflow would then remove it from local coverage without "
        "anyone being told, which is the defect this gate exists to prevent."
    )


def a_runner_only_action_names_its_reason() -> None:
    """NOT RUN is only honest when it says what the runner does that we cannot."""
    local = GATE.local_equivalent("actions/checkout@v4", {})  # type: ignore[attr-defined]
    assert local.run is None, "checkout must not be mirrored; this gate runs inside a checkout"
    assert not local.fault, "checkout is classified, so it is not a fault"
    assert "actions/checkout" in local.reason and len(local.reason) > 30, (
        f"the reason does not describe the step: {local.reason!r}"
    )


def the_pinned_linter_is_mirrored() -> None:
    """The step the remote caught and this gate used to skip."""
    with installed("2.11.4"):
        local = GATE.local_equivalent(  # type: ignore[attr-defined]
            "golangci/golangci-lint-action@v7",
            {"version": "v2.11.4", "working-directory": "witnessattestor"},
        )
    assert local.run is not None, f"the pinned linter did not resolve to a command: {local.reason}"
    assert "golangci-lint run" in local.run, local.run
    assert "witnessattestor" in local.run, (
        f"working-directory was dropped, so the wrong module would be linted: {local.run!r}"
    )


def a_version_mismatch_is_not_run_rather_than_a_pass() -> None:
    """A different version is a different set of linters, so its silence is worthless."""
    with installed("2.10.0"):
        local = GATE.local_equivalent(  # type: ignore[attr-defined]
            "golangci/golangci-lint-action@v7", {"version": "v2.11.4"}
        )
    assert local.run is None, (
        "a version this workstation does not have resolved to a command anyway. "
        "The mirror would then report on a different tool than the remote runs."
    )
    assert "2.11.4" in local.reason and "2.10.0" in local.reason, (
        f"the refusal must name both versions so the reader can fix it: {local.reason!r}"
    )


def an_absent_linter_is_not_run_rather_than_a_pass() -> None:
    """No binary is NOT RUN. It must never read as a clean lint."""
    with installed(""):
        local = GATE.local_equivalent(  # type: ignore[attr-defined]
            "golangci/golangci-lint-action@v7", {"version": "v2.11.4"}
        )
    assert local.run is None, "a missing golangci-lint resolved to a command anyway"
    assert "not on PATH" in local.reason, (
        f"the reason does not say the binary is missing: {local.reason!r}"
    )


def main() -> int:
    check("a failing first command is caught", first_command_failing_is_caught)
    check("a failing middle command is caught", middle_command_failing_is_caught)
    check("a failure stops the block", failure_stops_the_block)
    check("an all-succeeding block passes", a_passing_block_still_passes)
    check("pipefail is not set", pipefail_is_not_set)
    check("an unclassified action is a fault", an_unclassified_action_is_a_fault)
    check("a runner-only action names its reason", a_runner_only_action_names_its_reason)
    check("the pinned linter is mirrored", the_pinned_linter_is_mirrored)
    check("a version mismatch is not run", a_version_mismatch_is_not_run_rather_than_a_pass)
    check("an absent linter is not run", an_absent_linter_is_not_run_rather_than_a_pass)

    if FAILURES:
        print(f"FAIL: {len(FAILURES)} case(s) do not hold:")
        for line in FAILURES:
            print(f"  {line}")
        return 1
    print("OK: 10 case(s); the local mirror runs steps the way GitHub Actions does.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
