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


def main() -> int:
    check("a failing first command is caught", first_command_failing_is_caught)
    check("a failing middle command is caught", middle_command_failing_is_caught)
    check("a failure stops the block", failure_stops_the_block)
    check("an all-succeeding block passes", a_passing_block_still_passes)
    check("pipefail is not set", pipefail_is_not_set)

    if FAILURES:
        print(f"FAIL: {len(FAILURES)} case(s) do not hold:")
        for line in FAILURES:
            print(f"  {line}")
        return 1
    print("OK: 5 case(s); the local mirror runs steps the way GitHub Actions does.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
