#!/usr/bin/env python3
"""Run every shell step of every GitHub workflow locally, before the push.

The bug this exists to stop, observed 2026-08-01: a change was pushed after its
author opened `.github/workflows/no-internal-drafts.yml`, read the first two
steps, ran those two by hand, and saw them pass. The guard has three steps. The
third one rejects first-party product names, it was the one the change broke,
and it never ran locally because nobody read that far down the file. The push
went red on a public repository and the tag cut from it had to be withdrawn.

Running "the checks I happened to read" is not running the checks. So this
reads the workflows themselves and runs every shell step in them, in file and
step order, and it is deliberately noisy about the ones it cannot run.

    python3 scripts/workflow-steps-gate.py            # every workflow
    python3 scripts/workflow-steps-gate.py --list     # show the plan, run nothing
    python3 scripts/workflow-steps-gate.py --only no-internal-drafts

Exit 0 only when every runnable step exited 0. Any step failure, any workflow
that will not parse, and any absent dependency is a non-zero exit -- never a
skip. A gate that quietly skips what it cannot check reports a clean result for
a check that did not run, which is the same defect in a different costume.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from typing import Any, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from _lockfile import single_instance  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

# A marketplace step is one with `uses:` and no shell body. Every one of them
# used to be printed as SKIP and left at that, and on 2026-09-11 that cost three
# red pushes in a row: `golangci-lint (core module)` is a marketplace step, this
# gate skipped it on every push, and the remote failed it on every push with a
# finding a locally installed golangci-lint reports in under a second.
#
# So a marketplace step is now asked whether this workstation can do the same
# work, and the three answers are kept apart on purpose.
#
#   MIRRORED    -- there is a local equivalent, and it RUNS. A failure here is a
#                  failure of the gate, exactly as a shell step's is.
#   CANNOT_RUN  -- the step does something only a runner can do: provision a
#                  toolchain, upload to the run's artifact store, open a pull
#                  request. It is printed NOT RUN, by name, with the reason.
#   neither     -- an action nobody has classified. That is a FAULT rather than
#                  a skip. An action added to a workflow would otherwise remove
#                  itself from this gate's coverage silently, which is the whole
#                  defect above in its next costume.


class Local(NamedTuple):
    """What this workstation can do about one marketplace step."""

    run: str | None  # the shell to run, when there is a local equivalent
    reason: str  # why there is not, when `run` is None
    fault: bool = False  # an unclassified action, which fails the gate


def installed_golangci_version() -> str:
    """The golangci-lint version on PATH, or "" when there is none."""
    binary = shutil.which("golangci-lint")
    if binary is None:
        return ""
    proc = subprocess.run(  # noqa: S603 -- reading the version of a binary we are about to run
        [binary, "version"], capture_output=True, text=True, check=False
    )
    found = re.search(r"version\s+v?(\S+)", proc.stdout + proc.stderr)
    return found.group(1) if found else "unknown"


def golangci_lint(inputs: dict[str, Any]) -> Local:
    """Mirror golangci/golangci-lint-action with the binary on PATH.

    The pinned version is not a detail. golangci-lint adds, removes and retunes
    linters between patch releases, so a mirror running a different version
    reports on a different tool and its silence means nothing. A mismatch is
    therefore NOT RUN with both versions named, never a quiet pass.
    """
    wanted = str(inputs.get("version", "")).strip().lstrip("v")
    installed = installed_golangci_version()
    if not installed:
        return Local(None, f"golangci-lint is not on PATH; the workflow pins v{wanted}")
    if wanted and installed != wanted:
        return Local(
            None,
            f"the workflow pins v{wanted} and this workstation has v{installed}, "
            "which is a different set of linters",
        )
    directory = str(inputs.get("working-directory", "") or ".")
    # `golangci-lint run`, with nothing added. Narrowing the concurrency or the
    # linter set would make this a mirror of a command the remote never runs.
    return Local(f"cd {shlex.quote(directory)}\ngolangci-lint run", "")


MIRRORED: dict[str, Callable[[dict[str, Any]], Local]] = {
    "golangci/golangci-lint-action": golangci_lint,
}

# Steps that belong to the runner rather than to the repository. Each reason
# says what the step does there, so a reader can judge the gap rather than
# taking "not runnable" on trust.
CANNOT_RUN = {
    "actions/checkout": (
        "materialises the repository on the runner; this gate already runs "
        "inside a checkout of the revision under test"
    ),
    "actions/setup-go": "provisions a Go toolchain on the runner; the one on PATH is used here",
    "astral-sh/setup-uv": "provisions uv on the runner; the one on PATH is used here",
    "sigstore/cosign-installer": "provisions cosign on the runner; the one on PATH is used here",
    "actions/upload-artifact": "writes to the run's artifact store, which is only on the remote",
    "peter-evans/create-pull-request": "opens a pull request on the remote",
    "ossf/scorecard-action": "reads the repository's remote metadata and needs a token",
    "github/codeql-action/init": "builds a CodeQL database with a toolchain provisioned per run",
    "github/codeql-action/analyze": "queries a CodeQL database built by the step above",
    "github/codeql-action/upload-sarif": "uploads to code scanning on the remote",
}


def local_equivalent(uses: str, inputs: dict[str, Any]) -> Local:
    """Classify one marketplace step. Never returns a silent skip."""
    action = uses.split("@", 1)[0]
    builder = MIRRORED.get(action)
    if builder is not None:
        return builder(inputs)
    reason = CANNOT_RUN.get(action)
    if reason is not None:
        return Local(None, f"{action} {reason}")
    return Local(
        None,
        f"{action} is not classified in this gate. Add it to MIRRORED with a "
        "local equivalent, or to CANNOT_RUN with the reason a runner is needed. "
        "An unclassified action drops out of local coverage without saying so.",
        fault=True,
    )


def load_yaml(path: pathlib.Path):
    """Parse a workflow, or fail loudly. Never return a partial parse."""
    try:
        import yaml  # noqa: PLC0415 -- optional dependency, reported explicitly below
    except ImportError:
        sys.exit(
            "workflow-steps-gate: PyYAML is not importable.\n"
            "  Install it, or run this gate through uv:\n"
            "    uv run --with pyyaml python scripts/workflow-steps-gate.py\n"
            "  Refusing to continue: a gate that cannot read the workflows cannot\n"
            "  report that they passed."
        )
    try:
        return yaml.safe_load(path.read_text())
    except Exception as exc:  # noqa: BLE001 -- any parse failure is fatal by design
        sys.exit(f"workflow-steps-gate: {path.name} did not parse: {exc}")


class Step(NamedTuple):
    """One workflow step: a shell body, or a marketplace action and its inputs."""

    job: str
    # Not `index`: a NamedTuple field of that name overrides tuple.index().
    position: int
    name: str
    run: str | None
    uses: str
    inputs: dict[str, Any]

    @property
    def label(self) -> str:
        return f"{self.job}[{self.position}] {self.name}"


def steps_of(doc, path: pathlib.Path):
    """Yield every step, in declaration order."""
    jobs = (doc or {}).get("jobs") or {}
    if not jobs:
        sys.exit(f"workflow-steps-gate: {path.name} declares no jobs. Refusing to call it covered.")
    for job_name, job in jobs.items():
        for i, step in enumerate(job.get("steps") or []):
            name = step.get("name") or f"step {i}"
            yield Step(
                job=job_name,
                position=i,
                name=name,
                run=step.get("run"),
                uses=str(step.get("uses") or ""),
                inputs=step.get("with") or {},
            )


# The runner's default shell is bash, and workflow steps rely on it: `set -o pipefail`
# is a bashism that dash rejects outright, so running a step under /bin/sh reports a
# failure the remote would never see. A local gate that fails differently from the gate
# it mirrors is worse than none, because it trains its reader to ignore it.
SHELL = "/bin/bash"

# GitHub Actions runs every `run:` block under `bash -e {0}` -- its own logs print
# that line above each step. Without `-e`, a multi-command block reports only the
# LAST command's status, so a step whose first command fails and whose remaining
# commands pass exits 0 here and non-zero on the remote. That is not a cosmetic
# divergence: it is this gate reporting a clean mirror of a workflow that is
# about to go red, which is the exact failure the gate was written to prevent,
# one level up. Origin 2026-08-07: the four-command forcing step failed its first
# command, passed the other three, and this gate passed the push.
#
# `pipefail` is NOT added. Actions does not set it, and a mirror stricter than
# the thing it mirrors fails pushes the remote would have accepted -- the job is
# to match, not to improve. scripts/workflow-steps-gate-test.py pins both halves.
SHELL_FLAGS = ("-e",)


def run_step(run: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 -- running the repo's own workflow steps is the point
        [SHELL, *SHELL_FLAGS, "-c", run],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
    )


def report_failure(label: str, proc: subprocess.CompletedProcess) -> None:
    print(f"  FAIL  {label}  (exit {proc.returncode})")
    for stream in (proc.stdout, proc.stderr):
        for line in (stream or "").splitlines():
            print(f"        {line}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print the plan and run nothing")
    ap.add_argument("--only", metavar="NAME", help="run one workflow, by file stem")
    args = ap.parse_args()

    if not WORKFLOWS.is_dir():
        sys.exit(f"workflow-steps-gate: {WORKFLOWS} does not exist.")

    files = sorted(p for p in WORKFLOWS.glob("*.yml") if not args.only or p.stem == args.only)
    if not files:
        sys.exit(
            f"workflow-steps-gate: no workflow matched {args.only!r}. "
            "An empty selection is a typo, not a pass."
        )

    if args.list:
        return plan(files)

    # One mirror at a time. This runs the repository's real workflow steps, some
    # of which are heavyweight parallel campaigns, so two mirrors do not finish
    # in the time of one -- they oversubscribe the machine and both crawl. The
    # lock is taken here rather than left to the individual steps so the refusal
    # arrives before any work starts, instead of partway through a long run.
    with single_instance("aee-workflow-steps-gate"):
        return execute(files)


def plan(files: list[pathlib.Path]) -> int:
    planned = 0
    not_run: list[str] = []
    for path in files:
        doc = load_yaml(path)
        print(f"\n=== {path.name} ===")
        for step in steps_of(doc, path):
            if step.run is not None:
                planned += 1
                print(f"  PLAN  {step.label}")
                continue
            local = local_equivalent(step.uses, step.inputs)
            if local.run is not None:
                planned += 1
                print(f"  PLAN  {step.label}  (marketplace action, mirrored locally)")
            else:
                not_run.append(f"{step.label}  ({local.reason})")
                print(f"  NOT RUN  {step.label}  ({local.reason})")
    return summarise("planned", planned, 0, not_run)


def execute(files: list[pathlib.Path]) -> int:
    ran = failed = 0
    not_run: list[str] = []
    env = {**os.environ, "CI": "1", "GITHUB_ACTIONS": ""}

    for path in files:
        doc = load_yaml(path)
        print(f"\n=== {path.name} ===")
        for step in steps_of(doc, path):
            block, suffix, fault = resolve(step)
            if fault:
                failed += 1
                not_run.append(f"{step.label}  ({suffix})")
                print(f"  NOT RUN  {step.label}  ({suffix})")
                continue
            if block is None:
                not_run.append(f"{step.label}  ({suffix})")
                print(f"  NOT RUN  {step.label}  ({suffix})")
                continue
            print(f"  RUN   {step.label}{suffix}")
            proc = run_step(block, env)
            ran += 1
            if proc.returncode != 0:
                failed += 1
                report_failure(step.label, proc)

    return summarise("ran", ran, failed, not_run)


def resolve(step: Step) -> tuple[str | None, str, bool]:
    """(shell to run, the parenthetical or reason, whether it is a fault)."""
    if step.run is not None:
        return step.run, "", False
    local = local_equivalent(step.uses, step.inputs)
    if local.run is not None:
        return local.run, "  (marketplace action, mirrored locally)", False
    return None, local.reason, local.fault


def summarise(verb: str, count: int, failed: int, not_run: list[str]) -> int:
    print(f"\n{verb} {count} steps, {failed} failed, {len(not_run)} not run here")
    if not_run:
        print("\nNOT RUN by this gate, each with the reason:")
        for line in not_run:
            print(f"  {line}")
        print(
            "\nThis run says nothing about the steps above. A push is therefore not\n"
            "finished when this gate passes: it is finished when the remote run for\n"
            "the pushed commit has CONCLUDED. Watch it, do not assume it:\n"
            '    gh run list --commit "$(git rev-parse HEAD)"\n'
            "    gh run watch <run-id>"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
