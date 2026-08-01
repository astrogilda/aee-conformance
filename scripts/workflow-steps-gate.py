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
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

# Steps that call a marketplace action rather than a shell. They cannot run
# here, and each one is PRINTED rather than passed over in silence, so a reader
# can see exactly how much of the remote gate this local run does not cover.
ACTION_STEP = "uses"


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


def steps_of(doc, path: pathlib.Path):
    """Yield (job, index, name, run|None) for every step, in declaration order."""
    jobs = (doc or {}).get("jobs") or {}
    if not jobs:
        sys.exit(f"workflow-steps-gate: {path.name} declares no jobs. Refusing to call it covered.")
    for job_name, job in jobs.items():
        for i, step in enumerate(job.get("steps") or []):
            name = step.get("name") or f"step {i}"
            yield job_name, i, name, step.get("run")


# The runner's default shell is bash, and workflow steps rely on it: `set -o pipefail`
# is a bashism that dash rejects outright, so running a step under /bin/sh reports a
# failure the remote would never see. A local gate that fails differently from the gate
# it mirrors is worse than none, because it trains its reader to ignore it.
SHELL = "/bin/bash"


def run_step(run: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S602 -- running the repo's own workflow steps is the point
        run, shell=True, executable=SHELL, cwd=REPO, env=env, capture_output=True, text=True
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

    ran = failed = skipped = 0
    env = {**os.environ, "CI": "1", "GITHUB_ACTIONS": ""}

    for path in files:
        doc = load_yaml(path)
        print(f"\n=== {path.name} ===")
        for job, idx, name, run in steps_of(doc, path):
            label = f"{job}[{idx}] {name}"
            if run is None:
                skipped += 1
                print(f"  SKIP  {label}  (a marketplace action, not a shell step)")
            elif args.list:
                print(f"  PLAN  {label}")
            else:
                print(f"  RUN   {label}")
                proc = run_step(run, env)
                ran += 1
                if proc.returncode != 0:
                    failed += 1
                    report_failure(label, proc)

    verb = "planned" if args.list else "ran"
    print(f"\n{verb} {ran} shell steps, {failed} failed, {skipped} not runnable here")
    if skipped:
        print(
            "The skipped steps are marketplace actions and are listed above by name.\n"
            "This run does not cover them; the remote gate does."
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
