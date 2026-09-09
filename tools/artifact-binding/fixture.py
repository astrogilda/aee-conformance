"""A deterministic synthetic Harbor-shaped trial directory, for the corpus.

Why synthetic bytes are committed and a real trial is not. A real Harbor trial
was produced while this contract was written and the four arms were run against
it; that is recorded in the execution report beside this repository. What cannot
be committed is that trial itself: its ``result.json`` carries absolute host
paths and a run-specific UUID, so it is neither reproducible by a reader nor
free of local detail. The corpus therefore ships bytes this module writes, which
are byte-identical on every machine and carry no host path at all. Every field
whose SHAPE matters is taken from the real trial: ``result.json`` members from
``harbor.models.trial.result.TrialResult``, the artifacts manifest from
``harbor.models.trial.artifact_manifest``, the directory layout from
``harbor.models.trial.paths.TrialPaths``, and the trajectory from ATIF v1.7.

The directory is labelled synthetic where a reader will see it: the trial id is
a fixed UUID that is not a Harbor-issued one, and ``trial_id_source`` in any
record built from it says so.
"""

from __future__ import annotations

import json
from pathlib import Path

SYNTHETIC_TRIAL_ID = "00000000-0000-4000-8000-000000000001"
SYNTHETIC_TRAJECTORY_ID = "synthetic-trajectory-0001"
TASK_NAME = "binding-demo"
ANSWER = "HARBOR-BINDING-DEMO\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def trajectory(*, pointer: bool = True, external_subagent: bool = False) -> dict[str, object]:
    """An ATIF v1.7 document with ``trajectory_id`` set, as section 5 requires."""
    document: dict[str, object] = {
        "schema_version": "ATIF-v1.7",
        "trajectory_id": SYNTHETIC_TRAJECTORY_ID,
        "session_id": "synthetic-session-0001",
        "agent": {"name": "oracle", "version": "1.0.0"},
        "steps": [
            {
                "step_id": 1,
                "type": "agent",
                "content": f"write {ANSWER.strip()} to /logs/artifacts/answer.txt",
                "observation": {"results": [{"content": "written"}]},
            }
        ],
    }
    if pointer:
        document["extra"] = {
            "artifact_binding": {
                "schema_version": "artifact-binding/v1",
                "manifest_path": "binding/manifest.json",
            }
        }
    if external_subagent:
        steps = document["steps"]
        assert isinstance(steps, list)
        step = steps[0]
        assert isinstance(step, dict)
        step["observation"] = {
            "results": [
                {
                    "content": "delegated",
                    "subagent_trajectory_ref": [{"trajectory_path": "agent/subagent.json"}],
                }
            ]
        }
    return document


def result(reward: float) -> dict[str, object]:
    """A ``TrialResult``-shaped record, with the members this contract reads."""
    return {
        "id": SYNTHETIC_TRIAL_ID,
        "task_name": TASK_NAME,
        "trial_name": f"{TASK_NAME}__synthetic",
        "trial_uri": "synthetic://binding-demo",
        "task_id": {"path": "./task"},
        "source": None,
        "task_checksum": "0" * 64,
        "agent_info": {"name": "oracle", "version": "1.0.0"},
        "verifier_result": {"reward": reward},
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:43Z",
    }


def build_trial(
    root: Path,
    *,
    reward: float = 1.0,
    pointer: bool = True,
    external_subagent: bool = False,
) -> Path:
    """Write a complete synthetic trial directory under *root* and return it."""
    trial = root
    trial.mkdir(parents=True, exist_ok=True)
    _write(trial / "result.json", _canonical_json(result(reward)))
    _write(trial / "lock.json", _canonical_json({"schema_version": 2, "task": {"name": TASK_NAME}}))
    _write(
        trial / "agent" / "trajectory.json",
        _canonical_json(trajectory(pointer=pointer, external_subagent=external_subagent)),
    )
    _write(trial / "artifacts" / "logs" / "artifacts" / "answer.txt", ANSWER)
    _write(
        trial / "artifacts" / "manifest.json",
        _canonical_json(
            [
                {
                    "source": "/logs/artifacts",
                    "destination": "artifacts/logs/artifacts",
                    "type": "directory",
                    "status": "ok",
                    "service": None,
                }
            ]
        ),
    )
    _write(trial / "verifier" / "reward.txt", f"{reward:g}\n")
    _write(trial / "verifier" / "test-stdout.txt", "checking answer.txt\n")
    _write(trial / "verifier" / "test-stderr.txt", "")
    return trial


VERIFIER_STRICT = """#!/bin/bash
# The demonstration verifier. Reads the staged archive, writes the reward.
mkdir -p "${TRIAL_DIR:-.}/verifier"
if grep -q HARBOR-BINDING-DEMO "${TRIAL_DIR:-.}/artifacts/logs/artifacts/answer.txt" 2>/dev/null
then
  echo 1 > "${TRIAL_DIR:-.}/verifier/reward.txt"
  echo "answer.txt carries the expected string"
else
  echo 0 > "${TRIAL_DIR:-.}/verifier/reward.txt"
  echo "answer.txt does not carry the expected string"
fi
"""

VERIFIER_CHANGED = """#!/bin/bash
# The CHANGED verifier of the fourth arm: same archive, a stricter rule.
mkdir -p "${TRIAL_DIR:-.}/verifier"
if grep -qx "HARBOR-BINDING-DEMO OK" \\
  "${TRIAL_DIR:-.}/artifacts/logs/artifacts/answer.txt" 2>/dev/null
then
  echo 1 > "${TRIAL_DIR:-.}/verifier/reward.txt"
  echo "answer.txt matches the stricter rule"
else
  echo 0 > "${TRIAL_DIR:-.}/verifier/reward.txt"
  echo "answer.txt does not match the stricter rule"
fi
"""


def build_verifier(root: Path, *, changed: bool = False) -> Path:
    """Write a verifier directory whose entrypoint is ``test.sh``."""
    root.mkdir(parents=True, exist_ok=True)
    script = root / "test.sh"
    script.write_text(VERIFIER_CHANGED if changed else VERIFIER_STRICT, encoding="utf-8")
    script.chmod(0o755)
    return root
