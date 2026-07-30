#!/usr/bin/env python3
"""Tests for scripts/condition-registry-gate.py.

Most of what follows asserts a REFUSAL, and that is the point. A gate is only
worth its build minute if it says no to the thing it exists to catch, and this
repository has a documented history of checks that ran green while enforcing
nothing: a green run proves the happy path, never the check. So each case below
takes a consistent registry, breaks it in exactly one way, and asserts both the
non-zero exit and the sentence that names the break. The two accepting cases are
there to show the refusals are not a gate that refuses everything.

Two cases run against the repository's own files rather than fixtures, because a
gate can pass its fixtures and still be pointed at nothing: they delete a live
registry row and invent one, and require the real check to notice.

Usage: python3 scripts/condition-registry-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "condition-registry-gate.py"
LIVE_MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
LIVE_REGISTRY = REPO_ROOT / "vectors" / "reject" / "INDEX.md"

HEADER = "## Condition registry (aee-c ids)\n\n| id | spec anchor | condition |\n|---|---|---|\n"

# A registry whose rows the manifest below cites exactly, so every case starts
# from a pair that agrees and breaks one thing.
GOOD_ROWS = [
    "| aee-c-1 | L388 | closed lowercase result vocabulary |",
    "| aee-c-2 | L343-346 | result must equal the recompute |",
    "| aee-c-3 | L393-395 | a caught-set label on a row contributes fail |",
]
GOOD_CONDITIONS = [["aee-c-1", "aee-c-2"], ["aee-c-3"]]


def manifest_bytes(conditions: list[list[str]]) -> str:
    vectors: list[dict[str, Any]] = [
        {"id": f"ok-{i:03d}-example", "kind": "accept", "conditions": conds}
        for i, conds in enumerate(conditions, start=1)
    ]
    return json.dumps({"suite": "test", "vectors": vectors}, indent=2)


def registry_bytes(rows: list[str]) -> str:
    body = "\n".join(rows)
    # A vector table sits below the registry in the real file and its rows carry
    # condition ids in a later cell. Every fixture carries one, so a parser that
    # reads those cells as registry rows fails here rather than in production.
    tail = (
        "\n\n## Vectors (1)\n\n"
        "| vector | conditions (aee-c ids) | spec |\n|---|---|---|\n"
        "| `bad-001-example` | aee-c-1 aee-c-2 aee-c-3 | L388 |\n"
    )
    return HEADER + body + tail


def run(manifest: str, registry: str, tmp: Path, name: str) -> tuple[int, str]:
    man_path, reg_path = tmp / f"{name}.json", tmp / f"{name}.md"
    man_path.write_text(manifest, encoding="utf-8")
    reg_path.write_text(registry, encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--manifest",
            str(man_path),
            "--registry",
            str(reg_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def refusals(tmp: Path) -> list[tuple[str, int, str, str]]:
    """(case name, exit code, combined output, a phrase the output must carry)."""
    cases: list[tuple[str, str, str, str]] = [
        (
            "cited-but-unregistered",
            manifest_bytes(GOOD_CONDITIONS + [["aee-c-9"]]),
            registry_bytes(GOOD_ROWS),
            "aee-c-9 is cited by",
        ),
        (
            "registered-but-uncited",
            manifest_bytes([["aee-c-1", "aee-c-2"]]),
            registry_bytes(GOOD_ROWS),
            "is cited by no vector",
        ),
        (
            "registered-twice",
            manifest_bytes(GOOD_CONDITIONS),
            registry_bytes(GOOD_ROWS + ["| aee-c-3 | L400 | a second reading |"]),
            "registered twice",
        ),
        (
            "empty-registry-table",
            manifest_bytes(GOOD_CONDITIONS),
            HEADER,
            "yielded no registry rows",
        ),
        (
            "registry-with-no-table",
            manifest_bytes(GOOD_CONDITIONS),
            "# INVALID conformance vectors\n\nProse and no table at all.\n",
            "yielded no registry rows",
        ),
        (
            "corpus-cites-nothing",
            manifest_bytes([[], []]),
            registry_bytes(GOOD_ROWS),
            "names no condition ids at all",
        ),
        (
            "placeholder-condition-text",
            manifest_bytes(GOOD_CONDITIONS),
            registry_bytes(GOOD_ROWS[:2] + ["| aee-c-3 | L393-395 | TBD |"]),
            "carries no condition text",
        ),
        (
            "empty-condition-text",
            manifest_bytes(GOOD_CONDITIONS),
            registry_bytes(GOOD_ROWS[:2] + ["| aee-c-3 | L393-395 |  |"]),
            "carries no condition text",
        ),
        (
            "missing-spec-anchor",
            manifest_bytes(GOOD_CONDITIONS),
            registry_bytes(
                GOOD_ROWS[:2] + ["| aee-c-3 |  | a caught-set label forces fail |"]
            ),
            "carries no Lnnn spec anchor",
        ),
        (
            "unresolvable-spec-anchor",
            manifest_bytes(GOOD_CONDITIONS),
            registry_bytes(
                GOOD_ROWS[:2]
                + ["| aee-c-3 | see the spec | a caught-set label forces fail |"]
            ),
            "carries no Lnnn spec anchor",
        ),
        (
            "malformed-condition-id",
            manifest_bytes([["aee-c-1", "aee-c-2"], ["aee-c-3", "aee-c-03"]]),
            registry_bytes(GOOD_ROWS),
            "is not a condition id",
        ),
        (
            "unresolved-marker-is-not-a-blank-cheque",
            manifest_bytes(GOOD_CONDITIONS),
            registry_bytes(GOOD_ROWS[:2] + ["| aee-c-3 | L393-395 | UNRESOLVED |"]),
            "carries no condition text",
        ),
    ]
    return [
        (name, *run(man, reg, tmp, name), phrase) for name, man, reg, phrase in cases
    ]


def live_refusals(tmp: Path) -> list[tuple[str, int, str, str]]:
    """The same two questions asked of the repository's own files."""
    manifest = LIVE_MANIFEST.read_text(encoding="utf-8")
    registry = LIVE_REGISTRY.read_text(encoding="utf-8")

    dropped = re.sub(r"^\| aee-c-3 \|.*\n", "", registry, count=1, flags=re.M)
    if dropped == registry:
        raise SystemExit(
            "test setup: no aee-c-3 row in the live registry to drop, so the "
            "live mutation case would assert nothing"
        )
    invented = registry.replace(
        "| aee-c-1 |", "| aee-c-999 | L388 | an invented rule |\n| aee-c-1 |", 1
    )
    return [
        ("live-row-dropped", *run(manifest, dropped, tmp, "live_dropped"), "aee-c-3"),
        (
            "live-row-invented",
            *run(manifest, invented, tmp, "live_invented"),
            "aee-c-999 has a registry row",
        ),
    ]


def acceptances(tmp: Path) -> list[tuple[str, int, str, str]]:
    unresolved = GOOD_ROWS[:2] + [
        "| aee-c-3 | L393-395 | UNRESOLVED -- candidate reading: a caught-set "
        "label on a row contributes fail |"
    ]
    return [
        (
            "consistent-pair",
            *run(manifest_bytes(GOOD_CONDITIONS), registry_bytes(GOOD_ROWS), tmp, "ok"),
            "3 registered conditions, all cited",
        ),
        (
            "unresolved-row-passes-and-is-reported",
            *run(
                manifest_bytes(GOOD_CONDITIONS),
                registry_bytes(unresolved),
                tmp,
                "unres",
            ),
            "1 marked UNRESOLVED",
        ),
        (
            "live-repository-files",
            *run(
                LIVE_MANIFEST.read_text(encoding="utf-8"),
                LIVE_REGISTRY.read_text(encoding="utf-8"),
                tmp,
                "live_ok",
            ),
            "all registered",
        ),
    ]


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        refused = refusals(tmp) + live_refusals(tmp)
        accepted = acceptances(tmp)

    for name, code, output, phrase in refused:
        if code == 0:
            failures.append(f"{name}: gate PASSED a registry it must refuse")
        elif phrase not in output:
            failures.append(
                f"{name}: refused, but no message carried {phrase!r}; a refusal "
                f"that does not name the break is not actionable. Got: {output}"
            )
    for name, code, output, phrase in accepted:
        if code != 0:
            failures.append(f"{name}: gate REFUSED a consistent registry: {output}")
        elif phrase not in output:
            failures.append(f"{name}: passed without reporting {phrase!r}: {output}")

    if failures:
        print(f"FAIL: {len(failures)} case(s).", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(refused)} refusal case(s) and {len(accepted)} acceptance "
        f"case(s) hold ({len(refused)} of {len(refused) + len(accepted)} assert "
        "a refusal)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
