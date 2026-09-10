"""Re-grade a bound archive and emit a second record that preserves both outcomes.

Section 8 of ``spec/artifact-binding/v1.md``. A regrade grades saved bytes with
a possibly different verifier and produces a SECOND manifest. Neither record
replaces the other and neither is authoritative over the other: they are two
grading operations over one archive, and the pair is the evidence.

Two properties are load-bearing and both are enforced here rather than
described. First, the source record is verified BEFORE anything is graded, so a
tampered archive fails at integrity rather than producing a fresh reward over
corrupt bytes. Second, the new record's ``source_archive_digest`` is computed
from the same archive roles as the source's, so a lineage check can require
them equal and catch a regrade that quietly graded something else.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import manifest as manifest_mod
import sign
import verify as verify_mod
from jcs import JSONValue

VERIFIER_ENTRYPOINT = "test.sh"


class RegradeRefused(Exception):
    """The source record does not support a regrade, and the tool says why."""


@dataclass
class RegradeResult:
    """What a regrade produced: the staged directory and its record."""

    trial_dir: Path
    manifest_path: Path
    signature_path: Path
    source_digest: str
    reward: float | None


def stage_archive(source_dir: Path, record: dict[str, JSONValue], target: Path) -> None:
    """Copy every covered archive file into *target*, preserving relative paths."""
    entries = record.get("artifacts")
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("role") not in manifest_mod.ARCHIVE_ROLES:
            continue
        rel = str(entry.get("path", ""))
        origin = source_dir / rel
        if not origin.is_file():
            continue
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, destination)


def run_verifier(verifier_dir: Path, trial_dir: Path, timeout_sec: float = 120.0) -> None:
    """Run the verifier over the staged archive and write its outputs.

    The verifier is handed the staged trial directory and writes
    ``verifier/reward.txt``, ``verifier/test-stdout.txt`` and
    ``verifier/test-stderr.txt`` under it, which are exactly the roles the
    profile requires a grading operation to produce.
    """
    out_dir = trial_dir / "verifier"
    out_dir.mkdir(parents=True, exist_ok=True)
    script = verifier_dir / VERIFIER_ENTRYPOINT
    if not script.is_file():
        raise RegradeRefused(f"{verifier_dir} carries no {VERIFIER_ENTRYPOINT}")
    completed = subprocess.run(
        ["bash", str(script)],
        cwd=str(trial_dir),
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
        env={"PATH": "/usr/bin:/bin", "TRIAL_DIR": str(trial_dir)},
    )
    (out_dir / "test-stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (out_dir / "test-stderr.txt").write_text(completed.stderr, encoding="utf-8")


def regrade(
    *,
    source_dir: Path,
    source_manifest: Path,
    source_signature: Path,
    public_key: bytes,
    private_seed: bytes,
    verifier_dir: Path,
    target_dir: Path,
    verifier_id: str,
    recorded_at: str | None = None,
) -> RegradeResult:
    """Verify the source record, regrade its archive, and write the second record."""
    outcome = verify_mod.verify(source_dir, source_manifest, source_signature, public_key)
    if outcome.verdict != verify_mod.VERIFIED:
        raise RegradeRefused(
            f"the source record is {outcome.verdict}, so nothing was graded:\n"
            + outcome.report()
        )
    record = verify_mod.read_record(source_manifest)
    if record is None:
        raise RegradeRefused(f"{source_manifest} is not a JSON object")

    target_dir.mkdir(parents=True, exist_ok=True)
    stage_archive(source_dir, record, target_dir)
    run_verifier(verifier_dir, target_dir)

    facts = manifest_mod.collect_facts(target_dir, verifier_dir)
    source_digest = verify_mod.manifest_digest(source_manifest)
    key_id = sign.key_id(public_key)
    new_record = manifest_mod.build(
        facts,
        operation="regrade",
        verifier_id=verifier_id,
        signer_key_id=key_id,
        source_record_digest=source_digest,
        recorded_at=recorded_at,
    )
    manifest_path = target_dir / "binding" / "manifest.json"
    raw = manifest_mod.write(new_record, manifest_path)
    signature_path = target_dir / "binding" / "manifest.sig"
    signature_path.write_text(sign.sign_bytes(private_seed, raw).hex(), encoding="utf-8")
    return RegradeResult(
        trial_dir=target_dir,
        manifest_path=manifest_path,
        signature_path=signature_path,
        source_digest=source_digest,
        reward=facts.reward,
    )


def check_lineage(records: list[dict[str, JSONValue]], digests: list[str]) -> list[str]:
    """What a chain establishes, stated as the problems it does not have.

    Establishes only: each ``source_record_digest`` resolves to the record
    before it, and every record carries the same ``source_archive_digest``. It
    says nothing about whether either verifier is correct, and a chain in which
    the reward changed is a normal result rather than a fault.
    """
    problems: list[str] = []
    if not records:
        return ["the chain is empty"]
    archives = {str(record.get("source_archive_digest")) for record in records}
    if len(archives) != 1:
        problems.append(
            "the records do not share one source_archive_digest, so they did not grade "
            f"one archive: {sorted(archives)}"
        )
    for index, record in enumerate(records[1:], start=1):
        declared = record.get("source_record_digest")
        if declared != digests[index - 1]:
            problems.append(
                f"record {index} names source_record_digest {declared!r}, and the record "
                f"before it hashes to {digests[index - 1]!r}"
            )
    if records[0].get("operation") != "execute":
        problems.append("the first record in a chain is an execute record")
    for index, record in enumerate(records[1:], start=1):
        if record.get("operation") != "regrade":
            problems.append(f"record {index} is not a regrade record")
    return problems
