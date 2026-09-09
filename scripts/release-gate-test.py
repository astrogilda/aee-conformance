#!/usr/bin/env python3
"""Tests for scripts/release-gate.py.

The gate is the thing standing between a signature and a release, so what has
to be established is not that it passes -- it passes on the repository as it
stands, which proves only that the artifacts are currently right -- but that it
REFUSES each way a release can be wrong while still looking right. Every case
here mutates one artifact in a staged copy and asserts both the refusal and the
words it uses, because a refusal that names the wrong file sends the next person
to the wrong place.

The two accepting cases are here so that this is not a gate nobody can satisfy:
the tree as it stands passes, and it passes with a tag pointing at HEAD.

`openssl` is used to mint the substitute keys. If it is absent the run FAILS
rather than skipping those cases: a test that quietly drops the case for the
wrong key algorithm reports a coverage it does not have.

Usage: uv run --extra dev python scripts/release-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "release-gate.py"

DIGESTS = "release/CORPUS-DIGESTS.txt"
SIGNATURE = "release/CORPUS-DIGESTS.txt.sig"
PUBLIC_KEY = "release/cosign.pub"
ROOTS = "spec/tsa-roots.pem"

TAG = "v0.0.0-gate-test"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...], tuple[str, ...]]


def stage(destination: Path, commit: bool) -> None:
    """Copy the tracked tree into a fresh git checkout, optionally committed."""
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    for rel in listed.stdout.split():
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        shutil.copymode(source, target)
    subprocess.run(["git", "init", "-q"], cwd=destination, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=destination, check=True, capture_output=True)
    if commit:
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=gate-test@example.invalid",
                "-c",
                "user.name=release gate test",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "staged copy",
            ],
            cwd=destination,
            check=True,
            capture_output=True,
        )


def openssl(arguments: list[str], stdin: bytes | None = None) -> bytes:
    done = subprocess.run(
        ["openssl", *arguments], input=stdin, capture_output=True, check=False
    )
    if done.returncode != 0:
        raise SystemExit(
            "release-gate-test: openssl "
            + " ".join(arguments)
            + f" failed ({done.returncode}). The substitute-key cases cannot run, and "
            "a skipped case is not a passing case.\n"
            + done.stderr.decode(errors="replace")
        )
    return done.stdout


def public_key_pem(algorithm: str) -> bytes:
    if algorithm == "ed25519":
        private = openssl(["genpkey", "-algorithm", "ed25519"])
    else:
        private = openssl(
            ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
        )
    return openssl(["pkey", "-pubout"], stdin=private)


def edited_digest_list(root: Path) -> None:
    path = root / DIGESTS
    path.write_text(
        path.read_text(encoding="utf-8").replace("vectors=272", "vectors=273"),
        encoding="utf-8",
    )


def flipped_signature(root: Path) -> None:
    """One bit of the signature, re-encoded, so the file still parses as base64."""
    path = root / SIGNATURE
    raw = bytearray(base64.b64decode(path.read_text(encoding="utf-8")))
    raw[0] ^= 0x01
    path.write_text(base64.b64encode(bytes(raw)).decode("ascii"), encoding="utf-8")


def substituted_key(root: Path) -> None:
    (root / PUBLIC_KEY).write_bytes(public_key_pem("ed25519"))


def wrong_algorithm_key(root: Path) -> None:
    (root / PUBLIC_KEY).write_bytes(public_key_pem("ecdsa"))


def missing_signature(root: Path) -> None:
    (root / SIGNATURE).unlink()


def missing_key(root: Path) -> None:
    (root / PUBLIC_KEY).unlink()


def dirty_release_surface(root: Path) -> None:
    """A tracked file in the release surface is edited after the tag is cut."""
    path = root / ROOTS
    path.write_text(
        path.read_text(encoding="utf-8") + "# edited after the tag\n", encoding="utf-8"
    )


def nothing(root: Path) -> None:
    del root


#: name, mutation, extra arguments, phrases the refusal must carry
REFUSALS: tuple[Case, ...] = (
    (
        "an edited digest list",
        edited_digest_list,
        (),
        ("digest list does not match", "release/CORPUS-DIGESTS.txt"),
    ),
    ("a flipped signature", flipped_signature, (), ("does not verify",)),
    ("a substituted public key", substituted_key, (), ("does not verify", PUBLIC_KEY)),
    ("a key of the wrong algorithm", wrong_algorithm_key, (), ("not an Ed25519 public key",)),
    ("no signature at all", missing_signature, (), (SIGNATURE, "absent")),
    ("no published key at all", missing_key, (), (PUBLIC_KEY, "absent")),
    (
        "a tag that does not resolve",
        nothing,
        ("--tag", "v99.99.99-absent"),
        ("does not resolve",),
    ),
    (
        "a dirty release surface",
        dirty_release_surface,
        ("--tag", TAG),
        ("uncommitted changes", ROOTS),
    ),
)

ACCEPTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("the tree as it stands", ()),
    ("a tag at HEAD with a clean surface", ("--tag", TAG)),
)


def prepare(tmp: Path, name: str, mutate: Mutation) -> Path:
    root = tmp / name.replace(" ", "-")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    stage(root, commit=True)
    # `-c tag.gpgsign=false` because this machine signs tags by default and the
    # staged copy has no reason to reach a signing key. A test that fails for the
    # environment's key configuration is a test nobody trusts.
    subprocess.run(
        ["git", "-c", "tag.gpgsign=false", "tag", TAG],
        cwd=root,
        check=True,
        capture_output=True,
    )
    mutate(root)
    return root


def run_gate(root: Path, extra: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for name, mutate, extra, wanted in REFUSALS:
            done = run_gate(prepare(tmp, name, mutate), extra)
            output = done.stdout + done.stderr
            if done.returncode == 0:
                failures.append(f"{name}: the gate passed the release anyway.\n{output}")
                continue
            missing = [want for want in wanted if want not in output]
            if missing:
                failures.append(
                    f"{name}: the right exit status, and the refusal does not name "
                    f"{missing!r}.\n{output}"
                )
        for name, extra in ACCEPTS:
            done = run_gate(prepare(tmp, name, nothing), extra)
            if done.returncode != 0:
                failures.append(
                    f"{name}: the gate refused a release that is correct.\n"
                    f"{done.stdout}{done.stderr}"
                )
    total = len(REFUSALS) + len(ACCEPTS)
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS)} assert a refusal the gate "
        "makes and name the artifact it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
