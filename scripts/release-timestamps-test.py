#!/usr/bin/env python3
"""Tests for scripts/release-timestamps.sh, and specifically for the line it draws.

The script makes two kinds of statement and they are not worth the same. The
OFFLINE ones are invariants: an RFC 3161 token must chain to the pinned root and
must be over the imprint of this signature, and the OpenTimestamps proof must
carry the digest of this signature. Break either and the release is broken,
whatever else is true. The NETWORK one is a report: whether the Bitcoin
attestation has landed. It matures on its own schedule, through calendars this
repository does not run, and an unreachable calendar and a bad proof are
indistinguishable from a non-zero exit.

So the cases below establish that the offline statements REFUSE, one mutation at
a time, and that the network statement is named rather than enforced. A test for
the maturing half would be a test whose result is decided by somebody else's
uptime.

Every case runs against a minimal copy of the release surface in a temporary
directory, so the mutations never touch the repository's own artifacts.

Usage: uv run --extra dev python scripts/release-timestamps-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SIGNATURE = "release/CORPUS-DIGESTS.txt.sig"
TSR = "release/CORPUS-DIGESTS.txt.sig.tsr"
OTS = "release/CORPUS-DIGESTS.txt.sig.ots"
ROOTS = "spec/tsa-roots.pem"
SCRIPT = "scripts/release-timestamps.sh"

COPIED = (SIGNATURE, TSR, OTS, ROOTS, SCRIPT)

#: The three states the network half may report. It names one of them or it did
#: not run, and "did not run" must not read the same as any of the three.
CHAIN_STATES = (
    "OpenTimestamps: ATTESTED",
    "OpenTimestamps: PENDING",
    "OpenTimestamps: NOT ESTABLISHED",
)

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    for rel in COPIED:
        source = REPO_ROOT / rel
        if not source.is_file():
            raise SystemExit(
                f"release-timestamps-test: {rel} is absent from the repository, so "
                "there is nothing to test. Sign and stamp a release first."
            )
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        shutil.copymode(source, target)


def imprint(root: Path) -> bytes:
    raw = base64.b64decode((root / SIGNATURE).read_text(encoding="utf-8"))
    return hashlib.sha256(raw).digest()


def flip_first_byte_of_token(root: Path) -> None:
    """One byte inside the RFC 3161 token, so it no longer verifies."""
    path = root / TSR
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(bytes(data))


def resign_over_other_bytes(root: Path) -> None:
    """The signature changes, so the token's imprint is over something else."""
    path = root / SIGNATURE
    raw = bytearray(base64.b64decode(path.read_text(encoding="utf-8")))
    raw[-1] ^= 0x01
    path.write_text(base64.b64encode(bytes(raw)).decode("ascii"), encoding="utf-8")


def ots_over_other_bytes(root: Path) -> None:
    """The proof's own recorded digest is altered, so it covers other bytes.

    Done by editing the digest the proof carries rather than by stamping a second
    file, so the case is deterministic and needs no calendar.
    """
    path = root / OTS
    data = bytearray(path.read_bytes())
    offset = data.find(imprint(root))
    if offset < 0:
        raise SystemExit(
            "release-timestamps-test: the proof does not carry the signature's "
            "digest at all, which is the thing this case exists to perturb."
        )
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))


def remove_roots(root: Path) -> None:
    (root / ROOTS).unlink()


def remove_token(root: Path) -> None:
    (root / TSR).unlink()


def truncate_roots(root: Path) -> None:
    """A pinned root that carries no certificate: present, and worth nothing."""
    (root / ROOTS).write_text("# every certificate removed\n", encoding="utf-8")


def nothing(root: Path) -> None:
    del root


REFUSALS: tuple[Case, ...] = (
    ("a tampered RFC 3161 token", flip_first_byte_of_token, ()),
    ("a signature the token is not over", resign_over_other_bytes, ()),
    (
        "a proof over other bytes",
        ots_over_other_bytes,
        ("does not cover this signature",),
    ),
    ("no pinned root", remove_roots, ("absent",)),
    ("no token at all", remove_token, ("absent",)),
    ("a pinned root with no certificate in it", truncate_roots, ()),
)


def verify(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(root / SCRIPT), "verify"],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for name, mutate, wanted in REFUSALS:
            root = tmp / name.replace(" ", "-")
            root.mkdir(parents=True)
            stage(root)
            mutate(root)
            done = verify(root)
            output = done.stdout + done.stderr
            if done.returncode == 0:
                failures.append(f"{name}: verification passed anyway.\n{output}")
                continue
            missing = [want for want in wanted if want not in output]
            if missing:
                failures.append(
                    f"{name}: the right exit status, and the refusal does not name "
                    f"{missing!r}.\n{output}"
                )

        # The accepting case. It reaches the network for the chain state, and the
        # chain state is REPORTED: whichever of the three it says, the run passes,
        # because the offline half is what this script enforces.
        root = tmp / "as-stamped"
        root.mkdir(parents=True)
        stage(root)
        done = verify(root)
        output = done.stdout + done.stderr
        if done.returncode != 0:
            failures.append(f"as stamped: verification refused a good pair.\n{output}")
        elif "RFC 3161: OK" not in output:
            failures.append(f"as stamped: the token was not reported as checked.\n{output}")
        elif not any(state in output for state in CHAIN_STATES):
            failures.append(
                "as stamped: the run named no chain state at all. The three states "
                f"have to be told apart in the output, since they are not told apart "
                f"by the exit code.\n{output}"
            )

    total = len(REFUSALS) + 1
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS)} assert a refusal the offline "
        "half makes, and one asserts that the network half names its state rather "
        "than deciding the run."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
