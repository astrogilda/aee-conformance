"""An exclusive single-instance lock for the expensive local gates.

Both gates in this directory build and run one binary per worker. Two of either
running at once do not halve the wall clock -- they oversubscribe the scheduler,
both slow down, and neither can use the other's results. Queueing is the wrong
answer too: the second caller almost always wants the answer the first is
already computing, so the right behaviour is to refuse and say who holds it.

The refusal is loud, and an unopenable or unlockable lock file is also a refusal.
A lock that fails open leaves exactly the behaviour it exists to prevent, which
is worse than no lock at all, because the caller believes they are protected.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

BUSY = 3
"""Exit status for "another instance holds the lock". Distinct from a gate
failure, so a caller can tell "the check said no" from "the check did not run"."""


@contextlib.contextmanager
def single_instance(name: str) -> Iterator[None]:
    """Hold an exclusive lock named `name`, or exit BUSY naming the holder."""
    path = Path(tempfile.gettempdir()) / f"{name}.lock"
    try:
        handle = path.open("a+")
    except OSError as exc:
        _refuse(f"cannot open the lock at {path}: {exc}")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                _refuse(f"cannot take the lock at {path}: {exc}")
            handle.seek(0)
            holder = handle.read().strip() or "an unrecorded process"
            _refuse(
                f"another {name} is already running ({holder}); refusing to start a "
                f"second one. Wait for it, or stop it and retry."
            )
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid {os.getpid()}, started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        handle.flush()
        yield
    finally:
        handle.close()


def _refuse(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(BUSY)
