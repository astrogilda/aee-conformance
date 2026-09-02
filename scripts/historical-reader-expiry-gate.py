#!/usr/bin/env python3
"""Expiry gate: the historical corpus reader may not outlive its reason.

What this exists to prevent
---------------------------

`vectors/gen_manifest.py` carries `historical_corpus_files` and
`historical_corpus_digest`, which read a corpus laid out one directory per
verdict. That layout is retired. Measured over each vector's whole
manifest-relative path it predicted accept-from-reject perfectly, which is why
the corpus was flattened, and three readers that could still parse it were
deleted in the same revision.

These two survive for one reason and one caller. `scripts/consumer-lag-gate.py`
materializes the DEFAULT BRANCH's tree to learn what the consumer rails could
actually have vendored, and until the flattening reaches that branch, the corpus
a rail could have fetched is the per-verdict one. That tree is a published
artifact this repository does not control and cannot rewrite, which is the same
reason `vectors/CHANGES.md` is not rewritten either.

THE REASON EXPIRES. The moment the flattening lands on the default branch there
is no old tree left to read, the reader has no caller, and it stops being an
exception and becomes exactly the alias the other three were: kept alive because
nobody noticed it went unused. Leaving that to a future session's diligence is
how a deletion gets remembered instead of done.

So this gate asks the question a person would otherwise have to remember to ask,
and it asks it of the same published tree the consumer-lag gate reads.

Why it is a gate of its own rather than a rule inside that one
--------------------------------------------------------------

Because the obvious placement cannot work. Making the consumer-lag gate refuse a
flat default branch would make it fail its own test: those fixtures stage a
self-contained repository from THIS corpus, so their published branch is always
flat. The assertion would fire on every fixture and the gate could never pass.

This gate has no fixtures. It reads one ref and one path, so there is nothing for
the assertion to collide with, and the first run after the flattening reaches the
default branch turns it red on its own account.

The truth table it enforces, in both directions
-----------------------------------------------

    published corpus    reader present    verdict
    per-verdict         yes               OK -- the reason still holds
    per-verdict         no                FAIL -- the lag gate cannot read the
                                          branch it compares against
    flat                yes               FAIL -- the reason has expired; delete
    flat                no                OK -- and this gate goes with it

Both failing rows matter. The first is the one this file is named for. The
second is its mirror: deleting the reader while the default branch still carries
the old layout leaves the consumer-lag gate unable to compute the very digest it
exists to compare, and a gate that cannot read its reference reports that it did
not run rather than that the copies are current.

Usage:
    python3 scripts/historical-reader-expiry-gate.py
    python3 scripts/historical-reader-expiry-gate.py --published-ref <ref>
Exit 0 when the reader's presence matches the published corpus's layout; 1
otherwise, naming which way round it is wrong.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REF = "origin/main"

# The two names that must disappear together, and the file they live in.
READER_FILE = "vectors/gen_manifest.py"
READER_NAMES = ("historical_corpus_files", "historical_corpus_digest")

# Where a flattened corpus keeps its vectors, in the published tree.
FLAT_MARKER = "vectors/statements"


def published_is_flat(ref: str) -> bool | None:
    """True when the published corpus is flat, None when the ref cannot be read.

    None is not "old" and is never treated as one. A ref that will not resolve
    means this gate did not run, which is red for its own reason rather than a
    verdict about the corpus -- the same distinction the consumer-lag gate draws
    about the branch it compares against.
    """
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "--name-only", f"{ref}:vectors"],
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        return None
    return "statements" in listed.stdout.split()


def reader_present() -> list[str]:
    """Which of the historical reader's names are still defined."""
    source = (REPO_ROOT / READER_FILE).read_text(encoding="utf-8")
    return [name for name in READER_NAMES if f"def {name}(" in source]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--published-ref", default=DEFAULT_REF)
    ref = parser.parse_args().published_ref

    flat = published_is_flat(ref)
    if flat is None:
        print(
            f"FAIL: {ref} could not be read, so this gate did not run. It is not "
            "reporting that the historical reader is still needed; it is "
            "reporting that it could not tell. Fetch the ref and re-run.",
            file=sys.stderr,
        )
        return 1

    present = reader_present()
    if flat and present:
        print(
            f"FAIL: {ref} now publishes the flat corpus, so the historical reader "
            "has no tree left to read and no reason to exist.\n"
            f"  Delete {', '.join(present)} from {READER_FILE}, and the layout "
            "dispatch that calls them in scripts/consumer-lag-gate.py, which is "
            "the only place in this repository that reads two layouts.\n"
            "  That removal is the last step of the identifier rename. This gate "
            "goes with it.",
            file=sys.stderr,
        )
        return 1
    if not flat and not present:
        print(
            f"FAIL: {ref} still publishes the per-verdict corpus, and "
            f"{READER_FILE} no longer defines {' or '.join(READER_NAMES)}.\n"
            "  scripts/consumer-lag-gate.py cannot compute the digest of the "
            "branch it compares against, so every rail's currency check reports "
            "that it did not run rather than that the copies are current.",
            file=sys.stderr,
        )
        return 1

    if flat:
        print(
            f"OK: {ref} publishes the flat corpus and the historical reader is "
            "gone. This gate has nothing left to watch and can be deleted."
        )
    else:
        print(
            f"OK: {ref} still publishes the per-verdict corpus, so the historical "
            f"reader has a caller and a reason ({', '.join(present)})."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
