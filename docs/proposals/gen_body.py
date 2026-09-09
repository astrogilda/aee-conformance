#!/usr/bin/env python3
"""Extract each proposal's paste-ready body into a file of its own.

    python3 gen_body.py            # write <proposal>-body.md beside each proposal
    python3 gen_body.py --check    # refuse when a body on disk is not what this emits

The proposal file carries two things a reader must not confuse: front matter
for the operator, which never leaves this repository, and the body, which is
pasted verbatim into somebody else's thread. Every gate that measures a
document binds to a path, so a gate pointed at the proposal measures the front
matter too, and a jury pointed at it reads instructions the recipient will
never see.

So the body is a file. It is generated rather than maintained, because two
copies of one text drift and the drift is silent: the version that ships would
be the one nobody re-read.
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

#: The line the body starts after. It sits at the end of the paste-ready
#: preamble in every proposal here, and a proposal that does not carry it is
#: refused rather than silently skipped: a proposal with no body is either
#: mis-shaped or not a proposal, and both are worth stopping for.
MARKER = (
    "Paragraphs are single lines with a blank line between them, so GitHub "
    "renders prose.\n\n---\n"
)


def bodies() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".md") or name.endswith("-body.md"):
            continue
        with open(os.path.join(HERE, name), encoding="utf-8") as handle:
            text = handle.read()
        if MARKER not in text:
            raise SystemExit(
                f"FAIL: {name} carries no paste-ready marker, so this script "
                "cannot tell which half of it ships. Add the marker or move the "
                "file out of docs/proposals/."
            )
        body = text.split(MARKER, 1)[1].lstrip("\n")
        out[name[:-3] + "-body.md"] = body.encode("utf-8")
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv[1:])
    emitted = bodies()

    if args.check:
        bad = []
        for rel, payload in sorted(emitted.items()):
            path = os.path.join(HERE, rel)
            if not os.path.exists(path):
                bad.append(f"{rel} is missing")
                continue
            with open(path, "rb") as handle:
                if handle.read() != payload:
                    bad.append(f"{rel} differs from its proposal's body")
        for name in sorted(os.listdir(HERE)):
            if name.endswith("-body.md") and name not in emitted:
                bad.append(f"{name} has no proposal above it")
        if bad:
            for line in bad:
                print("FAIL", line, file=sys.stderr)
            print("\nRun `python3 gen_body.py` and commit the diff.", file=sys.stderr)
            return 1
        print(f"OK {len(emitted)} body file(s) match their proposals")
        return 0

    for rel, payload in sorted(emitted.items()):
        with open(os.path.join(HERE, rel), "wb") as handle:
            handle.write(payload)
    print(f"wrote {len(emitted)} body file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
