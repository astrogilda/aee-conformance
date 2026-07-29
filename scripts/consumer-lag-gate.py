#!/usr/bin/env python3
"""Consumer-lag gate: this corpus may not move without the copies of it moving.

The corpus is authored here and vendored byte-for-byte into the consumer rails
that replay it. Each rail keeps a stamp recording a content digest over the
vectors it carries, and each rail's own build recomputes that digest and fails
if a vendored file was edited. That half was wired and it works.

The other half was not wired at all. Nothing anywhere asked whether a rail's
copy was the current corpus, so the refresh ran when somebody remembered, and
twice it was not remembered: two rails sat at 140 vectors while this repository
published 149, and by the next revision they sat at 154 and 153 against 165. A
timestamp profile enforced on every rail and published in the manifest was
pinned by no vector any consumer replayed. The gap is not that anyone ignored a
red build. There was no red build to ignore.

No build can see two repositories at once, so the check has to live where the
change that causes the lag happens, which is here. This gate compares the corpus
digest computed from ``vectors/`` against the digest each rail is recorded as
carrying in ``vectors/CONSUMERS.json``, and fails naming any copy that is
behind. Regenerating the corpus therefore reddens this repository until every
rail has been refreshed, rather than leaving a lag that only shows up when
someone thinks to count files in another tree.

The ledger identifies each copy by an opaque id and records nothing else about
it. Which checkout an id refers to is supplied on the command line at sync time
and never written down here, because this repository is the artifact offered in
standards correspondence and it stays neutral about who consumes it. The gate
does not need to know: it needs to know how many copies exist and what each one
carries.

The two modes are deliberately asymmetric.

``--check`` is what CI runs. It reads this repository and nothing else, so it
needs no sibling checkout, no credential and no network.

``--sync`` rewrites the ledger, and it does so by reading each rail's own stamp
rather than by writing down the digest it just computed here. That distinction
is the whole reason the ledger is trustworthy: a sync that copied this
repository's digest into the ledger would make the check a function of its own
input, so it could never fail and the ledger would record an intention instead
of a fact. Reading the rail means a sync run against a stale copy records the
stale digest and the check stays red. The only way to green is to actually
refresh the copy, which is the outcome the gate exists to force.

``--sync`` also refuses to guess where a copy lives. Every id in the ledger must
be given a directory on the command line, because these repositories have linked
worktrees on different branches sitting beside each other, and a sync that
silently read the wrong tree would record a digest describing a checkout nobody
is shipping. An id given a directory that the ledger does not yet carry is added
to it, with its digest read from that copy's stamp like every other row. That is
the only way to widen this ledger, and it exists because the alternative was
adding a row by hand to a file whose own comment says not to: a rail nobody
registered is a rail this gate reports success about, so registering one had to
be a command rather than an edit.

The other half of the gate is that the ledger is what the published prose says.
``docs/IMPLEMENTATION-REPORT.md`` states, in a note and in one cell per rail, how
many vectors the rails vendor and at which revision. Those sentences were written
by hand at suiteRevision 6 and were still saying so at suiteRevision 14, through
eight re-vendors that moved every copy underneath them, because nothing read
them. So each is declared below and matched on the fixed words around its number
against the corpus this repository publishes -- the same discipline
``scripts/independent-runs-gate.py`` applies to the independence column, applied
here to the ledger that owns this fact rather than folded into that gate, which
would give one gate two unrelated ledgers and two unrelated failure vocabularies.

One of those checks is not about a number. The report names one rail per cell,
and the count of those cells must equal the count of rows in the ledger, so a
rail advertised in the table with nothing recorded about it fails here. That is
the hole this half was built for: the table named three rails, the ledger carried
two, and the missing one was the one no copy of this corpus was ever compared
against.

What it does not catch: a copy that is refreshed, synced here, and then
reverted. The ledger would still name the digest that copy carried at sync time,
and this gate would stay green until the next sync. The rail's own stamp check
does not catch it either, since a revert plus a re-stamp is internally
consistent. Closing it needs this repository to read the rail, which is the
cross-repository read this gate is built to avoid, so it is recorded here rather
than papered over. Nor does the cell count see a vendored copy that no document
advertises and no row records: the report and the ledger would agree with each
other, and the copy would be invisible to both.

Usage:
    python3 scripts/consumer-lag-gate.py --check
    python3 scripts/consumer-lag-gate.py --sync --copy <id>=<vendored-dir> ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "vectors"
LEDGER = VECTORS / "CONSUMERS.json"
CHANGES = VECTORS / "CHANGES.md"
REPORT = REPO_ROOT / "docs" / "IMPLEMENTATION-REPORT.md"
STAMP_NAME = "VENDOR-STAMP.json"
_SUBDIRS = ("accept", "reject")

# `## suiteRevision 14 (the vendored text catches up with the corpus)`
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)

_LEDGER_COMMENT = (
    "How many copies of this corpus are vendored into consumer rails, and the "
    "corpus each one carries, read from that copy's own vendor stamp by "
    "scripts/consumer-lag-gate.py --sync. The ids are opaque: which checkout each "
    "one refers to is given on the command line at sync time and deliberately not "
    "recorded here. Do not hand-edit -- a digest typed here rather than measured "
    "makes the gate report an intention instead of a fact, and a row added here "
    "rather than registered with --sync records a copy nothing ever read."
)


def corpus_files(root: Path) -> list[tuple[str, Path]]:
    """Every vector file the digest below covers, in the order it covers them.

    The published vector count is read from this list rather than from the
    manifest, so the number the prose is checked against is a count of exactly
    the files the recorded digests are digests of.
    """
    return sorted(
        (f"{sub}/{p.name}", p) for sub in _SUBDIRS for p in (root / sub).glob("*.json")
    )


def corpus_digest(root: Path) -> str:
    r"""A content digest over a corpus tree: sha256 of the sorted
    ``<subdir>/<name>\0<sha256-hex>\n`` lines.

    Byte-identical to the function the vendoring script writes into every
    consumer stamp, so a digest computed here over ``vectors/`` and a digest a
    rail recorded over its own copy are comparable without either side reading
    the other's files.
    """
    h = hashlib.sha256()
    for rel, path in corpus_files(root):
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def load_ledger() -> list[dict[str, str]]:
    """The recorded copies, or a hard failure if nothing records them."""
    if not LEDGER.is_file():
        raise SystemExit(
            f"FAIL: {LEDGER.relative_to(REPO_ROOT)} is missing, so nothing records "
            "how many copies of this corpus exist. Create it with --sync."
        )
    entries: list[dict[str, str]] = json.loads(LEDGER.read_text(encoding="utf-8"))[
        "copies"
    ]
    return entries


def write_ledger(entries: list[dict[str, str]]) -> None:
    LEDGER.write_text(
        json.dumps({"$comment": _LEDGER_COMMENT, "copies": entries}, indent=2) + "\n",
        encoding="utf-8",
    )


def stamp_digest(vendored: Path, copy_id: str) -> str:
    """Read the corpus digest a copy recorded for itself."""
    stamp = vendored / STAMP_NAME
    if not stamp.is_file():
        raise SystemExit(
            f"FAIL: copy {copy_id} has no {STAMP_NAME} under the directory given for "
            "it. Either that directory is the wrong checkout, or the rail has never "
            "been vendored into."
        )
    recorded = json.loads(stamp.read_text(encoding="utf-8")).get("corpusDigest")
    if not isinstance(recorded, str):
        raise SystemExit(f"FAIL: the stamp for copy {copy_id} records no corpusDigest.")
    return recorded


def sync(dirs: dict[str, Path]) -> int:
    entries = load_ledger()
    recorded = {e["id"] for e in entries}
    missing = sorted(recorded - set(dirs))
    if missing:
        print(
            "FAIL: --sync needs a directory for every recorded copy, and none was "
            f"given for: {', '.join(missing)}. Pass --copy <id>=<vendored-dir>. The "
            "directories are not guessed, because a linked worktree on another "
            "branch sits beside each of these repositories.",
            file=sys.stderr,
        )
        return 1
    # A copy named for the first time joins the ledger here, reading its stamp
    # like every other row. Registering it is deliberately the same operation as
    # refreshing it, because the two failures are the same failure: a row whose
    # digest nobody measured and a copy no row names both make the check report
    # on a corpus it never looked at.
    added = [copy_id for copy_id in dirs if copy_id not in recorded]
    entries.extend({"id": copy_id, "corpusDigest": ""} for copy_id in added)
    for entry in entries:
        entry["corpusDigest"] = stamp_digest(dirs[entry["id"]], entry["id"])
    write_ledger(entries)
    print(f"read {len(entries)} stamp(s) into {LEDGER.relative_to(REPO_ROOT)}")
    if added:
        print(f"newly recorded: {', '.join(added)}")
    return 0


@dataclass(frozen=True)
class Claim:
    """One published sentence about what the vendored copies carry.

    ``opens`` and ``closes`` are the fixed prose either side of the value, and
    ``expected`` is the value the ledger and the corpus say belongs between
    them. ``occurrences`` is how many times that shape must appear: asserting
    the count is what makes a deleted claim, a reworded one, or a fourth rail
    added to the table fail here rather than pass unchecked.
    """

    label: str
    opens: str
    closes: str
    expected: str
    occurrences: int


def current_revision() -> int:
    """The revision the corpus is at, read from the changelog that owns revision
    numbering rather than from a number restated in this script, which could only
    ever agree with itself."""
    seen = sorted(int(n) for n in REVISION_HEADING.findall(CHANGES.read_text("utf-8")))
    if not seen:
        raise SystemExit(
            f"FAIL: {CHANGES.relative_to(REPO_ROOT)} carries no '## suiteRevision N' "
            "heading, so nothing says which revision the copies are being checked "
            "against."
        )
    return seen[-1]


def claims(copies: int) -> tuple[Claim, ...]:
    """What the report must say, derived from what this gate just measured."""
    vectors = str(len(corpus_files(VECTORS)))
    revision = str(current_revision())
    return (
        Claim(
            "note 2's opening, the revision the rails carry",
            "**The consumer rails carry the suiteRevision-",
            " corpus.**",
            revision,
            1,
        ),
        Claim(
            "note 2's vendoring sentence",
            "each vendor all ",
            " byte-for-byte",
            f"{vectors} vectors of suiteRevision {revision}",
            1,
        ),
        Claim(
            "note 2's replay sentence",
            "and replays the full ",
            ".",
            vectors,
            1,
        ),
        Claim(
            "the implementations table, one verified-against cell per rail",
            "its vendored set (",
            " vectors)",
            vectors,
            copies,
        ),
    )


def _normalize(text: str) -> str:
    """Collapse every run of whitespace, so a paragraph rewrapped in a repo file
    is the same prose. Line numbers go with the line breaks; failures name the
    claim instead, which is what a reader needs to find it."""
    return " ".join(text.split())


def claim_failures(copies: int) -> list[str]:
    published = _normalize(REPORT.read_text(encoding="utf-8"))
    rel = REPORT.relative_to(REPO_ROOT)
    out: list[str] = []
    for claim in claims(copies):
        pattern = re.compile(
            re.escape(claim.opens) + "(.{0,60}?)" + re.escape(claim.closes)
        )
        hits = pattern.findall(published)
        if len(hits) != claim.occurrences:
            out.append(
                f"{rel}: {claim.label} was found {len(hits)} time(s), expected "
                f"{claim.occurrences}. The claim is matched on the words around it "
                f"({claim.opens.strip()!r} ... {claim.closes.strip()!r}); rewording "
                "or deleting it fails here rather than quietly leaving the ledger "
                "unpublished, and the count for the table is the number of rows in "
                "the ledger, so a rail named there with no copy recorded fails too."
            )
            continue
        out.extend(
            f"{rel}: {claim.label} says {hit!r} where the corpus this repository "
            f"publishes says {claim.expected!r}."
            for hit in hits
            if hit != claim.expected
        )
    return out


def check() -> int:
    entries = load_ledger()
    published = corpus_digest(VECTORS)
    behind = [e for e in entries if e.get("corpusDigest") != published]
    if behind:
        print(
            f"FAIL: {len(behind)} vendored cop(ies) do not carry the corpus this "
            f"repository publishes ({published[:16]}...):",
            file=sys.stderr,
        )
        for e in behind:
            print(
                f"  {e['id']} carries {str(e.get('corpusDigest'))[:16]}...",
                file=sys.stderr,
            )
        print(
            "\nRefresh each copy with the vendoring script that owns it, then re-run "
            "this gate with --sync so the ledger records what those copies now carry. "
            "Editing the ledger instead records an intention: the digests in it are "
            "read from the copies, never typed.",
            file=sys.stderr,
        )
        return 1
    stale = claim_failures(len(entries))
    if stale:
        print(
            "FAIL: every recorded copy carries the published corpus, but the report "
            "and that ledger do not agree:",
            file=sys.stderr,
        )
        for failure in stale:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nThese sentences are the only place a reader learns what the rails "
            "replay, and no rail can correct them: a lagging copy and its own stamp "
            "agree with each other perfectly. Rewrite them to the values above, or, "
            "if the disagreement is a count, register the rail the report names with "
            "--sync so there is a copy behind it.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {len(entries)} vendored cop(ies) carry the published corpus "
        f"({published[:16]}...), and the report publishes that corpus."
    )
    return 0


def parse_dirs(pairs: list[str]) -> dict[str, Path]:
    dirs: dict[str, Path] = {}
    for pair in pairs:
        copy_id, sep, where = pair.partition("=")
        if not sep:
            raise SystemExit(f"FAIL: --copy wants <id>=<vendored-dir>, got {pair!r}")
        dirs[copy_id] = Path(where).expanduser().resolve()
    return dirs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="gate the ledger (what CI runs)")
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the ledger from each copy's own vendor stamp",
    )
    ap.add_argument(
        "--copy",
        action="append",
        default=[],
        metavar="ID=DIR",
        help="the vendored corpus directory for one recorded copy, required by --sync",
    )
    args = ap.parse_args(argv[1:])
    if args.sync and sync(parse_dirs(args.copy)) != 0:
        return 1
    return check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
