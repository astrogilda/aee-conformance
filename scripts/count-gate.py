#!/usr/bin/env python3
"""Count gate: a corpus count is derived, and a bare integer standing for one is
not writable by hand.

Why a count needs a gate at all
-------------------------------
This corpus has been 125, 138, 140, 149, 153, 154, 156, 158, 165, 175 and 179
vectors, and it is larger again now. vectors/MANIFEST.json says by how much and
this sentence deliberately does not, because the census below reads no integer in
this file, so a live count written here would be exactly the unchecked cache the
gate exists to refuse. Every one of those historical numbers was typed into prose
in several places at once and the copies went stale at different rates, until two
documents in this repository disagreed about the size of the same corpus while
both looked authoritative. A count is a DERIVED fact. It has exactly one source,
and every appearance of it elsewhere is a cache with no invalidation.

The sources are named once, here:

  vectors/MANIFEST.json      the corpus as it stands: total, accept, reject
  vectors/CHANGES.md         the per-revision ledger, and so every size the
                             corpus has ever had; its head row is checked
                             against the manifest, which is what stops the
                             ledger and the corpus drifting apart
  docs/FORCING-BASELINE.json what the corpus forces: the four outcome counts,
                             the site total, the annotated sites
  docs/INDEPENDENT-RUNS.json the scores an outside reader posted, spelled as
                             posted

Check, not emit
---------------
The published counts are CHECKED against those sources rather than written into
the documents by a generator. Three reasons, and the first is a recorded decision
rather than a preference.

A generator that rewrites a span cannot fail. If the prose is a pure function of
the source it can only ever restate what it just read, and the check that the
sentence around the number still makes sense is not weakened but absent.
scripts/independent-runs-gate.py makes this argument at length for the
independence column and scripts/specpins.py makes it for line-range pins; the
same argument holds here, and holding it in two shapes in one repository would be
worse than holding it in one.

Second, the numbers live inside sentences that argue. A sentence of the shape
"N rules forced, N seen-but-tolerated, N unforced, N unmeasurable" sits in a
paragraph explaining why the four outcomes are kept apart. An emitter would have
to either drop that argument or carry it inside a script no reviewer of the
README opens.

Third, an emitting generator over a reviewed artifact defeats the review gate: a
reviewer approves prose and a later run rewrites it underneath them. A check
refuses instead, which leaves the author writing the sentence and the gate
refusing the number inside it.

The cost of checking is that a claim site has to be declared to be checked, and
that is exactly the hole the second half of this gate exists to close.

Banning the bare integer
------------------------
A gate that re-checks the counts it already knows about cannot catch the next one
somebody types into a new paragraph. So the second half is a CENSUS: it finds
every integer in the tracked prose that is shaped like a corpus count and refuses
unless something accounts for it.

What makes an integer count-shaped, mechanically:

  RATIO      `N/M` or `N of M`. Every score this repository publishes is written
             that way, and a denominator is a corpus size by construction.
  NOUN       a digit run immediately followed by `vectors`, optionally through
             `accept` or `reject`.
  VALUE      the integer equals a count the sources currently publish. This is
             the load-bearing rule and it is worth stating why: a count that is
             CORRECT when it is written necessarily equals the source. So
             requiring every source-valued integer to be accounted for catches
             the exact defect -- somebody types today's number, and it is nobody's
             job to revisit it -- for any wording, any noun, any file. The other
             two rules catch the smaller case of a count that was wrong when it
             was written.

Values below twenty are ambiguous with ordinary prose, so for those VALUE fires
only next to a word from the closed vocabulary in SMALL_VALUE_NOUNS below.

Forms that are not counts are masked before any of this runs: spec anchors
(`L157-165`, `spec:1023-1028`), vector ids and id lists (`ok-006/007/029`),
condition ids, RFC numbers, upstream issue numbers, dates, version strings and
hex digests.

A count-shaped integer is accounted for in one of five ways, and every one of
them is a statement somebody had to make on purpose:

  1. it sits inside a declared claim below, whose value comes from a source;
  2. it sits inside a span another gate is declared to own, named in DELEGATED;
  3. it sits inside a declared FROZEN span -- a figure that records a past event
     and must NOT track the corpus, each carrying the reason it is frozen;
  4. it is revision-attributed: the sentence it sits in names a suiteRevision,
     and the ledger row for that revision carries the value. This is the route a
     writer should reach for first, because it is the only one that also tells
     the READER the number is a snapshot: `passed all 165 vectors (suiteRevision
     11)` says so on its face;
  5. it sits in vectors/CHANGES.md under `## suiteRevision N` and the value is a
     size the corpus had at or before N. A changelog entry is scoped by the
     heading it sits under, which is the same reason scripts/independent-runs-gate.py
     exempts that file from its not-run check.

Anything else fails, naming the file, the line, the integer and the five routes.

What this cannot catch
----------------------
A count spelled in words. "one hundred and eighty-six vectors" is invisible to
every rule here, and so is "four sites" once the value four stops being the
annotated-site count. The declared claims cover the two word-spelled counts this
repository publishes today; a third would go unnoticed until it went stale.

A count that was wrong when it was written, next to a noun outside the two-word
vocabulary, whose value collides with nothing. "the suite ships 400 files" passes.
The VALUE rule closes this for every count that is correct at the time of writing,
which is the case that actually occurs, and nothing closes it for a number that
was never right.

A count in a file this census does not read: JSON and other data files (they are
sources or generated), the vendored predicate text under spec/predicates/ (its
bytes are upstream's and scripts/spec-drift-gate.py owns them), and
docs/COVERAGE-MATRIX.md (generated end to end and gated by
scripts/coverage-matrix-gate.py --check). Go is read for `//` and `/* */`
comments only, so a count inside a Go string literal is not seen.

Revision attribution is satisfied by any revision the sentence names, not by the
right one. A sentence naming two revisions accepts a value belonging to either.
Tightening that would mean parsing which clause a number belongs to, which is a
reading rather than a match.

Where the mechanism lives
-------------------------
The rule above is general and its subject is not. Everything below this line is
about THIS corpus -- its sources, its claim sites, its frozen incidents, its
vocabulary -- while the machinery that reads prose, masks the non-counts, finds
the count-shaped integers and resolves each against a declaration is in
scripts/countcensus.py, which knows about none of that. It is a library because a
consumer in another repository now runs the same rule over a different subject,
and one rule implemented twice is two rules that will disagree. The argument for
the rule stays here; only the code moved.

Usage:
    python3 scripts/count-gate.py
    python3 scripts/count-gate.py --root <staged copy>   (what its own tests run)
Exit 0 when every published count is derived and every count-shaped integer is
accounted for; 1 on any disagreement, naming each one.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from countcensus import (
    Census,
    Claim,
    Covered,
    Delegated,
    Frozen,
    Quantities,
    Token,
    check_claims,
    check_declarations,
    read_tracked,
    run_census,
)

# The tree under check. `--root` points it at a staged copy, which is how
# scripts/count-gate-test.py mutates one file and asserts the refusal without
# ever editing the repository it is testing.
REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_REL = "vectors/MANIFEST.json"
CHANGES_REL = "vectors/CHANGES.md"
BASELINE_REL = "docs/FORCING-BASELINE.json"
RUNS_REL = "docs/INDEPENDENT-RUNS.json"


def source(rel: str) -> Path:
    return REPO_ROOT / rel

# `## suiteRevision 16 (the corpus is regenerable, and was measured to prove it)`
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)
# `- Corpus: **186 vectors (46 accept, 140 reject)**, up from 179.` and the
# unbolded spelling the earlier entries use.
# The indeterminate group is optional because the ledger is history: every
# revision before the bucket existed declares a two-part row, and a regex that
# demanded three parts would fail on rows that were complete when written.
CORPUS_ROW = re.compile(
    r"Corpus:\s*\*{0,2}(\d+) vectors \((\d+) accept, (\d+) reject"
    r"(?:, (\d+) indeterminate)?\)",
    re.MULTILINE,
)

# Numbers this repository spells as words. Only the counts actually published
# that way need an entry; a value with no spelling here is checked as digits.
WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven"}


# --------------------------------------------------------------------------
# The sources
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Sources:
    """Every count this repository is entitled to publish, and where it came from."""

    total: int
    accept: int
    reject: int
    indeterminate: int
    revision: int
    forced: int
    tolerated: int
    unforced: int
    unmeasurable: int
    sites: int
    annotated: int
    ledger: dict[int, tuple[int, int, int, int]]
    figures: frozenset[str]

    def current(self) -> dict[int, str]:
        """The values that must not be typed by hand, and what each one is."""
        return {
            self.total: "the corpus total",
            self.accept: "the accept count",
            self.reject: "the reject count",
            # The indeterminate count is deliberately NOT here. This map drives
            # the census's VALUE rule, which fires on any integer equal to a
            # published count, and the bucket is two vectors: `2` collides with
            # "GATE 2", "version 2" and "the second pass" throughout this
            # repository, all of them within the small-value window of a noun in
            # SMALL_VALUE_NOUNS. Every one of those would fail as an unaccounted
            # count. The value is not unchecked -- it is grounded harder than the
            # census could ground it, by manifest_integrity_failures against the
            # entries and the files on disk, by head_row_failures against the
            # changelog, and by the three declared claims that publish the corpus
            # as a whole -- so what the exclusion drops is a heuristic that
            # produces only false positives at this magnitude.
            self.revision: "the current suiteRevision",
            self.forced: "the count of forced rules",
            self.tolerated: "the count of seen-but-tolerated rules",
            self.unforced: "the count of unforced rules",
            self.unmeasurable: "the count of unmeasurable rules",
            self.sites: "the count of mutation sites",
            self.annotated: "the count of annotated sites",
        }

    def historical(self) -> dict[int, set[int]]:
        """Value -> the revisions whose ledger row carries it."""
        out: dict[int, set[int]] = {}
        for rev, row in self.ledger.items():
            for value in row:
                # A revision predating the indeterminate bucket carries zero of
                # them, and admitting 0 here would exempt every "0" written next
                # to a count noun in a revision-naming sentence. An absent bucket
                # is not a size the corpus ever published.
                if value:
                    out.setdefault(value, set()).add(rev)
        return out


def revision_ledger() -> dict[int, tuple[int, int, int, int]]:
    """Every size the corpus has had, read from the changelog that owns revision
    numbering.

    One row per `## suiteRevision N` heading, taken from the `Corpus:` line
    inside that section. A section with no such line is a failure rather than a
    skip: a revision that declares no size makes every later reference to that
    revision's corpus unaccountable.
    """
    changes = source(CHANGES_REL)
    text = changes.read_text(encoding="utf-8")
    headings = list(REVISION_HEADING.finditer(text))
    if not headings:
        raise SystemExit(
            f"FAIL: {CHANGES_REL} carries no '## suiteRevision N' "
            "heading, so nothing says what size the corpus has ever been."
        )
    ledger: dict[int, tuple[int, int, int, int]] = {}
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        row = CORPUS_ROW.search(text, heading.end(), end)
        if row is None:
            raise SystemExit(
                f"FAIL: {CHANGES_REL} has no 'Corpus: N vectors "
                f"(A accept, R reject)' line under suiteRevision {heading.group(1)}, so "
                "that revision declares no size and every reference to its corpus is "
                "unaccountable."
            )
        ledger[int(heading.group(1))] = (
            int(row.group(1)),
            int(row.group(2)),
            int(row.group(3)),
            int(row.group(4) or 0),
        )
    return ledger


def load_sources() -> Sources:
    manifest = json.loads(source(MANIFEST_REL).read_text(encoding="utf-8"))
    baseline = json.loads(source(BASELINE_REL).read_text(encoding="utf-8"))
    runs = json.loads(source(RUNS_REL).read_text(encoding="utf-8"))
    ledger = revision_ledger()
    counts = baseline["counts"]
    return Sources(
        total=len(manifest["vectors"]),
        accept=manifest["counts"]["accept"],
        reject=manifest["counts"]["reject"],
        indeterminate=manifest["counts"]["indeterminate"],
        revision=max(ledger),
        forced=counts["KILLED"],
        tolerated=counts["SILENT"],
        unforced=counts["DEAD"],
        unmeasurable=counts["INCONCLUSIVE"],
        sites=len(baseline["sites"]),
        annotated=len(baseline["annotations"]),
        ledger=ledger,
        figures=frozenset(
            str(figure["figure"])
            for run in runs["runs"]
            for figure in run.get("figures", [])
        ),
    )


def manifest_integrity_failures(src: Sources) -> list[str]:
    """The root source is grounded in the files, not in a field it declares.

    ``counts`` in the manifest is written by the generator and is as hand-typable
    as any sentence. Every number this gate publishes descends from it, so it is
    checked three ways -- the declared counts, the entries that carry them, and
    the vector files on disk -- before any of them is used. A root that only
    agreed with itself would make the whole gate a check that cannot fail.
    """
    manifest = json.loads(source(MANIFEST_REL).read_text(encoding="utf-8"))
    out: list[str] = []
    for kind, declared in (
        ("accept", src.accept),
        ("reject", src.reject),
        ("indeterminate", src.indeterminate),
    ):
        entries = sum(1 for v in manifest["vectors"] if v.get("kind") == kind)
        on_disk = len(list((REPO_ROOT / "vectors" / kind).glob("*.json")))
        if declared == entries == on_disk:
            continue
        out.append(
            f"vectors/MANIFEST.json: it declares {declared} {kind} vector(s), carries "
            f"{entries} {kind} entr(ies), and vectors/{kind}/ holds {on_disk} file(s). "
            "Every published count descends from this field, so it may not disagree "
            "with the corpus it counts."
        )
    if src.total != len(manifest["vectors"]):
        out.append(
            f"vectors/MANIFEST.json: the total {src.total} is not the number of "
            f"entries it carries ({len(manifest['vectors'])})."
        )
    return out


INDEX_HEADING = re.compile(r"^## Vectors \((\d+)\)$", re.MULTILINE)
# The first cell of a vector row, in the spelling gen_manifest.py reads it: the
# reject index backticks its ids and the accept index does not. This mirrors
# gen_manifest.table_rows deliberately -- a second, looser parser here would let
# a row the manifest generator skips be counted as present by this gate.
INDEX_ROW_ID = re.compile(r"^\| *`?((?:ok|bad|ind)-[0-9][0-9a-z-]*)`? *\|", re.MULTILINE)
# Which family of the corpus each index table is the table of.
INDEX_FAMILY = {
    "vectors/accept/INDEX.md": "accept",
    "vectors/reject/INDEX.md": "reject",
    "vectors/indeterminate/INDEX.md": "indeterminate",
}


def index_failures(
    texts: dict[str, str], covered: dict[str, list[Covered]]
) -> list[str]:
    """Each index table carries exactly one row per corpus vector of its family.

    This used to check a `## Vectors (N)` heading against the table beneath it,
    and said in its own docstring what that cost: it catches a heading that has
    drifted from its table and it CANNOT catch a table that has drifted from the
    corpus. It then ran green through exactly that, for five vectors, until the
    manifest generator refused to run.

    Both sides now come from outside the file. The heading is compared with the
    manifest's entries for that family, and the rows are compared with the
    manifest's ids, in both directions and counting duplicates. The manifest is
    not a free-standing authority either -- manifest_integrity_failures grounds
    its counts in the vector files on disk before any of this is read -- so the
    chain a row has to satisfy runs table, manifest, directory, and no link in it
    is checkable against itself.
    """
    manifest = json.loads(source(MANIFEST_REL).read_text(encoding="utf-8"))
    by_family: dict[str, list[str]] = {}
    for vector in manifest["vectors"]:
        by_family.setdefault(str(vector["kind"]), []).append(str(vector["id"]))
    out: list[str] = []
    for rel, text in sorted(texts.items()):
        family = INDEX_FAMILY.get(rel)
        if family is None:
            continue
        expected = by_family.get(family, [])
        rows = INDEX_ROW_ID.findall(text)
        for heading in INDEX_HEADING.finditer(text):
            covered.setdefault(rel, []).append(
                Covered(heading.start(), heading.end(), "the vector-table heading")
            )
            if int(heading.group(1)) != len(expected):
                out.append(
                    f"{rel}: the vector-table heading says {heading.group(1)} and "
                    f"vectors/MANIFEST.json carries {len(expected)} {family} "
                    "vector(s)."
                )
        seen: dict[str, int] = {}
        for vid in rows:
            seen[vid] = seen.get(vid, 0) + 1
        if duplicated := sorted(vid for vid, n in seen.items() if n > 1):
            out.append(
                f"{rel}: {duplicated} each carry more than one row. A vector with two "
                "rows is a vector whose two rows can disagree."
            )
        if missing := [vid for vid in expected if vid not in seen]:
            out.append(
                f"{rel}: the corpus carries {missing} and this table has no row for "
                "them, so nothing here says what they test."
            )
        if extra := sorted(set(rows) - set(expected)):
            out.append(
                f"{rel}: {extra} have a row here and no entry in "
                "vectors/MANIFEST.json."
            )
    return out


def head_row_failures(src: Sources) -> list[str]:
    """The changelog's newest row is the manifest, or the ledger is not the corpus.

    Every historical size in this gate is read from that ledger, so a head row
    that disagrees with the manifest would let the whole file drift away from the
    corpus while every rule below it kept passing.
    """
    row = src.ledger[src.revision]
    if row == (src.total, src.accept, src.reject, src.indeterminate):
        return []
    return [
        f"vectors/CHANGES.md: suiteRevision {src.revision} declares "
        f"{row[0]} vectors ({row[1]} accept, {row[2]} reject, {row[3]} "
        f"indeterminate) and vectors/MANIFEST.json carries {src.total} "
        f"({src.accept} accept, {src.reject} reject, {src.indeterminate} "
        "indeterminate). The changelog is the ledger every historical count "
        "in this repository resolves through, so its newest row is the manifest or "
        "nothing else can be trusted."
    ]


# --------------------------------------------------------------------------
# Half one: the declared claims
# --------------------------------------------------------------------------


def claims(src: Sources) -> tuple[Claim, ...]:
    """Every live count this repository publishes, and what the sources say it is."""
    rev = src.revision
    corpus = (
        f"{src.total} vectors ({src.accept} accept, {src.reject} reject, "
        f"{src.indeterminate} indeterminate)"
    )
    return (
        Claim(
            "README.md",
            "the vector-count badge, its image",
            "badge/conformance%20vectors-",
            "-e8951c",
            str(src.total),
        ),
        Claim(
            "README.md",
            "the vector-count badge, its alt text",
            'alt="',
            ' conformance vectors"',
            str(src.total),
        ),
        Claim(
            "README.md",
            "what a full replay reports, in the forcing section",
            "the suite still reports ",
            ", exit 0. A rail with no",
            f"{src.total} of {src.total}",
        ),
        Claim(
            "README.md",
            "the size of the mutation sweep",
            "notices — ",
            " single-site weakenings of",
            str(src.sites),
        ),
        Claim(
            "README.md",
            "the four forcing outcomes",
            "tighten-only ratchet: **",
            ".** The four outcomes",
            f"{src.forced} rules forced, {src.tolerated} seen-but-tolerated, "
            f"{src.unforced} unforced, {src.unmeasurable}\nunmeasurable",
        ),
        Claim(
            "README.md",
            "how many forcing sites carry an annotation",
            "is a gap — and",
            "sites carry an annotation saying",
            WORDS.get(src.annotated, str(src.annotated)),
        ),
        Claim(
            "README.md",
            "the nightly sweep's size",
            "sweeps all ",
            " sites nightly",
            str(src.sites),
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the corpus line in the document header comment",
            f"Corpus SSOT: vectors/MANIFEST.json (suiteRevision {rev}, ",
            ").",
            f"{src.total} vectors: {src.accept} accept, {src.reject} reject, "
            f"{src.indeterminate} indeterminate",
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the reference-corpus section",
            f"`vectors/MANIFEST.json`, suiteRevision {rev}: **",
            "**.",
            corpus,
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the implementations table, the first-party result cells",
            f"reference corpus, suiteRevision {rev} | **",
            "** |",
            f"{src.total} / {src.total}",
            occurrences=2,
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the scoping paragraph on what agreement does not say",
            "Nor does agreement on ",
            " vectors say anything",
            str(src.total),
        ),
        Claim(
            "BUILD-NOTES.md",
            "the verified-state paragraph, what the replay covers",
            "sibling vector suite: ",
            ", both key policies",
            f"{src.accept} accept vectors, {src.reject} reject vectors, "
            f"{src.indeterminate} indeterminate vectors",
        ),
        Claim(
            "BUILD-NOTES.md",
            "the verified-state paragraph, the strict-pass total",
            "and empty), all ",
            " strict passes.",
            str(src.total),
        ),
        Claim(
            "crosswalks/aee-to-ave.md",
            "the provenance paragraph's statement of this corpus",
            "The conformance suite is at revision ",
            ", per vectors/MANIFEST.json.",
            f"{rev} with {src.total} vectors, {src.accept} accept, {src.reject} "
            f"reject and {src.indeterminate} indeterminate",
        ),
        Claim(
            ".github/workflows/ci.yml",
            "the vector-replay step name",
            "on the Python rail (must be ",
            ")",
            f"{src.total}/{src.total}",
        ),
        Claim(
            ".github/workflows/ci.yml",
            "the forcing job's note on what a vector count does not measure",
            "the suite still reports ",
            ", exit 0. The only way",
            f"{src.total} of {src.total}",
        ),
        Claim(
            ".github/workflows/ci.yml",
            "the forcing job's measured scope",
            "that carries between machines: ",
            " sites and",
            f"{src.forced} of {src.sites}",
        ),
        Claim(
            ".github/workflows/forcing-nightly.yml",
            "the nightly sweep's measured scope",
            "16-worker workstation: ",
            " sites,",
            str(src.sites),
        ),
        Claim(
            "TODO.md",
            "the open item on what the operator set cannot express",
            "not even as a gap. ",
            " sites is the size of what can be asked",
            str(src.sites),
        ),
    )


DELEGATED: tuple[Delegated, ...] = (
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "the implementations table, the vendored-set cells",
        r"its\s+vendored\s+set\s+\(\d+\s+vectors\)",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 2's vendoring sentence",
        r"each\s+vendor\s+all\s+\d+\s+vectors\s+of\s+suiteRevision\s+\d+\s+byte-for-byte",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 2's replay sentence",
        r"and\s+replays\s+the\s+full\s+\d+\.",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 2's opening, the revision the rails carry",
        r"\*\*The\s+consumer\s+rails\s+carry\s+the\s+suiteRevision-\d+\s+corpus\.\*\*",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "README.md",
        "the independence section's scoping sentence",
        r"It\s+has\s+not\s+been\s+run\s+against\s+suiteRevision\s+[\d,\s]*(?:and|or)\s+\d+,",
        "scripts/independent-runs-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 1's scoping sentence",
        r"He\s+has\s+not\s+run\s+suiteRevision\s+[\d,\s]*(?:and|or)\s+\d+,",
        "scripts/independent-runs-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "the implementations table, the not-run enumerations",
        r"suiteRevisions\s+[\d,\s]*(?:and|or)\s+\d+\s+not\s+run\s+by",
        "scripts/independent-runs-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "the feature-coverage paragraph's span of unread revisions",
        r"\*\*suiteRevision\s+\d+\s+through\s+\d+\*\*",
        "scripts/independent-runs-gate.py",
    ),
    # The accept-anchor measurement: how many of the conditions a refusal cites
    # are also cited by a vector that must be accepted. Both halves are derived
    # from the manifest on every run and ratcheted against
    # docs/ACCEPT-ANCHOR-BASELINE.json, so the gate that owns them is the one
    # that recomputes them rather than this census.
    Delegated(
        "vectors/CHANGES.md",
        "the accept-anchor traceability figure",
        r"That\s+second\s+number\s+is\s+\d+\s+of\s+\d+\s+today,",
        "scripts/accept-anchor-gate.py",
    ),
    Delegated(
        "vectors/CHANGES.md",
        "the accept-anchor parent-pairing figure",
        r"all\s+\d+\s+reject\s+vectors\s+declare\s+a\s+parent",
        "scripts/accept-anchor-gate.py",
    ),
)


FROZEN: tuple[Frozen, ...] = (
    Frozen(
        "scripts/complexity-table-gate.py",
        "the drift incident's Go-side measurement",
        "``evaluateKind`` from 24 to 28",
        "A gocyclo reading taken at suiteRevision 15, not a claim about the corpus. "
        "It became visible only when the revision counter reached the same value, "
        "which is the collision the MASKS note above already records happening at "
        "suiteRevision 20: a digit that names a complexity, read as a count because "
        "a published quantity happened to equal it.",
    ),
    Frozen(
        "README.md",
        "the external-rail contract, the shipped CLI's score",
        "it scored 0 of 186.",
        "An incident record. The CLI scored zero against the corpus as it stood, and "
        "a figure that tracked the corpus would be inventing a rerun nobody did.",
    ),
    Frozen(
        ".github/workflows/ci.yml",
        "the external-rail step's note",
        "186 the first time anybody tried",
        "The same incident, recorded where the step that now prevents it runs.",
    ),
    Frozen(
        ".github/workflows/ci.yml",
        "the forcing-test step's note",
        "scored 0 of 186 while its unit test passed",
        "The same incident, cited as the reason a gate's own tests assert refusals.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the evidence-basis table's semgrep row",
        "| semgrep | 52 |",
        "A reading of ANOTHER project's corpus, taken on the date the document "
        "states, and it collides with this suite's accept count only by "
        "coincidence. Tracking it to the accept count would rewrite a fact "
        "about 59 AVE records into a fact about these vectors.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "suiteRevision 15's mutation-campaign tally",
        "19 were seen and tolerated",
        "The result of a campaign run against a corpus of 179 vectors, recorded "
        "in the revision section that reports it. It equals the current "
        "suiteRevision by coincidence and must not follow it.",
    ),
    Frozen(
        "cmd/aee-verify/main.go",
        "the -json flag's comment",
        "scored 0 of 186 against the corpus it ships",
        "The same incident, recorded at the line that caused it.",
    ),
    Frozen(
        "cmd/aee-verify/main_test.go",
        "the machine-readable-output test's comment",
        "while scoring 0 of 186 as an",
        "The same incident, recorded at the test that did not catch it.",
    ),
    Frozen(
        "scripts/external-rail-gate.py",
        "the gate's own reason for existing",
        "the shipped CLI scored 0 of 186:",
        "The same incident. This gate exists because of it.",
    ),
    Frozen(
        "scripts/external-rail-gate.py",
        "the refusal message's account of the incident",
        "how the shipped CLI came to score 0 of 186 unnoticed.",
        "The same incident, quoted to whoever trips this gate.",
    ),
    Frozen(
        "scripts/forcing-gate-test.py",
        "the list of checks that could not fail",
        "scored 0 of 186 while its own unit test",
        "The same incident, cited among the checks that ran green while enforcing "
        "nothing.",
    ),
    Frozen(
        "docs/interpretation-decisions-open.md",
        "the coverage-partition decision's parity note",
        "so 134/134 parity was intact",
        "A parity figure at the revision the divergence was found, not a corpus size.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the stage/layer correlation in the AVE corpus",
        "37 of 44 static records are content",
        "A count of the AVE crosswalk corpus read on a stated date, not of this "
        "corpus. Its source is another project's published records.",
    ),
    Frozen(
        "scripts/consumer-lag-gate.py",
        "the two remembered lags",
        "two rails sat at 140 vectors while this repository",
        "The lag as it was measured. Both figures are sizes this corpus has had, and "
        "moving either would erase the event that made this gate necessary.",
    ),
    Frozen(
        "TODO.md",
        "the forcing-measurement entry, what a full replay reported",
        "the suite still reports 186 of 186, exit 0. `cmd/mutgen` enumerates 590 "
        "single-site",
        "A dated completed-work entry. The figures are the measurement as it stood "
        "when the work landed.",
    ),
    Frozen(
        "TODO.md",
        "the forcing-measurement entry, the baseline it wrote",
        "331 KILLED, 17 SILENT, 237 DEAD, 5 INCONCLUSIVE.",
        "The same dated entry: the baseline as written, not as it stands.",
    ),
    Frozen(
        "README.md",
        "the condition-registry section's account of the unresolvable ids",
        "so 17 ids cited by accept vectors",
        "A count of condition ids that resolved to nothing before the registry was "
        "widened, and a past defect rather than a live quantity. Its collision with "
        "a forcing outcome is a coincidence of value, not of meaning.",
    ),
    Frozen(
        "vectors/reject/INDEX.md",
        "the condition-registry paragraph's account of the unresolvable ids",
        "which left 17 ids cited by vectors and resolvable",
        "The same past defect, recorded in the registry it was found in.",
    ),
    Frozen(
        ".github/workflows/ci.yml",
        "the condition-registry step's note",
        "# 17 ids were cited by live vectors and registered nowhere",
        "The same past defect, recorded at the step that now reconciles both "
        "directions.",
    ),
    Frozen(
        "scripts/condition-registry-gate.py",
        "the gate's account of the ids that resolved nowhere",
        "registered nowhere: 17 of them",
        "The same past defect. This gate exists because of it.",
    ),
    Frozen(
        "vectors/reject/gen_invalid_vectors.py",
        "the generated registry paragraph's account of the unresolvable ids",
        'which left 17 ids cited by vectors and resolvable"',
        "The same past defect, in the generator that emits the sentence into the "
        "reject index.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "the suiteRevision-15 entry's account of the first mutation measurement",
        "590 single-site weakening changes across every rail file",
        "A changelog entry. The sweep was that size when the measurement was run, "
        "and a published revision is never mutated in place.",
    ),
    Frozen(
        "TODO.md",
        "the completed CI-label correction",
        "Correct the CI vector-replay label 138 -> 140",
        "A dated completed-work entry naming the edit it made.",
    ),
    Frozen(
        "scripts/condition-forcing-gate.py",
        "the reconstruction comment's account of the superseded projection",
        "24 of 78 conditions weak",
        "The projection as it was quoted, over a corpus the working tree no longer "
        "holds. The whole point of the code beneath this comment is that the figure "
        "is reconstructed rather than remembered, so tracking it to the corpus would "
        "erase the number the reconstruction exists to check itself against.",
    ),
)


# --------------------------------------------------------------------------
# Half two: the census
# --------------------------------------------------------------------------

# Forms that carry digits and are not counts. Masked to same-length filler before
# any trigger runs, so offsets into the file stay exact.
MASKS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\b(?:ok|bad)-\d+(?:/\d+)*",  # vector ids and id lists: ok-006/007/029
        r"\baee-c-\d+",  # condition ids
        # Disposition-row identifiers, DC-NN. A row in the objection ledger is
        # named, not counted, and the number is as much an identifier as a vector
        # id is. Unmasked it collides on value with whatever small count the
        # sources happen to publish -- DC-04 against the annotated-site count --
        # and the collision fires because a neighbouring row cites a path
        # carrying the word "vectors", which is a coincidence of vocabulary and
        # not a claim about anything.
        r"\bDC-\d+\b",
        # A revision NUMBER names a revision; it is an identifier, not a count.
        # Masked here and read from the unmasked text by ATTRIBUTION below, which
        # is the one place a revision number is allowed to settle a value.
        r"(?:suite)?[Rr]evisions?[-\s]+(?:[#>*]+\s*)?\d+(?:\s+through\s+\d+)?",
        r"\bL\d+(?:-\d+)?\b",  # spec anchors in the vector tables
        r"spec:\d+(?:-\d+)?",  # spec line citations in the sources
        r"\b\d{4}-\d{2}-\d{2}\b",  # dates
        r"RFC\s*\d+",  # RFC numbers
        # Encoding names. The digit in UTF-16 is part of the name of a character
        # encoding and never a quantity of anything, and this corpus argues about
        # UTF-16 code-unit ordering in a dozen places. It went unmasked only
        # because no published count had yet collided with it, which is the
        # false-positive mode this gate's own prose warns about.
        r"\bUTF-\d+\b",
        r"#\d+",  # upstream issue and pull-request numbers
        r"\bv?\d+\.\d+(?:\.\d+)*\b",  # version strings
        r"\bgo\d[\d.]*",  # toolchain versions
        r"\b[0-9a-f]{7,}\b",  # digests and short commit ids
        r"\b[A-Za-z]\d+\b",  # requirement ids: D18, U1, P7
        # Code points, byte sizes and registry decision ids, masked for the same
        # reason UTF-16 above is: each is a digit that names something rather
        # than counting anything, and each stayed invisible only while no
        # published quantity had collided with it. They collided at
        # suiteRevision 20, which appears in this tree as `U+0020` seven times,
        # as a 20 MiB parse bound, and as two registry decision numbers -- none
        # of them a claim about the corpus, and all of them reported as
        # unaccounted the moment the revision counter reached that value.
        r"U\+[0-9A-Fa-f]{4,6}",  # Unicode code points: U+0020
        r"\\u[0-9A-Fa-f]{4}",  # escaped code points:
        r"\b0\d+\b",  # zero-padded: a count is never written 0020
        r"\b\d+\s*(?:<<|>>)\s*\d+\b",  # shift expressions: 20 << 20
        r"\b\d+\s*[KMGT]i?B\b",  # byte sizes: 20 MiB
        r"\bdecisions?\s+\d+",  # interpretation-registry decision ids
    )
)

NOUN = re.compile(r"\b(\d{1,4})\s+(?:accept |reject )?vectors?\b", re.IGNORECASE)
# A revision the sentence names, in every spelling this repository uses. The
# optional comment marker is not decoration: these sentences are hard-wrapped
# inside `#` comment blocks, so `revision` and its number routinely sit on
# different lines with a marker between them.
ATTRIBUTION = re.compile(r"(?:suite)?[Rr]evisions?[-\s]+(?:[#>*]+\s*)?(\d+)")
# Below this, an integer is ambiguous with ordinary prose and only counts when it
# sits next to one of the words below.
#
# Raised from 20 to 21 at suiteRevision 20, when the revision counter walked into
# the band this threshold describes. A bare 20 is exactly as ambiguous in prose
# as a bare 19: on the day the corpus reached revision 20 the census reported a
# cron minute, a `head -20`, a URL fragment and a 20 MiB parse bound as
# unaccounted counts, none of which had changed and none of which is a claim
# about anything. The alternative was a mask per context, which chases the
# collision instead of naming it. Nothing real is lost: a genuine quantity of 20
# is still caught, because the words that make it a quantity are below.
#
# Raised again from 21 to 22 at suiteRevision 21, for the same reason and by the
# same argument: the counter moved one more step into the ambiguous band. What it
# reported this time was `1e21` in the JCS number tests -- the integer 10^21, a
# value that must be rejected by the safe-integer profile and is not a count of
# anything -- twice, plus a bare 21 in a design record. The threshold walking up
# behind the revision counter is expected and is not a weakening: the counter will
# keep moving, and each step is one more small integer that prose can use
# innocently. The check that survives is the one below, which asks whether a count
# NOUN sits beside the number.
SMALL_VALUE = 22
SMALL_VALUE_NOUNS = re.compile(
    r"(?i)\b(?:vectors?|suiteRevisions?|revisions?|sites?|rules?|forced|unforced|"
    r"tolerated|unmeasurable|annotations?|KILLED|SILENT|DEAD|INCONCLUSIVE)\b"
)
# How far either side of an integer the small-value vocabulary is looked for.
SMALL_VALUE_WINDOW = 32

READ_SUFFIXES = frozenset({".md", ".yml", ".yaml", ".py", ".go", ".toml"})
EXEMPT: dict[str, str] = {
    "docs/COVERAGE-MATRIX.md": (
        "generated end to end from the interpretation registry and gated by "
        "scripts/coverage-matrix-gate.py --check"
    ),
    "docs/FORCING-HONESTY.md": (
        "generated end to end from the manifest, the forcing baseline, the condition "
        "registry and the rail's code set, and gated by "
        "scripts/condition-forcing-gate.py --check"
    ),
}
EXEMPT_PREFIXES: dict[str, str] = {
    "spec/predicates/": (
        "vendored upstream bytes; scripts/spec-drift-gate.py owns them and an edit "
        "here is a re-vendor, not a count"
    ),
}

# The files whose count-shaped integers are CONTROL DATA rather than claims about
# the corpus, so the census reads no integer in them.
#
# This is not a convenience. Everything the census would find in these files is
# control data: the declaration tables name the very values they check, the
# refusal message quotes the routes a writer may take, the worked examples in the
# prose above are the sentences other files are checked against, an ordinal list
# marker and a regex repetition bound are digits that stand for nothing, and the
# tests write deliberately WRONG values into a staged copy to prove the refusal
# fires. A census over its own control data reports its vocabulary as unaccounted
# prose, which is what it did: seventy refusals, every one of them in these
# files, on the revision that introduced them.
#
# The class widened once, and the widening is the honest description rather than
# the original one. It was first written as "this gate's own subject", which
# described the three files it then held; a mutation rig for a DIFFERENT gate hits
# the identical wall, because a rig that proves a published figure is checked has
# to name that figure to retype it. What licenses the exemption is not whose gate
# the file belongs to, it is that the rig asserts the value is present before
# replacing it -- so a figure that goes stale fails the rig by name, which is
# strictly louder than the census refusal it is being excused from. A rig that
# retyped a value without asserting it first would not qualify.
#
# What it costs is one live count in the prose above, and that is not left
# unchecked: it is declared as a claim like any other, so a corpus that grows
# still fails here. Only the census is skipped; the claims, the delegations and
# the frozen figures are all still read out of these files.
SELF = {
    "scripts/count-gate.py": "this gate's own declarations, examples and vocabulary",
    "scripts/count-gate-test.py": (
        "the deliberately wrong values this gate's tests write to prove it refuses"
    ),
    "scripts/countcensus.py": (
        "the census engine's own vocabulary and worked examples, which are the "
        "shapes it looks for rather than claims about anything"
    ),
    "scripts/condition-forcing-crosscheck-test.py": (
        "the published figures this rig retypes to prove the crosscheck refuses a "
        "page that drifted; rig_text asserts each one is present before replacing "
        "it, so a stale figure fails the rig rather than passing the census"
    ),
}


def changelog_scope(text: str, position: int) -> int | None:
    """The revision whose section an offset sits in, for vectors/CHANGES.md."""
    scope: int | None = None
    for heading in REVISION_HEADING.finditer(text):
        if heading.start() > position:
            break
        scope = int(heading.group(1))
    return scope


def changelog_route(
    rel: str, text: str, token: Token, quantities: Quantities
) -> str | None:
    """Route 5: a changelog entry is scoped by the heading it sits under.

    A revision section may cite any size the corpus had at or before that
    revision, which is the same reason scripts/independent-runs-gate.py exempts
    that file from its not-run check.
    """
    if rel != CHANGES_REL:
        return None
    scope = changelog_scope(text, token.start)
    if scope is not None and all(
        any(revision <= scope for revision in quantities.historical.get(value, ()))
        for value in token.values
    ):
        return f"a size the corpus had at or before suiteRevision {scope}"
    return None


def quantities(src: Sources) -> Quantities:
    """What the sources currently publish, what they have published, what was posted."""
    return Quantities(
        current=src.current(),
        historical=src.historical(),
        posted=src.figures,
        posted_why="a score docs/INDEPENDENT-RUNS.json records as posted",
    )


CENSUS = Census(
    masks=MASKS,
    nouns=((NOUN, "an integer counting vectors"),),
    small_value_nouns=SMALL_VALUE_NOUNS,
    small_value=SMALL_VALUE,
    small_value_window=SMALL_VALUE_WINDOW,
    attribution=ATTRIBUTION,
    attribution_why="revision-attributed by the sentence it sits in",
    scope_route=changelog_route,
    self_files=SELF,
)


# --------------------------------------------------------------------------


def collect() -> tuple[list[str], int, int]:
    src = load_sources()
    texts = read_tracked(REPO_ROOT, READ_SUFFIXES, EXEMPT, EXEMPT_PREFIXES)
    failures = manifest_integrity_failures(src)
    failures.extend(head_row_failures(src))
    claim_out, covered = check_claims(claims(src), texts)
    failures.extend(claim_out)
    failures.extend(check_declarations(DELEGATED, FROZEN, texts, covered))
    failures.extend(index_failures(texts, covered))
    census_out, examined = run_census(CENSUS, quantities(src), texts, covered)
    failures.extend(census_out)
    return failures, len(texts), examined


def main(argv: list[str]) -> int:
    global REPO_ROOT
    parser = argparse.ArgumentParser(description="check every published corpus count")
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="the tree to check; a staged copy when the gate's own tests run it",
    )
    REPO_ROOT = parser.parse_args(argv[1:]).root.resolve()
    failures, files, examined = collect()
    if failures:
        print(f"FAIL: {len(failures)} count claim(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nA count is derived. Fix a wrong value by correcting the prose to what "
            "the sources say, never by editing a source to match the prose. Account "
            "for a new count-shaped integer in one of five ways: declare it as a "
            "claim in scripts/count-gate.py so it is checked; name the gate that "
            "already owns it in DELEGATED; freeze it in FROZEN with the reason it "
            "records a past event; attribute it in the prose itself, which is the "
            "route that also tells the reader "
            "(`passed all 165 vectors (suiteRevision 11)`); or delete the number, "
            "which is right whenever it cannot be derived and is not history.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: every published count is derived from its source, and all {examined} "
        f"count-shaped integer(s) across {files} tracked file(s) are accounted for."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
