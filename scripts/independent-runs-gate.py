#!/usr/bin/env python3
"""Independent-run gate: the column about someone else's implementation may not
outlive the runs it describes.

The one claim this repository exists to make rests on a single outside reader.
Everything else here is five implementations by one author sharing one reading of
RFC 8785 and RFC 7493, which is a drift check rather than corroboration. So the
independence column is the most consequential prose in the tree, and its value is
entirely that it is an accurate record of what someone else actually ran. A
figure invented there would be worse than no figure, and so, less obviously,
would a stale scope: the sentence that says which revisions were NOT run is what
stops a reader inferring that the unnamed ones were.

That sentence had rotted three times over, in three different documents, each
naming a different set. The suite was at revision 14 while the README said the
checker had not been run against 7, 8, 9 or 10, the implementation report said 7,
8 or 9, and the report's own table said 7 through 9. Every one of those was true
when it was written. Each stopped being true the next time the corpus moved, and
nothing anywhere disagreed with them, because nothing read them. Worse than the
lag was what all three shared: none of them named revision 4 at all. That
revision changed no vector -- its 140 files carry the revision-3 verdicts and
codes -- but it is where encoding well-formedness and the 128-deep nesting bound
became normative over a corpus that, in its own changelog's words, exercised
neither. A revision-3 pass is therefore not a revision-4 pass, and this checker
is the proof: it scored 140/140 at revision 3 and still read the nesting bound as
256 when revision 5 published.

So the not-run set stops being a thing anyone writes down. ``docs/
INDEPENDENT-RUNS.json`` records the runs -- one row per posted run, with the
score exactly as posted, the venue it was posted at, the classification its
author gave it, and the checker source digest and suite commit where those were
posted -- and the not-run set is what is left of 1..current after the rows are
removed. The current revision is read from ``vectors/CHANGES.md``, the
per-revision changelog that owns revision numbering, rather than from a number
typed here, because a revision number written in the ledger could only ever
agree with itself.

Why this gate reads hand-written prose instead of generating it
---------------------------------------------------------------

This repository does both. ``docs/COVERAGE-MATRIX.md`` is generated end to end
and gated with --check, and that is right for it: it is a table, its cells are
joins over two JSON files, and there is no argument in it for a generator to
lose.

The sentences here are the opposite shape. The not-run set is one clause inside a
paragraph that argues -- that revision 4 is on the list for a different reason
than revision 7 is, that a directed 153/153 is not the same evidence as a blind
125/125, that a figure moves the column only because a record was posted with it.
Its author's own wording is quoted in it verbatim because paraphrasing it would
soften it. A generated span would have to either drop that argument, which is
most of what makes the column trustworthy, or carry it inside a script that no
reviewer of the README ever opens.

There is a second reason, and it is the one specpins.py already names about
line-range pins: a generated span cannot fail. If the prose is a pure function of
the ledger, it can only ever restate what it just read, and the check that the
surrounding argument still matches the facts is not weakened but absent. The
defect being closed here is a person writing a set and not revisiting it when the
corpus moved. Generating the set removes the person, and with them the sentence
in which the set has to make sense. Checking it keeps the person writing the
argument and refuses when the set inside it has stopped being true.

The cost of that choice is that a claim site has to be declared here to be
checked. So each site is matched on the fixed words around the enumeration, and a
site that no longer matches is a failure by name rather than a silently skipped
check -- the same reason code-contract-gate.py matches its const block on the
comment text rather than on the constant names.

What it does not catch
----------------------

``vectors/CHANGES.md`` is exempt, deliberately. Its per-revision entries carry
not-run sentences too, and those are historical: each was true of the revision it
sits under and is scoped by sitting there, so correcting them would be rewriting
a changelog rather than fixing a claim. The consequence is real and is recorded
rather than papered over: a not-run claim written into a NEW changelog entry is
not checked by anything, and only the three documents whose sites are declared
below are.

Nor does it police the direction "a directed run described as unprompted".
It asserts the partition the ledger draws is internally consistent (a run its
author called directed may not be flagged unprompted) and that each unprompted
run is named where the report reserves that description, but whether a paragraph
elsewhere leans on a figure it should not is a reading, not a match, and a gate
that pretended otherwise would be measuring prose shape.

Usage: python3 scripts/independent-runs-gate.py
Exit 0 when the published prose is the ledger; 1 on any disagreement.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "docs" / "INDEPENDENT-RUNS.json"
CHANGES = REPO_ROOT / "vectors" / "CHANGES.md"
README = REPO_ROOT / "README.md"
REPORT = REPO_ROOT / "docs" / "IMPLEMENTATION-REPORT.md"

# `## suiteRevision 14 (the vendored text catches up with the corpus)`
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)
# `4, 7, 8, 9, 10, 11, 12, 13 or 14` and the `and` spelling the table cells use.
# No capturing group, so it can be embedded in a site pattern.
ENUMERATION = r"\d+(?:, \d+)*(?:,? (?:and|or) \d+)?"
SCORE = re.compile(r"^\d+/\d+$")
EVIDENCE = ("blind", "first-run-unchanged-build", "directed")
# The two documents that publish the independence column. A run's headline figure
# has to be stated in both or in neither.
#
# Annotated rather than inferred: unannotated, this is a tuple of its own two
# literal values, and a set built from it will not difference against the set of
# paths read out of a run record, which is an ordinary set of strings. These are
# document paths that happen to be known here, not a closed enumeration.
PUBLISHING_DOCS: tuple[str, ...] = ("README.md", "docs/IMPLEMENTATION-REPORT.md")
# A value this repository can source, or a note saying it cannot. Exactly one,
# because a field left null with nothing beside it and a field nobody thought
# about are the same field in a diff.
SOURCED_OR_EXPLAINED = (
    ("date", "dateNote"),
    ("checkerSourceDigest", "digestNote"),
    ("suiteCommit", "suiteCommitNote"),
)


@dataclass(frozen=True)
class Site:
    """One place the not-run set is published, found by the words around it.

    ``opens`` and ``closes`` are the fixed prose either side of the
    enumeration, and ``occurrences`` is how many times that shape must appear in
    the file. The count is asserted rather than assumed so that deleting a claim,
    or duplicating one into a second paragraph that will then rot on its own,
    fails here instead of passing.
    """

    path: Path
    label: str
    opens: str
    closes: str
    occurrences: int


SITES = (
    Site(
        README,
        "the independence section's scoping sentence",
        "It has not been run against suiteRevision ",
        ", so this suite publishes no score for it at any of them.",
        1,
    ),
    Site(
        REPORT,
        "note 1, the run history",
        "He has not run suiteRevision ",
        ", so this report publishes no score for him at any of them.",
        1,
    ),
    Site(
        REPORT,
        "the implementations table, the verified-against cell",
        "suiteRevisions ",
        " not run by its author",
        1,
    ),
    Site(
        REPORT,
        "the implementations table, the result cell",
        "suiteRevisions ",
        " not run by author (see note 1)",
        1,
    ),
)

# The revision the corpus is at, restated in the report's own prose. It is the
# input to the derivation below, so a stale copy of it would let a correct
# not-run set sit under a heading naming the wrong corpus. Checked as literals
# rather than by regex: rewording one fails loudly here, which is the intent.
CURRENT_REVISION_LITERALS = (
    ("Corpus SSOT: vectors/MANIFEST.json (suiteRevision {n},", 1),
    ("`vectors/MANIFEST.json`, suiteRevision {n}:", 1),
    ("| reference corpus, suiteRevision {n} |", 2),
)


def normalize(text: str) -> str:
    """Collapse every run of whitespace, so a paragraph rewrapped in a repo file
    is the same prose. Line numbers are lost with the line breaks; failures name
    the file and the claim instead, which is what a reader needs to find them."""
    return " ".join(text.split())


def read(path: Path) -> str:
    return normalize(path.read_text(encoding="utf-8"))


def current_revision() -> tuple[int, list[str]]:
    """The revision the corpus is at, read from the changelog that owns revision
    numbering, plus any reason that reading cannot be trusted."""
    seen = sorted({int(n) for n in REVISION_HEADING.findall(CHANGES.read_text("utf-8"))})
    if not seen:
        return 0, [
            "vectors/CHANGES.md carries no '## suiteRevision N' heading, so nothing "
            "says which revision the corpus is at and the not-run set has no domain."
        ]
    gaps = sorted(set(range(1, seen[-1] + 1)) - set(seen))
    if gaps:
        listed = ", ".join(str(g) for g in gaps)
        return seen[-1], [
            f"vectors/CHANGES.md jumps: it names suiteRevision {seen[-1]} but has no "
            f"entry for {listed}. The not-run set is computed over 1..current, so a "
            "missing entry would silently make a revision unaccountable."
        ]
    return seen[-1], []


def _run_field_failures(run: dict[str, Any], current: int) -> list[str]:
    """Everything one row must carry to license a figure in the prose."""
    rev = run.get("suiteRevision")
    where = f"run at suiteRevision {rev}"
    out: list[str] = []
    if not isinstance(rev, int) or not 1 <= rev <= current:
        return [f"{where}: suiteRevision must be an integer in 1..{current}."]
    out.extend(_figure_shape_failures(run, where))
    if not str(run.get("posting", "")).strip():
        out.append(
            f"{where}: names no posting. A score with no record behind it may not be "
            "published, so it may not be recorded here either."
        )
    if run.get("evidence") not in EVIDENCE:
        out.append(f"{where}: evidence must be one of {', '.join(EVIDENCE)}.")
    if run.get("unprompted") is not (run.get("evidence") != "directed"):
        out.append(
            f"{where}: a run its author called directed may not be flagged unprompted, "
            "and a run he did not call directed may not be flagged prompted."
        )
    out.extend(_pair_failures(run, where))
    return out


def headline(run: dict[str, Any]) -> str:
    """The figure a run is known by. Every other figure it carries is a
    qualification of this one."""
    for figure in run.get("figures", []):
        if figure.get("role") == "score":
            return str(figure.get("figure", ""))
    return ""


def _figure_shape_failures(run: dict[str, Any], where: str) -> list[str]:
    figures: list[dict[str, Any]] = run.get("figures", [])
    out = [
        f"{where}: the figure {f.get('figure')!r} must be spelled exactly as posted, "
        "as 'N/M', and must name at least one document that carries it."
        for f in figures
        if not SCORE.match(str(f.get("figure", ""))) or not f.get("carriedIn")
    ]
    scores = [f for f in figures if f.get("role") == "score"]
    if len(scores) != 1:
        out.append(
            f"{where}: exactly one figure is the run's headline (role 'score'); "
            f"{len(scores)} are."
        )
        return out
    carried = {str(c.get("file")) for c in scores[0].get("carriedIn", [])}
    missing = sorted(set(PUBLISHING_DOCS) - carried)
    if missing:
        out.append(
            f"{where}: the headline figure is not recorded as carried in "
            f"{', '.join(missing)}. Both documents publish this column, so both state "
            "the figure or the run has no business being cited in either."
        )
    return out


def _pair_failures(run: dict[str, Any], where: str) -> list[str]:
    out: list[str] = []
    for value, note in SOURCED_OR_EXPLAINED:
        has_value = run.get(value) is not None
        has_note = run.get(note) is not None
        if has_value == has_note:
            out.append(
                f"{where}: exactly one of {value} and {note} must be set. Recording "
                "neither leaves a reader unable to tell an unrecorded fact from an "
                "overlooked field; recording both says the value is and is not known."
            )
    return out


def ledger_failures(runs: list[dict[str, Any]], current: int) -> list[str]:
    out: list[str] = []
    seen: set[int] = set()
    for run in runs:
        out.extend(_run_field_failures(run, current))
        rev = run.get("suiteRevision")
        if isinstance(rev, int):
            if rev in seen:
                out.append(f"suiteRevision {rev} is recorded twice; one row per run.")
            seen.add(rev)
    return out


def not_run(runs: list[dict[str, Any]], current: int) -> list[int]:
    ran = {r["suiteRevision"] for r in runs if isinstance(r.get("suiteRevision"), int)}
    return [n for n in range(1, current + 1) if n not in ran]


def site_failures(site: Site, expected: list[int]) -> list[str]:
    pattern = re.compile(re.escape(site.opens) + f"({ENUMERATION})" + re.escape(site.closes))
    hits = pattern.findall(read(site.path))
    rel = site.path.relative_to(REPO_ROOT)
    if len(hits) != site.occurrences:
        return [
            f"{rel}: {site.label} was found {len(hits)} time(s), expected "
            f"{site.occurrences}. The claim is matched on the words around it "
            f"({site.opens.strip()!r} ... {site.closes.strip()!r}); rewording or "
            "deleting it fails here rather than quietly leaving the set unchecked."
        ]
    return [f"{rel}: {site.label} {why}" for hit in hits for why in _hit_failures(hit, expected)]


def _hit_failures(hit: str, expected: list[int]) -> list[str]:
    read_back = [int(n) for n in re.findall(r"\d+", hit)]
    if read_back != sorted(set(read_back)):
        return [f"lists {hit!r}, which is not in ascending order without repeats."]
    if read_back != expected:
        return [
            f"names suiteRevision(s) {hit!r}, but the ledger has no run for "
            f"{', '.join(str(n) for n in expected)}.\n"
            f"      A reader takes the named set as current and infers the unnamed "
            f"revisions were run. Correct the sentence, or record the missing run in "
            f"docs/INDEPENDENT-RUNS.json with the record and source digest it was "
            f"posted with."
        ]
    return []


def figure_failures(runs: list[dict[str, Any]]) -> list[str]:
    """Every posted figure must still appear, spelled as posted, in every document
    the ledger records as carrying it.

    Checking only the headline is not enough, and that gap is why this reads a
    per-figure list. The qualifications are where a column gets quietly inflated:
    a revision-2 pass reads very differently when the unchanged build scored
    132/138 than when it scored 138/138, and only one of those is what he posted.
    A run's secondary figures are not required to appear everywhere -- the
    revision-5 148/149 is carried by the changelog alone -- so where each one is
    carried is recorded rather than assumed.

    Presence is not a census either, and where a figure is stated several times
    the count is what closes the gap: asking only whether 153/153 still appears
    somewhere in the README says nothing about the two other places it appears,
    any one of which could be altered under a passing gate. The two publishing
    documents therefore record how many times each figure is stated and the count
    is asserted. ``vectors/CHANGES.md`` records ``null`` and is asked for presence
    only, because it is append-only history: a later entry citing an earlier
    figure legitimately adds a mention, and counting there would turn ordinary
    history-writing red.
    """
    out: list[str] = []
    cache: dict[str, str] = {}
    for run in runs:
        for figure in run.get("figures", []):
            for where in figure.get("carriedIn", []):
                rel = str(where.get("file"))
                text = cache.setdefault(rel, read(REPO_ROOT / rel))
                out.extend(_carried_failures(run, figure, where, rel, text))
    return out


def _carried_failures(
    run: dict[str, Any], figure: dict[str, Any], where: dict[str, Any], rel: str, text: str
) -> list[str]:
    fig = str(figure.get("figure"))
    said = f"{fig} as the {figure.get('role')} figure at suiteRevision {run['suiteRevision']}"
    want = where.get("times")
    found = text.count(fig)
    if want is None:
        return [] if found else [f"{rel}: the ledger records {said}, and it does not appear here."]
    if found != want:
        return [
            f"{rel}: the ledger records {said} as stated {want} time(s) here, and it "
            f"is stated {found}. Either a mention was altered, which is the defect "
            "this count exists to catch, or one was legitimately added or removed and "
            "the ledger has not been told."
        ]
    return []


def unprompted_failures(runs: list[dict[str, Any]], report: str) -> list[str]:
    """The figures that carry unprompted evidence are named as such in the
    report, and the ledger is what says which ones they are."""
    out: list[str] = []
    for run in runs:
        if not run.get("unprompted"):
            continue
        spelling = f"{headline(run)} at suiteRevision {run.get('suiteRevision')}"
        if spelling not in report:
            out.append(
                f"docs/IMPLEMENTATION-REPORT.md: the ledger calls {spelling} unprompted "
                "evidence, and the report does not name it that way."
            )
    return out


def quote_failures(quotes: list[dict[str, Any]]) -> list[str]:
    """His wording, verbatim, wherever this repository says it carries it.

    A shorter excerpt must be a contiguous substring of the fullest recorded
    wording, so a document cannot quietly carry a paraphrase that reads like a
    quotation of the same sentence.
    """
    out: list[str] = []
    longest = max((normalize(str(q["text"])) for q in quotes), key=len, default="")
    for quote in quotes:
        text = normalize(str(quote["text"]))
        if text not in longest:
            out.append(
                f"docs/INDEPENDENT-RUNS.json: the recorded wording {text[:60]!r}... is "
                "not an excerpt of the fullest wording recorded beside it, so one of "
                "the two is a paraphrase."
            )
        out.extend(
            f"{rel}: does not carry his wording verbatim: {text[:72]!r}..."
            for rel in quote.get("carriedIn", [])
            if text not in read(REPO_ROOT / str(rel))
        )
    return out


def current_revision_failures(report: str, current: int) -> list[str]:
    out: list[str] = []
    for template, want in CURRENT_REVISION_LITERALS:
        literal = template.format(n=current)
        found = report.count(literal)
        if found != want:
            out.append(
                f"docs/IMPLEMENTATION-REPORT.md: {literal!r} appears {found} time(s), "
                f"expected {want}. vectors/CHANGES.md says the corpus is at "
                f"suiteRevision {current}, and the report restates that number here."
            )
    return out


def collect() -> tuple[list[str], int, list[int]]:
    current, failures = current_revision()
    if failures:
        return failures, current, []
    ledger: dict[str, Any] = json.loads(LEDGER.read_text(encoding="utf-8"))
    runs: list[dict[str, Any]] = ledger["runs"]
    failures = ledger_failures(runs, current)
    if failures:
        return failures, current, []
    expected = not_run(runs, current)
    report = read(REPORT)
    for site in SITES:
        failures.extend(site_failures(site, expected))
    failures.extend(figure_failures(runs))
    failures.extend(unprompted_failures(runs, report))
    failures.extend(quote_failures(ledger["quotedWording"]))
    failures.extend(current_revision_failures(report, current))
    return failures, current, expected


def main() -> int:
    failures, current, expected = collect()
    if failures:
        print(
            f"FAIL: {len(failures)} independent-run claim(s) do not hold:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\ndocs/INDEPENDENT-RUNS.json is the record and the prose is derived from "
            "it. Never close one of these by adding a run that was not posted with a "
            "record and a source digest: an inaccurate independence claim is worse "
            "than no claim.",
            file=sys.stderr,
        )
        return 1
    listed = ", ".join(str(n) for n in expected) if expected else "none"
    print(
        f"OK: the corpus is at suiteRevision {current}; the independent checker has "
        f"posted no run for suiteRevision(s) {listed}, and every published claim "
        "names exactly that set."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
