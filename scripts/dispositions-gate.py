#!/usr/bin/env python3
"""Disposition gate: an objection this suite received is answered in public, and
the answer is checked against the repository that received it.

Why a disposition ledger needs a gate
-------------------------------------
A disposition of comments is the record of every objection an artifact received,
who raised it, what was decided and why. It is the oldest credibility instrument
in standards practice and it is cheap to fake, which is exactly why it is worth
holding to a machine: a ledger that records only the objections the author was
happy to accept is worse than no ledger, because it reads as evidence of scrutiny
while being evidence of selection.

So the ledger below is not free prose. Every row makes claims about things that
happened -- somebody said something, a revision landed, a vector was added -- and
every one of those claims resolves against a primary record that already exists
in this repository:

  vectors/CHANGES.md         owns revision numbering. A row claiming to have
                             landed at a revision that file does not carry is
                             refused.
  vectors/MANIFEST.json      owns the corpus. A row citing a vector the corpus
                             does not contain is refused.
  the recordedIn anchors     each row names files that already describe the
                             event, and a phrase from each. The phrase has to be
                             present. A row about an objection no prior record
                             carries cannot be written here, and a row whose
                             record is later reworded fails rather than going
                             quietly stale.

The last of those three is the load-bearing one, and it runs one way on purpose.
It stops this file inventing history. It cannot stop this file omitting history:
nothing here can tell that an objection was received and never written down. That
gap is real, it is named in DISPOSITIONS.md in the same words, and the only thing
that closes it is the objector, who can see their own comment is missing.

Render, not check
-----------------
The published table is GENERATED from the ledger and the gate diffs it, which is
the opposite of what scripts/count-gate.py argues for its own subject and for the
same reason. That gate's subject is sentences that argue, where an emitter could
only ever restate what it read. This one's subject is a table: rows in fixed
columns with no argument in them, which is the shape docs/COVERAGE-MATRIX.md
already takes here. The argued prose in DISPOSITIONS.md sits outside the
generated span, is written by hand, and is never touched by --render.

Usage:
    python3 scripts/dispositions-gate.py            check the ledger and the table
    python3 scripts/dispositions-gate.py --render   rewrite the generated span
    python3 scripts/dispositions-gate.py --root DIR check a staged copy

Exit 0 when every row resolves and the published table is the rendered one; 1 on
any disagreement, naming each. The run prints the tally by resolution, which is
the one derived source for any count of these rows: no number about this ledger
is written by hand anywhere, here or in the prose.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_REL = "docs/DISPOSITIONS.json"
PUBLISHED_REL = "DISPOSITIONS.md"
CHANGES_REL = "vectors/CHANGES.md"
MANIFEST_REL = "vectors/MANIFEST.json"

BEGIN = "<!-- rendered from docs/DISPOSITIONS.json by scripts/dispositions-gate.py -->"
END = "<!-- end rendered -->"

# Headings the published file may not lose. The appeal route is one of them
# because a disposition process with no stated way to contest a disposition is a
# publication rather than a process, and the heading is the cheapest thing to
# delete in a tidy-up.
REQUIRED_HEADINGS = (
    "## If you disagree with a disposition",
    "## What this ledger cannot catch",
)

ENTRY_ID = re.compile(r"^DC-\d\d$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)

# A resolution that leaves something unsettled has to say what, in the row
# itself. A partial disposition with no residual is how a gap gets absorbed by a
# status word.
RESIDUAL_REQUIRED = frozenset({"adopted-in-part", "open"})

REQUIRED_TEXT = (
    "raisedBy",
    "relationship",
    "raisedIn",
    "objectionForm",
    "objection",
    "resolution",
    "reason",
)


def source(rel: str) -> Path:
    return REPO_ROOT / rel


def flex(text: str) -> re.Pattern[str]:
    """Match ``text`` with every whitespace run free to rewrap.

    Every file this gate reads is hard-wrapped and rewrapped freely, so an anchor
    matched on literal bytes would fail on a reflow that changed nothing.
    """
    parts = re.split(r"(\s+)", text)
    return re.compile("".join(r"\s+" if p.isspace() else re.escape(p) for p in parts))


def load_json(rel: str) -> Any:
    return json.loads(source(rel).read_text(encoding="utf-8"))


def known_revisions() -> set[int]:
    text = source(CHANGES_REL).read_text(encoding="utf-8")
    return {int(m.group(1)) for m in REVISION_HEADING.finditer(text)}


def known_vectors() -> set[str]:
    manifest = load_json(MANIFEST_REL)
    return {str(v["id"]) for v in manifest["vectors"]}


def text_failures(entry: dict[str, Any], where: str) -> list[str]:
    """Every field that has to carry words, carrying words."""
    out = []
    for field in REQUIRED_TEXT:
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            out.append(f"{where}: {field} is empty or absent, and a row without it says nothing.")
    return out


def vocabulary_failures(entry: dict[str, Any], ledger: dict[str, Any], where: str) -> list[str]:
    """The two closed vocabularies, read from the ledger's own declaration."""
    out = []
    resolutions = set(ledger["resolutions"])
    forms = set(ledger["objectionForm"]["values"])
    if entry.get("resolution") not in resolutions:
        out.append(
            f"{where}: resolution {entry.get('resolution')!r} is not one of "
            f"{sorted(resolutions)}, which this ledger declares and defines."
        )
    if entry.get("objectionForm") not in forms:
        out.append(
            f"{where}: objectionForm {entry.get('objectionForm')!r} is not one of "
            f"{sorted(forms)}. Whether an objection is quoted or paraphrased changes "
            "what the row is evidence of, so it is never left unstated."
        )
    return out


def optional_pair_failure(entry: dict[str, Any], value: str, note: str, why: str) -> list[str]:
    """A nullable field is null WITH a note, or carries a value. Never neither.

    An absent field and an unrecorded fact read the same in a diff, which is the
    rule docs/INDEPENDENT-RUNS.json already holds itself to.
    """
    if entry.get(value) is not None:
        return []
    if isinstance(entry.get(note), str) and entry[note].strip():
        return []
    return [f"{value} is null and {note} does not say why. {why}"]


def anchor_failures(entry: dict[str, Any], where: str) -> list[str]:
    """Every row resolves against a record this repository already carries."""
    records = entry.get("recordedIn")
    if not isinstance(records, list) or not records:
        return [
            f"{where}: recordedIn is empty. A disposition row is a claim about something "
            "that happened, and it may not be written unless a primary record in this "
            "repository already carries it."
        ]
    out = []
    for record in records:
        path = source(str(record["file"]))
        if not path.is_file():
            out.append(f"{where}: recordedIn names {record['file']}, which does not exist.")
            continue
        if not flex(str(record["anchor"])).search(path.read_text(encoding="utf-8")):
            out.append(
                f"{where}: {record['file']} no longer carries {record['anchor']!r}. Either "
                "the record was reworded, in which case this row needs the new wording, or "
                "the row is describing something that file does not say."
            )
    return out


def entry_failures(
    entry: dict[str, Any], ledger: dict[str, Any], revisions: set[int], vectors: set[str]
) -> list[str]:
    where = str(entry.get("id"))
    out = text_failures(entry, where)
    out += vocabulary_failures(entry, ledger, where)
    out += [
        f"{where}: {failure}"
        for failure in optional_pair_failure(
            entry,
            "date",
            "dateNote",
            "An undated objection is fine; an unexplained absence is not.",
        )
        + optional_pair_failure(
            entry,
            "landedAtRevision",
            "landedNote",
            "A row that landed nowhere has to say what it changed instead.",
        )
    ]
    revision = entry.get("landedAtRevision")
    if revision is not None and revision not in revisions:
        out.append(
            f"{where}: landedAtRevision {revision} is not a revision {CHANGES_REL} carries. "
            "That file owns revision numbering; a row may not name a revision it does not."
        )
    if isinstance(entry.get("date"), str) and not ISO_DATE.match(entry["date"]):
        out.append(f"{where}: date {entry['date']!r} is not an ISO calendar date.")
    for vector in entry.get("vectors") or []:
        if vector not in vectors:
            out.append(f"{where}: vector {vector!r} is not in {MANIFEST_REL}.")
    residual = entry.get("residual")
    if entry.get("resolution") in RESIDUAL_REQUIRED and not residual:
        out.append(
            f"{where}: a {entry.get('resolution')!r} row states its residual, or the status "
            "word is absorbing a gap nobody is tracking."
        )
    out += anchor_failures(entry, where)
    return out


def ledger_failures(ledger: dict[str, Any]) -> list[str]:
    entries = ledger.get("entries")
    if not entries:
        return [
            f"{LEDGER_REL} carries no entries. An empty ledger passes every check below "
            "while enforcing nothing, and this repository has shipped that shape before."
        ]
    out = []
    seen: list[str] = []
    for entry in entries:
        entry_id = str(entry.get("id"))
        if not ENTRY_ID.match(entry_id):
            out.append(f"{entry_id!r} is not an identifier of the form DC-NN.")
        if entry_id in seen:
            out.append(f"{entry_id} appears more than once, so two rows can disagree.")
        seen.append(entry_id)
    if seen != sorted(seen):
        out.append(
            "the entries are not in identifier order. The ledger is append-only, so an "
            "out-of-order row is either an insertion into history or a renumbering."
        )
    return out


def cell(text: str) -> str:
    """One table cell: no pipes, no line breaks, nothing that reflows the row."""
    return " ".join(text.split()).replace("|", "\\|")


def landed(entry: dict[str, Any]) -> str:
    revision = entry.get("landedAtRevision")
    return f"suiteRevision {revision}" if revision is not None else "no corpus revision"


def evidence(entry: dict[str, Any]) -> str:
    vectors = entry.get("vectors") or []
    return ", ".join(f"`{v}`" for v in vectors) if vectors else "none"


def render_index(entries: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| # | Raised by | Where | Resolution | Landed | Forcing vectors |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for entry in entries:
        lines.append(
            f"| {entry['id']} | {cell(str(entry['raisedBy']))} | {cell(str(entry['raisedIn']))} "
            f"| **{entry['resolution']}** | {landed(entry)} | {cell(evidence(entry))} |"
        )
    return lines


def render_entry(entry: dict[str, Any]) -> list[str]:
    lines = [
        f"### {entry['id']} · {cell(str(entry['raisedIn']))}",
        "",
        f"**Raised by** {entry['raisedBy']}, {entry['relationship']}. "
        f"**Date** {entry.get('date') or 'not recorded: ' + str(entry.get('dateNote'))}.",
        "",
        f"**The objection** ({entry['objectionForm']}). {entry['objection']}",
        "",
        f"**Resolution: {entry['resolution']}.** {entry['reason']}",
    ]
    if entry.get("landedAtRevision") is None:
        lines += ["", f"**No corpus revision.** {entry['landedNote']}"]
    if entry.get("residual"):
        lines += ["", f"**Residual.** {entry['residual']}"]
    if entry.get("note"):
        lines += ["", f"**Note.** {entry['note']}"]
    anchors = ", ".join(f"`{r['file']}`" for r in entry["recordedIn"])
    lines += ["", f"**Recorded in** {anchors}.", ""]
    return lines


def render(ledger: dict[str, Any]) -> str:
    entries = list(ledger["entries"])
    lines = [BEGIN, "", *render_index(entries), ""]
    for entry in entries:
        lines += render_entry(entry)
    lines.append(END)
    return "\n".join(lines)


def span(text: str) -> tuple[int, int] | None:
    start = text.find(BEGIN)
    end = text.find(END)
    if start == -1 or end == -1 or end < start:
        return None
    return start, end + len(END)


def published_failures(ledger: dict[str, Any]) -> list[str]:
    path = source(PUBLISHED_REL)
    if not path.is_file():
        return [f"{PUBLISHED_REL} does not exist, so the ledger is not published anywhere."]
    text = path.read_text(encoding="utf-8")
    out = [
        f"{PUBLISHED_REL} has lost the heading {heading!r}, which it may not."
        for heading in REQUIRED_HEADINGS
        if heading not in text
    ]
    bounds = span(text)
    if bounds is None:
        return out + [
            f"{PUBLISHED_REL} carries no rendered span. It opens with {BEGIN!r} and closes "
            f"with {END!r}; run --render."
        ]
    if text[bounds[0] : bounds[1]] != render(ledger):
        out.append(
            f"{PUBLISHED_REL}: the published table is not the one {LEDGER_REL} renders. The "
            "ledger is the source, so fix the ledger and run --render; editing the table "
            "alone changes what a reader sees and not what the gate reads."
        )
    return out


def write_render(ledger: dict[str, Any]) -> int:
    path = source(PUBLISHED_REL)
    text = path.read_text(encoding="utf-8")
    bounds = span(text)
    if bounds is None:
        print(f"FAIL: {PUBLISHED_REL} carries no rendered span to write into.", file=sys.stderr)
        return 1
    path.write_text(text[: bounds[0]] + render(ledger) + text[bounds[1] :], encoding="utf-8")
    print(f"wrote the rendered span into {PUBLISHED_REL}")
    return 0


def tally(ledger: dict[str, Any]) -> str:
    counts: dict[str, int] = {}
    for entry in ledger["entries"]:
        key = str(entry.get("resolution"))
        counts[key] = counts.get(key, 0) + 1
    parts = ", ".join(f"{name} {counts[name]}" for name in sorted(counts))
    return f"{len(ledger['entries'])} objection(s) recorded: {parts}"


def collect(ledger: dict[str, Any]) -> list[str]:
    failures = ledger_failures(ledger)
    if failures:
        return failures
    revisions = known_revisions()
    vectors = known_vectors()
    for entry in ledger["entries"]:
        failures += entry_failures(entry, ledger, revisions, vectors)
    return failures + published_failures(ledger)


def main(argv: list[str]) -> int:
    global REPO_ROOT  # noqa: PLW0603 -- --root is how the gate's tests point it at a copy
    parser = argparse.ArgumentParser(description="check the disposition ledger")
    parser.add_argument("--render", action="store_true", help="rewrite the generated span")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="the tree to check")
    args = parser.parse_args(argv[1:])
    REPO_ROOT = args.root.resolve()
    ledger = load_json(LEDGER_REL)
    if args.render:
        return write_render(ledger)
    failures = collect(ledger)
    if failures:
        print(f"FAIL: {len(failures)} disposition claim(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nA disposition row is a claim about something that happened. Fix it by "
            "correcting the row to what the record says, never by editing the record to "
            "match the row. A new row needs a primary record in this repository to point "
            "at; if there is none, write the record first.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: {tally(ledger)}. Every row resolves, and {PUBLISHED_REL} is the rendered table.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
