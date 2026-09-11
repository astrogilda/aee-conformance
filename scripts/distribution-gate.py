#!/usr/bin/env python3
"""Distribution gate: the inbound page must still describe the repository it ships with.

`DISTRIBUTION.md` is the page a stranger lands on. Everything on it that matters
is a claim about the repository rather than an opinion about it, and every one of
those claims is a copy of something the repository already states elsewhere. A
copy with no invalidation is the defect this repository refuses everywhere else
it appears, so these are checked here rather than trusted.

What is checked, and what each one costs when it is wrong.

The RECIPE. The four-command release-verification block appears under the same
heading in `README.md` and in `DISTRIBUTION.md`. It is the one block in this
repository whose reader has, by construction, decided to trust nobody here: a
command that no longer works fails in the hands of exactly the person the page
was written for, and it fails silently in the sense that nothing in CI runs a
markdown fence. The two blocks are required to be byte-identical, which does not
prove either one runs and does mean that fixing one fixes both. The README
section is the explanatory home; this gate makes the second copy a copy rather
than a fork.

The TAG. The recipe checks out a tag, the inbound page names a tag to cite, and
the `go install` line pins one. `CITATION.cff` carries the released version and
is what GitHub's citation panel and an archive deposit read. All four are
required to agree. A page that tells a reader to cite a version the citation
file does not know about sends a citation into a permanent record naming bytes
no tag holds, and `scripts/citation-metadata-gate.py` already refuses that for
the deposit without ever reading the prose a human follows.

The CORPORA. The inbound page tables the corpora this repository ships, and the
independent-run issue form offers them as the choices a reporter picks from. The
set of tracked `<dir>/MANIFEST.json` files is what a tag actually publishes, and
each of those manifests names its own suite. A corpus that lands without a row
here is a corpus no arriving reader is told about; a corpus missing from the form
cannot have a run reported against it by the one route we ask people to use; and
a row or an option that outlives its corpus is worse than either, because it
advertises bytes the release does not carry. Every direction fails.

Vector COUNTS are deliberately not part of this gate's subject, because they are
deliberately not on the page. `scripts/count-gate.py` owns every published count
in this repository and the inbound page publishes none, pointing at
`release/CORPUS-DIGESTS.txt` and the manifests instead. A count in this table
would be a fourth copy, and this file would then be the fourth place to keep it
honest.

Usage:
    python3 scripts/distribution-gate.py
    python3 scripts/distribution-gate.py --root <tree>   (what its own tests run)

Exit 0 when the page agrees with the repository on every one of them; 1 on any
disagreement, and every disagreement is printed rather than only the first. There
is no partial pass: a page that is right about the corpora and wrong about the
tag is a page that misdirects a citation.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

README_REL = "README.md"
PAGE_REL = "DISTRIBUTION.md"
CITATION_REL = "CITATION.cff"
FORM_REL = ".github/ISSUE_TEMPLATE/independent-run.yml"

#: The heading both files put the verification recipe under. Matching on the
#: heading rather than on a line number keeps the gate working when either file
#: is reorganised, and makes a renamed heading a loud failure instead of a quiet
#: one: the recipe is findable by its own name or it is not findable.
RECIPE_HEADING = "Verify a release without trusting us"

#: The heading in DISTRIBUTION.md whose table lists the corpora. Same argument.
CORPORA_HEADING = "The corpora this repository ships"

FENCE = "```"


class GateError(Exception):
    """The page disagrees with the repository."""


def _read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.exists():
        raise GateError(f"{rel} does not exist, so nothing about it can be checked")
    return path.read_text(encoding="utf-8")


def recipe_block(text: str, rel: str) -> str:
    """The first fenced block under RECIPE_HEADING, fence lines included.

    Returned with the fences so that a change of language tag counts as a
    difference. `bash` and no tag render the same and are not the same thing to
    a reader deciding whether to paste the block into a shell.
    """
    marker = re.search(rf"^#+\s+{re.escape(RECIPE_HEADING)}\s*$", text, re.MULTILINE)
    if marker is None:
        raise GateError(
            f"{rel} has no heading '{RECIPE_HEADING}'. The recipe is found by its heading, "
            "so a renamed heading means the recipe cannot be checked at all."
        )
    start = text.find(FENCE, marker.end())
    if start == -1:
        raise GateError(f"{rel} has the heading '{RECIPE_HEADING}' and no fenced block under it")
    end = text.find(FENCE, text.index("\n", start))
    if end == -1:
        raise GateError(f"{rel}: the fenced block under '{RECIPE_HEADING}' is never closed")
    return text[start : end + len(FENCE)]


def released_version(text: str) -> str:
    """The `version` field of CITATION.cff, read without a YAML parser.

    A parser is the right tool and scripts/citation-metadata-gate.py uses one.
    This gate stays dependency-free on purpose: it is the gate that guards the
    page telling a stranger how to check a release, and a gate that cannot run
    in a fresh clone guards nothing there.
    """
    found = re.findall(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
    if len(found) != 1:
        raise GateError(
            f"{CITATION_REL} carries {len(found)} top-level `version:` lines; exactly one is "
            "readable. Two spellings of the released version is the drift this checks for."
        )
    return str(found[0]).strip("'\"")


def tags_claimed(page: str, recipe: str) -> dict[str, str]:
    """Every place the inbound page or the recipe commits to a version.

    Keyed by what the reader would be doing when they read it, because the
    failure message has to say which sentence sends them to the wrong bytes.
    """
    claims: dict[str, str] = {}

    checkout = re.search(r"^git checkout (v\S+)\s*$", recipe, re.MULTILINE)
    if checkout is None:
        raise GateError(
            "the verification recipe does not check out a tag. A recipe run on the default "
            "branch establishes which bytes the branch had today and nothing a citation can name."
        )
    claims["the recipe's `git checkout`"] = checkout.group(1)

    install = re.search(r"^go install \S+@(v\S+)\s*$", page, re.MULTILINE)
    if install is None:
        raise GateError(
            f"{PAGE_REL} has no `go install ...@vX` line. `@latest` moves, and a verifier that "
            "moves cannot be what a reported run was run with."
        )
    claims["the `go install` pin"] = install.group(1)

    heading = re.search(
        r"^#+\s+The tag to cite\s*$\s*\n\s*`(v[^`]+)`", page, re.MULTILINE
    )
    if heading is None:
        raise GateError(
            f"{PAGE_REL} has no 'The tag to cite' section opening with a backticked tag. "
            "The tag a citation should name is the first thing an arriving reader needs."
        )
    claims["the tag-to-cite section"] = heading.group(1)
    return claims


def tracked_corpora(root: Path) -> dict[str, str]:
    """Directory -> the suite name its manifest declares, for every tracked corpus.

    Enumerated from `git ls-files` rather than from a directory walk, for the
    reason scripts/release-digests.py gives: the tracked tree is what a tag
    publishes, so an untracked corpus on disk is not in the release and a
    tracked corpus missing from disk is a failure rather than a shorter list.
    """
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*/MANIFEST.json"],
        capture_output=True,
        text=True,
        check=True,
    )
    corpora: dict[str, str] = {}
    for rel in sorted(listed.stdout.split()):
        if rel.count("/") != 1 or not rel.endswith("/MANIFEST.json"):
            continue
        directory = rel.split("/")[0]
        if not (directory == "vectors" or directory.startswith("vectors-")):
            continue
        path = root / rel
        if not path.exists():
            raise GateError(f"{rel} is tracked and absent from disk")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        suite = manifest.get("suite")
        if not isinstance(suite, str) or not suite:
            raise GateError(f"{rel} declares no `suite`, so the table has nothing to agree with")
        corpora[directory] = suite
    if not corpora:
        raise GateError("no tracked corpus manifest was found; refusing to call the table correct")
    return corpora


def tabled_corpora(page: str) -> dict[str, str]:
    """Directory -> suite name, as the inbound page's corpora table states them."""
    marker = re.search(rf"^#+\s+{re.escape(CORPORA_HEADING)}\s*$", page, re.MULTILINE)
    if marker is None:
        raise GateError(f"{PAGE_REL} has no heading '{CORPORA_HEADING}'")
    section = page[marker.end() :]
    following = re.search(r"^#+\s+\S", section, re.MULTILINE)
    if following is not None:
        section = section[: following.start()]
    rows: dict[str, str] = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        directory = cells[0].strip("`").rstrip("/")
        suite = cells[1].strip("`")
        if directory == "vectors" or directory.startswith("vectors-"):
            if directory in rows:
                raise GateError(f"{PAGE_REL} tables `{directory}/` twice")
            rows[directory] = suite
    if not rows:
        raise GateError(
            f"{PAGE_REL}: the '{CORPORA_HEADING}' section tables no corpus. An empty table "
            "reads as a repository that ships none."
        )
    return rows


def offered_corpora(form: str) -> set[str]:
    """The corpus directories the independent-run form offers as choices.

    Read without a YAML parser for the reason released_version gives. The shape
    is fixed by the form: a dropdown's options are quoted scalars in a block
    list, and only the corpus dropdown's options are directory names.
    """
    offered = {
        match.group(1).rstrip("/")
        for match in re.finditer(r'^\s*-\s*"(vectors[^"]*)"\s*$', form, re.MULTILINE)
    }
    if not offered:
        raise GateError(
            f"{FORM_REL} offers no corpus to report a run against. A reporting path that "
            "cannot name the corpus collects a figure about nothing."
        )
    return offered


def _recipe_and_tag_failures(readme: str, page: str, citation: str) -> list[str]:
    """The recipe must be one recipe, and every tag on the page must be released.

    They are one function because the tag check reads the recipe: a recipe that
    could not be found is a tag check with nothing to read, and reporting a
    missing recipe followed by a missing tag would be one fault counted twice.
    """
    found: list[str] = []
    try:
        readme_recipe = recipe_block(readme, README_REL)
        page_recipe = recipe_block(page, PAGE_REL)
    except GateError as exc:
        return [str(exc)]

    if readme_recipe != page_recipe:
        found.append(
            f"the verification recipe differs between {README_REL} and {PAGE_REL}. "
            "They are two copies of one recipe and the reader who follows the stale one "
            "is the reader who trusts nobody here. Make them identical."
        )
    try:
        version = released_version(citation)
        for where, tag in tags_claimed(page, page_recipe).items():
            if tag != f"v{version}":
                found.append(
                    f"{where} names {tag}; {CITATION_REL} says the released version is "
                    f"{version}. A page that sends a citation to a version the citation "
                    "file does not know about names bytes no tag holds."
                )
    except GateError as exc:
        found.append(str(exc))
    return found


def _corpus_failures(root: Path, page: str, form: str) -> list[str]:
    """The table and the run form must both hold exactly the tracked corpus set."""
    found: list[str] = []
    try:
        tracked = tracked_corpora(root)
        tabled = tabled_corpora(page)
        offered = offered_corpora(form)
    except GateError as exc:
        return [str(exc)]

    for directory in sorted(set(tracked) - set(tabled)):
        found.append(
            f"`{directory}/` is a tracked corpus and {PAGE_REL} does not table it. "
            "An arriving reader is never told it exists."
        )
    for directory in sorted(set(tabled) - set(tracked)):
        found.append(
            f"{PAGE_REL} tables `{directory}/` and no such corpus is tracked. "
            "The page advertises bytes the release does not carry."
        )
    for directory in sorted(set(tracked) & set(tabled)):
        if tracked[directory] != tabled[directory]:
            found.append(
                f"`{directory}/` declares suite `{tracked[directory]}` in its manifest and "
                f"{PAGE_REL} tables it as `{tabled[directory]}`."
            )
    for directory in sorted(set(tracked) - offered):
        found.append(
            f"`{directory}/` is a tracked corpus and {FORM_REL} does not offer it. "
            "A run against it cannot be reported by the route we ask people to use."
        )
    for directory in sorted(offered - set(tracked)):
        found.append(f"{FORM_REL} offers `{directory}/` and no such corpus is tracked.")
    return found


def failures(root: Path) -> list[str]:
    """Every disagreement, collected rather than raised one at a time.

    A page wrong in two ways should print two lines. A gate that stops at the
    first fault turns one push into as many pushes as there are faults, and the
    second fault is then found by whoever the first fix was supposed to help.
    """
    try:
        readme = _read(root, README_REL)
        page = _read(root, PAGE_REL)
        citation = _read(root, CITATION_REL)
        form = _read(root, FORM_REL)
    except GateError as exc:
        return [str(exc)]

    return _recipe_and_tag_failures(readme, page, citation) + _corpus_failures(root, page, form)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()

    found = failures(args.root)
    if found:
        print("distribution-gate: the inbound page disagrees with the repository.")
        for line in found:
            print(f"  - {line}")
        return 1
    print(
        "OK: the verification recipe is one recipe, every tag on the inbound page is the "
        "released version, and the corpora table and the run form both name the tracked "
        "corpus set."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
