# A new `vectors-*` corpus

Use this template only for a pull request that adds a new sibling corpus
directory. A change to an existing corpus is an ordinary pull request and
`CONTRIBUTING.md` covers it.

A corpus here is a normative artifact: every vector in it obliges a third party
to implement a rule. The checklist below is what makes it possible for someone
who trusts neither of us to fetch the bytes and recompute the answer.

## What this corpus is

- **Specification it tests:** <name, and a link to the text>
- **Whose text it is:** <upstream project, or this repository, or a proposal>
- **Directory name:** `vectors-<name>/`
- **What it does not test:** <the sentence a citing author will need>

## Checklist

- [ ] **A manifest** at `vectors-<name>/MANIFEST.json` carrying, at minimum,
      the fields `vectors-ai-agent-action/MANIFEST.json` carries: the suite name,
      the predicate type, the outcome counts, the specification digest and
      provenance, the comparison surface, and a `corpusDigest`.
- [ ] **The digest is derived, never typed.** It is produced by regenerating the
      manifest, and `python3 vectors/gen_manifest.py` or the corpus's own
      equivalent reproduces it byte for byte.
- [ ] **A generator produces every vector file.** No vector is hand-written;
      `scripts/regenerability-gate.py` refuses a committed file no generator
      emits, and it refuses it on the push that adds it.
- [ ] **The specification is pinned by digest**, and the manifest says whether
      those bytes are upstream's as vendored or a proposal this repository is
      putting forward. A corpus that tests proposed text says so in the
      manifest and in every table that cites it.
- [ ] **Each vector names the rule it forces** and where the specification
      states it. A vector that pins an implementation's behaviour rather than a
      document's requirement is a regression test and does not belong in a
      corpus.
- [ ] **An indeterminate vector declares every reading** a conformant verifier
      may take, rather than a reject vector widened to accept both. A widened
      code set is satisfied by either answer and measures nothing.
- [ ] **The counts in the manifest and in any prose agree**, and
      `python3 scripts/count-gate.py` passes. A count in prose is a cache with
      no invalidation unless it is declared, delegated, frozen, or attributed to
      a revision in the sentence around it.
- [ ] **Provenance names you.** Your name is on the commits, and the manifest's
      provenance fields say whose specification text this corpus tracks and who
      authored the corpus. Co-authorship is the normal shape here, not an
      exception.
- [ ] **The full local gate run passes:**
      `uv run --with pyyaml python scripts/workflow-steps-gate.py`.

## What happens next

The corpus is reviewed for whether each vector forces something the
specification actually requires. A vector that settles a question the
specification leaves open is moved to the indeterminate set or dropped, and the
reason is recorded rather than applied silently. If anything is declined, it
becomes a row in [`DISPOSITIONS.md`](../../DISPOSITIONS.md) under a permanent
identifier, in your frame.
