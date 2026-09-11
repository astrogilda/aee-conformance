# Where this suite lives, and how to cite it

This file is for someone arriving from somewhere else. It answers four
questions: where the corpus is archived, what its name is in each place that
carries it, how to run it in one command, and how to cite what you ran.

It is deliberately inbound only. It does not record where this suite has been
submitted, who was asked to look at it, or what was said in reply. A file that
enumerated our own submissions would be a marketing document wearing a
distribution heading, and it would tell a reader nothing they can check.

## The one-command run

```bash
go install github.com/astrogilda/aee-conformance/cmd/aee-verify@latest
git clone https://github.com/astrogilda/aee-conformance
cd aee-conformance
python3 packaging/run_vectors.py --verifier "aee-verify --json"
```

The external contract that command speaks to is in
[`README.md`](README.md): a verdict in the exit status, one line of JSON on
stdout carrying the condition codes and the recomputed result, and a key policy
read from `AEE_SUBSTRATE_KEYS`. Any verifier that speaks it can be driven the
same way, and that is the point of the contract existing at all.

**A disagreement is the interesting outcome.** If your verifier and this corpus
answer differently on a vector, open an issue. It is a defect in one of the two
of them and it does not matter which; the corpus has been corrected by an
outside reader before, and the two rules that came out of it are why the
external contract is written down.

## Archive and identifiers

| Surface | Identifier | State |
| --- | --- | --- |
| Source of record | `github.com/astrogilda/aee-conformance` | live |
| Releases | git tags `v0.6.0` onward, with a GitHub Release object per tag | live |
| Corpus digest, AEE corpus | `corpusDigest` in `vectors/MANIFEST.json` | live, derived |
| Corpus digest, agent-action corpus | `corpusDigest` in `vectors-ai-agent-action/MANIFEST.json` | live, derived |
| Archival DOI | minted per release once the archive integration is enabled | not yet minted |
| Package registries | no package of this corpus is published anywhere today | none |
| Mirrors | none | none |

Nothing in the two rows at the bottom is a plan stated as a fact. When a DOI
exists it goes in that cell with the DOI itself, and until then the cell says
what is true.

## How to cite it

[`CITATION.cff`](CITATION.cff) is the machine-readable form and GitHub renders a
citation from it. Cite the corpus you actually ran, which means naming three
things and not two:

- the **repository**, by URL;
- the **suiteRevision** you ran against, from the head of
  [`vectors/CHANGES.md`](vectors/CHANGES.md);
- the **corpusDigest** from the manifest of the corpus you ran.

A citation that names only the repository names a moving target. The revision
number and the digest are what make a reader able to fetch the same bytes you
had. The changelog is per revision and says, for each one, what that revision
does not exercise, which is usually the sentence a citing author needs.

## The corpora this repository ships

Two, and they are not interchangeable. `vectors/` is the corpus for the
adversarial-execution-evidence predicate this repository vendors.
`vectors-ai-agent-action/` is a separate corpus against a different upstream
predicate, carrying its own manifest, its own digest and its own provenance
fields naming whose text it tracks. Every count, every digest and every run
report is scoped to one of them; a figure that does not say which corpus it
belongs to is not a figure about anything.

## Adding a corpus of your own

A new corpus lands here as a sibling `vectors-<name>/` directory rather than as
a new repository, on the pattern `vectors-ai-agent-action/` already sets. The
contract for one is in
[`.github/PULL_REQUEST_TEMPLATE/vectors-directory.md`](.github/PULL_REQUEST_TEMPLATE/vectors-directory.md):
a manifest, a derived digest, a generator that reproduces every byte, a pin to
the specification text it tests, and your name on the commit and in the
manifest's provenance.

The reason it is one repository is that a reader who has verified one corpus
here has already installed the verifier, already read the external contract, and
already knows what a `corpusDigest` is worth. Splitting the corpora across
repositories would spend all of that a second time.

## Reporting a run

[`RUNS.md`](RUNS.md) records every run of these corpora by an implementation
independent of this repository, in the reporter's own words. If you run the
suite, the form at
[`.github/ISSUE_TEMPLATE/independent-run.yml`](.github/ISSUE_TEMPLATE/independent-run.yml)
is the whole reporting path. A run that disagreed with the corpus is more
valuable there than one that agreed.
