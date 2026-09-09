# When an interoperability claim is evidence

Status: proposal, and a checker. The rule below is implemented in
`vectors-mcp-record-contract/check_run_record.py` and measured against
`vectors-mcp-record-contract/`, so it is not a rule anyone has to take on
trust.

## The rule

**An interoperability claim is evidence only when its run record is
re-checkable.** A claim is re-checkable when a third party can obtain the same
result from what is published and compare it byte for byte. That reduces to
four inputs, per direction of the cross-run:

1. **The inputs, at an immutable reference.** A commit identifier or a digest.
   A repository name plus a version string names a thing that can change under
   the claim. One project in this area published a tag against the wrong
   commit and left it in place rather than moving it, which was the right call
   and is also the demonstration that a tag can be moved.
2. **The runner, at an immutable reference or a digest.** Naming the library
   the runner was built on is not naming the runner. The driver that loaded the
   inputs and emitted the result is the part a third party has to have, and it
   is the part most often absent while both endpoints resolve cleanly.
3. **The invocation, verbatim.** A reader holding the inputs and the runner and
   not the invocation knows what ran and not what was asked of it, and a
   cross-run whose two sides ran different subsets is not a cross-run.
4. **The result, published, with a digest.** The digest is what turns a re-run
   into a comparison. Without the file, the digest is a promise about a file
   nobody else can hold; without the digest, the file is an unpinned artifact.

## Two declarations that decide what the number means

These do not decide whether a result can be obtained. They decide what it says,
so a checker reports them separately rather than folding them into one verdict.

**The counting rule.** A figure states what its denominator counts and how a
member that was not scored is counted. A figure written as N of N is read as N
passes. The same run is honestly describable as N members with no failures when
some were deliberately not scored, and those are different claims. A record can
enumerate its unscored members by name one line down and still publish a
headline with a whole numerator, and the headline is the half a reader quotes.
That case is a member of the corpus, and it is the one that separates a checker
reading the record from a checker reading the summary.

**Independence.** One of three: independent, self-report, or undeclared. A run
of somebody else's vectors by their author is worth publishing and is not
independent evidence. Only the third value is a defect: a declared self-report
tells a reader exactly what it is, and an undeclared record leaves the reader
to guess, so a checker that failed self-reports would push records towards
leaving the declaration out.

**The environment is noted and does not fail a record.** A result that turns
out not to depend on the runtime is a stronger result, and nobody can establish
that from a record that never named one.

## What a checker answers

Three answers, and keeping them apart is the point:

| answer | question |
|---|---|
| `recheckable` | can a third party obtain the same result from what is published |
| `figureMeansWhatItSays` | does the headline agree with its own counting rule |
| `independence` | independent, self-report, or undeclared |

A record can be fully re-checkable, carry a figure nobody should quote, and be
a declared self-report. Folding those into one pass is how each of them
disappears.

## Why this is not a documentation preference

An audit of one published cross-run claim in an open specification thread found
both halves of a paired figure presented in one table cell. One half was
re-checkable: the inputs were pinned at a tag object that resolves, the runner
was published, the invocation was in the repository's own instructions, and the
result file carried a reference digest. Re-running it reproduced that digest
byte for byte, on a runtime the record never named.

The other half was not, and the missing input was exactly item 2: both
endpoints resolved, and the driver between them existed nowhere. It was absent
from the working tree of the repository the claim named, absent from every
branch of its history, and absent from the repository that published the claim,
each established with a positive control on the same search path. Nothing about
the two halves distinguished them in the table.

The same claim also compressed a figure. The published run behind it recorded a
count of members with no failures, and six of those members were classified by
the runner as deliberately out of scope, by name, in the same paragraph. In the
table cell it appears as a whole numerator with no footnote.

Neither half of that is dishonest. Both are what happens when a table has one
column and the record behind it has three.

## Where these vectors land upstream

The conformance suite for this protocol takes a test case as two artifacts,
and a vector family for a record contract is no exception.

- A requirement row per rule, in the suite's per-proposal traceability file
  (`src/seps/sep-<NNNN>.yaml`), each row carrying either a `check:` slug that
  an emitted check must match exactly, or an `excluded:` reason.
- One scenario class per family, in `src/scenarios/server/`, emitting many
  checks rather than many scenarios, because each scenario spins its own server
  in continuous integration for every implementation.
- Registration in `src/scenarios/index.ts`, which is the suite's registry and
  the only place a scenario becomes reachable.
- An entry in `requirements/<spec-version>.yaml` only if a revision requires
  the family to be scored.

The suite's contribution rules ask for an issue first and a run against a real
implementation before a pull request, and they forbid a parallel entry point.
Nothing here proposes one: the checker in this repository is a reference for
the rule, and the upstream shape is a scenario emitting one check per rule
above.

## What this does not claim

It does not say a claim failing the rule is false. It says the claim is an
assertion, which is a statement about what a reader can do with it rather than
about whether it is true. A self-report from a careful engineer is frequently
correct and is not evidence, and the distinction is the entire content of this
document.
