# Open interpretation decisions (operator sign-off required)

The AEE v0.6 spec (`spec/predicates/adversarial-execution-evidence.md`) leaves a
handful of corners where the correct answer is a genuine **design call with
trade-offs**, not a reading the spec text forces. An independent from-spec
verifier (in-toto/attestation PR #570) reached the same verdict as our two rails
on the eleven load-bearing interpretation decisions (all now locked by forcing
vectors and recorded in `vectors/interpretation-decisions.json`), but recorded
these corners as places its author had to choose without the spec deciding for
them.

Per the conservative stance for this corpus, **none of these is resolved by a
vector**: adding a reject or accept vector would silently commit the suite (and
every consumer that certifies against it) to one side of an unresolved semantic
question. Each needs an operator decision and, ideally, a spec sentence that
makes the reading explicit, before it is locked.

Behavior of the two rails today (Go `aee/`, Python `packaging/run_vectors.py`)
is stated for each so the operator knows the current default.

---

## Corner A -- Duplicate `attackId` rows

**Question.** Two `attackResults` rows carry the same `attackId`. Legal (union
semantics) or a malformed statement?

- **Spec.** `attackResults` is "one row per executed attack" (L381), which reads
  as one row *per* attack; but coverage integrity keys on the **set** of row
  attackIds against the manifest (L413-416), and set semantics naturally dedupe.
  No sentence explicitly forbids a repeated `attackId`.
- **Current rails.** **Accept** (union): coverage integrity uses a set of row
  attackIds, so a duplicate row is absorbed with no effect.
- **From-spec checker.** Accept (union). No divergence.
- **Trade-offs.** Union-accept is forgiving and matches the set-based coverage
  check, but lets a producer carry two contradictory rows for one attack (e.g.
  one caught, one clean) with the `result` recompute reading both. Reject-as-
  malformed enforces "one row per attack" and removes the contradiction, at the
  cost of a stricter producer contract.
- **Recommendation.** **Reject duplicate `attackId` rows** as malformed. A
  single attack with two rows is a producer-assembly bug, and two contradictory
  rows for one attack is exactly the ambiguity the recompute should not have to
  arbitrate. Needs a spec sentence: "An `attackId` MUST NOT appear on more than
  one `attackResults` row." Then lock with a reject vector.

## Corner B -- `assessedClasses` overlapping the gap maps

**Question.** A class appears in both `coverage.assessedClasses` **and** one of
`coverage.outOfScope` / `coverage.routedElsewhere`. Contradiction (reject) or
tolerated (union)?

- **Spec.** "Disclosing a gap **moves** the class into one of these maps"
  (L376-379) reads as exclusive placement, and the run-binding/coverage prose
  treats the three sets as a partition of the manifest's classes; but there is
  no explicit "MUST NOT overlap".
- **Current rails.** **REJECT.** Both rails enforce an exhaustive, *disjoint*
  partition: each manifest class must be accounted exactly once across the three
  sets, so a class in two sets fails with `coverage-incomplete`
  (`aee/statement.go` `gate0CoverageIntegrity`, `run_vectors.py`
  `_coverage_partition_ok`).
- **From-spec checker.** **Accept** (union) -- overlap tolerated.
- **This is a live divergence.** Our rails and the independent checker disagree.
  It has not broken parity only because **no corpus vector exercises overlap**.
  A vector added on either side would immediately split the two implementations.
- **Trade-offs.** Disjoint-partition (reject) makes "assessed" and "disclosed
  gap" mutually exclusive, so a class cannot be simultaneously claimed as
  assessed and excused as out of scope -- the honest reading of "moves the class
  into". Union-accept is more permissive but lets a producer double-book a class,
  muddying what the `degraded` result actually bounds.
- **Recommendation.** **Keep the disjoint-partition (reject) reading** the rails
  already implement, and make it explicit in the spec: "A class MUST appear in
  exactly one of `assessedClasses`, `outOfScope`, `routedElsewhere`." Only after
  that spec change should a forcing vector be added; until then the rails are
  opinionated ahead of the text, which is the gap to close.

## Corner C -- Artifact-only statement with two subjects

**Question.** A statement whose rows are all `basis: artifact` carries two
`subject` entries. Legal or malformed?

- **Spec.** "For this predicate `subject` MUST contain exactly one entry ...; a
  **substrate-row-carrying statement** violating either requirement is
  malformed" (L122-124). The malformedness is explicitly scoped to
  substrate-row-carrying statements; an artifact-only statement derives no run
  binding and the cardinality rule's enforcement clause does not name it.
- **Current rails.** **Accept.** Subject cardinality is checked only when the
  statement carries a substrate row (`gate0SubstrateBindingInputs` runs under
  `hasSubstrateRows`; the Python rail mirrors this).
- **From-spec checker.** Accept. No divergence.
- **Trade-offs.** Accept follows the literal scope of the malformedness sentence
  and keeps artifact-only evidence permissive. Reject (extending "exactly one
  entry" to all statements) is simpler to state and avoids a statement whose
  single derived-binding path would be ambiguous if it later gained a substrate
  row, at the cost of contradicting the current scoped text.
- **Recommendation.** **Extend the one-subject requirement to every statement**
  (drop the "substrate-row-carrying" scope on the cardinality half, keeping it
  only on the six-digest-input half). One executed artifact per statement is the
  model everywhere else; a two-subject artifact-only statement has no coherent
  meaning. Needs the spec edit, then lock with a reject vector. `bad-607` already
  keeps a substrate row precisely so the current (scoped) rule undeniably
  applies; the artifact-only case is the open half.

---

## Also flagged: decision 8 zero-offset sub-reading (not a corner, a rail gap)

The independent checker read `armedAt` as "RFC 3339 with a **zero offset**"
(L659-663, "RFC 3339 UTC"). Both our rails currently accept a non-`Z` offset
(Go `time.Parse` and the Python `RFC3339_RE` both admit `[+-]HH:MM`) and compare
`armedAt`/`issuedAt` as **instants**, so an offset `armedAt` whose instant
precedes `issuedAt` is accepted today. The instant comparison is locked
(bad-702); the zero-offset strictness is **not** locked, because doing so would
change rail behavior on an arguably-ambiguous reading of "RFC 3339 UTC". If the
operator wants strict UTC-only `armedAt`, both rails must first reject a non-`Z`
offset, then a forcing vector can lock it. Recorded here so it is not silently
adopted or silently dropped.
