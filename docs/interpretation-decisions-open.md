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

## RESOLVED: Corner A -- Duplicate `attackId` rows

**Question.** Two `attackResults` rows carry the same `attackId`. Legal (union
semantics) or a malformed statement?

**Resolution (locked).** Duplicate `attackId` rows are **malformed**. "One row
per executed attack" is a well-formedness invariant, so a statement carrying two
rows with the same `attackId` is rejected. This is the converged debate's
recommended direction (open point 1): a single attack with two rows is a
producer-assembly bug, and two contradictory rows for one attack (e.g. one
caught, one clean) is exactly the ambiguity the recompute must not arbitrate.

- **Spec.** A sentence was added to the `attackResults` paragraph (L385-398):
  no two rows may carry the same `attackId`; coverage integrity set-compares row
  `attackId`s, so a duplicate would silently collapse under set semantics, and
  uniqueness is enforced separately, before that comparison.
- **Rails.** Both rails detect the duplicate BEFORE building the rowID set (Go
  `gate0CoverageIntegrity`, Python `_coverage_check_rows`), emitting
  `statement-malformed`. Previously the set-based coverage check absorbed the
  duplicate with no effect (all rails accepted).
- **Vector.** `bad-729-duplicate-attackid-rows` (a second row with the same
  `attackId` -> `statement-malformed`). Registry decision 13.

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

## RESOLVED: Corner C -- Artifact-only statement with two subjects

**Question.** A statement whose rows are all `basis: artifact` carries two
`subject` entries. Legal or malformed?

**Resolution (locked).** The one-subject requirement is now **unconditional**:
`subject` MUST contain exactly one entry on a statement of **any** basis, and a
statement carrying zero or more than one subject is malformed regardless of
whether any row is `basis: substrate`. Only the six binding-digest-input
requirement stays scoped to substrate-row-carrying statements. This is the
converged debate's recommended direction (open point 3): one executed artifact
per statement is the model everywhere else, and a two-subject artifact-only
statement has no coherent meaning.

- **Spec.** L122-126 was split: the cardinality half is stated unconditional
  ("on a statement of any basis"); the digest-input half keeps the
  substrate-row-carrying scope.
- **Rails.** The subject-cardinality check was hoisted out of the
  substrate-only path into unconditional Gate0 (Go `Gate0` step 9b, Python
  `_check_subject_cardinality`); the substrate-scoped binding-digest-input
  check is unchanged. Previously both rails accepted an artifact-only
  two-subject statement (cardinality ran only under `hasSubstrateRows`).
- **Vector.** `bad-728-artifact-two-subjects` (an artifact-only statement with a
  second subject -> `subject-cardinality`). `bad-607` retains the substrate
  case. Decision 12 in the registry lists both.
- **Reversibility.** The direction (unconditional vs substrate-scoped) is an
  editorial call recorded for vetting; it can be reversed there.

---

## RESOLVED: decision 8 zero-offset sub-reading (was a rail gap; now locked)

The independent checker read `armedAt` as "RFC 3339 with a **zero offset**"
(the spec says "RFC 3339 UTC"). Both our rails previously accepted a non-`Z`
offset (Go `time.Parse` and the Python `RFC3339_RE` both admit `[+-]HH:MM`) and
compared `armedAt`/`issuedAt` as instants, so an offset `armedAt` whose instant
precedes `issuedAt` was accepted. The independent-checker grok classified this
as a real rail bug rather than an editorial call: the spec already mandates UTC,
so accepting `+05:00` is out of spec. **Fixed:** the spec text now pins the zero
UTC offset (`Z` or `+00:00`, never a non-zero offset) explicitly, both rails
reject a non-zero offset (Go checks `t.Zone()` offset is 0; Python
`_armed_utc_offset_ok`), and `bad-727-armedat-non-utc-offset` locks it (a valid
`+05:00` instant before `issuedAt`, rejected as `arming-covers-nothing`,
distinct from a late `armedAt`). Decision 8 in the registry now lists bad-727.
Retained here for the audit trail. Rail propagation to the probity and mcp
verifier rails is a follow-up (tracked with corners A and C below).
