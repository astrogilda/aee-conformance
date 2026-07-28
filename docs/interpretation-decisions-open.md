# Open interpretation decisions (operator sign-off required)

The AEE v0.6 spec (`spec/predicates/adversarial-execution-evidence.md`) leaves a
handful of corners where the correct answer is a genuine **design call with
trade-offs**, not a reading the spec text forces. An independent from-spec
verifier (in-toto/attestation PR #570) reached the same verdict as our two rails
on the eleven load-bearing interpretation decisions (all now locked by forcing
vectors and recorded in `vectors/interpretation-decisions.json`), but recorded
these corners as places its author had to choose without the spec deciding for
them.

**Status: all three corners (A, B, C) are now RESOLVED** in the direction of a
converged 29-agent adversarial debate, each pinned in the spec text, locked by a
forcing vector, and recorded as a `forced` decision in
`vectors/interpretation-decisions.json` (`openCorners` is now empty). The
sections below are retained for the audit trail. Corner B is the single
editorial call (keep our existing reject reading) and is reversible at vetting;
A and C fixed a genuine under-enforcement present in every rail. Rail
propagation to the first-party verifier rails is a follow-up.

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

## RESOLVED: Corner B -- `assessedClasses` overlapping the gap maps

**Question.** A class appears in both `coverage.assessedClasses` **and** one of
`coverage.outOfScope` / `coverage.routedElsewhere`. Contradiction (reject) or
tolerated (union)?

**Resolution (locked).** **Keep the disjoint-partition (reject) reading** the
rails already implement, and make it explicit in the spec. This was a **live
divergence**: our two rails reject the overlap (disjoint partition) while the
independent from-spec checker accepts it (completeness-only); no corpus vector
exercised it, so 134/134 parity was intact. This is the one **editorial call**
among the three corners, and the converged debate chose keep-reject: a class
both assessed and disclosed as a gap is contradictory. **Reversible at
vetting.**

- **Spec.** The coverage paragraph (L376-381) now states the three sets are a
  disjoint partition: a class appears in exactly one of `assessedClasses`,
  `outOfScope`, `routedElsewhere` (a move, not a copy); a class in more than one
  is malformed.
- **Rails.** Unchanged - both already reject overlap via the exhaustive,
  disjoint partition check (Go `gate0CoverageIntegrity`, Python
  `_coverage_partition_ok`), emitting `coverage-incomplete`. The spec text now
  matches the rails rather than the rails being opinionated ahead of the text.
- **Vector.** `bad-730-coverage-class-overlap` (class XA in both
  `assessedClasses` and `outOfScope` -> `coverage-incomplete`). Registry
  decision 14.

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
Retained here for the audit trail. Rail propagation to the first-party
verifier rails is a follow-up (tracked with corners A and C below).

---

## Note: the registry is a POST-RUN reconciliation surface, not an answer key

The interpretation-decision registry (`vectors/interpretation-decisions.json`)
records, per forced reading, the spec anchor and the corpus vector(s) that lock
it. It is valuable **after** an independent implementation has committed its own
readings: it then shows exactly where those readings diverged, without either
author having to arbitrate. Read **before** implementing, it is an answer key,
and a from-spec independence claim made against it is worth less than one made
without it. So: a genuinely independent conformance result is one produced
without reading this registry (or the rail source, or the manifest's expected
condition codes) first; the registry is for reconciling and explaining
divergences afterward, not for pre-loading the "right" answers. Raised by the
independent from-spec checker (in-toto/attestation#570 round-8, Rul1an).

## suiteRevision 3: reason-map membership vectors

The coverage-partition membership rule (spec L381-383: the three sets are a
disjoint partition of the manifest's classes) is now forced on all three sets,
not just `assessedClasses`: `bad-819` (assessed), `bad-731` (`outOfScope`),
`bad-732` (`routedElsewhere`). Both rails already enforced reason-map membership;
these vectors were the untested consequence of the written rule. Not an open
corner (the spec forces it); recorded here for the audit trail.
