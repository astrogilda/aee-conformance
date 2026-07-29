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

- **Spec.** A sentence was added to the `attackResults` paragraph (L529-542):
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

- **Spec.** The coverage paragraph (L516-521) now states the three sets are a
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

- **Spec.** L185-189 was split: the cardinality half is stated unconditional
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
so accepting `+05:00` is out of spec. **Fixed:** the spec text pinned the zero
UTC offset explicitly, both rails rejected it, and
`bad-727-armedat-non-utc-offset` locked it (a valid `+05:00` instant before
`issuedAt`, rejected as `arming-covers-nothing`, distinct from a late
`armedAt`).

That fix was half a fix, and the other half was invisible for two revisions
because it was written on one field and applied at one call site. `issuedAt`
carried no zone rule at all, so the same offset was conformant a few fields
away and every rail accepted it there; and the sentence that pinned the zone
never pinned the case, so a lowercase designator was refused by the Go rail and
accepted by the Python rail, on the same bytes, inside this repository. Both
are closed at suiteRevision 10 by adopting the framework's `Timestamp` type on
`issuedAt` and stating the profile once on the field the arming record cites.
Every rail now runs both timestamps through one parse that carries the whole
profile, so a later reader cannot apply half of it; the zone half is locked by
`bad-727` and `bad-820`, the case half by `bad-750` and `bad-821`, and `-00:00`
is locked as admitted by `ok-038` and `ok-039`. Decision 8 in the registry
lists all of them. Retained here for the audit trail.

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

The coverage-partition membership rule (spec L521-523: the three sets are a
disjoint partition of the manifest's classes) is now forced on all three sets,
not just `assessedClasses`: `bad-819` (assessed), `bad-731` (`outOfScope`),
`bad-732` (`routedElsewhere`). Both rails already enforced reason-map membership;
these vectors were the untested consequence of the written rule. Not an open
corner (the spec forces it); recorded here for the audit trail.

## suiteRevision 9: which condition wins when a statement carries two

The spec does not decide the order in which a verifier evaluates its checks, and
says so: under Parsing Rules it makes only the consumption preconditions and the
evidence tier normative in its two-stage description, and states that "the
sequencing itself is informative" (L317-319). Nothing else in the document ranks
one condition against another, and it carries no failure-code registry at all,
so two rails can both reject the same bytes for reasons the spec is equally happy
with.

That is fine until a statement carries two faults, and then it stops being fine,
because the suite's conformance contract is which condition a verifier reports.
A statement whose first observation record has an undecodable payload and whose
second carries no `signatures` entry was reported as `record-undecodable` by a
rail that counted signature entries per record inside its payload-decode loop,
and as `record-signatures-empty` by the rails that counted them once over the
record set before that loop. Both rejected; they named different conditions.

**The suite pins the set-level reading**, and `bad-748` locks it. The argument is
the verify-then-read discipline the spec does make normative: a consumer verifies
each record's signature "before relying on any field inside the payload"
(L847-849), and a payload's fields "mean nothing until its signature verifies"
(L995-997). A record carrying no signature at all is therefore settled before the
bytes it carries are read. That argument is a reading, not a derivation: the same
passage explicitly permits the byte-pure gates to read payload fields without
verifying anything, so it does not by itself force the evaluation order.

**This is a spec ask, not a registry decision.** It is deliberately NOT recorded
in `vectors/interpretation-decisions.json`, because that registry records where
the text FORCES a reading and this text does not. The ask upstream is one
sentence: state that an observation record's envelope shape, including the
`signatures` entry count, is evaluated before the record's payload, so a
from-spec implementer is not left to choose. Until it lands, a from-spec verifier
that evaluates the count per record is conformant to the specification and fails
this corpus, and that is the corpus overreaching rather than the verifier erring.

The same paragraph applies to the second half of `bad-749`. Whether a
`signatures` member of the wrong JSON type reports the entry-count condition or
the parse catch-all is a failure-code question, and the spec has no failure-code
vocabulary; both readings return invalid, which is all the spec requires. The
suite reports the entry-count condition because it already does so for an absent
member, and splitting one requirement across two conditions on the basis of a
decoder's behavior is not a distinction the text makes.

## suiteRevision 12: the posture registry, and a vendored copy that predates the binding it certifies

Two readings this revision takes are not in the vendored bytes it certifies
against, and both need an upstream edit before the vendored copy can be
re-pinned. Recording them here rather than in
`vectors/interpretation-decisions.json` is the same call the entry above makes:
that registry records where the text FORCES a reading, and this text does not.

**The posture registry is treated as closed.** The vendored copy introduces the
values illustratively, as "the substrate-authoritative egress posture, e.g.
`no_network`, `allowlist`, `sinkhole`, with its configuration digest"
(L459-461), and names no consequence for a value outside that list. Every other
artifact in reach treats the set as closed and fail-closed: the predicate's own
JSON Schema, which also carries a fourth value the prose omits
(`unsafe_bypass_egress`), both binding-contract surfaces, and the shipped
admission policy. The argument for closing it is in the vendored text already,
one section away: a consumer is invited to coherence-check a `substrate` row's
claimed observation against the posture the run was contained under, because a
row "claiming a network-boundary observation under a `networkPosture` that
provides no interception path at that boundary is incoherent" (L808-812). No
verifier can decide whether an unregistered posture provides an interception
path at a boundary, so an open registry leaves that check permanently
unreachable while appearing to offer it. Three reject vectors (`bad-823`,
`bad-824`, `bad-825`) and three accept vectors (`ok-040` through `ok-042`) pin
the closed reading. Until the upstream edit lands, a from-spec verifier that
admits an unregistered posture is conformant to the vendored specification and
fails those three rejects, and that is the corpus running ahead of the text
rather than the verifier erring.

**The vendored copy still describes version 1 of the run binding.** The corpus
in this revision is minted under version 2, whose pre-image gains the carried
`observationVocabulary` digest and whose `networkPosture` input is the RFC 8785
canonical digest of the carried posture OBJECT rather than the value of that
object's own digest member. The vendored copy still gives the seven-member
version-1 pre-image (L157-163). The corpus therefore cites that passage for the
rule it means, which is that the pre-image is derived from the statement's own
values, while the passage enumerates a member list the corpus no longer uses.
Re-vendoring is what closes this, and re-vendoring requires the amendment to
exist upstream first: editing the vendored copy in place would make
`spec/VENDOR-PIN.json` name a commit that does not contain those bytes, which is
the one thing `scripts/spec-drift-gate.py` exists to refuse. The pin and the
recorded `specDigest` are therefore left exactly where they were, and this
paragraph is the record that the corpus moved ahead of them.

The upstream ask is two edits. State that `networkPosture.posture` is a closed
registry of four values, that a minor version MAY append and MUST NOT redefine,
and that an absent, non-string or unregistered value makes the statement
malformed. And carry the version-2 pre-image, with the two changed inputs and
the reason each is admissible: both are run configuration fixed before corpus
injection, which is what makes them knowable when the arming record that commits
to the binding is signed.
