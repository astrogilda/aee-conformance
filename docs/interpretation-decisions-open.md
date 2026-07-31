# Open interpretation decisions (operator sign-off required)

The AEE v0.7 spec (`spec/predicates/adversarial-execution-evidence.md`) leaves a
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

- **Spec.** A sentence was added to the `attackResults` paragraph (L880-892):
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

- **Spec.** The coverage paragraph (L867-872) now states the three sets are a
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

- **Spec.** L210-213 was split: the cardinality half is stated unconditional
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

The coverage-partition membership rule (spec L872-874: the three sets are a
disjoint partition of the manifest's classes) is now forced on all three sets,
not just `assessedClasses`: `bad-819` (assessed), `bad-731` (`outOfScope`),
`bad-732` (`routedElsewhere`). Both rails already enforced reason-map membership;
these vectors were the untested consequence of the written rule. Not an open
corner (the spec forces it); recorded here for the audit trail.

## suiteRevision 9: which condition wins when a statement carries two

The spec does not decide the order in which a verifier evaluates its checks, and
says so: under Parsing Rules it makes only the consumption preconditions and the
evidence tier normative in its two-stage description, and states that "the
sequencing itself is informative" (L413-415). Nothing else in the document ranks
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
(L1245-1247), and a payload's fields "mean nothing until its signature verifies"
(L1585-1587). A record carrying no signature at all is therefore settled before the
bytes it carries are read. That argument is a reading, not a derivation: the same
passage explicitly permits the byte-pure gates to read payload fields without
verifying anything, so it does not by itself force the evaluation order.

**This is a spec ask, not a registry decision.** It is deliberately NOT recorded
in `vectors/interpretation-decisions.json`, because that registry records where
the text FORCES a reading and this text does not. The ask upstream is one
sentence: state that an observation record's envelope shape, including the
`signatures` entry count, is evaluated before the record's payload, so a
from-spec implementer is not left to choose.

**RESOLVED at suiteRevision 17, and not by the ask landing.** The paragraph that
stood here said that until the sentence lands, "a from-spec verifier that
evaluates the count per record is conformant to the specification and fails this
corpus, and that is the corpus overreaching rather than the verifier erring."
That was true, it was written down, and the corpus went on overreaching for eight
revisions, because the two buckets it had could not express anything else: pin
one answer and a conformant rail fails, name both and the code-set comparison
stops measuring the question. The third bucket is what the sentence needed. The
statement is now the family `signature-count-vs-payload-decode` in
`vectors/indeterminate/`, whose members declare the `set-level`, `positional` and
`decode-first` readings, admit any of them, and refuse only a rail whose answers
across the family no single reading explains. `bad-748` is retired into
`ind-001`; nothing about the reading changed, only what the corpus requires of
somebody who reads it differently. The upstream ask stands and is now purely an
improvement: were it to land, this family would become a reject vector, which is
the direction a family should be able to move.

The same paragraph applies to the second half of `bad-749`. Whether a
`signatures` member of the wrong JSON type reports the entry-count condition or
the parse catch-all is a failure-code question, and the spec has no failure-code
vocabulary; both readings return invalid, which is all the spec requires. The
suite reports the entry-count condition because it already does so for an absent
member, and splitting one requirement across two conditions on the basis of a
decoder's behavior is not a distinction the text makes.

`bad-749` stayed a reject vector when its sibling moved, and the reason is worth
recording because it is the criterion for the bucket rather than a judgement about
this vector. A family has to be able to SEPARATE the readings it declares: the
generator refuses one whose declared readings predict the same condition on every
member. Here the second reading is the parse catch-all, a code that identifies
neither the record nor the member, and the only member that could discriminate it
is the vector itself, so the family would have one member, two readings and no
way for a rail's answers to be incoherent. That is a reject vector with a widened
set wearing a different hat, which is the thing the bucket exists to avoid. If a
discriminating member is ever constructed, the vector moves; until then the suite
keeps the reading it argues for above, and this paragraph is where a reader learns
that it is a reading.

## suiteRevision 17: what else was considered for the bucket, and refused

The vendored text was enumerated for open corners before the bucket was built,
because a bucket whose occupants were chosen after it existed would be a shape
looking for content. Only the family above qualified. The other candidates
divide three ways, and each way is a reason NOT to write a vector:

- **Limits, not choices.** "The set of attacks actually executed therefore
  remains a producer assertion under both shapes" (L513-528), and the
  shared-reference evidencing obligation on a row declaring `paired`, of which
  the text says outright that "a conforming verifier neither can nor may invent
  an evidencing heuristic in its place" (L888-900). Nothing in the carried bytes
  can see the omission, so every conformant verifier must ACCEPT these
  statements and there is no divergence to declare. They belong in `accept/`,
  and what is implementation-defined about them is nothing at all: what is
  undefined is what the evidence PROVES, which is a property of the predicate
  and not of a rail. The vendored text narrowed the second of these: the same
  obligation on a row declaring `pinned` is checked against
  `corpus.manifest.expectedPayloads`, so it left this class and is carried by
  reject vectors rather than by prose.
- **Consumer policy outside the verdict this suite reads.** A consumer MAY admit
  `pass_indirect` (L495-496), MAY reject an attestation carrying `unattested`
  substrate rows outright (L1111-1114), MAY bound a named key with a validity
  window (L1190), MAY coherence-check a row against the pinned posture
  (L1206-1210). None of these can move the verdict, because validity "is a function
  of carried bytes alone and holds identically for every consumer" (L1689-1692);
  a rail that answered the admission question in the verdict field would be wrong
  rather than free. These are real freedoms and they are invisible to a
  single-statement corpus by construction.
- **Producer options with forced verifier handling.** `observationSelectors`,
  `aeeDropBound`, the descriptor members no rule reads, the optional run-chaining
  members. The producer chooses; what the verifier does about the choice is
  determined, and accept vectors already carry it.

One family with two members is therefore the honest size of this bucket at
suiteRevision 17, and the enumeration is recorded so that the next reader adds to
it by argument rather than by rediscovering that the list is short.

## CLOSED at suiteRevision 14: the fourth result value the vendored copy now defines

The corpus at suiteRevision 13 recomputed `result` over four values while the
vendored copy defined three. The upstream edit has landed, the copy is
re-vendored at the commit carrying it, and the text and the corpus now say the
same thing, so this entry is closed. The reading is a registry decision
(decision 20) rather than an open ask, and what follows is retained as the
record of why the corpus moved first.

**What the text now carries.** `result` is one of `fail`, `degraded`,
`pass_indirect`, `pass`, ordered `fail` < `degraded` < `pass_indirect` <
`pass`, and is the minimum under that order of three independent conditions
rather than a cascade (L435-454). The two that existed are unchanged. The third
holds when some clean row, meaning a row whose `containmentObserved` is in the
carried labels and not in the carried caught set, declares a `basis` other than
`substrate` or a `method` other than `intercepted`, and it contributes
`pass_indirect`.

**Why the corpus took this reading before the text did.** The copy vendored at
suiteRevision 13 let a statement carrying no substrate evidence whatsoever
reach the top of its own ordering. A party holding the enclosing envelope key
and not the substrate's observation key relabels every row clean, moves every
row to `basis: artifact`, and drops the observation records, the batch root and
the run entropy that only a substrate row required; the result was `pass`. That
copy's own clean-row ordering said such a statement is self-reported absence
and the weakest, so the text ranked it lowest on the axis a consumer is told to
read and highest on the axis a consumer actually gates on. Reconciling those
two is what the amendment did, and the ordering paragraph now states that both
of those statements recompute to `pass_indirect` (L1098-1108).

**What the reading deliberately does not claim.** Driven over all eleven
finding-bearing accept vectors, the downgraded statement is byte-identical to
one an honest producer with no substrate vantage emits forward from the same run
configuration. So the condition does not separate the two and is not written as
though it does: it prices both below a live interception. An honest artifact-only
producer, `ok-007`, stays valid and reaches `pass_indirect`.

**Why it is phrased over the row members and not over the tier.** The tier is
key-relative, and the vendored copy already requires that neither the validity
gate nor the tier alters `result` (L398-402). A condition reading the tier would
make `result` vary with a consumer's trust anchors and stop being recomputable.
The cost is stated rather than hidden: an `unattested` substrate clean row still
reaches `pass` under this reading, and that is the one rank of the clean-row
ordering no byte-pure function can express.

While the ask was outstanding, a from-spec verifier that returned `pass` for an
artifact-basis or reconstructed clean row was conformant to the vendored
specification and failed `ok-006`, `ok-007`, `ok-029`, `ok-038`, `ok-044`,
`ok-045`, `bad-009`, `bad-010` and `bad-818`. Against the copy vendored now it
is not, because the amendment carries every part of the ask: `result` is
defined over the four values and the ordering, the recompute is stated as the
minimum of the three named conditions rather than as a cascade, the third
condition is said to read the declared `basis` and `method` and never the
evidence tier, and the default admission threshold stays `result == "pass"`
with a consumer relaxing below it required to key additionally on each clean
row's `basis`, `method` and derived tier (L486-500).
## CLOSED at suiteRevision 14: the posture registry, and a vendored copy that predated the binding it certified

Two readings suiteRevision 12 took were not in the bytes it certified against,
and both needed an upstream edit before the vendored copy could be re-pinned.
Both edits have landed and the copy is re-vendored at the commit carrying them,
so this entry is closed. The closed posture registry is now a registry decision
(decision 19) and the version-2 binding was already one (decision 18). What
follows is retained as the record of why the corpus moved first.

**The posture registry was treated as closed before the text said so.** The
copy vendored at suiteRevision 12 introduced the values illustratively, as the
substrate-authoritative egress posture followed by three examples, and named no
consequence for a value outside that list. Every other artifact in reach
treated the set as closed and fail-closed: the predicate's own JSON Schema,
which also carried a fourth value the prose omitted (`unsafe_bypass_egress`),
both binding-contract surfaces, and the shipped admission policy. The argument
for closing it was in that text already, one section away: a consumer is
invited to coherence-check a `substrate` row's claimed observation against the
posture the run was contained under, because a row "claiming a network-boundary
observation under a `networkPosture` that provides no interception path at that
boundary is incoherent" (L1206-1210). No verifier can decide whether an
unregistered posture provides an interception path at a boundary, so an open
registry left that check permanently unreachable while appearing to offer it.
The text now registers four values, states that a statement whose `posture` is
absent, is not a string, or carries a value outside the set is malformed and
fail-closed, and adds the append-only rule across minor versions (L807-815),
with the argument for closing the set written down rather than asserted
(L817-826). Three reject vectors (`bad-823`, `bad-824`, `bad-825`) and three
accept vectors (`ok-040` through `ok-042`) lock it, and a from-spec verifier
admitting an unregistered posture is no longer conformant.

**The vendored copy described version 1 of the run binding while the corpus was
minted under version 2.** The version-2 pre-image gains the carried
`observationVocabulary` digest, and its `networkPosture` input is the RFC 8785
canonical digest of the carried posture OBJECT rather than the value of that
object's own digest member. The copy vendored at suiteRevision 12 still gave
the seven-member version-1 pre-image, so the corpus cited that passage for the
rule it meant, which is that the pre-image is derived from the statement's own
values, while the passage enumerated a member list the corpus no longer used.
Re-vendoring is what closed it, and it could not happen sooner: editing the
vendored copy in place would have made `spec/VENDOR-PIN.json` name a commit
that does not contain those bytes, which is the one thing
`scripts/spec-drift-gate.py` exists to refuse. The copy now carries the
version-2 pre-image with both changed inputs and the reason each is admissible,
which is that both are run configuration fixed before corpus injection and so
knowable when the arming record that commits to the binding is signed
(L174-182), and it states the consequence a producer inherits: a member added
to the posture after arming derives a binding the producer's own records do not
carry, so its statement is invalid on that ground (L270-273).
