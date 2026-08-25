# AEE v0.7 conformance vectors: VALID (accept) set

Each file in this directory is a complete, unwrapped in-toto Statement (no outer DSSE) for
predicate type `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`
that a conforming verifier MUST accept: the statement is well-formed, every
`basis: substrate` row satisfies the byte-checkable validity gate (refs resolve
and are in range, referenced records class-match, every covering payload is
canonical RFC 8785 / RFC 7493 `+json` carrying the reserved members with
`aeeRunBinding` equal to the binding derived from the statement, row `method`
capped by the weakest signed `aeeMethod`, `batchRoot` recomputes under RFC 6962),
and the carried `result` equals the recompute. Condition ids below are stable
`aee-c-NN` ids; the suite README maps them to spec line ranges at the pinned
spec commit. Verdict for every vector here: **valid**; the per-row evidence tier
(attested / unattested / declared) is trust-relative and never alters validity
or `result`.

That type URI does not resolve. The in-toto attestation catalog redirects the
URIs of vetted predicates whose specification is merged, and this predicate is
in review as `in-toto/attestation#570`, so a request for the URI returns 404.
The URI identifies the predicate type, and dereferencing it is not part of
verifying any vector here. Read the specification in the copy this repository
carries, at
[`spec/predicates/adversarial-execution-evidence.md`](../../spec/predicates/adversarial-execution-evidence.md).

## Determinism recipe

Regenerate the set byte-identically with `python3 gen_valid_vectors.py`
(stdlib + `cryptography`). Committed files are UTF-8, LF, 2-space indent, JCS
(lexicographic) member ordering, standard base64 with padding.

Signing uses TEST keys (Ed25519/RFC 8032) whose seeds derive from published
constants: `seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`. Only the
PUBLIC halves are published, and because the derivation is open, these keys
are TEST-ONLY by construction; anyone can re-derive them. The
`substrate-observation-test` keyid is
`7e2b0652d86716f47e35573ae0082d670706b7a548dcb685df7bf103923dcb9c`, and the
`wrong-signer-test` keyid is
`a0667d352125206443e3005accb7223ef487f505d5fc3d392b629b6619177e0c`.

Timestamps are fixed at `issuedAt` 2026-01-01T00:00:00Z and `armedAt`
2025-12-31T23:59:00Z, the subject is `example-agent-bundle`, and attack ids
follow `XA-EXAMPLE-*` / `XB-EXAMPLE-*`. All digests derive from committed
synthetic one-line preimages (in `gen_valid_vectors.py`'s `PREIMAGES`): subject
`example-agent-bundle-content/v1`, substrate
`example-substrate-image-content/v1`, catch policy
`{"exampleCatchPolicy":{"mode":"enforce"}}`, network posture
`{"exampleNetworkPosture":{"posture":"sinkhole"}}`, run entropy
`example-run-start-checkpoint/v1`, and unchecked binding
`example-unchecked-binding/v1`. Corpus and vocabulary digests are JCS digests
of the embedded manifest and vocabulary objects.

## Construction checkpoint resolution (ok-017 / ok-030)

Pinned reading: "covering" records are the referenced records of the class(es)
the row's class-match rule requires; extra referenced records are
payload-checked but neither cap `method` nor gate the tier. Because
`examination` is method-pinned (`reconstructed`) and `interception` is the only
method-unconstrained kind, the min-composition accept half (ok-030) uses the
cross-kind mechanism: a reconstructed caught row referencing an examination
record (class cover) plus interception records signed `intercepted` and
`reconstructed`. The row's method equals the weakest signed `aeeMethod`
(`reconstructed`), so the vector is accepted under both the required-class and
the all-referenced covering readings, keeping it stable across the pending
tier-2 spec question.

## Vector index (one line per vector: which gate it exercises)

| vector | result | conditions (aee-c ids) | exercises |
|---|---|---|---|
| ok-001-caught-intercepted-fail | fail | aee-c-1, aee-c-3, aee-c-12, aee-c-28, aee-c-50 | canonical caught substrate/intercepted row covered by one interception record; single-leaf tree (root == leaf hash); producer layer name |
| ok-002-clean-pass-armed-sealed | pass | aee-c-7, aee-c-14, aee-c-26, aee-c-48, aee-c-63, aee-c-64, aee-c-65 | flagship clean row covered by arming + sealed (`aeeDropCount` 0), `actualLayer` "none", two-record tree |
| ok-003-clean-pass-bounded-drops | pass | aee-c-65 | sealed record with non-zero `aeeDropCount` 3 within self-declared `aeeDropBound` 5 still covers |
| ok-004-degraded-out-of-scope | degraded | aee-c-1, aee-c-6 | non-empty `coverage.outOfScope` forces recompute to `degraded` |
| ok-005-degraded-routed-elsewhere | degraded | aee-c-6 | non-empty `coverage.routedElsewhere` forces `degraded` |
| ok-006-clean-reconstructed | pass_indirect | aee-c-2, aee-c-13, aee-c-66 | clean (substrate, reconstructed) row class-matched by an examination record; indirect in time rather than in vantage, so the recompute floors it below `pass` |
| ok-007-artifact-only-recordless | pass_indirect | aee-c-2, aee-c-31, aee-c-57 | artifact-only statement: no records, no `batchRoot`, no `runEntropy`; over-strictness discriminator. The honest producer whose attack classes have no substrate vantage at all: it stays VALID and reaches the best result its evidence supports, which is the whole reason the rule prices rather than refuses |
| ok-008-artifact-fail-closed-method | fail | aee-c-5, aee-c-44 | artifact row with unknown `method` value fail-closes the row; carried `fail` recomputes; statement VALID |
| ok-009-artifact-oov-label-fail | fail | aee-c-4 | artifact row label outside carried `observationVocabulary.labels` fail-closes; VALID |
| ok-010-artifact-retired-basis-fail | fail | aee-c-43 | retired 0.4 `basis` value `substrate_observed` is out-of-vocabulary, no alias; fail-closed, VALID |
| ok-011-shared-run-records | pass | aee-c-15 | two clean rows legally share one arming + sealed record pair |
| ok-012-selectors-present | pass | aee-c-16 | `observationSelectors` positionally parallel to refs; advisory, result unchanged |
| ok-013-unknown-kind-extra-record | pass | aee-c-32, aee-c-71 | unrecognized `aeeKind` "aee-future-x" covers nothing, is ignored, still contributes its `batchRoot` leaf |
| ok-014-three-record-odd-split | fail | aee-c-26 | 3-leaf RFC 6962 recursive split (2+1), never duplicate-pad; parent of root-family rejects |
| ok-015-four-record-tree | fail | aee-c-26 | 4-leaf balanced RFC 6962 tree; two interceptions + arming + sealed |
| ok-016-caught-actuallayer-none | fail | aee-c-49 | caught row with `actualLayer` "none": observed-but-not-enforced (monitor-only vantage) |
| ok-017-method-weakening-allowed | fail | aee-c-23 | method cap is one-directional: reconstructed row referencing an intercepted-signed record is accepted |
| ok-018-aee-prefix-ignored | pass | aee-c-38, aee-c-61 | carried `evidenceTier` member and reserved-prefix `aeeInjected` member MUST be ignored |
| ok-019-wrong-keyid-sig-verifies | pass | aee-c-35 | keyid is a hint, never the check: garbage keyid on arming, ABSENT keyid on sealed, both sigs verify under the pinned key; tierWithPinnedKey ["attested"], tierWithoutKey ["unattested"] |
| ok-020-non-pae-signature | fail | aee-c-36 | record signed over raw payload bytes (no PAE): tier fault (row unattested), never a validity fault; tierWithPinnedKey ["unattested"], tierWithoutKey ["unattested"] |
| ok-021-producer-extra-members | fail | aee-c-73 | covering payload with extra non-`aee` producer members still covers |
| ok-022-two-arming-records | pass | aee-c-68 | two independent arming records + one sealed; each referenced record independently satisfies class constraints |
| ok-023-no-tofu-embedded-key | pass | aee-c-34 | payload embeds a tempting public key; consumer MUST NOT TOFU; expected tier without out-of-band pin is unattested; tierWithPinnedKey ["attested"], tierWithoutKey ["unattested"] |
| ok-024-mixed-basis-rows | fail | aee-c-33, aee-c-41 | pinned three rows: substrate covered by the substrate test key (attested), substrate covered by the wrong-signer test key (unattested), artifact (declared); tierWithPinnedKey ["attested","unattested","declared"], tierWithoutKey ["unattested","unattested","declared"] |
| ok-025-does-not-assert-present | pass | aee-c-84 | `doesNotAssert` present: advisory, never required, ignored for result |
| ok-026-five-record-tree | fail | aee-c-26 | 5-leaf unbalanced RFC 6962 split (4+1): deep-split discriminator |
| ok-027-artifact-missing-method | fail | aee-c-5, aee-c-42, aee-c-44 | artifact row with `method` member ABSENT: absence == unknown, fail-closed; carried `fail`; VALID |
| ok-028-empty-caught-pass | pass | aee-c-3, aee-c-52 | `caught: []` edge: vacuously no caught rows; vocabulary digest over the empty-caught object |
| ok-029-artifact-with-records | pass_indirect | aee-c-2, aee-c-24, aee-c-29, aee-c-30, aee-c-32 | artifact-only rows + 2 unreferenced records + CORRECT `batchRoot`; no substrate rows so no derived binding, and record `aeeRunBinding` values are unchecked bytes. The records are the point of the tier pin: verifiable material sits beside the row and the row is declared anyway, under both policies, because basis and not availability decides. tierWithPinnedKey ["declared"], tierWithoutKey ["declared"] |
| ok-030-method-min-multirecord | fail | aee-c-23, aee-c-45 | min-composition accept half: row method `reconstructed` equals the weakest signed `aeeMethod` across three referenced records {reconstructed, intercepted, reconstructed}; pairs with the cap-exceeded reject |
| ok-031-caught-reconstructed | fail | aee-c-13 | caught (substrate, reconstructed) row class-matched by an examination record: class-match keys on method, not caught-ness |
| ok-032-method-inferred-retired | fail | aee-c-5, aee-c-43 | retired 0.4 `method` value `inferred` is out-of-vocabulary, fail-closed; VALID |
| ok-033-artifact-degraded | degraded | aee-c-6 | artifact-only recordless degraded statement: parent for coverage-family rejects with no digest/binding cascade |
| ok-034-arming-chain-genesis | pass | aee-c-89 | arming payload carrying the optional run-chaining members in genesis form (`aeeRunSeq` 1, `aeeChainScope` present, no `aeePrevRunBinding`): syntax-checked in the reserved-member walk, nothing else normative reads them, and the record still covers |
| ok-035-unknown-kind-excluded-from-cap | pass | aee-c-23, aee-c-45, aee-c-71 | clean intercepted row referencing an unknown-`aeeKind` record signed `aeeMethod` "reconstructed": the record covers nothing and is otherwise ignored, so it neither invalidates the row (arming + sealed satisfy class-match) nor participates in the method cap, which reads only covering records |
| ok-036-payload-nesting-at-bound | pass | aee-c-18 | covering payload carrying a producer member nested exactly TO the bound (deepest open container at depth 128, scalar leaf): valid, and the discriminating twin of bad-741/bad-742 -- the one depth the corpus otherwise never touches, where a per-open-container counter and a per-parsed-value counter can disagree |
| ok-038-issuedat-negative-zero-offset | pass_indirect | aee-c-2, aee-c-85 | `issuedAt` spelled `2026-01-01T00:00:00-00:00`: the member of the timestamp profile no prose named before the profile was written, admitted because RFC 3339 section 4.3 makes `-00:00` a statement about the producer's locale and not about the instant. Same instant as ok-007, so a rail reading "zero offset" as "Z or +00:00 only" is caught here rather than at a third party |
| ok-039-armedat-negative-zero-offset | pass | aee-c-63, aee-c-85 | the same spelling on `armedAt`, inside the substrate-signed arming payload, re-signed with the batch root recomputed: the arming record must still cover the clean row and the statement must still recompute to `pass` |
| ok-040-posture-no-network | pass | aee-c-93 | `networkPosture.posture` "no_network": one of the three registered postures the rest of the corpus never carries, so the registry stopped being a set the corpus only claims to test |
| ok-041-posture-allowlist | pass | aee-c-93 | `networkPosture.posture` "allowlist": the registered value bad-305 swaps to, which is why the swap is invisible to any vocabulary rule and has to be caught by the run binding |
| ok-042-posture-unsafe-bypass-egress | pass | aee-c-93 | `networkPosture.posture` "unsafe_bypass_egress": the registered value the upstream prose omits from its list, admitted here because the schema beside that prose has always carried it |
| ok-043-posture-producer-member-bound | pass | aee-c-60 | `networkPosture` carrying a producer member the records commit to: valid, and the accepted half of the pair whose rejected half (bad-307) carries the same member with records that do not. The pair says the rule is about when the member was added, not about whether the posture may carry one |
| ok-044-clean-artifact-intercepted-indirect | pass_indirect | aee-c-2, aee-c-31 | the shape the artifact downgrade produces, and the one basis/method pairing the closed vocabularies permit that nothing else here exercised: a clean row indirect in vantage while claiming a live method. Recordless, so it needs no substrate participation to write, and `pass_indirect` is what stops it reading at the top of the ordering |
| ok-045-mixed-clean-rows-indirect | pass_indirect | aee-c-2, aee-c-14 | two clean rows, the first a live interception covered by its arming and sealed records and the second resting on the artifact's own account. Pins the quantifier: the rule fires on SOME clean row, so a direct row cannot carry an indirect one back up to `pass`. Second mixed-basis tier column beside ok-024, so neither the substrate half nor the artifact half of the partition rests on one vector: tierWithPinnedKey ["attested","declared"], tierWithoutKey ["unattested","declared"] |
| ok-046-seal-attacks-lower-bound | fail | aee-c-98 | two caught rows and a seal that names only one of their attacks. Pins the DIRECTION of the rule: a seal naming an attack obliges a caught row for it, and a seal omitting one licenses nothing, because an observation the substrate could not attribute subtracts from what the seal claims and can never add a false one. Without this vector a rail reading the sets as equal passes the whole corpus |
| ok-047-attribution-pinned | fail | aee-c-100, aee-c-101, aee-c-102, aee-c-103 | the satisfied form of the stronger attribution in all three of its parts at once: the row resolves an interception, the manifest declares an `expectedPayloads` entry for the row's attack, and the record it resolves carries a value from that entry. Needed beside the three refusals, because a rail that rejects every `pinned` row satisfies each refusal and is wrong |
| ok-048-attribution-paired-despite-expectation | fail | aee-c-105 | the corpus declares an expectation for this attack and the record carries the matching value, so the producer COULD have declared `pinned` truthfully and did not. `paired` is a floor rather than a confession: what a consumer learns from it is that this row does not carry the stronger binding, never that the producer had one and withheld it. A rail that infers the stronger value from the corpus, or refuses a truthful weaker one, fails here and nowhere else |
| ok-049-seal-names-caught-attack | fail | aee-c-98 | a seal that names an attack the statement carries a caught row for. ok-046 pins that the rule does not fire on omission; this pins that it is a rule at all rather than a member nothing reads |
| ok-050-registered-noncovering-kinds | pass | aee-c-23, aee-c-45, aee-c-106, aee-c-107 | a clean intercepted row referencing a `moat-drop` and an `uncommitted-observation` record, both signed `aeeMethod` "reconstructed". The document registers both as covering nothing in every state, so neither invalidates the row (arming + sealed satisfy class-match), neither participates in the method cap, neither enters the seal's `aeeObservedSet`, and neither is owed a caught row; both leaves stay in the batch root. ok-035 says the same of a kind no version registers, and a rail that gives either of these names covering semantics passes that vector and fails this one |
| ok-051-two-pinned-rows | fail | aee-c-100, aee-c-101, aee-c-102, aee-c-103 | two rows declaring the stronger attribution at once, each resolving its own interception whose committed value the manifest declared for that row's attack. Every earlier pinned vector carries a single row, and permuting one row is the identity, so the corpus could not reach the arm that decides which record belongs to which attack: `bad-982` is this statement with the assignment exchanged and nothing else touched. The two attacks sit in different coverage classes, because a consumer policy keyed on attack class is the cheapest example of one that reads the assignment |
| ok-052-liveness-probe-per-channel | fail | aee-c-98, aee-c-100, aee-c-101, aee-c-102, aee-c-103, aee-c-104 | detector liveness demonstrated on every claimed channel at once, built from members this version already has: `classes` assigns each attack to a channel, `expectedPayloads` is the stimulus a corpus author planted and predicted, `aeePayloadCommitment` is what the substrate committed to on the wire, `pinned` is the row asserting the two are comparable, and the seal's `aeeObservedAttacks` names all three. A check that never fires is indistinguishable from outside from a boundary nothing reached, and this is the shape that separates them. Three channels rather than two, because a rail that evaluates the first row and the last passes a two-channel statement while skipping everything between; it is the accept anchor `bad-983`, `bad-984` and `bad-985` are measured against, since a rail refusing every multi-channel `pinned` statement satisfies all three refusals and is wrong |
| ok-053-liveness-probe-uncaught-on-one-channel | fail | aee-c-14, aee-c-98, aee-c-100, aee-c-102, aee-c-103 | the same three planted probes, and the middle channel's probe produced no interception: its row is clean, its attribution is the honest floor, and the seal names the two channels the substrate did attribute and not the third. This MUST be accepted. Liveness is not a validity requirement at this version, and a producer whose detector genuinely did not fire emits exactly these bytes, so a rail that hard-codes the demand refuses the honest report along with the dishonest one. What the format does instead is make the difference legible: three probes declared, two named on the seal, and the gap between those sets is the channel this run cannot show a live detector for -- which `scripts/liveness-probe.py` computes and a consumer decides on. `bad-985` is the dishonest report of the same run |
| ok-054-producer-ordered-axis-inert | fail | aee-c-23, aee-c-45, aee-c-73 | a covering interception payload carrying a producer-defined member whose value is a token this predicate itself orders (`exampleFidelity: "reconstructed"`) beside a signed `aeeMethod` of `intercepted`. Producer territory is inert to a verifier, and the ordered case is the one a verifier is tempted to read: a rail that folds the member into the weakest-input method composition caps the row at `reconstructed` and reports `method-cap-exceeded` on a statement no requirement refuses. ok-021 carries producer members too, but content-free ones, so it forces only that such a member does not stop the record covering; this is the vector the ranking rail fails |
| ok-900-fail-outranks-degraded | fail | aee-c-1 | the composition law that decides every mixed run, and the one shape nothing else here carries: a caught row forcing `fail` in the same statement as a disclosed coverage gap forcing `degraded`. The recompute takes the minimum, so the carried token is `fail`, and a rail that ranks a real failure below a disclosed gap reports the softer verdict on every mixed run. Measured rather than argued: the ordering was invisible to the whole corpus until this vector |
| ok-901-row-missing-basis | fail | aee-c-1 | a row carrying no `basis` member at all. Absence is not a value, so the row cannot be classified and fail-closes exactly as an out-of-vocabulary one does; the statement stays VALID and carries `fail`. Recordless and artifact-shaped, so no digest or binding cascades. This resolves, in the accept direction, the reading the reject set had deferred: the reject-side twin is still deferred, and the reject index says so and says why |
| vate-1b-carried-admission-digest-unread | pass | aee-c-73 | prompted by VATE case `post-execution-admission-digest-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. Admission receipt A is the sole subject and every record is correctly bound and signed for A, while the arming payload carries admission receipt B's digest and the reference naming B. Two admission receipts disagree -- the relation the pinned case tests, receipt against receipt rather than executed artifact against receipt -- and the statement is valid and recomputes `pass`, because AEE never performs that comparison: the carried digest and reference are producer territory and the subject is read only as a binding input. A negative pin on the comparison this predicate does not perform |
| vate-1d-admission-receipt-as-sole-subject | pass | aee-c-22, aee-c-60 | prompted by VATE case `post-execution-admission-digest-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. Admission receipt A is the SOLE subject, so the binding covers the admission identity and the case-1 anti-splice genuinely bites: `vate-1a` is this statement with receipt B's digest in the subject slot and the A-bound records untouched. It is also the whole price: exactly one subject entry is permitted and the pre-image reads the first, so the receipt DISPLACES the executed artifact. Valid, `pass`, and naming no executed artifact anywhere -- a consumer learns which admission the run happened under and cannot learn what was run |
| vate-2a-aggregate-overrun-unread | pass | aee-c-73 | prompted by VATE case `post-execution-effective-constraints-aggregate-exceeded` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. Two carried side-effect amounts are each below the carried maximum and sum above it; the recompute reads the rows, the carried vocabulary and the two coverage maps and nothing else, no row carries a quantity, and there is no arithmetic to perform. Valid, `pass`. The amounts travel on ONE arming record because two records with identical payloads are duplicates and would be refused before aggregation could be reached |
| vate-3b-admitted-vs-observed-runtime-unread | pass | aee-c-73 | prompted by VATE case `post-execution-runtime-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. An admitted runtime and an observed runtime are declared side by side and differ. A statement carries exactly one `observationEnvironment`, so there is no second runtime for any rule to compare against, and both members are producer territory. Valid, `pass` |
| vate-3c-substrate-substituted-and-resigned | pass | aee-c-22, aee-c-60 | prompted by VATE case `post-execution-runtime-mismatch` at VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. An AEE-native boundary vector prompted by that case, not a VATE conformance result. The bound on `vate-1a` and `vate-3a`, and the reason both are stated narrowly: the whole run is re-bound to the substituted substrate digest and re-signed, the binding recomputed over the second observation-substrate identity and every record re-signed under the published substrate-observation test key. Nothing is spliced, so nothing is detected, and the statement is valid and recomputes `pass`. The binding is anti-splice and explicitly not anti-forge, so those two vectors establish that records were not MOVED, never that the identity they name is the true one |

## The vate-* boundary vectors

Eight vectors carry a `vate-` prefix: `vate-1b`, `vate-1d`, `vate-2a`, `vate-3b` and `vate-3c` here, and `vate-1a`, `vate-1c` and `vate-3a` in the reject set. They exist because three conformance cases from the Verifiable Agent Trust Envelope (VATE) discussion draft asked what this predicate natively establishes across an external admission, and a boundary claim with nothing executable behind it is only an opinion.

The pins those cases were read at, preserved here because a reader has to be able to go back to them: VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. The three case identifiers are `post-execution-admission-digest-mismatch`, `post-execution-effective-constraints-aggregate-exceeded` and `post-execution-runtime-mismatch`.

What these vectors are, stated so it cannot be read as anything else: they are AEE-native boundary vectors prompted by those cases. They are not VATE conformance results, they carry no VATE verdict, they are not a projection into any other format, and no vector here is evidence about any implementation other than a rail run against this corpus. Every expectation is this predicate's own, decided by this suite's own rails, and the corpus digest above is recorded as a pin rather than reproduced as a validation of any canonicalization profile.

The five accepts are the load-bearing half. Each carries exactly the fault its case is about and is valid anyway, which is a more precise statement of what this predicate declines to read than any sentence. The three rejects are narrow on purpose: `vate-1a` and `vate-3a` refuse a splice and say nothing about whether the identity a statement names is the true one, which `vate-3c` demonstrates from the other side, and `vate-1c` extends no rule that `bad-607` and `bad-728` do not already carry -- what it adds is the price of the case-1 anti-splice, made executable.

Case 3 needs one distinction stated, and it is stated here once rather than repeated per vector. `vate-3b` demonstrates the case's own comparison directly: a producer-declared admitted runtime and a producer-declared observed runtime, side by side and differing, and neither read. `vate-3a` and `vate-3c` exercise a different field, `observationEnvironment.substrate.digest.sha256`, which is the observation-substrate identity -- the substrate anchor this predicate binds a run to. That is an ADJACENT AEE binding surface, not a semantic equivalent of the source case's `admission_receipt.subject.runtime` against `post_execution_receipt.execution.runtime` comparison. `vate-3a` shows the anchor cannot be moved under records already signed; `vate-3c` shows that a run re-bound to the substituted substrate digest and re-signed is accepted. Neither is evidence about the runtime comparison, and neither is offered as such.

The case-1 trio is built on one shape so that the relation it instantiates is the source case's. Two synthetic admission receipts, A and B, are derived from published one-line preimages. `vate-1d` is receipt A in the sole subject slot with the records bound and signed for A; `vate-1a` is that statement with the subject digest moved from A to B and the records left exactly as they were signed; `vate-1b` is that statement with the arming payload carrying receipt B's digest and reference beside subject A. Both objects in the relation are admission receipts, as they are in the pinned case, which hashes a referenced admission receipt and compares the value with the digest a post-execution receipt asserts. The conclusion the trio makes executable is one sentence: AEE binds its sole subject against record splicing, and does not perform VATE's referenced-admission-receipt digest comparison.

## Coverage notes

The result vocabulary spans `fail` (ok-001), `pass` (ok-002), `degraded`
(ok-004), and `pass_indirect` (ok-006/007/029/038/044/045);
`doesNotAssert` appears only in ok-025. The minimum the recompute takes is
witnessed by ok-033, whose clean row is indirect AND whose coverage
discloses a gap: it reads `degraded`, the lower of the two, which is what
distinguishes a minimum from a cascade written in the other order. On the basis axis, the set
covers substrate (ok-001 family), artifact
(ok-007/008/009/027/029/032/033), retired/out-of-vocabulary (ok-010), and
mixed (ok-024) rows. The method axis covers intercepted (ok-001/002),
reconstructed (ok-006/017/030/031), absent (ok-027), unknown (ok-008), and
retired (ok-032). Record kinds exercised include interception, arming,
sealed, examination, unknown-forward (ok-013), and the two registered
non-covering kinds (ok-050), across trees of 1, 2, 3,
4, and 5 leaves. On the signature plane, the set exercises pinned-key
verifying (the default), wrong-signer-valid (ok-024), garbage/absent keyid
(ok-019), non-PAE (ok-020), and embedded-key bait (ok-023).

Every vector re-parses as JSON, regenerates byte-identically, and passes the
generator's built-in gate and recompute self-verifier (`python3
gen_valid_vectors.py` exits non-zero on any self-check failure).

All content is synthetic: producer vocabulary is spec-verbatim
(`policy.egress_sinkhole`, `none`, `sinkhole`, `egress_captured`, `no_egress`)
or obviously synthetic (`example*`, `XA-EXAMPLE-*`); payload type
`application/vnd.example.aee-observation.v1+json`; producer members are
content-free (`producerNote`, `extraA`) or deliberately rankable and still inert (`exampleFidelity`, ok-054). Nothing here derives from, or
describes, any real execution or production signing key.
