# aee-conformance — roadmap

Open work for the conformance-vector suite and reference verifier of the in-toto
Adversarial Execution Evidence (AEE) predicate. Contributions welcome.

> **Session code-health audit 2026-07-24:** `go build ./...` + `go vet ./...` + `mypy` all
> **CLEAN** — no findings for this repo. Combined cross-repo report:
> an internal audit report.

## Status: v0.6 review (in-toto/attestation#570)

The reviewer's independent from-spec checker went 138/138 on the earlier corner-case
features and conceded every open corner; the latest reply invites him to move the v0.6
proposal out of draft.

- [ ] **Await reviewer's read on moving v0.6 out of draft** — no code change pending on
  our side; the next step is the reviewer's call.
- [ ] **v0.7 forward-design — no longer held.** The hold said "not while v0.6 is at the
  merge line", and it was lifted before the design was written. The design converged and
  the specification text for v0.7 is now written upstream on the predicate branch; what
  this repository owes it is the section below. Left open rather than ticked because
  nothing has landed here: a spec written elsewhere is not a corpus.

## The predicate moved to v0.7 and this corpus has not moved with it

The specification text for v0.7 is written and sits upstream on the predicate branch.
Nothing here has been re-vendored to it, and that is a decision rather than a backlog
item that slipped.

`scripts/spec-drift-gate.py` exists to refuse the state between a normative
specification change and the corpus regeneration that answers it, and this is exactly
that state. Vendoring the new bytes and re-pinning `specDigest` would turn the gate green
by asserting a regeneration that did not happen, over a corpus in which every statement
carries the retired predicate type. Vendoring without re-pinning leaves the gate red,
which is honest and is what the gate is for, but a red gate is not a landing. So the
vendoring belongs in the same revision as the regeneration, and the rows below are that
revision.

Measured while deciding this, so nobody re-derives it: re-vendoring remaps the citations
and anchors and then refuses to write either pin ledger, because nineteen anchors come to
address prose they were not drawn around — the new text splits paragraphs several of them
were aimed at. Each needs a by-hand correction or an explicit `--accept-reaim`, and that
is corpus work, not spec work.

- [ ] **Re-vendor and regenerate in one revision.** `scripts/vendor-spec.py --from
  <attestation checkout>`, then correct the nineteen refused anchors by reading each
  against the claim beside it, then the generators, then `vectors/gen_manifest.py`, then a
  `suiteRevision` section in `vectors/CHANGES.md`. The drift gate stays red until the last
  of those, which is the ordering the gate documents.
- [ ] **Re-type every statement and every rail to the new predicate type.** The type URI
  is a constant in `aee/types.go`, `witnessattestor/aee.go` and `packaging/run_vectors.py`,
  the schema file under `witnessattestor/schema/` carries it in its name and its `$id`, and
  both generators emit it. Every vector in the corpus carries the retired value, so this is
  the whole corpus and not a subset of it. It is also the reason the previous row cannot be
  split: a re-vendor without this leaves the rails rejecting the corpus, and this without a
  re-vendor leaves the corpus certifying against bytes nobody has.
- [ ] **Re-run the independent implementation.** A breaking version spends the strongest
  external evidence this text has that it is determinate, and the disclosure discipline for
  the revised vectors applies: publish the vectors without the text or the text without the
  vectors, never a note naming the failing vector and its fix.

### Conformance conditions v0.7 needs, and the vector that would force each

These have no `aee-c` ids yet, on purpose. A condition id is the link between a vector and
the rule it forces, and `scripts/condition-registry-gate.py` refuses a registry row that no
vector cites, in that direction as well as the other. Minting ids here would put rows in the
registry that resolve to nothing until the vectors exist, which is the failure the gate was
written for. The ids are minted in the same change as the vectors; what is recorded now is
the rule, the witness and the proposed failure code, in the shape
`vectors/coverage-unforced.json` uses for a requirement no vector pins yet.

- [ ] **A clean row resolves no reference to an interception record.** Witness: derive from
  a caught intercepted parent by relabelling the row clean and keeping the reference.
  Proposed code `clean-row-contradicted`. Costs no accept vector: measured over the accept
  corpus, no vector pairs a clean row with an interception record today.
- [ ] **Every carried interception record is resolved by at least one caught row.** Witness:
  derive from a caught parent by emptying the row's references while keeping the record.
  Proposed code `interception-record-orphaned`. This one is breaking on the accept side:
  `ok-029-artifact-with-records` is the sole accept vector resting on an interception record
  no row resolves, measured against the current corpus, and it becomes malformed. Its
  replacement is part of the same change.
- [ ] **A statement carrying a substrate row carries a valid sealed record.** Witness:
  derive from a caught substrate parent by deleting the sealed record. Proposed code
  `sealed-record-absent`. Nine accept vectors carry a substrate row and no sealed record and
  all nine are regenerated: `ok-001`, `ok-006`, `ok-016`, `ok-017`, `ok-020`, `ok-021`,
  `ok-024`, `ok-030`, `ok-031`. Two of them are the vectors the run-end commitment exists
  for, which is why the requirement is unconditional.
- [ ] **The seal's committed record set equals the carried one.** Witnesses, two: drop an
  interception and recompute the batch root over what remains, leaving the seal intact; and
  add a record the seal does not commit to. Proposed code `observed-set-mismatch`. A third
  witness is worth writing on the accept side: a run that emitted nothing commits to the
  digest of the empty array.
- [ ] **A seal naming an attack obliges a caught row for it.** Witnesses: a seal naming an
  attack whose row is clean, and a seal naming an attack with no row at all. Proposed code
  `observed-attack-uncaught`. The complementary accept vector is the one that pins the
  direction: a seal omitting an attack whose row is caught stays valid, because the set is a
  lower bound, and without that vector a rail reading the rule as an equality passes the
  suite.
- [ ] **The assessed set is a subset of the run-start declaration.** Witness: an assessed
  class whose attacks the arming record never declared. Proposed code
  `assessed-set-exceeds-declaration`. The accept vector that pins the subset reading against
  an equality reading is again the load-bearing one: a run that declared two classes,
  assessed one and disclosed the other stays valid.
- [ ] **A row declaring the stronger attribution carries the binding it claims.** Witnesses,
  three, because the rule has three parts and a vector per part is what stops a rail from
  implementing one and passing: a pinned row resolving no interception record at all, which
  is the vacuity the rule was written against; a pinned row whose attack the manifest offers
  no expectation for; and a pinned row resolving an interception whose commitment is not the
  one the manifest declared. Proposed codes `attribution-pinned-recordless`,
  `attribution-unpinnable`, `attribution-pin-unmatched`.
- [ ] **The manifest's expected-payload map is well formed.** Witnesses: a key naming an
  attack the classes do not declare, an unsorted or duplicate-carrying array, and a
  non-64-hex entry. Proposed code `manifest-expected-payloads-malformed`.
- [ ] **An interception record carries its commitment member.** Witness: drop the member from
  an interception payload and re-sign. The existing `payload-missing-reserved` code covers
  the absence; a malformed value wants its own, proposed `payload-commitment-malformed`.
- [ ] **The attribution member is required and fail-closed on every row.** Witnesses: a row
  with the member absent and a row carrying a value outside the vocabulary, on both a
  substrate and an artifact row, since the member is required regardless of basis. The
  existing `fail-closed-substrate-row` code covers the substrate side; the artifact side
  reaches the recompute and wants a `result-recompute-mismatch` vector.
- [ ] **Keep the declared fault the only fault on the reject side.** Every reject vector
  carries exactly one fault and the generator asserts the absence of a second, so a new
  unconditional requirement can silently give a reject vector a fault it was not written
  to test. Measured against the current corpus: thirty-eight reject vectors carry a
  substrate row and no sealed record, so each acquires a second fault the moment the
  sealed record becomes unconditional and each needs a valid sealed record added; ten
  acquire one under the anti-orphan rule, among them the batch-root family, whose whole
  subject is a root over records no row was ever meant to resolve; and none acquires one
  under the clean-row contradiction rule. Do this before writing a single new vector: a
  reject vector with two faults passes for the wrong reason and stops measuring the rule
  it names.
- [ ] **Score the new vectors on the forcing harness before the revision closes.** A vector
  that passes because nothing tries to break it is the defect the forcing ratchet exists to
  expose, and it should expose these rather than certify them. The cross-row splice half of
  this row is now closed and the answer was not the one the row assumed: the splice exists
  as a live measurement in `aee/observation_refs_splice_test.go`, with a control beside it,
  and it is UNKILLABLE rather than merely unforced. Exchanging `observationRefs` between two
  caught rows of one coverage class leaves the whole report byte-identical, because no
  record commits to the attack it evidences and the specification puts the assignment
  outside every gate; cell U7 of `vectors/coverage-unforced.json` carries the reasoning.
  So a permutation vector must NOT be written against the predicate as it stands -- there is
  no conforming rail for it to separate from another. What remains here is the rest of the
  row: the attribution, manifest and seal rules above still need scoring once their vectors
  exist, and the splice becomes forcible only when a revision binds a record to its attack,
  at which point the measurement turns red and says so.

## The indeterminate bucket (added at suiteRevision 17)

`vectors/indeterminate/` carries the statements on which the specification settles the
verdict and not the condition. It has one family, `signature-count-vs-payload-decode`,
and the enumeration behind that number is in `docs/interpretation-decisions-open.md`
under suiteRevision 17.

- [ ] **RE-VENDOR THE THREE CONSUMER COPIES — BLOCKING, cross-repo.** The published
  corpus digest moved from `1bfb73d60bab6b81...` to `e6aa9bc2889603b9...` and the
  vendored layout gained a `indeterminate/` directory, so
  `scripts/consumer-lag-gate.py --check` is RED until the TypeScript rail, the standalone
  Python rail and the MCP server rail carry it. Each vendoring script must copy the new
  subdirectory, and each rail's replay must handle `kind: "indeterminate"` — verdict plus
  closure per member, coherence per family — or skip those two vectors explicitly rather
  than silently. Then `scripts/consumer-lag-gate.py --sync --copy <id>=<dir> ...`.
- [ ] **Ask upstream for the envelope-shape-before-payload sentence.** If it lands, the
  family becomes a reject vector and the readings collapse to one. The ask is recorded in
  `docs/interpretation-decisions-open.md`; nothing here is blocked on it.
- [ ] **A discriminating member for the `bad-749` wrong-type question.** The parse
  catch-all versus the specific condition is the same class of open question, and it stays
  a reject vector only because no second member exists that could separate the two
  readings. A family of one member and two readings cannot be incoherent, so it would be a
  widened expectation wearing a different hat. Construct the member or leave the reading
  argued.
- [ ] **The consumer-policy freedoms are still invisible.** A consumer MAY admit
  `pass_indirect`, MAY reject `unattested` substrate rows outright, MAY bound a key with a
  validity window, MAY run the posture coherence check. None of these can move the verdict
  this suite reads, so no single-statement vector can see them, and two conformant
  admission policies can differ completely while scoring identically here. Closing it needs
  an admission-level surface in the external-rail contract, which is a bigger change than
  this bucket and should not be smuggled into it.

## Standards-ecosystem interoperability

- [ ] **SARIF v2.1.0 output** — an `aee-in-sarif` convention doc + emitter so a verifier
  run lands as findings in the GitHub Security tab and any SARIF-consuming tool. Speaks a
  format security teams already ingest.
- [ ] **Framework crosswalk (`.md` + machine-readable `.json`)** — map the AEE evidence
  model and each conformance-vector class to OWASP MCP Top 10, the OWASP Agentic Security
  Initiative Top 10, OWASP AIVSS, and MITRE ATLAS, so findings land in the frameworks
  defenders already report against. Regenerate the table from the vectors; do not hand-edit.
- [ ] **`GOVERNANCE.md`** — document the decision process for new conformance vectors and
  schema changes, deprecation policy (IDs never reused), and the crosswalk-update process.
  Publish the record `$schema` at a stable URL.

## Suite hygiene & citability

- [ ] **Paired positive/negative fixtures per vector** — for each conformance vector, a
  short `<id>_positive` / `<id>_negative` fixture pair so any implementation's detection
  logic can be tested against the standard, with the logic living in the implementer's repo.
- [ ] **Claim -> verdict-token -> reproduce-command manifest** — a table mapping each thing
  the suite asserts to (a) the exact verdict token a verifier emits and (b) a one-line
  command an evaluator runs to reproduce it, so nothing has to be taken on trust.
- [ ] **Shippable tamper-evidence demo** — a dependency-free script that corrupts a copy of
  a signed record two ways (flip one byte, drop one entry) and shows the verifier catches
  each, recomputing from the record's own stored bytes (no re-serialization false alarms).
- [ ] **Citable dataset DOI** — mint a Zenodo (or equivalent) DOI for a tagged release of
  the conformance-vector corpus so it can be cited in papers and reports.

## Supply-chain posture

- [ ] **OpenSSF Scorecard workflow** — add `ossf/scorecard-action` and publish the badge.

## Predicate ergonomics

- [ ] **`honest_limits[]` + `contract_version` fields** — machine-readable declaration of
  exactly what a given evidence record does and does NOT cover, and the predicate contract
  version it was produced under, so a consumer can reason about scope explicitly.
- [ ] **Fail-closed client hygiene** — for any network path a verifier may use, enforce
  immutable config, single-flight, error-on-redirect, and coerce-unknown-toward-reject.

## Known gaps in the gates

- [x] **The corpus cannot be regenerated from the sources it declares** — CLOSED at
  suiteRevision 16. Both generators now build all seven vectors, both index tables carry their
  rows, `python3 vectors/gen_manifest.py` exits 0 and is idempotent, and the heading check in
  `scripts/count-gate.py` reads the manifest with a one-row-per-vector-per-family assertion
  beside it. The two accept vectors regenerate byte-identically from the committed files; the
  five reject vectors do NOT, and the reasons are the two rows below.
- [x] **Nothing asserts that the manifest is reproducible** — CLOSED by
  `scripts/regenerability-gate.py`, wired into `.github/workflows/ci.yml`. It copies the tree,
  empties the generated set, runs all three generators and diffs. Run against suiteRevision 15
  unmodified it names all seven vector files and the manifest.
- [ ] **Three shipped reject vectors carried a signature that does not verify, and nothing
  in the corpus could see it.** `bad-900`, `bad-901` and `bad-902` were minted by copying the
  parent's signature across a mutated payload. The reject generator's own second-fault
  self-check refuses all three on sight, and this directory publishes the invariant that every
  committed signature verifies, because signature verification is tier territory rather than
  validity. The three are rebuilt and correctly signed at suiteRevision 16, so the instance is
  closed; what is open is that no gate would have caught it. `packaging/run_vectors.py` never
  verifies a signature it is not asked about, and the generator self-check only sees bytes the
  generator built. A check that ran the self-check over the COMMITTED files, rather than over
  the freshly-built ones, would close it. File: `vectors/reject/gen_invalid_vectors.py`.
- [ ] **The two vector generators carry two different constant sets for one suite.** The
  accept generator's catch-policy pre-image, posture pre-image, run-entropy pre-image, corpus
  name and corpus uri all differ from the reject generator's, and each index publishes its own
  as THE determinism recipe. Five vectors were minted with the accept set and filed under the
  reject recipe, which no reader of either index could have detected and which is invisible to
  every gate here. Unifying them is a revision-scale change rather than a fix: every reject
  vector and every digest it carries would be re-minted. Recording it is the point until then.
  File: `vectors/reject/gen_invalid_vectors.py`, `vectors/accept/gen_valid_vectors.py`.
- [ ] **`ok-900` and `ok-901` each cite `aee-c-1` and neither is about the result
  vocabulary.** `ok-900` pins the minimum composition, which is `aee-c-2` with `aee-c-3` and
  `aee-c-6` beside it; `ok-901` pins the fail-closed basis branch, which is `aee-c-5`. The ids
  were hand-typed into the manifest at suiteRevision 15 and are preserved verbatim so the
  manifest's per-vector content did not move while its regenerability was being fixed.
  Correcting them is a one-line edit to each index row and a manifest regeneration.
  File: `vectors/accept/INDEX.md`.
- [ ] **Forcing is measured against ONE rail, so a rule only the Python rail states is
  invisible to it.** `scripts/forcing-gate.py` weakens `aee/` and replays; a rule the Go rail
  does not implement has no mutation site and therefore no row, and the two first-party rails
  are held to one vocabulary by `scripts/code-contract-gate.py` but not to one rule set. The
  same measurement over `packaging/run_vectors.py` needs a Python mutation operator set and a
  second baseline. File: `scripts/forcing-gate.py`.
- [ ] **A weakening the operator set cannot express is scored as nothing at all.** The eleven
  operators switch off a guard, a disjunct, a conjunct, a switch arm, a bool return or an
  emission. A rule that lives in a constant (a bound, a depth cap, a media type), in the ORDER
  of two checks, or in a data table is not a site, so it appears in no class -- not even as a
  gap. 590 sites is the size of what can be asked, never the size of the rail. File:
  `cmd/mutgen/mutate.go`.
- [ ] **The 157 unforced rules on branches no vector takes are a list, not a plan.** The
  nightly sweep re-derives which surviving mutants sit on a branch the corpus never enters,
  which is the evidence separating a mintable gap from one no new vector could close. Nothing
  yet drives that number down, and nothing distinguishes the rules worth a vector from the
  ones that are unreachable for a reason. File: `docs/FORCING-BASELINE.json`.

- [ ] **A vendored copy that is refreshed, recorded, then reverted stays green.** The
  consumer-lag gate compares `vectors/CONSUMERS.json` against the corpus published here,
  and that ledger records what each copy carried when it was last synced. A copy reverted
  after its sync would keep a stale ledger entry that still matches, and the copy's own
  stamp check cannot see it either, since a revert plus a re-stamp is internally
  consistent. Closing it needs this repository to read the consumer, which is the
  cross-repository read the gate is built to avoid. File: `scripts/consumer-lag-gate.py`.
- [ ] **A vendored copy no document advertises and no ledger row records is invisible.**
  A copy absent from `vectors/CONSUMERS.json` was reported as success, because the gate
  counts the rows it was told about and its message says it counts the copies that exist.
  That is now closed on one axis: the number of rails the implementation report names has
  to equal the number of rows, so a rail advertised with nothing recorded behind it fails.
  What is left is the copy nobody wrote down anywhere. The report and the ledger agree
  with each other, both are silent about it, and no reading of either surfaces it — only
  a sweep of the consuming stacks would. File: `scripts/consumer-lag-gate.py`.
- [ ] **A citation cut short of its subject is invisible when every word it lost was also
  rewritten.** The sync now asks its own question line by line as well as span by span,
  which closes the truncations that dropped prose upstream left alone. What remains is
  the case where the dropped words were themselves amended: nothing survives to be
  looked for, the span is simply shorter than it was, and that is the same event as a
  legitimate narrowing onto a tightened rule. Measured over every re-vendor where the
  remapper was live, no rule on the two documents separates them. The extent of the span
  is the only signal left and it does not discriminate: at suiteRevision 14 a three-line
  citation collapsed to one line inside a rewritten paragraph and was wrong
  (`aee/pae.go::IsLowerHex64`, which lost the words naming the digest value form), while
  at suiteRevision 13 six anchors collapsed three lines to one in the same way and were
  right (`bad-810` and its siblings, where the heading alone carries the requirement).
  Both narrow to a third of their former text. Further out the order inverts: a span cut
  to a sixth was accepted (`bad-727`, where the old anchor had run past its subject into
  the next clause) while spans cut to a fifth were repointed. Deciding between them needs
  the words the claim beside the citation depends on, which was measured and rejected
  when these pins were built, because a claim may name an identifier in passing and a
  citation may legitimately cover several passages, so it needed a standing per-citation
  exemption list. That list is the blessing the ledger exists to remove. The honest
  position is that this residue is a review question with the evidence attached, not a
  gate, and the sync prints the dropped prose so the reading is targeted rather than
  exhaustive. File: `scripts/specpins.py`.
- [ ] **The number profile is integers-only and the specification asks only for safe
  integers.** `checkSafeInteger` rejects any JSON number carrying a fractional part,
  anywhere in a canonicalized payload, including inside members the specification leaves
  to the producer ("everything else in the payload stays producer territory", L977-979).
  What the document states is the safe-integer bound (L83-85, and L856-858 for record
  payloads); it declares every numeric member it defines an integer and states no rule
  against a fractional number elsewhere. The rails reject one anyway, so cross-language
  float formatting can never split them, which is a real reason and a different one from
  conformance. No vector distinguishes the two readings, so a from-spec verifier that
  accepts `1.5` in producer territory is conformant and passes this corpus today. Decide
  whether to ask upstream for the stricter profile or to narrow the rails. File:
  `aee/jcs.go`.

- [ ] **Nothing compares an interpretation entry's anchors with the anchors its own
  prose quotes, outside the registry.** The registry gate now requires an entry's
  `specAnchors` to cover every line reference its title or reading makes, which is what
  found four entries whose recorded anchor sat two lines above the words the entry puts
  in quotation marks. The same disagreement is possible in `vectors/CHANGES.md`,
  `vectors/coverage-unforced.json` and `docs/interpretation-decisions-open.md`, which
  carry anchors and prose side by side with no equivalent check.
  File: `scripts/interpretation-registry-gate.py`.

## Recently landed

- [x] **Make forcing a measured property rather than a periodic audit** (2026-07-30) -- what the
  corpus obliges a verifier to implement is now a number CI holds, not an argument. A vector
  count never measured it: the evaluator satisfies a vector when any expected code in a stage is
  observed, so deleting the `result-vocabulary` emission turns two vectors' gate-0 column FAIL
  and the suite still reports 186 of 186, exit 0. `cmd/mutgen` enumerates 590 single-site
  weakenings of the rail and applies one at a time, `cmd/mutrun` replays the whole corpus in
  process under both key policies, and `scripts/forcing-gate.py` scores each replay with the
  harness's own `evaluate_vector` and holds the result as a tighten-only ratchet against
  `docs/FORCING-BASELINE.json`: 331 KILLED, 17 SILENT, 237 DEAD, 5 INCONCLUSIVE. Site identity is
  content-addressed (file, function, operator, digest of the mutated source), so an inserted rule
  disturbs one row instead of renumbering every row below it. Proven able to fail in both
  directions: deleting `bad-608-digest-uppercase`, the sole forcer of the lowercase-hex digest
  rule, turns four rows red by name and restoring it turns them green, and deleting the
  `len(s) != 64` check from `IsLowerHex64` is refused as two retired rules. Per push CI runs the
  rules recorded as forced -- the complete set where a regression is possible, and the set already
  known to terminate -- for about 1670 CPU-seconds, against about 3370 for the full sweep a nightly
  workflow runs, which is the only scope that can see forcing improve or falsify an annotation. Two
  independent full sweeps produce a byte-identical baseline.

- [x] **Separate unmintable from unminted, and both from unmeasurable** (2026-07-30) -- the
  baseline carries three states plus two annotations rather than a single gap list. INCONCLUSIVE
  is its own class, never folded into unforced: two mutants do not terminate, two do not build,
  one crashes, and nothing is asserted about any of them. Four sites are annotated as ones where
  "unforced" is the wrong word -- three true equivalent mutants (an empty case arm in a switch with
  no default; `case ResultFail: return 0`, whose deletion sends fail to a rank that still sorts
  bottom; `!hasStillArmed`, which `objBool`'s contract makes redundant beside `!stillArmed`) and
  one masked rule where an earlier check reaches every input that could distinguish it. Both
  annotation kinds are falsifiable and the gate falsifies them: an annotated site that is ever
  KILLED fails the build, so an annotation cannot decay into a suppression.

- [x] **Correct three rules the first forcing measurement recorded as unforced** (2026-07-30) --
  that campaign replayed each vector once, under the pinned key only, and reported
  `tiers_without_key: None`. The evaluator skips a tier column it was handed nothing for, so
  GATE 2's no-TOFU rule was compared against nothing and its three implementing sites --
  `DeriveTiers`'s `policy == nil || len(keys) == 0` guard, its `policy == nil` disjunct, and
  `anchorPolicyCodes`'s `policy == nil` -- scored DEAD on never-taken branches. Replaying under
  both key policies, as `run_vectors.observe_external` does, kills all three: `ok-024` forces
  them. The ground-truth gate is what surfaced it, refusing to score a run whose fast path
  disagreed with the real CLI on that column.

- [x] **Ask the sync's re-aim question line by line, not only span by span** (2026-07-29) --
  the synchronise refused to move a citation off text still in the document, but only
  ever looked for the span's text as one piece, so an amendment touching any part of a
  cited passage made the search fail and everything the remap abandoned went unexamined.
  The same question asked of each line refuses the citation that dropped prose upstream
  left in place, and names that prose in the refusal. Replaying the suiteRevision 14
  re-vendor against the parent commit reproduces the defect exactly: as the check stood,
  all twenty-six mis-aimed spans passed and both ledgers were written; with the line
  question, the re-vendor stops and names nine of them, every one of which the commit
  went on to repoint. Measured over every re-vendor where the remapper was live and
  scored against what a person did next, it refuses twenty-six spans, fifteen repointed
  and eleven deliberate narrowings cleared one at a time through `--accept-reaim`, which
  records nothing and so cannot rot. That aggregate carries eight of the nine above; the
  ninth sits in a section the same commit renamed, which leaves the automated pairing
  nothing to compare it against. Mutation-checked in
  both directions: with the line question stubbed out the replay writes both ledgers and
  refuses nothing, and the pre-existing whole-span refusal still fires with its own cause
  when a citation is aimed at unrelated prose. Replaying the corrected re-vendor produces
  ledger entries byte-identical to the committed ones for every citation the commit did
  not add or rename, so a correctly performed re-vendor reaches the same place and only
  stops earlier.

- [x] **Vendor the two amendments the corpus already implemented** (2026-07-29) --
  the pin moves two commits along the upstream predicate branch. The first binds the
  carried observation vocabulary and the carried network posture into the run identity
  and declares the posture vocabulary a closed four-value registry with an append-only
  rule; the second adds the fourth `result` value and restates the recompute as the
  minimum of three independent conditions. Both readings were already in the rails and
  the corpus, so no vector file moved and the replay was green against the new text
  before it arrived. The two entries in `docs/interpretation-decisions-open.md` that
  recorded the corpus running ahead are closed, and their readings become registry
  decisions 19 and 20.

- [x] **Re-aim every `spec:NNN` citation onto the passage its own claim names** (2026-07-29) --
  eighty-seven of ninety-eight citation spans across thirteen files were corrected by
  hand, each accepted through `--accept-reaim` by name so the ledger records a decision
  rather than a sweep. The backward measurement that found the drift returns zero over
  every citation not named that way, and reverting any single correction turns it red
  again. The classes separate as follows. Thirty-eight spans were mechanically drifted,
  and correcting thirty of them put the citation back on the text it was written for.
  Twenty-six are aimed somewhere their old text never went, because they were pointed at
  the wrong passage when they were written; eighteen of those the mechanical test could
  never see at all, since a citation still sitting on the prose it was first pointed at
  looks correct from history no matter what the claim beside it says. The remaining
  thirty-one address passages upstream has since rewritten, which the measurement cannot
  classify either way, and they were corrected on reading like the rest.

- [x] **Force reason-map membership on all three coverage sets** (2026-07-26, `cf0d540`) —
  the spec already made the three coverage sets a disjoint partition of the manifest's
  classes, but only `bad-819` forced the `assessedClasses` side. Added
  `bad-731-outofscope-unknown-class` and `bad-732-routedelsewhere-unknown-class`: each puts
  an unknown class key in one reason map, leaves the result alone, and is rejected as
  coverage-incomplete. Both reference rails (Go `aee/statement.go`, Python
  `_coverage_partition_ok` in `packaging/run_vectors.py`) already enforced it, so the two
  vectors lock the written rule and mutation-prove the rails (reverting the reason-map
  accounting flips both). Corpus now suiteRevision 3, 140 vectors (35 accept + 105 reject);
  full local gate green and remote CI green.
- [x] **Extend registry decision 14** (2026-07-26, `cf0d540`) — recorded the two new
  vectors in `vectors/interpretation-decisions.json`, and added a `CHANGES.md`
  suiteRevision-3 section.
- [x] **Document the registry as a post-run reconciliation surface** (2026-07-26, `cf0d540`) —
  added a note to `docs/interpretation-decisions-open.md` clarifying that the interpretation
  registry is read for post-run reconciliation, not as a pre-implementation answer key.
- [x] **Correct the CI vector-replay label 138 -> 140** (2026-07-26, `cf0d540`).
- [x] **Update the multi-implementation report** (2026-07-26, `cf0d540`) —
  `docs/IMPLEMENTATION-REPORT.md` now records the reviewer's re-run as a third
  fully-independent column on the earlier corner-case features (138/138 spec-diff-led,
  132/138 unchanged).

---
_Detailed rationale and cross-repo tracking live in the private product backlog; this file
is the public roadmap for the open conformance artifact._
