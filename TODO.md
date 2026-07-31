# aee-conformance — roadmap

Open work for the conformance-vector suite and reference verifier of the in-toto
Adversarial Execution Evidence (AEE) predicate. Contributions welcome.

> **Session code-health audit 2026-07-24:** `go build ./...` + `go vet ./...` + `mypy` all
> **CLEAN** — no findings for this repo. Combined cross-repo report:
> an internal audit report.

## Status: v0.7 review (in-toto/attestation#570)

The reviewer's independent from-spec checker went 138/138 on the earlier corner-case
features and conceded every open corner. The predicate has since moved to v0.7 and this
repository has moved with it: the specification is vendored, both reference rails
implement the four commitments it adds, the corpus is regenerated at the new type, and
the forcing ratchet is re-measured.

- [ ] **Await the reviewer's read on the revised proposal** — no code change pending on
  our side; the next step is the reviewer's call.
- [ ] **Re-run the independent implementation against the new corpus.** A breaking
  version spends the strongest external evidence this text has that it is determinate,
  and that evidence is now unspent: the ledger records no run for this revision and every
  published claim says so. The disclosure discipline for the revised vectors applies —
  publish the vectors without the text or the text without the vectors, never a note
  naming the failing vector and its fix.

## The predicate moved to v0.7 and the corpus moved with it

Landed at suiteRevision 18. The vendoring, the rules, the regeneration and the ratchet
are one revision, which is what the drift gate was refusing the state between.

- [x] **Re-vendored and regenerated in one revision** (2026-07-31). The nineteen refused
  anchors were re-aimed by reading each against the claim beside it; three clusters
  moved, and the three sites quoting the passage the revision rewrote now quote what it
  says.
- [x] **Every statement and every rail re-typed** (2026-07-31), across both reference
  rails, the attestor schema, both generators, the manifest, and the three consumer
  rails in the sibling repositories.
- [x] **The conformance conditions minted with their vectors** (2026-07-31), twelve of
  them, because the registry gate refuses a row no vector cites and a vector citing no
  row.
- [x] **The reject side kept to one declared fault each** (2026-07-31). Forty-five
  vectors briefly carried the mandatory seal as a second fault and none does now: four
  parent shapes gained the seal, the seal-constraint family gained a healthy unreferenced
  one so it still measures its own rule, and the twenty-one that carry a second condition
  as an unavoidable consequence of their single mutation declare it in one table with one
  reason.
- [x] **Every new rule scored on the forcing harness** (2026-07-31). The first pass found
  eight rules the corpus did not force: each had a second acceptable condition an older
  rule reported first. Eight vectors were written for them and every rule is forced on
  both reference rails.

Still open here:

- [ ] **The vendored consumer directory carries a version number nothing derives.** It is
  named for the retired version and the version it actually carries is in the stamp
  beside it, which is checked. Renaming it to the new number would put the same unchecked
  constant back in the same place; the rename that fixes the class is to a version-free
  name, and it is a cross-repository path change touching the vendoring script, both
  consumer gates, the rego corpus generator, the differential fuzzer and several website
  tests. File: `scripts/vendor_aee_corpus.py` in the consumer repository.
- [ ] **The admission rego module reaches nine of the twenty-six new rejects.** The other
  seventeen are settled inside a base64 observation record that module deliberately never
  decodes, so they sit on its denylist with that reason. Reaching them means teaching the
  module to decode a record payload, which is a scope decision about the admission gate
  rather than a defect in it. File: `deploy/admission/rego/` in the consumer repository.

## The indeterminate bucket (added at suiteRevision 17)

`vectors/indeterminate/` carries the statements on which the specification settles the
verdict and not the condition. It has one family, `signature-count-vs-payload-decode`,
and the enumeration behind that number is in `docs/interpretation-decisions-open.md`
under suiteRevision 17.

- [x] **The three consumer copies carry the published corpus** (2026-07-31). All three
  were re-vendored at suiteRevision 18 and the ledger records what each carries;
  `scripts/consumer-lag-gate.py --check` is green.
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
  gap. 743 sites is the size of what can be asked, never the size of the rail. File:
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
