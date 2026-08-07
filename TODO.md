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
the forcing ratchet is re-measured. He has now read v0.7 as well, at suiteRevision 22 on
2026-08-03: a blind first run of 179/232 and a directed pass of 232/232, both recorded in
`docs/INDEPENDENT-RUNS.json` with the null-digest caveat his own index carries for the
blind build.

- [ ] **Await the reviewer's read on the revised proposal** — no code change pending on
  our side; the next step is the reviewer's call.
- [ ] **Ask for a run at the current suiteRevision.** His v0.7 run is at suiteRevision
  22 and the corpus is three revisions past it; the ledger records no run for any
  revision after that one and every published claim says so. The disclosure discipline
  for the revised vectors applies — publish the vectors without the text or the text
  without the vectors, never a note naming the failing vector and its fix.

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
- [x] **The whole tier derivation was forced by one vector** (2026-07-31) -- the corpus pinned
  the derived per-row evidence tier for one of its fifty-two accept vectors, and the harness
  compares a tier column only where the manifest states one. Measured by mutation, five
  single-site weakenings of `aee/tier.go` were killed by `ok-024` and by nothing else, so
  retitling or dropping it would have retired five rules at once with every gate green. The
  tier-partition invariant added the same day hardens the Go rail and cannot see this: the
  measurement replays through `cmd/aee-verify` under `packaging/run_vectors.py` and never loads
  a Go test file. Five more accept vectors now pin their columns -- three whose index rows
  already asserted a tier in prose, two that gained the claim -- each derivable from the
  vector's own bytes rather than recorded from a rail's answer. The five sites move to between
  two and four forcing vectors, three sites outside `tier.go` gain vectors for the same reason,
  and the delta is additive everywhere: nothing lost a vector, nothing changed class.
  Mutation-checked by deleting `ok-024` outright: without the new pins all five go SILENT, with
  them all five stay KILLED.
- [x] **A directory of vectors in another encoding was invisible to the corpus runner**
  (2026-07-31) -- `checkManifestClosure` asked whether an unrecognised directory held vector
  files and decided vector-ness by file suffix, so a directory carrying the same statements as
  `.cbor` held no matching file, passed the kind check silently, and contributed to no per-kind
  count either. The two non-vector directories are named explicitly now and every other
  directory must be a manifest kind whatever it holds. Verified both ways against a real
  non-JSON vector directory. File: `aee/vectors_test.go`.
- [x] **The published harness scored a vector no manifest row named, and only noted it**
  (2026-07-31). Copying an accept vector to an unlisted name and running
  `python3 packaging/run_vectors.py` exited 0, printed a total one greater than the corpus size
  with every vector passing, scored the unlisted file PASS against a verdict derived from its
  directory, and reported the fact as a `note:` line. That was the wrong way round twice over:
  this is the rail the forcing measurement replays through and the one a third party runs, and
  the total it prints is where the published corpus size comes from, so an unlisted file
  inflated it silently while the Go runner refused the same tree by name. The note is a refusal
  now, and the closure is the one the Go runner makes: both directions per kind, the manifest's
  own counts block checked against the tree, every row's declared file member checked against
  the path the rail reads, and every directory under the suite root required to be a manifest
  kind or one of two named non-vector directories whatever it holds. `discover_vectors` took
  its three directory names from a literal, so a fourth was walked by nothing; it reads the
  kinds the manifest declares now, and a kind no contract here scores is refused by name rather
  than falling through to the reject contract. Suite-level refusals are carried in the totals
  in their own right, because reporting them only through the exit status leaves a table
  reading zero failures beside a non-zero exit. Mutation-checked over a copied tree against
  eleven weakenings -- an unlisted file, a deleted file, a fourth directory holding JSON, the
  same directory holding another encoding, a count inflated by one, a count naming an absent
  kind, the counts block dropped, a row retyped to a kind nothing scores, a whole kind removed
  from the manifest, a row's file member pointed elsewhere, and a vector smuggled into the
  keys directory -- each refused by name with the untouched copy green.
  File: `packaging/run_vectors.py`.
- [ ] **No statement carrying a pinned row can recompute above `fail`, so the attribution
  assignment cannot be exercised at a result any threshold-only consumer would admit.**
  Measured 2026-07-31 by construction and replay rather than read off the rules, because the
  reading this replaces cited `bad-982` as the demonstration and `bad-982` cannot be one: it
  carries `result: fail` with both rows caught, so a threshold consumer refuses it for the
  result and the assignment is never reached. The sweep builds every statement shape the
  reject generator can express -- record pools over every subset of the five record kinds,
  every reference subset within each pool, both bases, both methods, a caught
  label, a clean label and one outside the carried vocabulary, and coverage both complete and
  incomplete -- and scores each on the reference rail twice over, changing nothing between the
  two runs but the value of `attribution`. Under `paired` the sweep reaches `pass`,
  `pass_indirect` and `degraded`. Under `pinned` every valid statement recomputes to `fail`
  and not one reaches higher, and every shape the control reached above `fail` turns
  `attribution-pinned-recordless` the moment the member is raised. The reason is two coverage
  requirements this corpus already forces against each other: a pinned row must resolve an
  interception record (`bad-958`, `bad-973`) and a clean row must resolve none (`bad-950`), so
  a valid pinned row always carries a caught label, and a caught label floors the recompute.
  The consequence for `bad-982`, which exchanges the pinned assignment between two rows, is
  that no rewriting of it and no vector anyone could add would lift it above `fail`: a consumer
  admitting on `result` alone refuses it for the result and never reaches the assignment. The
  pair that does discriminate is already published -- `ok-051` carries the same two pinned rows
  with the assignment intact -- so a consumer that credits rows separates the two and one that
  does not gives both the same answer. What is left is a question for upstream rather than a
  gap here: an axis that acquired a normative reader at this version is readable only on
  statements a threshold consumer has already refused, and it is worth asking whether that is
  intended.
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
  gap. 754 sites is the size of what can be asked, never the size of the rail. File:
  `cmd/mutgen/mutate.go`.
- [ ] **The 185 unforced rules on branches no vector takes are a list, not a plan.** The
  nightly sweep re-derives which surviving mutants sit on a branch the corpus never enters,
  which is the evidence separating a mintable gap from one no new vector could close. Nothing
  yet drives that number down, and nothing distinguishes the rules worth a vector from the
  ones that are unreachable for a reason. The figure in this row is also not derived by any
  gate: the count gate accepted 157 here and accepts 185, so nothing was holding it to the
  baseline while the baseline moved under it. File: `docs/FORCING-BASELINE.json`.
- [x] **A sweep taken across two corpora was recorded as a measurement of one** (2026-08-02) --
  the worker trees symlink the corpus rather than copying it, so every mutant re-reads the
  vector files, while the manifest, the per-vector self-check and the unmutated observations
  each mutant is diffed against are read once at the start. A corpus written mid-campaign
  therefore makes a vector answer one way for the baseline and another for whichever mutants
  are in flight, and the difference is scored as those mutants killing it. That is how one rule
  came to be recorded as forced by two vectors that cannot reach its branch. CLOSED: the
  campaign now digests the manifest and every vector before the unmutated replay and again
  after the last mutant, and refuses rather than reporting a number.
- [ ] **A killed mutant on a branch no vector executes is a contradiction, and nothing says so.**
  The wrong row above sat next to measured coverage evidence, in the same file, saying the line
  it mutates is never executed -- and next to an equivalent mutation of the same line carrying
  the opposite class. The obvious check refuses a KILLED classification whose site line has an
  execution count of zero, and it is NOT sound as stated: `IF_OFF` rewrites a condition to
  `false && (COND)`, which short-circuits, so a guard whose CONDITION has side effects can be
  killed with its branch never taken. `types.go::parseEnvironment::IF_OFF::d57c9f848201` is
  exactly that -- the condition is `!decodeManifest(env.Corpus)` and the call populates the
  manifest for every statement -- and it is legitimately killed by most of the corpus at once.
  Making the check sound needs
  `cmd/mutgen` to report whether the expression it mutates contains a call, and the refusal
  restricted to the sites where it does not. File: `scripts/forcing-gate.py`,
  `cmd/mutgen/mutate.go`.

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

- [x] **A duplicate record and an undecodable one shared a guard, and no statement
  paired them** (suiteRevision 22). Both rails ran the duplicate scan inside the same
  condition as the batch-root recompute -- did every record decode -- so one record
  failing base64 switched off both, and a statement carrying a duplicate beside an
  undecodable record reported the decode failure and dropped `duplicate-record`. The
  corpus could not see it because no statement carried both conditions;
  `bad-410-duplicate-and-undecodable-record` does now. The Go rail was split first, the
  Python reference rail carried the same masking with a comment saying it was mirroring
  the Go rail, and both are split now: the scan runs over the records that decoded and
  skips the ones that did not, and the root check stays behind the decode guard, where
  it belongs. Files: `aee/validity.go`, `packaging/run_vectors.py`.
- [ ] **The vector above cannot fail the harness, and no reject vector in its shape
  could.** A reject expectation is a code SET the harness conforms a rail's answer by
  INTERSECTING, deliberately, so that a strict rail naming one condition and a
  superset-emitting rail naming every condition both pass the same manifest. Both of this
  vector's conditions sit in one expected set and in one gate stage, and
  `record-undecodable` is emitted first, so the primary code is the same with the defect
  present or absent -- measured: the whole corpus replays green through a rail with the
  shared guard restored. So the assertion that both conditions are reported lives in each
  rail's own oracle instead (`TestSetEmissionOnPairedRecordFaults`, and two checks in
  `run_vectors.py --self-test`), which is where a claim about THESE rails belongs rather
  than in the contract a third party is held to. What is still missing is any way for the
  corpus to say "a rail that emits sets must emit both of these" without demoting a
  single-code rail, and until there is, a defect of this shape is visible to the forcing
  campaign as a changed observation and to nothing else. Files: `packaging/run_vectors.py`,
  `aee/vectors_test.go`.
- [ ] **`bad-817` cites `aee-c-19` for a decode failure, and `aee-c-19` is the media-type
  rule.** The registry has no condition for the rule a payload breaks by not
  strict-decoding from base64 -- the DSSE envelope sentence at L1243-1245 -- so the only
  reject vector for `record-undecodable` borrowed the id belonging to `bad-204`, and its
  spec anchor `L1231-1234` addresses prose about `basis` and `method` that has nothing to
  do with encoding. The pin ledger froze that anchor because it can only judge an anchor
  that MOVES, never one that was wrong when it was first recorded, which is worth stating
  separately: it is a real limit of the mechanism. `bad-410` cites `aee-c-29` alone and
  anchors L1243-1245 directly rather than repeating the wrong id. Closing it means minting
  the missing condition, re-citing both vectors, re-syncing the anchor pin and the
  accept-anchor baseline, and restating the traceability figure, which is why it is a row
  and not a patch. Files: `vectors/reject/gen_invalid_vectors.py`, `spec/ANCHOR-PINS.json`.
- [ ] **The three consumer copies are behind suiteRevision 22.**
  `scripts/consumer-lag-gate.py --check` is red by design until each vendored copy is
  refreshed in its own repository and this ledger is re-read from the copies with
  `--sync`. Nothing here can close it: the sync reads each rail's own stamp on purpose, so
  that a run against a stale copy records the stale digest instead of greening itself.
  File: `vectors/CONSUMERS.json`.

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
