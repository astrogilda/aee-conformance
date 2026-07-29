# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

## suiteRevision 9 (one condition, three spellings, and a fixed precedence)

- Corpus: **158 vectors (36 accept, 122 reject)**. specDigest unchanged at
  `1590b988...`; no normative change, two new vectors closing two rail
  divergences the corpus could not see.
- **How they were found.** A review of the freshly landed signature-entry
  condition read the rails side by side and found two of them answering
  differently. Nothing in the corpus disagreed, because the condition had
  exactly one vector and that vector could not reach either question.
- **The first divergence: when the count is evaluated.** Four rails ask "does
  any record carry no signature entry" once over the whole record set, before
  any payload is decoded. One asked it per record, inside the payload-decode
  loop. Both readings report the same condition for a statement carrying one
  fault, which is every vector in the suite. Give a statement a first record
  whose payload does not decode and a second carrying no signature entry and
  they part: the per-record rail meets the decode fault first and names it, the
  set-level rail names the missing signature. Which condition a verifier reports
  is the conformance contract, so this is a divergence rather than a matter of
  style.
- **The set-level reading is the one the spec gives.** The predicate's
  verify-then-read discipline is normative: a consumer verifies each record's
  signature "before relying on any field inside the payload", and a payload's
  fields "mean nothing until its signature verifies". A record with no signature
  at all is therefore settled ahead of the bytes it carries. The spec does not
  decide the sequencing directly and says so, since it makes only the
  consumption preconditions and the tier normative in its two-stage ordering and
  calls the sequencing itself informative. The suite has to decide, because a
  primary condition is what it compares. Because the text does not force it, the
  pick is written down as a spec ask rather than as a registry decision:
  `docs/interpretation-decisions-open.md` carries the argument, the sentence to
  add upstream, and the plain statement that until it lands a from-spec verifier
  evaluating the count per record is conformant to the specification and fails
  this corpus.
- **The second divergence: what a wrong-typed member is.** A `signatures` member
  holding a string, an object or a number carries no entry, so four rails report
  the entry-count condition. One decoded the member into a typed list, failed,
  and reported the parse catch-all for the whole statement. The catch-all names
  neither the record nor the member, and the registry had already decided this
  question for the absent-member spelling, which reports the specific condition
  even though a missing required member would otherwise be a parse fault. Absent,
  empty and wrong-type are one requirement failing three ways, so they report one
  condition. A wrong-typed value INSIDE a signatures array is untouched and still
  reports the catch-all: an array carries entries, so a fault in one of them is a
  fault in the entry rather than in the count.
- **`bad-748-signatures-empty-precedes-undecodable-record`.** Derived from the
  `ok-002` clean shape: the arming record's payload is re-encoded as
  non-canonical base64 so it no longer strict-decodes, and the sealed record's
  signatures array is emptied, in that wire order. Swapping the two roles makes
  every rail agree, so the order is the vector. Neither mutation moves a
  commitment: signatures sit outside the PAE pre-image and a lenient decode of
  the tampered payload returns the parent's exact bytes, so the leaf, the
  batchRoot, the run binding and every carried signature are what the parent
  carried.
- **A precedence pin has to be compound, and its expectation must not widen.**
  This is the suite's first vector that is compound by design rather than
  because deriving it singly was impossible. Its expected set names ONE
  condition, so a rail reporting the other fails rather than passing on a set
  widened to accommodate it. The second-fault self-check, which exists to prove
  a vector carries only its declared fault, would have flagged the deliberate
  companion; the corpus now declares such companions explicitly under
  `alsoCarries`, exempting only what was declared, so an UNdeclared second fault
  in the same vector still fails the check.
- **`bad-749-record-signatures-not-an-array`.** Derived from the `ok-001` caught
  shape by replacing the covering record's signatures member with the JSON
  string `"sig"`. It reads as the likeliest producer bug of the three spellings,
  since a substrate that emits one signature object where the schema wants an
  array of them produces exactly this. Nothing is rederived, for the same reason
  `bad-745` rederives nothing.
- **Verified by mutation, per divergence.** With the Go rail's typed decode of
  the member restored, `bad-749` is the only failing vector of the 158 and fails
  as "primary code statement-malformed not in expected set". With the Go rail's
  count moved back inside the decode loop, `bad-748` is the only failing vector
  and fails as "primary code record-undecodable not in expected set". Each
  vector goes red for exactly the divergence it was written for.
- **Independent checker status.** `Rul1an/aee-checker`'s last author-run remains
  **suiteRevision 5 at 149/149** (2026-07-28, aee-checker#3). It has not run
  suiteRevision 6, 7, 8 or 9, so this suite publishes no score for it at any of
  the four.

## suiteRevision 8 (a corpus that declares no attack is not a corpus)

- Corpus: **156 vectors (36 accept, 120 reject)**. specDigest advances to
  `1590b988...` at upstream commit `b9a585a`. Two new vectors, one normative
  reason.
- **The defect.** A valid, passing, policy-admitted statement about an
  arbitrary subject could be minted with no substrate, no substrate key, no
  substrate run, no `observationRecords`, no `batchRoot`, no `runEntropy` and
  every carried digest fabricated. The verifier returned valid with result
  `pass` and the shipped admission policy returned compliant. This is a total
  bypass of the substrate, which is categorically worse than lying about a
  real run: there is nothing to lie about.
- **The mechanism, one step at a time.** Coverage integrity is an equality
  between two unions of attack identifiers, and an equality between two empty
  sets holds, so a manifest declaring nothing satisfied it vacuously. Zero
  declared attack identifiers means zero rows. Zero rows means zero
  `basis: substrate` rows. With no substrate row the predicate already
  permitted `runEntropy`, `observationRecords` and `batchRoot` to be absent.
  Every structure that would have required a substrate signature therefore
  dropped out of the statement, and what remained still verified.
- **The normative change.** The manifest now carries a floor: it MUST declare
  at least one attack identifier across all of its classes, and a manifest
  declaring none makes the statement malformed under the condition
  `corpus-manifest-no-attacks`. It sits with well-formedness rather than with
  `result` because a corpus declaring no adversarial inputs is not an
  adversarial corpus; scoring it would concede that a zero-attack run is a
  legitimate statement that merely scores badly, and that concession is the
  thing the floor refuses.
- **Why the rule counts identifiers and not classes.** Both
  `{"classes": {}}` and `{"classes": {"XA": []}}` were measured valid, passing
  and admitted before the fix. A rule phrased as "an empty classes object is
  malformed" closes only the first and leaves the second, which carries a real
  class name and reads far more plausibly as an assessment that found nothing.
  Counting identifiers closes both.
- **`bad-746-manifest-empty-classes` and
  `bad-747-manifest-class-declares-no-attacks`.** Two vectors because the
  bypass has two shapes and one vector leaves the other untested. Both derive
  from the `ok-007` artifact-only recordless shape, which already carries no
  records, no `batchRoot` and no `runEntropy`, so emptying the manifest is the
  whole distance between a valid statement and the bypass. The rederive chain
  drops the row the emptied manifest no longer declares and rebuilds the
  coverage partition around what is left; leaving either behind would add
  `row-attack-unknown` or `coverage-incomplete` and the vector would stop
  testing the floor. Everything else in both files still checks out: the
  corpus digest re-derives over the emptied manifest, coverage partitions it
  exactly, and the recompute returns `pass`.
- **What the floor does not touch.** A manifest that declares attack
  identifiers and assesses none of them stays valid. The honest fully-skipped
  run -- every class disclosed under `outOfScope`, no rows, result `degraded`
  -- was measured valid before this revision and is still valid after it,
  because its manifest declares an attack identifier. The Go rail pins that
  case as an explicit control beside the two new rejects.
- **Both reference rails.** The Go rail carries the check as
  `corpus-manifest-no-attacks` in `gate0Corpus`; the Python rail gained the
  identical condition code this revision in `_corpus_declares_attack`.
  Verified by mutation: with the Python check disabled, `bad-746` and
  `bad-747` are the only failing vectors of the 156 and both fail as "expected
  invalid, observed valid" -- the pre-fix bypass, reproduced.
- **Independent checker status.** `Rul1an/aee-checker`'s last author-run
  remains **suiteRevision 5 at 149/149** (2026-07-28, aee-checker#3). It has
  not run suiteRevision 6, suiteRevision 7 or suiteRevision 8, so this suite
  publishes no score for it at any of the three.

## suiteRevision 7 (a record must carry a signature to be a record)

- Corpus: **154 vectors (36 accept, 118 reject)**. specDigest advances to
  `da840f9e...` at upstream commit `3502c52`. One new vector, one normative
  reason.
- **The normative change.** `observationRecords` described a DSSE envelope as
  `payload`, `payloadType` and `signatures` without saying how many signature
  entries the last of those must carry, so a record carrying an empty array was
  a well-formed record by the letter of the definition. The definition now
  requires at least one entry. The revision also reconciles the verify-then-read
  order the same section states with the byte-pure gates that read payload
  fields before any verification: those gates read ahead deliberately, because a
  consumer holding no key material must still be able to run them, and what they
  produce is a stage rather than a conclusion. Coverage validity is restated in
  the same terms — it establishes that a statement is well formed and never that
  it is true, and it becomes a security property only in combination with
  observation-record signature verification.
- **Why the corpus could not see the zero case.** A DSSE leaf is
  `H(0x00 || PAE)` and the PAE pre-image spans `payloadType` and `payload` only,
  so signatures sit outside every commitment the predicate makes. Stripping
  every signature entry from every record leaves the leaf hashes, `batchRoot`,
  the run binding and the recomputed `result` bit for bit unchanged, leaves the
  statement valid, and drops only the derived evidence tier. A consumer gating
  on `result` alone therefore admitted an entirely unsigned attestation, and no
  check at the byte-pure layer could notice.
- **`bad-745-record-signatures-empty`.** Derived from the `ok-001` shape by
  emptying the covering record's `signatures` array, with an empty rederive
  chain — the only vector in the suite that alters a record and moves no
  committed digest at all, which is the finding stated as a construction. An
  absent member and an empty array are the same fault, since both are a count of
  zero. The check is byte-pure and proves nothing about the entries it counts: a
  record carrying one fabricated signature stays valid here and is caught only
  by verification at the tier, so the vector closes the literal zero-signature
  case and no more.
- **Both reference rails.** The Go rail carries the check as
  `record-signatures-empty` in `checkRecordsStatementLevel`; the Python rail
  gained the same code this revision, since without it the two rails disagreed
  on a statement with an empty `signatures` array — the Python rail answered
  valid where Go answered invalid. Verified by mutation: with the Python check
  disabled, `bad-745` is the only failing vector of the 154 and fails as
  "expected invalid, observed valid".
- **Independent checker status.** `Rul1an/aee-checker`'s last author-run remains
  **suiteRevision 5 at 149/149** (2026-07-28, aee-checker#3). It has not run
  suiteRevision 6 and has not run suiteRevision 7, so this suite publishes no
  score for it at either revision.

## suiteRevision 6 (the depth boundary and the noncharacter exclusion)

- Corpus: **153 vectors (36 accept, 117 reject)**. specDigest advances to
  `606215de...` at upstream commit `aa9aa9c`, which adds two paragraphs to the
  Prerequisites: the noncharacter exclusion below, and a normative-honesty
  sentence stating that a reading no vector exercises is untested rather than
  confirmed. Four new vectors, two normative reasons.
- **The depth boundary the previous revision could not discriminate.** Revision 5
  made the nesting bound normative at 128 with `bad-741`, but `bad-741` is a
  scalar leaf at open-container depth 130 — the one shape a verifier that counts
  per parsed value rejects correctly — and nothing in the corpus sat at the 128
  boundary, so a constant-only fix and a correct counting rule scored identically.
  The independent checker named this precisely. `ok-036` (accept) puts a scalar
  leaf at open-container depth 128, the exact bound; `bad-742` (reject) puts an
  **empty-container** leaf at open-container depth 129, one level past it. The
  empty-container shape is the discriminator: a verifier that charges nesting per
  parsed child never charges an empty container its own level, so it slips one
  past the bound.
- **A first-party split the pair also closed.** That exact shape was live in the
  reference Go rail: `decodeValue` charged depth per child, so `aee/jcs.go`
  accepted an empty-object leaf at open-container depth 129 where the Python rail
  (`run_vectors.py`, a bracket counter) rejected it — the two reference rails
  disagreeing on identical bytes at one depth, which is the parity the bound
  exists to guarantee. The guard moved into the container branch so an empty
  container is charged when it opens; `bad-742` is the regression pin (reverting
  the guard makes the buggy rail accept it). The same off-by-one was fixed in the
  TypeScript payload parse.
- **The noncharacter exclusion (`bad-743`, `bad-744`).** The string
  well-formedness rule cited strict I-JSON, and RFC 7493 section 2.1 forbids the
  66 Unicode noncharacters (U+FDD0..U+FDEF and U+nFFFE/U+nFFFF in every plane) in
  the same sentence as surrogates, but every rail accepted U+FFFF. A noncharacter
  is a valid scalar value that nothing substitutes for, so it is not a cross-rail
  decoding split — identical bytes give identical digests everywhere — but a
  verifier implementing the RFC 7493 label rather than the narrower scalar-value
  wording would reject a record another accepts. `bad-743` carries U+FFFF in a
  vocabulary label (statement position); `bad-744` carries it in a payload value.
  Every rail now rejects noncharacters wherever a string literal appears, at any
  depth and in both member-name and value position.
- **Independent checker status.** `Rul1an/aee-checker` reached **149/149 on
  suiteRevision 5** (2026-07-28, aee-checker#3): it adopted the 128 bound and,
  rather than only move the constant, moved its depth increment into the container
  branch, which resolves the 148/149 note recorded under revision 5 below. It has
  not run suiteRevision 6. Its author has stated the checker does not yet reject
  noncharacters, so on `bad-743`/`bad-744` we would expect it to answer valid
  where the reference rails answer invalid until it adds that check — a rule
  difference derived from his own note, not a run he produced, and not reported as
  his score. The two depth-boundary vectors his container-branch fix already
  handles.

## suiteRevision 5 (byte-level tier: the quadrant that had no coverage)

- Corpus: **149 vectors (35 accept, 114 reject)**, specDigest unchanged from
  revision 4. Nine new reject vectors, `bad-733` through `bad-741`.
- **The gap this closes.** Revision 4 made encoding well-formedness and the
  nesting bound normative and said plainly that the corpus exercised neither.
  It exercised nothing nearby: decoding all 140 files and all 219 base64
  payloads found no escape sequence of any kind, no non-UTF-8 byte and no raw
  control character anywhere. That is also the quadrant where the rails had
  actually diverged in the field, so it was the largest unguarded surface in
  the suite.
- **Statement position** (`statement-malformed`): unpaired high surrogate
  escape (`bad-733`), unpaired low (`bad-734`), reversed pair (`bad-735`),
  CESU-8 (`bad-736`), overlong UTF-8 (`bad-737`), raw U+0001 (`bad-738`). Each
  appends the fault to an `observationVocabulary` label and **recomputes the
  vocabulary digest over the mutated content**, so a rail that decodes leniently
  sees a self-consistent vocabulary and has no other rule left to catch the
  statement on. That is the construction that verified valid on one rail and
  invalid on three.
- **Payload position** (`payload-not-ijson`): unpaired surrogate escape
  (`bad-739`), CESU-8 (`bad-740`), nesting one level past the bound (`bad-741`).
- **New vector tier.** `bad-736`, `bad-737` and `bad-738` are not valid JSON
  texts, so they cannot be produced by a serializer and are written verbatim in
  binary. The generator asserts the property rather than assuming it: a vector
  declared byte-level that parses as a JSON text is an error, because the fault
  was lost in serialization. The runner reports whether its parse was faithful
  and skips the derived-commitment self-check when it was not, since every
  digest recomputed from a lossy reconstruction would mismatch for the
  substitution rather than for a second fault.
- **`bad-741` currently fails the independent from-spec checker, and that is
  the point.** On identical bytes the reference rails answer invalid and
  `Rul1an/aee-checker` answers **valid**, because its bound is 256 and the
  bound is now normative at 128. The 127-depth divergence recorded in revision 4
  is no longer an argument; it is a reproducible corpus failure. The checker
  needs a one-constant update to reach 149/149, and until it lands the honest
  parity figure for that implementation is **148/149**.
- Verified by mutation on both reference rails: removing the Go string-scalar
  scan changes every statement-position vector to `vocabulary-digest-mismatch`
  and the payload vectors to `payload-not-canonical`; removing the Python one
  restores the original `UnicodeEncodeError` crash, which is the defect the
  whole tier exists to keep closed.

## suiteRevision 4 (encoding well-formedness and a normative nesting bound)

- Corpus: 140 vectors (35 accept, 105 reject), verdicts and codes unchanged.
  New specDigest `39233b27b7f2...`, vendored from in-toto/attestation#570 at
  commit `98328d1`.
- **Normative change.** Strict I-JSON previously named only its duplicate-member
  half, and the string half was scoped to BMP-only, which constrains WHICH
  scalar values may appear rather than whether the bytes denote scalar values at
  all. The spec now requires, statement-wide and fail-closed, that every string
  literal be a well-formed sequence of Unicode scalar values: valid UTF-8 with no
  overlong form and no surrogate encoded directly in UTF-8, no unpaired surrogate
  escape in either order, no raw character below U+0020, and a `\u` escape of
  exactly four hexadecimal digits with no sign, whitespace or radix prefix. The
  check is required on the raw bytes, before any decoded string is read.
- **Normative change.** JSON nesting depth is bounded at 128, with the counting
  rule stated (open containers, not parsed values). It was previously unstated,
  so implementations chose their own: the reference rails chose 128 and the
  independent from-spec checker chose 256, which made identical bytes valid
  evidence to one conforming verifier and malformed to another across 127 depths.
- **Why no vectors changed.** Both rules codify what the reference rails already
  enforced, so no existing vector flips. That is also the honest limit of this
  revision: **the corpus does not yet exercise either rule.** Decoding all 140
  vector files and all 219 base64 record payloads finds no `\u` escape of any
  kind, no non-UTF-8 byte, and no raw control character anywhere, in either
  statement or payload position. An implementation can pass this revision at
  140/140 while getting the new rules wrong.
- **Follow-up, tracked.** A declared raw-bytes vector tier covering unpaired
  surrogate escapes, CESU-8, overlong forms, raw control characters and the
  depth boundary, in both positions. It is a tier rather than ordinary vectors
  because a vector carrying invalid UTF-8 cannot satisfy the generator's
  existing invariant that every emitted vector re-parses as JSON text.

## suiteRevision 3 (round-8 reason-map membership)

- Corpus: 140 vectors (35 accept, 105 reject). No normative spec change; the
  specDigest is unchanged. Two forcing vectors close the reason-map side of the
  coverage-partition membership rule already carried by the spec (L487-489): the
  three coverage sets are a disjoint partition of the manifest's classes, so
  membership runs both ways, but only `bad-819` forced the `assessedClasses`
  side. New reject vectors `bad-731-outofscope-unknown-class` and
  `bad-732-routedelsewhere-unknown-class` force it for the two reason maps (an
  unknown class key in `outOfScope` / `routedElsewhere`, `result` left alone,
  must be rejected `coverage-incomplete`). Both reference rails already enforced
  it (Go `aee/statement.go`, Python `_coverage_partition_ok`); the vectors lock
  the rule and mutation-prove the rails (reverting the reason-map accounting
  flips both vectors). Surfaced by the independent from-spec checker as an
  untested consequence of the written rule (in-toto/attestation#570 round-8,
  Rul1an). Registry decision 14 gains the two vectors.

## suiteRevision 2 (round-7 chain-scope redesign)

- Corpus: 138 vectors (35 accept, 103 reject). Normative change to the
  `aeeChainScope` arming-payload member: a free-form producer string becomes a
  duplicate-free array of tokens from the closed dimension vocabulary
  (`subject`, `corpus`, `networkPosture`), sorted in `observationVocabulary.labels`
  canonical order (UTF-16 code-unit). Each token pins a projection to a value
  already carried on the wire; a consumer compares the declared dimension set
  against its demanded scope (equality: neither finer nor coarser) and keys the
  gap/fork/genesis rules on the evaluated tuple, not the token set. No alias: the
  old string form fails closed.
- New reject vectors: `bad-721-chain-scope-not-array` (old string form),
  `bad-722-chain-scope-unknown-dimension`, `bad-723-chain-scope-not-canonical`,
  `bad-724-artifact-ref-out-of-range`. `ok-034-arming-chain-genesis` rewritten to
  the array form `["subject"]`.
- Out-of-range `observationRefs` is now a structural fault on ANY row, regardless
  of `basis`, fail-closed (previously enforced only on substrate rows).
- The whole statement is parsed as strict I-JSON: a duplicate member anywhere in
  the statement (not only inside a record payload) makes it malformed. New reject
  vector `bad-725-statement-duplicate-member` (raw statement bytes; the dict form
  cannot carry a repeat).
- `aeeBindingVersion` MAY be carried explicitly in the arming payload: a verifier
  reads it before deriving and rejects, fail-closed, a version it does not
  implement (the arming record covers nothing), distinguishably from a
  run-binding digest mismatch. Absent defaults to `1`; the carried value never
  drives the derivation. New reject vector `bad-726-arming-binding-version-carried`.
- Interpretation-decision hardening (from the independent from-spec checker's
  eleven recorded interpretation decisions, in-toto/attestation#570). Three
  forcing vectors lock spec-mandated readings the corpus did not yet exercise:
  `ok-035-unknown-kind-excluded-from-cap` (a referenced unknown-`aeeKind` record
  signed reconstructed covers nothing and is excluded from the method cap),
  `bad-818-artifact-clean-row-layer-not-none` (the clean-row `actualLayer: none`
  rule is not scoped to a basis, so an artifact clean row is held to it too), and
  `bad-819-assessed-class-not-in-manifest` (coverage is an exhaustive, disjoint
  partition of real manifest classes, mirroring `bad-816`). New machine-readable
  registry `vectors/interpretation-decisions.json` maps each of the eleven
  decisions to its spec anchor(s) and forcing vector(s), gated by
  `scripts/interpretation-registry-gate.py`. The four open corners (duplicate
  `attackId` rows; `assessedClasses` overlapping the gap maps; artifact-only
  multi-subject; and out-of-range artifact-row refs, already locked by
  `bad-724`) are recorded in `docs/interpretation-decisions-open.md`; the three
  genuine design calls among them are flagged for operator/spec resolution and
  deliberately left un-locked.
- `armedAt` zero UTC offset locked (decision 8 offset sub-case, a real rail bug).
  The spec says "RFC 3339 UTC" but both rails accepted a non-zero offset (e.g.
  `+05:00`) as a valid instant. Both rails now reject a non-zero offset; the spec
  pins `Z` or `+00:00`; new reject vector `bad-727-armedat-non-utc-offset`.
- Subject cardinality made unconditional (open corner C resolved). `subject` MUST
  contain exactly one entry on a statement of ANY basis; only the six
  binding-digest inputs stay substrate-scoped. Both rails previously enforced
  cardinality only under `hasSubstrateRows`, so an artifact-only two-subject
  statement was wrongly accepted. The spec text at L185-189 is split accordingly;
  new reject vector `bad-728-artifact-two-subjects` (`bad-607` keeps the substrate
  case). Registry decision 12.
- Duplicate `attackId` rows are now malformed (open corner A resolved). "One row
  per executed attack" is a well-formedness invariant; both rails detect a
  duplicate `attackId` across rows before the set-based coverage comparison
  (which silently collapsed it before) and emit `statement-malformed`. Spec
  paragraph at L495-508 gains the uniqueness sentence; new reject vector
  `bad-729-duplicate-attackid-rows`. Registry decision 13.
- Coverage sets pinned as a disjoint partition (open corner B resolved, the one
  editorial call; reversible at vetting). A class appears in exactly one of
  `assessedClasses`, `outOfScope`, `routedElsewhere`; a class in more than one is
  malformed. This was a live divergence (our rails reject overlap; the from-spec
  checker accepts it) that no vector exercised. Rails unchanged (both already
  reject via the disjoint-partition check); the spec text at L482-487 now matches
  them; new reject vector `bad-730-coverage-class-overlap`. Registry decision 14.
  With these three corners resolved, `interpretation-decisions.json` has no open
  corners remaining.

## suiteRevision 1 (first public release)

- Corpus: 125 vectors (34 accept, 91 reject) for the Adversarial Execution
  Evidence predicate v0.6, tracking in-toto/attestation#570 at commit `4a36b19`
  (which folds in the review revisions, including the BMP-only string profile
  and the optional arming-payload run-chaining members). `MANIFEST.json`
  enumerates every vector with its expected verdict, result, and code set.
- Each reject vector is broken exactly one way; each accept vector exercises a
  distinct valid shape.
- Notable coverage worth calling out for a reimplementer:
  - Canonicalization: a supplementary-plane `observationVocabulary.labels`
    entry (`bad-612-labels-non-bmp`, `vocabulary-not-canonical`) and a covering
    record payload whose member NAME carries a supplementary-plane code point
    (`bad-208-payload-member-non-bmp`, `payload-not-canonical`). Each stays
    byte-canonical under both the UTF-16 and the code-point member order, so the
    BMP-only rule is the single fault.
  - Type strictness: a caught row carrying `actualLayer` as a JSON number
    (`bad-506-actuallayer-json-number`, `statement-malformed`). A wrong-typed
    row member is a decode-layer fault, deliberately distinct from an absent
    member, so every rail rejects at the same altitude.
  - Run-chaining member syntax (`bad-718`/`bad-719`/`bad-720`,
    `arming-covers-nothing`): `aeeRunSeq` positive, `aeeChainScope` required
    whenever `aeeRunSeq` is present, and `aeePrevRunBinding` a lowercase 64-hex
    digest present exactly when `aeeRunSeq` exceeds 1. The genesis form is the
    accept vector `ok-034-arming-chain-genesis`.
  - Coverage partition: a whole manifest class left out of every coverage set
    with the result forced to pass (`bad-816-coverage-class-dropped`,
    `coverage-incomplete`), the class-granularity fail-open.
  - Base64 canonicality: a record payload re-encoded as non-canonical base64
    (`bad-817-payload-noncanonical-base64`, `record-undecodable`). The Go rail
    decodes with `base64.StdEncoding.Strict()` and the Python rail
    re-encode-compares, so both reject where a lenient decoder would accept.
