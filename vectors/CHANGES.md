# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

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
  coverage-partition membership rule already carried by the spec (L381-383): the
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
  statement was wrongly accepted. The spec text at L122-126 is split accordingly;
  new reject vector `bad-728-artifact-two-subjects` (`bad-607` keeps the substrate
  case). Registry decision 12.
- Duplicate `attackId` rows are now malformed (open corner A resolved). "One row
  per executed attack" is a well-formedness invariant; both rails detect a
  duplicate `attackId` across rows before the set-based coverage comparison
  (which silently collapsed it before) and emit `statement-malformed`. Spec
  paragraph at L385-398 gains the uniqueness sentence; new reject vector
  `bad-729-duplicate-attackid-rows`. Registry decision 13.
- Coverage sets pinned as a disjoint partition (open corner B resolved, the one
  editorial call; reversible at vetting). A class appears in exactly one of
  `assessedClasses`, `outOfScope`, `routedElsewhere`; a class in more than one is
  malformed. This was a live divergence (our rails reject overlap; the from-spec
  checker accepts it) that no vector exercised. Rails unchanged (both already
  reject via the disjoint-partition check); the spec text at L376-381 now matches
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
