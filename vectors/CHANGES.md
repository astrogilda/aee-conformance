# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

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
