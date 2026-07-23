# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

## suiteRevision 3 (2026-07-23)

- Corpus: 125 vectors (34 accept, 91 reject), tracking the predicate
  specification's review revisions at in-toto/attestation#570 commit
  `7de6055` (the BMP-only string profile and the optional arming-payload
  run-chaining members) on top of the `b5acaa5` baseline.
- New accept vector:
  - `ok-034-arming-chain-genesis`: an arming payload carrying the optional
    run-chaining members in genesis form (`aeeRunSeq` 1, `aeeChainScope`
    present, no `aeePrevRunBinding`). The members are syntax-checked in the
    reserved-member walk and nothing else normative reads them.
- New reject vectors:
  - `bad-612-labels-non-bmp` (`vocabulary-not-canonical`): a
    supplementary-plane `observationVocabulary.labels` entry, with the
    digest recomputed and sortedness intact under both the UTF-16 and the
    code-point order, so the BMP-only rule is the single fault.
  - `bad-208-payload-member-non-bmp` (`payload-not-canonical`): a covering
    record payload member whose NAME carries a supplementary-plane code
    point; the payload stays byte-canonical under both member orders, so
    the name itself is the single fault and the payload covers nothing.
  - `bad-506-actuallayer-json-number` (`statement-malformed`): a caught row
    carrying `actualLayer` as a JSON number. Type-strictness pin: a
    wrong-typed row member is a decode-layer fault, deliberately distinct
    from an absent member, so every rail must reject at the same altitude.
  - `bad-718-chain-runseq-zero`, `bad-719-chain-missing-scope`,
    `bad-720-chain-prev-not-hex` (`arming-covers-nothing`): the
    run-chaining member syntax — `aeeRunSeq` positive, `aeeChainScope`
    required whenever `aeeRunSeq` is present, `aeePrevRunBinding` a
    lowercase 64-hex digest present exactly when `aeeRunSeq` exceeds 1.

## suiteRevision 2 (2026-07-21)

- Corpus: 118 vectors (33 accept, 85 reject). Two reject vectors graduated from
  divergences found while hardening the reference rails:
  - `bad-816-coverage-class-dropped` (`coverage-incomplete`): a whole manifest
    class left out of all three coverage sets with the result forced to pass --
    the class-granularity coverage-partition fail-open.
  - `bad-817-payload-noncanonical-base64` (`record-undecodable`): a record
    payload re-encoded as non-canonical base64. The Go rail decodes with
    `base64.StdEncoding.Strict()` and the Python rail re-encode-compares, so
    both reject; a lenient decoder would accept.

## suiteRevision 1 (2026-07-21)

- Initial corpus: 116 vectors (33 accept, 83 reject) for the Adversarial
  Execution Evidence predicate v0.6, tracking in-toto/attestation#570 at commit
  `b5acaa5`.
- Each reject vector is broken exactly one way; each accept vector exercises a
  distinct valid shape. `MANIFEST.json` enumerates every vector with its
  expected verdict, result, and code set.
