# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

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
