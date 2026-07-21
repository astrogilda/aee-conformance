# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

## suiteRevision 1 (2026-07-21)

- Initial corpus: 116 vectors (33 accept, 83 reject) for the Adversarial
  Execution Evidence predicate v0.6, tracking in-toto/attestation#570 at commit
  `b5acaa5`.
- Each reject vector is broken exactly one way; each accept vector exercises a
  distinct valid shape. `MANIFEST.json` enumerates every vector with its
  expected verdict, result, and code set.
