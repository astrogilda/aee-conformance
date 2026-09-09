# Artifact-binding conformance corpus

Eight vectors for the contract in
[`spec/artifact-binding/v1.md`](../spec/artifact-binding/v1.md). Each member is a
complete trial directory with a signed binding record beside it, and each carries
the verdict an implementation must reach.

Run it:

```bash
python3 vectors-artifact-binding/check_vectors.py     # behaviour
python3 vectors-artifact-binding/gen_vectors.py       # regenerate, byte-identically
```

Both need `cryptography`, which this repository already declares for its vector
generators. The reference verification rail under `packaging/` is untouched by
this corpus and stays stdlib-only.

## Three verdicts, not two

Every other corpus here answers accept or reject. This one answers `verified`,
`failed` or `not-established`, and the third is the reason the corpus exists.
A record can be unreachable rather than wrong: a required artifact was never
captured, or a dependency was named and not covered. An implementation that
reports that as a pass admits an incomplete record; one that reports it as a
failure accuses a producer of tampering over a file nobody ever wrote. Two of
the eight members expect `not-established`, so an implementation that collapses
it into either neighbour scores zero on them rather than passing by accident.

The same structural rule the sibling corpora use applies here: a suite of
failures alone gives full marks to a verifier that refuses everything, so
`check_vectors.py` refuses a corpus with no passing member.

## The members

The four demonstration arms, and four conditions that are not arms:

| Condition | Verdict |
|---|---|
| intact archive, correct signer, every required role | `verified` |
| one byte changed in a covered artifact | `failed` |
| a required-role artifact absent | `not-established` |
| the same archive regraded by a changed verifier | `verified` |
| a record correctly signed by an unpinned key | `failed` |
| a valid signature over a non-canonical encoding | `failed` |
| a named dependency the record does not cover | `not-established` |
| an ATIF pointer that disagrees with the hashed document | `failed` |

`MANIFEST.json` carries the identifier, the case path, the expected verdict and
the codes for each, plus the published test key and a `corpusDigest` over the
entries.

## The key is published on purpose

`publicKey` in the manifest and `public.key` beside it are a TEST key whose seed
is in `gen_vectors.py`. A corpus a stranger cannot regenerate is a corpus they
have to trust, which is the opposite of what a conformance suite is for.
