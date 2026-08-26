# VALID conformance vectors (ai-agent-action v0.1)

This directory is the conformance suite's `vectors-ai-agent-action/accept/`
layout, laid out the same way as `vectors/accept/` for the
adversarial-execution-evidence suite next to it.

Ground truth: in-toto/attestation#588, `spec/predicates/ai-agent-action.md`
at `639ec56`, type URI
`https://in-toto.io/attestation/ai-agent-action/v0.1`.

That type URI does not resolve. The in-toto attestation catalog redirects
the URIs of vetted predicates whose specification is merged, and this
predicate is in review as the pull request named above, so a request for
the URI returns 404. The URI identifies the predicate type, and
dereferencing it is not part of verifying any vector here.

Every file is a complete in-toto Statement. A member whose claim is about
the hash chain carries a sidecar in `../records/<id>.jsonl`, the log lines
the chain hash is computed over, because that preimage is the underlying
gateway record rather than the Statement.

Regenerate byte-identically: `python3 ../gen_vectors.py`.
Self-check: `python3 ../check_vectors.py`.

## What an accept member claims

These bytes are valid under the canonicalization text this suite proposes
(`docs/ai-agent-action-canonicalization.md`), and where the member declares
a `chainHash` that value recomputes from the last line of its sidecar.

Every reject condition in the sibling directory has an accepting member
here carrying the same condition id. That pairing is enforced rather than
intended: `check_vectors.py` fails when a reject condition has no accepting
twin, because a corpus of rejections alone gives full marks to a verifier
that rejects everything, which is the one verifier that certifies nothing.

Two members exist only to hold a boundary from the admissible side:
`ok-011` carries a valid surrogate pair, which the string rule permits and
an over-eager verifier rejects alongside the unpaired half, and `ok-012`
carries 2^53 - 1, the largest value the safe-integer profile admits.

## Vectors (12)

| vector | conditions | expected | what it cites |
|---|---|---|---|
| `ok-001-canonical-chain-hash-integer-like-keys` | aia-c-1, aia-c-2 | valid | canonicalization: member ordering is JCS, never the host language's property order |
| `ok-002-canonical-chain-hash-non-ascii` | aia-c-3 | valid | canonicalization: JCS emits the character, never a \u escape |
| `ok-003-log-line-equals-canonical-bytes` | aia-c-4 | valid | canonicalization: the log line IS the canonical bytes, so the two readings of the preimage coincide |
| `ok-004-unique-members` | aia-c-5 | valid | canonicalization: I-JSON, no duplicate member at any depth |
| `ok-005-linear-chain-single-head` | aia-c-6, aia-c-7 | valid | chain shape: exactly one record carries any given previousHash |
| `ok-006-checkpoint-carries-chain-link` | aia-c-8 | valid | chain shape: every record type links through predicate.chain |
| `ok-007-float-in-content-payload-only` | aia-c-9 | valid | canonicalization: the safe-integer profile binds signed record fields; content payloads are JCS and admit floats |
| `ok-008-error-response-digest-over-error-member` | aia-c-10 | valid | content digest: a failed call digests the error member, named explicitly rather than left to the reader |
| `ok-009-previoushash-lowercase-64-hex` | aia-c-11 | valid | chain shape: previousHash is lowercase 64-hex or the literal genesis |
| `ok-010-extensions-depth-128` | aia-c-12 | valid | bounds: 128 is admissible; the counting rule is #570's |
| `ok-011-paired-surrogate-in-toolname` | aia-c-13 | valid | strings: the rule excludes an unpaired half, never a valid supplementary-plane character, so a verifier that rejects both is over-rejecting |
| `ok-012-largest-safe-integer-durationms` | aia-c-14 | valid | bounds: 2^53 - 1 is admissible, so the boundary is exercised from both sides rather than assumed |
