# VALID conformance vectors (ai-agent-action v0.1)

This directory is the conformance suite's `vectors-ai-agent-action/accept/`
layout, laid out the same way as `vectors/accept/` for the
adversarial-execution-evidence suite next to it.

Ground truth: in-toto/attestation#588, `spec/predicates/ai-agent-action.md`
at `639ec56`, type URI
`https://in-toto.io/attestation/ai-agent-action/v0.1`.

That commit is not an address. The pull request is opened from
`add-ai-agent-action-predicate` on the fork `elang2/attestation`, so the
commit was never in the review venue, and that branch has since been
rewritten past it: as of 2026-08-26 a plain clone of the review venue, of
this project's own fork, and of the head fork all exit 128 on it, while
each resolves its own HEAD. The commit is orphaned everywhere.

Nothing is lost, because the commit was never the pin. `../spec-vendored/`
carries the text itself, `MANIFEST.json` pins its sha256 as `specDigest`,
and `check_vectors.py` recomputes that digest on every run and refuses a
copy whose bytes moved. The bytes are the ground truth; the commit records
only where they came from.

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

Three members exist only to hold a boundary from the admissible side:
`ok-011` carries a valid surrogate pair in a VALUE, which the string rule
permits and an over-eager verifier rejects alongside the unpaired half;
`ok-012` carries 2^53 - 1, the largest value the safe-integer profile
admits; and `ok-013` carries extension member NAMES inside the BMP, where
UTF-16 code-unit order and code-point order agree.

`ok-011` and `ok-013` are the two halves of one distinction and are easy to
read as contradicting each other. They do not. A supplementary-plane
character is well formed everywhere and is admissible in value position,
which `ok-011` holds; it is inadmissible in member-name position, which
`bad-116` catches, because that is the only position JCS sorts.

The `appendix-b` family carries RFC 8785 Appendix B, Table 1: every row of it
that has a JSON representation, one vector each. They share `aia-c-16` and
they are the only members here whose claim is about how a number is written
rather than about a chain, a string or a bound.

They are shaped by `ok-007`. The safe-integer profile binds the fields the
chain hash covers, so an arbitrary double cannot go there; payloads are JCS
and admit floats, so that is where the number lives. Each statement therefore
carries the digest of the canonical payload and names its own bit pattern in
`toolName`, while `MANIFEST.json` carries the IEEE input as `ieee754` and the
text it must serialize to as `canonicalNumber`. Those two fields are where a
reader checks the row against the RFC.

`ok-014` and `ok-015` are the two IEEE patterns that share one JSON
representation, and their payload digests are equal by construction. Minus
zero serializing to `0` is the lossy step, and it is the row real
implementations disagree on. `check_vectors.py` recomputes each row from the
declared text rather than from the generator's serializer, so a generator
that agreed only with itself would not pass.

## Vectors (37)

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
| `ok-013-bmp-extension-member-names` | aia-c-15 | valid | strings: extension member names inside the BMP sort the same way under UTF-16 code units and under code points, so the record has one canonical form and one chain hash |
| `ok-014-appendix-b-zero` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 1. The IEEE 754 double 0000000000000000 is the JSON number 0, and no other text. Zero. |
| `ok-015-appendix-b-minus-zero` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 2. The IEEE 754 double 8000000000000000 is the JSON number 0, and no other text. Minus zero. |
| `ok-016-appendix-b-min-pos-number` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 3. The IEEE 754 double 0000000000000001 is the JSON number 5e-324, and no other text. Min pos number. |
| `ok-017-appendix-b-min-neg-number` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 4. The IEEE 754 double 8000000000000001 is the JSON number -5e-324, and no other text. Min neg number. |
| `ok-018-appendix-b-max-pos-number` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 5. The IEEE 754 double 7fefffffffffffff is the JSON number 1.7976931348623157e+308, and no other text. Max pos number. |
| `ok-019-appendix-b-max-neg-number` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 6. The IEEE 754 double ffefffffffffffff is the JSON number -1.7976931348623157e+308, and no other text. Max neg number. |
| `ok-020-appendix-b-max-pos-int` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 7. The IEEE 754 double 4340000000000000 is the JSON number 9007199254740992, and no other text. Max pos int. |
| `ok-021-appendix-b-max-neg-int` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 8. The IEEE 754 double c340000000000000 is the JSON number -9007199254740992, and no other text. Max neg int. |
| `ok-022-appendix-b-two-to-the-68` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 9. The IEEE 754 double 4430000000000000 is the JSON number 295147905179352830000, and no other text. ~2**68. |
| `ok-023-appendix-b-below-1e23` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 10. The IEEE 754 double 44b52d02c7e14af5 is the JSON number 9.999999999999997e+22, and no other text. |
| `ok-024-appendix-b-at-1e23` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 11. The IEEE 754 double 44b52d02c7e14af6 is the JSON number 1e+23, and no other text. |
| `ok-025-appendix-b-above-1e23` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 12. The IEEE 754 double 44b52d02c7e14af7 is the JSON number 1.0000000000000001e+23, and no other text. |
| `ok-026-appendix-b-below-1e21` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 13. The IEEE 754 double 444b1ae4d6e2ef4e is the JSON number 999999999999999700000, and no other text. |
| `ok-027-appendix-b-just-below-1e21` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 14. The IEEE 754 double 444b1ae4d6e2ef4f is the JSON number 999999999999999900000, and no other text. |
| `ok-028-appendix-b-at-1e21` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 15. The IEEE 754 double 444b1ae4d6e2ef50 is the JSON number 1e+21, and no other text. |
| `ok-029-appendix-b-below-1e-6` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 16. The IEEE 754 double 3eb0c6f7a0b5ed8c is the JSON number 9.999999999999997e-7, and no other text. |
| `ok-030-appendix-b-at-1e-6` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 17. The IEEE 754 double 3eb0c6f7a0b5ed8d is the JSON number 0.000001, and no other text. |
| `ok-031-appendix-b-ulp-minus-two` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 18. The IEEE 754 double 41b3de4355555553 is the JSON number 333333333.3333332, and no other text. |
| `ok-032-appendix-b-ulp-minus-one` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 19. The IEEE 754 double 41b3de4355555554 is the JSON number 333333333.33333325, and no other text. |
| `ok-033-appendix-b-ulp-centre` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 20. The IEEE 754 double 41b3de4355555555 is the JSON number 333333333.3333333, and no other text. |
| `ok-034-appendix-b-ulp-plus-one` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 21. The IEEE 754 double 41b3de4355555556 is the JSON number 333333333.3333334, and no other text. |
| `ok-035-appendix-b-ulp-plus-two` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 22. The IEEE 754 double 41b3de4355555557 is the JSON number 333333333.33333343, and no other text. |
| `ok-036-appendix-b-negative-small-fraction` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 23. The IEEE 754 double becbf647612f3696 is the JSON number -0.0000033333333333333333, and no other text. |
| `ok-037-appendix-b-round-to-even` | aia-c-16 | valid | number serialization: RFC 8785 Appendix B row 24. The IEEE 754 double 43143ff3c1cb0959 is the JSON number 1424953923781206.2, and no other text. Round to even. |
