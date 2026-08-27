# INVALID conformance vectors (ai-agent-action v0.1)

This directory is the conformance suite's `vectors-ai-agent-action/reject/`
layout, laid out the same way as `vectors/reject/` for the
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

## What a reject member claims

A conformant verifier rejects these bytes for exactly one declared reason.

The reason is declared under the canonicalization text this suite proposes,
NOT under #588 as it currently stands. That distinction is the whole point
of the directory. Each member was constructed by attacking the specification
text as written, and each one is constructible today precisely because no
rule in it forbids the construction. The attack harness that produced them
and the invariant each one breaks are recorded in the review comment the
suite was built for.

Four families:

- `bad-101` through `bad-104` are canonicalization divergences. The same
  logical record, serialized by a JavaScript, a Python and a Go gateway,
  yields three different chain hashes, and a log shipper that reparses
  yields a fourth. None of the three implementations has a bug.
- `bad-105` is a duplicate member: one record whose first-wins reading and
  whose committed hash describe different tool calls.
- `bad-106` and `bad-107` are chain-shape faults. `bad-106` is a fork, and
  it is the sharpest member here: two records share one `previousHash`, so
  every hash verifies, the genesis hash and therefore the subject digest
  are unchanged, and the presenter chooses which branch an auditor sees.
  `bad-107` chains past a checkpoint, leaving the anti-truncation record
  deletable.
- `bad-108` through `bad-115` are profile faults: a float in a signed field,
  a content digest over the wrong preimage for a failed call, a
  `previousHash` that is not canonical hex, a second genesis after a break,
  an unpaired surrogate, and the two sides of the depth and safe-integer
  bounds.
- `bad-116` is a sort-order divergence that JCS itself leaves open. Its
  record is well formed and every field is untouched; one `extensions`
  member name is a supplementary-plane character, so UTF-16 code-unit order
  and code-point order disagree about the canonical bytes and the record has
  two chain hashes. `bad-101` proves extension member names are chain-hash
  load-bearing by permuting them; this member shows the permutation cannot
  always be resolved, which is why the fix is to bound the character set
  rather than to restate the sort.

`bad-113` is already forbidden by #588's own text. It is here anyway,
because a rule with no vector is advice: the self-check in this suite
crashed on that member the first time it ran, which is what the member is
for.

## Vectors (16)

| vector | conditions | expected | what it cites |
|---|---|---|---|
| `bad-101-chain-hash-ecmascript-member-order` | aia-c-1 | invalid / chain-hash-mismatch | A1: JSON.stringify orders 2 before 10 and leaves zz before aa; JCS orders 10, 2, aa, zz. Three languages, three chain hashes. |
| `bad-102-chain-hash-ascii-escaped-string` | aia-c-3 | invalid / chain-hash-mismatch | A2: a producer whose serializer defaults to ASCII escaping emits different bytes for the same string |
| `bad-103-chain-hash-html-escaped-string` | aia-c-3 | invalid / chain-hash-mismatch | A2b: Go's encoding/json escapes <, > and & by default, so a Go gateway and a Node gateway disagree on identical input |
| `bad-104-log-line-not-canonical-bytes` | aia-c-4 | invalid / noncanonical-bytes | A3: the record parses identically and hashes differently; any log shipper that reserializes produces this |
| `bad-105-duplicate-member-toolname` | aia-c-5 | invalid / duplicate-member | A4: a first-wins reader displays read_file while the hash commits to delete_repository |
| `bad-106-chain-fork-shared-previoushash` | aia-c-6 | invalid / chain-fork | A5: two records carry one previousHash. Every hash verifies, the genesis hash and therefore the subject digest are unchanged, and the presenter chooses which branch the auditor sees. |
| `bad-107-checkpoint-omitted-from-chain` | aia-c-8 | invalid / checkpoint-not-linked | A6: the successor chains past the checkpoint to the record before it, so the checkpoint is deletable and the anti-truncation mechanism carries no weight |
| `bad-108-float-in-signed-record-field` | aia-c-9 | invalid / non-integer-in-signed-field | A7: the safe-integer profile binds signed record fields; the content-digest form is where a float belongs |
| `bad-109-error-response-digest-over-null` | aia-c-10 | invalid / content-digest-mismatch | A8: one of four readings a verifier could take of an absent result member, and the only one this suite forbids by naming the other |
| `bad-110-previoushash-uppercase-hex` | aia-c-11 | invalid / previoushash-not-canonical | A9: a case-normalizing verifier links it and a byte-comparing one does not, so the same logical link has two spellings |
| `bad-111-previoushash-wrong-length` | aia-c-11 | invalid / previoushash-not-canonical | A9b: 40 hex digits. Nothing in the current text excludes a digest from another algorithm |
| `bad-112-second-genesis-after-break` | aia-c-7 | invalid / duplicate-genesis | F3: the successor of a break restarts at genesis instead of chaining from the break, discarding the scar. #588 makes detection SHOULD; this member makes it MUST |
| `bad-113-unpaired-surrogate-in-toolname` | aia-c-13 | invalid / ill-formed-string | F2: already forbidden by #588's own text. The vector is what stops the rule from being advice |
| `bad-114-extensions-depth-129` | aia-c-12 | invalid / depth-exceeded | bounds: one level past the stated cap, so the counting rule is exercised rather than assumed |
| `bad-115-unsafe-integer-durationms` | aia-c-14 | invalid / unsafe-integer | bounds: 2^53 + 1, the first value the I-JSON profile excludes |
| `bad-116-astral-extension-member-name` | aia-c-15 | invalid / non-bmp-member-name | strings: U+1F680 is encoded UTF-16 as D83D DE80, so it sorts before U+FF3A by code unit and after it by code point. The record is well formed and every field is untouched; it has two canonical byte strings and therefore two chain hashes, so the successor's previousHash and the chain's subject digest both fork. |
