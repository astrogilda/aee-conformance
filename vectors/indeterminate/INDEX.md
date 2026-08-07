# INDETERMINATE conformance vectors (adversarial-execution-evidence v0.6)

This directory is the conformance suite's `vectors/indeterminate/`
layout. It carries the statements on which the specification settles
the VERDICT and does not settle the CONDITION.

Ground truth: `spec/predicates/adversarial-execution-evidence.md` @
`237f83b` (in-toto/attestation PR #570 branch),
version 0.6.0, type URI
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

## What an indeterminate vector claims

The other two directories each make a claim every conformant verifier
has to satisfy identically: `accept/` says these bytes are valid and
recompute to a named result, `reject/` says they are invalid and a
conformant rail names a condition from a declared set. Neither can say
that the verdict is settled while the condition is not, and that is
exactly what the specification says about the statements here. It
carries no failure-code vocabulary of any kind, and of its own
two-stage verification description it says that "the sequencing
itself is informative" (L413-415). Two rails can therefore both
reject the same bytes and name different conditions, and the text is
equally happy with both.

Widening a reject vector's expected set to name both conditions does
not express this. The harness compares code SETS, so a widened set is
satisfied by either answer and by a rail that emits both, and the
vector stops measuring the question instead of starting to. The
difference between "either answer is conformant" and "a rail may
report a superset" would be invisible in the manifest, which is the
condition under which a divergence goes unnoticed for revisions.

So a member of this directory declares:

- a DETERMINED verdict. Indeterminacy is scoped to the condition and
  never to the verdict; a vector whose verdict is open would certify
  nothing at all.
- a set of READINGS, each naming the condition that reading predicts
  for this member. A family is the set of members sharing one reading
  vocabulary, and it is written so that the readings are separable by
  some member's answer; the generator refuses a family in which two
  declared readings predict the same condition on every member.

## What a rail must satisfy

1. **Verdict.** Every member's declared verdict, exactly as a reject
   vector's.
2. **Closure.** On each member, the rail's codes intersect the union
   of that member's predicted conditions. An answer no declared
   reading predicts is a failure and not a widening: the corpus then
   has an undeclared reading, and it is added by name, with its
   argument, never by relaxing the set.
3. **Coherence.** Across the whole family, the rail's answers are
   explained by ONE declared reading. Either answer is admissible; no
   answer is not, and neither is a pair of answers straddling two
   readings, because that is a rail whose reported condition turns on
   incidental structure rather than on a policy it applies.

The reference rails' reading is RECORDED, in the manifest and in the
harness report, and is not required of anybody. That is the whole
point: the corpus stops failing a from-spec rail for a non-defect and
starts saying which reading each rail took, which is the thing two
agreeing rails can never tell each other.

Regenerate byte-identically with:
`python3 ../reject/gen_invalid_vectors.py`. These vectors are built by
the reject generator because they are built the same way, from the
same parents,
the same derived keys and the same second-fault self-check; only the
claim their manifest entry makes differs.

## Vectors (2)

### Family `signature-count-vs-payload-decode`

| vector | parent | single mutation | conditions (aee-c ids) | reading `decode-first` | reading `positional` | reading `set-level` | spec |
|---|---|---|---|---|---|---|---|
| `ind-001-undecodable-then-signatures-empty` | ok-002 | arming record payload re-encoded as non-canonical base64 AND the sealed record's signatures array emptied, in that wire order | aee-c-91 | `record-undecodable` | `record-undecodable` | `record-signatures-empty` | L413-415; L1257-1259; L1259-1266 |
| `ind-002-signatures-empty-then-undecodable` | ok-002 | arming record's signatures array emptied AND the sealed record's payload re-encoded as non-canonical base64, in that wire order | aee-c-91 | `record-undecodable` | `record-signatures-empty` | `record-signatures-empty` | L413-415; L1257-1259; L1259-1266 |

## Notes on specific vectors

- **ind-001-undecodable-then-signatures-empty**: the member that separates the set-level reading from the other two. It is the statement suiteRevision 9 shipped as a reject vector pinning the set-level answer alone; the pin was this suite's registry rather than the specification's, and this directory is where that difference can be said out loud.
- **ind-002-signatures-empty-then-undecodable**: the member that separates the positional reading from decode-first, and the one that makes the family falsifiable: without it a rail that reports the later fault on one order and the earlier on the other is indistinguishable from a rail with a policy.

## What is NOT in here

The specification leaves other things open, and most of them cannot
be a vector. They divide four ways and only the first is admissible
here:

- **Two conformant answers to a question the harness observes.**
  This directory.
- **A limit rather than a choice.** "The set of attacks actually
  executed therefore remains a producer assertion under both
  shapes" (L513-528), and the shared-reference evidencing rule on
  a row declaring `paired`, of which the text says outright that
  "a conforming verifier neither can nor may invent an evidencing
  heuristic in its place" (L902-914). Every conformant verifier
  must ACCEPT those statements: nothing in the carried bytes can
  see the omission, so there is no divergence to declare. They are
  accept vectors, and their limit is prose. The same obligation on
  a row declaring `pinned` is not in this class: the corpus
  declares the expected commitment and the verifier compares, so a
  row that fails it is a reject vector.
- **Consumer policy the byte-pure surface does not carry.** A
  consumer MAY reject an attestation carrying `unattested` substrate
  rows (L1125-1128), MAY admit `pass_indirect` (L495-496), MAY
  coherence-check a row against the pinned posture (L1220-1224), MAY
  bound a key with a validity window (L1204). None of these moves the
  verdict this suite reads, because validity "is a function of
  carried bytes alone and holds identically for every consumer"
  (L1716-1719). A rail that answered the admission question in the
  verdict field would be wrong, not free.
- **Producer options.** `observationSelectors`, `aeeDropBound`, the
  descriptor members no rule reads, the optional run-chaining
  members. The producer chooses; the verifier's handling is forced,
  and accept vectors already carry it.

