# AEE v0.6 verification core + go-witness attestor

A recomputable execution attestation toolkit for the in-toto Adversarial
Execution Evidence predicate, version 0.6
(`https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`).

The predicate's model is execute-and-attest, not match-and-assert: the
consumer recomputes the outcome from carried bytes instead of trusting a
producer-asserted verdict. This tree is a second, independently usable
implementation of that contract: any future producer of the predicateType
can self-certify; any consumer can reject a lying emitter.

Spec line references throughout the code are to the predicate specification
at commit `e5ea1eb` (`spec/predicates/adversarial-execution-evidence.md`).

## Layout

```
go.mod                      core module (stdlib-only, enforced by test)
aee/                        the verification core
  statement.go              GATE 0: statement well-formedness
  validity.go               GATE 1: coverage validity (consumption precondition)
  recompute.go              pure result recompute
  tier.go                   GATE 2: evidence tier {declared|unattested|attested}
  runbinding.go             run-binding v1: exactly ONE construction, fail-closed on others
  merkle.go                 RFC 6962: domain-separated, recursive split, duplicate-reject
  pae.go                    DSSE PAEv1 + digest helpers
  jcs.go                    RFC 8785 canonicalization + RFC 7493 I-JSON checks (stdlib)
  types.go / codes.go       parsed statement model + the closed failure-code set
  *_test.go                 unit tests, known answers, the conformance-vector runner
aeetest/                    deterministic synthetic statement builder (derived TEST keys)
cmd/aee-verify/             consumer CLI: gate0 → gate1 → recompute → tier table
witnessattestor/            SEPARATE module: the go-witness attestor + library-mode demo
go.work.example             wiring for building the attestor module (see BUILD-NOTES.md)
```

## The verification pipeline

1. GATE 0: statement well-formedness. Statement `_type` and
   `predicateType` (fail-closed: exactly one accepted construction, no
   cross-version fallback), result vocabulary, environment members,
   vocabulary shape/subset/digest, corpus manifest digest and duplicate
   attack ids, coverage integrity at attack granularity, per-row
   `actualLayer` altitude, subject cardinality and digest canonicality for
   substrate-carrying statements, `runEntropy` presence, `issuedAt`.
2. GATE 1: coverage validity. Statement-level record checks run first
   (batchRoot presence/recompute over RFC 6962 with domain separation and
   no pad-last-node, duplicate-record rejection, orphaned-root), then per
   `basis: substrate` row: refs resolve and are in range, referenced
   payloads are canonical RFC 8785 + I-JSON `+json` objects carrying the
   reserved members with a run binding equal to the derived one,
   class-match per `aeeKind` with each kind's constraints (arming armedAt
   and posture, sealed still-armed/drop-bound/joint posture equalities,
   examination method), and the row `method` capped by the weakest signed
   `aeeMethod` across covering records. On any failure the attestation is
   invalid and its `result` is never consumed — the report carries no
   result and no tiers.
3. Recompute equality. The carried `result` must equal the pure recompute
   over carried bytes; the recompute reads no records, no signature
   outcomes, no consumer policy.
4. GATE 2: evidence tier. Per row: `declared` (artifact basis), `attested`
   (every covering record verifies against a consumer-pinned substrate
   observation key), else `unattested`. No pinned key means every
   substrate row is `unattested`; the substrate root is never inferred
   from the predicate. A record's `keyid` is a lookup hint, never the
   check, and the tier never alters `result`.

## The failure-code contract

Every rejection carries a stable machine-readable code (`aee/codes.go`).
The deterministic primary code (first in pinned detection order) is the
conformance contract; message text and code order beyond the primary one
are not. A few precedence pins matter to anyone reimplementing the gates.
A missing binding input reports its own member code
(`run-entropy-missing`, `subject-sha256-missing`), not
`run-binding-mismatch`; that code is reserved for values that can be
derived but come out unequal. `records-absent` fires when
`observationRecords` is missing entirely, and `ref-out-of-range` fires
only once records exist. The method cap reads covering records only, so
records that cover nothing do not participate, and the two sealed posture
equalities (pinned digest, arming record's claim) are enforced jointly,
not independently. Signature failure is never a failure code; it is a
tier outcome.

## Conformance vectors

`aee/vectors_test.go` replays the sibling conformance vector suite
(default `../../vectors`, override `AEE_VECTORS_DIR`): every accept vector
must verify valid with matching result and tier columns under both key
policies; every reject vector must be invalid with the primary code inside
the vector's expected code set, emitting no result and no tiers. The runner
skips with an explicit message when the suite is not yet present. The
pinned-policy key is derived from the published test-key recipe
(`seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`). Nothing
private is committed anywhere in this repository.

## The go-witness attestor (`witnessattestor/`)

A go-witness-compatible attestor package; upstream go-witness PR staged.
It follows the upstream sarif pattern: an attestor that runs after the
step's products exist, locates a substrate-emitted evidence statement
among them (`aee-evidence.json` by default), re-hashes it for integrity
against the recorded product digest, and then runs the emit seam (GATE 0
+ GATE 1 + recompute equality), returning an error rather than signing on
any failure. The signed predicate bytes are exactly the validated bytes.

The security scope, stated in the package documentation and binding on every
description of the attestor: the witness envelope key backs the
**producer-asserted plane only** (assembly, gate-validity,
recompute-consistency at pipeline step time), while the
**substrate-covered plane** travels exclusively in the signed
`observationRecords`, verified per record at the consumer's tier
derivation against consumer-pinned substrate observation keys. The
attestor never claims that go-witness observed the execution, and
go-witness's own `commandrun` tracing is never `basis: substrate`. GATE 2
never runs at emit, since the tier is relative to the consumer and
derived by definition; the optional `expect-substrate-key` producer-QA
flag checks record signatures locally and derives no tier.

`cmd/aee-witness-demo` drives the attestor through the real witness run
lifecycle as a library and prints the signed standalone AEE statement.
Consume-side, `cmd/aee-verify` (core module, stdlib-only) is the MVP; a
witness `VerifyRunType` attestor that re-emits gate outcomes as a signed
verification summary is named future work (the witness verify CLI is
currently coupled to its policy attestor).

## On independence

One author wrote both the Go core here and the sibling Python implementation, so they
catch each other's bugs but do not amount to an independent audit. A third
implementation from someone else is welcome: wiring one in is roughly a single
command against the runner's stdin/stdout contract, and a conformant checker
passes even when it evaluates in a different order, since the suite compares
verdicts and code sets and ignores both message text and evaluation order.
