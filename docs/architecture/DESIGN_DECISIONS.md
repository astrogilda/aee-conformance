# Design decisions

Choices a reader might otherwise flag as duplication, complexity, or dead code.
Each one is deliberate, and this file records why.

## Two independent verifier rails (do NOT de-duplicate across languages)

The suite ships two full reference verifiers: the stdlib-only Go verifier
(`aee/`) and the Python reference rail (`packaging/run_vectors.py`). They
re-implement the same primitives -- RFC 8785 JCS canonicalization, DSSE PAE,
RFC 6962 Merkle, ed25519, and the gate logic -- independently, in different
languages.

This cross-language duplication is deliberate. When two independent
implementations agree byte for byte, that agreement is what lets the corpus act
as a conformance authority: a bug or shortcut in one rail gets caught by the
other, and collapsing them onto a shared core would throw that away. Duplication
_within_ a language is debt worth removing; the cross-rail kind should stay.

## The generators' own self-verifier (a producer-side second opinion)

`vectors/accept/gen_valid_vectors.py` carries its own `verify()` -- a third
independent implementation of the gate logic -- run at build time as producer-QA
over every vector it emits. It is distinct from the two consumer rails: it
checks the generator's output before the vector is committed. It is deliberately
independent and is not shared with the rails.

## Hand-rolled ed25519 in the Python rail (test keys only)

`packaging/run_vectors.py` contains a pure-Python RFC 8032 ed25519
implementation rather than importing `cryptography`. This is deliberate: the
Python rail's zero-dependency portability is what lets a relying party run it
out of process with nothing but a stdlib Python, which is part of the
conformance-authority story. The keys are TEST keys only (never production), the
implementation is validated against `cryptography` and covered by a
known-answer test, and non-constant-time execution is an accepted non-goal.

## Generator primitives are copied, not shared (a deliberate non-abstraction)

The two generators each define the trivial primitives `jcs`, the sha256 hex
helper, and `pae` (about seven lines total). These are NOT factored into a
shared module. The generators are self-contained standalone scripts run directly
(`python3 vectors/<dir>/gen_*.py`); introducing a shared module would add
import-path machinery to both for a handful of trivial lines, trading real
coupling for negligible de-duplication. Per the house code-style guidance, three
similar lines beat a premature abstraction. (The generators' Merkle helpers
additionally diverge on purpose: the reject generator carries deliberately-wrong
attack variants -- `merkle_root_no_domain`, `merkle_root_dup_pad` -- that must
not be unified with the correct root.)

## Accepted inherent complexity

Some functions exceed a conventional cyclomatic-complexity threshold because the
specification they implement is itself branch-heavy, not because of tangled
structure. These are algorithmic/orchestration complexity and are accepted.

Go verifier (measured with gocyclo):

| Function | Cyclo | Why it is inherent |
|---|---|---|
| `aee/validity.go` `checkSubstrateRow` | 37 | Per-row coverage: each observation kind (arming, sealed, examination, interception) has its own spec-mandated constraints, checked in one place. |
| `aee/statement.go` `Gate0` | 33 | Statement well-formedness enumerates every reserved-member and vocabulary rule the spec lists; the branch count is the rule count. |
| `aee/validity.go` `evaluateKind` | 24 | Type dispatch over the record kinds, each with a small kind-specific check. |
| `aee/statement.go` `gate0CoverageIntegrity` | 18 | The coverage-partition invariant across three disjoint sets against the manifest. |
| `aee/jcs.go` `decodeValue` | 18 | Recursive JSON value dispatch with the I-JSON profile checks. |

Python harness/generators: the functions carrying `# noqa: C901` are documented
individually in [`docs/complexity-rationales.toml`](../complexity-rationales.toml).

## The core is stdlib-only and go-witness-free

`aee/` imports nothing outside the Go standard library; `aee/imports_test.go`
enforces this at test time. The go-witness dependency lives only in the separate
`witnessattestor/` module, so a relying party can vendor the core verifier with
zero third-party supply-chain surface.
