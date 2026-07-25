<!--
Implementation report for the AEE v0.6 predicate conformance suite.
Corpus SSOT: vectors/MANIFEST.json (suiteRevision 2, 138 vectors: 35 accept, 103 reject).
Honest scoping: every claim below states exactly what each implementation was verified against.
Prerequisites for the two open columns are named, not glossed.
-->
# AEE v0.6 implementation report

A W3C-style "multiple independent interoperable implementations" report for the
Adversarial Execution Evidence predicate (in-toto/attestation PR #570). The
purpose is one claim, made honestly: the specification is determinate enough that
independent parties, in different languages, reach the same verdict on the same
bytes.

## Reference corpus

`vectors/MANIFEST.json`, suiteRevision 2: **138 vectors (35 accept, 103 reject)**.
Each accept vector must verify valid with its expected `result` token; each reject
vector must be invalid with a failure code drawn from the manifest's code set. The
corpus is regenerated deterministically from the generators and its vendored spec
digest is pinned and CI-checked (`scripts/spec-drift-gate.py`).

## Implementations

| Implementation | Language | Independence | Verified against | Result |
|---|---|---|---|---|
| Reference rail (`aee/`) | Go | first-party | reference corpus, suiteRevision 2 | **138 / 138** |
| Reference rail (`packaging/run_vectors.py`) | Python | first-party (independent decomposition) | reference corpus, suiteRevision 2 | **138 / 138** |
| `Rul1an/aee-checker` | Rust | **third-party, from-spec, no dependency on the reference impl** | corpus at suiteRevision 1 (spec `4a36b197`) | **125 / 125** (see note 1) |
| `@probity/verify` | TypeScript | first-party consumer rail | its vendored set (118 vectors) + cross-rail parity tests | pass (see note 2) |
| `probity-verify.py` | Python | first-party consumer rail (standalone) | its vendored set (118 vectors) + parity tests | pass (see note 2) |
| matchlock-mcp `_aee.py` | Python | first-party consumer rail | its vendored set (132 vectors) + parity tests | pass (see note 2) |

The two reference rails are independent decompositions (not shared code) and both
clear the full corpus. The Rust checker is the load-bearing independence result:
built from the spec text alone, its own I-JSON parser, RFC 8785 serializer, RFC
6962 Merkle root over DSSE PAE, run-binding derivation, and Ed25519 tier, with no
sight of the reference implementation and no reading of the corpus condition codes.

## Feature coverage

Two eras. The **core** predicate (through spec `4a36b197`) has three genuinely
independent implementations agreeing: the two reference rails and the from-spec
Rust checker. The **round-7** additions post-date the Rust checker's build, so they
are covered by the two reference rails plus the two consumer stacks (probity, mcp)
that were brought to parity.

| Feature | Go ref | Python ref | Rust (3rd-party) | probity | mcp |
|---|---|---|---|---|---|
| I-JSON / RFC 8785 canonical payloads | yes | yes | yes | yes | yes |
| RFC 6962 batch root over DSSE PAE | yes | yes | yes | yes | yes |
| `result` recompute (pass/degraded/fail) | yes | yes | yes | yes | yes |
| Evidence tier (declared/unattested/attested) | yes | yes | yes | yes | yes |
| The 11 interpretation decisions | yes | yes | yes | yes | yes |
| chain-scope machine-comparable array (round-7) | yes | yes | note 1 | yes | yes |
| statement-wide strict I-JSON (round-7, decision 11) | yes | yes | note 1 | yes | yes |
| read-first `aeeBindingVersion` (round-7) | yes | yes | note 1 | yes | yes |
| out-of-range refs fail-closed any row (round-7) | yes | yes | note 1 | yes | yes |
| `armedAt` zero UTC offset (round-7, decision 8) | yes | yes | note 1 | yes | yes |
| corners A/B/C: dup attackId / partition / cardinality | yes | yes | note 1 | yes | yes |

## Notes (the honest scoping)

1. **Rust checker is at suiteRevision 1 (spec `4a36b197`), pre-round-7.** Its
   125/125 is against the 125-vector corpus before the round-7 changes, so the
   round-7 rows are "not yet" for that column, not "fails". A re-run against
   suiteRevision 2 is invited in the round-7 reply; when it lands, this report gets
   a fourth fully-independent column on the round-7 features too.
2. **The consumer rails carry the round-7 rules but their vendored vector sets lag
   the reference corpus** (probity 118, mcp 132 vs the reference 138). The rules
   themselves are verified by cross-rail parity tests plus each rail's own suite
   and mutation checks; a full re-vendor of all 138 into probity and mcp is tracked
   as a follow-up. Until then, "pass" means the rail implements and is parity-tested
   on the rule, not that it replayed the full 138.

## What this report does NOT claim

Two independent implementations agreeing is strong evidence the text is
determinate; it is not proof it is unambiguous (both could share a reasonable but
unforced reading). The interpretation-decision registry
(`vectors/interpretation-decisions.json`) records where the text forces the reading
and locks each with a vector; three corners where it does not force the reading are
recorded, resolved in a stated direction, and marked reversible at vetting in
`docs/interpretation-decisions-open.md`. This report is a determinacy claim about
the corpus surface, not a security claim about any assessed artifact.
