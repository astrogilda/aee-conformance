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

`vectors/MANIFEST.json`, suiteRevision 3: **140 vectors (35 accept, 105 reject)**.
Each accept vector must verify valid with its expected `result` token; each reject
vector must be invalid with a failure code drawn from the manifest's code set. The
corpus is regenerated deterministically from the generators and its vendored spec
digest is pinned and CI-checked (`scripts/spec-drift-gate.py`).

## Implementations

| Implementation | Language | Independence | Verified against | Result |
|---|---|---|---|---|
| Reference rail (`aee/`) | Go | first-party | reference corpus, suiteRevision 3 | **140 / 140** |
| Reference rail (`packaging/run_vectors.py`) | Python | first-party (independent decomposition) | reference corpus, suiteRevision 3 | **140 / 140** |
| `Rul1an/aee-checker` | Rust | **third-party, from-spec, no dependency on the reference impl** | suiteRevision 2 (138), spec-diff-led | **138 / 138** (132/138 unchanged; see note 1) |
| `@probity/verify` | TypeScript | first-party consumer rail | its vendored set (118 vectors) + cross-rail parity tests | pass (see note 2) |
| `probity-verify.py` | Python | first-party consumer rail (standalone) | its vendored set (118 vectors) + parity tests | pass (see note 2) |
| matchlock-mcp `_aee.py` | Python | first-party consumer rail | its vendored set (132 vectors) + parity tests | pass (see note 2) |

The two reference rails are independent decompositions (not shared code) and both
clear the full corpus. The Rust checker is the load-bearing independence result:
built from the spec text alone, its own I-JSON parser, RFC 8785 serializer, RFC
6962 Merkle root over DSSE PAE, run-binding derivation, and Ed25519 tier, with no
sight of the reference implementation and no reading of the corpus condition codes.

## Feature coverage

Two eras. The **core** predicate and the **round-7** additions now both have three
genuinely independent implementations agreeing: the two reference rails and the
from-spec Rust checker, which re-ran against the round-7 corpus (suiteRevision 2)
and reached 138/138 after a spec-diff-led update (132/138 on the unchanged build).
Only the **suiteRevision-3** reason-map vectors (`bad-731`/`bad-732`) post-date the
Rust checker's latest run; they are covered by the two reference rails plus the two
consumer stacks (probity, mcp).

| Feature | Go ref | Python ref | Rust (3rd-party) | probity | mcp |
|---|---|---|---|---|---|
| I-JSON / RFC 8785 canonical payloads | yes | yes | yes | yes | yes |
| RFC 6962 batch root over DSSE PAE | yes | yes | yes | yes | yes |
| `result` recompute (pass/degraded/fail) | yes | yes | yes | yes | yes |
| Evidence tier (declared/unattested/attested) | yes | yes | yes | yes | yes |
| The 11 interpretation decisions | yes | yes | yes | yes | yes |
| chain-scope machine-comparable array (round-7) | yes | yes | yes | yes | yes |
| statement-wide strict I-JSON (round-7, decision 11) | yes | yes | yes | yes | yes |
| read-first `aeeBindingVersion` (round-7) | yes | yes | yes | yes | yes |
| out-of-range refs fail-closed any row (round-7) | yes | yes | yes | yes | yes |
| `armedAt` zero UTC offset (round-7, decision 8) | yes | yes | yes | yes | yes |
| corners A/B/C: dup attackId / partition / cardinality | yes | yes | yes | yes | yes |

## Notes (the honest scoping)

1. **Rust checker re-ran against the round-7 corpus (suiteRevision 2, 138) and
   reached 138/138**, spec-diff-led: the unchanged pre-round-7 build scored 132/138,
   and the six diverging vectors were exactly the round-7 changes (two of which were
   defects in the checker, the rest spec-boundary adoptions). So the round-7 features
   now have a third fully-independent column. The author is explicit that this pass
   was not blind (the changelog was read before implementing), unlike the 125/125,
   and keeps all three run records with a content-digest provenance index. Only the
   suiteRevision-3 reason-map vectors (`bad-731`/`bad-732`) post-date this run.
2. **The consumer rails carry the round-7 rules but their vendored vector sets lag
   the reference corpus** (probity 118, mcp 132 vs the reference 140). The rules
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
