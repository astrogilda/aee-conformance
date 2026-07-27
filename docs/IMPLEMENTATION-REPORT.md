<!--
Implementation report for the AEE v0.6 predicate conformance suite.
Corpus SSOT: vectors/MANIFEST.json (suiteRevision 3, 140 vectors: 35 accept, 105 reject).
Honest scoping: every claim below states exactly what each implementation was verified against.
Independence is counted by authorship, not by implementation count; see "How independence
is counted here" before adding any row to the table.
-->
# AEE v0.6 implementation report

A W3C-style "multiple independent interoperable implementations" report for the
Adversarial Execution Evidence predicate (in-toto/attestation PR #570). The
purpose is one claim, made honestly: the specification is determinate enough that
a party who did not write it, working in a different language, reaches the same
verdict on the same bytes.

## How independence is counted here

Independence is a property of authorship, not of implementation count. Six
implementations clear this corpus and one author wrote five of them. Those five
share a single reading of RFC 8785 and RFC 7493, so when they agree they have
confirmed that the reading was transcribed consistently across five languages,
which is worth having and is not the claim this report exists to make. A
misreading of the text produces the same agreement.

**The count of implementations independent of the specification's author is one:**
`Rul1an/aee-checker`. Every determinacy claim below rests on that column and on
nothing else. The first-party rails appear because a conformance suite should
state what it actually runs, not to be counted toward independence.

A measured instance of why the distinction matters: the specification did not pin
a maximum JSON nesting depth, so all five first-party rails chose 128 and agreed
at every depth, while the independent checker read the same text and chose 256.
For the 127 depths between them, identical bytes are valid evidence to one
conformant verifier and malformed to another. No amount of first-party agreement
could have surfaced that; the outside implementation surfaced it immediately.

## Reference corpus

`vectors/MANIFEST.json`, suiteRevision 3: **140 vectors (35 accept, 105 reject)**.
Each accept vector must verify valid with its expected `result` token; each reject
vector must be invalid with a failure code drawn from the manifest's code set. The
corpus is regenerated deterministically from the generators and its vendored spec
digest is pinned and CI-checked (`scripts/spec-drift-gate.py`).

## Implementations

| Implementation | Language | Author | Verified against | Result |
|---|---|---|---|---|
| Reference rail (`aee/`) | Go | spec author | reference corpus, suiteRevision 3 | **140 / 140** |
| Reference rail (`packaging/run_vectors.py`) | Python | spec author | reference corpus, suiteRevision 3 | **140 / 140** |
| `Rul1an/aee-checker` | Rust | **independent, from-spec text alone** | suiteRevision 2 (138), spec-diff-led | **138 / 138** (132/138 unchanged; see note 1) |
| `@probity/verify` | TypeScript | spec author | its vendored set (118 vectors) + cross-rail parity tests | pass (see note 2) |
| `probity-verify.py` | Python | spec author | its vendored set (118 vectors) + parity tests | pass (see note 2) |
| matchlock-mcp `_aee.py` | Python | spec author | its vendored set (132 vectors) + parity tests | pass (see note 2) |

The five first-party rails are separate decompositions rather than shared code, so
they do catch each other's transcription errors, and the differential fuzzer over
them catches drift. What they cannot catch is a misreading of the specification,
because they inherit one. Read their agreement as a drift check, not as
corroboration.

The Rust checker is the load-bearing result: built from the spec text alone, with
its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root over DSSE PAE,
run-binding derivation, and Ed25519 tier, with no sight of the reference
implementation and no reading of the corpus condition codes.

## Feature coverage

Two eras. The **core** predicate and the **round-7** additions have both been read
independently: the from-spec Rust checker re-ran against the round-7 corpus
(suiteRevision 2) and reached 138/138 after a spec-diff-led update (132/138 on the
unchanged build). That is one independent reading of each era, corroborated by the
first-party rails rather than the other way round. Only the **suiteRevision-3**
reason-map vectors (`bad-731`/`bad-732`) post-date the Rust checker's latest run,
so those two rules currently have no independent reading at all and are covered by
first-party rails alone.

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

One independent implementation agreeing is strong evidence the text is
determinate; it is not proof it is unambiguous. Two readers can share a
reasonable but unforced reading, and a single outside reader is a sample of one.
Nor does agreement on 140 vectors say anything about the surface no vector
touches, which is where the nesting-depth divergence above lived. The
interpretation-decision registry
(`vectors/interpretation-decisions.json`) records where the text forces the reading
and locks each with a vector; three corners where it does not force the reading are
recorded, resolved in a stated direction, and marked reversible at vetting in
`docs/interpretation-decisions-open.md`. This report is a determinacy claim about
the corpus surface, not a security claim about any assessed artifact.
