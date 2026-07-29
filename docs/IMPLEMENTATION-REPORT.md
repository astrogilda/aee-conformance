<!--
Implementation report for the AEE v0.6 predicate conformance suite.
Corpus SSOT: vectors/MANIFEST.json (suiteRevision 9, 158 vectors: 36 accept, 122 reject).
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
For the 127 depths between them, identical bytes were valid evidence to one
conformant verifier and malformed to another. No amount of first-party agreement
could have surfaced that; the outside implementation surfaced it immediately. The
bound is now normative at 128 and the checker adopted it (suiteRevision 5,
149/149). Reading it back also surfaced a second split the first-party rails hid
from each other: the reference Go rail charged nesting depth per parsed child, so
an empty-container leaf slipped one level past the bound while the Python rail
rejected it — our own two rails disagreeing on identical bytes at one exact depth,
fixed this round and now pinned by a boundary vector pair.

The same shape recurred at suiteRevision 9 and is worth recording, because it
says something about what a corpus can and cannot see. A newly landed condition
(a record's `signatures` member must carry at least one entry) had one vector,
that vector carried one fault, and every rail passed it. Two rails were
nonetheless answering differently: one asked the entry count per record inside
its payload-decode loop rather than once over the record set, so a statement
whose first record failed to decode and whose second carried no signature
reported a different condition there than everywhere else; and one decoded the
member into a typed list, so a member of the wrong JSON type reported the parse
catch-all instead of the condition. Neither divergence was reachable by a
single-fault vector or by a vector testing only the empty-array spelling, which
is the general lesson: a condition is under-tested until the corpus reaches every
spelling of it and fixes its precedence against the conditions it can collide
with. Both rails were corrected and both readings are now pinned.

## Reference corpus

`vectors/MANIFEST.json`, suiteRevision 9: **158 vectors (36 accept, 122 reject)**.
Each accept vector must verify valid with its expected `result` token; each reject
vector must be invalid with a failure code drawn from the manifest's code set. The
corpus is regenerated deterministically from the generators and its vendored spec
digest is pinned and CI-checked (`scripts/spec-drift-gate.py`).

## Implementations

| Implementation | Language | Author | Verified against | Result |
|---|---|---|---|---|
| Reference rail (`aee/`) | Go | spec author | reference corpus, suiteRevision 9 | **158 / 158** |
| Reference rail (`packaging/run_vectors.py`) | Python | spec author | reference corpus, suiteRevision 9 | **158 / 158** |
| `Rul1an/aee-checker` | Rust | **independent, from-spec text alone** | author-run suiteRevision 5 (149), 2026-07-28 (aee-checker#3); suiteRevisions 6 through 9 not run by its author | **149 / 149** at suiteRevision 5; suiteRevisions 6 through 9 not run by author (see note 1) |
| `ts-verify` | TypeScript | spec author | its vendored set (153 vectors) + cross-rail parity tests | pass (see note 2) |
| `py-verify` | Python | spec author | its vendored set (153 vectors) + parity tests | pass (see note 2) |
| MCP server rail `_aee.py` | Python | spec author | its vendored set (153 vectors) + parity tests | pass (see note 2) |

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
unchanged build), cleared the suiteRevision-3 corpus at 140/140, and then cleared
the **suiteRevision-5** byte-level tier (`bad-733` through `bad-741`) at 149/149
once it adopted the normative depth bound and moved its counter into the container
branch (aee-checker#3, 2026-07-28). That is one independent reading of each era so
far, corroborated by the first-party rails rather than the other way round. The
**suiteRevision-6** additions — the two depth-boundary vectors and the two
noncharacter vectors below — post-date that run, so those readings currently have
no independent confirmation and are covered by first-party rails alone; the
noncharacter pair in particular exercises a rule the checker's author has flagged
as not yet implemented on his side. The single **suiteRevision-7** addition
(`bad-745`, an observation record carrying zero `signatures` entries) and the two
**suiteRevision-8** additions (`bad-746` and `bad-747`, a corpus manifest
declaring no attack identifier in either of its two spellings) test requirements
the specification gained after that run, so they have no independent confirmation
either. The two **suiteRevision-9** additions (`bad-748` and `bad-749`) add no
requirement: they pin the precedence and the wrong-type spelling of the
signature-entry condition `bad-745` already carries, so they inherit that
vector's status.

| Feature | Go ref | Python ref | Rust (3rd-party) | TS rail | MCP rail |
|---|---|---|---|---|---|
| I-JSON / RFC 8785 canonical payloads | yes | yes | yes | yes | yes |
| RFC 6962 batch root over DSSE PAE | yes | yes | yes | yes | yes |
| `result` recompute (pass/degraded/fail) | yes | yes | yes | yes | yes |
| Evidence tier (declared/unattested/attested) | yes | yes | yes | yes | yes |
| The 17 interpretation decisions | yes | yes | 1–16 | yes | yes |
| chain-scope machine-comparable array (round-7) | yes | yes | yes | yes | yes |
| statement-wide strict I-JSON (round-7, decision 11) | yes | yes | yes | yes | yes |
| read-first `aeeBindingVersion` (round-7) | yes | yes | yes | yes | yes |
| out-of-range refs fail-closed any row (round-7) | yes | yes | yes | yes | yes |
| `armedAt` zero UTC offset (round-7, decision 8) | yes | yes | yes | yes | yes |
| corners A/B/C: dup attackId / partition / cardinality | yes | yes | yes | yes | yes |

## Notes (the honest scoping)

1. **The author's run history, each record content-digest-bound in his own
   provenance index.** A blind first run at suiteRevision 1 scored 125/125. At
   suiteRevision 2 the unchanged build scored 132/138 and a spec-diff-led update
   reached 138/138 — the six diverging vectors were exactly the round-7 changes (two
   of which were defects in the checker, the rest spec-boundary adoptions). At
   suiteRevision 3 the same build cleared 140/140. The author is explicit that every
   pass after the first was not blind (the changelog was read before implementing),
   unlike the 125/125.

   **His last author-run is suiteRevision 5 at 149/149 (2026-07-28, aee-checker#3).**
   The suiteRevision-5 vector `bad-741-payload-nesting-exceeds-max-depth` had pinned
   the nesting bound at 128 where his build read 256; he adopted 128 and, rather than
   only move the constant, moved his depth increment from per parsed value into the
   container branch, which is the counting rule the spec states next to the bound.
   **He has not run suiteRevision 6, 7, 8 or 9, so this
   report publishes no score for him at any of the four.** What we can say, in our own voice
   and not his: two of the four suiteRevision-6 vectors (`bad-743`, `bad-744`)
   require rejecting the Unicode
   noncharacters RFC 7493 section 2.1 forbids, and he has stated his checker does not
   yet implement that check, so we would expect it to answer valid where the
   reference rails answer invalid on those two — a rule difference we derived, not a
   run he produced, and not a score we will report as his. The other two are the
   depth-boundary pair his own container-branch fix already handles; the single
   suiteRevision-7 vector (`bad-745`) and the two suiteRevision-8 vectors
   (`bad-746`, `bad-747`) test requirements the specification gained after his last
   run, and the two suiteRevision-9 vectors (`bad-748`, `bad-749`) pin the
   precedence and the wrong-type spelling of the requirement `bad-745` carries.
   His suiteRevision-6 through suiteRevision-9 cells are "not run
   by author" until he posts a record and its source digest.
2. **The consumer rails carry the suiteRevision-6 corpus.** The TypeScript rail,
   the standalone Python rail and the MCP server rail each vendor all 153 vectors of
   suiteRevision 6 byte-for-byte (`VENDOR-STAMP.json` pins the source spec digest,
   upstream commit and a content digest; a consumer-side drift gate fails CI on any
   change without a re-vendor). "pass" means the rail implements the rule, is
   parity-tested on it, and replays the full 153. They have not yet re-vendored
   suiteRevision 7, 8 or 9, so `bad-745` and the signature-entry
   requirement it pins, `bad-746`/`bad-747` and the manifest floor they pin, and
   `bad-748`/`bad-749` and the precedence and wrong-type spelling they pin, are
   not yet exercised there. Each rail carries its own unit coverage of those
   rules in the meantime; the MCP server rail's placement fix at suiteRevision 9
   is pinned by a rail-local test rather than by the vector, precisely because
   the vendored copy has not caught up.

## What this report does NOT claim

One independent implementation agreeing is strong evidence the text is
determinate; it is not proof it is unambiguous. Two readers can share a
reasonable but unforced reading, and a single outside reader is a sample of one.
Nor does agreement on 158 vectors say anything about the surface no vector
touches, which is where the nesting-depth divergence above lived. The
interpretation-decision registry
(`vectors/interpretation-decisions.json`) records where the text forces the reading
and locks each with a vector; every decision it carries is now classified `forced`
and its open-corner list is empty. The three corners that were once open — duplicate
`attackId`, subject cardinality, and the coverage partition — are each resolved into
a forced decision with a forcing vector; the coverage partition is the single
editorial call kept reversible at vetting, with the audit trail in
`docs/interpretation-decisions-open.md`. This report is a determinacy claim about
the corpus surface, not a security claim about any assessed artifact.
