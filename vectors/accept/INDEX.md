# AEE v0.6 conformance vectors: VALID (accept) set

Each file in this directory is a complete, unwrapped in-toto Statement (no outer DSSE) for
predicate type `https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`
that a conforming verifier MUST accept: the statement is well-formed, every
`basis: substrate` row satisfies the byte-checkable validity gate (refs resolve
and are in range, referenced records class-match, every covering payload is
canonical RFC 8785 / RFC 7493 `+json` carrying the reserved members with
`aeeRunBinding` equal to the binding derived from the statement, row `method`
capped by the weakest signed `aeeMethod`, `batchRoot` recomputes under RFC 6962),
and the carried `result` equals the recompute. Condition ids below are stable
`aee-c-NN` ids; the suite README maps them to spec line ranges at the pinned
spec commit. Verdict for all 34: **valid**; the per-row evidence tier
(attested / unattested / declared) is trust-relative and never alters validity
or `result`.

## Determinism recipe

Regenerate the set byte-identically with `python3 gen_valid_vectors.py`
(stdlib + `cryptography`). Committed files are UTF-8, LF, 2-space indent, JCS
(lexicographic) member ordering, standard base64 with padding.

Signing uses TEST keys (Ed25519/RFC 8032) whose seeds derive from published
constants: `seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`. Only the
PUBLIC halves are published, and because the derivation is open, these keys
are TEST-ONLY by construction; anyone can re-derive them. The
`substrate-observation-test` keyid is
`7e2b0652d86716f47e35573ae0082d670706b7a548dcb685df7bf103923dcb9c`, and the
`wrong-signer-test` keyid is
`a0667d352125206443e3005accb7223ef487f505d5fc3d392b629b6619177e0c`.

Timestamps are fixed at `issuedAt` 2026-01-01T00:00:00Z and `armedAt`
2025-12-31T23:59:00Z, the subject is `example-agent-bundle`, and attack ids
follow `XA-EXAMPLE-*` / `XB-EXAMPLE-*`. All digests derive from committed
synthetic one-line preimages (in `gen_valid_vectors.py`'s `PREIMAGES`): subject
`example-agent-bundle-content/v1`, substrate
`example-substrate-image-content/v1`, catch policy
`{"exampleCatchPolicy":{"mode":"enforce"}}`, network posture
`{"exampleNetworkPosture":{"posture":"sinkhole"}}`, run entropy
`example-run-start-checkpoint/v1`, and unchecked binding
`example-unchecked-binding/v1`. Corpus and vocabulary digests are JCS digests
of the embedded manifest and vocabulary objects.

## Construction checkpoint resolution (ok-017 / ok-030)

Pinned reading: "covering" records are the referenced records of the class(es)
the row's class-match rule requires; extra referenced records are
payload-checked but neither cap `method` nor gate the tier. Because
`examination` is method-pinned (`reconstructed`) and `interception` is the only
method-unconstrained kind, the min-composition accept half (ok-030) uses the
cross-kind mechanism: a reconstructed caught row referencing an examination
record (class cover) plus interception records signed `intercepted` and
`reconstructed`. The row's method equals the weakest signed `aeeMethod`
(`reconstructed`), so the vector is accepted under both the required-class and
the all-referenced covering readings, keeping it stable across the pending
tier-2 spec question.

## Vector index (one line per vector: which gate it exercises)

| vector | result | conditions (aee-c ids) | exercises |
|---|---|---|---|
| ok-001-caught-intercepted-fail | fail | aee-c-1, aee-c-3, aee-c-12, aee-c-28, aee-c-50 | canonical caught substrate/intercepted row covered by one interception record; single-leaf tree (root == leaf hash); producer layer name |
| ok-002-clean-pass-armed-sealed | pass | aee-c-7, aee-c-14, aee-c-26, aee-c-48, aee-c-63, aee-c-64, aee-c-65 | flagship clean row covered by arming + sealed (`aeeDropCount` 0), `actualLayer` "none", two-record tree |
| ok-003-clean-pass-bounded-drops | pass | aee-c-65 | sealed record with non-zero `aeeDropCount` 3 within self-declared `aeeDropBound` 5 still covers |
| ok-004-degraded-out-of-scope | degraded | aee-c-1, aee-c-6 | non-empty `coverage.outOfScope` forces recompute to `degraded` |
| ok-005-degraded-routed-elsewhere | degraded | aee-c-6 | non-empty `coverage.routedElsewhere` forces `degraded` |
| ok-006-clean-reconstructed | pass | aee-c-13, aee-c-66 | clean (substrate, reconstructed) row class-matched by an examination record |
| ok-007-artifact-only-recordless | pass | aee-c-31, aee-c-57 | artifact-only statement: no records, no `batchRoot`, no `runEntropy`; over-strictness discriminator |
| ok-008-artifact-fail-closed-method | fail | aee-c-5, aee-c-44 | artifact row with unknown `method` value fail-closes the row; carried `fail` recomputes; statement VALID |
| ok-009-artifact-oov-label-fail | fail | aee-c-4 | artifact row label outside carried `observationVocabulary.labels` fail-closes; VALID |
| ok-010-artifact-retired-basis-fail | fail | aee-c-43 | retired 0.4 `basis` value `substrate_observed` is out-of-vocabulary, no alias; fail-closed, VALID |
| ok-011-shared-run-records | pass | aee-c-15 | two clean rows legally share one arming + sealed record pair |
| ok-012-selectors-present | pass | aee-c-16 | `observationSelectors` positionally parallel to refs; advisory, result unchanged |
| ok-013-unknown-kind-extra-record | pass | aee-c-32, aee-c-71 | unrecognized `aeeKind` "aee-future-x" covers nothing, is ignored, still contributes its `batchRoot` leaf |
| ok-014-three-record-odd-split | fail | aee-c-26 | 3-leaf RFC 6962 recursive split (2+1), never duplicate-pad; parent of root-family rejects |
| ok-015-four-record-tree | fail | aee-c-26 | 4-leaf balanced RFC 6962 tree; two interceptions + arming + sealed |
| ok-016-caught-actuallayer-none | fail | aee-c-49 | caught row with `actualLayer` "none": observed-but-not-enforced (monitor-only vantage) |
| ok-017-method-weakening-allowed | fail | aee-c-23 | method cap is one-directional: reconstructed row referencing an intercepted-signed record is accepted |
| ok-018-aee-prefix-ignored | pass | aee-c-38, aee-c-61 | carried `evidenceTier` member and reserved-prefix `aeeInjected` member MUST be ignored |
| ok-019-wrong-keyid-sig-verifies | pass | aee-c-35 | keyid is a hint, never the check: garbage keyid on arming, ABSENT keyid on sealed, both sigs verify under the pinned key |
| ok-020-non-pae-signature | fail | aee-c-36 | record signed over raw payload bytes (no PAE): tier fault (row unattested), never a validity fault |
| ok-021-producer-extra-members | fail | aee-c-73 | covering payload with extra non-`aee` producer members still covers |
| ok-022-two-arming-records | pass | aee-c-68 | two independent arming records + one sealed; each referenced record independently satisfies class constraints |
| ok-023-no-tofu-embedded-key | pass | aee-c-34 | payload embeds a tempting public key; consumer MUST NOT TOFU; expected tier without out-of-band pin is unattested |
| ok-024-mixed-basis-rows | fail | aee-c-33, aee-c-41 | pinned three rows: substrate covered by the substrate test key (attested), substrate covered by the wrong-signer test key (unattested), artifact (declared); tierWithPinnedKey ["attested","unattested","declared"], tierWithoutKey ["unattested","unattested","declared"] |
| ok-025-does-not-assert-present | pass | aee-c-84 | `doesNotAssert` present: advisory, never required, ignored for result |
| ok-026-five-record-tree | fail | aee-c-26 | 5-leaf unbalanced RFC 6962 split (4+1): deep-split discriminator |
| ok-027-artifact-missing-method | fail | aee-c-5, aee-c-42, aee-c-44 | artifact row with `method` member ABSENT: absence == unknown, fail-closed; carried `fail`; VALID |
| ok-028-empty-caught-pass | pass | aee-c-3, aee-c-52 | `caught: []` edge: vacuously no caught rows; vocabulary digest over the empty-caught object |
| ok-029-artifact-with-records | pass | aee-c-24, aee-c-29, aee-c-30, aee-c-32 | artifact-only rows + 2 unreferenced records + CORRECT `batchRoot`; no substrate rows so no derived binding, and record `aeeRunBinding` values are unchecked bytes |
| ok-030-method-min-multirecord | fail | aee-c-23, aee-c-45 | min-composition accept half: row method `reconstructed` equals the weakest signed `aeeMethod` across three referenced records {reconstructed, intercepted, reconstructed}; pairs with the cap-exceeded reject |
| ok-031-caught-reconstructed | fail | aee-c-13 | caught (substrate, reconstructed) row class-matched by an examination record: class-match keys on method, not caught-ness |
| ok-032-method-inferred-retired | fail | aee-c-5, aee-c-43 | retired 0.4 `method` value `inferred` is out-of-vocabulary, fail-closed; VALID |
| ok-033-artifact-degraded | degraded | aee-c-6 | artifact-only recordless degraded statement: parent for coverage-family rejects with no digest/binding cascade |
| ok-034-arming-chain-genesis | pass | aee-c-89 | arming payload carrying the optional run-chaining members in genesis form (`aeeRunSeq` 1, `aeeChainScope` present, no `aeePrevRunBinding`): syntax-checked in the reserved-member walk, nothing else normative reads them, and the record still covers |

## Coverage notes

The result vocabulary spans `fail` (ok-001), `pass` (ok-002), and `degraded`
(ok-004); `doesNotAssert` appears only in ok-025. On the basis axis, the set
covers substrate (ok-001 family), artifact
(ok-007/008/009/027/029/032/033), retired/out-of-vocabulary (ok-010), and
mixed (ok-024) rows. The method axis covers intercepted (ok-001/002),
reconstructed (ok-006/017/030/031), absent (ok-027), unknown (ok-008), and
retired (ok-032). Record kinds exercised include interception, arming,
sealed, examination, and unknown-forward (ok-013), across trees of 1, 2, 3,
4, and 5 leaves. On the signature plane, the set exercises pinned-key
verifying (the default), wrong-signer-valid (ok-024), garbage/absent keyid
(ok-019), non-PAE (ok-020), and embedded-key bait (ok-023).

Every vector re-parses as JSON, regenerates byte-identically, and passes the
generator's built-in gate and recompute self-verifier (`python3
gen_valid_vectors.py` exits non-zero on any self-check failure).

All content is synthetic: producer vocabulary is spec-verbatim
(`policy.egress_sinkhole`, `none`, `sinkhole`, `egress_captured`, `no_egress`)
or obviously synthetic (`example*`, `XA-EXAMPLE-*`); payload type
`application/vnd.example.aee-observation.v1+json`; producer members are
content-free (`producerNote`, `extraA`). Nothing here derives from, or
describes, any real execution or production signing key.
