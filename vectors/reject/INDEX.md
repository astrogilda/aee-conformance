# INVALID conformance vectors — adversarial-execution-evidence v0.6

This directory is the conformance suite's `vectors/reject/` layout.

Ground truth: `spec/predicates/adversarial-execution-evidence.md` @
`b5acaa5` (in-toto/attestation PR #570 branch), version 0.6.0, type URI
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`.
All `Lnnn` anchors below are line refs into that file at that commit.

Every file is a COMPLETE in-toto Statement (UNWRAPPED — no outer DSSE;
the inner `observationRecords` carry real DSSE signatures) that a
conforming verifier MUST reject for exactly ONE declared reason. Each is
derived from a fully-valid parent statement by ONE mutation plus its
declared rederive chain, so no second fault exists; the generator's
self-check asserts second-fault ABSENCE (root recomputes, vocabulary and
corpus digests verify, record bindings equal the derived binding, every
signature verifies, result recompute matches) for every vector whose
declared conditions do not target that commitment, and full gate
validity for every parent. Regenerate byte-identically with:
`python3 gen_invalid_vectors.py`.

## Determinism recipe

- Test signing key (Ed25519/RFC 8032), seed DERIVED, never stored:
  `seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`, role
  `substrate-observation-test` for every record signature in this set.
  - public key (hex): `496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62`
  - keyid = SHA-256 of the raw public key: `7e2b0652d86716f47e35573ae0082d670706b7a548dcb685df7bf103923dcb9c`
  - `keyid` is an unauthenticated hint, never the check (spec L678-680).
- Fixed timestamps: `issuedAt: 2026-01-01T00:00:00Z`, `armedAt: 2025-12-31T23:59:00Z`
  (a later `armedAt` appears only in bad-702).
- Record `payloadType`: `application/vnd.example.aee-observation.v1+json`.
- Subject `example-agent-bundle`; attack ids `XA-EXAMPLE-*`,
  `XB-EXAMPLE-*`; producer label/layer vocabulary is spec-verbatim
  (`egress_captured`, `no_egress`, `sinkhole`,
  `policy.egress_sinkhole`, `none`) or obviously synthetic
  (`example_label_a`, `example.method-x`).
- Committed files: UTF-8, LF, 2-space indent, lexicographic member
  order, std base64 with padding. For bad-201/202/203 the FAULT is a
  serialization property of the record payload bytes; those exact bytes
  travel base64-encoded, so the statement files themselves remain
  ordinary JSON and byte-replay is preserved (MANIFEST `rawBytes`).

## Derived digest preimages (all synthetic one-liners)

| digest | preimage |
|---|---|
| `f31821ae3e1d6e0611dc4d753e8f4c0232ad03df1f4bd32aa47b9cd4107fe3bf` | `sha256("example-intercepted-bytes/v1")` |
| `c39e2582a5ff1bc8a84718fd6115c847808668b962c1bcd07e263bf688cc6f72` | `sha256("example-intercepted-bytes/v2")` |
| `81c6e914fe332c0a08a53c43fe0e6fa5d0e5fde533bb03ab664e3d924e8bf829` | `sha256("example-orphan-root/v1")` |
| `cca32c26b70e238a58249962a8da351bd8acc047b638276b3503c05bf3c6499e` | `sha256("example-other-posture-config/v1")` |
| `bd34c306e2295a4974787aa2b81e7e95c37580d543cbc47f0b77a026aef7e051` | `sha256("example-run-start-entropy/v1")` |
| `1821aa6ff38428b2bf7ea727903b6d82768ea55dc24d4435890adcfe5fd0cea5` | `sha256("example-stale-corpus/v1")` |
| `1cdb63348f9249f7dfafdc0f052d6610dbf824efa4f0b3839f4a4418807ae587` | `sha256("example-stale-vocabulary/v1")` |
| `d14fbbcd076c6bfe5e6aa52b169c0baf7f7044ea46fe279afd7629e92baac8fc` | `sha256("example-agent-bundle-content/v1")` |
| `cba949a58d23fdd49bf37f2f1195c926fec35d22f545c949c0c56df943c67794` | `sha256("example-agent-bundle-b-content/v1")` |
| `018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb` | `sha256("example-substrate-image-content/v1")` |
| `4059bcf11682791da4726dca755cac73fa3ea61f492a3b37753504d6c5f71692` | `sha256("example-unchecked-binding-bytes/v1")` |
| `28f8fb978cae8aabc974e6557a3665523281bfd85fcee13429179120ad7667cc` | `sha256(JCS({"example": "catch-policy", "mode": "enforcing"}))` |
| `ba44e77b7861b9b7c5a7288b3d703a62289fb02b3a3e0f5612a4e74dbee0929e` | `sha256(JCS({"example": "posture-config", "posture": "sinkhole"}))` |

Corpus and vocabulary digests are JCS digests of the manifest and
`{"caught": [...], "labels": [...]}` objects embedded in each vector.
Run bindings derive per spec L72-78 from each statement's own values.
Negative known-answer for bad-303 — the v2 pre-image that MUST NOT
match (JCS, then SHA-256):

```json
{
  "aeeBindingVersion": "2",
  "catchPolicy": "28f8fb978cae8aabc974e6557a3665523281bfd85fcee13429179120ad7667cc",
  "corpus": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
  "networkPosture": "ba44e77b7861b9b7c5a7288b3d703a62289fb02b3a3e0f5612a4e74dbee0929e",
  "runEntropy": "bd34c306e2295a4974787aa2b81e7e95c37580d543cbc47f0b77a026aef7e051",
  "subject": "d14fbbcd076c6bfe5e6aa52b169c0baf7f7044ea46fe279afd7629e92baac8fc",
  "substrate": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb"
}
```

## Conditions referenced (aee-c ids)

Stable condition ids used by this suite; the conformance-repo README
carries the authoritative id-to-spec-line table.

| id | spec anchor | condition |
|---|---|---|
| aee-c-1 | L222 | closed lowercase result vocabulary |
| aee-c-2 | L182-185 | result must equal the recompute |
| aee-c-4 | L226-227 | fail-closed on out-of-vocabulary label |
| aee-c-5 | L227-228 | fail-closed on missing/out-of-vocab basis or method |
| aee-c-6 | L228-229 | degraded iff disclosed coverage gap |
| aee-c-10 | L240 | observationRefs non-empty on substrate rows |
| aee-c-11 | L240-241 | every ref index in range (integer) |
| aee-c-12 | L242-244 | caught intercepted row refs an interception record |
| aee-c-13 | L244-245 | reconstructed row refs an examination record |
| aee-c-14 | L245-248 | clean intercepted row refs arming AND covering sealed |
| aee-c-17 | L249-250 | covering payload is canonical RFC 8785 |
| aee-c-18 | L578-579 | covering payload is valid I-JSON (RFC 7493) |
| aee-c-19 | L580-581 | covering media type ends in +json |
| aee-c-20 | L250-251 | covering payload carries the reserved aee members |
| aee-c-22 | L251-252 | aeeRunBinding equals the derived run binding |
| aee-c-23 | L253-254 | row method capped by weakest signed aeeMethod |
| aee-c-24 | L627 | batchRoot required when records exist |
| aee-c-25 | L629-632 | RFC 6962 domain-separated hashing |
| aee-c-26 | L632-634 | RFC 6962 recursive split, never duplicate-pad |
| aee-c-27 | L634 | leaves in array order |
| aee-c-29 | L636-637 | duplicate byte-identical records invalid |
| aee-c-30 | L639-641 | batchRoot must recompute |
| aee-c-31 | L644-648 | batchRoot omitted exactly when records absent |
| aee-c-42 | L390-392 | method required, closed {intercepted, reconstructed} |
| aee-c-44 | L267-271 | fail-closed substrate row invalidates; artifact row stays a valid fail |
| aee-c-45 | L401-407 | weakest-input method composition |
| aee-c-47 | L541-549 | missing actualLayer = malformed statement, not fail |
| aee-c-48 | L550-555 | clean row actualLayer is the literal none |
| aee-c-51 | L301-307 | observationVocabulary required |
| aee-c-52 | L305-306 | caught is a subset of labels |
| aee-c-53 | L306 | vocabulary arrays sorted ascending, no duplicates |
| aee-c-54 | L306-307 | vocabulary digest is JCS of {caught, labels} |
| aee-c-57 | L311-313 | runEntropy required with any substrate row |
| aee-c-58 | L82 | exactly one subject on substrate-carrying statements |
| aee-c-59 | L82-86 | binding digest inputs lowercase 64-hex sha256 |
| aee-c-60 | L72-78 | binding pre-image construction |
| aee-c-62 | L91-98 | binding is anti-splice |
| aee-c-63 | L586-591 | arming record kind constraints |
| aee-c-64 | L591-596 | sealed record required members |
| aee-c-65 | L605-611 | sealed covering conditions |
| aee-c-66 | L596-598 | examination signed aeeMethod reconstructed |
| aee-c-68 | L505-506 | each referenced record independently satisfies its class constraints |
| aee-c-71 | L614-618 | unknown aeeKind covers nothing |
| aee-c-75 | L98-102 | fail-closed on unimplemented binding version |
| aee-c-77 | L3; L125 | statement _type and predicateType URIs |
| aee-c-78 | L290-313 | observationEnvironment required members |
| aee-c-79 | L294-297 | corpus digest re-derives from embedded manifest |
| aee-c-80 | L296-297 | attackId under at most one manifest class |
| aee-c-81 | L329 | row attackId appears in the manifest |
| aee-c-82 | L350-353 | coverage exactly equals the manifest at attack granularity |
| aee-c-83 | L318-322 | coverage member required |
| aee-c-84 | L650-660 | doesNotAssert single canonical spelling |
| aee-c-85 | L662-664 | issuedAt required, RFC 3339 |

## Vectors (83)

`parent` names the accept-suite shape the vector derives from (the
accept vectors land separately; the parent statements are built
in-memory by the generator and asserted fully valid before mutation).
`rederive` lists the derived commitments recomputed after the mutation
so the declared fault stays the ONLY fault.

| vector | parent | single mutation | rederive | conditions (aee-c ids) | expected rejection | spec |
|---|---|---|---|---|---|---|
| `bad-001-result-uppercase` | ok-002 | result: "PASS" | — | aee-c-1 aee-c-2 | `result-vocabulary`, `result-recompute-mismatch` (COMPOUND) | L222; L182-185 |
| `bad-002-result-mismatch-caught` | ok-001 | carried result: "pass" over a caught row (recompute: fail) | — | aee-c-2 | `result-recompute-mismatch` | L182-185; L224-226 |
| `bad-003-result-mismatch-oov-label` | ok-009 | carried result: "pass" over a fail-closed out-of-vocabulary label | — | aee-c-2 aee-c-4 | `result-recompute-mismatch` | L226-227 |
| `bad-004-result-mismatch-failclosed` | ok-008 | carried result: "pass" over a fail-closed unknown method row | — | aee-c-2 aee-c-5 | `result-recompute-mismatch` | L227-228 |
| `bad-005-result-mismatch-coverage-gap` | ok-004 | carried result: "pass" with a non-empty coverage.outOfScope | — | aee-c-2 aee-c-6 | `result-recompute-mismatch` | L228-229 |
| `bad-006-result-fail-on-pass` | ok-002 | carried result: "fail" where the recompute derives pass | — | aee-c-2 | `result-recompute-mismatch` | L182-185 |
| `bad-007-result-degraded-on-pass` | ok-002 | carried result: "degraded" where the recompute derives pass | — | aee-c-2 | `result-recompute-mismatch` | L182-185 |
| `bad-008-result-unknown-token` | ok-002 | result: "error" | — | aee-c-1 aee-c-2 | `result-vocabulary`, `result-recompute-mismatch` (COMPOUND) | L222 |
| `bad-101-refs-empty` | ok-001 | caught substrate row observationRefs: [] | — | aee-c-10 aee-c-12 | `refs-empty`, `caught-row-uncovered` (COMPOUND) | L240; L242-244 |
| `bad-102-ref-out-of-range` | ok-001 | observationRefs: [0, 7] with one record (valid cover kept) | — | aee-c-11 | `ref-out-of-range` | L240-241 |
| `bad-103-ref-negative` | ok-001 | observationRefs: [0, -1] | — | aee-c-11 | `ref-malformed` | L240-241 |
| `bad-104-caught-refs-arming-only` | ok-001 | append a fully-valid arming record; caught intercepted row refs only it | recompute-batch-root | aee-c-12 | `caught-row-uncovered` | L242-244 |
| `bad-105-reconstructed-refs-interception` | ok-006 | append a fully-valid interception record; reconstructed row refs only it | recompute-batch-root | aee-c-13 | `reconstructed-row-uncovered` | L244-245 |
| `bad-106-clean-missing-sealed` | ok-002 | clean row refs the arming record only | — | aee-c-14 | `clean-row-uncovered` | L245-248 |
| `bad-107-clean-missing-arming` | ok-002 | clean row refs the sealed record only | — | aee-c-14 | `clean-row-uncovered` | L245-248 |
| `bad-108-ref-non-integer` | ok-001 | observationRefs: [0, 1.5] | — | aee-c-11 | `ref-malformed` | L240-241 |
| `bad-201-payload-unsorted-keys` | ok-001 | covering payload re-serialized with reverse-sorted member order | re-sign-record, recompute-batch-root | aee-c-17 | `payload-not-canonical` | L249-250; L576-580 |
| `bad-202-payload-bignum` | ok-001 | covering payload gains an integer member 2^53+1 | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L578-579; L67-70 |
| `bad-203-payload-duplicate-member` | ok-001 | byte-crafted duplicate aeeMethod member in the covering payload | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L578-579 |
| `bad-204-payload-media-type` | ok-001 | covering record payloadType: "application/octet-stream" | re-sign-record, recompute-batch-root | aee-c-19 | `payload-media-type` | L580-581 |
| `bad-205-payload-missing-runbinding` | ok-001 | drop aeeRunBinding from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L250-251; L581-585 |
| `bad-206-payload-missing-kind` | ok-001 | drop aeeKind from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L250-251; L585-599 |
| `bad-207-payload-missing-method` | ok-001 | drop aeeMethod from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L250-251; L599-601 |
| `bad-301-run-binding-splice` | ok-002 | records signed under a binding derived from a DIFFERENT corpus digest (cross-run splice) | recompute-batch-root | aee-c-22 aee-c-62 | `run-binding-mismatch` | L251-252; L88-93 |
| `bad-302-method-inflation` | ok-001 | row method "intercepted"; sole covering record signed "reconstructed" | re-sign-record, recompute-batch-root | aee-c-23 | `method-cap-exceeded` | L253-254 |
| `bad-303-binding-version-2` | ok-002 | records signed with a binding derived from an "aeeBindingVersion": "2" pre-image | derive-binding-v2, re-sign-record, recompute-batch-root | aee-c-75 aee-c-22 | `run-binding-mismatch` | L98-102; L251-252 |
| `bad-304-method-cap-multirecord` | ok-030 | row method "intercepted" covered by TWO interceptions with signed methods {intercepted, reconstructed}: exceeds the weakest | re-sign-record, recompute-batch-root | aee-c-23 aee-c-45 | `method-cap-exceeded` | L253-254 |
| `bad-401-records-no-batchroot` | ok-002 | batchRoot member removed while observationRecords is non-empty | — | aee-c-24 | `batch-root-missing` | L627; L639-641 |
| `bad-402-root-no-domain-separation` | ok-014 | root computed without the 0x00/0x01 domain-separation prefixes | — | aee-c-25 | `batch-root-mismatch` | L629-632 |
| `bad-403-root-bitcoin-padding` | ok-014 | 3-leaf root computed by duplicate-last-leaf padding instead of the RFC 6962 recursive split | — | aee-c-26 | `batch-root-mismatch` | L632-634 |
| `bad-404-root-leaf-order-swapped` | ok-014 | root computed over leaves in swapped order | — | aee-c-27 | `batch-root-mismatch` | L634 |
| `bad-405-duplicate-records` | ok-002 | two byte-identical records in the tree; root recomputes CORRECTLY over all three leaves | recompute-batch-root | aee-c-29 | `duplicate-record` | L636-637 |
| `bad-406-root-hex-tamper` | ok-002 | one hex digit of batchRoot flipped | — | aee-c-30 | `batch-root-mismatch` | L639-641 |
| `bad-407-substrate-row-no-records` | ok-001 | remove observationRecords AND batchRoot under a substrate row (2-op mutation) | — | aee-c-31 aee-c-11 | `records-absent`, `ref-out-of-range` (COMPOUND) | L644-648; L240-241 |
| `bad-408-batchroot-without-records` | ok-007 | orphan batchRoot added to a recordless artifact-only statement | — | aee-c-31 | `batch-root-orphaned` | L644-648; L635 |
| `bad-409-artifact-records-bad-root` | ok-029 | one hex digit off on an artifact-only-with-records statement | — | aee-c-30 aee-c-24 | `batch-root-mismatch` | L639-641 |
| `bad-501-substrate-unknown-method` | ok-001 | substrate row method: "example.method-x" (unknown value); refs, records, root, entropy intact; carried fail kept | — | aee-c-44 aee-c-5 aee-c-42 | `fail-closed-substrate-row` | L267-271; L424-427 |
| `bad-502-missing-actual-layer` | ok-001 | drop actualLayer from the row | — | aee-c-47 | `malformed-missing-actual-layer` | L334-335; L541-549 |
| `bad-503-clean-row-layer-not-none` | ok-002 | clean row actualLayer: "policy.egress_sinkhole" (MUST be the literal "none") | — | aee-c-48 | `clean-row-layer-not-none` | L550-555 |
| `bad-504-substrate-oov-label` | ok-001 | substrate row containmentObserved: "example_label_a" (not in carried labels); carried fail kept | — | aee-c-4 aee-c-44 | `fail-closed-substrate-row` | L226-227; L267-271 |
| `bad-505-substrate-missing-method` | ok-001 | substrate row method member ABSENT | — | aee-c-5 aee-c-42 aee-c-44 | `fail-closed-substrate-row` | L227-228; L424-427; L267-271 |
| `bad-601-vocabulary-absent` | ok-007 | drop observationVocabulary; carried fail kept | — | aee-c-51 | `vocabulary-missing` | L301-307 |
| `bad-602-caught-not-subset` | ok-002 | caught gains "example_label_x" which is not in labels; digest recomputed over the mutated content | recompute-vocabulary-digest | aee-c-52 | `vocabulary-caught-not-subset` | L305-306 |
| `bad-603-labels-unsorted` | ok-002 | labels in descending order; digest recomputed | recompute-vocabulary-digest | aee-c-53 | `vocabulary-not-canonical` | L306 |
| `bad-604-caught-duplicate` | ok-002 | duplicate entry in caught; digest recomputed | recompute-vocabulary-digest | aee-c-53 | `vocabulary-not-canonical` | L306 |
| `bad-605-vocabulary-digest-mismatch` | ok-002 | stale vocabulary digest over unchanged content | — | aee-c-54 | `vocabulary-digest-mismatch` | L306-307 |
| `bad-606-missing-runentropy` | ok-002 | drop runEntropy on a substrate-row-carrying statement | — | aee-c-57 | `run-entropy-missing` | L311-313; L86-87 |
| `bad-607-two-subjects-substrate` | ok-002 | second subject appended to a substrate-row-carrying statement | — | aee-c-58 | `subject-cardinality` | L82 |
| `bad-608-digest-uppercase` | ok-002 | runEntropy digest upper-cased; binding rederived VERBATIM over the uppercase value and records re-signed with it | rederive-run-binding-verbatim, re-sign-record, recompute-batch-root | aee-c-59 | `digest-not-canonical` | L82-86 |
| `bad-609-digest-truncated` | ok-002 | substrate digest truncated to 63 hex chars; verbatim rederive chain | rederive-run-binding-verbatim, re-sign-record, recompute-batch-root | aee-c-59 | `digest-not-canonical` | L82-86 |
| `bad-610-empty-labels-substrate` | ok-001 | labels: [] and caught: [] (digest recomputed) under a substrate row whose label is now out-of-vocabulary | recompute-vocabulary-digest | aee-c-4 aee-c-44 aee-c-53 | `fail-closed-substrate-row` | L267-271; L306 |
| `bad-611-subject-no-sha256` | ok-002 | subject digest carries only sha512 | — | aee-c-59 aee-c-60 | `subject-sha256-missing` | L82-86 |
| `bad-701-arming-missing-armedat` | ok-002 | drop armedAt from the arming payload | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L586-591; L601-604 |
| `bad-702-armedat-after-issuedat` | ok-002 | arming armedAt: "2026-01-01T00:01:00Z" (after issuedAt) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L586-591 |
| `bad-703-arming-posture-mismatch` | ok-002 | arming aeePostureDigest differs from the pinned posture digest | re-sign-record, recompute-batch-root | aee-c-63 aee-c-65 | `arming-covers-nothing`, `sealed-covers-nothing`, `clean-row-uncovered` (COMPOUND) | L586-591; L605-611 |
| `bad-704-arming-method-reconstructed` | ok-002 | arming record signed aeeMethod: "reconstructed" | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L589-591; L601-604 |
| `bad-705-sealed-missing-dropcount` | ok-002 | drop aeeDropCount from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L591-596 |
| `bad-706-stillarmed-non-boolean` | ok-002 | sealed aeeStillArmed: "true" (string, not boolean) | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L591-596 |
| `bad-707-sealed-stillarmed-false` | ok-002 | sealed aeeStillArmed: false | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L605-611 |
| `bad-708-sealed-drops-no-bound` | ok-002 | sealed aeeDropCount: 3 with no aeeDropBound declared | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L605-611 |
| `bad-709-sealed-drops-exceed-bound` | ok-003 | sealed aeeDropCount: 6 exceeding the declared aeeDropBound: 5 | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L605-611 |
| `bad-710-sealed-posture-mismatch` | ok-002 | sealed aeePostureDigest edited (differs from the arming record's AND the pinned digest, which the arming constraint makes equivalent) | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` (COMPOUND) | L605-611 |
| `bad-712-examination-method-intercepted` | ok-006 | examination record signed aeeMethod: "intercepted" | re-sign-record, recompute-batch-root | aee-c-66 | `examination-covers-nothing` | L596-598; L601-604 |
| `bad-713-only-sealed-ref-noncovering` | ok-002 | clean row refs [good-arming, non-covering-sealed]; a fully-covering sealed record sits UNREFERENCED in the tree | recompute-batch-root | aee-c-68 | `sealed-covers-nothing` | L505-506; L245-248 |
| `bad-714-unknown-kind-sole-cover` | ok-002 | the arming record's aeeKind becomes "aee-future-x" (record otherwise fully valid); the clean row's only arming ref now covers nothing | re-sign-record, recompute-batch-root | aee-c-71 | `record-kind-unknown-covers-nothing` | L614-618 |
| `bad-715-sealed-missing-stillarmed` | ok-002 | drop aeeStillArmed from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L591-596 |
| `bad-716-sealed-missing-posture` | ok-002 | drop aeePostureDigest from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 aee-c-65 | `sealed-covers-nothing` | L591-596; L605-611 |
| `bad-717-arming-missing-posture` | ok-002 | drop aeePostureDigest from the arming payload | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L586-591 |
| `bad-801-wrong-predicatetype` | ok-002 | v0.5 predicateType URI on a v0.6-shaped statement | — | aee-c-77 | `predicate-type-unsupported` | L3; L129 |
| `bad-802-missing-catchpolicy` | ok-007 | drop catchPolicy | — | aee-c-78 | `environment-incomplete` | L290-299 |
| `bad-803-corpus-digest-mismatch` | ok-007 | corpus.digest is not the JCS digest of the embedded manifest | — | aee-c-79 | `corpus-digest-mismatch` | L294-297; L313-316 |
| `bad-804-attackid-two-classes` | ok-033 | XA-EXAMPLE-1 appears under two manifest classes; corpus digest recomputed | recompute-corpus-digest | aee-c-80 | `manifest-duplicate-attack` | L296-297 |
| `bad-805-row-unknown-attackid` | ok-001 | row attackId: "XA-EXAMPLE-9" absent from the manifest | — | aee-c-81 aee-c-82 | `row-attack-unknown`, `coverage-incomplete` (COMPOUND) | L329; L350-353 |
| `bad-806-coverage-attack-omitted` | ok-011 | one of the two rows of a 2-attack assessed class deleted (quiet omission) | — | aee-c-82 | `coverage-incomplete` | L350-353 |
| `bad-807-coverage-attack-superset` | ok-004 | added artifact-basis clean row for the outOfScope class's attack; result stays degraded | — | aee-c-82 | `coverage-incomplete` | L350-353 |
| `bad-808-coverage-absent` | ok-002 | drop coverage | — | aee-c-83 | `coverage-missing` | L318-322 |
| `bad-809-snake-case-doesnotassert` | ok-002 | statement carries the rejected snake_case spelling of doesNotAssert | — | aee-c-84 | `member-spelling` | L650-660 |
| `bad-810-missing-issuedat` | ok-007 | drop issuedAt | — | aee-c-85 | `issued-at-missing` | L662-664 |
| `bad-811-issuedat-not-rfc3339` | ok-007 | issuedAt: "yesterday" | — | aee-c-85 | `issued-at-malformed` | L662-664 |
| `bad-812-missing-networkposture` | ok-007 | drop networkPosture | — | aee-c-78 | `environment-incomplete` | L290-301 |
| `bad-813-missing-corpus` | ok-007 | drop corpus | — | aee-c-78 | `environment-incomplete` | L290-297 |
| `bad-814-missing-substrate` | ok-007 | drop substrate | — | aee-c-78 | `environment-incomplete` | L290-294 |
| `bad-815-wrong-statement-type` | ok-002 | _type is not the in-toto Statement/v1 URI | — | aee-c-77 | `statement-type-unsupported` | L125 |

## Notes on specific vectors

- **bad-001-result-uppercase** — uppercase token is both out-of-vocabulary and not the recompute.
- **bad-006-result-fail-on-pass** — equality is two-directional.
- **bad-101-refs-empty** — an empty ref set on a caught row inherently also uncovers it.
- **bad-201-payload-unsorted-keys** — rawBytes: the committed base64 payload bytes are the fault; identical content, non-JCS order.
- **bad-202-payload-bignum** — rawBytes.
- **bad-203-payload-duplicate-member** — rawBytes.
- **bad-204-payload-media-type** — PAE covers payloadType, so the record is re-signed: the media type is the ONLY fault.
- **bad-301-run-binding-splice** — the statement's own corpus is unchanged; the records were earned under another run's environment.
- **bad-303-binding-version-2** — negative known-answer: the v2 pre-image MUST NOT match; a verifier has exactly one construction and never tries a second.
- **bad-304-method-cap-multirecord** — min-composition: a max()/any() rail wrongly accepts this.
- **bad-405-duplicate-records** — single fault: duplicate identity, not root arithmetic.
- **bad-407-substrate-row-no-records** — precedence pin: records-absent is reported when the array is absent entirely; ref-out-of-range only when records exist.
- **bad-409-artifact-records-bad-root** — the root check is statement-level: it runs even with zero substrate rows.
- **bad-501-substrate-unknown-method** — pairs with ok-008: the SAME fail-closed axis on an artifact row is a VALID fail.
- **bad-502-missing-actual-layer** — malformed STATEMENT, deliberately NOT a fail-closed row: a verifier answering result:fail here fails conformance.
- **bad-504-substrate-oov-label** — pairs with ok-009 (artifact twin stays valid).
- **bad-505-substrate-missing-method** — pairs with ok-027 (artifact row with absent method is a VALID fail).
- **bad-601-vocabulary-absent** — artifact-only parent: no digest or binding cascade.
- **bad-606-missing-runentropy** — precedence pin: a missing binding INPUT reports its member code, never run-binding-mismatch.
- **bad-607-two-subjects-substrate** — subject[0] unchanged, so record bindings still derive: the cardinality rule is the ONLY fault.
- **bad-608-digest-uppercase** — a rail that derives verbatim finds the binding EQUAL; only the lowercase-64-hex format rule fails.
- **bad-610-empty-labels-substrate** — empty vocabulary is internally canonical (vacuously sorted, vacuously a subset); the fault is the fail-closed substrate row.
- **bad-611-subject-no-sha256** — precedence pin: missing binding input reports the member code; records keep the parent binding (unreachable check).
- **bad-703-arming-posture-mismatch** — inherently compound: the sealed record must equal BOTH the arming record's and the pinned digest, so one arming edit un-covers the sealed record too.
- **bad-710-sealed-posture-mismatch** — both posture sub-clauses fire together; they are distinguishable only in already-invalid statements.
- **bad-713-only-sealed-ref-noncovering** — discriminates rails that scan all records instead of the row's referenced set.
- **bad-714-unknown-kind-sole-cover** — pairs with ok-013: an unknown kind that no row NEEDS is ignored and only contributes its leaf.
- **bad-801-wrong-predicatetype** — a verifier MUST NOT process this as v0.6.
- **bad-802-missing-catchpolicy** — artifact-only parent: no binding cascade; defeats the empty-vs-enforcing policy distinguishability.
- **bad-803-corpus-digest-mismatch** — statement-side lie, vs bad-301's record-side splice.
- **bad-804-attackid-two-classes** — artifact-only degraded parent avoids any binding cascade; coverage over the assessed class is unchanged.
- **bad-805-row-unknown-attackid** — precedence pin: row-attack-unknown.
- **bad-806-coverage-attack-omitted** — the second interception record stays in the tree (unreferenced records are legal), so the root is untouched: single fault.
- **bad-807-coverage-attack-superset** — superset direction of exactly-equal coverage.
- **bad-809-snake-case-doesnotassert** — single-canonicalization rule: no alias.
- **bad-810-missing-issuedat** — artifact-only parent: no armedAt comparison cascade.

## Compound vectors and precedence pins

`expected` codes form a SET: a rail conforms when its code is in the
set and the verdict matches. Vectors marked COMPOUND are inherently
multi-condition (deriving them singly is impossible without
introducing a different fault); every other vector is single-fault by
construction. Registry precedence pins applied here:

1. A missing binding INPUT reports its member code, never
   `run-binding-mismatch` (bad-606, bad-611); binding mismatch is
   reserved for derivable-but-unequal (bad-301, bad-303).
2. `records-absent` is reported when `observationRecords` is absent
   entirely; `ref-out-of-range` only when records exist (bad-407).
3. The method cap reads COVERING records only: the referenced records
   of the class(es) the row's class-match rule requires; extras are
   payload-checked but neither cap nor tier-gate (bad-304).
4. The two sealed posture equalities are jointly enforced given the
   arming constraint (bad-710); distinguishable only in
   already-invalid statements.

Signature failure is NEVER a failure code in this suite: whether a
record's signature verifies against a consumer-named key is the
evidence tier's separate, trust-relative question. Every committed
signature here verifies under the derived test public key above.

## Deferred coverage (no vector, by design)

- **Missing or out-of-vocabulary `basis`** on a row: a row whose
  `basis` is absent or unknown cannot be classified for the
  fail-closed branch split (substrate => attestation invalid vs
  artifact => valid `fail`), and the spec text does not state which
  branch applies. This is a formal spec-edit ask on the PR thread;
  shipping a reject vector now would silently resolve the reading.
  The out-of-vocab METHOD and LABEL substrate twins (bad-501,
  bad-504) plus the valid artifact-row twins in the accept suite
  cover the decidable half of the fail-closed axis.
- **Duplicate-record identity discriminator** (leaf-hash vs
  byte-identical): bad-405 is invalid under BOTH readings; the
  discriminating vector waits on the spec answer.
- **observationSelectors length mismatch**: unstated in the spec;
  formal ask, no vector.
- **Artifact-only multi-subject**: the one-subject rule is scoped to
  substrate-carrying statements (L82); whether artifact-only
  multi-subject is legal is an open ask (bad-607 keeps a substrate
  row precisely so the rule undeniably applies).
- **Replay of a genuine runEntropy** (stateful-consumer concern) and
  **coherence checks** (MAY): behavior/harness territory, not
  statement-shape vectors.

