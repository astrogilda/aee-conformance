# INVALID conformance vectors (adversarial-execution-evidence v0.6)

This directory is the conformance suite's `vectors/reject/` layout.

Ground truth: `spec/predicates/adversarial-execution-evidence.md` @
`f2ea2aa` (in-toto/attestation PR #570 branch),
version 0.6.0, type URI
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`.
The commit is read from `spec/VENDOR-PIN.json`, which
`scripts/vendor-spec.py` derives from git at vendor time, so this
line cannot name a revision the vendored bytes did not come from.

`Lnnn` anchors below are line refs into the vendored copy, in the
coordinate frame of the commit named above and no other. They are
remapped onto the new line numbers whenever the spec is re-vendored,
and `spec/ANCHOR-PINS.json` records the text each one addresses, so
`scripts/spec-anchor-gate.py` fails when an anchor comes to point at
prose it was not drawn around.

Every file is a COMPLETE in-toto Statement (UNWRAPPED, no outer DSSE;
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
  - `keyid` is an unauthenticated hint, never the check (spec L1233-1235).
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
Run bindings derive per spec L157-165 from each statement's own values.
Negative known-answer for bad-303, the retired version-1 pre-image
that MUST NOT match (JCS, then SHA-256):

```json
{
  "aeeBindingVersion": "1",
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
| aee-c-1 | L388 | closed lowercase result vocabulary |
| aee-c-2 | L343-346 | result must equal the recompute |
| aee-c-4 | L396-397 | fail-closed on out-of-vocabulary label |
| aee-c-5 | L396-397 | fail-closed on missing/out-of-vocab basis or method |
| aee-c-6 | L398-399 | degraded iff disclosed coverage gap |
| aee-c-10 | L487 | observationRefs non-empty on substrate rows |
| aee-c-11 | L487-488 | every ref index in range (integer) |
| aee-c-12 | L489-491 | caught intercepted row refs an interception record |
| aee-c-13 | L491-492 | reconstructed row refs an examination record |
| aee-c-14 | L492-495 | clean intercepted row refs arming AND covering sealed |
| aee-c-17 | L496-497 | covering payload is canonical RFC 8785 |
| aee-c-18 | L992-996 | covering payload is valid I-JSON (RFC 7493) |
| aee-c-19 | L997-998 | covering media type ends in +json |
| aee-c-20 | L497-498 | covering payload carries the reserved aee members |
| aee-c-22 | L498-499 | aeeRunBinding equals the derived run binding |
| aee-c-23 | L500-501 | row method capped by weakest signed aeeMethod |
| aee-c-24 | L1140 | batchRoot required when records exist |
| aee-c-25 | L1142-1145 | RFC 6962 domain-separated hashing |
| aee-c-26 | L1145-1147 | RFC 6962 recursive split, never duplicate-pad |
| aee-c-27 | L1147 | leaves in array order |
| aee-c-29 | L1149-1150 | duplicate byte-identical records invalid |
| aee-c-30 | L1152-1154 | batchRoot must recompute |
| aee-c-31 | L1157-1167 | batchRoot omitted exactly when records absent |
| aee-c-42 | L758-759 | method required, closed {intercepted, reconstructed} |
| aee-c-44 | L531-535 | fail-closed substrate row invalidates; artifact row stays a valid fail |
| aee-c-45 | L769-775 | weakest-input method composition |
| aee-c-47 | L949-957 | missing actualLayer = malformed statement, not fail |
| aee-c-48 | L958-963 | clean row actualLayer is the literal none |
| aee-c-51 | L566-574 | observationVocabulary required |
| aee-c-52 | L570-572 | caught is a subset of labels |
| aee-c-53 | L572 | vocabulary arrays sorted ascending, no duplicates |
| aee-c-54 | L572-574 | vocabulary digest is JCS of {caught, labels} |
| aee-c-57 | L578-580 | runEntropy required with any substrate row |
| aee-c-58 | L193-196 | exactly one subject on a statement of any basis |
| aee-c-59 | L193-207 | binding digest inputs lowercase 64-hex sha256 |
| aee-c-60 | L157-165 | binding pre-image construction |
| aee-c-62 | L212-220 | binding is anti-splice |
| aee-c-63 | L1003-1007 | arming record kind constraints |
| aee-c-64 | L1008-1012 | sealed record required members |
| aee-c-65 | L1023-1103 | sealed covering conditions |
| aee-c-66 | L1013-1015 | examination signed aeeMethod reconstructed |
| aee-c-68 | L885-886 | each referenced record independently satisfies its class constraints |
| aee-c-71 | L1106-1110 | unknown aeeKind covers nothing |
| aee-c-75 | L220-224 | fail-closed on unimplemented binding version |
| aee-c-77 | L3; L286 | statement _type and predicateType URIs |
| aee-c-78 | L554-580 | observationEnvironment required members |
| aee-c-79 | L558-561 | corpus digest re-derives from embedded manifest |
| aee-c-80 | L560-561 | attackId under at most one manifest class |
| aee-c-81 | L658 | row attackId appears in the manifest |
| aee-c-82 | L694-697 | coverage exactly equals the manifest at attack granularity |
| aee-c-83 | L643-647 | coverage member required |
| aee-c-84 | L1169-1179 | doesNotAssert single canonical spelling |
| aee-c-85 | L1181 | issuedAt required, under the Timestamp profile |
| aee-c-86 | L133-146 | vocabulary labels/caught entries BMP-only; a supplementary-plane entry is malformed |
| aee-c-87 | L133-146 | covering payload member names BMP-only; a supplementary-plane name covers nothing |
| aee-c-88 | L658-664 | row members are strictly typed; a wrong-JSON-type member is a malformed statement |
| aee-c-89 | L1030-1061 | arming chain-member syntax: positive aeeRunSeq; aeeChainScope required with it; aeePrevRunBinding lowercase 64-hex, absent exactly when aeeRunSeq is 1 |
| aee-c-90 | L672-674 | no two attackResults rows share an attackId |
| aee-c-91 | L980-982 | each observation record's signatures member carries at least one entry |
| aee-c-92 | L699-721 | the corpus manifest declares at least one attack identifier across all of its classes |
| aee-c-93 | L585-593 | networkPosture.posture is a registered value |

## Vectors (135)

`parent` names the accept-suite shape the vector derives from (the
accept vectors land separately; the parent statements are built
in-memory by the generator and asserted fully valid before mutation).
`rederive` lists the derived commitments recomputed after the mutation
so the declared fault stays the ONLY fault.

| vector | parent | single mutation | rederive | conditions (aee-c ids) | expected rejection | spec |
|---|---|---|---|---|---|---|
| `bad-001-result-uppercase` | ok-002 | result: "PASS" | - | aee-c-1 aee-c-2 | `result-vocabulary`, `result-recompute-mismatch` (COMPOUND) | L388; L343-346 |
| `bad-002-result-mismatch-caught` | ok-001 | carried result: "pass" over a caught row (recompute: fail) | - | aee-c-2 | `result-recompute-mismatch` | L343-346; L388-396 |
| `bad-003-result-mismatch-oov-label` | ok-009 | carried result: "pass" over a fail-closed out-of-vocabulary label | - | aee-c-2 aee-c-4 | `result-recompute-mismatch` | L396-397 |
| `bad-004-result-mismatch-failclosed` | ok-008 | carried result: "pass" over a fail-closed unknown method row | - | aee-c-2 aee-c-5 | `result-recompute-mismatch` | L396-397 |
| `bad-005-result-mismatch-coverage-gap` | ok-004 | carried result: "pass" with a non-empty coverage.outOfScope | - | aee-c-2 aee-c-6 | `result-recompute-mismatch` | L398-399 |
| `bad-006-result-fail-on-pass` | ok-002 | carried result: "fail" where the recompute derives pass | - | aee-c-2 | `result-recompute-mismatch` | L343-346 |
| `bad-007-result-degraded-on-pass` | ok-002 | carried result: "degraded" where the recompute derives pass | - | aee-c-2 | `result-recompute-mismatch` | L343-346 |
| `bad-008-result-unknown-token` | ok-002 | result: "error" | - | aee-c-1 aee-c-2 | `result-vocabulary`, `result-recompute-mismatch` (COMPOUND) | L388 |
| `bad-009-result-pass-on-indirect-clean-row` | ok-007 | carried result: "pass" over a clean row that is artifact-basis and reconstructed (recompute: pass_indirect) | - | aee-c-2 | `result-recompute-mismatch` | L343-346 |
| `bad-010-result-pass-indirect-on-direct-clean-row` | ok-002 | carried result: "pass_indirect" where every clean row is substrate-basis and intercepted (recompute: pass) | - | aee-c-2 | `result-recompute-mismatch` | L343-346 |
| `bad-101-refs-empty` | ok-001 | caught substrate row observationRefs: [] | - | aee-c-10 aee-c-12 | `refs-empty`, `caught-row-uncovered` (COMPOUND) | L487; L489-491 |
| `bad-102-ref-out-of-range` | ok-001 | observationRefs: [0, 7] with one record (valid cover kept) | - | aee-c-11 | `ref-out-of-range` | L487-488 |
| `bad-103-ref-negative` | ok-001 | observationRefs: [0, -1] | - | aee-c-11 | `ref-malformed` | L487-488 |
| `bad-104-caught-refs-arming-only` | ok-001 | append a fully-valid arming record; caught intercepted row refs only it | recompute-batch-root | aee-c-12 | `caught-row-uncovered` | L489-491 |
| `bad-105-reconstructed-refs-interception` | ok-006 | append a fully-valid interception record; reconstructed row refs only it | recompute-batch-root | aee-c-13 | `reconstructed-row-uncovered` | L491-492 |
| `bad-106-clean-missing-sealed` | ok-002 | clean row refs the arming record only | - | aee-c-14 | `clean-row-uncovered` | L492-495 |
| `bad-107-clean-missing-arming` | ok-002 | clean row refs the sealed record only | - | aee-c-14 | `clean-row-uncovered` | L492-495 |
| `bad-108-ref-non-integer` | ok-001 | observationRefs: [0, 1.5] | - | aee-c-11 | `ref-malformed` | L487-488 |
| `bad-201-payload-unsorted-keys` | ok-001 | covering payload re-serialized with reverse-sorted member order | re-sign-record, recompute-batch-root | aee-c-17 | `payload-not-canonical` | L496-497; L990-997 |
| `bad-202-payload-bignum` | ok-001 | covering payload gains an integer member 2^53+1 | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L992-996; L82-85 |
| `bad-203-payload-duplicate-member` | ok-001 | byte-crafted duplicate aeeMethod member in the covering payload | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L992-996 |
| `bad-204-payload-media-type` | ok-001 | covering record payloadType: "application/octet-stream" | re-sign-record, recompute-batch-root | aee-c-19 | `payload-media-type` | L997-998 |
| `bad-208-payload-member-non-bmp` | ok-001 | covering payload gains a member whose NAME carries the supplementary-plane code point U+1F600 | re-sign-record, recompute-batch-root | aee-c-87 | `payload-not-canonical` | L133-146 |
| `bad-205-payload-missing-runbinding` | ok-001 | drop aeeRunBinding from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L497-498; L998-1002 |
| `bad-206-payload-missing-kind` | ok-001 | drop aeeKind from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L497-498; L1002-1016 |
| `bad-207-payload-missing-method` | ok-001 | drop aeeMethod from the covering payload | re-sign-record, recompute-batch-root | aee-c-20 | `payload-missing-reserved` | L497-498; L1016-1017 |
| `bad-301-run-binding-splice` | ok-002 | records signed under a binding derived from a DIFFERENT corpus digest (cross-run splice) | recompute-batch-root | aee-c-22 aee-c-62 | `run-binding-mismatch` | L498-499; L209-215 |
| `bad-302-method-inflation` | ok-001 | row method "intercepted"; sole covering record signed "reconstructed" | re-sign-record, recompute-batch-root | aee-c-23 | `method-cap-exceeded` | L500-501 |
| `bad-303-binding-version-1` | ok-002 | records signed with a binding derived from the retired "aeeBindingVersion": "1" pre-image | derive-binding-v1, re-sign-record, recompute-batch-root | aee-c-75 aee-c-22 | `run-binding-mismatch` | L220-224; L498-499 |
| `bad-726-arming-binding-version-carried` | ok-002 | arming payload carries an explicit aeeBindingVersion: "3" the verifier does not implement (read-first, distinct from the bad-303 digest mismatch) | re-sign-record, recompute-batch-root | aee-c-75 | `arming-covers-nothing` | L220-227 |
| `bad-304-method-cap-multirecord` | ok-030 | row method "intercepted" covered by TWO interceptions with signed methods {intercepted, reconstructed}: exceeds the weakest | re-sign-record, recompute-batch-root | aee-c-23 aee-c-45 | `method-cap-exceeded` | L500-501 |
| `bad-401-records-no-batchroot` | ok-002 | batchRoot member removed while observationRecords is non-empty | - | aee-c-24 | `batch-root-missing` | L1140; L1152-1154 |
| `bad-402-root-no-domain-separation` | ok-014 | root computed without the 0x00/0x01 domain-separation prefixes | - | aee-c-25 | `batch-root-mismatch` | L1142-1145 |
| `bad-403-root-bitcoin-padding` | ok-014 | 3-leaf root computed by duplicate-last-leaf padding instead of the RFC 6962 recursive split | - | aee-c-26 | `batch-root-mismatch` | L1145-1147 |
| `bad-404-root-leaf-order-swapped` | ok-014 | root computed over leaves in swapped order | - | aee-c-27 | `batch-root-mismatch` | L1147 |
| `bad-405-duplicate-records` | ok-002 | two byte-identical records in the tree; root recomputes CORRECTLY over all three leaves | recompute-batch-root | aee-c-29 | `duplicate-record` | L1149-1150 |
| `bad-406-root-hex-tamper` | ok-002 | one hex digit of batchRoot flipped | - | aee-c-30 | `batch-root-mismatch` | L1152-1154 |
| `bad-407-substrate-row-no-records` | ok-001 | remove observationRecords AND batchRoot under a substrate row (2-op mutation) | - | aee-c-31 aee-c-11 | `records-absent`, `ref-out-of-range` (COMPOUND) | L1157-1167; L487-488 |
| `bad-408-batchroot-without-records` | ok-007 | orphan batchRoot added to a recordless artifact-only statement | - | aee-c-31 | `batch-root-orphaned` | L1157-1167; L1148 |
| `bad-409-artifact-records-bad-root` | ok-029 | one hex digit off on an artifact-only-with-records statement | - | aee-c-30 aee-c-24 | `batch-root-mismatch` | L1152-1154 |
| `bad-501-substrate-unknown-method` | ok-001 | substrate row method: "example.method-x" (unknown value); refs, records, root, entropy intact; carried fail kept | - | aee-c-44 aee-c-5 aee-c-42 | `fail-closed-substrate-row` | L531-535; L792-795 |
| `bad-502-missing-actual-layer` | ok-001 | drop actualLayer from the row | - | aee-c-47 | `malformed-missing-actual-layer` | L663-664; L949-957 |
| `bad-503-clean-row-layer-not-none` | ok-002 | clean row actualLayer: "policy.egress_sinkhole" (MUST be the literal "none") | - | aee-c-48 | `clean-row-layer-not-none` | L958-963 |
| `bad-818-artifact-clean-row-layer-not-none` | ok-007 | artifact clean row actualLayer: "policy.egress_sinkhole" (a clean row MUST carry the literal "none" regardless of basis) | - | aee-c-48 | `clean-row-layer-not-none` | L958-963 |
| `bad-504-substrate-oov-label` | ok-001 | substrate row containmentObserved: "example_label_a" (not in carried labels); carried fail kept | - | aee-c-4 aee-c-44 | `fail-closed-substrate-row` | L396-397; L531-535 |
| `bad-505-substrate-missing-method` | ok-001 | substrate row method member ABSENT | - | aee-c-5 aee-c-42 aee-c-44 | `fail-closed-substrate-row` | L396-397; L792-795; L531-535 |
| `bad-506-actuallayer-json-number` | ok-001 | caught row actualLayer carried as the JSON number 7 (wrong member type); refs, records, root, entropy intact; carried fail kept | - | aee-c-88 | `statement-malformed` | L658-664 |
| `bad-601-vocabulary-absent` | ok-007 | drop observationVocabulary; carried fail kept | - | aee-c-51 | `vocabulary-missing` | L566-574 |
| `bad-602-caught-not-subset` | ok-002 | caught gains "example_label_x" which is not in labels; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-52 | `vocabulary-caught-not-subset` | L570-572 |
| `bad-603-labels-unsorted` | ok-002 | labels in descending order; digest recomputed | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-53 | `vocabulary-not-canonical` | L572 |
| `bad-604-caught-duplicate` | ok-002 | duplicate entry in caught; digest recomputed | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-53 | `vocabulary-not-canonical` | L572 |
| `bad-605-vocabulary-digest-mismatch` | ok-002 | stale vocabulary digest over unchanged content | rederive-binding, re-sign-record, recompute-batch-root | aee-c-54 | `vocabulary-digest-mismatch` | L572-574 |
| `bad-606-missing-runentropy` | ok-002 | drop runEntropy on a substrate-row-carrying statement | - | aee-c-57 | `run-entropy-missing` | L578-580; L207-208 |
| `bad-607-two-subjects-substrate` | ok-002 | second subject appended to a substrate-row-carrying statement | - | aee-c-58 | `subject-cardinality` | L193-196 |
| `bad-608-digest-uppercase` | ok-002 | runEntropy digest upper-cased; binding rederived VERBATIM over the uppercase value and records re-signed with it | rederive-run-binding-verbatim, re-sign-record, recompute-batch-root | aee-c-59 | `digest-not-canonical` | L193-207 |
| `bad-609-digest-truncated` | ok-002 | substrate digest truncated to 63 hex chars; verbatim rederive chain | rederive-run-binding-verbatim, re-sign-record, recompute-batch-root | aee-c-59 | `digest-not-canonical` | L193-207 |
| `bad-610-empty-labels-substrate` | ok-001 | labels: [] and caught: [] (digest recomputed) under a substrate row whose label is now out-of-vocabulary | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-4 aee-c-44 aee-c-53 | `fail-closed-substrate-row` | L531-535; L572 |
| `bad-611-subject-no-sha256` | ok-002 | subject digest carries only sha512 | - | aee-c-59 aee-c-60 | `subject-sha256-missing` | L193-207 |
| `bad-612-labels-non-bmp` | ok-001 | labels gains the supplementary-plane entry U+1F600; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-86 | `vocabulary-not-canonical` | L133-146 |
| `bad-701-arming-missing-armedat` | ok-002 | drop armedAt from the arming payload | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1003-1007; L1019-1022 |
| `bad-702-armedat-after-issuedat` | ok-002 | arming armedAt: "2026-01-01T00:01:00Z" (after issuedAt) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1005-1006 |
| `bad-703-arming-posture-mismatch` | ok-002 | arming aeePostureDigest differs from the pinned posture digest | re-sign-record, recompute-batch-root | aee-c-63 aee-c-65 | `arming-covers-nothing`, `sealed-covers-nothing`, `clean-row-uncovered` (COMPOUND) | L1003-1007; L1023-1103 |
| `bad-704-arming-method-reconstructed` | ok-002 | arming record signed aeeMethod: "reconstructed" | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1007; L1019-1022 |
| `bad-705-sealed-missing-dropcount` | ok-002 | drop aeeDropCount from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L1008-1012 |
| `bad-706-stillarmed-non-boolean` | ok-002 | sealed aeeStillArmed: "true" (string, not boolean) | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L1008-1012 |
| `bad-707-sealed-stillarmed-false` | ok-002 | sealed aeeStillArmed: false | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1023-1103 |
| `bad-708-sealed-drops-no-bound` | ok-002 | sealed aeeDropCount: 3 with no aeeDropBound declared | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1023-1103 |
| `bad-709-sealed-drops-exceed-bound` | ok-003 | sealed aeeDropCount: 6 exceeding the declared aeeDropBound: 5 | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` | L1023-1103 |
| `bad-710-sealed-posture-mismatch` | ok-002 | sealed aeePostureDigest edited (differs from the arming record's AND the pinned digest, which the arming constraint makes equivalent) | re-sign-record, recompute-batch-root | aee-c-65 | `sealed-covers-nothing` (COMPOUND) | L1023-1103 |
| `bad-712-examination-method-intercepted` | ok-006 | examination record signed aeeMethod: "intercepted" | re-sign-record, recompute-batch-root | aee-c-66 | `examination-covers-nothing` | L1013-1015; L1019-1022 |
| `bad-713-only-sealed-ref-noncovering` | ok-002 | clean row refs [good-arming, non-covering-sealed]; a fully-covering sealed record sits UNREFERENCED in the tree | recompute-batch-root | aee-c-68 | `sealed-covers-nothing` | L885-886; L492-495 |
| `bad-714-unknown-kind-sole-cover` | ok-002 | the arming record's aeeKind becomes "aee-future-x" (record otherwise fully valid); the clean row's only arming ref now covers nothing | re-sign-record, recompute-batch-root | aee-c-71 | `record-kind-unknown-covers-nothing` | L1106-1110 |
| `bad-715-sealed-missing-stillarmed` | ok-002 | drop aeeStillArmed from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 | `sealed-covers-nothing` | L1008-1012 |
| `bad-716-sealed-missing-posture` | ok-002 | drop aeePostureDigest from the sealed payload | re-sign-record, recompute-batch-root | aee-c-64 aee-c-65 | `sealed-covers-nothing` | L1008-1012; L1023-1103 |
| `bad-717-arming-missing-posture` | ok-002 | drop aeePostureDigest from the arming payload | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1003-1007 |
| `bad-727-armedat-non-utc-offset` | ok-002 | armedAt carries a non-zero UTC offset (+05:00): a valid instant no later than issuedAt, but not RFC 3339 UTC | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1005 |
| `bad-728-artifact-two-subjects` | ok-007 | a second subject appended to an ARTIFACT-ONLY statement (no substrate rows) | - | aee-c-58 | `subject-cardinality` | L193-196 |
| `bad-729-duplicate-attackid-rows` | ok-001 | a second attackResults row carrying the SAME attackId as the first (one row per executed attack) | - | aee-c-90 | `statement-malformed` | L658-671 |
| `bad-730-coverage-class-overlap` | ok-004 | class XA appears in BOTH assessedClasses and outOfScope: the three coverage sets are not a disjoint partition | - | aee-c-82 | `coverage-incomplete` | L650-654 |
| `bad-718-chain-runseq-zero` | ok-002 | arming payload gains aeeRunSeq: 0 with aeeChainScope present (a sequence number is a positive integer) | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1030-1061 |
| `bad-719-chain-missing-scope` | ok-002 | arming payload gains aeeRunSeq: 1 with NO aeeChainScope (aeeChainScope is required whenever aeeRunSeq is present) | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1030-1061 |
| `bad-720-chain-prev-not-hex` | ok-002 | arming payload gains aeeRunSeq: 2, aeeChainScope, and an aeePrevRunBinding that is not lowercase 64-hex | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1030-1061 |
| `bad-721-chain-scope-not-array` | ok-002 | arming payload gains aeeRunSeq: 1 with aeeChainScope as a free-form string, not the required array of registered dimension tokens | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1034-1038 |
| `bad-722-chain-scope-unknown-dimension` | ok-002 | arming payload gains aeeRunSeq: 1 with an aeeChainScope carrying a token outside the closed dimension vocabulary | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1034-1038 |
| `bad-723-chain-scope-not-canonical` | ok-002 | arming payload gains aeeRunSeq: 1 with an aeeChainScope array whose tokens are not in canonical (UTF-16 code-unit) order | re-sign-record, recompute-batch-root | aee-c-89 | `arming-covers-nothing` | L1034-1038 |
| `bad-724-artifact-ref-out-of-range` | ok-029 | an artifact row carries an observationRefs index out of range for observationRecords (fail-closed on any row, not only substrate rows) | - | aee-c-11 | `ref-out-of-range` | L487-488 |
| `bad-725-statement-duplicate-member` | ok-002 | raw statement bytes carrying a duplicate top-level predicateType member (the whole statement is parsed as strict I-JSON, not only record payloads) | - | aee-c-18 | `statement-malformed` | L83-89 |
| `bad-801-wrong-predicatetype` | ok-002 | v0.5 predicateType URI on a v0.6-shaped statement | - | aee-c-77 | `predicate-type-unsupported` | L3; L290 |
| `bad-802-missing-catchpolicy` | ok-007 | drop catchPolicy | - | aee-c-78 | `environment-incomplete` | L554-563 |
| `bad-803-corpus-digest-mismatch` | ok-007 | corpus.digest is not the JCS digest of the embedded manifest | - | aee-c-79 | `corpus-digest-mismatch` | L558-561; L580-583 |
| `bad-804-attackid-two-classes` | ok-033 | XA-EXAMPLE-1 appears under two manifest classes; corpus digest recomputed | recompute-corpus-digest | aee-c-80 | `manifest-duplicate-attack` | L560-561 |
| `bad-805-row-unknown-attackid` | ok-001 | row attackId: "XA-EXAMPLE-9" absent from the manifest | - | aee-c-81 aee-c-82 | `row-attack-unknown`, `coverage-incomplete` (COMPOUND) | L658; L694-697 |
| `bad-806-coverage-attack-omitted` | ok-011 | one of the two rows of a 2-attack assessed class deleted (quiet omission) | - | aee-c-82 | `coverage-incomplete` | L694-697 |
| `bad-807-coverage-attack-superset` | ok-004 | added artifact-basis clean row for the outOfScope class's attack; result stays degraded | - | aee-c-82 | `coverage-incomplete` | L694-697 |
| `bad-816-coverage-class-dropped` | ok-004 | manifest class XB dropped from all three coverage sets (not assessed, not outOfScope, not routedElsewhere), result forced to pass: the class-granularity coverage-partition fail-open | - | aee-c-82 | `coverage-incomplete` | L645-650; L694-697 |
| `bad-819-assessed-class-not-in-manifest` | ok-001 | assessedClasses padded with class XZ the manifest never carried | - | aee-c-82 | `coverage-incomplete` | L650-654; L694-697 |
| `bad-731-outofscope-unknown-class` | ok-004 | outOfScope carries class XZ the manifest never carried | - | aee-c-82 | `coverage-incomplete` | L650-654; L694-697 |
| `bad-732-routedelsewhere-unknown-class` | ok-004 | routedElsewhere carries class XZ the manifest never carried | - | aee-c-82 | `coverage-incomplete` | L650-654; L694-697 |
| `bad-733-statement-lone-high-surrogate-escape` | ok-002 | vocabulary label carrying an unpaired high surrogate escape; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L87-113 |
| `bad-734-statement-lone-low-surrogate-escape` | ok-002 | vocabulary label carrying an unpaired low surrogate escape; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L87-113 |
| `bad-735-statement-reversed-surrogate-pair` | ok-002 | vocabulary label carrying a low surrogate followed by a high surrogate; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L87-113 |
| `bad-736-statement-cesu8-vocabulary-label` | ok-002 | vocabulary label carrying a surrogate encoded directly in UTF-8 (CESU-8, ED A0 80); digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L87-113 |
| `bad-737-statement-overlong-utf8` | ok-002 | vocabulary label carrying the overlong encoding C0 AF; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L87-113 |
| `bad-738-statement-raw-control-character` | ok-002 | vocabulary label carrying a raw unescaped U+0001; digest recomputed over the mutated content | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L87-113 |
| `bad-739-payload-lone-surrogate-escape` | ok-001 | covering payload gains a member whose value carries an unpaired surrogate escape | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L954-957 |
| `bad-740-payload-cesu8` | ok-001 | covering payload gains a member whose value carries a surrogate encoded directly in UTF-8 (CESU-8, ED A0 80) | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L954-957 |
| `bad-741-payload-nesting-exceeds-max-depth` | ok-001 | covering payload nested 129 deep, one level past the normative bound | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L128-135 |
| `bad-742-payload-nesting-empty-container-leaf` | ok-001 | covering payload nested 129 deep with an empty-container leaf, one past the bound | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L128-135 |
| `bad-743-statement-noncharacter-vocabulary-label` | ok-002 | vocabulary label carrying the noncharacter U+FFFF | recompute-vocabulary-digest, rederive-binding, re-sign-record, recompute-batch-root | aee-c-18 | `statement-malformed` | L93-120 |
| `bad-744-payload-noncharacter` | ok-001 | covering payload gains a member whose value carries the noncharacter U+FFFF | re-sign-record, recompute-batch-root | aee-c-18 | `payload-not-ijson` | L93-120 |
| `bad-745-record-signatures-empty` | ok-001 | covering record's signatures array emptied to [] | - | aee-c-91 | `record-signatures-empty` | L980-982 |
| `bad-748-signatures-empty-precedes-undecodable-record` | ok-002 | arming record payload re-encoded as non-canonical base64 AND the sealed record's signatures array emptied, in that wire order | - | aee-c-91 | `record-signatures-empty` (COMPOUND) (also carries: `record-undecodable`) | L980-982; L982-989 |
| `bad-749-record-signatures-not-an-array` | ok-001 | covering record's signatures member replaced with the JSON string "sig" | - | aee-c-91 | `record-signatures-empty` | L980-982 |
| `bad-746-manifest-empty-classes` | ok-007 | corpus manifest emptied to {"classes": {}}; the row it declared and that row's coverage entry come out with it | drop-undeclared-rows, rebuild-coverage-partition, recompute-corpus-digest | aee-c-92 | `corpus-manifest-no-attacks` | L699-721 |
| `bad-747-manifest-class-declares-no-attacks` | ok-007 | corpus manifest keeps class XA but empties its attack-id array; the row it declared and that row's coverage entry come out with it | drop-undeclared-rows, rebuild-coverage-partition, recompute-corpus-digest | aee-c-92 | `corpus-manifest-no-attacks` | L699-721 |
| `bad-817-payload-noncanonical-base64` | ok-001 | covering record payload re-encoded as non-canonical base64 (nonzero trailing bits); the record no longer strict-decodes | - | aee-c-19 | `record-undecodable` | L968-971 |
| `bad-808-coverage-absent` | ok-002 | drop coverage | - | aee-c-83 | `coverage-missing` | L643-647 |
| `bad-809-snake-case-doesnotassert` | ok-002 | statement carries the rejected snake_case spelling of doesNotAssert | - | aee-c-84 | `member-spelling` | L1169-1179 |
| `bad-810-missing-issuedat` | ok-007 | drop issuedAt | - | aee-c-85 | `issued-at-missing` | L1181 |
| `bad-811-issuedat-not-rfc3339` | ok-007 | issuedAt: "yesterday" | - | aee-c-85 | `issued-at-malformed` | L1181 |
| `bad-812-missing-networkposture` | ok-007 | drop networkPosture | - | aee-c-78 | `environment-incomplete` | L554-564 |
| `bad-813-missing-corpus` | ok-007 | drop corpus | - | aee-c-78 | `environment-incomplete` | L554-561 |
| `bad-814-missing-substrate` | ok-007 | drop substrate | - | aee-c-78 | `environment-incomplete` | L554-558 |
| `bad-815-wrong-statement-type` | ok-002 | _type is not the in-toto Statement/v1 URI | - | aee-c-77 | `statement-type-unsupported` | L286 |
| `bad-750-armedat-lowercase-separator` | ok-002 | arming armedAt: "2025-12-31t23:59:00Z" (lowercase date-time separator) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1005 |
| `bad-751-armedat-lowercase-zone-designator` | ok-002 | arming armedAt: "2025-12-31T23:59:00z" (lowercase zone designator) | re-sign-record, recompute-batch-root | aee-c-63 | `arming-covers-nothing` | L1005 |
| `bad-820-issuedat-non-utc-offset` | ok-007 | issuedAt: "2026-01-01T05:00:00+05:00" (a non-zero UTC offset) | - | aee-c-85 | `issued-at-malformed` | L1181 |
| `bad-821-issuedat-lowercase-separator` | ok-007 | issuedAt: "2026-01-01t00:00:00Z" (lowercase date-time separator) | - | aee-c-85 | `issued-at-malformed` | L1181 |
| `bad-822-issuedat-lowercase-zone-designator` | ok-007 | issuedAt: "2026-01-01T00:00:00z" (lowercase zone designator) | - | aee-c-85 | `issued-at-malformed` | L1181 |
| `bad-823-posture-unregistered` | ok-002 | networkPosture.posture: "example_posture_x", a value the registry does not carry | rederive-binding, re-sign-record, recompute-batch-root | aee-c-93 | `posture-vocabulary` | L585-593 |
| `bad-824-posture-not-a-string` | ok-002 | networkPosture.posture: 3, a value of the wrong JSON type | rederive-binding, re-sign-record, recompute-batch-root | aee-c-93 | `posture-vocabulary` | L585-593 |
| `bad-825-posture-array` | ok-002 | networkPosture.posture: ["sinkhole"], an array wrapping a registered value | rederive-binding, re-sign-record, recompute-batch-root | aee-c-93 | `posture-vocabulary` | L585-593 |
| `bad-305-posture-swapped` | ok-002 | networkPosture.posture swapped from "sinkhole" to "allowlist"; every digest, signature and record left exactly as the producer signed them | - | aee-c-22 aee-c-60 | `run-binding-mismatch` | L157-165; L498-499 |
| `bad-306-vocabulary-caught-narrowed` | ok-002 | caught narrowed to [] with the vocabulary digest re-derived over the narrowed arrays; the records keep the binding they were signed with | recompute-vocabulary-digest | aee-c-22 aee-c-60 | `run-binding-mismatch` | L157-165; L498-499 |
| `bad-307-posture-member-added-after-arming` | ok-002 | networkPosture gains a producer member the records do not commit to | - | aee-c-22 aee-c-60 | `run-binding-mismatch` | L157-165; L498-499 |

## Notes on specific vectors

- **bad-001-result-uppercase**: uppercase token is both out-of-vocabulary and not the recompute.
- **bad-006-result-fail-on-pass**: equality is two-directional.
- **bad-009-result-pass-on-indirect-clean-row**: this is the statement a party holding only the enclosing envelope key produces by moving every row to artifact basis and dropping the records: valid before the fourth result value existed, and a recompute mismatch after it.
- **bad-010-result-pass-indirect-on-direct-clean-row**: the new token is not a floor a producer may volunteer down to; equality is two-directional here exactly as it is for bad-006.
- **bad-101-refs-empty**: an empty ref set on a caught row inherently also uncovers it.
- **bad-201-payload-unsorted-keys**: rawBytes: the committed base64 payload bytes are the fault; identical content, non-JCS order.
- **bad-202-payload-bignum**: rawBytes.
- **bad-203-payload-duplicate-member**: rawBytes.
- **bad-204-payload-media-type**: PAE covers payloadType, so the record is re-signed: the media type is the ONLY fault.
- **bad-208-payload-member-non-bmp**: rawBytes; BMP-only string profile: the name sorts last under BOTH the UTF-16 and the code-point member order, so the payload bytes stay canonical under either reading and the supplementary-plane member NAME is the single fault (a supplementary-plane member VALUE stays legal).
- **bad-301-run-binding-splice**: the statement's own corpus is unchanged; the records were earned under another run's environment.
- **bad-303-binding-version-1**: negative known-answer: version 1 is retired with no alias and no dual-accept window, so its pre-image MUST NOT match; a verifier has exactly one construction and never tries a second. The vector is named for the construction its records were minted under, and it is the retired one rather than a future one on purpose: a vector minted under a version nobody has implemented rejects whether or not the rule holds, because its digest matches no construction at all, while this one is a digest a real producer could have emitted last revision.
- **bad-726-arming-binding-version-carried**: an explicit binding-version declaration the verifier does not implement is read before deriving and makes the arming record cover nothing, distinguishably from a run-binding digest mismatch. The declared version has to be one no verifier implements, so it moves whenever the implemented construction does: it read "2" while the implemented construction was version 1, and left that value in place the version 2 landed, at which point the record declared exactly what the verifier derives and the vector asserted nothing.
- **bad-304-method-cap-multirecord**: min-composition: a max()/any() rail wrongly accepts this.
- **bad-405-duplicate-records**: single fault: duplicate identity, not root arithmetic.
- **bad-407-substrate-row-no-records**: precedence pin: records-absent is reported when the array is absent entirely; ref-out-of-range only when records exist.
- **bad-409-artifact-records-bad-root**: the root check is statement-level: it runs even with zero substrate rows.
- **bad-501-substrate-unknown-method**: pairs with ok-008: the SAME fail-closed axis on an artifact row is a VALID fail.
- **bad-502-missing-actual-layer**: malformed STATEMENT, deliberately NOT a fail-closed row: a verifier answering result:fail here fails conformance.
- **bad-818-artifact-clean-row-layer-not-none**: pairs with bad-503, the substrate twin: the clean-row none rule is not scoped to a basis (L958-963 says 'a row', no basis qualifier), so an artifact clean row is held to it too.
- **bad-504-substrate-oov-label**: pairs with ok-009 (artifact twin stays valid).
- **bad-505-substrate-missing-method**: pairs with ok-027 (artifact row with absent method is a VALID fail).
- **bad-506-actuallayer-json-number**: type-strictness pin: row members are strings, and a wrong-typed member is a decode-layer fault, deliberately a DIFFERENT altitude than an absent one, a rail that maps the number to member absence (malformed-missing-actual-layer) fails conformance here.
- **bad-601-vocabulary-absent**: artifact-only parent: no digest or binding cascade.
- **bad-605-vocabulary-digest-mismatch**: the binding is rederived over the STALE carried digest, not over the digest the arrays recompute to, because that is the value a verifier reading the statement folds into the pre-image; deriving over the honest one would leave every record mismatched and the vector would report a binding fault instead of the digest fault.
- **bad-606-missing-runentropy**: precedence pin: a missing binding INPUT reports its member code, never run-binding-mismatch.
- **bad-607-two-subjects-substrate**: subject[0] unchanged, so record bindings still derive: the cardinality rule is the ONLY fault.
- **bad-608-digest-uppercase**: a rail that derives verbatim finds the binding EQUAL; only the lowercase-64-hex format rule fails.
- **bad-610-empty-labels-substrate**: empty vocabulary is internally canonical (vacuously sorted, vacuously a subset); the fault is the fail-closed substrate row.
- **bad-611-subject-no-sha256**: precedence pin: missing binding input reports the member code; records keep the parent binding (unreachable check).
- **bad-612-labels-non-bmp**: BMP-only string profile: the entry sorts last under BOTH the UTF-16 and the code-point order, so sortedness, the caught subset, and the digest all still verify and the supplementary-plane entry is the single fault.
- **bad-703-arming-posture-mismatch**: inherently compound: the sealed record must equal BOTH the arming record's and the pinned digest, so one arming edit un-covers the sealed record too.
- **bad-710-sealed-posture-mismatch**: both posture sub-clauses fire together; they are distinguishable only in already-invalid statements.
- **bad-713-only-sealed-ref-noncovering**: discriminates rails that scan all records instead of the row's referenced set.
- **bad-714-unknown-kind-sole-cover**: pairs with ok-013: an unknown kind that no row NEEDS is ignored and only contributes its leaf.
- **bad-727-armedat-non-utc-offset**: RFC 3339 UTC means a zero offset; +05:00 parses as a valid instant (18:59Z, before issuedAt) but is not UTC, so the arming record covers nothing, distinct from a late armedAt (bad-702).
- **bad-728-artifact-two-subjects**: subject cardinality is unconditional (spec:193-196): exactly one subject on a statement of any basis. bad-607 keeps a substrate row; this locks the previously substrate-scoped rule as unconditional on an artifact-only statement.
- **bad-729-duplicate-attackid-rows**: two rows share attackId XA-EXAMPLE-1. Coverage integrity set-compares row attackIds to the manifest, so a duplicate collapses under set semantics and would pass silently; uniqueness is a well-formedness invariant detected before the set is built.
- **bad-730-coverage-class-overlap**: the from-spec checker accepts overlap (completeness-only); our two rails reject it (disjoint partition). A class both assessed and disclosed as a gap is contradictory. Keeping the reject reading is the converged debate recommendation, reversible at vetting.
- **bad-718-chain-runseq-zero**: pairs with the genesis accept vector ok-034 (aeeRunSeq 1, scope present, no predecessor).
- **bad-719-chain-missing-scope**: an unscoped counter makes every chain rule vacuous, so the syntax check rejects it fail-closed.
- **bad-720-chain-prev-not-hex**: a predecessor binding is a lowercase 64-hex run binding digest, present exactly when aeeRunSeq exceeds 1.
- **bad-721-chain-scope-not-array**: the old free-form string form is rejected fail-closed; array of registered tokens is the sole accepted shape (no alias).
- **bad-722-chain-scope-unknown-dimension**: an unrecognized dimension token fails closed, as every closed vocabulary in this spec does.
- **bad-723-chain-scope-not-canonical**: canonical order is corpus < networkPosture < subject; the same canonicality rule as observationVocabulary.labels.
- **bad-724-artifact-ref-out-of-range**: an out-of-range reference is a structural integrity fault on any row regardless of basis; a reference that does not resolve is never silently ignored.
- **bad-725-statement-duplicate-member**: rawStatement: the dict form cannot carry a duplicate member; a lenient parser keeps the last silently, so a duplicate anywhere in the statement is a malformed statement, fail-closed.
- **bad-801-wrong-predicatetype**: a verifier MUST NOT process this as v0.6.
- **bad-802-missing-catchpolicy**: artifact-only parent: no binding cascade; defeats the empty-vs-enforcing policy distinguishability.
- **bad-803-corpus-digest-mismatch**: statement-side lie, vs bad-301's record-side splice.
- **bad-804-attackid-two-classes**: artifact-only degraded parent avoids any binding cascade; coverage over the assessed class is unchanged.
- **bad-805-row-unknown-attackid**: precedence pin: row-attack-unknown.
- **bad-806-coverage-attack-omitted**: the second interception record stays in the tree (unreferenced records are legal), so the root is untouched: single fault.
- **bad-807-coverage-attack-superset**: superset direction of exactly-equal coverage.
- **bad-816-coverage-class-dropped**: distinct from bad-806/807 (attack granularity within an assessed class): a whole manifest class left silently unaccounted.
- **bad-819-assessed-class-not-in-manifest**: mirror of bad-816 (a manifest class dropped from every coverage set): here a fabricated class pads assessedClasses. Coverage must be an exhaustive, disjoint partition of the manifest's real classes, so a class in a coverage set that the manifest never carried is the same class-granularity coverage-partition fault.
- **bad-731-outofscope-unknown-class**: reason-map mirror of bad-819 (which forces the assessedClasses side). The three coverage sets are a disjoint partition of the manifest's classes, so membership runs both ways; nothing forced the outOfScope side until now (in-toto/attestation#570 round-8, Rul1an). Both rails already enforce it (Go statement.go, Python _coverage_partition_ok); this vector locks the rule and mutation-proves the rails..
- **bad-732-routedelsewhere-unknown-class**: reason-map mirror of bad-819 for the routedElsewhere side (see bad-731). Closes the second untested consequence of the partition-membership rule (in-toto/attestation#570 round-8)..
- **bad-733-statement-lone-high-surrogate-escape**: rawStatement: the file is valid UTF-8 and parses as JSON, so only a check on the raw bytes sees it. A lenient parse yields a lone surrogate that no later comparison can tell from a written one..
- **bad-734-statement-lone-low-surrogate-escape**: rawStatement: a low surrogate with no preceding high surrogate..
- **bad-735-statement-reversed-surrogate-pair**: rawStatement: both halves are present, in the wrong order, so a check that counts surrogates rather than pairing them passes..
- **bad-736-statement-cesu8-vocabulary-label**: rawBytes: not valid UTF-8. A lenient decoder substitutes U+FFFD, and because the vocabulary digest is recomputed from the decoded strings the statement is self-consistent afterwards. This is the exact construction that verified valid on one rail and invalid on three..
- **bad-737-statement-overlong-utf8**: rawBytes: the overlong form is the other half of the UTF-8 well-formedness rule, and a length-only scanner steps over it..
- **bad-738-statement-raw-control-character**: rawBytes: JSON forbids an unescaped character below U+0020..
- **bad-739-payload-lone-surrogate-escape**: rawBytes: the payload position of the rule bad-733 covers statement-wide. The code differs because a payload that is not a parseable I-JSON value covers nothing..
- **bad-740-payload-cesu8**: rawBytes: the payload path byte-compares against the carried bytes, so a substitution cannot round-trip there; this vector pins the CODE rather than the verdict..
- **bad-741-payload-nesting-exceeds-max-depth**: rawBytes: the bound is normative because it was not. The reference rails chose 128 and the independent from-spec checker chose 256, so identical bytes were evidence to one conforming verifier and malformed to another across 127 depths..
- **bad-742-payload-nesting-empty-container-leaf**: rawBytes: the empty-container companion to bad-741. A rail that charges a level per parsed child rather than per open container never charges an empty container, so it accepts at depth 129 what the bracket-counting rails reject. bad-741's scalar leaf could not discriminate it..
- **bad-743-statement-noncharacter-vocabulary-label**: rawBytes: a noncharacter is a valid scalar that nothing substitutes, so this is not a live cross-rail split; it is the RFC 7493 label made true, so a from-spec verifier reading the label does not reject a record we accept..
- **bad-744-payload-noncharacter**: rawBytes: the payload position of bad-743. RFC 7493 section 2.1 forbids noncharacters in every string literal, not only member names..
- **bad-745-record-signatures-empty**: the count is byte-pure and verifies nothing: a record carrying one fabricated signature entry passes it and is caught only at the tier, so this vector closes the literal zero-signature case and no more. It is also the suite's one vector with an empty rederive chain, because signatures are outside the PAE pre-image and so outside batchRoot.
- **bad-748-signatures-empty-precedes-undecodable-record**: deliberately two-fault, which is what makes it a precedence pin rather than a duplicate of bad-745: a condition that only ever appears alone cannot say which of two conditions a rail must report. The expected set names one code on purpose, so a rail that reports the decode fault instead fails rather than passing on a widened set.
- **bad-749-record-signatures-not-an-array**: the wrong-type spelling of zero entries. It reads as the more likely producer bug of the three, since a substrate that emits one signature object where the schema wants an array of them produces exactly this. The expected set names the specific condition rather than the parse catch-all, because the catch-all identifies neither the record nor the member, and because an ABSENT signatures member already reports the specific condition on the same reasoning.
- **bad-746-manifest-empty-classes**: the bare shape of the bypass. Every other check on this statement passes: the corpus digest re-derives over the emptied manifest, coverage is a partition of nothing, the recompute returns pass, and with no substrate row nothing requires runEntropy, observationRecords or a batchRoot. Only the manifest floor rejects it, which is why the floor sits in well-formedness and not in result: a corpus declaring no adversarial inputs is not an adversarial corpus, and scoring it would concede that the run is a legitimate statement that merely scores badly.
- **bad-747-manifest-class-declares-no-attacks**: the twin bad-746 cannot catch, and the reason the rule counts identifiers rather than classes. This manifest carries a real class name and assessedClasses names it, so the coverage partition is exactly satisfied and the statement reads like an assessment that found nothing rather than like an empty object; a rule phrased as "an empty classes object is malformed" would admit it.
- **bad-817-payload-noncanonical-base64**: encoding-layer divergence: Go decodes with StdEncoding.Strict() and the Python rail re-encode-compares, so both reject; a lenient decoder would accept. The stale signature and batch root are unreachable because a decode failure short-circuits both checks (validity.go:120).
- **bad-809-snake-case-doesnotassert**: single-canonicalization rule: no alias.
- **bad-810-missing-issuedat**: artifact-only parent: no armedAt comparison cascade.
- **bad-750-armedat-lowercase-separator**: the parent's instant with the separator lowercased. The profile is uppercase and this was already a rejection before the profile was written down, since the clause names Z and +00:00 and admits no lowercase spelling; the Python reference rail accepted it anyway, which is the divergence this vector exists to hold shut.
- **bad-751-armedat-lowercase-zone-designator**: the separator's twin: the other half of the case rule, isolated so a rail that enforces the case of one designator and not the other is caught. Distinct from bad-727 (a non-zero offset), which is the zone half of the same profile.
- **bad-820-issuedat-non-utc-offset**: the parent's instant at a non-zero offset. issuedAt is typed as the framework Timestamp, which requires the UTC timezone, so a valid instant in a non-UTC spelling is malformed. The counterpart on the arming record is bad-727, which every rail rejected while every rail accepted this one.
- **bad-821-issuedat-lowercase-separator**: the spelling the Go reference rail refused and the Python reference rail accepted with result pass, an accept-on-one reject-on-another split inside one repository that no vector reached.
- **bad-822-issuedat-lowercase-zone-designator**: the separator's twin on the predicate field, isolated for the same reason as bad-751: a rail enforcing the case of one designator and not the other passes every both-lowercase mutant.
- **bad-823-posture-unregistered**: the pinned digest member is untouched, so both covering records still compare equal on aeePostureDigest and the unregistered string is the single fault.
- **bad-824-posture-not-a-string**: a wrong-type posture is the same requirement failing as an unregistered one, so it reports the same condition rather than the parse catch-all; a rail that decodes the member into a string field and lets the decode failure escape names a different condition than its peers for these exact bytes.
- **bad-825-posture-array**: the shape that separated the rails before it was fixed: testing membership of an unhashable value against a set raises rather than returning false, so two rails crashed on it while a third rejected it cleanly, which is a crash and a cross-rail split at once. It is kept distinct from the wrong-type vector because a scalar of the wrong type and a container of the wrong type reach a membership test by different paths.
- **bad-305-posture-swapped**: both values are registered, so this is the swap no vocabulary rule can see. Under the version-1 binding this statement was VALID and the substitution cost nothing: it changed no digest and broke no signature. It is a mismatch now because the binding covers the carried posture object rather than the value of that object's own digest member.
- **bad-306-vocabulary-caught-narrowed**: the caught set decides which labels are caught, and both the recompute and the coverage validity requirements read it, so a producer that narrows it after the run turns a caught row into a clean one. Nothing resisted that under version 1: the vocabulary's own digest re-derives from the arrays beside it and no record's binding moved. Binding the carried digest is what closes it.
- **bad-307-posture-member-added-after-arming**: the consequence the binding change makes normative, in the direction that must fail. The binding covers the carried object, so a member added to the posture after arming invalidates the producer's own statement. Its accepted twin is ok-043, which carries the same member with records committing to it, and the pair is what makes this a rule about WHEN the member was added rather than about whether the posture may carry one at all.

## Compound vectors and precedence pins

`expected` codes form a SET: a rail conforms when its code is in the
set and the verdict matches. Vectors marked COMPOUND carry more than
one condition; every other vector is single-fault by construction.
Most are compound because deriving them singly is impossible without
introducing a different fault. `bad-748` is the exception and is
compound on purpose: a precedence pin can only be written as a
statement carrying both conditions at once, and its expected set names
ONE code so that a rail reporting the other fails rather than passing
on a set widened to accommodate it. Registry precedence pins applied
here:

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

Signature VERIFICATION failure is NEVER a failure code in this suite:
whether a record's signature verifies against a consumer-named key is
the evidence tier's separate, trust-relative question. Every committed
signature here verifies under the derived test public key above. How
many entries the array carries is a different question, answered
without key material and therefore inside validity: `bad-745` carries
a record with zero of them and no signature to verify, `bad-749`
carries a member of the wrong JSON type that holds none either, and
`bad-748` fixes which condition a rail reports when a record with no
entries shares a statement with one whose payload does not decode.

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
  substrate-carrying statements (L193); whether artifact-only
  multi-subject is legal is an open ask (bad-607 keeps a substrate
  row precisely so the rule undeniably applies).
- **Replay of a genuine runEntropy** (stateful-consumer concern) and
  **coherence checks** (MAY): behavior/harness territory, not
  statement-shape vectors.

