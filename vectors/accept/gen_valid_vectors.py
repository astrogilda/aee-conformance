#!/usr/bin/env python3
"""Deterministic generator for the AEE v0.6 ACCEPT (valid) conformance vectors.

Emits ok-001 .. ok-033 as complete, unwrapped in-toto Statement JSON files that a
conforming verifier MUST accept, into the directory containing this script.

Determinism recipe (normative for this suite):
  - Ed25519/RFC 8032 keys with seeds DERIVED from published constants:
        seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")
    roles: substrate-observation-test, wrong-signer-test, statement-test.
    Only PUBLIC keys are ever published; anyone re-derives the seeds.
  - Fixed timestamps: issuedAt 2026-01-01T00:00:00Z, armedAt 2025-12-31T23:59:00Z.
  - Subject name: example-agent-bundle. Attack ids: XA-EXAMPLE-*, XB-EXAMPLE-*.
  - Every digest is DERIVED from a committed synthetic one-line preimage
    (see PREIMAGES below); nothing is hand-typed.
  - Committed files: UTF-8, LF, 2-space indent, JCS (lexicographic) member
    ordering, standard base64 with padding, trailing newline.

All content is synthetic. The producer vocabulary uses only strings the public
predicate specification itself publishes (e.g. policy.egress_sinkhole, none,
sinkhole, egress_captured, no_egress) or obviously synthetic example values.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

OUT_DIR = Path(__file__).resolve().parent

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"
PAYLOAD_TYPE = "application/vnd.example.aee-observation.v1+json"
ISSUED_AT = "2026-01-01T00:00:00Z"
ARMED_AT = "2025-12-31T23:59:00Z"
SUBJECT_NAME = "example-agent-bundle"

# ---------------------------------------------------------------------------
# canonicalization + hashing
# ---------------------------------------------------------------------------


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for the value space this suite uses.

    The suite restricts itself to ASCII strings, small integers, booleans,
    arrays and objects, for which JCS coincides with minimal-separator,
    code-point-sorted JSON.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE PAEv1 over (payloadType, payload)."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def rfc6962_root(leaves: list[bytes]) -> str:
    """RFC 6962 Merkle root; leaf = H(0x00||PAE), node = H(0x01||l||r),
    recursive split at the largest power of two strictly less than n."""

    def mth(entries: list[bytes]) -> bytes:
        n = len(entries)
        if n == 1:
            return hashlib.sha256(b"\x00" + entries[0]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + mth(entries[:k]) + mth(entries[k:])).digest()

    return mth(leaves).hex()


# ---------------------------------------------------------------------------
# derived test keys (public halves only are ever published)
# ---------------------------------------------------------------------------


def derive_key(role: str) -> tuple[Ed25519PrivateKey, bytes, str]:
    seed = hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()
    keyid = sha256_hex(pub)
    return priv, pub, keyid


SUB_PRIV, SUB_PUB, SUB_KEYID = derive_key("substrate-observation-test")
WRONG_PRIV, WRONG_PUB, WRONG_KEYID = derive_key("wrong-signer-test")
STMT_PRIV, STMT_PUB, STMT_KEYID = derive_key("statement-test")

# ---------------------------------------------------------------------------
# synthetic one-line preimages -> every digest in the suite
# ---------------------------------------------------------------------------

PREIMAGES: dict[str, Any] = {
    "subject": "example-agent-bundle-content/v1",
    "substrate": "example-substrate-image-content/v1",
    "catch-policy": {"exampleCatchPolicy": {"mode": "enforce"}},
    "network-posture": {"exampleNetworkPosture": {"posture": "sinkhole"}},
    "run-entropy": "example-run-start-checkpoint/v1",
    "unchecked-binding": "example-unchecked-binding/v1",
}

SUBJECT_DIGEST = sha256_hex(PREIMAGES["subject"].encode())
SUBSTRATE_DIGEST = sha256_hex(PREIMAGES["substrate"].encode())
CATCH_POLICY_DIGEST = sha256_hex(jcs(PREIMAGES["catch-policy"]))
POSTURE_DIGEST = sha256_hex(jcs(PREIMAGES["network-posture"]))
RUN_ENTROPY_DIGEST = sha256_hex(PREIMAGES["run-entropy"].encode())
UNCHECKED_BINDING = sha256_hex(PREIMAGES["unchecked-binding"].encode())

DEFAULT_LABELS = ["egress_captured", "no_egress"]
DEFAULT_CAUGHT = ["egress_captured"]


def vocab_obj(labels: list[str], caught: list[str]) -> dict[str, Any]:
    return {
        "digest": {"sha256": sha256_hex(jcs({"caught": caught, "labels": labels}))},
        "labels": labels,
        "caught": caught,
    }


def corpus_obj(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "example-adversarial-corpus",
        "uri": "pkg:example/adversarial-corpus@1.0.0",
        "digest": {"sha256": sha256_hex(jcs(manifest))},
        "manifest": manifest,
    }


def run_binding(corpus_digest: str) -> str:
    pre = {
        "aeeBindingVersion": "1",
        "catchPolicy": CATCH_POLICY_DIGEST,
        "corpus": corpus_digest,
        "networkPosture": POSTURE_DIGEST,
        "runEntropy": RUN_ENTROPY_DIGEST,
        "subject": SUBJECT_DIGEST,
        "substrate": SUBSTRATE_DIGEST,
    }
    return sha256_hex(jcs(pre))


# ---------------------------------------------------------------------------
# observation record construction
# ---------------------------------------------------------------------------


def make_record(
    kind: str,
    binding: str,
    method: str | None = None,
    note: str | None = None,
    drop_count: int = 0,
    drop_bound: int | None = None,
    extra: dict[str, Any] | None = None,
    signer: str = "substrate",
    keyid_mode: str = "normal",  # normal | garbage | absent
    sig_mode: str = "pae",  # pae | raw
) -> dict[str, Any]:
    payload: dict[str, Any]
    if kind == "interception":
        payload = {
            "aeeKind": "interception",
            "aeeMethod": method or "intercepted",
            "aeeRunBinding": binding,
        }
    elif kind == "arming":
        payload = {
            "aeeKind": "arming",
            "aeeMethod": "intercepted",
            "aeePostureDigest": POSTURE_DIGEST,
            "aeeRunBinding": binding,
            "armedAt": ARMED_AT,
        }
    elif kind == "sealed":
        payload = {
            "aeeDropCount": drop_count,
            "aeeKind": "sealed",
            "aeeMethod": "intercepted",
            "aeePostureDigest": POSTURE_DIGEST,
            "aeeRunBinding": binding,
            "aeeStillArmed": True,
        }
        if drop_bound is not None:
            payload["aeeDropBound"] = drop_bound
    elif kind == "examination":
        payload = {
            "aeeKind": "examination",
            "aeeMethod": "reconstructed",
            "aeeRunBinding": binding,
        }
    else:  # forward-compat unknown kind
        payload = {
            "aeeKind": kind,
            "aeeMethod": method or "intercepted",
            "aeeRunBinding": binding,
        }
    if note is not None:
        payload["producerNote"] = note
    if extra:
        payload.update(extra)

    payload_bytes = jcs(payload)
    priv = SUB_PRIV if signer == "substrate" else WRONG_PRIV
    keyid = SUB_KEYID if signer == "substrate" else WRONG_KEYID
    signed_bytes = (
        pae(PAYLOAD_TYPE, payload_bytes) if sig_mode == "pae" else payload_bytes
    )
    sig = base64.b64encode(priv.sign(signed_bytes)).decode()

    entry: dict[str, str] = {"sig": sig}
    if keyid_mode == "normal":
        entry["keyid"] = keyid
    elif keyid_mode == "garbage":
        entry["keyid"] = "deadbeef" * 8

    return {
        "payload": base64.b64encode(payload_bytes).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [entry],
    }


def make_row(
    attack_id: str,
    observed: str,
    basis: str | None,
    method: str | None,
    layer: str,
    refs: list[int] | None,
    selectors: list[str] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {"attackId": attack_id, "containmentObserved": observed}
    if basis is not None:
        row["basis"] = basis
    if method is not None:
        row["method"] = method
    row["actualLayer"] = layer
    if refs is not None:
        row["observationRefs"] = refs
    if selectors is not None:
        row["observationSelectors"] = selectors
    return row


def make_statement(
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    records: list[dict[str, Any]] | None = None,
    assessed: list[str] | None = None,
    out_of_scope: dict[str, Any] | None = None,
    routed_elsewhere: dict[str, Any] | None = None,
    labels: list[str] | None = None,
    caught: list[str] | None = None,
    with_entropy: bool = True,
    does_not_assert: list[str] | None = None,
    predicate_extra: dict[str, Any] | None = None,
    binding_for_root: str | None = None,
) -> dict[str, Any]:
    labels = DEFAULT_LABELS if labels is None else labels
    caught = DEFAULT_CAUGHT if caught is None else caught
    corpus = corpus_obj(manifest)
    env = {
        "substrate": {
            "name": "example-substrate-image",
            "digest": {"sha256": SUBSTRATE_DIGEST},
        },
        "corpus": corpus,
        "catchPolicy": {"digest": {"sha256": CATCH_POLICY_DIGEST}},
        "networkPosture": {"posture": "sinkhole", "digest": {"sha256": POSTURE_DIGEST}},
        "observationVocabulary": vocab_obj(labels, caught),
    }
    if with_entropy:
        env["runEntropy"] = {"digest": {"sha256": RUN_ENTROPY_DIGEST}}

    caught_set = set(caught)
    label_set = set(labels)

    def carried_result() -> str:
        forced_fail = False
        for r in rows:
            lab = r.get("containmentObserved")
            if lab in caught_set or lab not in label_set:
                forced_fail = True
            if r.get("basis") not in ("substrate", "artifact"):
                forced_fail = True
            if r.get("method") not in ("intercepted", "reconstructed"):
                forced_fail = True
        if forced_fail:
            return "fail"
        if (out_of_scope or {}) or (routed_elsewhere or {}):
            return "degraded"
        return "pass"

    predicate: dict[str, Any] = {
        "result": carried_result(),
        "observationEnvironment": env,
        "coverage": {
            "assessedClasses": assessed
            if assessed is not None
            else sorted(manifest["classes"]),
            "outOfScope": out_of_scope or {},
            "routedElsewhere": routed_elsewhere or {},
        },
        "attackResults": rows,
        "issuedAt": ISSUED_AT,
    }
    if records:
        predicate["observationRecords"] = records
        leaves = [
            pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records
        ]
        predicate["batchRoot"] = rfc6962_root(leaves)
    if does_not_assert is not None:
        predicate["doesNotAssert"] = does_not_assert
    if predicate_extra:
        predicate.update(predicate_extra)

    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": SUBJECT_NAME, "digest": {"sha256": SUBJECT_DIGEST}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


# ---------------------------------------------------------------------------
# the 33 accept vectors
# ---------------------------------------------------------------------------


def build_vectors() -> dict[str, dict[str, Any]]:
    v: dict[str, dict[str, Any]] = {}

    man_1 = {"classes": {"XA": ["XA-EXAMPLE-1"]}}
    b_1 = run_binding(sha256_hex(jcs(man_1)))
    man_2 = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"]}}
    b_2 = run_binding(sha256_hex(jcs(man_2)))
    man_ab = {"classes": {"XA": ["XA-EXAMPLE-1"], "XB": ["XB-EXAMPLE-1"]}}
    b_ab = run_binding(sha256_hex(jcs(man_ab)))
    man_2b = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"], "XB": ["XB-EXAMPLE-1"]}}
    b_2b = run_binding(sha256_hex(jcs(man_2b)))
    man_2b2 = {
        "classes": {
            "XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"],
            "XB": ["XB-EXAMPLE-1", "XB-EXAMPLE-2"],
        }
    }
    b_2b2 = run_binding(sha256_hex(jcs(man_2b2)))

    # ok-001 canonical caught row; single-leaf tree (root == leaf hash)
    v["ok-001-caught-intercepted-fail"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record("interception", b_1, note="example interception observation a")
        ],
    )

    # ok-002 canonical clean pass, arming + sealed, dropCount 0
    v["ok-002-clean-pass-armed-sealed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
    )

    # ok-003 sealed with self-bounded non-zero drop count
    v["ok-003-clean-pass-bounded-drops"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1),
            make_record("sealed", b_1, drop_count=3, drop_bound=5),
        ],
    )

    # ok-004 degraded via outOfScope
    v["ok-004-degraded-out-of-scope"] = make_statement(
        man_ab,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_ab), make_record("sealed", b_ab)],
        assessed=["XA"],
        out_of_scope={"XB": "example: class not assessed in this run"},
    )

    # ok-005 degraded via routedElsewhere
    v["ok-005-degraded-routed-elsewhere"] = make_statement(
        man_ab,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_ab), make_record("sealed", b_ab)],
        assessed=["XA"],
        routed_elsewhere={"XB": "example: class assessed under a separate statement"},
    )

    # ok-006 clean (substrate, reconstructed) covered by examination
    v["ok-006-clean-reconstructed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "reconstructed", "none", [0]
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b")
        ],
    )

    # ok-007 artifact-only, recordless: no records, no batchRoot, no runEntropy
    v["ok-007-artifact-only-recordless"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        with_entropy=False,
    )

    # ok-008 artifact row with unknown method: fail-closed row, carried fail, VALID
    v["ok-008-artifact-fail-closed-method"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "artifact",
                "example_unknown_method",
                "none",
                [],
            )
        ],
        with_entropy=False,
    )

    # ok-009 artifact row with out-of-vocabulary label: fail-closed, VALID
    v["ok-009-artifact-oov-label-fail"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "example_label_a",
                "artifact",
                "reconstructed",
                "none",
                [],
            )
        ],
        with_entropy=False,
    )

    # ok-010 retired 0.4 basis value: out-of-vocabulary, fail-closed, no alias
    v["ok-010-artifact-retired-basis-fail"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate_observed",
                "reconstructed",
                "none",
                [],
            )
        ],
        with_entropy=False,
    )

    # ok-011 two clean rows share one arming+sealed pair
    v["ok-011-shared-run-records"] = make_statement(
        man_2,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
            make_row(
                "XA-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
        ],
        records=[make_record("arming", b_2), make_record("sealed", b_2)],
    )

    # ok-012 observationSelectors parallel to refs; advisory only
    v["ok-012-selectors-present"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate",
                "intercepted",
                "none",
                [0, 1],
                selectors=["example-selector-a", "example-selector-b"],
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
    )

    # ok-013 unknown record kind: covers nothing, still contributes its leaf
    v["ok-013-unknown-kind-extra-record"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1),
            make_record("sealed", b_1),
            make_record("aee-future-x", b_1, note="example future observation"),
        ],
    )

    # ok-014 three records: RFC 6962 recursive split (2+1), no padding
    v["ok-014-three-record-odd-split"] = make_statement(
        man_2,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [1, 2]
            ),
        ],
        records=[
            make_record("interception", b_2, note="example interception observation a"),
            make_record("arming", b_2),
            make_record("sealed", b_2),
        ],
    )

    # ok-015 four-record balanced tree
    v["ok-015-four-record-tree"] = make_statement(
        man_2b,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
            make_row(
                "XB-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [2, 3]
            ),
        ],
        records=[
            make_record("interception", b_2b, note="example interception observation a"),
            make_record("interception", b_2b, note="example interception observation b"),
            make_record("arming", b_2b),
            make_record("sealed", b_2b),
        ],
    )

    # ok-016 caught row with actualLayer none: observed-but-not-enforced
    v["ok-016-caught-actuallayer-none"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "egress_captured", "substrate", "intercepted", "none", [0]
            )
        ],
        records=[
            make_record("interception", b_1, note="example interception observation a")
        ],
    )

    # ok-017 method cap is one-directional: reconstructed row may reference an
    # intercepted-signed record (examination satisfies class-match)
    v["ok-017-method-weakening-allowed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "reconstructed",
                "policy.egress_sinkhole",
                [0, 1],
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b"),
            make_record("interception", b_1, note="example interception observation a"),
        ],
    )

    # ok-018 reserved-prefix predicate members MUST be ignored
    v["ok-018-aee-prefix-ignored"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
        predicate_extra={"evidenceTier": "attested", "aeeInjected": "x"},
    )

    # ok-019 keyid is a hint, never the check: garbage keyid + absent keyid,
    # both signatures verify against the pinned substrate key
    v["ok-019-wrong-keyid-sig-verifies"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1, keyid_mode="garbage"),
            make_record("sealed", b_1, keyid_mode="absent"),
        ],
    )

    # ok-020 signature over raw payload (no PAE): tier fault, never validity
    v["ok-020-non-pae-signature"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record(
                "interception",
                b_1,
                note="example interception observation a",
                sig_mode="raw",
            )
        ],
    )

    # ok-021 producer extra members in a covering payload still cover
    v["ok-021-producer-extra-members"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record(
                "interception",
                b_1,
                note="example interception observation a",
                extra={"extraA": "example-extra-value"},
            )
        ],
    )

    # ok-022 two independent arming records + one sealed
    v["ok-022-two-arming-records"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate",
                "intercepted",
                "none",
                [0, 1, 2],
            )
        ],
        records=[
            make_record("arming", b_1, note="example arming vantage a"),
            make_record("arming", b_1, note="example arming vantage b"),
            make_record("sealed", b_1),
        ],
    )

    # ok-023 payload embeds a tempting public key; consumer MUST NOT TOFU it
    v["ok-023-no-tofu-embedded-key"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record(
                "arming", b_1, extra={"embeddedVerificationKey": SUB_PUB.hex()}
            ),
            make_record("sealed", b_1),
        ],
    )

    # ok-024 exactly three rows: substrate/attested, substrate/unattested
    # (valid signature by the wrong-signer test key), artifact/declared
    v["ok-024-mixed-basis-rows"] = make_statement(
        man_2b,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
            make_row("XB-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", []),
        ],
        records=[
            make_record("interception", b_2b, note="example interception observation a"),
            make_record(
                "interception",
                b_2b,
                note="example interception observation b",
                signer="wrong",
            ),
        ],
    )

    # ok-025 doesNotAssert present: advisory, never required, never weakening
    v["ok-025-does-not-assert-present"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
        does_not_assert=[
            "example: no claim is made about behavior outside the thrown corpus",
            "example: no claim is made about host integrity beyond the substrate attestation",
        ],
    )

    # ok-026 five records: unbalanced RFC 6962 split (4+1)
    v["ok-026-five-record-tree"] = make_statement(
        man_2b2,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
            make_row(
                "XB-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [2],
            ),
            make_row(
                "XB-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [3, 4]
            ),
        ],
        records=[
            make_record("interception", b_2b2, note="example interception observation a"),
            make_record("interception", b_2b2, note="example interception observation b"),
            make_record("interception", b_2b2, note="example interception observation c"),
            make_record("arming", b_2b2),
            make_record("sealed", b_2b2),
        ],
    )

    # ok-027 artifact row with method member ABSENT: fail-closed, carried fail, VALID
    v["ok-027-artifact-missing-method"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", None, "none", [])],
        with_entropy=False,
    )

    # ok-028 empty caught set: vacuously no caught rows, clean pass
    v["ok-028-empty-caught-pass"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
        caught=[],
    )

    # ok-029 artifact rows + unreferenced records + CORRECT batchRoot; no
    # substrate rows => no derived binding, record binding values are unchecked
    v["ok-029-artifact-with-records"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        records=[
            make_record(
                "interception",
                UNCHECKED_BINDING,
                note="example interception observation a",
            ),
            make_record(
                "interception",
                UNCHECKED_BINDING,
                note="example interception observation b",
            ),
        ],
        with_entropy=False,
    )

    # ok-030 min-composition accept half: row method equals the WEAKEST signed
    # aeeMethod across its referenced records {reconstructed, intercepted,
    # reconstructed} = reconstructed
    v["ok-030-method-min-multirecord"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "reconstructed",
                "none",
                [0, 1, 2],
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b"),
            make_record(
                "interception",
                b_1,
                method="intercepted",
                note="example interception observation a",
            ),
            make_record(
                "interception",
                b_1,
                method="reconstructed",
                note="example interception observation b",
            ),
        ],
    )

    # ok-031 caught (substrate, reconstructed) row covered by examination
    v["ok-031-caught-reconstructed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "reconstructed",
                "none",
                [0],
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b")
        ],
    )

    # ok-032 retired 0.4 method value "inferred": out-of-vocabulary, fail-closed
    v["ok-032-method-inferred-retired"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "inferred", "none", [])],
        with_entropy=False,
    )

    # ok-033 artifact-only degraded: recordless parent for coverage-family rejects
    v["ok-033-artifact-degraded"] = make_statement(
        man_ab,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        assessed=["XA"],
        out_of_scope={"XB": "example: class not assessed in this run"},
        with_entropy=False,
    )

    return v


# ---------------------------------------------------------------------------
# independent-ish self-verifier (mirrors the spec's gates; asserts every
# vector is VALID and its carried result recomputes)
# ---------------------------------------------------------------------------

METHOD_RANK = {"reconstructed": 1, "intercepted": 2}


def verify(stmt: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    pred = stmt["predicate"]
    env = pred["observationEnvironment"]
    vocab = env["observationVocabulary"]
    labels, caught = vocab["labels"], vocab["caught"]

    # vocabulary shape + digest
    if sorted(labels) != labels or sorted(caught) != caught:
        errs.append("vocab not sorted")
    if not set(caught) <= set(labels):
        errs.append("caught not subset")
    if vocab["digest"]["sha256"] != sha256_hex(
        jcs({"caught": caught, "labels": labels})
    ):
        errs.append("vocab digest mismatch")
    # corpus digest
    if env["corpus"]["digest"]["sha256"] != sha256_hex(jcs(env["corpus"]["manifest"])):
        errs.append("corpus digest mismatch")

    rows = pred["attackResults"]
    records = pred.get("observationRecords", [])
    substrate_rows = [r for r in rows if r.get("basis") == "substrate"]

    # batchRoot
    if records:
        leaves = [pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records]
        if len(set(leaves)) != len(leaves):
            errs.append("duplicate record")
        if pred.get("batchRoot") != rfc6962_root(leaves):
            errs.append("batchRoot mismatch")
    elif "batchRoot" in pred:
        errs.append("orphan batchRoot")

    # run binding (derivable only for substrate-carrying statements)
    binding = None
    if substrate_rows:
        if "runEntropy" not in env:
            errs.append("runEntropy missing")
        else:
            binding = sha256_hex(
                jcs(
                    {
                        "aeeBindingVersion": "1",
                        "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
                        "corpus": env["corpus"]["digest"]["sha256"],
                        "networkPosture": env["networkPosture"]["digest"]["sha256"],
                        "runEntropy": env["runEntropy"]["digest"]["sha256"],
                        "subject": stmt["subject"][0]["digest"]["sha256"],
                        "substrate": env["substrate"]["digest"]["sha256"],
                    }
                )
            )

    def payload_of(i: int) -> Any:
        raw = base64.b64decode(records[i]["payload"])
        obj = json.loads(raw)
        if jcs(obj) != raw:
            errs.append(f"record {i} payload not canonical")
        return obj

    for r in substrate_rows:
        refs = r.get("observationRefs")
        if not refs:
            errs.append(f"row {r['attackId']}: empty refs")
            continue
        if any(not isinstance(i, int) or i < 0 or i >= len(records) for i in refs):
            errs.append(f"row {r['attackId']}: ref out of range")
            continue
        payloads = {i: payload_of(i) for i in refs}
        for i, p in payloads.items():
            for m in ("aeeRunBinding", "aeeKind", "aeeMethod"):
                if m not in p:
                    errs.append(f"record {i}: missing {m}")
            if binding is not None and p.get("aeeRunBinding") != binding:
                errs.append(f"record {i}: run binding mismatch")
            if not records[i]["payloadType"].endswith("+json"):
                errs.append(f"record {i}: media type")

        kinds = {i: payloads[i].get("aeeKind") for i in refs}
        lab = r.get("containmentObserved")
        is_caught = lab in caught
        is_clean = lab in labels and lab not in caught
        meth = r.get("method")

        def arming_ok(p: dict[str, Any]) -> bool:
            return (
                p.get("armedAt") is not None
                and p.get("armedAt") <= pred["issuedAt"]
                and p.get("aeePostureDigest") == env["networkPosture"]["digest"]["sha256"]
                and p.get("aeeMethod") == "intercepted"
            )

        def sealed_ok(p: dict[str, Any]) -> bool:
            dc = p.get("aeeDropCount")
            bound_ok = dc == 0 or (
                isinstance(p.get("aeeDropBound"), int) and dc <= p["aeeDropBound"]
            )
            return (
                p.get("aeeStillArmed") is True
                and isinstance(dc, int)
                and bound_ok
                and p.get("aeePostureDigest") == env["networkPosture"]["digest"]["sha256"]
                and p.get("aeeMethod") == "intercepted"
            )

        if meth == "reconstructed":
            if not any(kinds[i] == "examination" for i in refs):
                errs.append(f"row {r['attackId']}: no examination cover")
        elif meth == "intercepted":
            if is_caught and not any(kinds[i] == "interception" for i in refs):
                errs.append(f"row {r['attackId']}: no interception cover")
            if is_clean:
                if not any(
                    kinds[i] == "arming" and arming_ok(payloads[i]) for i in refs
                ):
                    errs.append(f"row {r['attackId']}: no covering arming")
                if not any(
                    kinds[i] == "sealed" and sealed_ok(payloads[i]) for i in refs
                ):
                    errs.append(f"row {r['attackId']}: no covering sealed")

        # method cap: row no stronger than weakest signed aeeMethod across refs
        ranks = [
            METHOD_RANK.get(payloads[i].get("aeeMethod"), 0)
            for i in refs
            if kinds[i] in ("interception", "arming", "sealed", "examination")
        ]
        if ranks and METHOD_RANK.get(meth, 0) > min(ranks):
            errs.append(f"row {r['attackId']}: method cap exceeded")

    # result recompute
    forced = any(
        r.get("containmentObserved") in caught
        or r.get("containmentObserved") not in labels
        or r.get("basis") not in ("substrate", "artifact")
        or r.get("method") not in ("intercepted", "reconstructed")
        for r in rows
    )
    cov = pred["coverage"]
    expect = (
        "fail"
        if forced
        else ("degraded" if (cov["outOfScope"] or cov["routedElsewhere"]) else "pass")
    )
    if pred["result"] != expect:
        errs.append(f"result recompute {expect} != carried {pred['result']}")

    # coverage integrity at attack granularity
    manifest = env["corpus"]["manifest"]["classes"]
    by_class: dict[str, set[str]] = {}
    for r in rows:
        cls = next((c for c, ids in manifest.items() if r["attackId"] in ids), None)
        if cls is None:
            errs.append(f"row attack {r['attackId']} not in manifest")
        else:
            by_class.setdefault(cls, set()).add(r["attackId"])
    for c in cov["assessedClasses"]:
        if by_class.get(c, set()) != set(manifest.get(c, [])):
            errs.append(f"class {c}: coverage incomplete")
    for c in list(cov["outOfScope"]) + list(cov["routedElsewhere"]):
        if c in by_class:
            errs.append(f"class {c}: rows present for non-assessed class")

    return errs


def verify_signatures(stmt: dict[str, Any]) -> dict[int, str]:
    """Tier-plane check (informative): which records verify under which key."""
    out: dict[int, str] = {}
    pubs = {
        "substrate-observation-test": Ed25519PublicKey.from_public_bytes(SUB_PUB),
        "wrong-signer-test": Ed25519PublicKey.from_public_bytes(WRONG_PUB),
    }
    for i, rec in enumerate(stmt["predicate"].get("observationRecords", [])):
        raw = base64.b64decode(rec["payload"])
        signed = pae(rec["payloadType"], raw)
        sig = base64.b64decode(rec["signatures"][0]["sig"])
        for name, pub in pubs.items():
            try:
                pub.verify(sig, signed)
                out[i] = name
                break
            except InvalidSignature:
                continue
        else:
            out[i] = "no-pae-verify"
    return out


def main() -> int:
    vectors = build_vectors()
    assert len(vectors) == 33, len(vectors)
    failures = 0
    for name, stmt in vectors.items():
        errs = verify(stmt)
        if errs:
            failures += 1
            print(f"INVALID {name}: {errs}")
        path = OUT_DIR / f"{name}.json"
        text = json.dumps(stmt, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        path.write_text(text, encoding="utf-8")
        json.loads(path.read_text())  # parse check
        print(f"wrote {path.name}  result={stmt['predicate']['result']}")
    print(f"keyids: substrate-observation-test={SUB_KEYID}")
    print(f"        wrong-signer-test={WRONG_KEYID}")
    print(f"        statement-test={STMT_KEYID}")
    sig_map = verify_signatures(vectors["ok-024-mixed-basis-rows"])
    print(f"ok-024 signer map (expect substrate,wrong): {sig_map}")
    sig_map20 = verify_signatures(vectors["ok-020-non-pae-signature"])
    print(f"ok-020 signer map (expect no-pae-verify): {sig_map20}")
    if failures:
        print(f"FAIL: {failures} vectors invalid")
        return 1
    print("all 33 vectors VALID under self-verifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
