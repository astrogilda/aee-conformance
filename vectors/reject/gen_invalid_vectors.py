#!/usr/bin/env python3
"""AEE v0.6 INVALID conformance-vector generator.

Generates the 91 reject vectors of the adversarial-execution-evidence v0.6
conformance suite. Every vector is a COMPLETE in-toto Statement that a
conforming verifier MUST reject for exactly ONE declared reason: each is
derived from a fully-valid parent statement by one mutation plus the declared
rederive chain (re-sign mutated record payloads, recompute the RFC 6962
batchRoot, recompute vocabulary/corpus digests, rederive the run binding),
so no second fault is introduced. A self-check pass asserts second-fault
ABSENCE for every vector and full gate-validity for every parent.

Ground truth: spec/predicates/adversarial-execution-evidence.md @ e5ea1eb
(in-toto/attestation PR #570 branch), version 0.6.0. Every anchor is a line
ref into that single vendored revision, which folds in the review revisions
(the BMP-only string profile and the arming-payload run-chaining members).

Determinism recipe (nothing random, nothing typed):
  - Test key seeds are DERIVED, never stored:
      seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")
    All record signatures here use role "substrate-observation-test".
    keyid = lowercase hex SHA-256 of the raw 32-byte Ed25519 public key.
  - Every digest is derived from a committed one-line synthetic preimage
    (see PREIMAGES below and INDEX.md).
  - Fixed timestamps: issuedAt 2026-01-01T00:00:00Z,
    armedAt 2025-12-31T23:59:00Z (a later armedAt only in bad-702).
  - Attack ids are synthetic: XA-EXAMPLE-*, XB-EXAMPLE-*.
  - Record payloadType: application/vnd.example.aee-observation.v1+json.

Run: python3 gen_invalid_vectors.py   (writes bad-*.json + INDEX.md beside it)
Requires: python3 + the "cryptography" package (Ed25519).
"""

import base64
import copy
import hashlib
import json
import os
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

OUT = os.path.dirname(os.path.abspath(__file__))

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"
PAYLOAD_TYPE = "application/vnd.example.aee-observation.v1+json"
ISSUED_AT = "2026-01-01T00:00:00Z"
ARMED_AT = "2025-12-31T23:59:00Z"


# ---------------------------------------------------------------- primitives

def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for the ASCII/small-int subset used here."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def sha256hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def jcs_digest(obj: Any) -> str:
    return sha256hex(jcs(obj))


def b64(b: bytes) -> str:
    return base64.standard_b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.standard_b64decode(s)


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return (b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " +
            str(len(payload)).encode() + b" " + payload)


def record_pae(rec: dict[str, Any]) -> bytes:
    return pae(rec["payloadType"], unb64(rec["payload"]))


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def merkle_root(records: list[dict[str, Any]]) -> str | None:
    """RFC 6962: leaf H(0x00||PAE), node H(0x01||l||r), recursive split."""
    leaves = [_h(b"\x00" + record_pae(r)) for r in records]

    def node(ls: list[bytes]) -> bytes:
        if len(ls) == 1:
            return ls[0]
        k = 1
        while k * 2 < len(ls):
            k *= 2
        return _h(b"\x01" + node(ls[:k]) + node(ls[k:]))

    return node(leaves).hex() if leaves else None


def merkle_root_no_domain(records: list[dict[str, Any]]) -> str:
    """WRONG on purpose (bad-402): no 0x00/0x01 domain separation."""
    leaves = [_h(record_pae(r)) for r in records]

    def node(ls: list[bytes]) -> bytes:
        if len(ls) == 1:
            return ls[0]
        k = 1
        while k * 2 < len(ls):
            k *= 2
        return _h(node(ls[:k]) + node(ls[k:]))

    return node(leaves).hex()


def merkle_root_dup_pad(records: list[dict[str, Any]]) -> str:
    """WRONG on purpose (bad-403): duplicate-last-leaf padding rounds."""
    level = [_h(b"\x00" + record_pae(r)) for r in records]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [_h(b"\x01" + level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def hex_tamper(h: str) -> str:
    return ("1" if h[0] == "0" else "0") + h[1:]


# ---------------------------------------------------------------- test key

def key_for(role: str) -> tuple[Ed25519PrivateKey, bytes, str]:
    seed = hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub, sha256hex(pub)


SUB_PRIV, SUB_PUB, SUB_KEYID = key_for("substrate-observation-test")


# ---------------------------------------------------------------- preimages

PREIMAGES = {
    "subject": "example-agent-bundle-content/v1",
    "subject-b": "example-agent-bundle-b-content/v1",
    "substrate": "example-substrate-image-content/v1",
    "run-entropy": "example-run-start-entropy/v1",
    "intercepted-bytes-1": "example-intercepted-bytes/v1",
    "intercepted-bytes-2": "example-intercepted-bytes/v2",
    "unchecked-binding": "example-unchecked-binding-bytes/v1",
    "other-posture": "example-other-posture-config/v1",
    "stale-vocabulary": "example-stale-vocabulary/v1",
    "stale-corpus": "example-stale-corpus/v1",
    "orphan-root": "example-orphan-root/v1",
}
D = {k: sha256hex(v.encode()) for k, v in PREIMAGES.items()}

CATCHPOLICY_OBJ = {"example": "catch-policy", "mode": "enforcing"}
POSTURE_OBJ = {"example": "posture-config", "posture": "sinkhole"}
CATCHPOLICY_D = jcs_digest(CATCHPOLICY_OBJ)
POSTURE_D = jcs_digest(POSTURE_OBJ)

M1 = {"classes": {"XA": ["XA-EXAMPLE-1"]}}
M2 = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"]}}
MAB = {"classes": {"XA": ["XA-EXAMPLE-1"], "XB": ["XB-EXAMPLE-1"]}}
M_ALT = {"classes": {"XA": ["XA-EXAMPLE-1"], "XZ": ["XZ-EXAMPLE-9"]}}


# ---------------------------------------------------------------- builders

def environment(manifest: dict[str, Any], entropy: bool = True,
                labels: list[str] | None = None,
                caught: list[str] | None = None) -> dict[str, Any]:
    labels = ["egress_captured", "no_egress"] if labels is None else labels
    caught = ["egress_captured"] if caught is None else caught
    # Deep-copy the manifest so no built statement aliases a module-level
    # constant: a mutator like _b804 (which appends to classes["XB"] in
    # place) must never leak its fault into later vectors built from the
    # same shared manifest (that aliasing once gave bad-807 a second
    # fault: manifest-duplicate-attack inherited from bad-804).
    manifest = copy.deepcopy(manifest)
    env = {
        "substrate": {"name": "example-substrate-image",
                      "digest": {"sha256": D["substrate"]}},
        "corpus": {"name": "example-corpus",
                   "uri": "pkg:example/example-corpus@1.0.0",
                   "digest": {"sha256": jcs_digest(manifest)},
                   "manifest": manifest},
        "catchPolicy": {"digest": {"sha256": CATCHPOLICY_D}},
        "networkPosture": {"posture": "sinkhole",
                           "digest": {"sha256": POSTURE_D}},
        "observationVocabulary": {
            "digest": {"sha256": jcs_digest({"caught": caught,
                                             "labels": labels})},
            "labels": labels, "caught": caught},
    }
    if entropy:
        env["runEntropy"] = {"digest": {"sha256": D["run-entropy"]}}
    return env


def binding_preimage(env: dict[str, Any], subject_sha: str | None = None,
                     version: str = "1") -> dict[str, str]:
    return {
        "aeeBindingVersion": version,
        "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
        "corpus": env["corpus"]["digest"]["sha256"],
        "networkPosture": env["networkPosture"]["digest"]["sha256"],
        "runEntropy": env["runEntropy"]["digest"]["sha256"],
        "subject": subject_sha or D["subject"],
        "substrate": env["substrate"]["digest"]["sha256"],
    }


def binding_for(env: dict[str, Any], **kw: Any) -> str:
    return sha256hex(jcs(binding_preimage(env, **kw)))


def sign_bytes(payload: bytes, ptype: str = PAYLOAD_TYPE) -> dict[str, Any]:
    sig = SUB_PRIV.sign(pae(ptype, payload))
    return {"payload": b64(payload), "payloadType": ptype,
            "signatures": [{"keyid": SUB_KEYID, "sig": b64(sig)}]}


def record(payload_obj: Any, ptype: str = PAYLOAD_TYPE) -> dict[str, Any]:
    return sign_bytes(jcs(payload_obj), ptype)


def interception_payload(binding: str, method: str = "intercepted",
                         commit: str = "intercepted-bytes-1") -> dict[str, str]:
    return {"aeeKind": "interception", "aeeMethod": method,
            "aeeRunBinding": binding, "commitment": D[commit],
            "producerNote": "example interception"}


def arming_payload(binding: str, armed_at: str = ARMED_AT, posture: str = POSTURE_D,
                   method: str = "intercepted") -> dict[str, str]:
    return {"aeeKind": "arming", "aeeMethod": method,
            "aeeRunBinding": binding, "aeePostureDigest": posture,
            "armedAt": armed_at}


def sealed_payload(binding: str, still: bool = True, drop: int = 0,
                   bound: int | None = None, posture: str = POSTURE_D,
                   method: str = "intercepted") -> dict[str, Any]:
    p = {"aeeKind": "sealed", "aeeMethod": method, "aeeRunBinding": binding,
         "aeePostureDigest": posture, "aeeStillArmed": still,
         "aeeDropCount": drop}
    if bound is not None:
        p["aeeDropBound"] = bound
    return p


def examination_payload(binding: str, method: str = "reconstructed") -> dict[str, Any]:
    return {"aeeKind": "examination", "aeeMethod": method,
            "aeeRunBinding": binding,
            "statesCompared": ["example-state-a", "example-state-b"]}


def caught_row(refs: tuple[int, ...] = (0,), attack: str = "XA-EXAMPLE-1",
               basis: str = "substrate", method: str = "intercepted",
               layer: str = "policy.egress_sinkhole",
               label: str = "egress_captured") -> dict[str, Any]:
    return {"attackId": attack, "containmentObserved": label, "basis": basis,
            "method": method, "actualLayer": layer,
            "observationRefs": list(refs)}


def clean_row(refs: tuple[int, ...] = (0, 1), attack: str = "XA-EXAMPLE-1",
              basis: str = "substrate",
              method: str = "intercepted") -> dict[str, Any]:
    return {"attackId": attack, "containmentObserved": "no_egress",
            "basis": basis, "method": method, "actualLayer": "none",
            "observationRefs": list(refs)}


def artifact_row(attack: str = "XA-EXAMPLE-1", label: str = "egress_captured",
                 method: str = "intercepted", basis: str = "artifact",
                 layer: str = "none") -> dict[str, str]:
    # observationRefs intentionally absent: refs on artifact rows are
    # unconstrained by the spec (open question; suite pins spec-literal).
    return {"attackId": attack, "containmentObserved": label, "basis": basis,
            "method": method, "actualLayer": layer}


def statement(env: dict[str, Any], rows: list[dict[str, Any]],
              records: list[dict[str, Any]] | None = None, result: str = "pass",
              coverage: dict[str, Any] | None = None,
              subject: list[dict[str, Any]] | None = None,
              batch_root: str = "auto") -> dict[str, Any]:
    pred: dict[str, Any] = {
        "result": result,
        "observationEnvironment": env,
        "coverage": coverage if coverage is not None else
            {"assessedClasses": ["XA"], "outOfScope": {},
             "routedElsewhere": {}},
        "attackResults": rows,
        "issuedAt": ISSUED_AT,
    }
    if records is not None:
        pred["observationRecords"] = records
        pred["batchRoot"] = (merkle_root(records) if batch_root == "auto"
                             else batch_root)
    return {"_type": STATEMENT_TYPE,
            "subject": subject or [{"name": "example-agent-bundle",
                                    "digest": {"sha256": D["subject"]}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": pred}


def reroot(st: dict[str, Any]) -> dict[str, Any]:
    st["predicate"]["batchRoot"] = merkle_root(
        st["predicate"]["observationRecords"])
    return st


# ---------------------------------------------------------------- parents
# In-memory equivalents of the BUILD accept shapes (the accept suite lands
# separately); each parent is asserted fully valid by the self-check below.

def P_caught() -> dict[str, Any]:  # ok-001 shape: caught substrate/intercepted, 1 interception
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [caught_row()], [record(interception_payload(b))],
                     result="fail")


def P_clean() -> dict[str, Any]:  # ok-002 shape: clean pass, arming + sealed(drop 0)
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [clean_row()],
                     [record(arming_payload(b)), record(sealed_payload(b))],
                     result="pass")


def P_clean_bounded() -> dict[str, Any]:  # ok-003 shape: sealed(drop 3, bound 5)
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [clean_row()],
                     [record(arming_payload(b)),
                      record(sealed_payload(b, drop=3, bound=5))],
                     result="pass")


def P_degraded() -> dict[str, Any]:  # ok-004 shape: clean substrate row + outOfScope class
    env = environment(MAB)
    b = binding_for(env)
    return statement(env, [clean_row()],
                     [record(arming_payload(b)), record(sealed_payload(b))],
                     result="degraded",
                     coverage={"assessedClasses": ["XA"],
                               "outOfScope": {"XB": "example scope reason"},
                               "routedElsewhere": {}})


def P_reconstructed() -> dict[str, Any]:  # ok-006 shape: caught substrate/reconstructed + exam
    env = environment(M1)
    b = binding_for(env)
    return statement(env,
                     [caught_row(method="reconstructed", layer="none")],
                     [record(examination_payload(b))], result="fail")


def P_artifact() -> dict[str, Any]:  # ok-007 shape: artifact-only, recordless, no entropy
    env = environment(M1, entropy=False)
    return statement(env, [artifact_row()], result="fail")


def P_artifact_unknown_method() -> dict[str, Any]:  # ok-008 shape: fail-closed method, valid
    env = environment(M1, entropy=False)
    return statement(env, [artifact_row(label="no_egress",
                                        method="example.method-x")],
                     result="fail")


def P_artifact_oov_label() -> dict[str, Any]:  # ok-009 shape: fail-closed label, valid
    env = environment(M1, entropy=False)
    return statement(env, [artifact_row(label="example_label_x")],
                     result="fail")


def P_two_attacks() -> dict[str, Any]:  # ok-011 shape: two caught rows, two interceptions
    env = environment(M2)
    b = binding_for(env)
    return statement(env,
                     [caught_row(refs=(0,)),
                      caught_row(refs=(1,), attack="XA-EXAMPLE-2")],
                     [record(interception_payload(b)),
                      record(interception_payload(
                          b, commit="intercepted-bytes-2"))],
                     result="fail")


def P_three_records() -> dict[str, Any]:  # ok-014 shape: 3-record odd-split tree
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [clean_row()],
                     [record(arming_payload(b)), record(sealed_payload(b)),
                      record(interception_payload(b))],
                     result="pass")


def P_artifact_with_records() -> dict[str, Any]:  # ok-029 shape: artifact rows + 2 records
    env = environment(M1, entropy=False)
    ub = D["unchecked-binding"]  # no substrate rows => no derived binding
    return statement(env, [artifact_row()],
                     [record(interception_payload(ub)),
                      record(interception_payload(
                          ub, commit="intercepted-bytes-2"))],
                     result="fail")


def P_multirecord() -> dict[str, Any]:  # ok-030 shape: caught row covered by TWO interceptions
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [caught_row(refs=(0, 1))],
                     [record(interception_payload(b)),
                      record(interception_payload(
                          b, commit="intercepted-bytes-2"))],
                     result="fail")


def P_artifact_degraded() -> dict[str, Any]:  # ok-033 shape: artifact-only degraded
    env = environment(MAB, entropy=False)
    return statement(env, [artifact_row(label="no_egress")],
                     result="degraded",
                     coverage={"assessedClasses": ["XA"],
                               "outOfScope": {"XB": "example scope reason"},
                               "routedElsewhere": {}})


PARENTS = {
    "ok-001 shape (caught intercepted, 1 interception)": P_caught,
    "ok-002 shape (clean pass, arming+sealed drop 0)": P_clean,
    "ok-003 shape (clean pass, sealed drop 3 bound 5)": P_clean_bounded,
    "ok-004 shape (clean substrate row, outOfScope class, degraded)": P_degraded,
    "ok-006 shape (caught reconstructed, examination)": P_reconstructed,
    "ok-007 shape (artifact-only recordless)": P_artifact,
    "ok-008 shape (artifact row, fail-closed method, valid fail)": P_artifact_unknown_method,
    "ok-009 shape (artifact row, fail-closed label, valid fail)": P_artifact_oov_label,
    "ok-011 shape (two caught rows, two interceptions)": P_two_attacks,
    "ok-014 shape (three-record odd-split tree)": P_three_records,
    "ok-029 shape (artifact rows + unreferenced records + root)": P_artifact_with_records,
    "ok-030 shape (caught row covered by two interceptions)": P_multirecord,
    "ok-033 shape (artifact-only degraded)": P_artifact_degraded,
}


# ---------------------------------------------------------------- vectors

VECTORS: list[dict[str, Any]] = []


def vec(vid: str, parent: str, mutation: str, rederive: list[str],
        conds: list[int], codes: list[str],
        build: Callable[[], dict[str, Any]], compound: bool = False,
        spec: str = "", note: str = "") -> None:
    VECTORS.append({"id": vid, "parent": parent, "mutation": mutation,
                    "rederive": rederive, "conds": conds, "codes": codes,
                    "compound": compound, "spec": spec, "note": note,
                    "build": build})


def set_result(parentfn: Callable[[], dict[str, Any]],
               value: str) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = parentfn()
        st["predicate"]["result"] = value
        return st
    return b


def set_refs(parentfn: Callable[[], dict[str, Any]], row_idx: int,
             refs: list[Any]) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = parentfn()
        st["predicate"]["attackResults"][row_idx]["observationRefs"] = refs
        return st
    return b


def mutate_record_payload(st: dict[str, Any], idx: int,
                          mutfn: Callable[[dict[str, Any]], dict[str, Any]],
                          ptype: str | None = None) -> dict[str, Any]:
    """Rebuild record idx: parse payload, apply mutfn, re-sign, re-root."""
    recs = st["predicate"]["observationRecords"]
    obj = json.loads(unb64(recs[idx]["payload"]))
    obj = mutfn(obj)
    recs[idx] = record(obj, ptype or recs[idx]["payloadType"])
    return reroot(st)


def raw_record_bytes(st: dict[str, Any], idx: int, payload_bytes: bytes,
                     ptype: str = PAYLOAD_TYPE) -> dict[str, Any]:
    """Rebuild record idx over EXACT raw payload bytes; re-sign, re-root."""
    st["predicate"]["observationRecords"][idx] = sign_bytes(payload_bytes,
                                                            ptype)
    return reroot(st)


# --- (a) result recompute -------------------------------------------------

vec("bad-001-result-uppercase", "ok-002", 'result: "PASS"', [],
    [1, 2], ["result-vocabulary", "result-recompute-mismatch"],
    set_result(P_clean, "PASS"), compound=True, spec="L260; L215-218",
    note="uppercase token is both out-of-vocabulary and not the recompute")
vec("bad-002-result-mismatch-caught", "ok-001",
    'carried result: "pass" over a caught row (recompute: fail)', [],
    [2], ["result-recompute-mismatch"], set_result(P_caught, "pass"),
    spec="L215-218; L262-264")
vec("bad-003-result-mismatch-oov-label", "ok-009",
    'carried result: "pass" over a fail-closed out-of-vocabulary label', [],
    [2, 4], ["result-recompute-mismatch"],
    set_result(P_artifact_oov_label, "pass"), spec="L264-265")
vec("bad-004-result-mismatch-failclosed", "ok-008",
    'carried result: "pass" over a fail-closed unknown method row', [],
    [2, 5], ["result-recompute-mismatch"],
    set_result(P_artifact_unknown_method, "pass"), spec="L265-266")
vec("bad-005-result-mismatch-coverage-gap", "ok-004",
    'carried result: "pass" with a non-empty coverage.outOfScope', [],
    [2, 6], ["result-recompute-mismatch"], set_result(P_degraded, "pass"),
    spec="L266-267")
vec("bad-006-result-fail-on-pass", "ok-002",
    'carried result: "fail" where the recompute derives pass', [],
    [2], ["result-recompute-mismatch"], set_result(P_clean, "fail"),
    spec="L215-218", note="equality is two-directional")
vec("bad-007-result-degraded-on-pass", "ok-002",
    'carried result: "degraded" where the recompute derives pass', [],
    [2], ["result-recompute-mismatch"], set_result(P_clean, "degraded"),
    spec="L215-218")
vec("bad-008-result-unknown-token", "ok-002", 'result: "error"', [],
    [1, 2], ["result-vocabulary", "result-recompute-mismatch"],
    set_result(P_clean, "error"), compound=True, spec="L260")

# --- (b1) refs / class-match ---------------------------------------------

vec("bad-101-refs-empty", "ok-001",
    "caught substrate row observationRefs: []", [],
    [10, 12], ["refs-empty", "caught-row-uncovered"],
    set_refs(P_caught, 0, []), compound=True, spec="L278; L280-282",
    note="an empty ref set on a caught row inherently also uncovers it")
vec("bad-102-ref-out-of-range", "ok-001",
    "observationRefs: [0, 7] with one record (valid cover kept)", [],
    [11], ["ref-out-of-range"], set_refs(P_caught, 0, [0, 7]),
    spec="L278-279")
vec("bad-103-ref-negative", "ok-001", "observationRefs: [0, -1]", [],
    [11], ["ref-malformed"], set_refs(P_caught, 0, [0, -1]),
    spec="L278-279")


def _b104() -> dict[str, Any]:
    st = P_caught()
    b = binding_for(st["predicate"]["observationEnvironment"])
    st["predicate"]["observationRecords"].append(record(arming_payload(b)))
    st["predicate"]["attackResults"][0]["observationRefs"] = [1]
    return reroot(st)


vec("bad-104-caught-refs-arming-only", "ok-001",
    "append a fully-valid arming record; caught intercepted row refs only it",
    ["recompute-batch-root"], [12], ["caught-row-uncovered"], _b104,
    spec="L280-282")


def _b105() -> dict[str, Any]:
    st = P_reconstructed()
    b = binding_for(st["predicate"]["observationEnvironment"])
    st["predicate"]["observationRecords"].append(
        record(interception_payload(b)))
    st["predicate"]["attackResults"][0]["observationRefs"] = [1]
    return reroot(st)


vec("bad-105-reconstructed-refs-interception", "ok-006",
    "append a fully-valid interception record; reconstructed row refs only it",
    ["recompute-batch-root"], [13], ["reconstructed-row-uncovered"], _b105,
    spec="L282-283")
vec("bad-106-clean-missing-sealed", "ok-002",
    "clean row refs the arming record only", [],
    [14], ["clean-row-uncovered"], set_refs(P_clean, 0, [0]),
    spec="L283-286")
vec("bad-107-clean-missing-arming", "ok-002",
    "clean row refs the sealed record only", [],
    [14], ["clean-row-uncovered"], set_refs(P_clean, 0, [1]),
    spec="L283-286")
vec("bad-108-ref-non-integer", "ok-001", "observationRefs: [0, 1.5]", [],
    [11], ["ref-malformed"], set_refs(P_caught, 0, [0, 1.5]),
    spec="L278-279")

# --- (b2) covering payload canonicality ----------------------------------


def _b201() -> dict[str, Any]:
    st = P_caught()
    obj = json.loads(unb64(
        st["predicate"]["observationRecords"][0]["payload"]))
    parts = [f'"{k}":{json.dumps(obj[k], separators=(",", ":"))}'
             for k in sorted(obj, reverse=True)]
    return raw_record_bytes(st, 0, ("{" + ",".join(parts) + "}").encode())


vec("bad-201-payload-unsorted-keys", "ok-001",
    "covering payload re-serialized with reverse-sorted member order",
    ["re-sign-record", "recompute-batch-root"], [17],
    ["payload-not-canonical"], _b201, spec="L287-288; L625-630",
    note="rawBytes: the committed base64 payload bytes are the fault; "
         "identical content, non-JCS order")


def _b202() -> dict[str, Any]:
    st = P_caught()
    return mutate_record_payload(
        st, 0, lambda o: {**o, "extraA": 9007199254740993})


vec("bad-202-payload-bignum", "ok-001",
    "covering payload gains an integer member 2^53+1",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b202, spec="L627-629; L67-70", note="rawBytes")


def _b203() -> dict[str, Any]:
    st = P_caught()
    obj = json.loads(unb64(
        st["predicate"]["observationRecords"][0]["payload"]))
    parts = []
    for k in sorted(obj):
        parts.append(f'"{k}":{json.dumps(obj[k], separators=(",", ":"))}')
        if k == "aeeMethod":
            parts.append(
                f'"{k}":{json.dumps(obj[k], separators=(",", ":"))}')
    return raw_record_bytes(st, 0, ("{" + ",".join(parts) + "}").encode())


vec("bad-203-payload-duplicate-member", "ok-001",
    "byte-crafted duplicate aeeMethod member in the covering payload",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b203, spec="L627-629", note="rawBytes")


def _b204() -> dict[str, Any]:
    st = P_caught()
    recs = st["predicate"]["observationRecords"]
    return raw_record_bytes(st, 0, unb64(recs[0]["payload"]),
                            ptype="application/octet-stream")


vec("bad-204-payload-media-type", "ok-001",
    'covering record payloadType: "application/octet-stream"',
    ["re-sign-record", "recompute-batch-root"], [19], ["payload-media-type"],
    _b204, spec="L630-631",
    note="PAE covers payloadType, so the record is re-signed: the media "
         "type is the ONLY fault")


def _drop_member(member: str) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = P_caught()
        return mutate_record_payload(
            st, 0, lambda o: {k: v for k, v in o.items() if k != member})
    return b


def _b208() -> dict[str, Any]:
    st = P_caught()
    return mutate_record_payload(
        st, 0, lambda o: {**o, "zz\U0001F600": "example-value"})


vec("bad-208-payload-member-non-bmp", "ok-001",
    "covering payload gains a member whose NAME carries the supplementary-"
    "plane code point U+1F600",
    ["re-sign-record", "recompute-batch-root"], [87],
    ["payload-not-canonical"], _b208,
    spec="L72-86",
    note="rawBytes; BMP-only string profile: the name sorts last under BOTH "
         "the UTF-16 and the code-point member order, so the payload bytes "
         "stay canonical under either reading and the supplementary-plane "
         "member NAME is the single fault (a supplementary-plane member "
         "VALUE stays legal)")
vec("bad-205-payload-missing-runbinding", "ok-001",
    "drop aeeRunBinding from the covering payload",
    ["re-sign-record", "recompute-batch-root"], [20],
    ["payload-missing-reserved"], _drop_member("aeeRunBinding"),
    spec="L288-289; L631-635")
vec("bad-206-payload-missing-kind", "ok-001",
    "drop aeeKind from the covering payload",
    ["re-sign-record", "recompute-batch-root"], [20],
    ["payload-missing-reserved"], _drop_member("aeeKind"),
    spec="L288-289; L635-649")
vec("bad-207-payload-missing-method", "ok-001",
    "drop aeeMethod from the covering payload",
    ["re-sign-record", "recompute-batch-root"], [20],
    ["payload-missing-reserved"], _drop_member("aeeMethod"),
    spec="L288-289; L649-651")

# --- (b3/b4) binding + method cap ----------------------------------------


def _b301() -> dict[str, Any]:
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    alt_env = copy.deepcopy(env)
    alt_env["corpus"]["digest"]["sha256"] = jcs_digest(M_ALT)
    b_alt = binding_for(alt_env)
    st["predicate"]["observationRecords"] = [
        record(arming_payload(b_alt)), record(sealed_payload(b_alt))]
    return reroot(st)


vec("bad-301-run-binding-splice", "ok-002",
    "records signed under a binding derived from a DIFFERENT corpus digest "
    "(cross-run splice)", ["recompute-batch-root"], [22, 62],
    ["run-binding-mismatch"], _b301, spec="L289-290; L121-126",
    note="the statement's own corpus is unchanged; the records were earned "
         "under another run's environment")


def _b302() -> dict[str, Any]:
    st = P_caught()
    return mutate_record_payload(
        st, 0, lambda o: {**o, "aeeMethod": "reconstructed"})


vec("bad-302-method-inflation", "ok-001",
    'row method "intercepted"; sole covering record signed '
    '"reconstructed"', ["re-sign-record", "recompute-batch-root"], [23],
    ["method-cap-exceeded"], _b302, spec="L291-292")


def _b303() -> dict[str, Any]:
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    b2 = sha256hex(jcs(binding_preimage(env, version="2")))
    st["predicate"]["observationRecords"] = [
        record(arming_payload(b2)), record(sealed_payload(b2))]
    return reroot(st)


vec("bad-303-binding-version-2", "ok-002",
    'records signed with a binding derived from an "aeeBindingVersion": '
    '"2" pre-image', ["derive-binding-v2", "re-sign-record",
                      "recompute-batch-root"], [75, 22],
    ["run-binding-mismatch"], _b303, spec="L131-135; L289-290",
    note="negative known-answer: the v2 pre-image MUST NOT match; a "
         "verifier has exactly one construction and never tries a second")


def _b304() -> dict[str, Any]:
    st = P_multirecord()
    return mutate_record_payload(
        st, 1, lambda o: {**o, "aeeMethod": "reconstructed"})


vec("bad-304-method-cap-multirecord", "ok-030",
    'row method "intercepted" covered by TWO interceptions with signed '
    "methods {intercepted, reconstructed}: exceeds the weakest",
    ["re-sign-record", "recompute-batch-root"], [23, 45],
    ["method-cap-exceeded"], _b304, spec="L291-292",
    note="min-composition: a max()/any() rail wrongly accepts this")

# --- (b5) batchRoot / RFC 6962 -------------------------------------------


def _b401() -> dict[str, Any]:
    st = P_clean()
    del st["predicate"]["batchRoot"]
    return st


vec("bad-401-records-no-batchroot", "ok-002",
    "batchRoot member removed while observationRecords is non-empty", [],
    [24], ["batch-root-missing"], _b401, spec="L736; L748-750")


def _b402() -> dict[str, Any]:
    st = P_three_records()
    st["predicate"]["batchRoot"] = merkle_root_no_domain(
        st["predicate"]["observationRecords"])
    return st


vec("bad-402-root-no-domain-separation", "ok-014",
    "root computed without the 0x00/0x01 domain-separation prefixes", [],
    [25], ["batch-root-mismatch"], _b402, spec="L738-741")


def _b403() -> dict[str, Any]:
    st = P_three_records()
    st["predicate"]["batchRoot"] = merkle_root_dup_pad(
        st["predicate"]["observationRecords"])
    return st


vec("bad-403-root-bitcoin-padding", "ok-014",
    "3-leaf root computed by duplicate-last-leaf padding instead of the "
    "RFC 6962 recursive split", [], [26], ["batch-root-mismatch"], _b403,
    spec="L741-743")


def _b404() -> dict[str, Any]:
    st = P_three_records()
    recs = st["predicate"]["observationRecords"]
    st["predicate"]["batchRoot"] = merkle_root([recs[1], recs[0], recs[2]])
    return st


vec("bad-404-root-leaf-order-swapped", "ok-014",
    "root computed over leaves in swapped order", [], [27],
    ["batch-root-mismatch"], _b404, spec="L743")


def _b405() -> dict[str, Any]:
    st = P_clean()
    recs = st["predicate"]["observationRecords"]
    recs.append(copy.deepcopy(recs[0]))
    return reroot(st)


vec("bad-405-duplicate-records", "ok-002",
    "two byte-identical records in the tree; root recomputes CORRECTLY "
    "over all three leaves", ["recompute-batch-root"], [29],
    ["duplicate-record"], _b405, spec="L745-746",
    note="single fault: duplicate identity, not root arithmetic")


def _b406() -> dict[str, Any]:
    st = P_clean()
    st["predicate"]["batchRoot"] = hex_tamper(st["predicate"]["batchRoot"])
    return st


vec("bad-406-root-hex-tamper", "ok-002",
    "one hex digit of batchRoot flipped", [], [30], ["batch-root-mismatch"],
    _b406, spec="L748-750")


def _b407() -> dict[str, Any]:
    st = P_caught()
    del st["predicate"]["observationRecords"]
    del st["predicate"]["batchRoot"]
    return st


vec("bad-407-substrate-row-no-records", "ok-001",
    "remove observationRecords AND batchRoot under a substrate row "
    "(2-op mutation)", [], [31, 11], ["records-absent", "ref-out-of-range"],
    _b407, compound=True, spec="L753-757; L278-279",
    note="precedence pin: records-absent is reported when the array is "
         "absent entirely; ref-out-of-range only when records exist")


def _b408() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["batchRoot"] = D["orphan-root"]
    return st


vec("bad-408-batchroot-without-records", "ok-007",
    "orphan batchRoot added to a recordless artifact-only statement", [],
    [31], ["batch-root-orphaned"], _b408, spec="L753-757; L744")


def _b409() -> dict[str, Any]:
    st = P_artifact_with_records()
    st["predicate"]["batchRoot"] = hex_tamper(st["predicate"]["batchRoot"])
    return st


vec("bad-409-artifact-records-bad-root", "ok-029",
    "one hex digit off on an artifact-only-with-records statement", [],
    [30, 24], ["batch-root-mismatch"], _b409, spec="L748-750",
    note="the root check is statement-level: it runs even with zero "
         "substrate rows")

# --- (d/e) basis / method / actualLayer ----------------------------------


def _row_mut(parentfn: Callable[[], dict[str, Any]], row_idx: int,
             mutfn: Callable[[dict[str, Any]], dict[str, Any]]
             ) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = parentfn()
        rows = st["predicate"]["attackResults"]
        rows[row_idx] = mutfn(rows[row_idx])
        return st
    return b


vec("bad-501-substrate-unknown-method", "ok-001",
    'substrate row method: "example.method-x" (unknown value); refs, '
    "records, root, entropy intact; carried fail kept", [],
    [44, 5, 42], ["fail-closed-substrate-row"],
    _row_mut(P_caught, 0, lambda r: {**r, "method": "example.method-x"}),
    spec="L305-309; L467-470",
    note="pairs with ok-008: the SAME fail-closed axis on an artifact row "
         "is a VALID fail")
vec("bad-502-missing-actual-layer", "ok-001",
    "drop actualLayer from the row", [], [47],
    ["malformed-missing-actual-layer"],
    _row_mut(P_caught, 0,
             lambda r: {k: v for k, v in r.items() if k != "actualLayer"}),
    spec="L374-375; L590-598",
    note="malformed STATEMENT, deliberately NOT a fail-closed row: a "
         "verifier answering result:fail here fails conformance")
vec("bad-503-clean-row-layer-not-none", "ok-002",
    'clean row actualLayer: "policy.egress_sinkhole" (MUST be the literal '
    '"none")', [], [48], ["clean-row-layer-not-none"],
    _row_mut(P_clean, 0,
             lambda r: {**r, "actualLayer": "policy.egress_sinkhole"}),
    spec="L599-604")
vec("bad-504-substrate-oov-label", "ok-001",
    'substrate row containmentObserved: "example_label_a" (not in carried '
    "labels); carried fail kept", [], [4, 44],
    ["fail-closed-substrate-row"],
    _row_mut(P_caught, 0,
             lambda r: {**r, "containmentObserved": "example_label_a"}),
    spec="L264-265; L305-309",
    note="pairs with ok-009 (artifact twin stays valid)")
vec("bad-505-substrate-missing-method", "ok-001",
    "substrate row method member ABSENT", [], [5, 42, 44],
    ["fail-closed-substrate-row"],
    _row_mut(P_caught, 0,
             lambda r: {k: v for k, v in r.items() if k != "method"}),
    spec="L265-266; L467-470; L305-309",
    note="pairs with ok-027 (artifact row with absent method is a VALID "
         "fail)")
vec("bad-506-actuallayer-json-number", "ok-001",
    "caught row actualLayer carried as the JSON number 7 (wrong member "
    "type); refs, records, root, entropy intact; carried fail kept", [],
    [88], ["statement-malformed"],
    _row_mut(P_caught, 0, lambda r: {**r, "actualLayer": 7}),
    spec="L369-375",
    note="type-strictness pin: row members are strings, and a wrong-typed "
         "member is a decode-layer fault, deliberately a DIFFERENT altitude "
         "than an absent one — a rail that maps the number to member "
         "absence (malformed-missing-actual-layer) fails conformance here")

# --- (f/g) vocabulary + runEntropy + subject -----------------------------


def _b601() -> dict[str, Any]:
    st = P_artifact()
    del st["predicate"]["observationEnvironment"]["observationVocabulary"]
    return st


vec("bad-601-vocabulary-absent", "ok-007",
    "drop observationVocabulary; carried fail kept", [], [51],
    ["vocabulary-missing"], _b601, spec="L339-347",
    note="artifact-only parent: no digest or binding cascade")


def _vocab_mut(labels: list[str] | None = None,
               caught: list[str] | None = None, redigest: bool = True,
               stale: bool = False) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = P_clean() if labels != [] else P_caught()
        env = st["predicate"]["observationEnvironment"]
        v = env["observationVocabulary"]
        if labels is not None:
            v["labels"] = labels
        if caught is not None:
            v["caught"] = caught
        if stale:
            v["digest"]["sha256"] = D["stale-vocabulary"]
        elif redigest:
            v["digest"]["sha256"] = jcs_digest(
                {"caught": v["caught"], "labels": v["labels"]})
        return st
    return b


vec("bad-602-caught-not-subset", "ok-002",
    'caught gains "example_label_x" which is not in labels; digest '
    "recomputed over the mutated content",
    ["recompute-vocabulary-digest"], [52], ["vocabulary-caught-not-subset"],
    _vocab_mut(caught=["egress_captured", "example_label_x"]),
    spec="L343-345")
vec("bad-603-labels-unsorted", "ok-002",
    "labels in descending order; digest recomputed",
    ["recompute-vocabulary-digest"], [53], ["vocabulary-not-canonical"],
    _vocab_mut(labels=["no_egress", "egress_captured"]), spec="L345")
vec("bad-604-caught-duplicate", "ok-002",
    "duplicate entry in caught; digest recomputed",
    ["recompute-vocabulary-digest"], [53], ["vocabulary-not-canonical"],
    _vocab_mut(caught=["egress_captured", "egress_captured"]), spec="L345")
vec("bad-605-vocabulary-digest-mismatch", "ok-002",
    "stale vocabulary digest over unchanged content", [], [54],
    ["vocabulary-digest-mismatch"], _vocab_mut(stale=True, redigest=False),
    spec="L345-347")


def _b606() -> dict[str, Any]:
    st = P_clean()
    del st["predicate"]["observationEnvironment"]["runEntropy"]
    return st


vec("bad-606-missing-runentropy", "ok-002",
    "drop runEntropy on a substrate-row-carrying statement", [], [57],
    ["run-entropy-missing"], _b606, spec="L351-353; L119-120",
    note="precedence pin: a missing binding INPUT reports its member code, "
         "never run-binding-mismatch")


def _b607() -> dict[str, Any]:
    st = P_clean()
    st["subject"].append({"name": "example-agent-bundle-b",
                          "digest": {"sha256": D["subject-b"]}})
    return st


vec("bad-607-two-subjects-substrate", "ok-002",
    "second subject appended to a substrate-row-carrying statement", [],
    [58], ["subject-cardinality"], _b607, spec="L115",
    note="subject[0] unchanged, so record bindings still derive: the "
         "cardinality rule is the ONLY fault")


def _verbatim_rebind(mutate_env: Callable[[dict[str, Any]], str | None]
                     ) -> Callable[[], dict[str, Any]]:
    """Mutate a binding input, then rederive the binding VERBATIM over the
    mutated statement values and re-sign both records with it, so the
    format rule is the only fault (no binding cascade)."""
    def b() -> dict[str, Any]:
        st = P_clean()
        env = st["predicate"]["observationEnvironment"]
        subj_sha = mutate_env(st)
        bv = sha256hex(jcs(binding_preimage(
            env, subject_sha=subj_sha or None)))
        st["predicate"]["observationRecords"] = [
            record(arming_payload(bv)), record(sealed_payload(bv))]
        return reroot(st)
    return b


def _m608(st: dict[str, Any]) -> None:
    env = st["predicate"]["observationEnvironment"]
    env["runEntropy"]["digest"]["sha256"] = \
        env["runEntropy"]["digest"]["sha256"].upper()
    return None


def _m609(st: dict[str, Any]) -> None:
    env = st["predicate"]["observationEnvironment"]
    env["substrate"]["digest"]["sha256"] = \
        env["substrate"]["digest"]["sha256"][:63]
    return None


vec("bad-608-digest-uppercase", "ok-002",
    "runEntropy digest upper-cased; binding rederived VERBATIM over the "
    "uppercase value and records re-signed with it",
    ["rederive-run-binding-verbatim", "re-sign-record",
     "recompute-batch-root"], [59], ["digest-not-canonical"],
    _verbatim_rebind(_m608), spec="L115-119",
    note="a rail that derives verbatim finds the binding EQUAL; only the "
         "lowercase-64-hex format rule fails")
vec("bad-609-digest-truncated", "ok-002",
    "substrate digest truncated to 63 hex chars; verbatim rederive chain",
    ["rederive-run-binding-verbatim", "re-sign-record",
     "recompute-batch-root"], [59], ["digest-not-canonical"],
    _verbatim_rebind(_m609), spec="L115-119")


def _b610() -> dict[str, Any]:
    st = P_caught()
    env = st["predicate"]["observationEnvironment"]
    v = env["observationVocabulary"]
    v["labels"], v["caught"] = [], []
    v["digest"]["sha256"] = jcs_digest({"caught": [], "labels": []})
    return st


vec("bad-610-empty-labels-substrate", "ok-001",
    "labels: [] and caught: [] (digest recomputed) under a substrate row "
    "whose label is now out-of-vocabulary",
    ["recompute-vocabulary-digest"], [4, 44, 53],
    ["fail-closed-substrate-row"], _b610, spec="L305-309; L345",
    note="empty vocabulary is internally canonical (vacuously sorted, "
         "vacuously a subset); the fault is the fail-closed substrate row")


def _b611() -> dict[str, Any]:
    st = P_clean()
    st["subject"][0]["digest"] = {
        "sha512": hashlib.sha512(
            PREIMAGES["subject"].encode()).hexdigest()}
    return st


vec("bad-611-subject-no-sha256", "ok-002",
    "subject digest carries only sha512", [], [59, 60],
    ["subject-sha256-missing"], _b611, spec="L115-119",
    note="precedence pin: missing binding input reports the member code; "
         "records keep the parent binding (unreachable check)")


def _b612() -> dict[str, Any]:
    st = P_caught()
    v = st["predicate"]["observationEnvironment"]["observationVocabulary"]
    v["labels"] = [*v["labels"], "\U0001F600"]
    v["digest"]["sha256"] = jcs_digest(
        {"caught": v["caught"], "labels": v["labels"]})
    return st


vec("bad-612-labels-non-bmp", "ok-001",
    "labels gains the supplementary-plane entry U+1F600; digest recomputed "
    "over the mutated content",
    ["recompute-vocabulary-digest"], [86], ["vocabulary-not-canonical"],
    _b612, spec="L72-86",
    note="BMP-only string profile: the entry sorts last under BOTH the "
         "UTF-16 and the code-point order, so sortedness, the caught "
         "subset, and the digest all still verify and the supplementary-"
         "plane entry is the single fault")

# --- (h) arming / sealed / examination -----------------------------------


def _rec_mut(parentfn: Callable[[], dict[str, Any]], idx: int,
             mutfn: Callable[[dict[str, Any]], dict[str, Any]]
             ) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        return mutate_record_payload(parentfn(), idx, mutfn)
    return b


vec("bad-701-arming-missing-armedat", "ok-002",
    "drop armedAt from the arming payload",
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {k: v for k, v in o.items() if k != "armedAt"}),
    spec="L636-641; L651-654")
vec("bad-702-armedat-after-issuedat", "ok-002",
    'arming armedAt: "2026-01-01T00:01:00Z" (after issuedAt)',
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "armedAt": "2026-01-01T00:01:00Z"}),
    spec="L636-641")
vec("bad-703-arming-posture-mismatch", "ok-002",
    "arming aeePostureDigest differs from the pinned posture digest",
    ["re-sign-record", "recompute-batch-root"], [63, 65],
    ["arming-covers-nothing", "sealed-covers-nothing",
     "clean-row-uncovered"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeePostureDigest": D["other-posture"]}),
    compound=True, spec="L636-641; L655-699",
    note="inherently compound: the sealed record must equal BOTH the "
         "arming record's and the pinned digest, so one arming edit "
         "un-covers the sealed record too")
vec("bad-704-arming-method-reconstructed", "ok-002",
    'arming record signed aeeMethod: "reconstructed"',
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0, lambda o: {**o, "aeeMethod": "reconstructed"}),
    spec="L639-641; L651-654")
vec("bad-705-sealed-missing-dropcount", "ok-002",
    "drop aeeDropCount from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [64],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1,
             lambda o: {k: v for k, v in o.items() if k != "aeeDropCount"}),
    spec="L641-646")
vec("bad-706-stillarmed-non-boolean", "ok-002",
    'sealed aeeStillArmed: "true" (string, not boolean)',
    ["re-sign-record", "recompute-batch-root"], [64],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1, lambda o: {**o, "aeeStillArmed": "true"}),
    spec="L641-646")
vec("bad-707-sealed-stillarmed-false", "ok-002",
    "sealed aeeStillArmed: false",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1, lambda o: {**o, "aeeStillArmed": False}),
    spec="L655-699")
vec("bad-708-sealed-drops-no-bound", "ok-002",
    "sealed aeeDropCount: 3 with no aeeDropBound declared",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1, lambda o: {**o, "aeeDropCount": 3}),
    spec="L655-699")
vec("bad-709-sealed-drops-exceed-bound", "ok-003",
    "sealed aeeDropCount: 6 exceeding the declared aeeDropBound: 5",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean_bounded, 1, lambda o: {**o, "aeeDropCount": 6}),
    spec="L655-699")
vec("bad-710-sealed-posture-mismatch", "ok-002",
    "sealed aeePostureDigest edited (differs from the arming record's AND "
    "the pinned digest, which the arming constraint makes equivalent)",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1,
             lambda o: {**o, "aeePostureDigest": D["other-posture"]}),
    compound=True, spec="L655-699",
    note="both posture sub-clauses fire together; they are distinguishable "
         "only in already-invalid statements")
vec("bad-712-examination-method-intercepted", "ok-006",
    'examination record signed aeeMethod: "intercepted"',
    ["re-sign-record", "recompute-batch-root"], [66],
    ["examination-covers-nothing"],
    _rec_mut(P_reconstructed, 0,
             lambda o: {**o, "aeeMethod": "intercepted"}),
    spec="L646-648; L651-654")


def _b713() -> dict[str, Any]:
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    b = binding_for(env)
    st["predicate"]["observationRecords"] = [
        record(arming_payload(b)),
        record(sealed_payload(b, still=False)),      # referenced, bad
        record(sealed_payload(b)),                   # covering, UNREFERENCED
    ]
    st["predicate"]["attackResults"][0]["observationRefs"] = [0, 1]
    return reroot(st)


vec("bad-713-only-sealed-ref-noncovering", "ok-002",
    "clean row refs [good-arming, non-covering-sealed]; a fully-covering "
    "sealed record sits UNREFERENCED in the tree",
    ["recompute-batch-root"], [68], ["sealed-covers-nothing"], _b713,
    spec="L554-555; L283-286",
    note="discriminates rails that scan all records instead of the row's "
         "referenced set")
vec("bad-714-unknown-kind-sole-cover", "ok-002",
    'the arming record\'s aeeKind becomes "aee-future-x" (record otherwise '
    "fully valid); the clean row's only arming ref now covers nothing",
    ["re-sign-record", "recompute-batch-root"], [71],
    ["record-kind-unknown-covers-nothing"],
    _rec_mut(P_clean, 0, lambda o: {**o, "aeeKind": "aee-future-x"}),
    spec="L702-706",
    note="pairs with ok-013: an unknown kind that no row NEEDS is ignored "
         "and only contributes its leaf")
vec("bad-715-sealed-missing-stillarmed", "ok-002",
    "drop aeeStillArmed from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [64],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1,
             lambda o: {k: v for k, v in o.items()
                        if k != "aeeStillArmed"}),
    spec="L641-646")
vec("bad-716-sealed-missing-posture", "ok-002",
    "drop aeePostureDigest from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [64, 65],
    ["sealed-covers-nothing"],
    _rec_mut(P_clean, 1,
             lambda o: {k: v for k, v in o.items()
                        if k != "aeePostureDigest"}),
    spec="L641-646; L655-699")
vec("bad-717-arming-missing-posture", "ok-002",
    "drop aeePostureDigest from the arming payload",
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {k: v for k, v in o.items()
                        if k != "aeePostureDigest"}),
    spec="L636-641")

CHAIN_SCOPE = "example-substrate-key-and-subject/v1"

vec("bad-718-chain-runseq-zero", "ok-002",
    "arming payload gains aeeRunSeq: 0 with aeeChainScope present (a "
    "sequence number is a positive integer)",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeeChainScope": CHAIN_SCOPE, "aeeRunSeq": 0}),
    spec="L662-673",
    note="pairs with the genesis accept vector ok-034 (aeeRunSeq 1, scope "
         "present, no predecessor)")
vec("bad-719-chain-missing-scope", "ok-002",
    "arming payload gains aeeRunSeq: 1 with NO aeeChainScope "
    "(aeeChainScope is required whenever aeeRunSeq is present)",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0, lambda o: {**o, "aeeRunSeq": 1}),
    spec="L662-673",
    note="an unscoped counter makes every chain rule vacuous, so the "
         "syntax check rejects it fail-closed")
vec("bad-720-chain-prev-not-hex", "ok-002",
    "arming payload gains aeeRunSeq: 2, aeeChainScope, and an "
    "aeePrevRunBinding that is not lowercase 64-hex",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeeChainScope": CHAIN_SCOPE,
                        "aeePrevRunBinding": "EXAMPLE-NOT-64-HEX",
                        "aeeRunSeq": 2}),
    spec="L662-673",
    note="a predecessor binding is a lowercase 64-hex run binding digest, "
         "present exactly when aeeRunSeq exceeds 1")

# --- (k) statement-level -------------------------------------------------


def _b801() -> dict[str, Any]:
    st = P_clean()
    st["predicateType"] = ("https://in-toto.io/attestation/"
                           "adversarial-execution-evidence/v0.5")
    return st


vec("bad-801-wrong-predicatetype", "ok-002",
    "v0.5 predicateType URI on a v0.6-shaped statement", [], [77],
    ["predicate-type-unsupported"], _b801, spec="L3; L162",
    note="a verifier MUST NOT process this as v0.6")


def _drop_env(member: str) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = P_artifact()
        del st["predicate"]["observationEnvironment"][member]
        return st
    return b


vec("bad-802-missing-catchpolicy", "ok-007", "drop catchPolicy", [],
    [78], ["environment-incomplete"], _drop_env("catchPolicy"),
    spec="L328-337",
    note="artifact-only parent: no binding cascade; defeats the "
         "empty-vs-enforcing policy distinguishability")


def _b803() -> dict[str, Any]:
    st = P_artifact()
    env = st["predicate"]["observationEnvironment"]
    env["corpus"]["digest"]["sha256"] = D["stale-corpus"]
    return st


vec("bad-803-corpus-digest-mismatch", "ok-007",
    "corpus.digest is not the JCS digest of the embedded manifest", [],
    [79], ["corpus-digest-mismatch"], _b803, spec="L332-335; L353-356",
    note="statement-side lie, vs bad-301's record-side splice")


def _b804() -> dict[str, Any]:
    st = P_artifact_degraded()
    env = st["predicate"]["observationEnvironment"]
    env["corpus"]["manifest"]["classes"]["XB"].append("XA-EXAMPLE-1")
    env["corpus"]["digest"]["sha256"] = jcs_digest(
        env["corpus"]["manifest"])
    return st


vec("bad-804-attackid-two-classes", "ok-033",
    "XA-EXAMPLE-1 appears under two manifest classes; corpus digest "
    "recomputed", ["recompute-corpus-digest"], [80],
    ["manifest-duplicate-attack"], _b804, spec="L334-335",
    note="artifact-only degraded parent avoids any binding cascade; "
         "coverage over the assessed class is unchanged")
vec("bad-805-row-unknown-attackid", "ok-001",
    'row attackId: "XA-EXAMPLE-9" absent from the manifest', [],
    [81, 82], ["row-attack-unknown", "coverage-incomplete"],
    _row_mut(P_caught, 0, lambda r: {**r, "attackId": "XA-EXAMPLE-9"}),
    compound=True, spec="L369; L393-396",
    note="precedence pin: row-attack-unknown")


def _b806() -> dict[str, Any]:
    st = P_two_attacks()
    del st["predicate"]["attackResults"][1]
    return st


vec("bad-806-coverage-attack-omitted", "ok-011",
    "one of the two rows of a 2-attack assessed class deleted (quiet "
    "omission)", [], [82], ["coverage-incomplete"], _b806,
    spec="L393-396",
    note="the second interception record stays in the tree (unreferenced "
         "records are legal), so the root is untouched: single fault")


def _b807() -> dict[str, Any]:
    st = P_degraded()
    st["predicate"]["attackResults"].append(
        artifact_row(attack="XB-EXAMPLE-1", label="no_egress"))
    return st


vec("bad-807-coverage-attack-superset", "ok-004",
    "added artifact-basis clean row for the outOfScope class's attack; "
    "result stays degraded", [], [82], ["coverage-incomplete"], _b807,
    spec="L393-396",
    note="superset direction of exactly-equal coverage")


def _b816() -> dict[str, Any]:
    st = P_degraded()
    st["predicate"]["coverage"]["outOfScope"] = {}
    st["predicate"]["result"] = "pass"
    return st


vec("bad-816-coverage-class-dropped", "ok-004",
    "manifest class XB dropped from all three coverage sets (not assessed, "
    "not outOfScope, not routedElsewhere), result forced to pass: the "
    "class-granularity coverage-partition fail-open", [], [82],
    ["coverage-incomplete"], _b816,
    spec="L360-365; L393-396",
    note="distinct from bad-806/807 (attack granularity within an assessed "
         "class): a whole manifest class left silently unaccounted")


_B64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def _noncanonical_b64(s: str) -> str:
    """Return a base64 string that a lenient decoder (validate=True) still
    accepts but that is NOT RFC 4648 canonical: the last pre-padding character
    is remapped so a trailing bit that must be zero is set. Go's
    base64.StdEncoding.Strict() (aee/validity.go:108) and the Python rail's
    re-encode-compare both reject it as record-undecodable, while a lenient
    decoder would silently accept it -- the divergence this vector pins."""
    core = s.rstrip("=")
    pad = len(s) - len(core)
    assert pad > 0, "payload must carry padding to have slack trailing bits"
    tampered = _B64_ALPHABET[_B64_ALPHABET.index(core[-1]) | 1]
    return core[:-1] + tampered + "=" * pad


def _b817() -> dict[str, Any]:
    st = P_caught()
    recs = st["predicate"]["observationRecords"]
    recs[0]["payload"] = _noncanonical_b64(recs[0]["payload"])
    return st


vec("bad-817-payload-noncanonical-base64", "ok-001",
    "covering record payload re-encoded as non-canonical base64 (nonzero "
    "trailing bits); the record no longer strict-decodes",
    [], [19], ["record-undecodable"], _b817,
    spec="L609-612",
    note="encoding-layer divergence: Go decodes with StdEncoding.Strict() and "
         "the Python rail re-encode-compares, so both reject; a lenient decoder "
         "would accept. The stale signature and batch root are unreachable "
         "because a decode failure short-circuits both checks (validity.go:120)")


def _b808() -> dict[str, Any]:
    st = P_clean()
    del st["predicate"]["coverage"]
    return st


vec("bad-808-coverage-absent", "ok-002", "drop coverage", [], [83],
    ["coverage-missing"], _b808, spec="L358-362")


def _b809() -> dict[str, Any]:
    st = P_clean()
    st["predicate"]["does_not_assert"] = ["example negative scope"]
    return st


vec("bad-809-snake-case-doesnotassert", "ok-002",
    "statement carries the rejected snake_case spelling of doesNotAssert",
    [], [84], ["member-spelling"], _b809, spec="L759-769",
    note="single-canonicalization rule: no alias")


def _b810() -> dict[str, Any]:
    st = P_artifact()
    del st["predicate"]["issuedAt"]
    return st


vec("bad-810-missing-issuedat", "ok-007", "drop issuedAt", [], [85],
    ["issued-at-missing"], _b810, spec="L771-773",
    note="artifact-only parent: no armedAt comparison cascade")


def _b811() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["issuedAt"] = "yesterday"
    return st


vec("bad-811-issuedat-not-rfc3339", "ok-007", 'issuedAt: "yesterday"', [],
    [85], ["issued-at-malformed"], _b811, spec="L771-773")
vec("bad-812-missing-networkposture", "ok-007", "drop networkPosture", [],
    [78], ["environment-incomplete"], _drop_env("networkPosture"),
    spec="L328-339")
vec("bad-813-missing-corpus", "ok-007", "drop corpus", [], [78],
    ["environment-incomplete"], _drop_env("corpus"), spec="L328-335")
vec("bad-814-missing-substrate", "ok-007", "drop substrate", [], [78],
    ["environment-incomplete"], _drop_env("substrate"), spec="L328-332")


def _b815() -> dict[str, Any]:
    st = P_clean()
    st["_type"] = "https://in-toto.io/Statement/v0.9"
    return st


vec("bad-815-wrong-statement-type", "ok-002",
    "_type is not the in-toto Statement/v1 URI", [], [77],
    ["statement-type-unsupported"], _b815, spec="L158")


# ---------------------------------------------------------------- checks

RESULT_VOCAB = {"pass", "degraded", "fail"}
BASIS_VOCAB = {"substrate", "artifact"}
METHOD_VOCAB = {"intercepted", "reconstructed"}


def recompute_result(st: dict[str, Any]) -> str:
    p = st["predicate"]
    v = p["observationEnvironment"]["observationVocabulary"]
    labels, caught = set(v["labels"]), set(v["caught"])
    for r in p["attackResults"]:
        lab = r.get("containmentObserved")
        if (lab in caught or lab not in labels
                or r.get("basis") not in BASIS_VOCAB
                or r.get("method") not in METHOD_VOCAB):
            return "fail"
    cov = p["coverage"]
    if cov["outOfScope"] or cov["routedElsewhere"]:
        return "degraded"
    return "pass"


def verify_record_sigs(st: dict[str, Any]) -> None:
    pub = Ed25519PublicKey.from_public_bytes(SUB_PUB)
    for rec in st["predicate"].get("observationRecords", []):
        for s in rec["signatures"]:
            pub.verify(unb64(s["sig"]), record_pae(rec))


def parent_gate_check(name: str, st: dict[str, Any]) -> None:
    """Full validity-gate check: parents MUST pass every gate."""
    p = st["predicate"]
    env = p["observationEnvironment"]
    v = env["observationVocabulary"]
    assert p["result"] in RESULT_VOCAB, name
    assert p["result"] == recompute_result(st), name
    assert v["digest"]["sha256"] == jcs_digest(
        {"caught": v["caught"], "labels": v["labels"]}), name
    assert sorted(v["labels"]) == v["labels"], name
    assert set(v["caught"]) <= set(v["labels"]), name
    assert env["corpus"]["digest"]["sha256"] == jcs_digest(
        env["corpus"]["manifest"]), name
    recs = p.get("observationRecords")
    if recs is not None:
        assert p["batchRoot"] == merkle_root(recs), name
        paes = [record_pae(r) for r in recs]
        assert len(paes) == len(set(paes)), name + ": duplicate record"
    verify_record_sigs(st)
    substrate_rows = [r for r in p["attackResults"]
                      if r.get("basis") == "substrate"
                      and r.get("method") in METHOD_VOCAB
                      and r.get("containmentObserved") in set(v["labels"])]
    if any(r.get("basis") == "substrate" for r in p["attackResults"]):
        assert "runEntropy" in env, name
    for row in substrate_rows:
        refs = row["observationRefs"]
        assert refs and all(isinstance(i, int) and 0 <= i < len(recs)
                            for i in refs), name
        b = binding_for(env, subject_sha=st["subject"][0]["digest"]["sha256"])
        kinds, methods = [], []
        for i in refs:
            payload = unb64(recs[i]["payload"])
            obj = json.loads(payload)
            assert payload == jcs(obj), name + ": non-canonical payload"
            assert recs[i]["payloadType"].endswith("+json"), name
            assert obj["aeeRunBinding"] == b, name + ": binding"
            kinds.append(obj["aeeKind"])
            methods.append(obj["aeeMethod"])
            if obj["aeeKind"] == "arming":
                assert obj["armedAt"] <= p["issuedAt"], name
                assert obj["aeePostureDigest"] == \
                    env["networkPosture"]["digest"]["sha256"], name
                assert obj["aeeMethod"] == "intercepted", name
            if obj["aeeKind"] == "sealed":
                assert obj["aeeStillArmed"] is True, name
                assert (obj["aeeDropCount"] == 0 or
                        obj["aeeDropCount"] <= obj.get("aeeDropBound", -1)
                        ), name
                assert obj["aeePostureDigest"] == \
                    env["networkPosture"]["digest"]["sha256"], name
            if obj["aeeKind"] == "examination":
                assert obj["aeeMethod"] == "reconstructed", name
        caught = row["containmentObserved"] in set(v["caught"])
        if caught and row["method"] == "intercepted":
            assert "interception" in kinds, name
            cover = [m for k, m in zip(kinds, methods, strict=False)
                     if k == "interception"]
        elif row["method"] == "reconstructed":
            assert "examination" in kinds, name
            cover = [m for k, m in zip(kinds, methods, strict=False)
                     if k == "examination"]
        else:
            assert "arming" in kinds and "sealed" in kinds, name
            cover = [m for k, m in zip(kinds, methods, strict=False)
                     if k in ("arming", "sealed")]
        rank = {"reconstructed": 0, "intercepted": 1}
        assert rank[row["method"]] <= min(rank[m] for m in cover), name


def second_fault_absence(v: dict[str, Any], st: dict[str, Any]) -> None:  # noqa: C901 -- one branch per independent fault family; see docs/complexity-rationales.toml
    """Assert every derived commitment NOT under test still verifies."""
    conds = set(v["conds"])
    p = st["predicate"]
    env = p.get("observationEnvironment", {})
    recs = p.get("observationRecords")
    # (i) batchRoot recomputes unless a root condition is targeted
    if not conds & {24, 25, 26, 27, 29, 30, 31}:
        if recs is not None:
            assert p["batchRoot"] == merkle_root(recs), v["id"]
    # (ii) vocabulary digest verifies unless targeted
    if not conds & {51, 54} and "observationVocabulary" in env:
        voc = env["observationVocabulary"]
        assert voc["digest"]["sha256"] == jcs_digest(
            {"caught": voc["caught"], "labels": voc["labels"]}), v["id"]
    # (iii) corpus digest verifies unless targeted
    if not conds & {79} and "corpus" in env:
        assert env["corpus"]["digest"]["sha256"] == jcs_digest(
            env["corpus"]["manifest"]), v["id"]
    # (iv) record bindings equal the derived binding unless targeted
    has_substrate = any(r.get("basis") == "substrate"
                       for r in p.get("attackResults", []))
    if (recs and has_substrate and "runEntropy" in env
            and "sha256" in st["subject"][0]["digest"]
            and not conds & {22, 57, 59, 60, 62, 75}):
        b = binding_for(env,
                        subject_sha=st["subject"][0]["digest"]["sha256"])
        for rec in recs:
            try:
                obj = json.loads(unb64(rec["payload"]))
            except ValueError:
                continue
            if isinstance(obj, dict) and "aeeRunBinding" in obj:
                assert obj["aeeRunBinding"] == b, v["id"]
    # (v) every signature verifies (signature failure is never a vector
    # fault in this suite: it is tier territory, not validity)
    verify_record_sigs(st)
    # (vi) result recompute matches unless targeted/underivable
    if not conds & {1, 2, 51, 83}:
        if ("observationVocabulary" in env and "coverage" in p
                and p.get("result") in RESULT_VOCAB):
            assert p["result"] == recompute_result(st), v["id"]


# ---------------------------------------------------------------- INDEX.md

COND = {
    1: ("L260", "closed lowercase result vocabulary"),
    2: ("L215-218", "result must equal the recompute"),
    4: ("L264-265", "fail-closed on out-of-vocabulary label"),
    5: ("L265-266", "fail-closed on missing/out-of-vocab basis or method"),
    6: ("L266-267", "degraded iff disclosed coverage gap"),
    10: ("L278", "observationRefs non-empty on substrate rows"),
    11: ("L278-279", "every ref index in range (integer)"),
    12: ("L280-282", "caught intercepted row refs an interception record"),
    13: ("L282-283", "reconstructed row refs an examination record"),
    14: ("L283-286", "clean intercepted row refs arming AND covering sealed"),
    17: ("L287-288", "covering payload is canonical RFC 8785"),
    18: ("L627-629", "covering payload is valid I-JSON (RFC 7493)"),
    19: ("L630-631", "covering media type ends in +json"),
    20: ("L288-289", "covering payload carries the reserved aee members"),
    22: ("L289-290", "aeeRunBinding equals the derived run binding"),
    23: ("L291-292", "row method capped by weakest signed aeeMethod"),
    24: ("L736", "batchRoot required when records exist"),
    25: ("L738-741", "RFC 6962 domain-separated hashing"),
    26: ("L741-743", "RFC 6962 recursive split, never duplicate-pad"),
    27: ("L743", "leaves in array order"),
    29: ("L745-746", "duplicate byte-identical records invalid"),
    30: ("L748-750", "batchRoot must recompute"),
    31: ("L753-757", "batchRoot omitted exactly when records absent"),
    41: ("L398-400", "basis required, closed {substrate, artifact}"),
    42: ("L433-435", "method required, closed {intercepted, reconstructed}"),
    44: ("L305-309", "fail-closed substrate row invalidates; artifact row "
                     "stays a valid fail"),
    45: ("L444-450", "weakest-input method composition"),
    47: ("L590-598", "missing actualLayer = malformed statement, not fail"),
    48: ("L599-604", "clean row actualLayer is the literal none"),
    51: ("L339-347", "observationVocabulary required"),
    52: ("L343-345", "caught is a subset of labels"),
    53: ("L345", "vocabulary arrays sorted ascending, no duplicates"),
    54: ("L345-347", "vocabulary digest is JCS of {caught, labels}"),
    57: ("L351-353", "runEntropy required with any substrate row"),
    58: ("L115", "exactly one subject on substrate-carrying statements"),
    59: ("L115-119", "binding digest inputs lowercase 64-hex sha256"),
    60: ("L87-93", "binding pre-image construction"),
    62: ("L124-131", "binding is anti-splice"),
    63: ("L636-641", "arming record kind constraints"),
    64: ("L641-646", "sealed record required members"),
    65: ("L655-699", "sealed covering conditions"),
    66: ("L646-648", "examination signed aeeMethod reconstructed"),
    68: ("L554-555", "each referenced record independently satisfies its "
                     "class constraints"),
    71: ("L702-706", "unknown aeeKind covers nothing"),
    75: ("L131-135", "fail-closed on unimplemented binding version"),
    77: ("L3; L158", "statement _type and predicateType URIs"),
    78: ("L328-353", "observationEnvironment required members"),
    79: ("L332-335", "corpus digest re-derives from embedded manifest"),
    80: ("L334-335", "attackId under at most one manifest class"),
    81: ("L369", "row attackId appears in the manifest"),
    82: ("L393-396", "coverage exactly equals the manifest at attack "
                     "granularity"),
    83: ("L358-362", "coverage member required"),
    84: ("L759-769", "doesNotAssert single canonical spelling"),
    85: ("L771-773", "issuedAt required, RFC 3339"),
    86: ("L72-86", "vocabulary labels/caught entries BMP-only; a "
                             "supplementary-plane entry is malformed"),
    87: ("L72-86", "covering payload member names BMP-only; a "
                             "supplementary-plane name covers nothing"),
    88: ("L369-375", "row members are strictly typed; a wrong-JSON-type "
                     "member is a malformed statement"),
    89: ("L662-673", "arming chain-member syntax: positive "
                               "aeeRunSeq; aeeChainScope required with it; "
                               "aeePrevRunBinding lowercase 64-hex, absent "
                               "exactly when aeeRunSeq is 1"),
}


def write_index() -> None:
    L: list[str] = []
    L.append("# INVALID conformance vectors — adversarial-execution-evidence v0.6")
    L.append("")
    L.append("This directory is the conformance suite's `vectors/reject/` layout.")
    L.append("")
    L.append("Ground truth: `spec/predicates/adversarial-execution-evidence.md` @")
    L.append("`e5ea1eb` (in-toto/attestation PR #570 branch), version 0.6.0, type URI")
    L.append(f"`{PREDICATE_TYPE}`.")
    L.append("All `Lnnn` anchors below are line refs into that single vendored")
    L.append("revision, which folds in the review revisions (the BMP-only string")
    L.append("profile and the arming-payload run-chaining members).")
    L.append("")
    L.append("Every file is a COMPLETE in-toto Statement (UNWRAPPED — no outer DSSE;")
    L.append("the inner `observationRecords` carry real DSSE signatures) that a")
    L.append("conforming verifier MUST reject for exactly ONE declared reason. Each is")
    L.append("derived from a fully-valid parent statement by ONE mutation plus its")
    L.append("declared rederive chain, so no second fault exists; the generator's")
    L.append("self-check asserts second-fault ABSENCE (root recomputes, vocabulary and")
    L.append("corpus digests verify, record bindings equal the derived binding, every")
    L.append("signature verifies, result recompute matches) for every vector whose")
    L.append("declared conditions do not target that commitment, and full gate")
    L.append("validity for every parent. Regenerate byte-identically with:")
    L.append("`python3 gen_invalid_vectors.py`.")
    L.append("")
    L.append("## Determinism recipe")
    L.append("")
    L.append("- Test signing key (Ed25519/RFC 8032), seed DERIVED, never stored:")
    L.append("  `seed(role) = SHA-256(\"in-toto-aee-test-key/<role>/v1\")`, role")
    L.append("  `substrate-observation-test` for every record signature in this set.")
    L.append(f"  - public key (hex): `{SUB_PUB.hex()}`")
    L.append(f"  - keyid = SHA-256 of the raw public key: `{SUB_KEYID}`")
    L.append("  - `keyid` is an unauthenticated hint, never the check (spec L807-809).")
    L.append(f"- Fixed timestamps: `issuedAt: {ISSUED_AT}`, `armedAt: {ARMED_AT}`")
    L.append("  (a later `armedAt` appears only in bad-702).")
    L.append(f"- Record `payloadType`: `{PAYLOAD_TYPE}`.")
    L.append("- Subject `example-agent-bundle`; attack ids `XA-EXAMPLE-*`,")
    L.append("  `XB-EXAMPLE-*`; producer label/layer vocabulary is spec-verbatim")
    L.append("  (`egress_captured`, `no_egress`, `sinkhole`,")
    L.append("  `policy.egress_sinkhole`, `none`) or obviously synthetic")
    L.append("  (`example_label_a`, `example.method-x`).")
    L.append("- Committed files: UTF-8, LF, 2-space indent, lexicographic member")
    L.append("  order, std base64 with padding. For bad-201/202/203 the FAULT is a")
    L.append("  serialization property of the record payload bytes; those exact bytes")
    L.append("  travel base64-encoded, so the statement files themselves remain")
    L.append("  ordinary JSON and byte-replay is preserved (MANIFEST `rawBytes`).")
    L.append("")
    L.append("## Derived digest preimages (all synthetic one-liners)")
    L.append("")
    L.append("| digest | preimage |")
    L.append("|---|---|")
    for k in sorted(PREIMAGES):
        L.append(f"| `{D[k]}` | `sha256(\"{PREIMAGES[k]}\")` |")
    cp_jcs = json.dumps(CATCHPOLICY_OBJ, sort_keys=True)
    L.append(f"| `{CATCHPOLICY_D}` | `sha256(JCS({cp_jcs}))` |")
    L.append(f"| `{POSTURE_D}` | `sha256(JCS({json.dumps(POSTURE_OBJ, sort_keys=True)}))` |")
    L.append("")
    L.append("Corpus and vocabulary digests are JCS digests of the manifest and")
    L.append("`{\"caught\": [...], \"labels\": [...]}` objects embedded in each vector.")
    L.append("Run bindings derive per spec L87-93 from each statement's own values.")
    L.append("Negative known-answer for bad-303 — the v2 pre-image that MUST NOT")
    L.append("match (JCS, then SHA-256):")
    _env = environment(M1)
    L.append("")
    L.append("```json")
    L.append(json.dumps(binding_preimage(_env, version="2"), sort_keys=True,
                        indent=2))
    L.append("```")
    L.append("")
    L.append("## Conditions referenced (aee-c ids)")
    L.append("")
    L.append("Stable condition ids used by this suite; the conformance-repo README")
    L.append("carries the authoritative id-to-spec-line table.")
    L.append("")
    L.append("| id | spec anchor | condition |")
    L.append("|---|---|---|")
    used = sorted({c for v in VECTORS for c in v["conds"]})
    for c in used:
        L.append(f"| aee-c-{c} | {COND[c][0]} | {COND[c][1]} |")
    L.append("")
    L.append(f"## Vectors ({len(VECTORS)})")
    L.append("")
    L.append("`parent` names the accept-suite shape the vector derives from (the")
    L.append("accept vectors land separately; the parent statements are built")
    L.append("in-memory by the generator and asserted fully valid before mutation).")
    L.append("`rederive` lists the derived commitments recomputed after the mutation")
    L.append("so the declared fault stays the ONLY fault.")
    L.append("")
    L.append(
        "| vector | parent | single mutation | rederive | "
        "conditions (aee-c ids) | expected rejection | spec |"
    )
    L.append("|---|---|---|---|---|---|---|")
    for v in VECTORS:
        conds = " ".join(f"aee-c-{c}" for c in v["conds"])
        codes = ", ".join(f"`{c}`" for c in v["codes"])
        if v["compound"]:
            codes += " (COMPOUND)"
        red = ", ".join(v["rederive"]) if v["rederive"] else "—"
        L.append(f"| `{v['id']}` | {v['parent']} | {v['mutation']} | {red} "
                 f"| {conds} | {codes} | {v['spec']} |")
    L.append("")
    L.append("## Notes on specific vectors")
    L.append("")
    for v in VECTORS:
        if v["note"]:
            L.append(f"- **{v['id']}** — {v['note']}.")
    L.append("")
    L.append("## Compound vectors and precedence pins")
    L.append("")
    L.append("`expected` codes form a SET: a rail conforms when its code is in the")
    L.append("set and the verdict matches. Vectors marked COMPOUND are inherently")
    L.append("multi-condition (deriving them singly is impossible without")
    L.append("introducing a different fault); every other vector is single-fault by")
    L.append("construction. Registry precedence pins applied here:")
    L.append("")
    L.append("1. A missing binding INPUT reports its member code, never")
    L.append("   `run-binding-mismatch` (bad-606, bad-611); binding mismatch is")
    L.append("   reserved for derivable-but-unequal (bad-301, bad-303).")
    L.append("2. `records-absent` is reported when `observationRecords` is absent")
    L.append("   entirely; `ref-out-of-range` only when records exist (bad-407).")
    L.append("3. The method cap reads COVERING records only: the referenced records")
    L.append("   of the class(es) the row's class-match rule requires; extras are")
    L.append("   payload-checked but neither cap nor tier-gate (bad-304).")
    L.append("4. The two sealed posture equalities are jointly enforced given the")
    L.append("   arming constraint (bad-710); distinguishable only in")
    L.append("   already-invalid statements.")
    L.append("")
    L.append("Signature failure is NEVER a failure code in this suite: whether a")
    L.append("record's signature verifies against a consumer-named key is the")
    L.append("evidence tier's separate, trust-relative question. Every committed")
    L.append("signature here verifies under the derived test public key above.")
    L.append("")
    L.append("## Deferred coverage (no vector, by design)")
    L.append("")
    L.append("- **Missing or out-of-vocabulary `basis`** on a row: a row whose")
    L.append("  `basis` is absent or unknown cannot be classified for the")
    L.append("  fail-closed branch split (substrate => attestation invalid vs")
    L.append("  artifact => valid `fail`), and the spec text does not state which")
    L.append("  branch applies. This is a formal spec-edit ask on the PR thread;")
    L.append("  shipping a reject vector now would silently resolve the reading.")
    L.append("  The out-of-vocab METHOD and LABEL substrate twins (bad-501,")
    L.append("  bad-504) plus the valid artifact-row twins in the accept suite")
    L.append("  cover the decidable half of the fail-closed axis.")
    L.append("- **Duplicate-record identity discriminator** (leaf-hash vs")
    L.append("  byte-identical): bad-405 is invalid under BOTH readings; the")
    L.append("  discriminating vector waits on the spec answer.")
    L.append("- **observationSelectors length mismatch**: unstated in the spec;")
    L.append("  formal ask, no vector.")
    L.append("- **Artifact-only multi-subject**: the one-subject rule is scoped to")
    L.append("  substrate-carrying statements (L115); whether artifact-only")
    L.append("  multi-subject is legal is an open ask (bad-607 keeps a substrate")
    L.append("  row precisely so the rule undeniably applies).")
    L.append("- **Replay of a genuine runEntropy** (stateful-consumer concern) and")
    L.append("  **coherence checks** (MAY): behavior/harness territory, not")
    L.append("  statement-shape vectors.")
    L.append("")
    with open(os.path.join(OUT, "INDEX.md"), "w") as f:
        f.write("\n".join(L) + "\n")


# ---------------------------------------------------------------- main

def main() -> None:
    # 1. parents must be fully valid
    for name, fn in PARENTS.items():
        parent_gate_check(name, fn())

    # 2. generate, self-check, write
    ids: set[str] = set()
    for v in VECTORS:
        assert v["id"] not in ids, "duplicate id " + v["id"]
        ids.add(v["id"])
        st = v["build"]()
        second_fault_absence(v, st)
        path = os.path.join(OUT, v["id"] + ".json")
        with open(path, "w") as f:
            json.dump(st, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        with open(path) as f:
            json.load(f)  # every vector parses as JSON

    assert len(VECTORS) == 91, f"expected 91 vectors, built {len(VECTORS)}"

    # 3. index
    write_index()
    print(f"OK: {len(VECTORS)} invalid vectors + INDEX.md")
    print(f"    test pub {SUB_PUB.hex()[:16]}... keyid {SUB_KEYID[:16]}...")


if __name__ == "__main__":
    main()
