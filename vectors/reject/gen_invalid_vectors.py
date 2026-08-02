#!/usr/bin/env python3
"""AEE v0.7 INVALID conformance-vector generator.

Generates the reject vectors of the adversarial-execution-evidence v0.7
conformance suite. Every vector is a COMPLETE in-toto Statement that a
conforming verifier MUST reject for exactly ONE declared reason: each is
derived from a fully-valid parent statement by one mutation plus the declared
rederive chain (re-sign mutated record payloads, recompute the RFC 6962
batchRoot, recompute vocabulary/corpus digests, rederive the run binding),
so no second fault is introduced. A self-check pass asserts second-fault
ABSENCE for every vector and full gate-validity for every parent.

Ground truth: spec/predicates/adversarial-execution-evidence.md, version 0.7.0,
at the upstream commit spec/VENDOR-PIN.json names (in-toto/attestation PR #570
branch). The written INDEX reads that pin rather than restating the commit, so
it cannot name a revision the vectors were not built against.

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
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
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
    # Two more observed values, for the three-channel liveness statements. A
    # third channel needs a third predicted value, and the unmatched case needs
    # a fourth that no channel's corpus entry declares: reusing one channel's
    # value on another channel's record would make the two records
    # byte-identical, which is a different fault (aee-c-29) and would mask the
    # one under test.
    "intercepted-bytes-3": "example-intercepted-bytes/v3",
    "intercepted-bytes-4": "example-intercepted-bytes/v4",
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
                     version: str = "2") -> dict[str, str]:
    """The run-binding pre-image object, in the construction ``version`` names.

    Version 2 is the implemented construction. It differs from version 1 twice,
    and both differences are readable here: ``observationVocabulary`` is a
    member version 1 did not have, and ``networkPosture`` is the JCS digest of
    the carried posture OBJECT rather than the value of that object's own
    digest member. Version 1 is still constructible because one vector is the
    negative known-answer for it: a statement whose records were minted under
    the retired construction, which a version-2 verifier must refuse rather
    than attempt a second derivation for.
    """
    if version == "1":
        return {
            "aeeBindingVersion": "1",
            "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
            "corpus": env["corpus"]["digest"]["sha256"],
            "networkPosture": env["networkPosture"]["digest"]["sha256"],
            "runEntropy": env["runEntropy"]["digest"]["sha256"],
            "subject": subject_sha or D["subject"],
            "substrate": env["substrate"]["digest"]["sha256"],
        }
    return {
        "aeeBindingVersion": version,
        "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
        "corpus": env["corpus"]["digest"]["sha256"],
        "networkPosture": jcs_digest(env["networkPosture"]),
        "observationVocabulary": env["observationVocabulary"]["digest"]["sha256"],
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
                         commit: str = "intercepted-bytes-1") -> dict[str, Any]:
    # aeePayloadCommitment is the reserved spelling for what an interception
    # record has always carried here under a producer name. The array is
    # single-valued because one derived preimage is one observed value; a
    # record resolved by several rows may carry several, which is why the
    # member is an array rather than a string.
    return {"aeeKind": "interception", "aeeMethod": method,
            "aeePayloadCommitment": [D[commit]],
            "aeeRunBinding": binding,
            "producerNote": "example interception"}


# The sentinels a run-level record carries until statement() knows the record
# set and the coverage it is committing against. Neither is ever emitted: the
# self-check refuses a statement whose records still carry one.
OBSERVED_SET_PENDING = "PENDING-OBSERVED-SET"
ASSESSED_PENDING = ["PENDING-ASSESSED-ATTACKS"]


def arming_payload(binding: str, armed_at: str = ARMED_AT, posture: str = POSTURE_D,
                   method: str = "intercepted",
                   assessed: list[str] | None = None) -> dict[str, Any]:
    return {"aeeAssessedAttacks": ASSESSED_PENDING if assessed is None else assessed,
            "aeeKind": "arming", "aeeMethod": method,
            "aeeRunBinding": binding, "aeePostureDigest": posture,
            "armedAt": armed_at}


def sealed_payload(binding: str, still: bool = True, drop: int = 0,
                   bound: int | None = None, posture: str = POSTURE_D,
                   method: str = "intercepted",
                   observed: str | None = None,
                   observed_attacks: list[str] | None = None) -> dict[str, Any]:
    # The empty aeeObservedAttacks is the honest value and is required rather
    # than omissible, so a substrate holding no probe-to-record correspondence
    # says so on the wire instead of leaving an absence nothing records.
    p: dict[str, Any] = {
        "aeeKind": "sealed", "aeeMethod": method, "aeeRunBinding": binding,
        "aeeObservedAttacks": observed_attacks or [],
        "aeeObservedSet": OBSERVED_SET_PENDING if observed is None else observed,
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
               label: str = "egress_captured",
               attribution: str = "paired") -> dict[str, Any]:
    return {"attackId": attack, "containmentObserved": label, "basis": basis,
            "method": method, "attribution": attribution, "actualLayer": layer,
            "observationRefs": list(refs)}


def clean_row(refs: tuple[int, ...] = (0, 1), attack: str = "XA-EXAMPLE-1",
              basis: str = "substrate",
              method: str = "intercepted",
              attribution: str = "paired") -> dict[str, Any]:
    return {"attackId": attack, "containmentObserved": "no_egress",
            "basis": basis, "method": method, "attribution": attribution,
            "actualLayer": "none", "observationRefs": list(refs)}


def artifact_row(attack: str = "XA-EXAMPLE-1", label: str = "egress_captured",
                 method: str = "intercepted", basis: str = "artifact",
                 layer: str = "none",
                 attribution: str = "paired") -> dict[str, str]:
    # observationRefs intentionally absent: refs on artifact rows are
    # unconstrained by the spec (open question; suite pins spec-literal).
    return {"attackId": attack, "containmentObserved": label, "basis": basis,
            "method": method, "attribution": attribution, "actualLayer": layer}


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
    st = {"_type": STATEMENT_TYPE,
          "subject": subject or [{"name": "example-agent-bundle",
                                  "digest": {"sha256": D["subject"]}}],
          "predicateType": PREDICATE_TYPE,
          "predicate": pred}
    if records is not None:
        reseal(st)
        pred["batchRoot"] = (merkle_root(records) if batch_root == "auto"
                             else batch_root)
    return st


def observed_set_digest(records: list[dict[str, Any]]) -> str:
    """The value a seal's aeeObservedSet commits to.

    SHA-256 of the JCS canonicalization of the duplicate-free array, sorted
    ascending by UTF-16 code unit, of the leaf hashes of every interception and
    examination record. The entries are lowercase hex and therefore ASCII, so a
    byte sort IS the UTF-16 code-unit sort over this value space.
    """
    leaves = set()
    for r in records:
        try:
            obj = json.loads(unb64(r["payload"]))
        except (ValueError, KeyError):
            continue
        if isinstance(obj, dict) and obj.get("aeeKind") in (
                "interception", "examination"):
            leaves.add(_h(b"\x00" + record_pae(r)).hex())
    return sha256hex(jcs(sorted(leaves)))


def reseal(st: dict[str, Any]) -> dict[str, Any]:
    """Fill every run-level sentinel from the statement it ended up in.

    A seal commits to the leaf hashes of the interception and examination
    records the statement carries, and an arming record declares a set the
    carried coverage must be a subset of. Both are functions of the whole
    statement rather than of the record, so both are written as sentinels at
    build time and filled here. This runs on EVERY re-root, because any change
    to any record moves the leaf set the seal committed to -- and a seal left
    committing to the pre-mutation set is precisely the second fault the
    self-check below exists to refuse.

    A record carrying a concrete value keeps it. That is how a vector whose
    subject IS the commitment is written: it passes the wrong value explicitly.
    """
    recs = st["predicate"].get("observationRecords")
    if not recs:
        return st
    digest = observed_set_digest(recs)
    declared = sorted({
        a
        for ids in st["predicate"]["observationEnvironment"]["corpus"]
        .get("manifest", {}).get("classes", {}).values()
        if isinstance(ids, list)
        for a in ids
        if isinstance(a, str)
    })
    for i, r in enumerate(recs):
        try:
            obj = json.loads(unb64(r["payload"]))
        except (ValueError, KeyError):
            continue
        if not isinstance(obj, dict):
            continue
        changed = False
        # aeeObservedSet is a pure function of the carried record set, so it is
        # recomputed on every reseal rather than filled once. Any mutation to
        # any interception or examination payload moves the leaf it commits to,
        # and a seal left committing to the pre-mutation set is exactly the
        # second fault this generator refuses. aeeAssessedAttacks is a producer
        # DECLARATION rather than a derived value, so it is only ever filled
        # from the sentinel and never recomputed over a vector's own choice.
        if obj.get("aeeKind") == "sealed" and "aeeObservedSet" in obj and \
                obj["aeeObservedSet"] != digest:
            obj["aeeObservedSet"] = digest
            changed = True
        if obj.get("aeeAssessedAttacks") == ASSESSED_PENDING:
            obj["aeeAssessedAttacks"] = declared
            changed = True
        if changed:
            recs[i] = record(obj, r["payloadType"])
    return st


def reroot(st: dict[str, Any], reseal_first: bool = True) -> dict[str, Any]:
    """Recompute the batch root, resealing first unless the vector forbids it.

    reseal_first=False is for the vectors whose declared fault IS a run-level
    commitment: resealing one of those would repair the mutation under test.
    """
    if reseal_first:
        reseal(st)
    st["predicate"]["batchRoot"] = merkle_root(
        st["predicate"]["observationRecords"])
    return st


def rebind_records(st: dict[str, Any]) -> dict[str, Any]:
    """Rederive the run binding over the mutated statement, re-sign, re-root.

    Version 2 of the binding folds in the vocabulary digest and the canonical
    digest of the whole networkPosture object, so a mutation to either moves the
    derived binding. A vector that mutates one of them and leaves its records
    carrying the parent's binding therefore carries a second fault, and the
    self-check below refuses it. Every payload member other than aeeRunBinding
    is preserved, so the declared mutation stays the only difference from the
    parent.
    """
    env = st["predicate"]["observationEnvironment"]
    bv = binding_for(env, subject_sha=st["subject"][0]["digest"].get("sha256"))
    st["predicate"]["observationRecords"] = [
        record({**json.loads(unb64(r["payload"])), "aeeRunBinding": bv},
               r["payloadType"])
        for r in st["predicate"]["observationRecords"]]
    return reroot(st)


# ---------------------------------------------------------------- parents
# In-memory equivalents of the BUILD accept shapes (the accept suite lands
# separately); each parent is asserted fully valid by the self-check below.

def P_caught() -> dict[str, Any]:  # ok-001 shape: caught substrate/intercepted, 1 interception
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [caught_row()],
                     [record(interception_payload(b)),
                      record(sealed_payload(b))],
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
                     [record(examination_payload(b)),
                      record(sealed_payload(b))], result="fail")


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


def P_artifact_clean() -> dict[str, Any]:  # ok-007 shape: artifact-only CLEAN row, recordless
    # pass_indirect, not pass: the single clean row is indirect in both vantage
    # and time, which is the third condition of the recompute.
    env = environment(M1, entropy=False)
    return statement(env, [artifact_row(label="no_egress", method="reconstructed")],
                     result="pass_indirect")


def P_two_attacks() -> dict[str, Any]:  # ok-011 shape: two caught rows, two interceptions
    env = environment(M2)
    b = binding_for(env)
    return statement(env,
                     [caught_row(refs=(0,)),
                      caught_row(refs=(1,), attack="XA-EXAMPLE-2")],
                     [record(interception_payload(b)),
                      record(interception_payload(
                          b, commit="intercepted-bytes-2")),
                      record(sealed_payload(b))],
                     result="fail")


def P_clean_two() -> dict[str, Any]:  # ok-011 shape: two clean rows, one arming+sealed pair
    env = environment(M2)
    b = binding_for(env)
    return statement(env,
                     [clean_row(), clean_row(attack="XA-EXAMPLE-2")],
                     [record(arming_payload(b)), record(sealed_payload(b))],
                     result="pass")


def P_three_records() -> dict[str, Any]:  # ok-014 shape: 3-record odd-split tree
    env = environment(M2)
    b = binding_for(env)
    return statement(env, [caught_row(refs=(0,)),
                           clean_row(refs=(1, 2), attack="XA-EXAMPLE-2")],
                     [record(interception_payload(b)),
                      record(arming_payload(b)), record(sealed_payload(b))],
                     result="fail")


def P_artifact_with_records() -> dict[str, Any]:  # ok-029 shape: artifact rows, 2 loose records
    env = environment(M1, entropy=False)
    ub = D["unchecked-binding"]  # no substrate rows => no derived binding
    return statement(env, [artifact_row()],
                     [record(examination_payload(ub)),
                      record({**examination_payload(ub),
                              "statesCompared": ["example-state-c",
                                                 "example-state-d"]})],
                     result="fail")


def P_multirecord() -> dict[str, Any]:  # ok-030 shape: caught row covered by TWO interceptions
    env = environment(M1)
    b = binding_for(env)
    return statement(env, [caught_row(refs=(0, 1))],
                     [record(interception_payload(b)),
                      record(interception_payload(
                          b, commit="intercepted-bytes-2")),
                      record(sealed_payload(b))],
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
    "ok-007 shape (artifact-only clean row, recordless, pass_indirect)": P_artifact_clean,
    "ok-011 shape (two caught rows, two interceptions)": P_two_attacks,
    "ok-011 shape (two clean rows, one arming+sealed pair)": P_clean_two,
    "ok-014 shape (three-record odd-split tree)": P_three_records,
    "ok-029 shape (artifact rows + unreferenced records + root)": P_artifact_with_records,
    "ok-030 shape (caught row covered by two interceptions)": P_multirecord,
    "ok-033 shape (artifact-only degraded)": P_artifact_degraded,
}


# ---------------------------------------------------------------- vectors


# Conditions a vector carries as an unavoidable CONSEQUENCE of its one declared
# mutation, rather than as a second mutation. They are listed here rather than
# beside each vector because the reason is shared and belongs in one place: a
# reviewer asking "why does this reject vector report two conditions" should
# find one answer, not twenty scattered notes.
#
# The distinction that matters is whether a differently-built vector could
# avoid the extra condition. Where one could, it was rebuilt instead of listed:
# the seal-constraint family gained a healthy unreferenced seal, and the
# three-record parent gained the caught row its accept counterpart always had.
# What remains cannot be built away.
#
#   observed-set-mismatch, on the eight vectors whose declared fault makes a
#   covering payload UNREADABLE. A verifier cannot classify the kind of a
#   record it cannot parse, so it cannot count that record's leaf, while the
#   seal legitimately committed to a record the substrate did emit. The
#   specification names this outcome where it defines the member: the statement
#   is invalid on the recompute without the verifier ever learning why.
#
#   interception-record-orphaned, on the seven vectors whose declared fault
#   removes or breaks the reference a caught row used to carry, or takes the
#   row's label out of the caught set. The record stays; the row that accounted
#   for it does not. That is the same edit seen from the record's side.
#
#   sealed-record-absent, on the five vectors whose declared fault moves the
#   derived run binding or the pinned posture. EVERY record then fails its
#   comparison, so no valid seal remains and none could: a second seal added to
#   the statement would fail the same comparison.
#
#   malformed-missing-actual-layer on bad-506, which predates this version: a
#   row whose actualLayer is a JSON number both fails to decode (the catch-all)
#   and leaves the member absent (its own code), from the one wrong type.
INHERENT_EXTRA: dict[str, list[str]] = {
    **{vid: ["observed-set-mismatch"] for vid in (
        "bad-202-payload-bignum",
        "bad-203-payload-duplicate-member",
        "bad-739-payload-lone-surrogate-escape",
        "bad-740-payload-cesu8",
        "bad-741-payload-nesting-exceeds-max-depth",
        "bad-742-payload-nesting-empty-container-leaf",
        "bad-744-payload-noncharacter",
        "bad-817-payload-noncanonical-base64",
    )},
    **{vid: ["interception-record-orphaned"] for vid in (
        "bad-101-refs-empty",
        "bad-103-ref-negative",
        "bad-104-caught-refs-arming-only",
        "bad-105-reconstructed-refs-interception",
        "bad-108-ref-non-integer",
        "bad-504-substrate-oov-label",
        "bad-610-empty-labels-substrate",
    )},
    **{vid: ["sealed-record-absent"] for vid in (
        "bad-301-run-binding-splice",
        "bad-303-binding-version-1",
        "bad-305-posture-swapped",
        "bad-306-vocabulary-caught-narrowed",
        "bad-307-posture-member-added-after-arming",
    )},
    "bad-506-actuallayer-json-number": ["malformed-missing-actual-layer"],
}


VECTORS: list[dict[str, Any]] = []


def vec(vid: str, parent: str, mutation: str, rederive: list[str],
        conds: list[int], codes: list[str],
        build: Callable[[], dict[str, Any]] | Callable[[], str]
        | Callable[[], bytes],
        compound: bool = False,
        also_carries: list[str] | None = None,
        spec: str = "", note: str = "") -> None:
    """Register one reject vector.

    ``codes`` is the expected-rejection SET: a rail conforms when the condition
    it reports is in it. ``also_carries`` names conditions the statement carries
    DELIBERATELY that a conforming rail is not expected to report as its primary,
    which is how a precedence pin keeps a single-code expectation while still
    telling the second-fault self-check that the extra fault was intended.
    """
    VECTORS.append({"id": vid, "parent": parent, "mutation": mutation,
                    "rederive": rederive, "conds": conds, "codes": codes,
                    "compound": compound,
                    "also": list(also_carries or []) + INHERENT_EXTRA.get(vid, []),
                    "spec": spec, "note": note, "build": build})


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
    set_result(P_clean, "PASS"), compound=True, spec="L435; L390-393",
    note="uppercase token is both out-of-vocabulary and not the recompute")
vec("bad-002-result-mismatch-caught", "ok-001",
    'carried result: "pass" over a caught row (recompute: fail)', [],
    [2], ["result-recompute-mismatch"], set_result(P_caught, "pass"),
    spec="L390-393; L435-443")
vec("bad-003-result-mismatch-oov-label", "ok-009",
    'carried result: "pass" over a fail-closed out-of-vocabulary label', [],
    [2, 4], ["result-recompute-mismatch"],
    set_result(P_artifact_oov_label, "pass"), spec="L443-444")
vec("bad-004-result-mismatch-failclosed", "ok-008",
    'carried result: "pass" over a fail-closed unknown method row', [],
    [2, 5], ["result-recompute-mismatch"],
    set_result(P_artifact_unknown_method, "pass"), spec="L443-444")
vec("bad-005-result-mismatch-coverage-gap", "ok-004",
    'carried result: "pass" with a non-empty coverage.outOfScope', [],
    [2, 6], ["result-recompute-mismatch"], set_result(P_degraded, "pass"),
    spec="L444-446")
vec("bad-006-result-fail-on-pass", "ok-002",
    'carried result: "fail" where the recompute derives pass', [],
    [2], ["result-recompute-mismatch"], set_result(P_clean, "fail"),
    spec="L390-393", note="equality is two-directional")
vec("bad-007-result-degraded-on-pass", "ok-002",
    'carried result: "degraded" where the recompute derives pass', [],
    [2], ["result-recompute-mismatch"], set_result(P_clean, "degraded"),
    spec="L390-393")
vec("bad-008-result-unknown-token", "ok-002", 'result: "error"', [],
    [1, 2], ["result-vocabulary", "result-recompute-mismatch"],
    set_result(P_clean, "error"), compound=True, spec="L435")
vec("bad-009-result-pass-on-indirect-clean-row", "ok-007",
    'carried result: "pass" over a clean row that is artifact-basis and '
    "reconstructed (recompute: pass_indirect)", [],
    [2], ["result-recompute-mismatch"],
    set_result(P_artifact_clean, "pass"), spec="L390-393",
    note="this is the statement a party holding only the enclosing envelope "
         "key produces by moving every row to artifact basis and dropping the "
         "records: valid before the fourth result value existed, and a "
         "recompute mismatch after it")
vec("bad-010-result-pass-indirect-on-direct-clean-row", "ok-002",
    'carried result: "pass_indirect" where every clean row is substrate-basis '
    "and intercepted (recompute: pass)", [],
    [2], ["result-recompute-mismatch"],
    set_result(P_clean, "pass_indirect"), spec="L390-393",
    note="the new token is not a floor a producer may volunteer down to; "
         "equality is two-directional here exactly as it is for bad-006")

# --- (b1) refs / class-match ---------------------------------------------

vec("bad-101-refs-empty", "ok-001",
    "caught substrate row observationRefs: []", [],
    [10, 12], ["refs-empty", "caught-row-uncovered"],
    set_refs(P_caught, 0, []), compound=True, spec="L552; L554-556",
    note="an empty ref set on a caught row inherently also uncovers it")
vec("bad-102-ref-out-of-range", "ok-001",
    "observationRefs: [0, 7] with one record (valid cover kept)", [],
    [11], ["ref-out-of-range"], set_refs(P_caught, 0, [0, 7]),
    spec="L552-553")
vec("bad-103-ref-negative", "ok-001", "observationRefs: [0, -1]", [],
    [11], ["ref-malformed"], set_refs(P_caught, 0, [0, -1]),
    spec="L552-553")


def _b104() -> dict[str, Any]:
    st = P_caught()
    b = binding_for(st["predicate"]["observationEnvironment"])
    st["predicate"]["observationRecords"].append(record(arming_payload(b)))
    st["predicate"]["attackResults"][0]["observationRefs"] = [1]
    return reroot(st)


vec("bad-104-caught-refs-arming-only", "ok-001",
    "append a fully-valid arming record; caught intercepted row refs only it",
    ["recompute-batch-root"], [12], ["caught-row-uncovered"], _b104,
    spec="L554-556")


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
    spec="L556-557")
vec("bad-106-clean-missing-sealed", "ok-002",
    "clean row refs the arming record only", [],
    [14], ["clean-row-uncovered"], set_refs(P_clean, 0, [0]),
    spec="L557-560")
vec("bad-107-clean-missing-arming", "ok-002",
    "clean row refs the sealed record only", [],
    [14], ["clean-row-uncovered"], set_refs(P_clean, 0, [1]),
    spec="L557-560")
vec("bad-108-ref-non-integer", "ok-001", "observationRefs: [0, 1.5]", [],
    [11], ["ref-malformed"], set_refs(P_caught, 0, [0, 1.5]),
    spec="L552-553")

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
    ["payload-not-canonical"], _b201, spec="L561-562; L1253-1260",
    note="rawBytes: the committed base64 payload bytes are the fault; "
         "identical content, non-JCS order")


def _b202() -> dict[str, Any]:
    st = P_caught()
    return mutate_record_payload(
        st, 0, lambda o: {**o, "extraA": 9007199254740993})


vec("bad-202-payload-bignum", "ok-001",
    "covering payload gains an integer member 2^53+1",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b202, spec="L1255-1259; L99-102", note="rawBytes")


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
    _b203, spec="L1255-1259", note="rawBytes")


def _b204() -> dict[str, Any]:
    st = P_caught()
    recs = st["predicate"]["observationRecords"]
    return raw_record_bytes(st, 0, unb64(recs[0]["payload"]),
                            ptype="application/octet-stream")


vec("bad-204-payload-media-type", "ok-001",
    'covering record payloadType: "application/octet-stream"',
    ["re-sign-record", "recompute-batch-root"], [19], ["payload-media-type"],
    _b204, spec="L1260-1261",
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
    spec="L150-163",
    note="rawBytes; BMP-only string profile: the name sorts last under BOTH "
         "the UTF-16 and the code-point member order, so the payload bytes "
         "stay canonical under either reading and the supplementary-plane "
         "member NAME is the single fault (a supplementary-plane member "
         "VALUE stays legal)")
vec("bad-205-payload-missing-runbinding", "ok-001",
    "drop aeeRunBinding from the covering payload",
    ["re-sign-record", "recompute-batch-root"], [20],
    ["payload-missing-reserved"], _drop_member("aeeRunBinding"),
    spec="L562-563; L1261-1265")
vec("bad-206-payload-missing-kind", "ok-001",
    "drop aeeKind from the covering payload",
    ["re-sign-record", "recompute-batch-root"], [20],
    ["payload-missing-reserved"], _drop_member("aeeKind"),
    spec="L562-563; L1265-1284")
vec("bad-207-payload-missing-method", "ok-001",
    "drop aeeMethod from the covering payload",
    ["re-sign-record", "recompute-batch-root"], [20],
    ["payload-missing-reserved"], _drop_member("aeeMethod"),
    spec="L562-563; L1284-1285")

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
    ["run-binding-mismatch"], _b301, spec="L563-564; L226-232",
    note="the statement's own corpus is unchanged; the records were earned "
         "under another run's environment")


def _b302() -> dict[str, Any]:
    st = P_caught()
    return mutate_record_payload(
        st, 0, lambda o: {**o, "aeeMethod": "reconstructed"})


vec("bad-302-method-inflation", "ok-001",
    'row method "intercepted"; sole covering record signed '
    '"reconstructed"', ["re-sign-record", "recompute-batch-root"], [23],
    ["method-cap-exceeded"], _b302, spec="L565-566")


def _b303() -> dict[str, Any]:
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    b1 = sha256hex(jcs(binding_preimage(env, version="1")))
    st["predicate"]["observationRecords"] = [
        record(arming_payload(b1)), record(sealed_payload(b1))]
    return reroot(st)


vec("bad-303-binding-version-1", "ok-002",
    'records signed with a binding derived from the retired '
    '"aeeBindingVersion": "1" pre-image', ["derive-binding-v1",
                                           "re-sign-record",
                                           "recompute-batch-root"], [75, 22],
    ["run-binding-mismatch"], _b303, spec="L237-241; L563-564",
    note="negative known-answer: version 1 is retired with no alias and no "
         "dual-accept window, so its pre-image MUST NOT match; a verifier has "
         "exactly one construction and never tries a second. The vector is "
         "named for the construction its records were minted under, and it is "
         "the retired one rather than a future one on purpose: a vector minted "
         "under a version nobody has implemented rejects whether or not the "
         "rule holds, because its digest matches no construction at all, while "
         "this one is a digest a real producer could have emitted last "
         "revision")
def _b726() -> dict[str, Any]:
    st = P_clean()
    return mutate_record_payload(st, 0, lambda o: {**o, "aeeBindingVersion": "3"})


vec("bad-726-arming-binding-version-carried", "ok-002",
    "arming payload carries an explicit aeeBindingVersion: \"3\" the verifier "
    "does not implement (read-first, distinct from the bad-303 digest mismatch)",
    ["re-sign-record", "recompute-batch-root"], [75],
    ["arming-covers-nothing"],
    _b726,
    spec="L237-244",
    note="an explicit binding-version declaration the verifier does not "
         "implement is read before deriving and makes the arming record cover "
         "nothing, distinguishably from a run-binding digest mismatch. The "
         "declared version has to be one no verifier implements, so it moves "
         "whenever the implemented construction does: it read \"2\" while the "
         "implemented construction was version 1, and left that value in place "
         "the version 2 landed, at which point the record declared exactly what "
         "the verifier derives and the vector asserted nothing")


def _b304() -> dict[str, Any]:
    st = P_multirecord()
    return mutate_record_payload(
        st, 1, lambda o: {**o, "aeeMethod": "reconstructed"})


vec("bad-304-method-cap-multirecord", "ok-030",
    'row method "intercepted" covered by TWO interceptions with signed '
    "methods {intercepted, reconstructed}: exceeds the weakest",
    ["re-sign-record", "recompute-batch-root"], [23, 45],
    ["method-cap-exceeded"], _b304, spec="L565-566",
    note="min-composition: a max()/any() rail wrongly accepts this")

# --- (b5) batchRoot / RFC 6962 -------------------------------------------


def _b401() -> dict[str, Any]:
    st = P_clean()
    del st["predicate"]["batchRoot"]
    return st


vec("bad-401-records-no-batchroot", "ok-002",
    "batchRoot member removed while observationRecords is non-empty", [],
    [24], ["batch-root-missing"], _b401, spec="L1603; L1615-1617")


def _b402() -> dict[str, Any]:
    st = P_three_records()
    st["predicate"]["batchRoot"] = merkle_root_no_domain(
        st["predicate"]["observationRecords"])
    return st


vec("bad-402-root-no-domain-separation", "ok-014",
    "root computed without the 0x00/0x01 domain-separation prefixes", [],
    [25], ["batch-root-mismatch"], _b402, spec="L1605-1608")


def _b403() -> dict[str, Any]:
    st = P_three_records()
    st["predicate"]["batchRoot"] = merkle_root_dup_pad(
        st["predicate"]["observationRecords"])
    return st


vec("bad-403-root-bitcoin-padding", "ok-014",
    "3-leaf root computed by duplicate-last-leaf padding instead of the "
    "RFC 6962 recursive split", [], [26], ["batch-root-mismatch"], _b403,
    spec="L1608-1610")


def _b404() -> dict[str, Any]:
    st = P_three_records()
    recs = st["predicate"]["observationRecords"]
    st["predicate"]["batchRoot"] = merkle_root([recs[1], recs[0], recs[2]])
    return st


vec("bad-404-root-leaf-order-swapped", "ok-014",
    "root computed over leaves in swapped order", [], [27],
    ["batch-root-mismatch"], _b404, spec="L1610")


def _b405() -> dict[str, Any]:
    st = P_clean()
    recs = st["predicate"]["observationRecords"]
    recs.append(copy.deepcopy(recs[0]))
    return reroot(st)


vec("bad-405-duplicate-records", "ok-002",
    "two byte-identical records in the tree; root recomputes CORRECTLY "
    "over all three leaves", ["recompute-batch-root"], [29],
    ["duplicate-record"], _b405, spec="L1612-1613",
    note="single fault: duplicate identity, not root arithmetic")


def _b406() -> dict[str, Any]:
    st = P_clean()
    st["predicate"]["batchRoot"] = hex_tamper(st["predicate"]["batchRoot"])
    return st


vec("bad-406-root-hex-tamper", "ok-002",
    "one hex digit of batchRoot flipped", [], [30], ["batch-root-mismatch"],
    _b406, spec="L1615-1617")


def _b407() -> dict[str, Any]:
    st = P_caught()
    del st["predicate"]["observationRecords"]
    del st["predicate"]["batchRoot"]
    return st


vec("bad-407-substrate-row-no-records", "ok-001",
    "remove observationRecords AND batchRoot under a substrate row "
    "(2-op mutation)", [], [31, 11], ["records-absent", "ref-out-of-range"],
    _b407, compound=True, spec="L1619-1631; L552-553",
    note="precedence pin: records-absent is reported when the array is "
         "absent entirely; ref-out-of-range only when records exist")


def _b408() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["batchRoot"] = D["orphan-root"]
    return st


vec("bad-408-batchroot-without-records", "ok-007",
    "orphan batchRoot added to a recordless artifact-only statement", [],
    [31], ["batch-root-orphaned"], _b408, spec="L1619-1631; L1611")


def _b409() -> dict[str, Any]:
    st = P_artifact_with_records()
    st["predicate"]["batchRoot"] = hex_tamper(st["predicate"]["batchRoot"])
    return st


vec("bad-409-artifact-records-bad-root", "ok-029",
    "one hex digit off on an artifact-only-with-records statement", [],
    [30, 24], ["batch-root-mismatch"], _b409, spec="L1615-1617",
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
    spec="L720-724; L1012-1049",
    note="pairs with ok-008: the SAME fail-closed axis on an artifact row "
         "is a VALID fail")
vec("bad-502-missing-actual-layer", "ok-001",
    "drop actualLayer from the row", [], [47],
    ["malformed-missing-actual-layer"],
    _row_mut(P_caught, 0,
             lambda r: {k: v for k, v in r.items() if k != "actualLayer"}),
    spec="L887-888; L1212-1220",
    note="malformed STATEMENT, deliberately NOT a fail-closed row: a "
         "verifier answering result:fail here fails conformance")
vec("bad-503-clean-row-layer-not-none", "ok-002",
    'clean row actualLayer: "policy.egress_sinkhole" (MUST be the literal '
    '"none")', [], [48], ["clean-row-layer-not-none"],
    _row_mut(P_clean, 0,
             lambda r: {**r, "actualLayer": "policy.egress_sinkhole"}),
    spec="L1221-1226")
vec("bad-818-artifact-clean-row-layer-not-none", "ok-007",
    'artifact clean row actualLayer: "policy.egress_sinkhole" (a clean row '
    'MUST carry the literal "none" regardless of basis)', [], [48],
    ["clean-row-layer-not-none"],
    _row_mut(P_artifact_clean, 0,
             lambda r: {**r, "actualLayer": "policy.egress_sinkhole"}),
    spec="L1221-1226",
    note="pairs with bad-503, the substrate twin: the clean-row none rule is "
         "not scoped to a basis (L1221-1226 says 'a row', no basis qualifier), so "
         "an artifact clean row is held to it too")
vec("bad-504-substrate-oov-label", "ok-001",
    'substrate row containmentObserved: "example_label_a" (not in carried '
    "labels); carried fail kept", [], [4, 44],
    ["fail-closed-substrate-row"],
    _row_mut(P_caught, 0,
             lambda r: {**r, "containmentObserved": "example_label_a"}),
    spec="L443-444; L720-724",
    note="pairs with ok-009 (artifact twin stays valid)")
vec("bad-505-substrate-missing-method", "ok-001",
    "substrate row method member ABSENT", [], [5, 42, 44],
    ["fail-closed-substrate-row"],
    _row_mut(P_caught, 0,
             lambda r: {k: v for k, v in r.items() if k != "method"}),
    spec="L443-444; L1012-1049; L720-724",
    note="pairs with ok-027 (artifact row with absent method is a VALID "
         "fail)")
vec("bad-506-actuallayer-json-number", "ok-001",
    "caught row actualLayer carried as the JSON number 7 (wrong member "
    "type); refs, records, root, entropy intact; carried fail kept", [],
    [88], ["statement-malformed"],
    _row_mut(P_caught, 0, lambda r: {**r, "actualLayer": 7}),
    spec="L880-888",
    note="type-strictness pin: row members are strings, and a wrong-typed "
         "member is a decode-layer fault, deliberately a DIFFERENT altitude "
         "than an absent one, a rail that maps the number to member "
         "absence (malformed-missing-actual-layer) fails conformance here")

# --- (f/g) vocabulary + runEntropy + subject -----------------------------


def _b601() -> dict[str, Any]:
    st = P_artifact()
    del st["predicate"]["observationEnvironment"]["observationVocabulary"]
    return st


vec("bad-601-vocabulary-absent", "ok-007",
    "drop observationVocabulary; carried fail kept", [], [51],
    ["vocabulary-missing"], _b601, spec="L756-764",
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
        # The carried vocabulary digest is a binding input under version 2, so
        # every one of these mutations moves the derived binding. Rederiving
        # over the mutated statement keeps the vocabulary rule the only fault;
        # for the stale-digest vector that means deriving over the STALE value,
        # which is what a verifier reading the carried bytes derives too.
        return rebind_records(st)
    return b


_VOCAB_REDERIVE = ["recompute-vocabulary-digest", "rederive-binding",
                   "re-sign-record", "recompute-batch-root"]

vec("bad-602-caught-not-subset", "ok-002",
    'caught gains "example_label_x" which is not in labels; digest '
    "recomputed over the mutated content",
    _VOCAB_REDERIVE, [52], ["vocabulary-caught-not-subset"],
    _vocab_mut(caught=["egress_captured", "example_label_x"]),
    spec="L760-762")
vec("bad-603-labels-unsorted", "ok-002",
    "labels in descending order; digest recomputed",
    _VOCAB_REDERIVE, [53], ["vocabulary-not-canonical"],
    _vocab_mut(labels=["no_egress", "egress_captured"]), spec="L762")
vec("bad-604-caught-duplicate", "ok-002",
    "duplicate entry in caught; digest recomputed",
    _VOCAB_REDERIVE, [53], ["vocabulary-not-canonical"],
    _vocab_mut(caught=["egress_captured", "egress_captured"]), spec="L762")
vec("bad-605-vocabulary-digest-mismatch", "ok-002",
    "stale vocabulary digest over unchanged content",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"], [54],
    ["vocabulary-digest-mismatch"], _vocab_mut(stale=True, redigest=False),
    spec="L762-764",
    note="the binding is rederived over the STALE carried digest, not over "
         "the digest the arrays recompute to, because that is the value a "
         "verifier reading the statement folds into the pre-image; deriving "
         "over the honest one would leave every record mismatched and the "
         "vector would report a binding fault instead of the digest fault")


def _b606() -> dict[str, Any]:
    st = P_clean()
    del st["predicate"]["observationEnvironment"]["runEntropy"]
    return st


vec("bad-606-missing-runentropy", "ok-002",
    "drop runEntropy on a substrate-row-carrying statement", [], [57],
    ["run-entropy-missing"], _b606, spec="L768-770; L224-225",
    note="precedence pin: a missing binding INPUT reports its member code, "
         "never run-binding-mismatch")


def _b607() -> dict[str, Any]:
    st = P_clean()
    st["subject"].append({"name": "example-agent-bundle-b",
                          "digest": {"sha256": D["subject-b"]}})
    return st


vec("bad-607-two-subjects-substrate", "ok-002",
    "second subject appended to a substrate-row-carrying statement", [],
    [58], ["subject-cardinality"], _b607, spec="L210-213",
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
    _verbatim_rebind(_m608), spec="L210-224",
    note="a rail that derives verbatim finds the binding EQUAL; only the "
         "lowercase-64-hex format rule fails")
vec("bad-609-digest-truncated", "ok-002",
    "substrate digest truncated to 63 hex chars; verbatim rederive chain",
    ["rederive-run-binding-verbatim", "re-sign-record",
     "recompute-batch-root"], [59], ["digest-not-canonical"],
    _verbatim_rebind(_m609), spec="L210-224")


def _b610() -> dict[str, Any]:
    st = P_caught()
    env = st["predicate"]["observationEnvironment"]
    v = env["observationVocabulary"]
    v["labels"], v["caught"] = [], []
    v["digest"]["sha256"] = jcs_digest({"caught": [], "labels": []})
    return rebind_records(st)


vec("bad-610-empty-labels-substrate", "ok-001",
    "labels: [] and caught: [] (digest recomputed) under a substrate row "
    "whose label is now out-of-vocabulary",
    ["recompute-vocabulary-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"], [4, 44, 53],
    ["fail-closed-substrate-row"], _b610, spec="L720-724; L762",
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
    ["subject-sha256-missing"], _b611, spec="L210-224",
    note="precedence pin: missing binding input reports the member code; "
         "records keep the parent binding (unreachable check)")


def _b612() -> dict[str, Any]:
    st = P_caught()
    v = st["predicate"]["observationEnvironment"]["observationVocabulary"]
    v["labels"] = [*v["labels"], "\U0001F600"]
    v["digest"]["sha256"] = jcs_digest(
        {"caught": v["caught"], "labels": v["labels"]})
    return rebind_records(st)


vec("bad-612-labels-non-bmp", "ok-001",
    "labels gains the supplementary-plane entry U+1F600; digest recomputed "
    "over the mutated content",
    ["recompute-vocabulary-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"], [86], ["vocabulary-not-canonical"],
    _b612, spec="L150-163",
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


def _seal_mut(parentfn: Callable[[], dict[str, Any]], idx: int,
              mutfn: Callable[[dict[str, Any]], dict[str, Any]]
              ) -> Callable[[], dict[str, Any]]:
    """Break the seal a row rests on, and leave a healthy one beside it.

    From 0.7 a statement carrying a substrate row must carry a valid sealed
    record whether or not any row resolves it. A vector whose subject is a
    seal that covers no CLEAN ROW would therefore also carry "this statement
    has no valid seal at all", and a rail could pass it having implemented
    neither of the two rules: reject on the second and never look at the
    first. The healthy, unreferenced seal separates them, so the referenced
    seal still fails its own constraint and the statement still has a seal.
    """
    def b() -> dict[str, Any]:
        st = mutate_record_payload(parentfn(), idx, mutfn)
        env = st["predicate"]["observationEnvironment"]
        st["predicate"]["observationRecords"].append(
            record(sealed_payload(binding_for(env))))
        return reroot(st)
    return b


vec("bad-701-arming-missing-armedat", "ok-002",
    "drop armedAt from the arming payload",
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {k: v for k, v in o.items() if k != "armedAt"}),
    spec="L1266-1270; L1287-1290")
vec("bad-702-armedat-after-issuedat", "ok-002",
    'arming armedAt: "2026-01-01T00:01:00Z" (after issuedAt)',
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "armedAt": "2026-01-01T00:01:00Z"}),
    spec="L1269-1270")
vec("bad-703-arming-posture-mismatch", "ok-002",
    "arming aeePostureDigest differs from the pinned posture digest",
    ["re-sign-record", "recompute-batch-root"], [63, 65],
    ["arming-covers-nothing", "sealed-covers-nothing",
     "clean-row-uncovered"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeePostureDigest": D["other-posture"]}),
    compound=True, spec="L1266-1270; L1291-1296",
    note="inherently compound: the sealed record must equal BOTH the "
         "arming record's and the pinned digest, so one arming edit "
         "un-covers the sealed record too")
vec("bad-704-arming-method-reconstructed", "ok-002",
    'arming record signed aeeMethod: "reconstructed"',
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0, lambda o: {**o, "aeeMethod": "reconstructed"}),
    spec="L1270; L1287-1290")
vec("bad-705-sealed-missing-dropcount", "ok-002",
    "drop aeeDropCount from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [64],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {k: v for k, v in o.items() if k != "aeeDropCount"}),
    spec="L1273-1278")
vec("bad-706-stillarmed-non-boolean", "ok-002",
    'sealed aeeStillArmed: "true" (string, not boolean)',
    ["re-sign-record", "recompute-batch-root"], [64],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1, lambda o: {**o, "aeeStillArmed": "true"}),
    spec="L1273-1278")
vec("bad-707-sealed-stillarmed-false", "ok-002",
    "sealed aeeStillArmed: false",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1, lambda o: {**o, "aeeStillArmed": False}),
    spec="L1291-1296")
vec("bad-708-sealed-drops-no-bound", "ok-002",
    "sealed aeeDropCount: 3 with no aeeDropBound declared",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1, lambda o: {**o, "aeeDropCount": 3}),
    spec="L1291-1296")
vec("bad-709-sealed-drops-exceed-bound", "ok-003",
    "sealed aeeDropCount: 6 exceeding the declared aeeDropBound: 5",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean_bounded, 1, lambda o: {**o, "aeeDropCount": 6}),
    spec="L1291-1296")
vec("bad-710-sealed-posture-mismatch", "ok-002",
    "sealed aeePostureDigest edited (differs from the arming record's AND "
    "the pinned digest, which the arming constraint makes equivalent)",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {**o, "aeePostureDigest": D["other-posture"]}),
    compound=True, spec="L1291-1296",
    note="both posture sub-clauses fire together; they are distinguishable "
         "only in already-invalid statements")
vec("bad-712-examination-method-intercepted", "ok-006",
    'examination record signed aeeMethod: "intercepted"',
    ["re-sign-record", "recompute-batch-root"], [66],
    ["examination-covers-nothing"],
    _rec_mut(P_reconstructed, 0,
             lambda o: {**o, "aeeMethod": "intercepted"}),
    spec="L1279-1281; L1287-1290")


def _b713() -> dict[str, Any]:
    """The covering seal sits BEFORE the referenced one, and that ordering is
    the whole vector.

    This built the covering seal LAST, which produced a statement byte-identical
    to `bad-707`: `_seal_mut` already appends an unreferenced covering seal, on
    purpose and for a documented reason, so hand-building the same three records
    in the same order reconstructed a vector that already existed. Two
    identifiers then addressed one statement, and `aee-c-68` was credited with a
    discriminator that was really `aee-c-65`'s.

    Putting the covering seal first makes the statement distinct AND buys the
    discrimination the duplicate never had. A rail that resolves the row's
    referenced set rejects this, because the seal the row names does not cover.
    A rail that instead scans the record list and stops at the first seal that
    covers accepts it. Under the old ordering that rail also had to scan past
    the bad seal to reach the good one, so the vector could not tell a
    first-match scanner from a correct implementation; now it can.
    """
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    b = binding_for(env)
    st["predicate"]["observationRecords"] = [
        record(arming_payload(b)),
        record(sealed_payload(b)),                   # covering, UNREFERENCED, FIRST
        record(sealed_payload(b, still=False)),      # referenced, bad
    ]
    st["predicate"]["attackResults"][0]["observationRefs"] = [0, 2]
    return reroot(st)


vec("bad-713-only-sealed-ref-noncovering", "ok-002",
    "clean row refs [good-arming, non-covering-sealed]; a fully-covering "
    "sealed record sits UNREFERENCED and EARLIER in the tree",
    ["recompute-batch-root"], [68], ["sealed-covers-nothing"], _b713,
    spec="L1139-1140; L557-560",
    note="discriminates rails that scan all records instead of the row's "
         "referenced set, and specifically one that stops at the first seal "
         "that covers: the covering seal precedes the referenced one")
vec("bad-714-unknown-kind-sole-cover", "ok-002",
    'the arming record\'s aeeKind becomes "aee-future-x" (record otherwise '
    "fully valid); the clean row's only arming ref now covers nothing",
    ["re-sign-record", "recompute-batch-root"], [71],
    ["record-kind-unknown-covers-nothing"],
    _rec_mut(P_clean, 0, lambda o: {**o, "aeeKind": "aee-future-x"}),
    spec="L1561-1565",
    note="pairs with ok-013: an unknown kind that no row NEEDS is ignored "
         "and only contributes its leaf")
vec("bad-715-sealed-missing-stillarmed", "ok-002",
    "drop aeeStillArmed from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [64],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {k: v for k, v in o.items()
                         if k != "aeeStillArmed"}),
    spec="L1273-1278")
vec("bad-716-sealed-missing-posture", "ok-002",
    "drop aeePostureDigest from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [64, 65],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {k: v for k, v in o.items()
                         if k != "aeePostureDigest"}),
    spec="L1273-1278; L1291-1296")
vec("bad-717-arming-missing-posture", "ok-002",
    "drop aeePostureDigest from the arming payload",
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {k: v for k, v in o.items()
                        if k != "aeePostureDigest"}),
    spec="L1266-1270")
vec("bad-727-armedat-non-utc-offset", "ok-002",
    "armedAt carries a non-zero UTC offset (+05:00): a valid instant no later "
    "than issuedAt, but not RFC 3339 UTC",
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "armedAt": "2025-12-31T23:59:00+05:00"}),
    spec="L1269",
    note="RFC 3339 UTC means a zero offset; +05:00 parses as a valid instant "
         "(18:59Z, before issuedAt) but is not UTC, so the arming record covers "
         "nothing, distinct from a late armedAt (bad-702)")


# --- round-8 corner resolutions (open corners C/A/B locked; see
#     docs/interpretation-decisions-open.md) --------------------------------

def _b728() -> dict[str, Any]:
    st = P_artifact()  # artifact-only, no substrate rows
    st["subject"].append({"name": "example-agent-bundle-b",
                          "digest": {"sha256": D["subject-b"]}})
    return st


vec("bad-728-artifact-two-subjects", "ok-007",
    "a second subject appended to an ARTIFACT-ONLY statement (no substrate "
    "rows)", [], [58], ["subject-cardinality"], _b728, spec="L210-213",
    note="subject cardinality is unconditional (spec:210-213): exactly one "
         "subject on a statement of any basis. bad-607 keeps a substrate row; "
         "this locks the previously substrate-scoped rule as unconditional on "
         "an artifact-only statement")


def _b729() -> dict[str, Any]:
    st = P_caught()  # single caught row, manifest M1 (one attack)
    rows = st["predicate"]["attackResults"]
    rows.append(dict(rows[0]))  # a second row with the SAME attackId
    return st


vec("bad-729-duplicate-attackid-rows", "ok-001",
    "a second attackResults row carrying the SAME attackId as the first "
    "(one row per executed attack)", [], [90], ["statement-malformed"], _b729,
    spec="L880-892",
    note="two rows share attackId XA-EXAMPLE-1. Coverage integrity set-compares "
         "row attackIds to the manifest, so a duplicate collapses under set "
         "semantics and would pass silently; uniqueness is a well-formedness "
         "invariant detected before the set is built")


def _b730() -> dict[str, Any]:
    st = P_degraded()  # manifest MAB: classes XA, XB; assessedClasses ["XA"]
    # XA now appears in BOTH assessedClasses and outOfScope: the three coverage
    # sets are no longer a disjoint partition.
    st["predicate"]["coverage"]["outOfScope"] = {
        "XA": "example scope reason", "XB": "example scope reason"}
    return st


vec("bad-730-coverage-class-overlap", "ok-004",
    "class XA appears in BOTH assessedClasses and outOfScope: the three "
    "coverage sets are not a disjoint partition", [], [82],
    ["coverage-incomplete"], _b730, spec="L872-876",
    note="the from-spec checker accepts overlap (completeness-only); our two "
         "rails reject it (disjoint partition). A class both assessed and "
         "disclosed as a gap is contradictory. Keeping the reject reading is "
         "the converged debate recommendation, reversible at vetting")


CHAIN_SCOPE = ["subject"]

vec("bad-718-chain-runseq-zero", "ok-002",
    "arming payload gains aeeRunSeq: 0 with aeeChainScope present (a "
    "sequence number is a positive integer)",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeeChainScope": CHAIN_SCOPE, "aeeRunSeq": 0}),
    spec="L1485-1516",
    note="pairs with the genesis accept vector ok-034 (aeeRunSeq 1, scope "
         "present, no predecessor)")
vec("bad-719-chain-missing-scope", "ok-002",
    "arming payload gains aeeRunSeq: 1 with NO aeeChainScope "
    "(aeeChainScope is required whenever aeeRunSeq is present)",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0, lambda o: {**o, "aeeRunSeq": 1}),
    spec="L1485-1516",
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
    spec="L1485-1516",
    note="a predecessor binding is a lowercase 64-hex run binding digest, "
         "present exactly when aeeRunSeq exceeds 1")

vec("bad-721-chain-scope-not-array", "ok-002",
    "arming payload gains aeeRunSeq: 1 with aeeChainScope as a free-form "
    "string, not the required array of registered dimension tokens",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeeChainScope": "example-substrate-key-and-subject/v1",
                        "aeeRunSeq": 1}),
    spec="L1489-1493",
    note="the old free-form string form is rejected fail-closed; array of "
         "registered tokens is the sole accepted shape (no alias)")
vec("bad-722-chain-scope-unknown-dimension", "ok-002",
    "arming payload gains aeeRunSeq: 1 with an aeeChainScope carrying a "
    "token outside the closed dimension vocabulary",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeeChainScope": ["bogus-dimension"], "aeeRunSeq": 1}),
    spec="L1489-1493",
    note="an unrecognized dimension token fails closed, as every closed "
         "vocabulary in this spec does")
vec("bad-723-chain-scope-not-canonical", "ok-002",
    "arming payload gains aeeRunSeq: 1 with an aeeChainScope array whose "
    "tokens are not in canonical (UTF-16 code-unit) order",
    ["re-sign-record", "recompute-batch-root"], [89],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "aeeChainScope": ["subject", "corpus"], "aeeRunSeq": 1}),
    spec="L1489-1493",
    note="canonical order is corpus < networkPosture < subject; the same "
         "canonicality rule as observationVocabulary.labels")
vec("bad-724-artifact-ref-out-of-range", "ok-029",
    "an artifact row carries an observationRefs index out of range for "
    "observationRecords (fail-closed on any row, not only substrate rows)",
    [], [11], ["ref-out-of-range"],
    set_refs(P_artifact_with_records, 0, [99]),
    spec="L552-553",
    note="an out-of-range reference is a structural integrity fault on any "
         "row regardless of basis; a reference that does not resolve is "
         "never silently ignored")

def _b725() -> str:
    """A statement carrying a duplicate top-level member (RFC 7493). The dict
    representation cannot express a repeat, so emit raw text with a second
    predicateType member. json.loads keeps the last silently; a strict rail
    parses the whole statement as I-JSON and rejects the duplicate statement-wide,
    not only inside record payloads."""
    st = P_clean()
    text = json.dumps(st, indent=2, sort_keys=True, ensure_ascii=False)
    lines = text.split("\n")
    dup = ('  "predicateType": '
           '"https://in-toto.io/attestation/adversarial-execution-evidence/v0.6",')
    lines.insert(1, dup)
    return "\n".join(lines)


vec("bad-725-statement-duplicate-member", "ok-002",
    "raw statement bytes carrying a duplicate top-level predicateType member "
    "(the whole statement is parsed as strict I-JSON, not only record payloads)",
    [], [18], ["statement-malformed"],
    _b725, spec="L100-106",
    note="rawStatement: the dict form cannot carry a duplicate member; a lenient "
         "parser keeps the last silently, so a duplicate anywhere in the "
         "statement is a malformed statement, fail-closed")

# --- (k) statement-level -------------------------------------------------


def _b801() -> dict[str, Any]:
    st = P_clean()
    st["predicateType"] = ("https://in-toto.io/attestation/"
                           "adversarial-execution-evidence/v0.5")
    return st


vec("bad-801-wrong-predicatetype", "ok-002",
    "v0.5 predicateType URI on a v0.6-shaped statement", [], [77],
    ["predicate-type-unsupported"], _b801, spec="L3; L317",
    note="a verifier MUST NOT process this as v0.6")


def _drop_env(member: str) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = P_artifact()
        del st["predicate"]["observationEnvironment"][member]
        return st
    return b


vec("bad-802-missing-catchpolicy", "ok-007", "drop catchPolicy", [],
    [78], ["environment-incomplete"], _drop_env("catchPolicy"),
    spec="L743-753",
    note="artifact-only parent: no binding cascade; defeats the "
         "empty-vs-enforcing policy distinguishability")


def _b803() -> dict[str, Any]:
    st = P_artifact()
    env = st["predicate"]["observationEnvironment"]
    env["corpus"]["digest"]["sha256"] = D["stale-corpus"]
    return st


vec("bad-803-corpus-digest-mismatch", "ok-007",
    "corpus.digest is not the JCS digest of the embedded manifest", [],
    [79], ["corpus-digest-mismatch"], _b803, spec="L747-751; L770-773",
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
    ["manifest-duplicate-attack"], _b804, spec="L749-751",
    note="artifact-only degraded parent avoids any binding cascade; "
         "coverage over the assessed class is unchanged")
vec("bad-805-row-unknown-attackid", "ok-001",
    'row attackId: "XA-EXAMPLE-9" absent from the manifest', [],
    [81, 82], ["row-attack-unknown", "coverage-incomplete"],
    _row_mut(P_caught, 0, lambda r: {**r, "attackId": "XA-EXAMPLE-9"}),
    compound=True, spec="L880; L923-926",
    note="precedence pin: row-attack-unknown")


def _b806() -> dict[str, Any]:
    st = P_two_attacks()
    del st["predicate"]["attackResults"][1]
    return st


vec("bad-806-coverage-attack-omitted", "ok-011",
    "one of the two rows of a 2-attack assessed class deleted (quiet "
    "omission)", [], [82], ["coverage-incomplete"], _b806,
    spec="L923-926",
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
    spec="L923-926",
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
    spec="L867-872; L923-926",
    note="distinct from bad-806/807 (attack granularity within an assessed "
         "class): a whole manifest class left silently unaccounted")


def _b819() -> dict[str, Any]:
    st = P_caught()
    st["predicate"]["coverage"]["assessedClasses"] = ["XA", "XZ"]
    return st


vec("bad-819-assessed-class-not-in-manifest", "ok-001",
    "assessedClasses padded with class XZ the manifest never carried", [],
    [82], ["coverage-incomplete"], _b819,
    spec="L872-876; L923-926",
    note="mirror of bad-816 (a manifest class dropped from every coverage set): "
         "here a fabricated class pads assessedClasses. Coverage must be an "
         "exhaustive, disjoint partition of the manifest's real classes, so a "
         "class in a coverage set that the manifest never carried is the same "
         "class-granularity coverage-partition fault")


def _b731() -> dict[str, Any]:
    st = P_degraded()
    st["predicate"]["coverage"]["outOfScope"]["XZ"] = \
        "unknown class the manifest never carried"
    return st


vec("bad-731-outofscope-unknown-class", "ok-004",
    "outOfScope carries class XZ the manifest never carried", [],
    [82], ["coverage-incomplete"], _b731,
    spec="L872-876; L923-926",
    note="reason-map mirror of bad-819 (which forces the assessedClasses side). "
         "The three coverage sets are a disjoint partition of the manifest's "
         "classes, so membership runs both ways; nothing forced the outOfScope "
         "side until now (in-toto/attestation#570 round-8, Rul1an). Both rails "
         "already enforce it (Go statement.go, Python _coverage_partition_ok); "
         "this vector locks the rule and mutation-proves the rails.")


def _b732() -> dict[str, Any]:
    st = P_degraded()
    st["predicate"]["coverage"]["routedElsewhere"]["XZ"] = \
        "unknown class the manifest never carried"
    return st


vec("bad-732-routedelsewhere-unknown-class", "ok-004",
    "routedElsewhere carries class XZ the manifest never carried", [],
    [82], ["coverage-incomplete"], _b732,
    spec="L872-876; L923-926",
    note="reason-map mirror of bad-819 for the routedElsewhere side (see "
         "bad-731). Closes the second untested consequence of the "
         "partition-membership rule (in-toto/attestation#570 round-8).")


# --- (l) byte-level string well-formedness -------------------------------
#
# This quadrant had ZERO corpus coverage until now. Decoding all 140 vector
# files of suiteRevision 4 and all 219 base64 record payloads found no escape
# sequence of any
# kind, no non-UTF-8 byte and no raw control character anywhere, in either
# position. It is also the quadrant where the rails actually diverged in the
# field: one accepted a statement the other three rejected, and a fourth
# crashed instead of returning a verdict.
#
# Every statement-position vector here appends the fault to
# observationVocabulary.labels and recomputes the vocabulary digest OVER THE
# MUTATED CONTENT. That is the point. A rail that decodes leniently sees a
# self-consistent vocabulary and has no other rule left to catch the statement
# on, so only a check on the raw bytes rejects it. The digest is computed with
# surrogatepass where the content is not otherwise encodable, which is exactly
# the substitution a lenient rail performs.
#
# The appended label sorts last under UTF-16 code-unit order, because every
# existing label is ASCII, so sortedness, duplicate-freedom and the caught
# subset all still hold and the byte-level fault is the single fault.

_LONE_HI = "zz_\ud800"
_LONE_LO = "zz_\udc00"
_REVERSED = "zz_\udc00\ud800"


def _voc_label_fault(label: str) -> dict[str, Any]:
    """A clean statement whose vocabulary gains `label`, digest recomputed."""
    st = P_clean()
    v = st["predicate"]["observationEnvironment"]["observationVocabulary"]
    v["labels"] = [*v["labels"], label]
    pre = (
        '{"caught":['
        + ",".join(json.dumps(c) for c in v["caught"])
        + '],"labels":['
        + ",".join(json.dumps(x) for x in v["labels"])
        + "]}"
    )
    v["digest"]["sha256"] = sha256hex(pre.encode("utf-8", "surrogatepass"))
    # The vocabulary digest is a binding input under version 2, so recomputing
    # it over the mutated label moves the run binding too. Rederiving and
    # re-signing keeps the byte-level fault the single fault; without it every
    # one of these vectors would also carry a run-binding mismatch, which a
    # lenient rail would report instead of the encoding fault the vector exists
    # to catch.
    return rebind_records(st)


def _escaped(st: dict[str, Any]) -> str:
    """Serialize with ensure_ascii, so a lone surrogate rides as a backslash-u
    ESCAPE and the file itself stays valid UTF-8. This is the half a fatal
    decoder cannot catch: the bytes are well formed, the escape is not."""
    return json.dumps(st, indent=2, sort_keys=True, ensure_ascii=True)


def _b733() -> str:
    return _escaped(_voc_label_fault(_LONE_HI))


vec("bad-733-statement-lone-high-surrogate-escape", "ok-002",
    "vocabulary label carrying an unpaired high surrogate escape; digest "
    "recomputed over the mutated content",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b733, spec="L104-130",
    note="rawStatement: the file is valid UTF-8 and parses as JSON, so only a "
         "check on the raw bytes sees it. A lenient parse yields a lone "
         "surrogate that no later comparison can tell from a written one.")


def _b734() -> str:
    return _escaped(_voc_label_fault(_LONE_LO))


vec("bad-734-statement-lone-low-surrogate-escape", "ok-002",
    "vocabulary label carrying an unpaired low surrogate escape; digest "
    "recomputed over the mutated content",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b734, spec="L104-130",
    note="rawStatement: a low surrogate with no preceding high surrogate.")


def _b735() -> str:
    return _escaped(_voc_label_fault(_REVERSED))


vec("bad-735-statement-reversed-surrogate-pair", "ok-002",
    "vocabulary label carrying a low surrogate followed by a high surrogate; "
    "digest recomputed over the mutated content",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b735, spec="L104-130",
    note="rawStatement: both halves are present, in the wrong order, so a "
         "check that counts surrogates rather than pairing them passes.")


def _b736() -> bytes:
    """The same label as bad-733, encoded rather than escaped. surrogatepass
    emits ED A0 80, a surrogate encoded directly in UTF-8 (CESU-8)."""
    st = _voc_label_fault(_LONE_HI)
    text = json.dumps(st, indent=2, sort_keys=True, ensure_ascii=False)
    return text.encode("utf-8", "surrogatepass")


vec("bad-736-statement-cesu8-vocabulary-label", "ok-002",
    "vocabulary label carrying a surrogate encoded directly in UTF-8 "
    "(CESU-8, ED A0 80); digest recomputed over the mutated content",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b736, spec="L104-130",
    note="rawBytes: not valid UTF-8. A lenient decoder substitutes U+FFFD, and "
         "because the vocabulary digest is recomputed from the decoded strings "
         "the statement is self-consistent afterwards. This is the exact "
         "construction that verified valid on one rail and invalid on three.")


def _b737() -> bytes:
    """C0 AF is an overlong encoding of '/': a sequence a permissive decoder
    accepts and a strict one refuses."""
    st = _voc_label_fault("zz_OVERLONG")
    text = json.dumps(st, indent=2, sort_keys=True, ensure_ascii=False)
    return text.encode("utf-8").replace(b"OVERLONG", b"\xc0\xaf")


vec("bad-737-statement-overlong-utf8", "ok-002",
    "vocabulary label carrying the overlong encoding C0 AF; digest recomputed "
    "over the mutated content",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b737, spec="L104-130",
    note="rawBytes: the overlong form is the other half of the UTF-8 "
         "well-formedness rule, and a length-only scanner steps over it.")


def _b738() -> bytes:
    """A raw U+0001 inside a string literal. JSON forbids an unescaped
    character below U+0020, so this is refused at the byte level rather than
    by any vocabulary rule."""
    st = _voc_label_fault("zz_CTRL")
    text = json.dumps(st, indent=2, sort_keys=True, ensure_ascii=False)
    return text.encode("utf-8").replace(b"CTRL", b"\x01")


vec("bad-738-statement-raw-control-character", "ok-002",
    "vocabulary label carrying a raw unescaped U+0001; digest recomputed over "
    "the mutated content",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b738, spec="L104-130",
    note="rawBytes: JSON forbids an unescaped character below U+0020.")


def _b739() -> dict[str, Any]:
    """A covering payload carrying an unpaired surrogate escape. The payload is
    base64 inside the statement, so the statement file stays valid UTF-8 and
    the fault is reached only after the record decodes."""
    st = P_caught()
    obj = json.loads(unb64(st["predicate"]["observationRecords"][0]["payload"]))
    obj["aeeNote"] = _LONE_HI
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)
    return raw_record_bytes(st, 0, body.encode())


vec("bad-739-payload-lone-surrogate-escape", "ok-001",
    "covering payload gains a member whose value carries an unpaired surrogate "
    "escape",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b739, spec="L1217-1220",
    note="rawBytes: the payload position of the rule bad-733 covers "
         "statement-wide. The code differs because a payload that is not a "
         "parseable I-JSON value covers nothing.")


def _b740() -> dict[str, Any]:
    """The same payload fault as bad-739, encoded rather than escaped."""
    st = P_caught()
    obj = json.loads(unb64(st["predicate"]["observationRecords"][0]["payload"]))
    obj["aeeNote"] = "PLACEHOLDER"
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()
    return raw_record_bytes(st, 0, body.replace(b"PLACEHOLDER",
                                                b"\xed\xa0\x80"))


vec("bad-740-payload-cesu8", "ok-001",
    "covering payload gains a member whose value carries a surrogate encoded "
    "directly in UTF-8 (CESU-8, ED A0 80)",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b740, spec="L1217-1220",
    note="rawBytes: the payload path byte-compares against the carried bytes, "
         "so a substitution cannot round-trip there; this vector pins the "
         "CODE rather than the verdict.")


def _b741() -> dict[str, Any]:
    """A covering payload that is otherwise complete and valid, carrying ONE
    producer member nested 129 deep -- one level past the normative bound.

    The nesting is added to a real covering payload rather than replacing it, so
    depth is the single fault. An earlier draft replaced the payload outright,
    which also dropped the reserved members: every rail still rejected, but a
    rail whose own bound is 256 rejected for the missing members instead, and
    the vector discriminated nothing."""
    depth = 129
    st = P_caught()
    obj = json.loads(unb64(st["predicate"]["observationRecords"][0]["payload"]))
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)
    deep = '{"a":' * depth + "1" + "}" * depth
    # Splice the deep value in as one more member, keeping the object canonical:
    # "aaDeep" sorts before every reserved member name, which all start "aee".
    body = '{"aaDeep":' + deep + "," + body[1:]
    return raw_record_bytes(st, 0, body.encode())


vec("bad-741-payload-nesting-exceeds-max-depth", "ok-001",
    "covering payload nested 129 deep, one level past the normative bound",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b741, spec="L145-152",
    note="rawBytes: the bound is normative because it was not. The reference "
         "rails chose 128 and the independent from-spec checker chose 256, so "
         "identical bytes were evidence to one conforming verifier and "
         "malformed to another across 127 depths.")


def _b742() -> dict[str, Any]:
    """A covering payload nested 129 deep whose deepest leaf is an EMPTY container.

    The twin of bad-741, and the one bad-741 could not catch. A rail that charges a
    nesting level only when it recurses into a child -- rather than when a container
    OPENS -- never charges an empty container its own level, so an empty-object or
    empty-array leaf slips one level past the bound. bad-741's leaf is a scalar,
    which forces a child recursion and is charged correctly, so it hid this. Here the
    innermost value is `{}`: 128 wrapping objects plus the empty object is
    open-container depth 129, one past the bound, and the empty container is the only
    fault. Two reference rails (the Go core and the TypeScript payload parse)
    accepted this until the guard moved into the container branch."""
    st = P_caught()
    obj = json.loads(unb64(st["predicate"]["observationRecords"][0]["payload"]))
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)
    # The payload's own outermost brace is open-container depth 1, so a member value
    # of 127 wrapping objects around an empty object puts that empty object at depth
    # 129 -- one past the bound, and the exact depth where a per-child counter accepts
    # it. (bad-741's scalar leaf at 129 wrapping lands at depth 130, one deeper, where
    # even the buggy counter rejects; that is why it could not discriminate this.)
    deep = '{"a":' * 127 + "{}" + "}" * 127
    body = '{"aaDeep":' + deep + "," + body[1:]
    return raw_record_bytes(st, 0, body.encode())


vec("bad-742-payload-nesting-empty-container-leaf", "ok-001",
    "covering payload nested 129 deep with an empty-container leaf, one past the bound",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b742, spec="L145-152",
    note="rawBytes: the empty-container companion to bad-741. A rail that charges a "
         "level per parsed child rather than per open container never charges an "
         "empty container, so it accepts at depth 129 what the bracket-counting rails "
         "reject. bad-741's scalar leaf could not discriminate it.")


def _b743() -> str:
    """A vocabulary label carrying U+FFFF, a Unicode noncharacter, as a \\u escape.
    It is a valid scalar value that round-trips faithfully, so unlike the surrogate
    labels the vocabulary digest is recomputed over the canonical (ensure_ascii=False)
    form the rail also canonicalizes, keeping the noncharacter the single fault. RFC
    7493 section 2.1 forbids noncharacters, so a from-spec verifier that implements the
    label rather than the narrower scalar-value MUST rejects it; the byte-level
    string-scalar scan at GATE 0 catches it as statement-malformed before the digest
    is read."""
    st = P_clean()
    v = st["predicate"]["observationEnvironment"]["observationVocabulary"]
    v["labels"] = [*v["labels"], "zz_\uffff"]
    pre = json.dumps({"caught": v["caught"], "labels": v["labels"]},
                     sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    v["digest"]["sha256"] = sha256hex(pre.encode("utf-8"))
    return _escaped(rebind_records(st))


vec("bad-743-statement-noncharacter-vocabulary-label", "ok-002",
    "vocabulary label carrying the noncharacter U+FFFF",
    _VOCAB_REDERIVE, [18], ["statement-malformed"],
    _b743, spec="L110-137",
    note="rawBytes: a noncharacter is a valid scalar that nothing substitutes, so "
         "this is not a live cross-rail split; it is the RFC 7493 label made true, "
         "so a from-spec verifier reading the label does not reject a record we "
         "accept.")


def _b744() -> dict[str, Any]:
    """A covering payload carrying U+FFFF, a Unicode noncharacter, in a producer
    member value. The payload-position companion to bad-743: rejected as
    payload-not-ijson because a payload that is not a well-formed I-JSON value
    covers nothing."""
    st = P_caught()
    obj = json.loads(unb64(st["predicate"]["observationRecords"][0]["payload"]))
    obj["aeeNote"] = "zz_\uffff"
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return raw_record_bytes(st, 0, body)


vec("bad-744-payload-noncharacter", "ok-001",
    "covering payload gains a member whose value carries the noncharacter U+FFFF",
    ["re-sign-record", "recompute-batch-root"], [18], ["payload-not-ijson"],
    _b744, spec="L110-137",
    note="rawBytes: the payload position of bad-743. RFC 7493 section 2.1 forbids "
         "noncharacters in every string literal, not only member names.")


def _b745() -> dict[str, Any]:
    """A covering record whose signatures array is emptied. The spec now requires
    the member to carry at least one entry, and an absent member is the same zero
    as an empty array; the empty array is the spelling that reaches a rail whose
    record type makes signatures a list, since both decode to a count of nothing.

    Nothing is rederived, and that is the finding rather than a shortcut. A DSSE
    leaf is H(0x00 || PAE) and the PAE pre-image spans only payloadType and
    payload, so signatures sit outside every committed digest: the leaf, the
    batchRoot, the run binding and the recomputed result are all bit for bit what
    the parent carried. This is the only mutation in the suite that alters a
    record and moves no commitment at all, which is precisely why the zero case
    was invisible to every other check at this layer -- a statement stripped of
    every signature stayed valid and kept its result, and only the derived
    evidence tier dropped."""
    st = P_caught()
    st["predicate"]["observationRecords"][0]["signatures"] = []
    return st


vec("bad-745-record-signatures-empty", "ok-001",
    "covering record's signatures array emptied to []", [],
    [91], ["record-signatures-empty"], _b745, spec="L1243-1245",
    note="the count is byte-pure and verifies nothing: a record carrying one "
         "fabricated signature entry passes it and is caught only at the tier, so "
         "this vector closes the literal zero-signature case and no more. It is "
         "also the suite's one vector with an empty rederive chain, because "
         "signatures are outside the PAE pre-image and so outside batchRoot")


# bad-745 alone left two questions open, and two rails answered each of them
# differently while every vector still passed.
#
# The first question is WHEN the count is evaluated. bad-745 carries one fault,
# so a rail that counts entries per record inside its payload-decode loop and a
# rail that counts them once over the whole record set before that loop report
# the same condition. Give a statement one record that does not decode and a
# second that carries no signature entry, and the two rails part. Neither is
# wrong: the specification carries no failure-code vocabulary and says the
# sequencing of its own two stages is informative (L413-415), so both rails
# return invalid and name conditions the text is equally happy with. That
# question is therefore not settled by a reject vector at all; it is the
# indeterminate family below, whose members declare every reading a conformant
# rail may take and require the rail's answers to be explained by ONE of them.
#
# The second question is what a signatures member of the WRONG JSON TYPE is. It
# carries no entry, so it fails the same requirement; but a rail that decodes
# the member into a typed list reports the parse catch-all instead, which names
# neither the record nor the member. bad-749 pins the specific condition, on the
# same reasoning that already puts an ABSENT member there rather than under the
# catch-all: absent, empty and wrong-type are one fault counted three ways.


def _b749() -> dict[str, Any]:
    """A record whose signatures member is the JSON string "sig" rather than an
    array. The member carries no entry, so it fails the same at-least-one-entry
    requirement an empty array fails; an entry count over a value that is not an
    array is undefined, and undefined fails closed.

    Nothing is rederived, for the same reason bad-745 rederives nothing:
    signatures sit outside the PAE pre-image, so the leaf, the batchRoot, the run
    binding and the recomputed result are all bit for bit what the parent
    carried."""
    st = P_caught()
    st["predicate"]["observationRecords"][0]["signatures"] = "sig"
    return st


vec("bad-749-record-signatures-not-an-array", "ok-001",
    "covering record's signatures member replaced with the JSON string \"sig\"",
    [], [91], ["record-signatures-empty"], _b749, spec="L1243-1245",
    note="the wrong-type spelling of zero entries. It reads as the more likely "
         "producer bug of the three, since a substrate that emits one signature "
         "object where the schema wants an array of them produces exactly this. "
         "The expected set names the specific condition rather than the parse "
         "catch-all, because the catch-all identifies neither the record nor the "
         "member, and because an ABSENT signatures member already reports the "
         "specific condition on the same reasoning")


# --- (i) the indeterminate family ------------------------------------------
#
# Written into ../indeterminate/ rather than beside the vectors above, because
# what these two members carry is a different claim, and the corpus had nowhere
# to put it. An accept vector says every conformant verifier admits these bytes;
# a reject vector says every conformant verifier refuses them AND names a
# condition this suite pins. Neither sentence can say "the verdict is settled
# and the condition is not", which is the whole of what the specification says
# here: it carries no failure-code vocabulary at all, and it says of its own
# two-stage description that "the sequencing itself is informative" (L413-415).
#
# So a from-spec rail that reports the decode fault where the reference rail
# reports the missing signature is conformant to the text, and a corpus that
# fails it is the corpus overreaching. The alternative available under two
# buckets -- naming both codes in one reject expectation -- is worse, because
# the harness compares code SETS and a widened set is satisfied by either
# answer AND by a rail that emits both, so the vector would stop measuring the
# question rather than start measuring it. That is how a check comes to measure
# nothing.
#
# An indeterminate vector therefore carries a DETERMINED verdict and a set of
# declared READINGS, one condition per reading per member, and the conformance
# requirement is that a rail's answers across the whole family be explained by
# ONE of them. Either answer is admissible; no answer, and no pair of answers
# straddling two readings, is. The reference rail's reading is recorded, not
# required.
#
# Two members are what it takes to discriminate the three readings, and the
# discriminating dimension is the wire order of the two faulted records:
#
#   set-level     the signature-entry count is asked once over the record set
#                 before any payload is decoded. Reports the missing signature
#                 on both members. (The reading this suite's own failure-code
#                 contract describes, and the one both first-party rails take.)
#   positional    the count is asked per record inside the decode loop, so the
#                 first faulted record in wire order wins.
#   decode-first  every payload is decoded before any count is asked, so the
#                 decode fault wins on both members.
#
# The profile a rail cannot have is (missing-signature, decode-fault): reporting
# the LATER fault on one member and the EARLIER one on the other is not produced
# by any policy applied uniformly, and it is the shape a primary-code selector
# that overwrites rather than sets-if-unset produces. A single-fault corpus can
# never see it, which is the reason this family exists at all.

IND_VECTORS: list[dict[str, Any]] = []


def ind(vid: str, family: str, parent: str, mutation: str, conds: list[int],
        readings: dict[str, str],
        build: Callable[[], dict[str, Any]],
        spec: str = "", note: str = "") -> None:
    """Register one member of an indeterminate family.

    ``readings`` maps a reading name to the condition THAT reading predicts for
    THIS member. Every member of a family declares the same reading names; the
    union of the predictions is the closure set a rail's codes must intersect,
    and the per-reading rows are what the coherence check is run against.
    """
    IND_VECTORS.append({"id": vid, "family": family, "parent": parent,
                        "mutation": mutation, "conds": conds,
                        "readings": readings, "spec": spec, "note": note,
                        "build": build})


IND_SIGNATURE_COUNT = "signature-count-vs-payload-decode"


def _clean_with_spare_seal() -> dict[str, Any]:
    """The clean parent, plus a healthy unreferenced seal.

    The family's question is which of two RECORD faults a rail names first, and
    one of its two members puts the decode fault on the record the row rests on
    for its seal. From 0.7 that would additionally leave the statement with no
    valid seal at all, giving a rail a third answer the declared readings do not
    predict and breaking the property that makes the family readable. The spare
    seal removes the third answer from both members symmetrically, so the role
    exchange between them stays the only difference."""
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    st["predicate"]["observationRecords"].append(
        record(sealed_payload(binding_for(env))))
    return reroot(st)


def _i001() -> dict[str, Any]:
    """Two record faults at once, undecodable FIRST: the arming record's payload
    is re-encoded as non-canonical base64 so it no longer strict-decodes, and the
    sealed record's signatures array is emptied.

    Neither mutation moves a commitment. Signatures sit outside the PAE
    pre-image, and a lenient base64 decode of the tampered payload yields the
    parent's exact bytes, so the leaf, the batchRoot and the run binding are
    unchanged and the parent's signatures still verify."""
    st = _clean_with_spare_seal()
    recs = st["predicate"]["observationRecords"]
    recs[0]["payload"] = _noncanonical_b64(recs[0]["payload"])
    recs[1]["signatures"] = []
    return st


def _i002() -> dict[str, Any]:
    """The same two faults with the roles of the two records exchanged, so the
    record carrying no signature is FIRST in wire order.

    This member is what separates a rail that asks the count per record from one
    that decodes everything first: both name the decode fault on _i001, and only
    the decode-first rail still names it here."""
    st = _clean_with_spare_seal()
    recs = st["predicate"]["observationRecords"]
    recs[0]["signatures"] = []
    recs[1]["payload"] = _noncanonical_b64(recs[1]["payload"])
    return st


ind("ind-001-undecodable-then-signatures-empty", IND_SIGNATURE_COUNT, "ok-002",
    "arming record payload re-encoded as non-canonical base64 AND the sealed "
    "record's signatures array emptied, in that wire order",
    [91],
    {"set-level": "record-signatures-empty",
     "positional": "record-undecodable",
     "decode-first": "record-undecodable"},
    _i001, spec="L413-415; L1243-1245; L1245-1252",
    note="the member that separates the set-level reading from the other two. "
         "It is the statement suiteRevision 9 shipped as a reject vector pinning "
         "the set-level answer alone; the pin was this suite's registry rather "
         "than the specification's, and this directory is where that difference "
         "can be said out loud")

ind("ind-002-signatures-empty-then-undecodable", IND_SIGNATURE_COUNT, "ok-002",
    "arming record's signatures array emptied AND the sealed record's payload "
    "re-encoded as non-canonical base64, in that wire order",
    [91],
    {"set-level": "record-signatures-empty",
     "positional": "record-signatures-empty",
     "decode-first": "record-undecodable"},
    _i002, spec="L413-415; L1243-1245; L1245-1252",
    note="the member that separates the positional reading from decode-first, "
         "and the one that makes the family falsifiable: without it a rail that "
         "reports the later fault on one order and the earlier on the other is "
         "indistinguishable from a rail with a policy")


# --- (m) the manifest floor -----------------------------------------------
#
# The corpus manifest must declare at least one attack identifier. Without the
# floor the suite could not see a TOTAL BYPASS of the substrate, which is a
# strictly worse fault than lying about a run: coverage integrity is an
# equality between two unions of attack ids, and an equality between two empty
# sets holds, so a manifest declaring nothing passed it vacuously. From there
# the rest followed by construction -- no declared attack means no rows, no
# rows means no `basis: substrate` row, and with no substrate row the predicate
# permits runEntropy, observationRecords and batchRoot all to be absent. Every
# structure that would have forced a substrate signature dropped out, and a
# valid `pass` about an arbitrary subject verified with no substrate, no
# substrate key, no substrate run and every carried digest fabricated.
#
# TWO vectors, because the bypass has two shapes and one vector leaves the
# other untested. The rule is counted over attack IDENTIFIERS rather than over
# classes precisely so both are closed: a manifest carrying a real class name
# with an empty id array declares exactly as much as an empty classes object,
# nothing to execute, and it is the more plausible of the two to meet in the
# field because the class name reads as a real assessment.
#
# The parent is the ok-007 artifact-only recordless shape, which already
# carries no records, no batchRoot and no runEntropy, so emptying the manifest
# is the whole distance between a valid statement and the bypass. The row the
# emptied manifest no longer declares, and the coverage entry that accounted
# for it, come out in the rederive chain: leaving either behind would add
# row-attack-unknown or coverage-incomplete and the vector would stop testing
# the floor. What remains is the exact statement the defect produced.


def _no_attack_manifest(classes: dict[str, Any],
                        assessed: list[str]) -> dict[str, Any]:
    st = P_artifact_clean()
    env = st["predicate"]["observationEnvironment"]
    manifest = {"classes": classes}
    env["corpus"]["manifest"] = manifest
    env["corpus"]["digest"]["sha256"] = jcs_digest(manifest)
    st["predicate"]["attackResults"] = []
    st["predicate"]["coverage"] = {"assessedClasses": assessed,
                                   "outOfScope": {}, "routedElsewhere": {}}
    # A statement with no rows has no clean row, so the indirect condition of
    # the recompute cannot hold and the parent's pass_indirect stops matching.
    # Carrying pass keeps this vector isolating the manifest floor rather than
    # picking up a recompute mismatch it was not written to test.
    st["predicate"]["result"] = "pass"
    return st


def _b746() -> dict[str, Any]:
    return _no_attack_manifest({}, [])


vec("bad-746-manifest-empty-classes", "ok-007",
    "corpus manifest emptied to {\"classes\": {}}; the row it declared and "
    "that row's coverage entry come out with it",
    ["drop-undeclared-rows", "rebuild-coverage-partition",
     "recompute-corpus-digest"],
    [92], ["corpus-manifest-no-attacks"], _b746, spec="L928-950",
    note="the bare shape of the bypass. Every other check on this statement "
         "passes: the corpus digest re-derives over the emptied manifest, "
         "coverage is a partition of nothing, the recompute returns pass, and "
         "with no substrate row nothing requires runEntropy, "
         "observationRecords or a batchRoot. Only the manifest floor rejects "
         "it, which is why the floor sits in well-formedness and not in "
         "result: a corpus declaring no adversarial inputs is not an "
         "adversarial corpus, and scoring it would concede that the run is a "
         "legitimate statement that merely scores badly")


def _b747() -> dict[str, Any]:
    return _no_attack_manifest({"XA": []}, ["XA"])


vec("bad-747-manifest-class-declares-no-attacks", "ok-007",
    "corpus manifest keeps class XA but empties its attack-id array; the row "
    "it declared and that row's coverage entry come out with it",
    ["drop-undeclared-rows", "rebuild-coverage-partition",
     "recompute-corpus-digest"],
    [92], ["corpus-manifest-no-attacks"], _b747, spec="L928-950",
    note="the twin bad-746 cannot catch, and the reason the rule counts "
         "identifiers rather than classes. This manifest carries a real class "
         "name and assessedClasses names it, so the coverage partition is "
         "exactly satisfied and the statement reads like an assessment that "
         "found nothing rather than like an empty object; a rule phrased as "
         "\"an empty classes object is malformed\" would admit it")


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
    spec="L1231-1234",
    note="encoding-layer divergence: Go decodes with StdEncoding.Strict() and "
         "the Python rail re-encode-compares, so both reject; a lenient decoder "
         "would accept. The stale signature and batch root are unreachable "
         "because a decode failure short-circuits both checks (validity.go:120)")


def _b808() -> dict[str, Any]:
    st = P_clean()
    del st["predicate"]["coverage"]
    return st


vec("bad-808-coverage-absent", "ok-002", "drop coverage", [], [83],
    ["coverage-missing"], _b808, spec="L865-869")


def _b809() -> dict[str, Any]:
    st = P_clean()
    st["predicate"]["does_not_assert"] = ["example negative scope"]
    return st


vec("bad-809-snake-case-doesnotassert", "ok-002",
    "statement carries the rejected snake_case spelling of doesNotAssert",
    [], [84], ["member-spelling"], _b809, spec="L1633-1643",
    note="single-canonicalization rule: no alias")


def _b810() -> dict[str, Any]:
    st = P_artifact()
    del st["predicate"]["issuedAt"]
    return st


vec("bad-810-missing-issuedat", "ok-007", "drop issuedAt", [], [85],
    ["issued-at-missing"], _b810, spec="L1645",
    note="artifact-only parent: no armedAt comparison cascade")


def _b811() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["issuedAt"] = "yesterday"
    return st


vec("bad-811-issuedat-not-rfc3339", "ok-007", 'issuedAt: "yesterday"', [],
    [85], ["issued-at-malformed"], _b811, spec="L1645")
vec("bad-812-missing-networkposture", "ok-007", "drop networkPosture", [],
    [78], ["environment-incomplete"], _drop_env("networkPosture"),
    spec="L743-754")
vec("bad-813-missing-corpus", "ok-007", "drop corpus", [], [78],
    ["environment-incomplete"], _drop_env("corpus"), spec="L743-751")
vec("bad-814-missing-substrate", "ok-007", "drop substrate", [], [78],
    ["environment-incomplete"], _drop_env("substrate"), spec="L743-747")


def _b815() -> dict[str, Any]:
    st = P_clean()
    st["_type"] = "https://in-toto.io/Statement/v0.9"
    return st


vec("bad-815-wrong-statement-type", "ok-002",
    "_type is not the in-toto Statement/v1 URI", [], [77],
    ["statement-type-unsupported"], _b815, spec="L313")


# --- the timestamp profile, on both fields that carry it -------------------
#
# The profile is one rule cited from two places, so it needs a vector on each
# field and in each direction. The zone half was written on armedAt only, which
# left issuedAt admitting a non-zero offset on all five rails (bad-820); the
# case half was written on neither field, and the rails had already split on it.
# The accept side is ok-038 and ok-039, which carry the negative zero offset the
# profile admits.
#
# The case half needs one vector per designator rather than one carrying both
# lowercased. A rail whose zero-offset test reads the literal suffix rather than
# the parsed offset rejects a lowercase `z` as a side effect of the zone rule,
# so a both-lowercase mutant stays rejected however the case rule is written and
# forces nothing. Separated, each designator has a mutant only its own rule
# refuses, which is what makes the rule mutation-provable on every rail.

vec("bad-750-armedat-lowercase-separator", "ok-002",
    'arming armedAt: "2025-12-31t23:59:00Z" (lowercase date-time separator)',
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "armedAt": "2025-12-31t23:59:00Z"}),
    spec="L1269",
    note="the parent's instant with the separator lowercased. The profile is "
         "uppercase and this was already a rejection before the profile was "
         "written down, since the clause names Z and +00:00 and admits no "
         "lowercase spelling; the Python reference rail accepted it anyway, "
         "which is the divergence this vector exists to hold shut")
vec("bad-751-armedat-lowercase-zone-designator", "ok-002",
    'arming armedAt: "2025-12-31T23:59:00z" (lowercase zone designator)',
    ["re-sign-record", "recompute-batch-root"], [63],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {**o, "armedAt": "2025-12-31T23:59:00z"}),
    spec="L1269",
    note="the separator's twin: the other half of the case rule, isolated so a "
         "rail that enforces the case of one designator and not the other is "
         "caught. Distinct from bad-727 (a non-zero offset), which is the zone "
         "half of the same profile")


def _b820() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["issuedAt"] = "2026-01-01T05:00:00+05:00"
    return st


vec("bad-820-issuedat-non-utc-offset", "ok-007",
    'issuedAt: "2026-01-01T05:00:00+05:00" (a non-zero UTC offset)', [],
    [85], ["issued-at-malformed"], _b820, spec="L1645",
    note="the parent's instant at a non-zero offset. issuedAt is typed as the "
         "framework Timestamp, which requires the UTC timezone, so a valid "
         "instant in a non-UTC spelling is malformed. The counterpart on the "
         "arming record is bad-727, which every rail rejected while every rail "
         "accepted this one")


def _b821() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["issuedAt"] = "2026-01-01t00:00:00Z"
    return st


vec("bad-821-issuedat-lowercase-separator", "ok-007",
    'issuedAt: "2026-01-01t00:00:00Z" (lowercase date-time separator)', [],
    [85], ["issued-at-malformed"], _b821, spec="L1645",
    note="the spelling the Go reference rail refused and the Python reference "
         "rail accepted with result pass, an accept-on-one reject-on-another "
         "split inside one repository that no vector reached")


def _b822() -> dict[str, Any]:
    st = P_artifact()
    st["predicate"]["issuedAt"] = "2026-01-01T00:00:00z"
    return st


vec("bad-822-issuedat-lowercase-zone-designator", "ok-007",
    'issuedAt: "2026-01-01T00:00:00z" (lowercase zone designator)', [],
    [85], ["issued-at-malformed"], _b822, spec="L1645",
    note="the separator's twin on the predicate field, isolated for the same "
         "reason as bad-751: a rail enforcing the case of one designator and "
         "not the other passes every both-lowercase mutant")


# --- (m) the closed posture registry -------------------------------------
#
# Every other vector in this suite carries the posture "sinkhole", so until
# these three landed the registry was untested by construction: a rail that
# admitted only that one string and a rail that admitted any string at all
# scored identically on the whole corpus. The three registered values the
# corpus does not use are covered on the accept side (ok-040 to ok-042); these
# are the three shapes that are not a registered value.
#
# All three rederive the binding over the mutated posture object. That is not
# tidiness: the posture object is a binding input under version 2, so leaving
# the parent's records in place would give each vector a run-binding mismatch
# as well, and the vector would then be indistinguishable from bad-305.

def _posture_mut(value: Any) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        st = P_clean()
        st["predicate"]["observationEnvironment"]["networkPosture"]["posture"] = value
        return rebind_records(st)
    return b


_POSTURE_REDERIVE = ["rederive-binding", "re-sign-record",
                     "recompute-batch-root"]

vec("bad-823-posture-unregistered", "ok-002",
    'networkPosture.posture: "example_posture_x", a value the registry does '
    "not carry", _POSTURE_REDERIVE, [93], ["posture-vocabulary"],
    _posture_mut("example_posture_x"), spec="L807-815",
    note="the pinned digest member is untouched, so both covering records "
         "still compare equal on aeePostureDigest and the unregistered string "
         "is the single fault")
vec("bad-824-posture-not-a-string", "ok-002",
    "networkPosture.posture: 3, a value of the wrong JSON type",
    _POSTURE_REDERIVE, [93], ["posture-vocabulary"],
    _posture_mut(3), spec="L807-815",
    note="a wrong-type posture is the same requirement failing as an "
         "unregistered one, so it reports the same condition rather than the "
         "parse catch-all; a rail that decodes the member into a string field "
         "and lets the decode failure escape names a different condition than "
         "its peers for these exact bytes")
vec("bad-825-posture-array", "ok-002",
    'networkPosture.posture: ["sinkhole"], an array wrapping a registered '
    "value", _POSTURE_REDERIVE, [93], ["posture-vocabulary"],
    _posture_mut(["sinkhole"]), spec="L807-815",
    note="the shape that separated the rails before it was fixed: testing "
         "membership of an unhashable value against a set raises rather than "
         "returning false, so two rails crashed on it while a third rejected "
         "it cleanly, which is a crash and a cross-rail split at once. It is "
         "kept distinct from the wrong-type vector because a scalar of the "
         "wrong type and a container of the wrong type reach a membership "
         "test by different paths")


# --- (n) the two inputs version 2 added ----------------------------------
#
# These are the vectors the version-2 binding exists for. Both are statements
# that were fully VALID under version 1, where neither input was bound: the
# posture string sat beside a digest nothing compared it against, and the
# vocabulary's digest verified against the arrays beside it and so re-derived
# for free. Neither mutation moved a signature or a digest, so a party holding
# only the outer envelope key could make either edit undetectably. Under
# version 2 each derives a binding the producer's own records do not carry.

def _b305() -> dict[str, Any]:
    # The posture string is swapped between two REGISTERED values, so the
    # closed-registry check has nothing to say and the binding is the only
    # thing that can catch it. The pinned digest member is left alone, which is
    # what makes the swap free under version 1: a producer's posture
    # configuration travels nowhere in the statement, so no verifier can check
    # the string against the digest taken over it.
    st = P_clean()
    st["predicate"]["observationEnvironment"]["networkPosture"]["posture"] = "allowlist"
    return st


vec("bad-305-posture-swapped", "ok-002",
    'networkPosture.posture swapped from "sinkhole" to "allowlist"; every '
    "digest, signature and record left exactly as the producer signed them",
    [], [22, 60], ["run-binding-mismatch"], _b305, spec="L174-182; L563-564",
    note="both values are registered, so this is the swap no vocabulary rule "
         "can see. Under the version-1 binding this statement was VALID and "
         "the substitution cost nothing: it changed no digest and broke no "
         "signature. It is a mismatch now because the binding covers the "
         "carried posture object rather than the value of that object's own "
         "digest member")


def _b306() -> dict[str, Any]:
    # The caught set is narrowed and the vocabulary digest re-derived over the
    # narrowed arrays, which is free: the digest is verified only against the
    # arrays beside it. The parent is the clean-row shape rather than a caught
    # one on purpose. Narrowing caught on a caught-row parent also changes which
    # cover that row requires (a caught row references an interception; a clean
    # row references arming and sealed), so such a vector would carry an
    # uncovered-row fault alongside the binding one and could not attribute
    # either. On this parent the narrowing moves nothing except the vocabulary
    # digest, which is exactly the input under test.
    st = P_clean()
    v = st["predicate"]["observationEnvironment"]["observationVocabulary"]
    v["caught"] = []
    v["digest"]["sha256"] = jcs_digest({"caught": [], "labels": v["labels"]})
    return st


vec("bad-306-vocabulary-caught-narrowed", "ok-002",
    "caught narrowed to [] with the vocabulary digest re-derived over the "
    "narrowed arrays; the records keep the binding they were signed with",
    ["recompute-vocabulary-digest"], [22, 60],
    ["run-binding-mismatch"], _b306, spec="L174-182; L563-564",
    note="the caught set decides which labels are caught, and both the "
         "recompute and the coverage validity requirements read it, so a "
         "producer that narrows it after the run turns a caught row into a "
         "clean one. Nothing resisted that under version 1: the vocabulary's "
         "own digest re-derives from the arrays beside it and no record's "
         "binding moved. Binding the carried digest is what closes it")


def _b307() -> dict[str, Any]:
    # The extension case, in the direction that must fail. The producer adds a
    # member to networkPosture after the arming record was signed, so the
    # records commit to the object without it. ok-043 is the same statement with
    # the records committing to the extended object, and it is VALID.
    st = P_clean()
    st["predicate"]["observationEnvironment"]["networkPosture"][
        "producerNote"] = "example posture annotation"
    return st


vec("bad-307-posture-member-added-after-arming", "ok-002",
    "networkPosture gains a producer member the records do not commit to",
    [], [22, 60], ["run-binding-mismatch"], _b307,
    spec="L174-182; L563-564",
    note="the consequence the binding change makes normative, in the "
         "direction that must fail. The binding covers the carried object, so "
         "a member added to the posture after arming invalidates the "
         "producer's own statement. Its accepted twin is ok-043, which carries "
         "the same member with records committing to it, and the pair is what "
         "makes this a rule about WHEN the member was added rather than about "
         "whether the posture may carry one at all")


# --- (o) the commitments this version adds ---------------------------------
# Five coverage validity requirements hold on the statement, or on every row
# rather than only on a basis: substrate row, plus the three-part attribution
# rule and the shape rules of the four members that carry them. Each vector
# below is derived from a fully valid parent by ONE mutation.


M_PIN = {"classes": {"XA": ["XA-EXAMPLE-1"]},
         "expectedPayloads": {"XA-EXAMPLE-1": [D["intercepted-bytes-1"]]}}


def P_pinned() -> dict[str, Any]:  # ok-047 shape: a satisfied `pinned` row
    env = environment(M_PIN)
    b = binding_for(env)
    return statement(env, [caught_row(attribution="pinned")],
                     [record(interception_payload(b)),
                      record(sealed_payload(b))],
                     result="fail")


PARENTS["ok-047 shape (pinned row, corpus expectation, matching record)"] = P_pinned


def _b950() -> dict[str, Any]:
    """A clean row that is otherwise fully covered and resolves an interception.

    Isolating this rule takes a two-row statement, and the reason is worth
    stating because a one-row version measures the wrong thing. Relabel the
    only row of a caught statement and it stops being covered (a clean row
    needs arming AND sealed) while the interception it abandoned becomes an
    orphan, so the vector reports two older conditions and never reaches this
    one. Here the clean row resolves valid arming and sealed records, so it is
    covered; a caught sibling row resolves the interception, so nothing is
    orphaned; and the clean row ALSO resolves the interception, which is the
    single contradiction under test."""
    env = environment(M2)
    b = binding_for(env)
    return statement(
        env,
        [caught_row(refs=(0,)),
         clean_row(refs=(0, 1, 2), attack="XA-EXAMPLE-2")],
        [record(interception_payload(b)), record(arming_payload(b)),
         record(sealed_payload(b))],
        result="fail",
        coverage={"assessedClasses": ["XA"], "outOfScope": {},
                  "routedElsewhere": {}})


vec("bad-950-clean-row-refs-interception", "ok-014",
    "a fully covered clean row also resolves the caught row's interception "
    "record",
    [], [94], ["clean-row-contradicted"], _b950,
    spec="L574-579",
    note="the relabelling attack the requirement is written against: the row "
         "and the record it cites state the two halves of a contradiction, and "
         "the check is a membership test that reads no signature and no key. "
         "It is stated over every row because the contradiction does not "
         "depend on the vantage the row declares")


def _b951() -> dict[str, Any]:
    """Empty the caught row's references and keep the interception record.

    The escalation of dropping the reference instead of the record: the
    substrate signed an interception and the producer reports nothing about it.
    The row is left with an empty refs array, which is its own condition, so the
    seal is what the row rests on and the interception is the orphan."""
    st = P_caught()
    st["predicate"]["attackResults"][0]["observationRefs"] = [1]
    return st


vec("bad-951-interception-no-caught-row", "ok-001",
    "the caught row is re-pointed at the sealed record, leaving the "
    "interception record resolved by nobody",
    [], [95], ["caught-row-uncovered", "interception-record-orphaned"], _b951,
    compound=True, spec="L580-585",
    note="inherently compound: a caught row that resolves no interception is "
         "uncovered by the older requirement at the same moment the record it "
         "abandoned becomes an orphan under the newer one. The pair is what "
         "the anti-orphan rule is for, since dropping the reference and "
         "dropping the record are the same withdrawal from two sides")


def _b952() -> dict[str, Any]:
    """Delete the sealed record from a statement carrying a substrate row."""
    st = P_caught()
    st["predicate"]["observationRecords"] = \
        st["predicate"]["observationRecords"][:1]
    return reroot(st)


vec("bad-952-substrate-row-no-seal", "ok-001",
    "the sealed record is deleted from a statement carrying a substrate row",
    ["recompute-batch-root"], [96], ["sealed-record-absent"], _b952,
    spec="L586-594",
    note="before 0.7 a sealed record was required only to cover a clean "
         "intercepted row, so a statement whose rows were all caught carried "
         "none and the run-end commitment had nowhere to live on exactly the "
         "statements a record deletion works against")


def _b953() -> dict[str, Any]:
    """Delete an interception and recompute the root, leaving the seal intact.

    The deletion attack the run-end commitment exists for: a party holding the
    enclosing envelope key drops an inconvenient interception and recomputes a
    self-consistent root over what remains. The seal is signed by a party that
    does not control the carried set, so it still commits to the record that is
    gone. reseal is suppressed for exactly that reason."""
    st = P_two_attacks()
    recs = st["predicate"]["observationRecords"]
    del recs[1]
    st["predicate"]["attackResults"] = st["predicate"]["attackResults"][:1]
    st["predicate"]["observationEnvironment"]["corpus"] = \
        environment(M1)["corpus"]
    return _rebind_no_reseal(st)


def _rebind_no_reseal(st: dict[str, Any]) -> dict[str, Any]:
    """Rederive the binding and re-sign every record WITHOUT resealing.

    The ordinary rebind repairs a stale observed set, which is right everywhere
    except here: a vector whose subject IS the stale commitment must keep it."""
    env = st["predicate"]["observationEnvironment"]
    bv = binding_for(env, subject_sha=st["subject"][0]["digest"].get("sha256"))
    st["predicate"]["observationRecords"] = [
        record({**json.loads(unb64(r["payload"])), "aeeRunBinding": bv},
               r["payloadType"])
        for r in st["predicate"]["observationRecords"]]
    return reroot(st, reseal_first=False)


vec("bad-953-observed-set-drops-a-record", "ok-011",
    "one interception is deleted with its row and the root recomputed over "
    "what remains, while the seal still commits to the deleted record",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"],
    [97], ["observed-set-mismatch"], _b953,
    spec="L595-599; L1422-1431",
    note="the attack the run-end commitment is for. batchRoot recomputes over "
         "the carried records and can never detect a missing member; the seal "
         "is signed by a party that does not control the carried set, so a "
         "dropped record removes a leaf and the two values diverge")


def _b954() -> dict[str, Any]:
    """Append an interception the seal never committed to.

    The other direction of the same requirement: the carried set grows rather
    than shrinks. The new record is resolved by the caught row, so it is not an
    orphan, and every signature verifies."""
    st = P_caught()
    env = st["predicate"]["observationEnvironment"]
    b = binding_for(env)
    st["predicate"]["observationRecords"].append(
        record(interception_payload(b, commit="intercepted-bytes-2")))
    st["predicate"]["attackResults"][0]["observationRefs"] = [0, 2]
    return reroot(st, reseal_first=False)


vec("bad-954-observed-set-gains-a-record", "ok-001",
    "an interception record the seal does not commit to is appended and "
    "resolved by the caught row",
    ["recompute-batch-root"], [97], ["observed-set-mismatch"], _b954,
    spec="L595-599; L1422-1431")


def _b955() -> dict[str, Any]:
    """A seal naming an attack whose row is CLEAN rather than caught."""
    st = P_clean()
    recs = st["predicate"]["observationRecords"]
    obj = json.loads(unb64(recs[1]["payload"]))
    obj["aeeObservedAttacks"] = ["XA-EXAMPLE-1"]
    recs[1] = record(obj, recs[1]["payloadType"])
    return reroot(st)


vec("bad-955-seal-names-clean-attack", "ok-002",
    "the seal names an attack whose only row reports a clean containment",
    ["re-sign-record", "recompute-batch-root"], [98],
    ["observed-attack-uncaught"], _b955,
    spec="L1458-1465",
    note="the seal claims the run attributed an observation to this attack "
         "while the row says nothing was caught. The rule reads one way only, "
         "so it is the naming that obliges the caught row and never the "
         "omission that obliges a clean one")


def _b956() -> dict[str, Any]:
    """A seal naming an attack the statement carries no row for at all."""
    st = P_two_attacks()
    recs = st["predicate"]["observationRecords"]
    obj = json.loads(unb64(recs[2]["payload"]))
    obj["aeeObservedAttacks"] = ["XA-EXAMPLE-1", "XA-EXAMPLE-2"]
    recs[2] = record(obj, recs[2]["payloadType"])
    st["predicate"]["attackResults"] = st["predicate"]["attackResults"][:1]
    st["predicate"]["observationRecords"] = [recs[0], recs[2]]
    st["predicate"]["observationEnvironment"]["corpus"] = \
        environment(M2)["corpus"]
    return reroot(st)


vec("bad-956-seal-names-rowless-attack", "ok-011",
    "the seal names two attacks and the statement carries a row for only one",
    ["re-sign-record", "recompute-batch-root"], [98],
    ["coverage-incomplete", "observed-attack-uncaught"], _b956,
    compound=True, spec="L1458-1465",
    note="inherently compound: an attack the manifest declares under an "
         "assessed class and no row reports is a coverage-integrity fault at "
         "the older gate, and the seal naming it is the newer one. The pair "
         "is unavoidable, because the only way to carry a seal naming an "
         "attack with no row is to carry a statement with no row for it")


def _b957() -> dict[str, Any]:
    """An assessed class whose attacks the arming record never declared."""
    st = P_degraded()
    recs = st["predicate"]["observationRecords"]
    obj = json.loads(unb64(recs[0]["payload"]))
    obj["aeeAssessedAttacks"] = ["XB-EXAMPLE-1"]
    recs[0] = record(obj, recs[0]["payloadType"])
    return reroot(st)


vec("bad-957-assessed-exceeds-declaration", "ok-004",
    "the arming record declares only the class the run did NOT assess, so "
    "the assessed set is not a subset of the run-start declaration",
    ["re-sign-record", "recompute-batch-root"], [99],
    ["assessed-set-exceeds-declaration"], _b957,
    spec="L1390-1396",
    note="coverage inflation is the withdrawal's mirror image and the only "
         "half of that pair a commitment can reach: inflation must keep the "
         "run-level records its fabricated rows point at, and withdrawal need "
         "keep nothing at all")


def _b958() -> dict[str, Any]:
    """A `pinned` row resolving no interception record at all.

    The vacuity the rule's existence part is written against: delete the
    interception, point the row at the seal, keep the stronger label. Every
    universally quantified clause about the records the row resolves is then
    true over an empty set."""
    st = P_pinned()
    st["predicate"]["observationRecords"] = \
        st["predicate"]["observationRecords"][1:]
    st["predicate"]["attackResults"][0]["observationRefs"] = [0]
    return reroot(st)


vec("bad-958-pinned-row-resolves-no-interception", "ok-047",
    "the interception is deleted and the pinned row re-pointed at the seal",
    ["recompute-batch-root"], [100],
    ["caught-row-uncovered", "attribution-pinned-recordless"], _b958,
    compound=True, spec="L600-609",
    note="inherently compound, and the compounding is the point: the older "
         "requirement catches this shape only because the row is CAUGHT, and "
         "a producer that also relabels the row escapes it while keeping the "
         "stronger attribution. The existence part is what does not depend on "
         "the label")


def _b959() -> dict[str, Any]:
    """A `pinned` row whose attack the manifest offers no expectation for."""
    env = environment(M1)          # no expectedPayloads at all
    b = binding_for(env)
    return statement(env, [caught_row(attribution="pinned")],
                     [record(interception_payload(b)),
                      record(sealed_payload(b))],
                     result="fail")


vec("bad-959-pinned-without-expectation", "ok-047",
    "the corpus manifest carries no expectedPayloads entry for the attack the "
    "pinned row names",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"], [101],
    ["attribution-unpinnable"], _b959,
    spec="L600-609; L775-781",
    note="a row whose attackId carries no such entry MUST declare paired. "
         "Where the corpus declares nothing there is nothing to compare, and "
         "the stronger value would be a claim about a check that cannot run")


def _b960() -> dict[str, Any]:
    """A `pinned` row resolving an interception whose commitment is not the
    one the manifest declared."""
    env = environment(M_PIN)
    b = binding_for(env)
    return statement(env, [caught_row(attribution="pinned")],
                     [record(interception_payload(
                         b, commit="intercepted-bytes-2")),
                      record(sealed_payload(b))],
                     result="fail")


vec("bad-960-pinned-commitment-unmatched", "ok-047",
    "the interception the pinned row resolves commits to a value the corpus "
    "did not declare for that attack",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"], [102],
    ["attribution-pin-unmatched"], _b960,
    spec="L600-609",
    note="the borrowed-record case the stronger value narrows: re-pointing a "
         "row at an interception signed for a different attack raises nothing "
         "here, because the borrowed record must also carry this attack's "
         "committed value")


def _expected_payloads(value: Any) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        env = environment(M1)
        env["corpus"]["manifest"]["expectedPayloads"] = value
        env["corpus"]["digest"]["sha256"] = jcs_digest(env["corpus"]["manifest"])
        bv = binding_for(env)
        return statement(env, [caught_row()],
                         [record(interception_payload(bv)),
                          record(sealed_payload(bv))],
                         result="fail")
    return b


vec("bad-961-expected-payloads-unknown-attack", "ok-001",
    "the manifest's expectedPayloads names an attack its own classes do not "
    "declare",
    ["recompute-corpus-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"],
    [103], ["manifest-expected-payloads-malformed"],
    _expected_payloads({"XZ-EXAMPLE-9": [D["intercepted-bytes-1"]]}),
    spec="L775-781")

vec("bad-962-expected-payloads-unsorted", "ok-001",
    "an expectedPayloads array carries its two entries in descending order",
    ["recompute-corpus-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"],
    [103], ["manifest-expected-payloads-malformed"],
    _expected_payloads({"XA-EXAMPLE-1": sorted(
        [D["intercepted-bytes-1"], D["intercepted-bytes-2"]], reverse=True)}),
    spec="L775-781",
    note="the sortedness rule is the canonicality rule the vocabulary arrays "
         "already carry, so two rails deriving the manifest digest from the "
         "same entries in different orders is not a thing that can happen")

vec("bad-963-expected-payloads-not-hex", "ok-001",
    "an expectedPayloads entry is not lowercase 64-hex",
    ["recompute-corpus-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"],
    [103], ["manifest-expected-payloads-malformed"],
    _expected_payloads({"XA-EXAMPLE-1": [D["intercepted-bytes-1"].upper()]}),
    spec="L775-781")

vec("bad-964-expected-payloads-empty-array", "ok-001",
    "an expectedPayloads array carries no entry",
    ["recompute-corpus-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"],
    [103], ["manifest-expected-payloads-malformed"],
    _expected_payloads({"XA-EXAMPLE-1": []}),
    spec="L775-781",
    note="an empty expectation is not a weaker expectation. It reads as a "
         "declaration that no commitment can match, which every pinned row "
         "for that attack would then fail while the manifest looked complete")


vec("bad-965-commitment-not-hex", "ok-001",
    "the interception record's aeePayloadCommitment carries an entry that is "
    "not lowercase 64-hex",
    ["re-sign-record", "recompute-batch-root"], [104],
    ["payload-commitment-malformed"],
    _rec_mut(P_caught, 0, lambda o: {
        **o, "aeePayloadCommitment": ["not-a-commitment"]}),
    spec="L1377-1388",
    note="the ABSENCE of the member keeps reporting payload-missing-reserved, "
         "which is the code every other missing reserved member takes. A "
         "present-but-malformed value is a different fault: a producer told "
         "its record is missing a value the record plainly carries has been "
         "told the wrong thing")

vec("bad-966-commitment-empty-array", "ok-001",
    "the interception record's aeePayloadCommitment is an empty array",
    ["re-sign-record", "recompute-batch-root"], [104],
    ["payload-commitment-malformed"],
    _rec_mut(P_caught, 0, lambda o: {**o, "aeePayloadCommitment": []}),
    spec="L1377-1388")

vec("bad-967-commitment-absent", "ok-001",
    "the interception record carries no aeePayloadCommitment at all",
    ["re-sign-record", "recompute-batch-root"], [104],
    ["payload-missing-reserved"],
    _rec_mut(P_caught, 0, lambda o: {
        k: v for k, v in o.items() if k != "aeePayloadCommitment"}),
    spec="L1377-1388",
    note="the absent half of the pair above, kept as its own vector because "
         "the two report different conditions and a rail collapsing them "
         "passes whichever one it implemented")


def _drop_row_member(member: str) -> dict[str, Any]:
    """Remove one member from the caught parent's only row."""
    st = P_caught()
    del st["predicate"]["attackResults"][0][member]
    return st


def _set_row_member(member: str, value: Any) -> dict[str, Any]:
    """Set one member on the caught parent's only row."""
    st = P_caught()
    st["predicate"]["attackResults"][0][member] = value
    return st


vec("bad-968-substrate-row-missing-attribution", "ok-001",
    "the caught substrate row carries no attribution member",
    [], [105], ["fail-closed-substrate-row"],
    lambda: _drop_row_member("attribution"),
    spec="L1045-1049",
    note="absence is not a value, so the row cannot be classified and "
         "fail-closes exactly as an out-of-vocabulary one does. The result "
         "still recomputes to fail, because a caught row forced fail already")

vec("bad-969-substrate-row-attribution-oov", "ok-001",
    'the caught substrate row carries attribution: "example_strong"',
    [], [105], ["fail-closed-substrate-row"],
    lambda: _set_row_member("attribution", "example_strong"),
    spec="L1045-1049")


def _artifact_attribution(value: Any) -> Callable[[], dict[str, Any]]:
    """An ARTIFACT row whose attribution is absent or out of vocabulary.

    The member is required regardless of basis, and on an artifact row the
    consequence reaches the recompute rather than coverage validity: the row
    fail-closes, the recompute drops to fail, and the carried pass_indirect no
    longer equals it. A rail that reads attribution only on substrate rows
    passes bad-968 and bad-969 and fails here."""
    def b() -> dict[str, Any]:
        env = environment(M1, entropy=False)
        row = artifact_row(label="no_egress", method="reconstructed")
        if value is None:
            del row["attribution"]
        else:
            row["attribution"] = value
        return statement(env, [row], result="pass_indirect")
    return b


vec("bad-970-artifact-row-missing-attribution", "ok-007",
    "an artifact-only clean row carries no attribution member, so the row "
    "fail-closes and the carried result no longer recomputes",
    [], [105], ["result-recompute-mismatch"],
    _artifact_attribution(None), spec="L1045-1049")

vec("bad-971-artifact-row-attribution-oov", "ok-007",
    'an artifact-only clean row carries attribution: "example_strong"',
    [], [105], ["result-recompute-mismatch"],
    _artifact_attribution("example_strong"), spec="L1045-1049")


# --- (p) the 0.7 rules a mutation campaign found unforced ------------------
# Every vector below was written because switching the rule off in a rail left
# the corpus green. Each of the five had a vector already; each of those
# vectors declared a SECOND acceptable condition that an older rule reported
# first, so the newer rule could be deleted and the older one carried the
# vector. A vector that passes for a rule other than the one it names measures
# nothing about that rule.


def _b972() -> dict[str, Any]:
    """A second interception record no caught row resolves.

    bad-951 already refuses an orphan, and it refuses it as caught-row-uncovered
    too, because the row it strips the reference from stops being covered at the
    same moment. Here the caught row keeps its own interception and is fully
    covered, so nothing older fires and the orphan is alone."""
    st = P_caught()
    env = st["predicate"]["observationEnvironment"]
    b = binding_for(env)
    recs = st["predicate"]["observationRecords"]
    recs.insert(1, record(interception_payload(b, commit="intercepted-bytes-2")))
    return reroot(st)


vec("bad-972-second-interception-unresolved", "ok-001",
    "a second interception record is carried that no caught row resolves, "
    "while the caught row keeps its own",
    ["recompute-batch-root"], [95], ["interception-record-orphaned"], _b972,
    spec="L580-585",
    note="an interception the statement carries and no caught row accounts "
         "for is an observation the substrate signed and the producer then "
         "reported nothing about")


def _b973() -> dict[str, Any]:
    """A CLEAN row declaring the stronger attribution.

    bad-958 refuses a pinned row that resolves no interception, and refuses it
    as caught-row-uncovered too, because it reaches that shape by deleting the
    record a CAUGHT row rested on. A clean row needs arming and sealed rather
    than an interception, so this row is fully covered by the older rule and
    still resolves no interception at all. The manifest carries an expectation
    for the attack, so the part under test is the existence part alone."""
    env = environment(M_PIN)
    b = binding_for(env)
    return statement(env, [clean_row(attribution="pinned")],
                     [record(arming_payload(b)), record(sealed_payload(b))],
                     result="pass")


vec("bad-973-pinned-clean-row", "ok-002",
    "a fully covered CLEAN row declares attribution: pinned and therefore "
    "resolves no interception record",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"], [100],
    ["attribution-pinned-recordless"], _b973,
    spec="L600-609",
    note="the vacuity the existence part is written against, on the one row "
         "shape where no older requirement fires first: a universally "
         "quantified rule over an empty set is true, so without this part a "
         "producer resolves only run-level records and keeps the stronger "
         "value with nothing checking it")


vec("bad-974-sealed-missing-observedset", "ok-002",
    "drop aeeObservedSet from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [97],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {k: v for k, v in o.items() if k != "aeeObservedSet"}),
    spec="L1422-1431",
    note="the member is required on the kind, so its ABSENCE makes the record "
         "cover nothing rather than making the recompute disagree. bad-953 "
         "and bad-954 carry the disagreement; nothing carried the absence, so "
         "a rail could implement the equality and never require the member")

vec("bad-975-sealed-missing-observedattacks", "ok-002",
    "drop aeeObservedAttacks from the sealed payload",
    ["re-sign-record", "recompute-batch-root"], [98],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {k: v for k, v in o.items()
                         if k != "aeeObservedAttacks"}),
    spec="L1458-1465",
    note="the empty array is the honest value and is REQUIRED rather than "
         "omissible: a substrate holding no probe-to-record correspondence "
         "says so on the wire. Allowing the member to be absent would make "
         "the whole control escapable by omission, which is the defect the "
         "mandatory sealed record exists to close, reintroduced one level "
         "down")

vec("bad-976-sealed-observedattacks-unknown", "ok-002",
    "the sealed aeeObservedAttacks names an identifier the manifest does not "
    "declare",
    ["re-sign-record", "recompute-batch-root"], [98],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1,
              lambda o: {**o, "aeeObservedAttacks": ["XZ-EXAMPLE-9"]}),
    spec="L1458-1465")

vec("bad-977-arming-missing-assessedattacks", "ok-002",
    "drop aeeAssessedAttacks from the arming payload",
    ["re-sign-record", "recompute-batch-root"], [99],
    ["arming-covers-nothing"],
    _rec_mut(P_clean, 0,
             lambda o: {k: v for k, v in o.items()
                        if k != "aeeAssessedAttacks"}),
    spec="L1390-1396",
    note="bad-957 carries the subset comparison failing; nothing carried the "
         "member missing, so a rail could implement the comparison over a "
         "member it never required and skip every statement that omitted it")

def _b979() -> dict[str, Any]:
    """An ARTIFACT-ONLY statement carrying an interception record no row resolves.

    The anti-orphan rule is stated over every row rather than only over a
    substrate row, so it holds on a statement that derives no run binding at
    all. Nothing measured that until a mutation campaign switched the
    artifact-only arm of the requirement off and the whole corpus stayed green:
    every other vector carrying the condition also carries a substrate row, so
    the arm that runs before the substrate path returns had no witness. The
    parent is the artifact-only shape whose records are deliberately
    unreferenced, with one record's kind moved back to interception."""
    st = P_artifact_with_records()
    ub = D["unchecked-binding"]
    st["predicate"]["observationRecords"][0] = record(interception_payload(ub))
    return reroot(st)


vec("bad-979-artifact-only-interception-orphaned", "ok-029",
    "an artifact-only statement carries an interception record that no caught "
    "row resolves",
    ["recompute-batch-root"], [95], ["interception-record-orphaned"], _b979,
    spec="L569-585",
    note="the requirement holds on the statement rather than on a substrate "
         "row, and this is the only vector that reaches it on a statement with "
         "no substrate row at all. Without it the artifact-only arm is dead "
         "code the corpus never exercises")


vec("bad-978-arming-assessedattacks-unsorted", "ok-011",
    "the arming aeeAssessedAttacks carries its two entries in descending order",
    ["re-sign-record", "recompute-batch-root"], [99],
    ["arming-covers-nothing"],
    _rec_mut(P_clean_two, 0,
             lambda o: {**o, "aeeAssessedAttacks": ["XA-EXAMPLE-2",
                                                    "XA-EXAMPLE-1"]}),
    spec="L1390-1396",
    note="sorted ascending by UTF-16 code unit, the canonicality rule the "
         "vocabulary arrays already carry. Two entries are the fewest that "
         "can be out of order, and a one-attack manifest cannot express it")


# --- (h2) the two kinds registered as non-covering -------------------------

def noncovering_payload(binding: str, kind: str) -> dict[str, Any]:
    """A record of one of the two kinds the document registers as non-covering.

    Neither kind carries constraints, so the payload carries the three reserved
    members every record carries and nothing else. In particular neither carries
    aeePayloadCommitment: a substrate holding a commitment emits an
    interception, and a record declaring it holds none while carrying one says
    two things."""
    return {"aeeKind": kind, "aeeMethod": "intercepted",
            "aeeRunBinding": binding,
            "producerNote": "example non-covering observation"}


def _noncovering_sole_cover(kind: str) -> Callable[[], dict[str, Any]]:
    def b() -> dict[str, Any]:
        env = environment(M1)
        bv = binding_for(env)
        return statement(env, [caught_row()],
                         [record(noncovering_payload(bv, kind)),
                          record(sealed_payload(bv))],
                         result="fail")
    return b


vec("bad-980-moat-drop-sole-cover", "ok-001",
    "the caught row's only resolved record is a moat-drop, which covers "
    "nothing in every state",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"], [106],
    ["moat-drop-covers-nothing"], _noncovering_sole_cover("moat-drop"),
    spec="L1317-1331; L1333-1346",
    note="the kind is registered rather than unknown, so the refusal names it "
         "rather than reporting the unrecognized-kind condition. A rail that "
         "routes both through one condition passes bad-714 and fails here, and "
         "the producer it answers is told to upgrade a verifier that is "
         "already current. It also pins what the record cannot buy: a drop the "
         "containment layer performed is not an interception of the traffic, "
         "so it cannot make a caught row caught")

vec("bad-981-uncommitted-observation-sole-cover", "ok-001",
    "the caught row's only resolved record is an uncommitted-observation, "
    "which covers nothing in every state",
    ["rederive-binding", "re-sign-record", "recompute-batch-root"], [107],
    ["uncommitted-observation-covers-nothing"],
    _noncovering_sole_cover("uncommitted-observation"),
    spec="L1317-1331; L1348-1361",
    note="an observation the substrate declined or was unable to commit to "
         "cannot stand in for an interception anywhere. The record is bound to "
         "the run and signed by the substrate, which is exactly what makes the "
         "substitution tempting and is why the refusal is worth a vector")


# --- (h3) the assignment a pinned row declares, over two rows --------------

M_PIN2 = {"classes": {"XA": ["XA-EXAMPLE-1"], "XB": ["XB-EXAMPLE-1"]},
          "expectedPayloads": {"XA-EXAMPLE-1": [D["intercepted-bytes-1"]],
                               "XB-EXAMPLE-1": [D["intercepted-bytes-2"]]}}


def P_two_pinned() -> dict[str, Any]:  # ok-051 shape: two satisfied pinned rows
    env = environment(M_PIN2)
    b = binding_for(env)
    return statement(
        env,
        [caught_row(refs=(0,), attack="XA-EXAMPLE-1", attribution="pinned"),
         caught_row(refs=(1,), attack="XB-EXAMPLE-1", attribution="pinned")],
        [record(interception_payload(b, commit="intercepted-bytes-1")),
         record(interception_payload(b, commit="intercepted-bytes-2")),
         record(sealed_payload(b))],
        result="fail",
        coverage={"assessedClasses": ["XA", "XB"], "outOfScope": {},
                  "routedElsewhere": {}})


PARENTS["ok-051 shape (two pinned rows, one interception each)"] = P_two_pinned


def _b982() -> dict[str, Any]:
    """The cross-row assignment splice, on two rows that declare `pinned`.

    The two rows exchange their observationRefs and NOTHING else moves: the
    record set, every signature, every digest and the batch root are the bytes
    the producer signed, and the multiset of references across the statement is
    unchanged. What changes is which attack each record is claimed to evidence.

    Until this vector the corpus could not reach the arm that decides it. Every
    other pinned vector carries a single row, and permuting one row is the
    identity, so the kill was proven against a statement built outside the
    corpus and no vendored copy was ever measured against it."""
    st = P_two_pinned()
    rows = st["predicate"]["attackResults"]
    rows[0]["observationRefs"], rows[1]["observationRefs"] = (
        rows[1]["observationRefs"], rows[0]["observationRefs"])
    return st


vec("bad-982-pinned-assignment-spliced", "ok-051",
    "the two pinned rows exchange observationRefs; the record set, every "
    "signature and the batch root are untouched",
    [], [102], ["attribution-pin-unmatched"], _b982,
    spec="L600-609",
    note="the permutation a consumer policy keyed on attack class would act "
         "on. Where the corpus declares no expectation the same operator is "
         "invisible and stays so, which is what cell U7 records; here the "
         "corpus predicted what each attack's interception would commit to, "
         "so each row now resolves a record carrying the other attack's value")


# --- (p) detector liveness, per channel ------------------------------------
# A detector that never fires and a boundary nothing ever reached emit the same
# clean run, so the only way to separate them is to plant something the detector
# MUST catch and then check from the bytes that it did. The construction needs
# no member this version does not already have: `classes` says which channel an
# attack belongs to, `expectedPayloads` is the planted stimulus, the
# interception's `aeePayloadCommitment` is what the substrate committed to,
# `pinned` is the row asserting the two are comparable, and the seal's
# `aeeObservedAttacks` is the run-end list of what was attributed.
#
# The claim is strictly per channel: a probe caught on one channel says nothing
# about the channel beside it. THREE channels rather than two, because a rail
# that evaluates the first row and the last passes a two-channel statement while
# skipping everything between, and each vector below plants its fault on a
# channel that is neither the first nor the last where it can.
#
# ok-052 is the accept anchor for all three: a rail that refuses every
# multi-channel `pinned` statement satisfies each refusal here and is wrong.

M_PIN3 = {"classes": {"XA": ["XA-EXAMPLE-1"],
                      "XB": ["XB-EXAMPLE-1"],
                      "XC": ["XC-EXAMPLE-1"]},
          "expectedPayloads": {"XA-EXAMPLE-1": [D["intercepted-bytes-1"]],
                               "XB-EXAMPLE-1": [D["intercepted-bytes-2"]],
                               "XC-EXAMPLE-1": [D["intercepted-bytes-3"]]}}

LIVE_COVERAGE = {"assessedClasses": ["XA", "XB", "XC"], "outOfScope": {},
                 "routedElsewhere": {}}
LIVE_ATTACKS = ["XA-EXAMPLE-1", "XB-EXAMPLE-1", "XC-EXAMPLE-1"]


def _three_pinned(manifest: dict[str, Any],
                  commits: tuple[str, str, str]) -> dict[str, Any]:
    """ok-052 shape: one planted probe per channel, each demonstrated live."""
    env = environment(manifest)
    b = binding_for(env)
    return statement(
        env,
        [caught_row(refs=(0,), attack="XA-EXAMPLE-1", attribution="pinned"),
         caught_row(refs=(1,), attack="XB-EXAMPLE-1", attribution="pinned"),
         caught_row(refs=(2,), attack="XC-EXAMPLE-1", attribution="pinned")],
        [record(interception_payload(b, commit=commits[0])),
         record(interception_payload(b, commit=commits[1])),
         record(interception_payload(b, commit=commits[2])),
         record(sealed_payload(b, observed_attacks=LIVE_ATTACKS))],
        result="fail",
        coverage=LIVE_COVERAGE)


def P_three_pinned() -> dict[str, Any]:
    return _three_pinned(M_PIN3, ("intercepted-bytes-1", "intercepted-bytes-2",
                                  "intercepted-bytes-3"))


PARENTS["ok-052 shape (a demonstrated live probe on each of three channels)"] \
    = P_three_pinned


def _b983() -> dict[str, Any]:
    """The middle channel's interception commits to a value no corpus entry
    declares, while the channels either side of it stay satisfied."""
    return _three_pinned(M_PIN3, ("intercepted-bytes-1", "intercepted-bytes-4",
                                  "intercepted-bytes-3"))


vec("bad-983-liveness-middle-channel-commitment-unmatched", "ok-052",
    "the middle channel's interception commits to a value the corpus declared "
    "for no attack, with the first and last channels left satisfied",
    ["re-sign-record", "recompute-batch-root"], [102],
    ["attribution-pin-unmatched"], _b983,
    spec="L600-609",
    note="bad-960 is this fault on a statement with one channel, where the "
         "first pinned row and the only pinned row are the same row. A rail "
         "that decides the attribution rule on the first row it meets, or that "
         "stops at the first row it can satisfy, passes that vector and reports "
         "this statement valid while the middle channel's detector is evidenced "
         "by a value nobody predicted")


def _b984() -> dict[str, Any]:
    """The last channel keeps the stronger attribution after its planted probe
    is removed from the corpus, so nothing remains to compare against."""
    manifest = copy.deepcopy(M_PIN3)
    del manifest["expectedPayloads"]["XC-EXAMPLE-1"]
    return _three_pinned(manifest, ("intercepted-bytes-1", "intercepted-bytes-2",
                                    "intercepted-bytes-3"))


vec("bad-984-liveness-last-channel-unpinnable", "ok-052",
    "the corpus drops the last channel's expectedPayloads entry while its row "
    "keeps declaring pinned",
    ["recompute-corpus-digest", "rederive-binding", "re-sign-record",
     "recompute-batch-root"], [101],
    ["attribution-unpinnable"], _b984,
    spec="L600-609; L775-781",
    note="the per-channel form of bad-959. A channel whose probe the corpus no "
         "longer predicts cannot be shown live by comparison, and a producer "
         "that keeps the stronger value there is claiming a check that has no "
         "input. The two channels before it are unchanged, so a rail deciding "
         "the run on the channels it has already satisfied accepts this")


def _b985() -> dict[str, Any]:
    """The middle channel's interception is deleted and its row re-pointed at
    the seal, leaving a caught pinned row resolving no interception at all."""
    st = P_three_pinned()
    recs = st["predicate"]["observationRecords"]
    del recs[1]                       # channel B's interception
    rows = st["predicate"]["attackResults"]
    rows[0]["observationRefs"] = [0]  # channel A, unmoved
    rows[1]["observationRefs"] = [2]  # channel B, now resolving the seal
    rows[2]["observationRefs"] = [1]  # channel C, shifted down by the deletion
    return reroot(st)


vec("bad-985-liveness-middle-channel-probe-uncaught", "ok-052",
    "the middle channel's interception is deleted and its row re-pointed at "
    "the seal, which still names the channel's attack",
    ["recompute-batch-root"], [100],
    ["caught-row-uncovered", "attribution-pinned-recordless"], _b985,
    compound=True, spec="L600-609",
    note="the dead detector papered over: the channel produced nothing, the "
         "producer reported a catch anyway, and every universally quantified "
         "clause about the records the row resolves is true over an empty set. "
         "ok-053 is the honest report of the same run -- the same three planted "
         "probes, the middle channel's row clean and its attack absent from the "
         "seal -- and it is accepted, so what this vector refuses is the claim "
         "and never the outcome")


# --- (i) rules the corpus was measured not to force ------------------------
# Every vector below closes a rule a mutation campaign found the corpus did not
# force: the rail's check could be switched off and the whole suite stayed green.
# They are the only vectors here that exist because of a measurement rather than
# a reading of the specification, which is why each note says what went unseen.

vec("bad-900-sealed-method-reconstructed", "ok-002",
    'sealed record signed aeeMethod: "reconstructed"',
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"],
    _seal_mut(P_clean, 1, lambda o: {**o, "aeeMethod": "reconstructed"}),
    spec="L1273-1278; L1287-1290",
    note="the sealed twin of bad-704 and bad-712. Every other kind's method "
         "constraint had a vector and this one did not, so a rail that read "
         "the sealed record's aeeMethod and did nothing with it passed")


def _b901() -> dict[str, Any]:
    # The bounded parent, not the drop-zero one: a negative count on a record
    # carrying no aeeDropBound is caught by the bound clause first (bad-708),
    # so the sign rule is only reachable where a bound is declared and the
    # count is inside it by arithmetic that reads the sign the wrong way.
    st = mutate_record_payload(P_clean_bounded(), 1,
                               lambda o: {**o, "aeeDropCount": -1})
    env = st["predicate"]["observationEnvironment"]
    st["predicate"]["observationRecords"].append(
        record(sealed_payload(binding_for(env))))
    return reroot(st)


vec("bad-901-sealed-negative-dropcount", "ok-003",
    "sealed aeeDropCount: -1 inside a declared aeeDropBound: 5",
    ["re-sign-record", "recompute-batch-root"], [65],
    ["sealed-covers-nothing"], _b901,
    spec="L1291-1296",
    note="a count of dropped observations below zero is not a count. The "
         "corpus tested the bound from above (bad-709) and never from below, "
         "so a rail comparing only against the bound accepted it")


def _b902() -> dict[str, Any]:
    # Two arming records, one of them carrying a posture the run never pinned.
    # With a single arming record this rule is unreachable: the sealed record's
    # posture must equal both the arming record's and the pinned digest, and
    # the pinned comparison fires first on every input that could reach the
    # arming comparison. The set of arming postures is built from ALL of the
    # row's referenced arming records while class-match needs only one of them
    # to be valid, so a second arming record is what separates the two clauses.
    st = P_clean()
    env = st["predicate"]["observationEnvironment"]
    st["predicate"]["observationRecords"].append(
        record(arming_payload(binding_for(env), posture=D["other-posture"])))
    st["predicate"]["attackResults"][0]["observationRefs"] = [0, 1, 2]
    return reroot(st)


vec("bad-902-sealed-posture-ne-arming", "ok-002",
    "a second arming record carrying a posture digest the run never pinned, "
    "referenced by the clean row alongside the valid arming and sealed pair",
    ["recompute-batch-root"], [65],
    ["sealed-covers-nothing"], _b902,
    spec="L1291-1296",
    note="the sealed-vs-arming half of the posture equality, which bad-710 "
         "cannot separate. A rule can go unforced because the corpus SHAPE "
         "cannot express its precondition rather than because nobody wrote "
         "the vector, and the two need different fixes")


def _b905() -> dict[str, Any]:
    # The vocabulary object is present and one of its two required arrays is
    # not. The digest is re-derived over the object as carried so the vector
    # cannot be dismissed as a stale digest: it is the shape that is wrong.
    st = P_artifact_degraded()
    voc = st["predicate"]["observationEnvironment"]["observationVocabulary"]
    del voc["labels"]
    voc["digest"]["sha256"] = jcs_digest({"caught": voc["caught"]})
    return st


vec("bad-905-vocabulary-labels-absent", "ok-033",
    "drop labels from an observationVocabulary that is otherwise present; "
    "digest re-derived over the truncated object",
    ["recompute-vocabulary-digest"], [51],
    ["vocabulary-not-canonical"], _b905, spec="L756-764",
    note="bad-601 drops the whole vocabulary and every array vector edits an "
         "array that is there. The half-present object sat between them: a "
         "rail checking that the member exists, then reading labels, accepted "
         "a statement carrying no label set at all")


def _b906() -> dict[str, Any]:
    # The corpus keeps its name, uri and digest and loses the manifest that
    # digest is taken over, so the pinned value has no pre-image anywhere in
    # the statement and the coverage rules have no class map to read.
    st = P_artifact_degraded()
    del st["predicate"]["observationEnvironment"]["corpus"]["manifest"]
    return st


vec("bad-906-corpus-manifest-absent", "ok-033",
    "drop corpus.manifest, keeping the corpus name, uri and digest", [],
    [78], ["environment-incomplete"], _b906, spec="L743-753",
    note="one statement two rails read two ways: the Go rail called the "
         "environment incomplete and the Python rail accepted it, and nothing "
         "in the corpus made them disagree out loud")


# ---------------------------------------------------------------- checks

# The result vocabulary, in the order the recompute takes its minimum over.
RESULT_ORDER = {"fail": 0, "degraded": 1, "pass_indirect": 2, "pass": 3}
RESULT_VOCAB = frozenset(RESULT_ORDER)
BASIS_VOCAB = {"substrate", "artifact"}
METHOD_VOCAB = {"intercepted", "reconstructed"}


def recompute_result(st: dict[str, Any]) -> str:
    """The minimum of the three independent conditions, under RESULT_ORDER."""
    p = st["predicate"]
    v = p["observationEnvironment"]["observationVocabulary"]
    labels, caught = set(v["labels"]), set(v["caught"])
    forces_fail = False
    indirect = False
    for r in p["attackResults"]:
        lab = r.get("containmentObserved")
        if (lab in caught or lab not in labels
                or r.get("basis") not in BASIS_VOCAB
                or r.get("method") not in METHOD_VOCAB):
            forces_fail = True
        elif r.get("basis") != "substrate" or r.get("method") != "intercepted":
            indirect = True
    cov = p["coverage"]
    return min(
        ["fail" if forces_fail else "pass",
         "degraded" if (cov["outOfScope"] or cov["routedElsewhere"]) else "pass",
         "pass_indirect" if indirect else "pass"],
        key=RESULT_ORDER.__getitem__)


def verify_record_sigs(st: dict[str, Any]) -> None:
    """Assert every signature a record actually carries verifies.

    A record whose signatures member is not an array carries no signature to
    verify, so it is skipped rather than iterated. The skip is not a weakening:
    the vector that produces such a member is testing the entry COUNT, and a
    member with no entries has nothing this assertion could check. Iterating it
    would walk the characters of a string instead.
    """
    pub = Ed25519PublicKey.from_public_bytes(SUB_PUB)
    for rec in st["predicate"].get("observationRecords", []):
        sigs = rec["signatures"]
        if not isinstance(sigs, list):
            continue
        for s in sigs:
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
        # Every substrate row indexes into the observation records, so the
        # records have to be there. Stated rather than assumed: the reads below
        # sit outside the block that established the list is present, so a
        # statement carrying substrate rows and no records reached them as None
        # and died with a TypeError from inside len(). That reports the
        # interpreter's problem instead of the vector's, in a checker whose only
        # job is to say which rule a vector broke.
        assert recs is not None, (
            name + ": substrate rows cite observation records, but the "
            "statement carries none"
        )
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
    commitments_check(name, st)


def commitments_check(name: str, st: dict[str, Any]) -> None:  # noqa: C901 -- one branch per independent 0.7 requirement; see docs/complexity-rationales.toml
    """The coverage validity requirements 0.7 adds, asserted over a PARENT.

    A parent is the statement every vector derived from it starts as, so a
    parent that quietly violates one of these makes every child carry a fault
    it was not written to test. That is not hypothetical here: nine accept
    shapes and four parents carried a substrate row and no sealed record when
    the requirement became unconditional.
    """
    p = st["predicate"]
    env = p["observationEnvironment"]
    voc = env["observationVocabulary"]
    caught_set, label_set = set(voc["caught"]), set(voc["labels"])
    rows = p["attackResults"]
    recs = p.get("observationRecords") or []
    declared = {a for ids in env["corpus"].get("manifest", {}).get("classes", {}).values()
                for a in ids}

    for row in rows:
        assert row.get("attribution") in ("pinned", "paired"), \
            name + ": attribution is required on every row"

    payloads: list[Any] = []
    for r in recs:
        try:
            payloads.append(json.loads(unb64(r["payload"])))
        except (ValueError, KeyError):
            payloads.append(None)

    def resolved(row: dict[str, Any]) -> list[int]:
        refs = row.get("observationRefs")
        return [i for i in refs if isinstance(i, int) and 0 <= i < len(recs)] \
            if isinstance(refs, list) else []

    def kind_of(i: int) -> Any:
        return payloads[i].get("aeeKind") if isinstance(payloads[i], dict) else None

    # a clean row resolves no interception record
    for row in rows:
        lab = row.get("containmentObserved")
        if lab in label_set and lab not in caught_set:
            assert not any(kind_of(i) == "interception" for i in resolved(row)), \
                name + ": a clean row resolves an interception record"

    # every carried interception record is resolved by a caught row
    seen: set[int] = set()
    for row in rows:
        if row.get("containmentObserved") in caught_set:
            seen.update(resolved(row))
    for i, _ in enumerate(recs):
        if kind_of(i) == "interception":
            assert i in seen, name + f": interception record {i} is an orphan"

    # every interception record carries a well-formed commitment
    for i, _ in enumerate(recs):
        if kind_of(i) == "interception":
            values = payloads[i].get("aeePayloadCommitment")
            assert isinstance(values, list) and values, \
                name + f": interception record {i} carries no commitment"
            assert values == sorted(set(values)), \
                name + f": interception record {i} commitment is not canonical"

    if not any(r.get("basis") == "substrate" for r in rows):
        return

    b = binding_for(env, subject_sha=st["subject"][0]["digest"]["sha256"])
    observed = observed_set_digest(recs)
    caught_ids = {r.get("attackId") for r in rows
                  if r.get("containmentObserved") in caught_set}
    assessed = {a for cls in p["coverage"]["assessedClasses"]
                for a in env["corpus"]["manifest"]["classes"].get(cls, [])}

    seals = 0
    for i, _ in enumerate(recs):
        obj = payloads[i]
        if not isinstance(obj, dict) or obj.get("aeeRunBinding") != b:
            continue
        if obj.get("aeeKind") == "sealed":
            seals += 1
            assert obj.get("aeeObservedSet") == observed, \
                name + ": the seal does not commit to the carried record set"
            attacks = obj.get("aeeObservedAttacks")
            assert isinstance(attacks, list) and attacks == sorted(set(attacks)), \
                name + ": aeeObservedAttacks is absent or not canonical"
            assert set(attacks) <= declared, name + ": seal names an unknown attack"
            assert set(attacks) <= caught_ids, \
                name + ": the seal names an attack with no caught row"
        if obj.get("aeeKind") == "arming":
            decl = obj.get("aeeAssessedAttacks")
            assert isinstance(decl, list) and decl == sorted(set(decl)), \
                name + ": aeeAssessedAttacks is absent or not canonical"
            assert set(decl) <= declared, name + ": arming names an unknown attack"
            assert assessed <= set(decl), \
                name + ": the assessed set exceeds the run-start declaration"
    assert seals >= 1, name + ": a substrate row with no sealed record"


def second_fault_absence(v: dict[str, Any], st: Any) -> None:  # noqa: C901 -- one branch per independent fault family; see docs/complexity-rationales.toml
    """Assert every derived commitment NOT under test still verifies."""
    if not isinstance(st, dict):
        # Raw-statement vector (str/bytes): the fault is a byte-level construction
        # (e.g. a duplicate top-level member) that is single by construction and
        # not introspectable as a dict. No derived-commitment cross-check applies.
        return
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
    # (iii) corpus digest verifies unless targeted. A corpus carrying no
    # manifest has no pre-image to re-derive from, and that absence is itself
    # the fault under test (bad-906), so there is nothing here to assert rather
    # than an assertion being waived: re-deriving would be reading a member the
    # vector exists to remove.
    if not conds & {79} and "manifest" in env.get("corpus", {}):
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
    # (vii) the seal still commits to the CARRIED record set unless a run-end
    # commitment is what the vector targets. Every mutation to an interception
    # or examination payload moves the leaf that record contributes, so a
    # vector that mutates one and leaves the seal alone acquires a second
    # fault -- the exact shape this file exists to refuse, and one no earlier
    # assertion could see because before 0.7 nothing on the wire depended on
    # the record set as a set.
    if recs and not conds & {97, 98, 99}:
        want = observed_set_digest(recs)
        for rec in recs:
            try:
                obj = json.loads(unb64(rec["payload"]))
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("aeeKind") == "sealed" \
                    and "aeeObservedSet" in obj \
                    and obj["aeeObservedSet"] != want:
                # An UNREADABLE record cannot be classified by a verifier, so a
                # seal that legitimately counted it disagrees with every rail.
                # That outcome is declared per vector in INHERENT_EXTRA rather
                # than waived here.
                assert "observed-set-mismatch" in v["also"], v["id"]
    # (vi) result recompute matches unless targeted/underivable
    if not conds & {1, 2, 51, 83}:
        if ("observationVocabulary" in env and "coverage" in p
                and p.get("result") in RESULT_VOCAB):
            assert p["result"] == recompute_result(st), v["id"]


# ---------------------------------------------------------------- INDEX.md

COND = {
    1: ("L435", "closed lowercase result vocabulary"),
    2: ("L390-393", "result must equal the recompute"),
    3: ("L440-442", "a row carrying a label from the carried caught set "
                    "contributes fail"),
    4: ("L443-444", "fail-closed on out-of-vocabulary label"),
    5: ("L443-444", "fail-closed on missing/out-of-vocab basis or method"),
    6: ("L444-446", "degraded iff disclosed coverage gap"),
    7: ("L447-450", "UNRESOLVED -- ok-002 is the sole carrier and the corpus "
                    "does not separate this id from aee-c-2. Candidate "
                    "reading, recorded rather than asserted: the third "
                    "recompute condition, which contributes pass_indirect "
                    "when some clean row is not (substrate, intercepted) and "
                    "pass when none is"),
    10: ("L552", "observationRefs non-empty on substrate rows"),
    11: ("L552-553", "every ref index in range (integer)"),
    12: ("L554-556", "caught intercepted row refs an interception record"),
    13: ("L556-557", "reconstructed row refs an examination record"),
    14: ("L557-560", "clean intercepted row refs arming AND covering sealed"),
    15: ("L918-920", "one run-level arming/sealed/examination record covers "
                     "every row earned under it"),
    16: ("L913-918", "observationSelectors is producer vocabulary positionally "
                     "parallel to observationRefs; no gate reads it"),
    17: ("L561-562", "covering payload is canonical RFC 8785"),
    18: ("L1255-1259", "covering payload is valid I-JSON (RFC 7493)"),
    19: ("L1260-1261", "covering media type ends in +json"),
    20: ("L562-563", "covering payload carries the reserved aee members"),
    22: ("L563-564", "aeeRunBinding equals the derived run binding"),
    23: ("L565-566", "row method capped by weakest signed aeeMethod"),
    24: ("L1603", "batchRoot required when records exist"),
    25: ("L1605-1608", "RFC 6962 domain-separated hashing"),
    26: ("L1608-1610", "RFC 6962 recursive split, never duplicate-pad"),
    27: ("L1610", "leaves in array order"),
    28: ("L1610", "a single-record tree's root is its leaf hash"),
    29: ("L1612-1613", "duplicate byte-identical records invalid"),
    30: ("L1615-1617", "batchRoot must recompute"),
    31: ("L1619-1631", "batchRoot omitted exactly when records absent"),
    32: ("L1605-1609", "batchRoot is over every carried record in array "
                       "order, referenced by a row or not"),
    33: ("L726-735", "the evidence tier is derived per row and never carried: "
                     "artifact is declared, substrate is attested when every "
                     "covering signature verifies under consumer policy and "
                     "unattested otherwise, and the tier never alters result"),
    34: ("L732-734", "no TOFU: a consumer with no policy-pinned substrate "
                     "root treats every substrate row as unattested and MUST "
                     "NOT infer the root from the predicate"),
    35: ("L1746-1748", "keyid is an unauthenticated lookup hint, never the "
                       "check"),
    36: ("L1245-1247; L545-546", "a record signature is DSSE PAE over "
                               "(payloadType, payload); the byte-pure "
                               "validity gate never reads a signature, so a "
                               "signature that does not verify is a tier "
                               "fact and not a validity fault"),
    38: ("L739-741", "a carried predicate-level evidenceTier member MUST be "
                     "ignored"),
    41: ("L952-953", "basis required, closed {substrate, artifact}"),
    43: ("L1049-1053", "the retired 0.4 basis and method values are "
                     "out-of-vocabulary, with no alias"),
    42: ("L987-988", "method required, closed {intercepted, reconstructed}"),
    44: ("L720-724", "fail-closed substrate row invalidates; artifact row "
                     "stays a valid fail"),
    45: ("L998-1004", "weakest-input method composition"),
    47: ("L1212-1220", "missing actualLayer = malformed statement, not fail"),
    48: ("L1221-1226", "clean row actualLayer is the literal none"),
    49: ("L1226-1229", "the literal none is valid on a caught row too, and "
                     "states that the event was observed and no enforcement "
                     "layer acted"),
    50: ("L1212-1213", "actualLayer names the enforcement layer that acted on "
                     "the row's containment event"),
    51: ("L756-764", "observationVocabulary required"),
    52: ("L760-762", "caught is a subset of labels"),
    53: ("L762", "vocabulary arrays sorted ascending, no duplicates"),
    54: ("L762-764", "vocabulary digest is JCS of {caught, labels}"),
    57: ("L768-770", "runEntropy required with any substrate row"),
    58: ("L210-213", "exactly one subject on a statement of any basis"),
    59: ("L210-224", "binding digest inputs lowercase 64-hex sha256"),
    60: ("L174-182", "binding pre-image construction"),
    61: ("L739-741", "a predicate-level member beginning with the reserved "
                     "aee prefix MUST be ignored"),
    62: ("L229-237", "binding is anti-splice"),
    63: ("L1266-1270", "arming record kind constraints"),
    64: ("L1273-1278", "sealed record required members"),
    65: ("L1291-1296", "sealed covering conditions"),
    66: ("L1279-1281", "examination signed aeeMethod reconstructed"),
    68: ("L1139-1140", "each referenced record independently satisfies its "
                     "class constraints"),
    71: ("L1561-1565", "unknown aeeKind covers nothing"),
    73: ("L1567-1569", "the aee payload member prefix is reserved; every "
                       "other payload member is producer territory and does "
                       "not stop a record covering"),
    75: ("L237-241", "fail-closed on unimplemented binding version"),
    77: ("L3; L313", "statement _type and predicateType URIs"),
    78: ("L743-770", "observationEnvironment required members"),
    79: ("L747-751", "corpus digest re-derives from embedded manifest"),
    80: ("L749-751", "attackId under at most one manifest class"),
    81: ("L880", "row attackId appears in the manifest"),
    82: ("L923-926", "coverage exactly equals the manifest at attack "
                     "granularity"),
    83: ("L865-869", "coverage member required"),
    84: ("L1633-1643", "doesNotAssert single canonical spelling"),
    85: ("L1645", "issuedAt required, under the Timestamp profile"),
    86: ("L150-163", "vocabulary labels/caught entries BMP-only; a "
                             "supplementary-plane entry is malformed"),
    87: ("L150-163", "covering payload member names BMP-only; a "
                             "supplementary-plane name covers nothing"),
    88: ("L880-888", "row members are strictly typed; a wrong-JSON-type "
                     "member is a malformed statement"),
    90: ("L901-903", "no two attackResults rows share an attackId"),
    89: ("L1485-1516", "arming chain-member syntax: positive "
                               "aeeRunSeq; aeeChainScope required with it; "
                               "aeePrevRunBinding lowercase 64-hex, absent "
                               "exactly when aeeRunSeq is 1"),
    91: ("L1243-1245", "each observation record's signatures member carries at "
                     "least one entry"),
    92: ("L928-950", "the corpus manifest declares at least one attack "
                     "identifier across all of its classes"),
    93: ("L807-815", "networkPosture.posture is a registered value"),
    94: ("L574-579", "a clean row resolves no observationRefs index to an "
                     "interception record"),
    95: ("L580-585", "every carried interception record is resolved by at "
                     "least one observationRefs index on a caught row"),
    96: ("L586-594", "a statement carrying a basis: substrate row carries a "
                     "sealed record satisfying every constraint of its kind, "
                     "whether or not a row resolves an index to it"),
    97: ("L595-599", "aeeObservedSet on every carried sealed record equals "
                     "the value recomputed over the carried interception and "
                     "examination records"),
    98: ("L1458-1465", "every attack the seal names in aeeObservedAttacks has "
                       "a row whose containmentObserved is in the carried "
                       "caught set; the rule reads in one direction only"),
    99: ("L1390-1396", "the union of the manifest identifiers for the carried "
                       "assessedClasses is a SUBSET of the arming record's "
                       "aeeAssessedAttacks"),
    100: ("L600-609", "a row declaring attribution: pinned resolves at least "
                      "one interception record"),
    101: ("L600-609", "a row declaring attribution: pinned names an attack "
                      "the manifest carries an expectedPayloads entry for"),
    102: ("L600-609", "every interception a pinned row resolves carries in "
                      "aeePayloadCommitment at least one value from that "
                      "attack's expectedPayloads entry"),
    103: ("L775-781", "corpus.manifest.expectedPayloads is well formed: every "
                      "key a declared attack, every array non-empty, sorted "
                      "by UTF-16 code unit, duplicate-free and lowercase "
                      "64-hex"),
    104: ("L1377-1388", "an interception record carries aeePayloadCommitment, "
                        "non-empty, sorted by UTF-16 code unit, duplicate-free "
                        "and lowercase 64-hex"),
    105: ("L1045-1049", "attribution is required on every row and its "
                        "vocabulary is closed; a missing or out-of-vocabulary "
                        "value is fail-closed exactly as basis and method are"),
    106: ("L1317-1331", "a moat-drop record covers nothing in every state and "
                        "carries no constraint that could change that; it "
                        "still contributes its leaf to batchRoot, never enters "
                        "aeeObservedSet or the method cap, and the refusal a "
                        "row earns by resolving one names the kind rather than "
                        "reporting an unrecognized kind"),
    107: ("L1317-1331", "an uncommitted-observation record covers nothing in "
                        "every state on the same terms, and in particular "
                        "cannot stand in for an interception: not for a caught "
                        "row's coverage, not for the existence requirement a "
                        "pinned row must satisfy, and not for the "
                        "expectedPayloads comparison"),
}


def vendored_commit() -> str:
    """The upstream commit the vendored spec came from, read from the pin.

    Typed at vendor time, this constant went stale the first time the upstream
    branch moved and the INDEX then named a revision the vectors were not built
    against. ``spec/VENDOR-PIN.json`` is written by ``scripts/vendor-spec.py``
    from git, so reading it here removes the only copy that could disagree.
    """
    pin_path = os.path.normpath(
        os.path.join(OUT, "..", "..", "spec", "VENDOR-PIN.json")
    )
    with open(pin_path, encoding="utf-8") as f:
        return str(json.load(f)["commit"])[:7]


def write_index() -> None:
    L: list[str] = []
    L.append("# INVALID conformance vectors (adversarial-execution-evidence v0.6)")
    L.append("")
    L.append("This directory is the conformance suite's `vectors/reject/` layout.")
    L.append("")
    L.append("Ground truth: `spec/predicates/adversarial-execution-evidence.md` @")
    L.append(f"`{vendored_commit()}` (in-toto/attestation PR #570 branch),")
    L.append("version 0.6.0, type URI")
    L.append(f"`{PREDICATE_TYPE}`.")
    L.append("The commit is read from `spec/VENDOR-PIN.json`, which")
    L.append("`scripts/vendor-spec.py` derives from git at vendor time, so this")
    L.append("line cannot name a revision the vendored bytes did not come from.")
    L.append("")
    L.append("`Lnnn` anchors below are line refs into the vendored copy, in the")
    L.append("coordinate frame of the commit named above and no other. They are")
    L.append("remapped onto the new line numbers whenever the spec is re-vendored,")
    L.append("and `spec/ANCHOR-PINS.json` records the text each one addresses, so")
    L.append("`scripts/spec-anchor-gate.py` fails when an anchor comes to point at")
    L.append("prose it was not drawn around.")
    L.append("")
    L.append("Every file is a COMPLETE in-toto Statement (UNWRAPPED, no outer DSSE;")
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
    L.append("  - `keyid` is an unauthenticated hint, never the check (spec L1746-1748).")
    L.append(f"- Fixed timestamps: `issuedAt: {ISSUED_AT}`, `armedAt: {ARMED_AT}`")
    L.append("  (a later `armedAt` appears only in bad-702).")
    L.append(f"- Record `payloadType`: `{PAYLOAD_TYPE}`.")
    L.append("- Subject `example-agent-bundle`; attack ids `XA-EXAMPLE-*`,")
    L.append("  `XB-EXAMPLE-*` and `XC-EXAMPLE-*`, one class per detection")
    L.append("  channel; producer label/layer vocabulary is spec-verbatim")
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
    L.append("Run bindings derive per spec L174-182 from each statement's own values.")
    L.append("Negative known-answer for bad-303, the retired version-1 pre-image")
    L.append("that MUST NOT match (JCS, then SHA-256):")
    _env = environment(M1)
    L.append("")
    L.append("```json")
    L.append(json.dumps(binding_preimage(_env, version="1"), sort_keys=True,
                        indent=2))
    L.append("```")
    L.append("")
    L.append("## Condition registry (aee-c ids)")
    L.append("")
    L.append("This table is the id-to-spec-line registry, and it is the only one:")
    L.append("no other file in this repository carries a second copy. It covers")
    L.append("EVERY id the suite cites, in either direction, so an id carried only")
    L.append("by an accept vector resolves here rather than nowhere. Until")
    L.append("2026-07-30 the table listed only the ids the reject set happened to")
    L.append("use and this paragraph named a table in the repository README that")
    L.append("has never existed, which left 17 ids cited by vectors and resolvable")
    L.append("to no rule at all.")
    L.append("")
    L.append("`scripts/condition-registry-gate.py` fails when a condition a vector")
    L.append("cites has no row here, and when a row here names a condition no")
    L.append("vector cites, so neither direction can drift again unnoticed.")
    L.append("")
    L.append("A row reading `UNRESOLVED` is one whose meaning could not be")
    L.append("established from the specification and the rails. It records the")
    L.append("candidate reading and says it is a candidate, because a registry row")
    L.append("that guesses is worse than one that is missing: it looks resolved.")
    L.append("")
    L.append("| id | spec anchor | condition |")
    L.append("|---|---|---|")
    for c in sorted(COND):
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
        if v["also"]:
            also = ", ".join(f"`{c}`" for c in v["also"])
            codes += f" (also carries: {also})"
        red = ", ".join(v["rederive"]) if v["rederive"] else "-"
        L.append(f"| `{v['id']}` | {v['parent']} | {v['mutation']} | {red} "
                 f"| {conds} | {codes} | {v['spec']} |")
    L.append("")
    L.append("## Notes on specific vectors")
    L.append("")
    for v in VECTORS:
        if v["note"]:
            L.append(f"- **{v['id']}**: {v['note']}.")
    L.append("")
    L.append("## Compound vectors and precedence pins")
    L.append("")
    L.append("`expected` codes form a SET: a rail conforms when its code is in the")
    L.append("set and the verdict matches. Vectors marked COMPOUND carry more than")
    L.append("one condition; every other vector is single-fault by construction.")
    L.append("Most are compound because deriving them singly is impossible without")
    L.append("introducing a different fault. No vector in this directory is compound")
    L.append("in order to pin a precedence: a statement whose two conditions the")
    L.append("specification does not order between belongs in `vectors/indeterminate/`,")
    L.append("where every reading a conformant rail may take is declared and the rail")
    L.append("is held to one of them. Registry precedence pins applied here:")
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
    L.append("Signature VERIFICATION failure is NEVER a failure code in this suite:")
    L.append("whether a record's signature verifies against a consumer-named key is")
    L.append("the evidence tier's separate, trust-relative question. Every committed")
    L.append("signature here verifies under the derived test public key above. How")
    L.append("many entries the array carries is a different question, answered")
    L.append("without key material and therefore inside validity: `bad-745` carries")
    L.append("a record with zero of them and no signature to verify, and `bad-749`")
    L.append("carries a member of the wrong JSON type that holds none either. Which")
    L.append("condition a rail reports when a record with no entries shares a")
    L.append("statement with one whose payload does not decode is not settled by the")
    L.append("specification and is not settled here: it is the indeterminate family")
    L.append("`ind-001` / `ind-002` in `vectors/indeterminate/`.")
    L.append("")
    L.append("## Deferred coverage (no vector, by design)")
    L.append("")
    L.append("- **Missing or out-of-vocabulary `basis` on a SUBSTRATE-carrying")
    L.append("  statement**: the fail-closed branch split (substrate => the")
    L.append("  attestation is invalid vs artifact => a valid `fail`) turns on a")
    L.append("  classification the row itself refuses to supply, and the spec")
    L.append("  text does not state which branch applies. Shipping a reject")
    L.append("  vector here would silently resolve that reading, so there is")
    L.append("  none; it is a formal spec-edit ask on the PR thread.")
    L.append("  This bullet has NARROWED. The accept suite now ships")
    L.append("  `ok-901-row-missing-basis`, a recordless statement whose single")
    L.append("  row carries no `basis` member, no refs and no substrate")
    L.append("  participation of any kind: it is VALID and it recomputes to")
    L.append("  `fail`. That decides the half of the question a statement with")
    L.append("  no substrate vantage can even ask, and it was shipped because")
    L.append("  the rail's basis branch was measured to have no vector behind")
    L.append("  it in either direction. What stays open is the half this")
    L.append("  directory would have to answer: the same row inside a statement")
    L.append("  that does carry substrate evidence. The out-of-vocab METHOD and")
    L.append("  LABEL substrate twins (bad-501, bad-504) plus the valid")
    L.append("  artifact-row twins in the accept suite cover the decidable rest")
    L.append("  of the fail-closed axis.")
    L.append("- **Duplicate-record identity discriminator** (leaf-hash vs")
    L.append("  byte-identical): bad-405 is invalid under BOTH readings; the")
    L.append("  discriminating vector waits on the spec answer.")
    L.append("- **observationSelectors length mismatch**: unstated in the spec;")
    L.append("  formal ask, no vector.")
    L.append("- **Artifact-only multi-subject**: the one-subject rule is scoped to")
    L.append("  substrate-carrying statements (L210); whether artifact-only")
    L.append("  multi-subject is legal is an open ask (bad-607 keeps a substrate")
    L.append("  row precisely so the rule undeniably applies).")
    L.append("- **Replay of a genuine runEntropy** (stateful-consumer concern) and")
    L.append("  **coherence checks** (MAY): behavior/harness territory, not")
    L.append("  statement-shape vectors.")
    L.append("")
    with open(os.path.join(OUT, "INDEX.md"), "w") as f:
        f.write("\n".join(L) + "\n")


IND_OUT = os.path.normpath(os.path.join(OUT, "..", "indeterminate"))


def ind_families() -> dict[str, list[dict[str, Any]]]:
    fams: dict[str, list[dict[str, Any]]] = {}
    for v in IND_VECTORS:
        fams.setdefault(str(v["family"]), []).append(v)
    return fams


def ind_family_check() -> None:
    """Refuse a family that cannot discriminate the readings it declares.

    Two ways a declared reading set is a claim nothing measures, and both are
    refused here rather than shipped. A member that declares a different set of
    reading NAMES than its siblings makes the coherence check unrunnable, since
    there is then no single reading to hold a rail to. And two readings that
    predict the same condition on EVERY member are one reading written twice: a
    rail's answers can never separate them, so declaring both advertises a
    distinction the corpus cannot see -- the shape of a check that measures
    nothing.
    """
    for family, members in sorted(ind_families().items()):
        names = {frozenset(m["readings"]) for m in members}
        assert len(names) == 1, (
            f"{family}: members declare different reading names {names}; a "
            "coherence check has no single reading to hold a rail to"
        )
        declared = sorted(next(iter(names)))
        assert len(declared) >= 2, (
            f"{family}: declares {len(declared)} reading(s). A family with one "
            "reading is a reject vector wearing a different hat"
        )
        for i, left in enumerate(declared):
            for right in declared[i + 1:]:
                assert any(m["readings"][left] != m["readings"][right]
                           for m in members), (
                    f"{family}: readings {left!r} and {right!r} predict the same "
                    "condition on every member, so no rail's answers can ever "
                    "separate them; add a discriminating member or drop one"
                )


def write_ind_index() -> None:
    L: list[str] = []
    L.append("# INDETERMINATE conformance vectors "
             "(adversarial-execution-evidence v0.6)")
    L.append("")
    L.append("This directory is the conformance suite's `vectors/indeterminate/`")
    L.append("layout. It carries the statements on which the specification settles")
    L.append("the VERDICT and does not settle the CONDITION.")
    L.append("")
    L.append("Ground truth: `spec/predicates/adversarial-execution-evidence.md` @")
    L.append(f"`{vendored_commit()}` (in-toto/attestation PR #570 branch),")
    L.append("version 0.6.0, type URI")
    L.append(f"`{PREDICATE_TYPE}`.")
    L.append("")
    L.append("## What an indeterminate vector claims")
    L.append("")
    L.append("The other two directories each make a claim every conformant verifier")
    L.append("has to satisfy identically: `accept/` says these bytes are valid and")
    L.append("recompute to a named result, `reject/` says they are invalid and a")
    L.append("conformant rail names a condition from a declared set. Neither can say")
    L.append("that the verdict is settled while the condition is not, and that is")
    L.append("exactly what the specification says about the statements here. It")
    L.append("carries no failure-code vocabulary of any kind, and of its own")
    L.append("two-stage verification description it says that \"the sequencing")
    L.append("itself is informative\" (L413-415). Two rails can therefore both")
    L.append("reject the same bytes and name different conditions, and the text is")
    L.append("equally happy with both.")
    L.append("")
    L.append("Widening a reject vector's expected set to name both conditions does")
    L.append("not express this. The harness compares code SETS, so a widened set is")
    L.append("satisfied by either answer and by a rail that emits both, and the")
    L.append("vector stops measuring the question instead of starting to. The")
    L.append("difference between \"either answer is conformant\" and \"a rail may")
    L.append("report a superset\" would be invisible in the manifest, which is the")
    L.append("condition under which a divergence goes unnoticed for revisions.")
    L.append("")
    L.append("So a member of this directory declares:")
    L.append("")
    L.append("- a DETERMINED verdict. Indeterminacy is scoped to the condition and")
    L.append("  never to the verdict; a vector whose verdict is open would certify")
    L.append("  nothing at all.")
    L.append("- a set of READINGS, each naming the condition that reading predicts")
    L.append("  for this member. A family is the set of members sharing one reading")
    L.append("  vocabulary, and it is written so that the readings are separable by")
    L.append("  some member's answer; the generator refuses a family in which two")
    L.append("  declared readings predict the same condition on every member.")
    L.append("")
    L.append("## What a rail must satisfy")
    L.append("")
    L.append("1. **Verdict.** Every member's declared verdict, exactly as a reject")
    L.append("   vector's.")
    L.append("2. **Closure.** On each member, the rail's codes intersect the union")
    L.append("   of that member's predicted conditions. An answer no declared")
    L.append("   reading predicts is a failure and not a widening: the corpus then")
    L.append("   has an undeclared reading, and it is added by name, with its")
    L.append("   argument, never by relaxing the set.")
    L.append("3. **Coherence.** Across the whole family, the rail's answers are")
    L.append("   explained by ONE declared reading. Either answer is admissible; no")
    L.append("   answer is not, and neither is a pair of answers straddling two")
    L.append("   readings, because that is a rail whose reported condition turns on")
    L.append("   incidental structure rather than on a policy it applies.")
    L.append("")
    L.append("The reference rails' reading is RECORDED, in the manifest and in the")
    L.append("harness report, and is not required of anybody. That is the whole")
    L.append("point: the corpus stops failing a from-spec rail for a non-defect and")
    L.append("starts saying which reading each rail took, which is the thing two")
    L.append("agreeing rails can never tell each other.")
    L.append("")
    L.append("Regenerate byte-identically with:")
    L.append("`python3 ../reject/gen_invalid_vectors.py`. These vectors are built by")
    L.append("the reject generator because they are built the same way, from the")
    L.append("same parents,")
    L.append("the same derived keys and the same second-fault self-check; only the")
    L.append("claim their manifest entry makes differs.")
    L.append("")
    L.append(f"## Vectors ({len(IND_VECTORS)})")
    L.append("")
    for family, members in sorted(ind_families().items()):
        declared = sorted(next(iter(members))["readings"])
        L.append(f"### Family `{family}`")
        L.append("")
        header = ("| vector | parent | single mutation | conditions (aee-c ids) | "
                  + " | ".join(f"reading `{r}`" for r in declared) + " | spec |")
        L.append(header)
        L.append("|---|---|---|" + "---|" * (len(declared) + 2))
        for m in members:
            conds = " ".join(f"aee-c-{c}" for c in m["conds"])
            cells = " | ".join(f"`{m['readings'][r]}`" for r in declared)
            L.append(f"| `{m['id']}` | {m['parent']} | {m['mutation']} | {conds} "
                     f"| {cells} | {m['spec']} |")
        L.append("")
    L.append("## Notes on specific vectors")
    L.append("")
    for v in IND_VECTORS:
        if v["note"]:
            L.append(f"- **{v['id']}**: {v['note']}.")
    L.append("")
    L.append("## What is NOT in here")
    L.append("")
    L.append("The specification leaves other things open, and most of them cannot")
    L.append("be a vector. They divide four ways and only the first is admissible")
    L.append("here:")
    L.append("")
    L.append("- **Two conformant answers to a question the harness observes.**")
    L.append("  This directory.")
    L.append("- **A limit rather than a choice.** \"The set of attacks actually")
    L.append("  executed therefore remains a producer assertion under both")
    L.append("  shapes\" (L513-528), and the shared-reference evidencing rule on")
    L.append("  a row declaring `paired`, of which the text says outright that")
    L.append("  \"a conforming verifier neither can nor may invent an evidencing")
    L.append("  heuristic in its place\" (L888-900). Every conformant verifier")
    L.append("  must ACCEPT those statements: nothing in the carried bytes can")
    L.append("  see the omission, so there is no divergence to declare. They are")
    L.append("  accept vectors, and their limit is prose. The same obligation on")
    L.append("  a row declaring `pinned` is not in this class: the corpus")
    L.append("  declares the expected commitment and the verifier compares, so a")
    L.append("  row that fails it is a reject vector.")
    L.append("- **Consumer policy the byte-pure surface does not carry.** A")
    L.append("  consumer MAY reject an attestation carrying `unattested` substrate")
    L.append("  rows (L1111-1114), MAY admit `pass_indirect` (L495-496), MAY")
    L.append("  coherence-check a row against the pinned posture (L1206-1210), MAY")
    L.append("  bound a key with a validity window (L1190). None of these moves the")
    L.append("  verdict this suite reads, because validity \"is a function of")
    L.append("  carried bytes alone and holds identically for every consumer\"")
    L.append("  (L1689-1692). A rail that answered the admission question in the")
    L.append("  verdict field would be wrong, not free.")
    L.append("- **Producer options.** `observationSelectors`, `aeeDropBound`, the")
    L.append("  descriptor members no rule reads, the optional run-chaining")
    L.append("  members. The producer chooses; the verifier's handling is forced,")
    L.append("  and accept vectors already carry it.")
    L.append("")
    with open(os.path.join(IND_OUT, "INDEX.md"), "w") as f:
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
        if isinstance(st, bytes):
            # Byte-level vector: the fault IS the encoding, so the file is not
            # valid UTF-8 and cannot be produced by any serializer. Written
            # verbatim in binary. These are the only vectors exempt from the
            # re-parse check below, and the exemption is the assertion: a
            # byte-level vector that decodes as UTF-8 is not testing what it
            # claims to, so it must fail to decode.
            with open(path, "wb") as fb:
                fb.write(st if st.endswith(b"\n") else st + b"\n")
            with open(path, "rb") as fb:
                written = fb.read()
            try:
                json.loads(written.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            raise SystemExit(
                f"{v['id']}: declared a byte-level vector but is a valid JSON "
                "text; either the fault was lost in serialization, or the "
                "vector belongs in the raw-statement tier, whose members are "
                "parseable and carry their fault in the parsed content"
            )
        with open(path, "w") as f:
            if isinstance(st, str):
                # Raw-statement vector: bytes crafted to carry a fault the dict
                # representation cannot express (e.g. a duplicate top-level
                # member). Written verbatim, not re-serialized from a dict.
                f.write(st if st.endswith("\n") else st + "\n")
            else:
                json.dump(st, f, indent=2, sort_keys=True, ensure_ascii=False)
                f.write("\n")
        with open(path) as f:
            json.load(f)  # every vector parses as JSON (a duplicate member is last-wins)

    # Drop tripwire, read from the committed corpus rather than typed here. A
    # typed count only ever states what was true when someone last edited it,
    # and it is blind in the direction that actually went wrong: five vector
    # files were once committed into this directory with no builder behind
    # them, which leaves a typed count agreeing with the builders it still has
    # while the directory holds more files than this generator can produce.
    # Reading the directory fails on that, on a builder deleted without its
    # file, and on a file deleted without its builder, and it cannot itself go
    # stale. Deleting a vector deliberately means deleting both, which is the
    # act the tripwire should permit and the only one it does.
    on_disk = len([f for f in os.listdir(OUT) if f.startswith("bad-")
                   and f.endswith(".json")])
    assert len(VECTORS) == on_disk, (
        f"built {len(VECTORS)} reject vectors but {on_disk} bad-*.json files "
        "are committed beside this generator; a file with no builder cannot "
        "be regenerated and a builder with no file was silently dropped"
    )

    # 3. the indeterminate family, built the same way into the sibling directory
    ind_family_check()
    os.makedirs(IND_OUT, exist_ok=True)
    for iv in IND_VECTORS:
        assert iv["id"] not in ids, "duplicate id " + iv["id"]
        ids.add(iv["id"])
        ist = iv["build"]()
        # The same second-fault assertion the reject set runs. An indeterminate
        # vector is indeterminate in WHICH condition is reported, never in how
        # many faults it carries: an undeclared third fault would give a rail a
        # third answer and the declared readings would stop being exhaustive.
        second_fault_absence(iv, ist)
        with open(os.path.join(IND_OUT, iv["id"] + ".json"), "w") as f:
            json.dump(ist, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write("\n")

    ind_on_disk = len([f for f in os.listdir(IND_OUT) if f.startswith("ind-")
                       and f.endswith(".json")])
    assert len(IND_VECTORS) == ind_on_disk, (
        f"built {len(IND_VECTORS)} indeterminate vectors but {ind_on_disk} "
        "ind-*.json files are committed in vectors/indeterminate/; the same "
        "tripwire the reject set carries, for the same reason"
    )

    # 4. indexes
    write_index()
    write_ind_index()
    print(f"OK: {len(VECTORS)} invalid vectors + INDEX.md")
    print(f"    {len(IND_VECTORS)} indeterminate vectors + INDEX.md")
    print(f"    test pub {SUB_PUB.hex()[:16]}... keyid {SUB_KEYID[:16]}...")


if __name__ == "__main__":
    main()
