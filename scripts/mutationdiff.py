#!/usr/bin/env python3
"""The one-mutation relation: what a reject vector differs from its parent by.

Every reject vector in this corpus declares a parent, and both indexes and the
accept-anchor gate's own docstring describe it as "a fully valid parent
statement plus exactly one mutation". That was a statement about shape. Nothing
compared the bytes, and under the gap the relation rotted: `vate-1a` differed
from `vate-1d` in eleven leaves, `vate-1c` from `ok-002` in twelve, `vate-3a`
in eleven, and no reject vector in the corpus except one was within one leaf of
the accept vector it named. This module is the arithmetic that makes the
sentence checkable, and `scripts/accept-anchor-gate.py` is what refuses on it.

What is compared, and why it is not the raw JSON
------------------------------------------------
A statement carries signatures over its own record payloads, a Merkle root over
those records, and several digests over material the statement also carries in
full. Move one member and all of them move with it. Counted naively, no signed
artifact can ever differ from another in one leaf, and the count would measure
how much machinery a field sits under rather than how many decisions a vector's
author made.

So the comparison is over the SEMANTIC PRE-IMAGE: the statement with each
derived field replaced by a token, and record payloads decoded from base64 so
that the members inside them are leaves rather than one opaque blob. The
derived fields are

    predicate.batchRoot                              (RFC 6962 over the records)
    each record's signatures                         (Ed25519 over its PAE)
    aeeRunBinding inside each record payload         (over the environment)
    aeeObservedSet inside each sealed payload        (over the record set)
    aeePostureDigest inside each run-level payload   (a copy of the carried one)
    observationEnvironment.corpus.digest             (over corpus.manifest)
    observationEnvironment.observationVocabulary.digest  (over labels + caught)

and the whole of the care is in the word REPLACED. A derived field collapses to
the token only when its value equals what its own derivation recomputes over
the statement it sits in. A field that has been set to something the derivation
does not produce is not derived any more -- it is a value somebody chose, which
is exactly what a mutation is -- so it stays and it counts. That is what keeps
this from being a blanket exclusion: `bad-401`, whose declared fault IS a
tampered batch root, and `bad-301`, whose fault IS a spliced run binding, each
still measure as one mutation, and they measure it AT the field they mutated.

The rule reads in one line: a derived field that agrees with its own derivation
changed because the mutation changed, and a derived field that disagrees is the
mutation.

Two consequences worth stating rather than leaving to be rediscovered.

A statement with no `runEntropy` has no derivable binding at all, so records in
an artifact-only statement keep whatever binding they carry verbatim. That is
correct and costs nothing: parent and child carry the same literal, so the leaf
does not differ.

A record whose payload does not decode -- deliberately, in the family of
vectors whose fault is the encoding -- cannot have its members read. Its
payload is compared as one leaf carrying the undecodable bytes, so the vector
measures as one mutation at the payload, which is what it is.

Leaf paths
----------
A leaf is a scalar at a JSON path (`predicate.attackResults[0].basis`). Empty
containers are leaves too, spelled `{}` and `[]`, because a member emptied and
a member removed are different edits and a diff that cannot see the first would
report a vector as unchanged. A path present on one side and absent on the
other counts once.
"""

from __future__ import annotations

import base64
import binascii
import copy
import difflib
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# The token a self-consistent derived field collapses to. It is spelled with
# characters no digest and no vocabulary member can contain, so it can never
# collide with a value a vector legitimately carries.
DERIVED = "<derived>"

# The leaf a uniformly carried run binding is hoisted to.
CARRIED_BINDING = "<carried-run-binding>"

_UNDECODABLE = "payload bytes are not the canonical form of what they encode"


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON over the value space this suite uses."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs_digest(obj: Any) -> str | None:
    """The JCS digest of a value, or None when the value has no canonical form.

    Several vectors carry a lone surrogate or a non-character on purpose, and a
    value that cannot be canonicalized has no derivation to agree with. None
    means the field is left verbatim rather than collapsed -- which is right:
    an uncanonicalizable environment is not one whose digests can be said to
    follow from it.
    """
    try:
        return sha256_hex(jcs(obj))
    except (UnicodeEncodeError, ValueError, TypeError):
        return None


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE PAEv1 over (payloadType, payload)."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def strict_b64(value: Any) -> bytes | None:
    """The bytes a canonical base64 string carries, or None.

    Strict on purpose: a payload that decodes only under a lenient decoder is
    one of this corpus's declared faults, and treating it as decodable would
    let the projection read members out of a record a conforming verifier
    refuses to read at all.
    """
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    if base64.standard_b64encode(raw).decode() != value:
        return None
    return raw


def record_leaf(record: dict[str, Any]) -> bytes | None:
    raw = strict_b64(record.get("payload"))
    ptype = record.get("payloadType")
    if raw is None or not isinstance(ptype, str):
        return None
    return hashlib.sha256(b"\x00" + pae(ptype, raw)).digest()


def merkle_root(records: list[Any]) -> str | None:
    """RFC 6962 over the carried records, or None when one cannot be hashed."""
    leaves: list[bytes] = []
    for r in records:
        if not isinstance(r, dict):
            return None
        leaf = record_leaf(r)
        if leaf is None:
            return None
        leaves.append(leaf)
    if not leaves:
        return None

    def node(entries: list[bytes]) -> bytes:
        if len(entries) == 1:
            return entries[0]
        k = 1
        while k * 2 < len(entries):
            k *= 2
        return hashlib.sha256(b"\x01" + node(entries[:k])
                              + node(entries[k:])).digest()

    return node(leaves).hex()


def decode_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    """The object a record's payload encodes, or None."""
    raw = strict_b64(record.get("payload"))
    if raw is None:
        return None
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def canonical_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    """The object a record's payload encodes, IF its bytes are canonical.

    A payload whose bytes are not the RFC 8785 form of what they parse to is
    read as opaque. Several vectors carry exactly that -- members out of order,
    a member spelled twice, an encoding a strict decoder refuses -- and each
    fault lives in the bytes rather than in the parse. Parsing them anyway
    silently repaired the mutation: three vectors measured as ZERO differences
    from the accept vector they were derived from, which is a reject vector
    reporting itself identical to a statement a verifier must accept.
    """
    obj = decode_payload(record)
    if obj is None:
        return None
    raw = strict_b64(record.get("payload"))
    canonical = None
    try:
        canonical = jcs(obj)
    except (UnicodeEncodeError, ValueError, TypeError):
        return None
    return obj if raw == canonical else None


def observed_set_digest(records: list[Any]) -> str | None:
    """The value a seal's aeeObservedSet commits to over these records."""
    leaves = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        obj = decode_payload(r)
        if obj is None or obj.get("aeeKind") not in ("interception",
                                                     "examination"):
            continue
        leaf = record_leaf(r)
        if leaf is not None:
            leaves.add(leaf.hex())
    return jcs_digest(sorted(leaves))


def derived_binding(env: Any, subject_sha: Any, version: Any) -> str | None:
    """The run binding this environment and subject derive, or None.

    Version 2 is the implemented construction. Version 1 is derivable too
    because one vector's declared fault is a statement minted under the retired
    one, and that vector's binding must be recognised as derived-under-1 rather
    than counted as a hand-set value: it is one mutation at the version member,
    not two.
    """
    if not isinstance(env, dict) or not isinstance(subject_sha, str):
        return None
    if version not in ("1", "2"):
        return None
    try:
        pre = {
            "aeeBindingVersion": version,
            "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
            "corpus": env["corpus"]["digest"]["sha256"],
            "runEntropy": env["runEntropy"]["digest"]["sha256"],
            "subject": subject_sha,
            "substrate": env["substrate"]["digest"]["sha256"],
        }
        if version == "1":
            pre["networkPosture"] = env["networkPosture"]["digest"]["sha256"]
        else:
            pre["networkPosture"] = jcs_digest(env["networkPosture"])
            pre["observationVocabulary"] = (
                env["observationVocabulary"]["digest"]["sha256"])
    except (KeyError, TypeError):
        return None
    return jcs_digest(pre)


def suite_public_keys() -> dict[str, bytes]:
    """The three test keys, re-derived from the published recipe.

    `vectors/keys/README.md` publishes seed(role) = SHA-256 of
    "in-toto-aee-test-key/<role>/v1" and no private material, so this is a
    re-derivation and not a copy: a key typed here could go stale against the
    generators, and a key that has gone stale would report every signature as
    somebody else's and every re-signed record as a mutation.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    keys = {}
    for role in ("substrate-observation-test", "wrong-signer-test",
                 "statement-test"):
        seed = hashlib.sha256(
            f"in-toto-aee-test-key/{role}/v1".encode()).digest()
        keys[role] = Ed25519PrivateKey.from_private_bytes(
            seed).public_key().public_bytes_raw()
    return keys


# The order the carried result takes its minimum over.
_RESULT_ORDER = {"fail": 0, "degraded": 1, "pass_indirect": 2, "pass": 3}


def recomputed_result(pred: Any) -> str | None:  # noqa: C901 -- mirrors the specification's own recompute; see docs/complexity-rationales.toml
    """The result these rows and this coverage force, or None if unreadable.

    `predicate.result` is not an independent member: the specification defines
    it as the minimum of three conditions over the rows the statement carries
    and the coverage it declares. A mutation to a row or to a class in scope
    therefore MOVES the result, and counting that as a second mutation would
    make every coverage vector read as two.

    It stays comparable where it matters, because the collapse is pairwise: the
    family of vectors whose declared fault IS a result the rows do not support
    carry a value this function does not produce, so nothing collapses and the
    difference is visible at `predicate.result`, which is where it belongs.
    """
    if not isinstance(pred, dict):
        return None
    rows = pred.get("attackResults")
    env = pred.get("observationEnvironment")
    coverage = pred.get("coverage")
    if not isinstance(rows, list) or not isinstance(env, dict) \
            or not isinstance(coverage, dict):
        return None
    vocab = env.get("observationVocabulary")
    if not isinstance(vocab, dict):
        return None
    labels, caught = vocab.get("labels"), vocab.get("caught")
    if not isinstance(labels, list) or not isinstance(caught, list):
        return None
    label_set, caught_set = set(labels), set(caught)
    forced_fail = False
    indirect = False
    for row in rows:
        if not isinstance(row, dict):
            return None
        observed = row.get("containmentObserved")
        if observed in caught_set or observed not in label_set:
            forced_fail = True
        elif row.get("basis") not in ("substrate", "artifact"):
            forced_fail = True
        elif row.get("method") not in ("intercepted", "reconstructed"):
            forced_fail = True
        elif row.get("attribution") not in ("pinned", "paired"):
            forced_fail = True
        elif row.get("basis") != "substrate" or row.get("method") != "intercepted":
            indirect = True
    degraded = bool(coverage.get("outOfScope") or coverage.get("routedElsewhere"))
    candidates = ["fail" if forced_fail else "pass",
                  "degraded" if degraded else "pass",
                  "pass_indirect" if indirect else "pass"]
    return min(candidates, key=_RESULT_ORDER.__getitem__)


def signature_descriptor(record: dict[str, Any],
                         public_keys: dict[str, bytes]) -> str | None:
    """One leaf describing WHO signed this record, HOW, and under what keyid.

    A record's signature block is one decision, not three, and the three parts
    move together. Signing with a different key changes the keyid and the
    signature bytes; signing the bare payload instead of its PAE changes only
    the bytes. Compared member by member, the first would count as two
    mutations and the second as one, which measures the encoding of a choice
    rather than the choice. So the whole `signatures` value collapses to one
    leaf carrying the keyid as written, the role whose key actually produced
    the signature, and the pre-image it was produced over.

    The signature BYTES never survive into the comparison, and that is the
    point: a re-signed record is what every mutation to a payload produces, and
    counting it would make one mutation read as three. A signature no suite key
    accounts for is described as unverifiable rather than dropped, so a
    tampered signature still differs from the parent's real one.

    Returns None when the block is not a list of signature entries at all, in
    which case the caller leaves it verbatim: the shape itself is the mutation.
    """
    sigs = record.get("signatures")
    if not isinstance(sigs, list):
        return None
    raw = strict_b64(record.get("payload"))
    ptype = record.get("payloadType")
    parts = []
    for entry in sigs:
        if not isinstance(entry, dict):
            return None
        keyid = entry.get("keyid", "<absent>")
        sig = strict_b64(entry.get("sig"))
        signer = "unverifiable"
        if sig is not None and raw is not None and isinstance(ptype, str):
            for role, pub in public_keys.items():
                key = Ed25519PublicKey.from_public_bytes(pub)
                for mode, message in (("pae", pae(ptype, raw)), ("raw", raw)):
                    try:
                        key.verify(sig, message)
                    except InvalidSignature:
                        continue
                    signer = f"{role}/{mode}"
                    break
                if signer != "unverifiable":
                    break
        extra = sorted(set(entry) - {"keyid", "sig"})
        parts.append(f"keyid={keyid},signer={signer}"
                     + (f",extra={extra}" if extra else ""))
    return f"{DERIVED}:signatures[{'; '.join(parts)}]"


def _derived_marks(  # noqa: C901 -- one guarded branch per derived field; see docs/complexity-rationales.toml
        statement: Any, public_keys: dict[str, bytes]) -> dict[str, Any]:
    """Which derived fields of this statement agree with their own derivation.

    Returned as a flat map from a marker key to True/False, computed from the
    statement AS GIVEN so that no collapse can feed another: an environment
    whose corpus digest had already been replaced would derive a different run
    binding, and the records would then read as hand-set.
    """
    marks: dict[str, Any] = {}
    if not isinstance(statement, dict):
        return marks
    pred = statement.get("predicate")
    if not isinstance(pred, dict):
        return marks
    env = pred.get("observationEnvironment")
    records = pred.get("observationRecords")

    recomputed = recomputed_result(pred)
    marks["result"] = recomputed is not None and pred.get("result") == recomputed

    subject_sha: Any = None
    subject = statement.get("subject")
    if isinstance(subject, list) and subject and isinstance(subject[0], dict):
        digest = subject[0].get("digest")
        if isinstance(digest, dict):
            subject_sha = digest.get("sha256")

    if isinstance(env, dict):
        corpus = env.get("corpus")
        if isinstance(corpus, dict) and isinstance(corpus.get("digest"), dict) \
                and "manifest" in corpus:
            derived = jcs_digest(corpus["manifest"])
            marks["corpus-digest"] = (
                derived is not None
                and corpus["digest"].get("sha256") == derived)
        vocab = env.get("observationVocabulary")
        if isinstance(vocab, dict) and isinstance(vocab.get("digest"), dict) \
                and "labels" in vocab and "caught" in vocab:
            derived = jcs_digest(
                {"caught": vocab["caught"], "labels": vocab["labels"]})
            marks["vocabulary-digest"] = (
                derived is not None
                and vocab["digest"].get("sha256") == derived)

    if not isinstance(records, list) or not records:
        return marks

    root = merkle_root(records)
    marks["batch-root"] = root is not None and pred.get("batchRoot") == root
    observed = observed_set_digest(records)
    binding = derived_binding(env, subject_sha, "2")
    posture_digest: Any = None
    if isinstance(env, dict):
        posture = env.get("networkPosture")
        if isinstance(posture, dict) and isinstance(posture.get("digest"), dict):
            posture_digest = posture["digest"].get("sha256")

    carried = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        payload = canonical_payload(record)
        if payload is not None and "aeeRunBinding" in payload:
            carried.add(str(payload["aeeRunBinding"]))
    marks["uniform-binding"] = (
        next(iter(carried)) if len(carried) == 1 else None)
    marks["uniform-binding-derived"] = (
        len(carried) == 1 and binding is not None
        and next(iter(carried)) == binding)

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        marks[f"signature/{index}"] = signature_descriptor(record, public_keys)
        payload = canonical_payload(record)
        if payload is None:
            continue
        if "aeeRunBinding" in payload:
            marks[f"binding/{index}"] = (
                binding is not None and payload["aeeRunBinding"] == binding)
        if "aeeObservedSet" in payload:
            marks[f"observed-set/{index}"] = (
                observed is not None and payload["aeeObservedSet"] == observed)
        if "aeePostureDigest" in payload and posture_digest is not None:
            marks[f"posture-digest/{index}"] = (
                payload["aeePostureDigest"] == posture_digest)
    return marks


def semantic_preimage(  # noqa: C901 -- one guarded branch per derived field; see docs/complexity-rationales.toml
        statement: Any, public_keys: dict[str, bytes],
        collapse: dict[str, Any] | None = None) -> Any:
    """The statement with the agreed derived fields replaced by a token.

    `collapse` names which markers may be replaced, and it is computed for the
    PAIR rather than for one statement, because collapsing per-statement can
    manufacture a difference between two values that are byte-identical. It
    did: `vate-1a` is `vate-1d` with the subject digest moved and every record
    left exactly as the producer signed it, so the parent's run binding derives
    and the child's does not, and a per-statement projection replaced the
    parent's binding with a token while leaving the child's literal -- turning
    two identical strings into two differences and reporting a one-mutation
    control as three.

    The rule is therefore: a derived field collapses only where BOTH sides
    agree with their own derivation. Where either side disagrees, both are
    compared as written, so the mutation is visible exactly once and an
    unchanged field stays unchanged.
    """
    if not isinstance(statement, dict):
        return statement
    allow = collapse if collapse is not None else {}
    out = copy.deepcopy(statement)
    pred = out.get("predicate")
    if not isinstance(pred, dict):
        return out
    env = pred.get("observationEnvironment")
    records = pred.get("observationRecords")

    if allow.get("result"):
        pred["result"] = DERIVED

    if isinstance(env, dict):
        corpus = env.get("corpus")
        if allow.get("corpus-digest") and isinstance(corpus, dict) \
                and isinstance(corpus.get("digest"), dict):
            corpus["digest"]["sha256"] = DERIVED
        vocab = env.get("observationVocabulary")
        if allow.get("vocabulary-digest") and isinstance(vocab, dict) \
                and isinstance(vocab.get("digest"), dict):
            vocab["digest"]["sha256"] = DERIVED

    if not isinstance(records, list) or not records:
        return out

    uniform = {str(payload["aeeRunBinding"])
               for payload in (canonical_payload(r) for r in records
                               if isinstance(r, dict))
               if payload is not None and "aeeRunBinding" in payload}
    if allow.get("uniform-binding") and len(uniform) == 1:
        # Every record carries one copy of one run-level value. Replacing a
        # binding the statement does not derive moves every copy, and counting
        # the copies would report one decision as three on a three-record
        # statement. Hoisted to a single leaf, so the change is counted where
        # it was made; a statement whose records DISAGREE about the binding is
        # not hoisted, and there the per-record difference is the mutation.
        pred[CARRIED_BINDING] = (DERIVED if allow.get("uniform-binding-derived")
                                 else next(iter(uniform)))

    if allow.get("batch-root"):
        pred["batchRoot"] = DERIVED

    projected: list[Any] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            projected.append(record)
            continue
        record = dict(record)
        token = allow.get(f"signature/{index}")
        if token is not None and signature_descriptor(record,
                                                      public_keys) is not None:
            record["signatures"] = token
        payload = canonical_payload(record)
        if payload is None:
            # Left as the base64 string it is. A record whose bytes are not the
            # canonical form of what they encode has no member structure a
            # conforming verifier will read -- that is the declared fault of a
            # whole family here -- and decoding it anyway would erase the very
            # difference the vector exists to carry.
            raw = record.get("payload")
            record["payload"] = (
                f"<{_UNDECODABLE}, sha256 "
                f"{sha256_hex(raw.encode() if isinstance(raw, str) else b'')}>")
        else:
            payload = dict(payload)
            if CARRIED_BINDING in pred and "aeeRunBinding" in payload:
                payload["aeeRunBinding"] = CARRIED_BINDING
            for key, marker in (("aeeRunBinding", "binding"),
                                ("aeeObservedSet", "observed-set"),
                                ("aeePostureDigest", "posture-digest")):
                if key in payload and allow.get(f"{marker}/{index}"):
                    payload[key] = DERIVED
            record["payload"] = payload
        projected.append(record)
    pred["observationRecords"] = projected
    return out


def agreed(parent_marks: dict[str, Any],
           child_marks: dict[str, Any]) -> dict[str, Any]:
    """The markers both statements agree on, and may therefore collapse.

    A marker present on only ONE side belongs to a record the other statement
    does not carry. There is nothing for it to disagree with, and the record
    itself is already counted once as an addition, so it collapses on its own
    reading: leaving it alone instead made every vector that appends a record
    report one extra difference at the hoisted binding.
    """
    allow: dict[str, Any] = {}
    for key in set(parent_marks) | set(child_marks):
        mine = parent_marks.get(key)
        theirs = child_marks.get(key)
        if key == "uniform-binding":
            # Gate only: BOTH sides must carry one binding across every record
            # for the hoist to be sound. The VALUE hoisted is each statement's
            # own, never the other's -- writing the parent's value on both
            # sides made two vectors whose whole fault is a moved binding
            # measure as zero mutations from a statement a verifier accepts.
            if isinstance(mine, str) and isinstance(theirs, str):
                allow[key] = True
            continue
        if key.startswith("signature/"):
            # The signature descriptor is not a yes/no: it names the signer,
            # the pre-image and the keyid. Two records collapse to the same
            # token when those agree, and to different tokens otherwise, so the
            # comparison happens between the descriptions rather than between
            # signature bytes that move whenever the payload does.
            if key not in parent_marks:
                allow[key] = theirs
            elif key not in child_marks:
                allow[key] = mine
            elif mine is not None and theirs is not None:
                allow[key] = mine if mine == theirs else None
            else:
                # One of the two records has no readable signature block at
                # all -- `signatures` is not an array of entries. That is the
                # mutation, so neither side collapses and the member is
                # compared as written. Collapsing the malformed side onto the
                # healthy side's description erased it: a vector whose whole
                # fault is a signatures member of the wrong type measured as
                # ZERO mutations from the vector it was derived from.
                allow[key] = None
            continue
        if key not in parent_marks:
            allow[key] = theirs is True
        elif key not in child_marks:
            allow[key] = mine is True
        else:
            allow[key] = mine is True and theirs is True
    return allow


def _canonical(value: Any) -> str:
    """A comparable spelling of a value, for aligning list elements."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    except (TypeError, ValueError):
        return repr(value)


def _walk(before: Any, after: Any, path: str,  # noqa: C901 -- type dispatch over a JSON tree; see docs/complexity-rationales.toml
          out: list[str]) -> None:
    """Append the paths at which `after` differs from `before`.

    A whole subtree that appears on one side and not the other is ONE entry, at
    the path where it appears. That is the difference between counting edits
    and counting bytes: appending an unreferenced record to a statement is one
    decision by the vector's author, and eleven leaves inside a payload the
    parent never carried are that one decision seen from underneath. The
    corpus has a family of vectors that add exactly one record, and counted
    leaf by leaf every one of them measured as a dozen mutations.
    """
    if isinstance(before, dict) and isinstance(after, dict):
        removed = [k for k in sorted(before) if k not in after]
        added = [k for k in sorted(after) if k not in before]
        if len(removed) == 1 and len(added) == 1 \
                and _canonical(before[removed[0]]) == _canonical(after[added[0]]):
            # One member gone and one arrived carrying the same value: the
            # member was renamed, which is one edit. Counted as two, every
            # vector that moves a value to a different key -- a digest from
            # `sha256` to `sha512`, say -- would read as two mutations.
            out.append(f"{path}.{removed[0]} -> {added[0]}" if path
                       else f"{removed[0]} -> {added[0]}")
            removed, added = [], []
        for key in removed + added:
            out.append(f"{path}.{key}" if path else str(key))
        for key in sorted(set(before) & set(after)):
            _walk(before[key], after[key],
                  f"{path}.{key}" if path else str(key), out)
        return
    if isinstance(before, list) and isinstance(after, list):
        if len(before) == len(after) and before != after \
                and sorted(_canonical(v) for v in before) \
                == sorted(_canonical(v) for v in after):
            # The same elements in a different order. One edit: a vector whose
            # declared fault is that an array the specification requires sorted
            # is not sorted has permuted it, and pairing the elements off would
            # count the permutation once per element that moved.
            out.append(f"{path} (reordered)")
            return
        matcher = difflib.SequenceMatcher(
            None, [_canonical(v) for v in before],
            [_canonical(v) for v in after], autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            # An element present on both sides of a replaced span is one
            # element that changed; the surplus on either side is an element
            # added or removed, and each of those is one entry.
            paired = min(i2 - i1, j2 - j1)
            for offset in range(paired):
                _walk(before[i1 + offset], after[j1 + offset],
                      f"{path}[{j1 + offset}]", out)
            for offset in range(paired, i2 - i1):
                out.append(f"{path}[{i1 + offset}]")
            for offset in range(paired, j2 - j1):
                out.append(f"{path}[{j1 + offset}]")
        return
    if before != after or type(before) is not type(after):
        out.append(path or "<the whole statement>")


SERIALIZATION = "<serialized-bytes>"
_AS_EMITTED = "the canonical serialization of the parsed statement"


def serialization_leaf(raw: bytes | None, parsed: Any) -> str:
    """How this vector's FILE differs from the form its generator emits.

    Some faults live in the bytes and disappear on the way through a parser: a
    statement carrying one member twice parses last-wins, so the object is the
    object its parent has and the vector reads as identical to a statement a
    verifier must accept. Three of those measured as zero mutations before this
    leaf existed.

    The value is the description when the file is what the generator's writer
    produces, and the digest of the bytes otherwise. A digest rather than a
    diff because there is nothing structured to diff: the point is only that
    these bytes are not the ones the parse accounts for, and two vectors that
    differ only below the parser still differ here.
    """
    if raw is None:
        return _AS_EMITTED
    try:
        emitted = (json.dumps(parsed, sort_keys=True, indent=2,
                              ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return f"unserializable, sha256 {sha256_hex(raw)}"
    if raw == emitted:
        return _AS_EMITTED
    return f"hand-written, sha256 {sha256_hex(raw)}"


def mutation_paths(parent: Any, child: Any,
                   public_keys: dict[str, bytes] | None = None,
                   parent_bytes: bytes | None = None,
                   child_bytes: bytes | None = None) -> list[str]:
    """The paths at which the child differs from its parent.

    The returned list IS the set the caller may describe. A refusal that names
    a count it did not compute, or a set it did not walk, is the shape of
    defect this whole module exists to remove, so the count is the length of
    this list and never anything else.

    `parent_bytes` and `child_bytes` are the files as committed. Passing them
    adds the serialization leaf; omitting them compares the parsed statements
    only, which is right for a caller holding objects that were never files.
    """
    if public_keys is None:
        public_keys = suite_public_keys()
    allow = agreed(_derived_marks(parent, public_keys),
                   _derived_marks(child, public_keys))
    before = semantic_preimage(parent, public_keys, allow)
    after = semantic_preimage(child, public_keys, allow)
    if isinstance(before, dict) and isinstance(after, dict):
        before = dict(before)
        after = dict(after)
        before[SERIALIZATION] = serialization_leaf(parent_bytes, parent)
        after[SERIALIZATION] = serialization_leaf(child_bytes, child)
    out: list[str] = []
    _walk(before, after, "", out)
    return out
