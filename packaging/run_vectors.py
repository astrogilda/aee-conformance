#!/usr/bin/env python3
"""Differential conformance harness for the Adversarial Execution Evidence
(AEE) predicate, v0.6.

Predicate type URI:
    https://in-toto.io/attestation/adversarial-execution-evidence/v0.6

This harness loads every conformance vector under ``vectors/`` (a sibling of
this script's parent directory by default) and checks each one against the
suite MANIFEST expectations:

* accept vectors (``accept/ok-*.json``) must be VALID, recompute to the
  expected ``result``, and derive the expected per-row evidence tiers under
  both key policies (with the pinned TEST substrate key, and with no key);
* reject vectors (``reject/bad-*.json``) must be INVALID with a failure code
  drawn from the MANIFEST's ``expected.codes`` set.

Rails
-----
1. EXTERNAL RAIL (optional): pass ``--verifier <path>`` (or set the
   ``AEE_EXTERNAL_VERIFIER`` environment variable) to run every vector
   through an external verifier.  The harness first probes the verifier
   for v0.6 capability by scanning its bytes for the v0.6 predicate type
   URI; a verifier that does not know the v0.6 type is reported and the
   harness falls back to the reference rail, so the suite is verifiable
   standalone.

   External-rail contract (also the Rail-C wire-in contract): the verifier
   is invoked as ``<cmd> <vector-file>``; exit 0 means valid, non-zero
   means invalid; if the LAST stdout line is a JSON object of the shape
   ``{"verdict": "valid"|"invalid", "codes": [...], "result": "...",
   "tiers": [...]}`` the harness additionally checks codes/result/tiers,
   otherwise it checks the verdict only.

2. REFERENCE RAIL (default, self-contained, stdlib-only): an independent
   Python implementation of the spec's checks -- statement well-formedness
   (GATE 0), the byte-checkable per-substrate-row coverage validity gate
   (GATE 1), the pure ``result`` recompute, and the per-row evidence tier
   (GATE 2) -- including RFC 8785 (JCS) canonicalization, RFC 7493
   (I-JSON) payload strictness, DSSE PAEv1, the RFC 6962 domain-separated
   batch root, the versioned run-binding derivation, and pure-Python
   Ed25519 (RFC 8032) for tier signature verification.

The reference rail deliberately emits the SET of every failure it detects;
conformance for a reject vector is ``expected.codes`` intersecting the
emitted set plus verdict equality, so a strict single-code rail and this
superset-emitting rail can both pass the same MANIFEST.

Second-fault-absence self-checks: for every reject vector the harness
additionally asserts that commitments NOT named by the vector's expected
codes still verify (batch root recomputes, vocabulary digest verifies,
corpus digest verifies, record bindings equal the derived binding), which
machine-checks the suite's single-fault discipline.

Outputs a gate-by-vector coverage report: a human table on stdout plus
``conformance-report.json`` (all paths repo-relative).  Exit status: 0 all
checks pass, 1 any check fails, 2 usage or suite-not-found.

TEST KEYS ONLY: the harness re-derives the suite's Ed25519 test keys from
the published recipe ``seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")``.
These keys prove nothing and must never sign real evidence.

Run ``run_vectors.py --self-test`` to exercise the reference rail against
built-in synthetic statements without needing the vector files.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

AEE_PREDICATE_TYPE = (
    "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SAFE_INT_LIMIT = 2 ** 53

KEY_ROLES = ("substrate-observation-test", "wrong-signer-test", "statement-test")
PINNED_ROLE = "substrate-observation-test"

RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# ---------------------------------------------------------------------------
# RFC 8785 (JCS) canonical JSON -- subset sufficient for this suite
# (null / bool / int / str / array / object; non-integer numbers are outside
# the suite's I-JSON profile and are rejected).
# ---------------------------------------------------------------------------


class JcsError(ValueError):
    pass


_JCS_CTRL = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _utf16_sort_key(s: str) -> bytes:
    """UTF-16 code-unit sort key (RFC 8785 section 3.2.3).

    Big-endian UTF-16 bytes compare lexicographically exactly as the 16-bit
    code-unit sequence does, so ``sorted(..., key=_utf16_sort_key)`` is the
    code-unit order the spec pins. This is deliberately NOT plain ``sorted``
    (code-point order): a supplementary-plane string's lead surrogate
    (0xD800..0xDBFF) sorts before a BMP code point in 0xE000..0xFFFF under
    UTF-16 and after it under code points. The BMP-only string profile makes
    that divergence unconstructible in accepted input, so this key is the
    comparator-level pin, shared by member-name canonicalization and the
    vocabulary sortedness check.
    """
    return s.encode("utf-16-be")


def _all_bmp(strings: list[str]) -> bool:
    """True when every code point of every string lies inside the BMP."""
    return all(ord(ch) <= 0xFFFF for s in strings for ch in s)


def _member_names_bmp(v: Any) -> bool:
    """True when every object member name, at any depth, is BMP-only.

    Member values are unconstrained; only the sorted member names participate
    in RFC 8785 member ordering.
    """
    if isinstance(v, dict):
        return all(_all_bmp([k]) and _member_names_bmp(x) for k, x in v.items())
    if isinstance(v, list):
        return all(_member_names_bmp(x) for x in v)
    return True


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(_JCS_CTRL.get(o, f"\\u{o:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs_dumps(obj: Any) -> bytes:
    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            raise JcsError("non-integer number outside the suite I-JSON profile")
        if isinstance(v, str):
            return _jcs_string(v)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=_utf16_sort_key)
            return "{" + ",".join(
                _jcs_string(k) + ":" + ser(v[k]) for k in keys
            ) + "}"
        raise JcsError(f"unsupported type: {type(v)!r}")

    return ser(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# RFC 7493 (I-JSON) strict payload parse: duplicate members and unsafe
# integers rejected.
# ---------------------------------------------------------------------------


class IJsonError(ValueError):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


def _reject_dup_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise IJsonError("payload-not-ijson", f"duplicate member {k!r}")
        d[k] = v
    return d


def _walk_check_ints(v: Any) -> None:
    if isinstance(v, bool):
        return
    if isinstance(v, int):
        if abs(v) >= SAFE_INT_LIMIT:
            raise IJsonError("payload-not-ijson", "integer outside safe range")
    elif isinstance(v, float):
        raise IJsonError("payload-not-ijson", "non-integer number")
    elif isinstance(v, list):
        for x in v:
            _walk_check_ints(x)
    elif isinstance(v, dict):
        for x in v.values():
            _walk_check_ints(x)


# Untrusted-input resource bounds, pinned to match the Go rail (aee/jcs.go
# maxParseDepth / maxParseBytes) so the two independent rails accept and reject
# exactly the same payloads. The depth bound is a cross-rail parity requirement,
# not only a DoS defense: stdlib JSON parser depth defaults diverge across
# languages (Go 10000, CPython ~1000-10000 by platform, serde_json 128), so a
# shared explicit bound is what keeps the rails from splitting on deep input.
MAX_PARSE_DEPTH = 128
MAX_PARSE_BYTES = 20 << 20  # 20 MiB
# Whole-statement bound, matched with the Go rail (aee/types.go maxStatementBytes)
# so the two rails split on the same oversized input; a resource guard, not a
# conformance rule.
MAX_STATEMENT_BYTES = 64 << 20  # 64 MiB


def _max_json_depth(text: str) -> int:
    """Maximum bracket-nesting depth of a JSON text, ignoring string bodies."""
    depth = maxd = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > maxd:
                maxd = depth
        elif ch in "]}":
            depth -= 1
    return maxd


def strict_b64decode(s: str) -> bytes:
    """Decode standard base64, mirroring Go's base64.StdEncoding.Strict()
    (aee/validity.go:108, aee/tier.go:93): reject non-alphabet characters
    (validate=True) AND non-canonical encodings -- trailing bits in the final
    quantum ("QUJ=" decodes to "AB" only under a lenient decoder), non-standard
    padding -- that Python's b64decode would otherwise accept. A payload the Go
    rail rejects as record-undecodable must not decode on the Python rail, or
    the two rails disagree at the encoding layer. Raises binascii.Error /
    ValueError on any rejection, matching the callers' existing except clauses."""
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("non-canonical base64 (fails re-encode round-trip)")
    return raw


def strict_payload_parse(raw: bytes) -> dict[str, Any]:
    """Parse record payload bytes; raise IJsonError with a registry code."""
    if len(raw) > MAX_PARSE_BYTES:
        raise IJsonError("payload-not-canonical", "payload exceeds the maximum size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise IJsonError("payload-not-canonical", "payload is not UTF-8") from None
    if _max_json_depth(text) > MAX_PARSE_DEPTH:
        raise IJsonError("payload-not-canonical",
                         "payload nesting exceeds the maximum depth")
    try:
        obj = json.loads(text, object_pairs_hook=_reject_dup_pairs)
    except IJsonError:
        raise
    except (ValueError, RecursionError):
        raise IJsonError("payload-not-canonical", "payload does not parse as JSON") from None
    if not isinstance(obj, dict):
        raise IJsonError("payload-not-canonical", "payload is not a JSON object")
    if not _member_names_bmp(obj):
        # BMP-only string profile: a supplementary-plane member name makes the
        # covering payload cover nothing, the same handling as non-canonical
        # bytes (the payload can be byte-canonical under both member orders
        # when they happen to agree on its names; the name itself is rejected).
        raise IJsonError(
            "payload-not-canonical", "supplementary-plane object member name"
        )
    _walk_check_ints(obj)
    try:
        canon = jcs_dumps(obj)
    except JcsError:
        raise IJsonError("payload-not-ijson", "payload not canonicalizable") from None
    if canon != raw:
        raise IJsonError("payload-not-canonical", "payload bytes are not RFC 8785 canonical")
    return obj


# ---------------------------------------------------------------------------
# DSSE PAEv1 + RFC 6962 Merkle root (domain-separated, recursive split)
# ---------------------------------------------------------------------------


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(pt), pt, len(payload)) + payload


def merkle_root_hex(leaves: list[bytes]) -> str:
    def node(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 1:
            return hashlib.sha256(b"\x00" + leaves[lo]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(
            b"\x01" + node(lo, lo + k) + node(lo + k, hi)
        ).digest()

    if not leaves:
        raise ValueError("empty leaf set has no root")
    return node(0, len(leaves)).hex()


# ---------------------------------------------------------------------------
# Pure-Python Ed25519 (RFC 8032).  Slow but dependency-free and sufficient
# for a conformance suite; TEST keys only.
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


# Points are extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z.
_Point = tuple[int, int, int, int]
_IDENT: _Point = (0, 1, 1, 0)


def _pt_add(p: _Point, q: _Point) -> _Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _pt_mul(s: int, p: _Point) -> _Point:
    q = _IDENT
    while s > 0:
        if s & 1:
            q = _pt_add(q, p)
        p = _pt_add(p, p)
        s >>= 1
    return q


def _pt_eq(p: _Point, q: _Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


_BY = 4 * _inv(5) % _P


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _pt_compress(p: _Point) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _pt_decompress(s: bytes) -> _Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def ed25519_public_key(seed: bytes) -> bytes:
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _pt_compress(_pt_mul(a, _B))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _pt_compress(_pt_mul(a, _B))
    r = int.from_bytes(_sha512(prefix, msg), "little") % _L
    rp = _pt_compress(_pt_mul(r, _B))
    k = int.from_bytes(_sha512(rp, pub, msg), "little") % _L
    s = (r + k * a) % _L
    return rp + s.to_bytes(32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    a = _pt_decompress(pub)
    if a is None:
        return False
    rp = _pt_decompress(sig[:32])
    if rp is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(sig[:32], pub, msg), "little") % _L
    return _pt_eq(_pt_mul(s, _B), _pt_add(rp, _pt_mul(k, a)))


def derive_test_keys() -> dict[str, dict[str, Any]]:
    """Re-derive the suite's TEST keys from the published recipe."""
    keys = {}
    for role in KEY_ROLES:
        seed = hashlib.sha256(
            (f"in-toto-aee-test-key/{role}/v1").encode()
        ).digest()
        pub = ed25519_public_key(seed)
        keys[role] = {
            "seed": seed,
            "public": pub,
            "keyid": sha256_hex(pub),
        }
    return keys


# ---------------------------------------------------------------------------
# Reference verifier (Rail R): GATE 0 -> GATE 1 -> recompute -> tier
# ---------------------------------------------------------------------------


class Outcome:
    def __init__(self) -> None:
        self.codes: list[str] = []
        self.result: str | None = None
        self.tiers_with_key: list[str] | None = None
        self.tiers_without_key: list[str] | None = None

    @property
    def verdict(self) -> str:
        return "invalid" if self.codes else "valid"

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)


def _is_hex64_lower(v: Any) -> bool:
    return isinstance(v, str) and bool(HEX64_RE.match(v))


def _digest_of(obj: Any) -> Any:
    if isinstance(obj, dict):
        d = obj.get("digest")
        if isinstance(d, dict):
            return d.get("sha256")
    return None


def _rfc3339_ok(v: Any) -> bool:
    return isinstance(v, str) and bool(RFC3339_RE.match(v))


def _rfc3339_key(v: str) -> datetime | None:
    """Comparable key for RFC 3339 instants (suite uses UTC 'Z' timestamps)."""
    s = v.strip()
    if s.endswith(("z", "Z")):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


METHOD_ORDER = {"reconstructed": 0, "intercepted": 1}


class RecordView:
    """A decoded observation record: PAE bytes always; payload object only
    when it passes the strict parse."""

    def __init__(self, idx: int, rec: Any):
        self.idx = idx
        self.raw = rec
        self.payload_type = rec.get("payloadType") if isinstance(rec, dict) else None
        self.payload_bytes: bytes | None = None
        self.pae: bytes | None = None
        self.payload: dict[str, Any] | None = None
        self.payload_error: str | None = None
        self.decode_err: bool = False
        if isinstance(rec, dict) and isinstance(rec.get("payload"), str):
            try:
                self.payload_bytes = strict_b64decode(rec["payload"])
            except (binascii.Error, ValueError):
                self.payload_bytes = None
                self.decode_err = True
        if self.payload_bytes is not None and isinstance(self.payload_type, str):
            self.pae = pae(self.payload_type, self.payload_bytes)
        if self.payload_bytes is not None:
            try:
                self.payload = strict_payload_parse(self.payload_bytes)
            except IJsonError as e:
                self.payload_error = e.code
        media_ok = isinstance(self.payload_type, str) and self.payload_type.endswith(
            "+json"
        )
        self.media_ok = media_ok

    @property
    def kind(self) -> Any:
        return self.payload.get("aeeKind") if self.payload else None

    @property
    def method(self) -> Any:
        return self.payload.get("aeeMethod") if self.payload else None


@dataclass
class _VerifyState:
    """Mutable holder for the locals shared across ``verify``'s ordered checks.

    Each ``_check_*`` method reads and writes these fields and appends codes to
    the ``Outcome``; the field types mirror the loosely-typed originals.
    """

    stmt: Any
    pred: Any = None
    result: Any = None
    issued_at: Any = None
    env: dict[str, Any] = field(default_factory=dict)
    vocab: dict[str, Any] | None = None
    labels: list[Any] | None = None
    caught: list[Any] | None = None
    corpus: Any = None
    manifest_classes: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = field(default_factory=list)
    has_substrate: bool = False
    coverage: Any = None
    fail_closed_rows: set[int] = field(default_factory=set)
    has_records: bool = False
    views: list[RecordView] = field(default_factory=list)
    derived_binding: str | None = None
    pinned_posture: Any = None
    row_covering: dict[int, list[RecordView]] = field(default_factory=dict)


class ReferenceVerifier:
    def __init__(self, pinned_pubs: list[bytes]):
        self.pinned_pubs = pinned_pubs

    # -- record cover validity -------------------------------------------

    def _arming_ok(self, rv: RecordView, pinned_posture: Any, issued_at: Any) -> bool:
        p = rv.payload or {}
        armed = p.get("armedAt")
        if not _rfc3339_ok(armed):
            return False
        if _rfc3339_ok(issued_at):
            # armed/issued_at each passed _rfc3339_ok above, so both are
            # strings here; an absent/None timestamp yields a None key and is
            # skipped for ordering exactly as a malformed one is (never crash,
            # never silently accept -- absence was already rejected above).
            a = _rfc3339_key(armed) if isinstance(armed, str) else None
            b = _rfc3339_key(issued_at) if isinstance(issued_at, str) else None
            if a is not None and b is not None and a > b:
                return False
        if p.get("aeePostureDigest") != pinned_posture:
            return False
        if p.get("aeeMethod") != "intercepted":
            return False
        if not self._arming_chain_ok(p):
            return False
        return True

    @staticmethod
    def _arming_chain_ok(p: dict[str, Any]) -> bool:
        """Syntax of the optional run-chaining members an arming payload MAY
        carry (aeeRunSeq / aeePrevRunBinding / aeeChainScope): aeeRunSeq is a
        positive safe-range integer; aeeChainScope is a string, required
        whenever aeeRunSeq is present; aeePrevRunBinding is a lowercase
        64-hex string, present exactly when aeeRunSeq is greater than 1. A
        chain member present without aeeRunSeq is rejected fail-closed.
        Syntax-checked here in the reserved-member walk; nothing else
        normative reads the members."""
        has_seq = "aeeRunSeq" in p
        has_prev = "aeePrevRunBinding" in p
        has_scope = "aeeChainScope" in p
        if not has_seq:
            return not has_prev and not has_scope
        seq = p.get("aeeRunSeq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            return False
        if not isinstance(p.get("aeeChainScope"), str):
            return False
        if seq == 1:
            return not has_prev
        prev = p.get("aeePrevRunBinding")
        return isinstance(prev, str) and bool(HEX64_RE.match(prev))

    def _sealed_ok(self, rv: RecordView, pinned_posture: Any) -> bool:
        p = rv.payload or {}
        if p.get("aeeStillArmed") is not True:
            return False
        drops = p.get("aeeDropCount")
        if not isinstance(drops, int) or isinstance(drops, bool) or drops < 0:
            return False
        if drops > 0:
            bound = p.get("aeeDropBound")
            if not isinstance(bound, int) or isinstance(bound, bool):
                return False
            if drops > bound:
                return False
        if p.get("aeePostureDigest") != pinned_posture:
            return False
        if p.get("aeeMethod") != "intercepted":
            return False
        return True

    def _examination_ok(self, rv: RecordView) -> bool:
        return (rv.payload or {}).get("aeeMethod") == "reconstructed"

    def _record_verifies(self, rv: RecordView) -> bool:
        if rv.pae is None or not isinstance(rv.raw, dict):
            return False
        sigs = rv.raw.get("signatures")
        if not isinstance(sigs, list):
            return False
        for sig in sigs:
            if not isinstance(sig, dict) or not isinstance(sig.get("sig"), str):
                continue
            try:
                sig_bytes = strict_b64decode(sig["sig"])
            except (binascii.Error, ValueError):
                continue
            for pub in self.pinned_pubs:
                if ed25519_verify(pub, rv.pae, sig_bytes):
                    return True
        return False

    # -- main entry -------------------------------------------------------

    def verify(self, stmt: Any) -> Outcome:
        out = Outcome()
        st = _VerifyState(stmt=stmt)
        if self._check_statement_type(st, out):
            return out
        self._check_gate0_wellformed(st, out)
        self._check_vocabulary(st, out)
        self._check_corpus(st, out)
        self._check_rows_setup(st, out)
        self._check_coverage(st, out)
        self._check_per_row_statements(st, out)
        self._check_substrate_binding_inputs(st, out)
        self._check_fail_closed_rows(st, out)
        self._check_records(st, out)
        self._check_run_binding(st, out)
        self._check_gate1_coverage(st, out)
        self._check_result_recompute(st, out)
        if out.codes:
            return out  # invalid: no result, no tiers (behavior assertion 2)
        self._check_gate2_tiers(st, out)
        return out

    def _check_statement_type(self, st: _VerifyState, out: Outcome) -> bool:
        stmt = st.stmt
        if not isinstance(stmt, dict):
            out.add("statement-type-unsupported")
            return True

        if stmt.get("_type") != STATEMENT_TYPE:
            out.add("statement-type-unsupported")
        if stmt.get("predicateType") != AEE_PREDICATE_TYPE:
            out.add("predicate-type-unsupported")

        pred = stmt.get("predicate")
        if not isinstance(pred, dict):
            out.add("predicate-type-unsupported")
            return True
        st.pred = pred
        return False

    # ---- GATE 0: statement well-formedness ------------------------------

    def _check_gate0_wellformed(self, st: _VerifyState, out: Outcome) -> None:
        pred = st.pred
        if "does_not_assert" in pred:
            out.add("member-spelling")

        result = pred.get("result")
        if result not in ("pass", "degraded", "fail"):
            out.add("result-vocabulary")
        st.result = result

        issued_at = pred.get("issuedAt")
        if issued_at is None:
            out.add("issued-at-missing")
        elif not _rfc3339_ok(issued_at):
            out.add("issued-at-malformed")
        st.issued_at = issued_at

        env = pred.get("observationEnvironment")
        env = env if isinstance(env, dict) else {}
        for member in ("substrate", "corpus", "catchPolicy", "networkPosture"):
            if member not in env:
                out.add("environment-incomplete")
        st.env = env
        vocab = env.get("observationVocabulary")
        if not isinstance(vocab, dict):
            out.add("vocabulary-missing")
            vocab = None
        st.vocab = vocab

    def _check_vocabulary(self, st: _VerifyState, out: Outcome) -> None:
        vocab = st.vocab
        labels: list[Any] | None = None
        caught: list[Any] | None = None
        if vocab is not None:
            labels = vocab.get("labels")
            caught = vocab.get("caught")
            if not self._vocab_shape_ok(labels, caught):
                out.add("vocabulary-not-canonical")
            self._vocab_check_pairs(out, vocab, labels, caught)
            if not isinstance(labels, list) or not isinstance(caught, list):
                labels, caught = None, None
        st.labels = labels
        st.caught = caught

    @staticmethod
    def _vocab_shape_ok(labels: Any, caught: Any) -> bool:
        for arr in (labels, caught):
            if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
                return False
            # Sortedness is by UTF-16 code unit (RFC 8785 section 3.2.3), the
            # same comparator member-name canonicalization uses, and every
            # entry must be BMP-only: a supplementary-plane vocabulary entry
            # makes the statement malformed, the same handling as
            # non-canonical bytes.
            if sorted(arr, key=_utf16_sort_key) != arr or len(set(arr)) != len(arr):
                return False
            if not _all_bmp(arr):
                return False
        return True

    def _vocab_check_pairs(
        self, out: Outcome, vocab: Any, labels: Any, caught: Any
    ) -> None:
        if not (isinstance(labels, list) and isinstance(caught, list)):
            return
        if not set(caught) <= set(labels):
            out.add("vocabulary-caught-not-subset")
        expect = sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))
        if _digest_of(vocab) != expect:
            out.add("vocabulary-digest-mismatch")

    def _check_corpus(self, st: _VerifyState, out: Outcome) -> None:
        env = st.env
        corpus = env.get("corpus")
        st.corpus = corpus
        manifest_classes: dict[str, Any] | None = None
        if isinstance(corpus, dict):
            manifest = corpus.get("manifest")
            classes = manifest.get("classes") if isinstance(manifest, dict) else None
            if isinstance(manifest, dict):
                self._corpus_digest(out, corpus, manifest)
            if isinstance(classes, dict):
                manifest_classes = classes
                self._corpus_dupes(out, classes)
        st.manifest_classes = manifest_classes

    @staticmethod
    def _corpus_digest(out: Outcome, corpus: Any, manifest: Any) -> None:
        try:
            expect = sha256_hex(jcs_dumps(manifest))
            if _digest_of(corpus) != expect:
                out.add("corpus-digest-mismatch")
        except JcsError:
            out.add("corpus-digest-mismatch")

    @staticmethod
    def _corpus_dupes(out: Outcome, classes: dict[Any, Any]) -> None:
        seen: set[str] = set()
        for ids in classes.values():
            for aid in ids if isinstance(ids, list) else []:
                if aid in seen:
                    out.add("manifest-duplicate-attack")
                seen.add(aid)

    def _check_rows_setup(self, st: _VerifyState, out: Outcome) -> None:
        rows = st.pred.get("attackResults")
        rows = rows if isinstance(rows, list) else []
        rows = [r for r in rows if isinstance(r, dict)]
        st.rows = rows
        st.has_substrate = any(r.get("basis") == "substrate" for r in rows)

    # coverage integrity at attack granularity

    def _check_coverage(self, st: _VerifyState, out: Outcome) -> None:
        coverage = st.pred.get("coverage")
        st.coverage = coverage
        manifest_classes = st.manifest_classes
        if not isinstance(coverage, dict):
            out.add("coverage-missing")
            return
        if manifest_classes is None:
            return
        assessed = coverage.get("assessedClasses")
        assessed = assessed if isinstance(assessed, list) else []
        oos = coverage.get("outOfScope")
        oos = oos if isinstance(oos, dict) else {}
        routed = coverage.get("routedElsewhere")
        routed = routed if isinstance(routed, dict) else {}
        if not self._coverage_partition_ok(manifest_classes, assessed, oos, routed):
            out.add("coverage-incomplete")
        self._coverage_check_rows(st, out, manifest_classes, assessed)

    @staticmethod
    def _coverage_partition_ok(
        manifest_classes: dict[str, Any],
        assessed: list[Any],
        oos: dict[str, Any],
        routed: dict[str, Any],
    ) -> bool:
        # Coverage MUST be an exhaustive, disjoint partition of the
        # manifest's classes across assessedClasses/outOfScope/
        # routedElsewhere, each a real manifest class (spec:360-365,
        # 350-353): without this a whole class is silently dropped from
        # all three sets (or a fabricated class pads assessedClasses).
        acct: dict[str, int] = {}
        for _c in assessed:
            acct[_c] = acct.get(_c, 0) + 1
        for _c in oos:
            acct[_c] = acct.get(_c, 0) + 1
        for _c in routed:
            acct[_c] = acct.get(_c, 0) + 1
        return all(n == 1 and c in manifest_classes for c, n in acct.items()) and all(
            acct.get(c, 0) == 1 for c in manifest_classes
        )

    @staticmethod
    def _coverage_index(
        manifest_classes: dict[str, Any], assessed: list[Any]
    ) -> tuple[dict[Any, Any], set[Any]]:
        attack_class: dict[Any, Any] = {}
        for cls, ids in manifest_classes.items():
            for aid in ids if isinstance(ids, list) else []:
                attack_class.setdefault(aid, cls)
        expected_ids: set[Any] = set()
        for cls in assessed:
            _mc = manifest_classes.get(cls)
            for aid in _mc if isinstance(_mc, list) else []:
                expected_ids.add(aid)
        return attack_class, expected_ids

    def _coverage_check_rows(
        self,
        st: _VerifyState,
        out: Outcome,
        manifest_classes: dict[str, Any],
        assessed: list[Any],
    ) -> None:
        attack_class, expected_ids = self._coverage_index(manifest_classes, assessed)
        row_ids = set()
        for r in st.rows:
            aid = r.get("attackId")
            row_ids.add(aid)
            if aid not in attack_class:
                out.add("row-attack-unknown")
            elif attack_class[aid] not in assessed:
                out.add("coverage-incomplete")
        if expected_ids - {i for i in row_ids if i in attack_class}:
            out.add("coverage-incomplete")

    # per-row statement checks

    def _check_per_row_statements(self, st: _VerifyState, out: Outcome) -> None:
        rows = st.rows
        labels = st.labels
        caught = st.caught
        for r in rows:
            # Row members are strictly typed: a member present with a
            # non-string JSON value is a malformed statement (a different
            # altitude than an ABSENT basis/method, which is a fail-closed
            # row, or an absent actualLayer, which has its own code).
            for member in ("attackId", "containmentObserved", "basis", "method", "actualLayer"):
                if member in r and not isinstance(r[member], str):
                    out.add("statement-malformed")
        for r in rows:
            if "actualLayer" not in r:
                out.add("malformed-missing-actual-layer")
        if labels is not None and caught is not None:
            for r in rows:
                lab = r.get("containmentObserved")
                if (
                    lab in labels
                    and lab not in caught
                    and "actualLayer" in r
                    and r.get("actualLayer") != "none"
                ):
                    out.add("clean-row-layer-not-none")

    # substrate-carrying statements: binding inputs

    def _check_substrate_binding_inputs(self, st: _VerifyState, out: Outcome) -> None:
        if not st.has_substrate:
            return
        stmt = st.stmt
        env = st.env
        subject = stmt.get("subject")
        subject = subject if isinstance(subject, list) else []
        if len(subject) != 1:
            out.add("subject-cardinality")
        subj_digest = _digest_of(subject[0]) if subject else None
        if subject and subj_digest is None:
            out.add("subject-sha256-missing")
        if "runEntropy" not in env:
            out.add("run-entropy-missing")
        self._binding_digest_canonical(out, env, subj_digest)

    @staticmethod
    def _binding_digest_canonical(
        out: Outcome, env: dict[str, Any], subj_digest: Any
    ) -> None:
        for val in (
            subj_digest,
            _digest_of(env.get("substrate")),
            _digest_of(env.get("corpus")),
            _digest_of(env.get("catchPolicy")),
            _digest_of(env.get("networkPosture")),
            _digest_of(env.get("runEntropy")),
        ):
            if val is not None and not _is_hex64_lower(val):
                out.add("digest-not-canonical")

    # fail-closed substrate rows are invalid (cannot satisfy class-match)

    def _check_fail_closed_rows(self, st: _VerifyState, out: Outcome) -> None:
        rows = st.rows
        labels = st.labels
        fail_closed_rows: set[int] = set()
        for i, r in enumerate(rows):
            lab_bad = labels is not None and r.get("containmentObserved") not in labels
            basis_bad = r.get("basis") not in ("substrate", "artifact")
            method_bad = r.get("method") not in ("intercepted", "reconstructed")
            if lab_bad or basis_bad or method_bad:
                fail_closed_rows.add(i)
                if r.get("basis") == "substrate":
                    out.add("fail-closed-substrate-row")
        st.fail_closed_rows = fail_closed_rows

    # ---- statement-level record checks ----------------------------------

    def _check_records(self, st: _VerifyState, out: Outcome) -> None:
        pred = st.pred
        records = pred.get("observationRecords")
        has_records = isinstance(records, list) and len(records) > 0
        views: list[RecordView] = []
        if isinstance(records, list) and records:
            views = [RecordView(i, rec) for i, rec in enumerate(records)]
            if any(v.decode_err for v in views):
                # Mirror Go validity.go:105-120: a record whose payload is not
                # strict base64 is record-undecodable, and the dup-record and
                # batch-root checks are then skipped (a bad leaf makes the
                # recomputed root meaningless), so both rails emit the same
                # single code instead of the Python rail additionally reporting
                # batch-root-mismatch.
                out.add("record-undecodable")
            else:
                self._records_batch_root(out, pred, views)
                self._records_duplicates(out, views)
        elif pred.get("batchRoot") is not None:
            out.add("batch-root-orphaned")
        st.has_records = has_records
        st.views = views

    @staticmethod
    def _records_batch_root(out: Outcome, pred: Any, views: list[RecordView]) -> None:
        root = pred.get("batchRoot")
        if root is None:
            out.add("batch-root-missing")
        elif all(v.pae is not None for v in views):
            if merkle_root_hex([v.pae for v in views if v.pae is not None]) != root:
                out.add("batch-root-mismatch")
        else:
            out.add("batch-root-mismatch")

    @staticmethod
    def _records_duplicates(out: Outcome, views: list[RecordView]) -> None:
        seen_leaves: set[bytes] = set()
        for v in views:
            key = v.pae if v.pae is not None else jcs_dumps_safe(v.raw)
            if key in seen_leaves:
                out.add("duplicate-record")
            seen_leaves.add(key)

    # ---- run binding derivation -----------------------------------------

    def _check_run_binding(self, st: _VerifyState, out: Outcome) -> None:
        derived_binding = None
        if st.has_substrate:
            stmt = st.stmt
            env = st.env
            try:
                subject0 = stmt["subject"][0]
                vals = {
                    "aeeBindingVersion": "1",
                    "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
                    "corpus": env["corpus"]["digest"]["sha256"],
                    "networkPosture": env["networkPosture"]["digest"]["sha256"],
                    "runEntropy": env["runEntropy"]["digest"]["sha256"],
                    "subject": subject0["digest"]["sha256"],
                    "substrate": env["substrate"]["digest"]["sha256"],
                }
                if all(isinstance(v, str) for v in vals.values()):
                    derived_binding = sha256_hex(jcs_dumps(vals))
            except (KeyError, IndexError, TypeError):
                derived_binding = None  # member codes already emitted
        st.derived_binding = derived_binding

    # ---- GATE 1: per-substrate-row coverage validity --------------------

    def _check_gate1_coverage(self, st: _VerifyState, out: Outcome) -> None:
        pinned_posture = _digest_of(st.env.get("networkPosture"))
        st.pinned_posture = pinned_posture
        row_covering: dict[int, list[RecordView]] = {}
        for i, r in enumerate(st.rows):
            self._gate1_row(st, out, i, r, pinned_posture, row_covering)
        st.row_covering = row_covering

    def _gate1_row(
        self,
        st: _VerifyState,
        out: Outcome,
        i: int,
        r: dict[str, Any],
        pinned_posture: Any,
        row_covering: dict[int, list[RecordView]],
    ) -> None:
        if r.get("basis") != "substrate" or i in st.fail_closed_rows:
            return
        if not st.has_records:
            out.add("records-absent")
            return
        refs = r.get("observationRefs")
        if not isinstance(refs, list) or len(refs) == 0:
            out.add("refs-empty")
            # an uncovered caught row is the immediate consequence
            lab = r.get("containmentObserved")
            if st.caught is not None and lab in st.caught:
                out.add("caught-row-uncovered")
            return
        ref_views = self._gate1_resolve_refs(st, out, refs)
        if ref_views is None:
            return

        # payload validity of every referenced record
        self._gate1_check_payloads(st, out, ref_views)

        # class-match + kind constraints
        covering = self._gate1_class_match(st, out, r, ref_views, pinned_posture)
        row_covering[i] = covering

        # method cap: weakest signed aeeMethod across covering records
        self._gate1_method_cap(out, r, covering)

    def _gate1_resolve_refs(
        self, st: _VerifyState, out: Outcome, refs: list[Any]
    ) -> list[RecordView] | None:
        views = st.views
        ref_views: list[RecordView] = []
        refs_ok = True
        for ref in refs:
            if isinstance(ref, bool) or not isinstance(ref, int) or ref < 0:
                out.add("ref-malformed")
                refs_ok = False
            elif ref >= len(views):
                out.add("ref-out-of-range")
                refs_ok = False
            else:
                ref_views.append(views[ref])
        if not refs_ok and not ref_views:
            return None
        return ref_views

    def _gate1_check_payloads(
        self, st: _VerifyState, out: Outcome, ref_views: list[RecordView]
    ) -> None:
        derived_binding = st.derived_binding
        for rv in ref_views:
            self._gate1_check_payload(out, rv, derived_binding)

    @staticmethod
    def _gate1_check_payload(
        out: Outcome, rv: RecordView, derived_binding: str | None
    ) -> None:
        if not rv.media_ok:
            out.add("payload-media-type")
        if rv.payload_error is not None:
            out.add(rv.payload_error)
            return
        if rv.payload is None:
            out.add("payload-not-canonical")
            return
        missing = [
            m
            for m in ("aeeRunBinding", "aeeKind", "aeeMethod")
            if m not in rv.payload
        ]
        if missing:
            out.add("payload-missing-reserved")
        if (
            derived_binding is not None
            and "aeeRunBinding" in rv.payload
            and rv.payload["aeeRunBinding"] != derived_binding
        ):
            out.add("run-binding-mismatch")

    @staticmethod
    def _uncovered_code(unknown_ref: bool, specific: str) -> str:
        return "record-kind-unknown-covers-nothing" if unknown_ref else specific

    def _gate1_class_match(
        self,
        st: _VerifyState,
        out: Outcome,
        r: dict[str, Any],
        ref_views: list[RecordView],
        pinned_posture: Any,
    ) -> list[RecordView]:
        usable = [rv for rv in ref_views if rv.payload is not None and rv.media_ok]
        known_kinds = ("interception", "arming", "sealed", "examination")
        unknown_ref = any(rv.kind not in known_kinds for rv in usable)

        lab = r.get("containmentObserved")
        method = r.get("method")
        if method == "reconstructed":
            return self._gate1_cover_reconstructed(out, usable, unknown_ref)
        if st.caught is not None and lab in st.caught:
            return self._gate1_cover_caught(out, usable, unknown_ref)
        return self._gate1_cover_clean(st, out, usable, unknown_ref, pinned_posture)

    def _gate1_cover_reconstructed(
        self, out: Outcome, usable: list[RecordView], unknown_ref: bool
    ) -> list[RecordView]:
        exams = [rv for rv in usable if rv.kind == "examination"]
        good = [rv for rv in exams if self._examination_ok(rv)]
        if not exams:
            out.add(self._uncovered_code(unknown_ref, "reconstructed-row-uncovered"))
        elif not good:
            out.add("examination-covers-nothing")
        return good

    def _gate1_cover_caught(
        self, out: Outcome, usable: list[RecordView], unknown_ref: bool
    ) -> list[RecordView]:
        inters = [rv for rv in usable if rv.kind == "interception"]
        if not inters:
            out.add(self._uncovered_code(unknown_ref, "caught-row-uncovered"))
        return inters

    def _gate1_cover_clean(
        self,
        st: _VerifyState,
        out: Outcome,
        usable: list[RecordView],
        unknown_ref: bool,
        pinned_posture: Any,
    ) -> list[RecordView]:
        good_arm = self._gate1_clean_arm(st, out, usable, unknown_ref, pinned_posture)
        good_seal = self._gate1_clean_seal(out, usable, unknown_ref, pinned_posture)
        return good_arm + good_seal

    def _gate1_clean_arm(
        self,
        st: _VerifyState,
        out: Outcome,
        usable: list[RecordView],
        unknown_ref: bool,
        pinned_posture: Any,
    ) -> list[RecordView]:
        issued_at = st.issued_at
        armings = [rv for rv in usable if rv.kind == "arming"]
        good_arm = [
            rv for rv in armings if self._arming_ok(rv, pinned_posture, issued_at)
        ]
        if not armings:
            out.add(self._uncovered_code(unknown_ref, "clean-row-uncovered"))
        elif not good_arm:
            out.add("arming-covers-nothing")
        return good_arm

    def _gate1_clean_seal(
        self,
        out: Outcome,
        usable: list[RecordView],
        unknown_ref: bool,
        pinned_posture: Any,
    ) -> list[RecordView]:
        sealeds = [rv for rv in usable if rv.kind == "sealed"]
        good_seal = [rv for rv in sealeds if self._sealed_ok(rv, pinned_posture)]
        if not sealeds:
            out.add(self._uncovered_code(unknown_ref, "clean-row-uncovered"))
        elif not good_seal:
            out.add("sealed-covers-nothing")
        return good_seal

    def _gate1_method_cap(
        self, out: Outcome, r: dict[str, Any], covering: list[RecordView]
    ) -> None:
        if not covering:
            return
        method = r.get("method")
        # the comprehension only admits records whose method is a key
        # of METHOD_ORDER, so index directly -- min never sees a None.
        methods = [
            METHOD_ORDER[rv.method] for rv in covering if rv.method in METHOD_ORDER
        ]
        if methods and method in METHOD_ORDER:
            if METHOD_ORDER[method] > min(methods):
                out.add("method-cap-exceeded")

    # ---- result recompute (pure function of carried rows) ---------------

    def _check_result_recompute(self, st: _VerifyState, out: Outcome) -> None:
        labels = st.labels
        caught = st.caught
        rows = st.rows
        result = st.result
        coverage = st.coverage
        if labels is not None and caught is not None and rows:
            recomputed = self._recompute(rows, labels, caught, coverage)
            if result in ("pass", "degraded", "fail") and recomputed != result:
                out.add("result-recompute-mismatch")
            elif result not in ("pass", "degraded", "fail"):
                # unknown token can never equal the recompute
                out.add("result-recompute-mismatch")

    # ---- GATE 2: evidence tier per key policy ---------------------------

    def _check_gate2_tiers(self, st: _VerifyState, out: Outcome) -> None:
        out.result = st.result
        out.tiers_with_key = self._tiers(st.rows, st.row_covering, with_keys=True)
        out.tiers_without_key = self._tiers(st.rows, st.row_covering, with_keys=False)

    @staticmethod
    def _recompute(
        rows: list[dict[str, Any]],
        labels: list[Any],
        caught: list[Any],
        coverage: Any,
    ) -> str:
        for r in rows:
            lab = r.get("containmentObserved")
            if lab not in labels or lab in caught:
                return "fail"
            if r.get("basis") not in ("substrate", "artifact"):
                return "fail"
            if r.get("method") not in ("intercepted", "reconstructed"):
                return "fail"
        cov = coverage if isinstance(coverage, dict) else {}
        if cov.get("outOfScope") or cov.get("routedElsewhere"):
            return "degraded"
        return "pass"

    def _tiers(
        self,
        rows: list[dict[str, Any]],
        row_covering: dict[int, list[RecordView]],
        with_keys: bool,
    ) -> list[str]:
        tiers = []
        for i, r in enumerate(rows):
            if r.get("basis") == "artifact":
                tiers.append("declared")
                continue
            if not with_keys or not self.pinned_pubs:
                tiers.append("unattested")
                continue
            covering = row_covering.get(i, [])
            if covering and all(self._record_verifies(rv) for rv in covering):
                tiers.append("attested")
            else:
                tiers.append("unattested")
        return tiers


def jcs_dumps_safe(obj: Any) -> bytes:
    try:
        return jcs_dumps(obj)
    except JcsError:
        return repr(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Second-fault-absence self-checks (single-fault discipline, machine-checked)
# ---------------------------------------------------------------------------

# Single source of truth: each failure code declares its report gate stage
# and the second-fault families it belongs to (a code may belong to more than
# one, e.g. environment-incomplete). CODE_STAGE and the _*_FAULT_CODES sets are
# DERIVED below so a new code is declared in exactly one place.
_CODE_REGISTRY: dict[str, tuple[str, tuple[str, ...]]] = {
    "statement-malformed": ("gate0", ()),
    "statement-type-unsupported": ("gate0", ()),
    "predicate-type-unsupported": ("gate0", ()),
    "member-spelling": ("gate0", ()),
    "result-vocabulary": ("gate0", ()),
    "issued-at-missing": ("gate0", ()),
    "issued-at-malformed": ("gate0", ()),
    "environment-incomplete": ("gate0", ("corpus", "binding")),
    "vocabulary-missing": ("gate0", ("vocab",)),
    "vocabulary-not-canonical": ("gate0", ("vocab",)),
    "vocabulary-caught-not-subset": ("gate0", ("vocab",)),
    "vocabulary-digest-mismatch": ("gate0", ("vocab",)),
    "corpus-digest-mismatch": ("gate0", ("corpus",)),
    "manifest-duplicate-attack": ("gate0", ("corpus",)),
    "coverage-missing": ("gate0", ()),
    "coverage-incomplete": ("gate0", ()),
    "row-attack-unknown": ("gate0", ()),
    "malformed-missing-actual-layer": ("gate0", ()),
    "clean-row-layer-not-none": ("gate0", ()),
    "subject-cardinality": ("gate0", ("binding",)),
    "subject-sha256-missing": ("gate0", ("binding",)),
    "run-entropy-missing": ("gate0", ("binding",)),
    "digest-not-canonical": ("gate0", ("binding",)),
    "fail-closed-substrate-row": ("gate0", ()),
    "record-undecodable": ("gate0", ("root",)),
    "batch-root-missing": ("gate0", ("root", "binding")),
    "batch-root-mismatch": ("gate0", ("root",)),
    "batch-root-orphaned": ("gate0", ("root",)),
    "duplicate-record": ("gate0", ("root",)),
    "records-absent": ("gate1", ("root", "binding")),
    "refs-empty": ("gate1", ("root", "binding")),
    "ref-malformed": ("gate1", ("root", "binding")),
    "ref-out-of-range": ("gate1", ("root", "binding")),
    "payload-not-canonical": ("gate1", ("binding",)),
    "payload-not-ijson": ("gate1", ("binding",)),
    "payload-media-type": ("gate1", ("binding",)),
    "payload-missing-reserved": ("gate1", ("binding",)),
    "run-binding-mismatch": ("gate1", ("binding",)),
    "method-cap-exceeded": ("gate1", ()),
    "caught-row-uncovered": ("gate1", ()),
    "reconstructed-row-uncovered": ("gate1", ()),
    "clean-row-uncovered": ("gate1", ()),
    "arming-covers-nothing": ("gate1", ()),
    "sealed-covers-nothing": ("gate1", ()),
    "examination-covers-nothing": ("gate1", ()),
    "record-kind-unknown-covers-nothing": ("gate1", ()),
    "result-recompute-mismatch": ("recompute", ()),
}

CODE_STAGE = {code: stage for code, (stage, _fams) in _CODE_REGISTRY.items()}


def _fault_family(name: str) -> set[str]:
    return {c for c, (_s, fams) in _CODE_REGISTRY.items() if name in fams}


_ROOT_FAULT_CODES = _fault_family("root")
_VOCAB_FAULT_CODES = _fault_family("vocab")
_CORPUS_FAULT_CODES = _fault_family("corpus")
_BINDING_FAULT_CODES = _fault_family("binding")


def second_fault_absence(stmt: Any, expected_codes: set[str]) -> list[str]:
    """Return a list of second-fault findings (empty = clean)."""
    findings: list[str] = []
    if not isinstance(stmt, dict):
        return findings
    pred = stmt.get("predicate")
    if not isinstance(pred, dict):
        return findings
    env = pred.get("observationEnvironment")
    env = env if isinstance(env, dict) else {}
    _sfa_batch_root(pred, expected_codes, findings)
    _sfa_vocabulary(env, expected_codes, findings)
    _sfa_corpus(env, expected_codes, findings)
    _sfa_binding(stmt, pred, env, expected_codes, findings)
    return findings


def _sfa_batch_root(
    pred: dict[str, Any], expected_codes: set[str], findings: list[str]
) -> None:
    # (i) batch root recomputes unless a root-family fault is expected
    records = pred.get("observationRecords")
    root = pred.get("batchRoot")
    if (
        not (expected_codes & _ROOT_FAULT_CODES)
        and isinstance(records, list)
        and records
        and isinstance(root, str)
    ):
        _sfa_root_recompute(records, root, findings)


def _sfa_root_recompute(records: list[Any], root: str, findings: list[str]) -> None:
    views = [RecordView(i, rec) for i, rec in enumerate(records)]
    if all(v.pae is not None for v in views):
        if merkle_root_hex([v.pae for v in views if v.pae is not None]) != root:
            findings.append("second-fault: batchRoot does not recompute")
    else:
        findings.append("second-fault: undecodable record payload")


def _sfa_vocabulary(
    env: dict[str, Any], expected_codes: set[str], findings: list[str]
) -> None:
    # (ii) vocabulary digest verifies unless a vocabulary fault is expected
    vocab = env.get("observationVocabulary")
    if not (expected_codes & _VOCAB_FAULT_CODES) and isinstance(vocab, dict):
        labels, caught = vocab.get("labels"), vocab.get("caught")
        if isinstance(labels, list) and isinstance(caught, list):
            try:
                expect = sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))
                if _digest_of(vocab) != expect:
                    findings.append("second-fault: vocabulary digest mismatch")
            except JcsError:
                findings.append("second-fault: vocabulary not canonicalizable")


def _sfa_corpus(
    env: dict[str, Any], expected_codes: set[str], findings: list[str]
) -> None:
    # (iii) corpus digest verifies unless a corpus fault is expected
    corpus = env.get("corpus")
    if not (expected_codes & _CORPUS_FAULT_CODES) and isinstance(corpus, dict):
        manifest = corpus.get("manifest")
        if isinstance(manifest, dict):
            try:
                if _digest_of(corpus) != sha256_hex(jcs_dumps(manifest)):
                    findings.append("second-fault: corpus digest mismatch")
            except JcsError:
                findings.append("second-fault: corpus manifest not canonicalizable")


def _sfa_binding(
    stmt: dict[str, Any],
    pred: dict[str, Any],
    env: dict[str, Any],
    expected_codes: set[str],
    findings: list[str],
) -> None:
    # (iv) referenced record bindings equal the derived binding unless a
    # binding-family fault is expected
    if expected_codes & _BINDING_FAULT_CODES:
        return
    rows = pred.get("attackResults")
    rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    if not any(r.get("basis") == "substrate" for r in rows):
        return
    records = pred.get("observationRecords")
    derived = _sfa_derived_binding(stmt, env)
    if derived is not None and isinstance(records, list):
        views = [RecordView(i, rec) for i, rec in enumerate(records)]
        _sfa_binding_scan(rows, views, derived, findings)


def _sfa_derived_binding(stmt: dict[str, Any], env: dict[str, Any]) -> str | None:
    try:
        vals = {
            "aeeBindingVersion": "1",
            "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
            "corpus": env["corpus"]["digest"]["sha256"],
            "networkPosture": env["networkPosture"]["digest"]["sha256"],
            "runEntropy": env["runEntropy"]["digest"]["sha256"],
            "subject": stmt["subject"][0]["digest"]["sha256"],
            "substrate": env["substrate"]["digest"]["sha256"],
        }
        return sha256_hex(jcs_dumps(vals))
    except (KeyError, IndexError, TypeError, JcsError):
        return None


def _sfa_binding_scan(
    rows: list[dict[str, Any]],
    views: list[RecordView],
    derived: str,
    findings: list[str],
) -> None:
    for r in rows:
        for ref in r.get("observationRefs") or []:
            if (
                isinstance(ref, int)
                and not isinstance(ref, bool)
                and 0 <= ref < len(views)
            ):
                p = views[ref].payload
                if p is not None and p.get("aeeRunBinding") != derived:
                    findings.append(
                        "second-fault: record binding != derived binding"
                    )
                    break


# ---------------------------------------------------------------------------
# External rail
# ---------------------------------------------------------------------------


def probe_external_verifier(path: str) -> tuple[bool, str]:
    """Return (v0.6-capable, note)."""
    if not os.path.isfile(path):
        return False, "external verifier not found at the given path"
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return False, f"external verifier unreadable: {e}"
    if AEE_PREDICATE_TYPE.encode() in data:
        return True, "v0.6 predicate type URI found; external rail enabled"
    return (
        False,
        "external verifier located but the v0.6 predicate type URI was not "
        "found in it (not v0.6-capable); using the self-contained reference rail",
    )


def run_external(cmd: list[str], vector_path: str) -> dict[str, Any]:
    name = os.path.basename(vector_path)
    try:
        proc = subprocess.run(
            cmd + [vector_path],
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        # A hung external verifier must not kill the whole suite run: report a
        # non-verdict for this vector so the loop continues.
        print(f"external verifier timed out on {name}", file=sys.stderr)
        return {
            "verdict": "error",
            "codes": ["external-verifier-timeout"],
            "result": None,
            "tiers": None,
        }
    except OSError as e:
        # Covers a missing, non-executable, or otherwise unrunnable --verifier.
        print(f"external verifier could not run on {name}: {e}", file=sys.stderr)
        return {
            "verdict": "error",
            "codes": ["external-verifier-unrunnable"],
            "result": None,
            "tiers": None,
        }
    # Surface the external verifier's own diagnostics rather than swallowing
    # them: captured stderr is otherwise invisible when a run misbehaves.
    stderr_txt = proc.stderr.decode("utf-8", "replace").strip()
    if stderr_txt:
        print(f"external verifier stderr on {name}:\n{stderr_txt}", file=sys.stderr)
    verdict = "valid" if proc.returncode == 0 else "invalid"
    codes: list[str] = []
    result = None
    tiers = None
    lines = [ln for ln in proc.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]
    if lines:
        try:
            parsed = json.loads(lines[-1])
            if isinstance(parsed, dict):
                verdict = parsed.get("verdict", verdict)
                codes = parsed.get("codes") or []
                result = parsed.get("result")
                tiers = parsed.get("tiers")
        except ValueError:
            pass
    return {"verdict": verdict, "codes": codes, "result": result, "tiers": tiers}


# ---------------------------------------------------------------------------
# Suite runner
# ---------------------------------------------------------------------------

GATE_NAMES = ("gate0", "gate1", "recompute", "tier", "self-check")



def load_manifest(suite_dir: str) -> dict[str, Any] | None:
    path = os.path.join(suite_dir, "MANIFEST.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


def manifest_index(manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    if not manifest:
        return idx
    vectors = manifest.get("vectors") or manifest.get("index") or []
    if isinstance(vectors, dict):
        for vid, entry in vectors.items():
            if isinstance(entry, dict):
                idx[vid] = entry
    elif isinstance(vectors, list):
        for entry in vectors:
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                idx[entry["id"]] = entry
    return idx


def discover_vectors(suite_dir: str) -> list[tuple[str, str]]:
    """Return (kind, path) pairs sorted by file name."""
    found: list[tuple[str, str]] = []
    for sub, kind in (("accept", "accept"), ("reject", "reject")):
        d = os.path.join(suite_dir, sub)
        if os.path.isdir(d):
            for name in sorted(os.listdir(d)):
                if name.endswith(".json"):
                    found.append((kind, os.path.join(d, name)))
    return found


def evaluate_vector(
    kind: str,
    entry: dict[str, Any] | None,
    observed: dict[str, Any],
    self_check_findings: list[str] | None,
) -> tuple[bool, dict[str, str], list[str]]:
    """Return (pass, per-gate status, reasons)."""
    reasons: list[str] = []
    gates = {g: "-" for g in GATE_NAMES}
    expected = (entry or {}).get("expected") or {}
    exp_verdict = expected.get("verdict") or (
        "valid" if kind == "accept" else "invalid"
    )
    obs_verdict = observed["verdict"]
    obs_codes = set(observed.get("codes") or [])

    # Cross-check the observed verdict against the manifest's declared verdict
    # (falling back to the directory-derived expectation). This strengthens the
    # per-kind checks below by also catching a manifest whose declared verdict
    # disagrees with the vector's accept/reject placement.
    if obs_verdict != exp_verdict:
        reasons.append(
            f"verdict: manifest declares {exp_verdict!r}, observed {obs_verdict!r}"
        )

    if kind == "accept":
        _eval_accept(expected, observed, obs_verdict, obs_codes, gates, reasons)
    else:
        _eval_reject(
            expected,
            observed,
            obs_verdict,
            obs_codes,
            self_check_findings,
            gates,
            reasons,
        )

    ok = not reasons
    return ok, gates, reasons


def _eval_accept(
    expected: dict[str, Any],
    observed: dict[str, Any],
    obs_verdict: Any,
    obs_codes: set[Any],
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    for g in ("gate0", "gate1", "recompute", "tier"):
        gates[g] = "PASS"
    if obs_verdict != "valid":
        for code in obs_codes:
            gates[CODE_STAGE.get(code, "gate0")] = "FAIL"
        reasons.append(
            f"expected valid, observed invalid with codes {sorted(obs_codes)}"
        )
    exp_result = expected.get("result")
    if obs_verdict == "valid" and exp_result is not None:
        if observed.get("result") != exp_result:
            gates["recompute"] = "FAIL"
            reasons.append(
                "result: expected {!r}, observed {!r}".format(exp_result, observed.get("result"))
            )
    _eval_accept_tiers(expected, observed, gates, reasons)


def _eval_accept_tiers(
    expected: dict[str, Any],
    observed: dict[str, Any],
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    for field_name, obs_key in (
        ("tierWithPinnedKey", "tiers_with_key"),
        ("tierWithoutKey", "tiers_without_key"),
    ):
        exp_tiers = expected.get(field_name)
        obs_tiers = observed.get(obs_key)
        if exp_tiers is not None and obs_tiers is not None:
            if list(exp_tiers) != list(obs_tiers):
                gates["tier"] = "FAIL"
                reasons.append(
                    f"{field_name}: expected {exp_tiers}, observed {obs_tiers}"
                )
    # behavior assertion 1: the tier never alters the result
    if (
        observed.get("tiers_with_key") is not None
        and observed.get("result") is not None
        and observed.get("result_without_key") not in (None, observed["result"])
    ):
        gates["tier"] = "FAIL"
        reasons.append("tier derivation altered the result")


def _eval_reject(
    expected: dict[str, Any],
    observed: dict[str, Any],
    obs_verdict: Any,
    obs_codes: set[Any],
    self_check_findings: list[str] | None,
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    exp_codes = set(expected.get("codes") or [])
    if obs_verdict != "invalid":
        gates["gate0"] = gates["gate1"] = gates["recompute"] = "FAIL"
        reasons.append("expected invalid, observed valid")
    else:
        _eval_reject_stages(exp_codes, obs_codes, gates, reasons)
        # behavior assertion 2: invalid emits no result and no tiers
        if observed.get("result") is not None or observed.get("tiers_with_key"):
            gates["recompute"] = "FAIL"
            reasons.append("invalid vector emitted a result or tiers")
    if self_check_findings is not None:
        if self_check_findings:
            gates["self-check"] = "FAIL"
            reasons.extend(self_check_findings)
        else:
            gates["self-check"] = "PASS"


def _eval_reject_stages(
    exp_codes: set[Any],
    obs_codes: set[Any],
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    stage = "gate0"
    if not exp_codes:
        gates[stage] = "PASS"
        return
    hit = exp_codes & obs_codes
    if not hit:
        reasons.append(
            f"no expected code observed: expected {sorted(exp_codes)}, observed {sorted(obs_codes)}"
        )
    # Group expected codes by gate stage; a stage is PASS iff ANY of
    # its expected codes was observed, matching the disjunctive
    # "no expected code observed" reason above (several coverage
    # codes are conditional alternates in the generator, so a vector
    # legitimately declares more than one and emits one). Iterating
    # the set directly let a later unobserved code overwrite an
    # earlier PASS, making the sub-status depend on PYTHONHASHSEED.
    stage_hit: dict[str, bool] = {}
    for code in exp_codes:
        st = CODE_STAGE.get(code, "gate0")
        stage_hit[st] = stage_hit.get(st, False) or (code in obs_codes)
    for st, seen in stage_hit.items():
        gates[st] = "PASS" if seen else "FAIL"


def run_suite(args: argparse.Namespace) -> int:
    suite_dir = os.path.abspath(args.vectors)
    if not os.path.isdir(suite_dir):
        print(f"suite directory not found: {args.vectors}", file=sys.stderr)
        return 2

    manifest = load_manifest(suite_dir)
    idx = manifest_index(manifest)
    vectors = discover_vectors(suite_dir)
    report_base = os.path.dirname(suite_dir) or "."

    if not vectors:
        rel = os.path.relpath(suite_dir, report_base)
        print(
            f"no vectors found under {rel} (accept/ and reject/ are empty "
            "or missing); nothing to run"
        )
        return 2

    external_cmd, probe_note = _run_rail_selection(args)

    keys = derive_test_keys()
    pinned = [keys[PINNED_ROLE]["public"]]
    ref_with = ReferenceVerifier(pinned)
    ref_without = ReferenceVerifier([])

    rows_out: list[dict[str, Any]] = []
    failures = 0
    for kind, path in vectors:
        row, failed = _run_process_vector(
            kind, path, idx, external_cmd, ref_with, ref_without, report_base
        )
        if failed:
            failures += 1
        rows_out.append(row)

    # manifest completeness both ways
    suite_notes, note_failures = _run_manifest_notes(manifest, idx, rows_out)
    failures += note_failures

    report, report_path = _run_write_report(
        args, suite_dir, report_base, external_cmd, probe_note, suite_notes, rows_out
    )
    _run_print_table(
        report, rows_out, suite_notes, probe_note, report_path, report_base
    )
    return 1 if failures else 0


def _run_rail_selection(args: argparse.Namespace) -> tuple[list[str] | None, str]:
    # rail selection
    external_cmd: list[str] | None = None
    probe_note = "no external verifier supplied; using the reference rail"
    verifier = args.verifier or os.environ.get("AEE_EXTERNAL_VERIFIER")
    if verifier:
        capable, probe_note = probe_external_verifier(verifier)
        if capable:
            if verifier.endswith(".py"):
                external_cmd = [sys.executable, verifier]
            else:
                external_cmd = [verifier]
    return external_cmd, probe_note


def _run_observe(
    external_cmd: list[str] | None,
    ref_with: ReferenceVerifier,
    ref_without: ReferenceVerifier,
    path: str,
    stmt: Any,
) -> dict[str, Any]:
    if external_cmd is not None:
        ext = run_external(external_cmd, path)
        return {
            "verdict": ext["verdict"],
            "codes": ext["codes"],
            "result": ext["result"],
            "tiers_with_key": ext["tiers"],
            "tiers_without_key": None,
            "result_without_key": None,
        }
    o_with = ref_with.verify(stmt)
    o_without = ref_without.verify(stmt)
    return {
        "verdict": o_with.verdict,
        "codes": o_with.codes,
        "result": o_with.result,
        "tiers_with_key": o_with.tiers_with_key,
        "tiers_without_key": o_without.tiers_without_key,
        "result_without_key": o_without.result,
    }


def _run_process_vector(
    kind: str,
    path: str,
    idx: dict[str, dict[str, Any]],
    external_cmd: list[str] | None,
    ref_with: ReferenceVerifier,
    ref_without: ReferenceVerifier,
    report_base: str,
) -> tuple[dict[str, Any], bool]:
    vid = os.path.splitext(os.path.basename(path))[0]
    entry = idx.get(vid)
    rel = os.path.relpath(path, report_base)
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_STATEMENT_BYTES + 1)
        if len(raw) > MAX_STATEMENT_BYTES:
            raise ValueError(f"statement exceeds {MAX_STATEMENT_BYTES} bytes")
        stmt = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError) as e:
        return {
            "id": vid,
            "file": rel,
            "kind": kind,
            "status": "FAIL",
            "gates": {g: "FAIL" for g in GATE_NAMES},
            "reasons": [f"vector unreadable: {e}"],
        }, True

    observed = _run_observe(external_cmd, ref_with, ref_without, path, stmt)

    self_check = None
    if kind == "reject":
        exp_codes = set(((entry or {}).get("expected") or {}).get("codes") or [])
        self_check = second_fault_absence(stmt, exp_codes)

    ok, gates, reasons = evaluate_vector(kind, entry, observed, self_check)
    row = {
        "id": vid,
        "file": rel,
        "kind": kind,
        "status": "PASS" if ok else "FAIL",
        "gates": gates,
        "observed": {
            "verdict": observed["verdict"],
            "codes": observed["codes"],
            "result": observed["result"],
        },
        "expected": (entry or {}).get("expected"),
        "inManifest": entry is not None,
        "reasons": reasons,
    }
    return row, (not ok)


def _run_manifest_notes(
    manifest: dict[str, Any] | None,
    idx: dict[str, dict[str, Any]],
    rows_out: list[dict[str, Any]],
) -> tuple[list[str], int]:
    suite_notes: list[str] = []
    if manifest is None:
        suite_notes.append(
            "MANIFEST.json not found: expectations inferred from directory "
            "names only (verdict-level checks; no code, tier, or self-check "
            "exemption data)"
        )
        return suite_notes, 0
    on_disk = {r["id"] for r in rows_out}
    missing_files = sorted(set(idx) - on_disk)
    unlisted = sorted(on_disk - set(idx))
    note_failures = 0
    if missing_files:
        note_failures += 1
        suite_notes.append(
            f"MANIFEST lists vectors with no file on disk: {missing_files}"
        )
    if unlisted:
        suite_notes.append(f"files on disk not listed in MANIFEST: {unlisted}")
    return suite_notes, note_failures


def _run_write_report(
    args: argparse.Namespace,
    suite_dir: str,
    report_base: str,
    external_cmd: list[str] | None,
    probe_note: str,
    suite_notes: list[str],
    rows_out: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    report: dict[str, Any] = {
        "suite": os.path.relpath(suite_dir, report_base),
        "predicateType": AEE_PREDICATE_TYPE,
        "rail": "external" if external_cmd else "reference",
        "externalVerifierProbe": probe_note,
        "pinnedTestKeyRole": PINNED_ROLE,
        "totals": {
            "vectors": len(rows_out),
            "pass": sum(1 for r in rows_out if r["status"] == "PASS"),
            "fail": sum(1 for r in rows_out if r["status"] == "FAIL"),
        },
        "notes": suite_notes,
        "gateColumns": list(GATE_NAMES),
        "vectors": rows_out,
    }
    report_path = args.report or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "conformance-report.json"
    )
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=False)
        f.write("\n")
    return report, report_path


def _run_print_table(
    report: dict[str, Any],
    rows_out: list[dict[str, Any]],
    suite_notes: list[str],
    probe_note: str,
    report_path: str,
    report_base: str,
) -> None:
    # stdout coverage table (gate x vector)
    print(f"rail: {report['rail']}  ({probe_note})")
    gate_cols = " ".join(f"{g:<10}" for g in GATE_NAMES)
    header = f"{'vector':<42} {'status':<6} {gate_cols}"
    print(header)
    print("-" * len(header))
    for r in rows_out:
        row_gates = " ".join(f"{r['gates'][g]:<10}" for g in GATE_NAMES)
        print(f"{r['id'][:42]:<42} {r['status']:<6} {row_gates}")
        if r["status"] == "FAIL":
            for reason in r["reasons"]:
                print(f"    ! {reason}")
    for note in suite_notes:
        print(f"note: {note}")
    t = report["totals"]
    print(
        f"totals: {t['vectors']} vectors, {t['pass']} pass, {t['fail']} fail; "
        f"report written to {os.path.relpath(report_path, report_base)}"
    )


# ---------------------------------------------------------------------------
# Built-in self-test: synthetic statements exercising the reference rail
# ---------------------------------------------------------------------------


def _selftest_build(keys: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build a minimal valid substrate statement with arming + sealed +
    interception records signed by the derived test key."""
    def d(s: str) -> str:  # synthetic digest for the self-test statement
        return sha256_hex(s.encode())

    labels = ["example_label_a", "example_label_b"]
    caught = ["example_label_a"]
    manifest = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"]}}
    env: dict[str, Any] = {
        "substrate": {"name": "example-substrate", "digest": {"sha256": d("substrate")}},
        "corpus": {
            "name": "example-corpus",
            "uri": "pkg:example/corpus@1",
            "digest": {"sha256": sha256_hex(jcs_dumps(manifest))},
            "manifest": manifest,
        },
        "catchPolicy": {"digest": {"sha256": d("catch-policy-doc")}},
        "networkPosture": {"posture": "sinkhole", "digest": {"sha256": d("posture")}},
        "observationVocabulary": {
            "digest": {
                "sha256": sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))
            },
            "labels": labels,
            "caught": caught,
        },
        "runEntropy": {"digest": {"sha256": d("run-start")}},
    }
    subject: list[dict[str, Any]] = [
        {"name": "example-agent-bundle", "digest": {"sha256": d("subject")}}
    ]
    binding = sha256_hex(
        jcs_dumps(
            {
                "aeeBindingVersion": "1",
                "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
                "corpus": env["corpus"]["digest"]["sha256"],
                "networkPosture": env["networkPosture"]["digest"]["sha256"],
                "runEntropy": env["runEntropy"]["digest"]["sha256"],
                "subject": subject[0]["digest"]["sha256"],
                "substrate": env["substrate"]["digest"]["sha256"],
            }
        )
    )
    ptype = "application/vnd.example.aee-observation.v1+json"
    seed = keys[PINNED_ROLE]["seed"]
    keyid = keys[PINNED_ROLE]["keyid"]

    def record(payload_obj: dict[str, Any]) -> dict[str, Any]:
        payload = jcs_dumps(payload_obj)
        sig = ed25519_sign(seed, pae(ptype, payload))
        return {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": ptype,
            "signatures": [
                {"keyid": keyid, "sig": base64.b64encode(sig).decode()}
            ],
        }

    posture = env["networkPosture"]["digest"]["sha256"]
    rec_arming = record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "arming",
            "aeeMethod": "intercepted",
            "armedAt": "2025-12-31T23:59:00Z",
            "aeePostureDigest": posture,
        }
    )
    rec_sealed = record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "sealed",
            "aeeMethod": "intercepted",
            "aeeStillArmed": True,
            "aeeDropCount": 0,
            "aeePostureDigest": posture,
        }
    )
    rec_intercept = record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "interception",
            "aeeMethod": "intercepted",
            "producerNote": "synthetic",
        }
    )
    records = [rec_arming, rec_sealed, rec_intercept]
    leaves = [
        pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records
    ]
    stmt = {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": AEE_PREDICATE_TYPE,
        "predicate": {
            "result": "fail",
            "observationEnvironment": env,
            "coverage": {
                "assessedClasses": ["XA"],
                "outOfScope": {},
                "routedElsewhere": {},
            },
            "attackResults": [
                {
                    "attackId": "XA-EXAMPLE-1",
                    "containmentObserved": "example_label_a",
                    "basis": "substrate",
                    "method": "intercepted",
                    "actualLayer": "example.layer-a",
                    "observationRefs": [2],
                },
                {
                    "attackId": "XA-EXAMPLE-2",
                    "containmentObserved": "example_label_b",
                    "basis": "substrate",
                    "method": "intercepted",
                    "actualLayer": "none",
                    "observationRefs": [0, 1],
                },
            ],
            "observationRecords": records,
            "batchRoot": merkle_root_hex(leaves),
            "issuedAt": "2026-01-01T00:00:00Z",
        },
    }
    return stmt


def self_test() -> int:
    keys = derive_test_keys()
    ref = ReferenceVerifier([keys[PINNED_ROLE]["public"]])
    ref_nokey = ReferenceVerifier([])
    base = _selftest_build(keys)
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        checks.append((name, cond, detail))

    # Ed25519 known-answer test: the pure-Python RFC 8032 implementation must
    # reproduce a reference signature computed by the `cryptography` library for
    # a fixed seed and message (regenerate the expected value from cryptography
    # if this vector ever changes).
    _kat_seed = bytes.fromhex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    )
    _kat_msg = b"aee-conformance ed25519 known-answer test"
    _kat_pub = bytes.fromhex(
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    )
    _kat_sig = bytes.fromhex(
        "fb6b33be7173edac6bbecc0c916806fa15e58360924d26b9c60466f491193f2b"
        "3aba43873d55404a43649ca8534736ca92941456ac379899dc443f9c2a03f607"
    )
    check(
        "ed25519 known-answer (RFC 8032, vs cryptography)",
        ed25519_sign(_kat_seed, _kat_msg) == _kat_sig
        and ed25519_verify(_kat_pub, _kat_msg, _kat_sig),
        "hand-rolled signature must match the reference",
    )

    # Comparator pin, mirrored from the Go rail's unit pin: a
    # supplementary-plane string orders BEFORE a BMP private-use code point
    # under UTF-16 code units and AFTER it under code points. With the
    # BMP-only profile enforced no corpus vector can probe this divergence,
    # so this is the only layer where the comparator's order stays
    # expressible; reverting the sort key to code-point order turns it red.
    check(
        "utf-16 code-unit comparator (supplementary before private-use)",
        sorted(["\uE000", "\U0001F600"], key=_utf16_sort_key)
        == ["\U0001F600", "\uE000"],
        "sort key must compare 16-bit code units, not code points",
    )

    o = ref.verify(base)
    check(
        "base statement valid",
        o.verdict == "valid" and o.result == "fail",
        f"codes={o.codes} result={o.result}",
    )
    check(
        "tiers with pinned key",
        o.tiers_with_key == ["attested", "attested"],
        str(o.tiers_with_key),
    )
    o2 = ref_nokey.verify(base)
    check(
        "tiers without key",
        o2.tiers_without_key == ["unattested", "unattested"],
        str(o2.tiers_without_key),
    )
    check(
        "tier never alters result",
        o2.result == o.result,
        f"{o2.result} vs {o.result}",
    )

    def mutate(fn: Callable[[dict[str, Any]], object]) -> Outcome:
        s = json.loads(json.dumps(base))
        fn(s)
        return ref.verify(s)

    def add_astral_label(s: dict[str, Any]) -> None:
        # Supplementary-plane label with the digest recomputed and sortedness
        # intact under both orders: the BMP-only rule is the only violation.
        v = s["predicate"]["observationEnvironment"]["observationVocabulary"]
        v["labels"] = [*v["labels"], "\U0001F600"]
        v["digest"]["sha256"] = sha256_hex(
            jcs_dumps({"caught": v["caught"], "labels": v["labels"]})
        )

    m = mutate(add_astral_label)
    check(
        "supplementary-plane vocabulary entry rejected (BMP-only profile)",
        m.verdict == "invalid" and "vocabulary-not-canonical" in m.codes,
        str(m.codes),
    )

    # Supplementary-plane member NAME in a covering payload covers nothing;
    # a supplementary-plane VALUE stays legal. Checked at the payload-parse
    # layer, where the covering-payload analysis reads it.
    bad_name = jcs_dumps({"aeeKind": "interception", "zz\U0001F600": "x"})
    try:
        strict_payload_parse(bad_name)
        bmp_name_rejected = False
        bmp_name_detail = "parse accepted a supplementary-plane member name"
    except IJsonError as e:
        bmp_name_rejected = e.code == "payload-not-canonical"
        bmp_name_detail = e.code
    check(
        "supplementary-plane payload member name rejected (BMP-only profile)",
        bmp_name_rejected,
        bmp_name_detail,
    )
    ok_value = jcs_dumps({"aeeKind": "interception", "note": "\U0001F600"})
    try:
        strict_payload_parse(ok_value)
        bmp_value_ok = True
        bmp_value_detail = ""
    except IJsonError as e:
        bmp_value_ok = False
        bmp_value_detail = e.code
    check(
        "supplementary-plane payload member VALUE stays legal",
        bmp_value_ok,
        bmp_value_detail,
    )

    m = mutate(lambda s: s["predicate"].__setitem__("result", "pass"))
    check(
        "carried pass on fail recompute",
        m.verdict == "invalid" and "result-recompute-mismatch" in m.codes,
        str(m.codes),
    )
    m = mutate(
        lambda s: s["predicate"].__setitem__(
            "batchRoot", "0" * 64
        )
    )
    check(
        "tampered batch root",
        "batch-root-mismatch" in m.codes,
        str(m.codes),
    )
    m = mutate(
        lambda s: s["predicate"]["observationEnvironment"]["observationVocabulary"][
            "labels"
        ].reverse()
    )
    check(
        "unsorted vocabulary labels",
        "vocabulary-not-canonical" in m.codes,
        str(m.codes),
    )
    m = mutate(
        lambda s: s["predicate"]["attackResults"][0].__setitem__(
            "observationRefs", [0]
        )
    )
    check(
        "caught row referencing arming only",
        "caught-row-uncovered" in m.codes,
        str(m.codes),
    )
    m = mutate(
        lambda s: s["predicate"]["attackResults"][0].__setitem__("method", "examined")
    )
    check(
        "unknown method on substrate row",
        "fail-closed-substrate-row" in m.codes,
        str(m.codes),
    )
    m = mutate(lambda s: s["predicate"]["observationEnvironment"].pop("runEntropy"))
    check(
        "missing runEntropy",
        "run-entropy-missing" in m.codes and "run-binding-mismatch" not in m.codes,
        str(m.codes),
    )
    m = mutate(
        lambda s: s["predicate"]["attackResults"][1].__setitem__(
            "observationRefs", [7]
        )
    )
    check("ref out of range", "ref-out-of-range" in m.codes, str(m.codes))

    def wrong_signer(s: dict[str, Any]) -> None:
        seed = keys["wrong-signer-test"]["seed"]
        rec = s["predicate"]["observationRecords"][2]
        sig = ed25519_sign(
            seed, pae(rec["payloadType"], base64.b64decode(rec["payload"]))
        )
        rec["signatures"] = [
            {
                "keyid": keys["wrong-signer-test"]["keyid"],
                "sig": base64.b64encode(sig).decode(),
            }
        ]

    s = json.loads(json.dumps(base))
    wrong_signer(s)
    o3 = ref.verify(s)
    check(
        "wrong-signer record: valid but unattested (signature failure is a "
        "tier outcome, never a failure code)",
        o3.verdict == "valid" and o3.tiers_with_key == ["unattested", "attested"],
        f"verdict={o3.verdict} tiers={o3.tiers_with_key} codes={o3.codes}",
    )

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print("{}  {}{}".format("PASS" if ok else "FAIL", name, f"  [{detail}]" if not ok else ""))
    print(f"self-test: {len(checks)} checks, {len(failed)} failed")
    return 1 if failed else 0


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AEE v0.6 conformance vector harness (differential when an "
        "external v0.6-capable verifier is supplied; self-contained otherwise)"
    )
    default_vectors = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), os.pardir, "vectors"
    )
    parser.add_argument(
        "--vectors",
        default=os.path.normpath(default_vectors),
        help="suite directory containing MANIFEST.json, accept/, reject/",
    )
    parser.add_argument(
        "--verifier",
        default=None,
        help="path to an external verifier to run differentially "
        "(also read from AEE_EXTERNAL_VERIFIER); probed for v0.6 capability",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="output path for conformance-report.json",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the built-in reference-rail self-test and exit",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return run_suite(args)


if __name__ == "__main__":
    sys.exit(main())
