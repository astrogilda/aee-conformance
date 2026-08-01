#!/usr/bin/env python3
"""Detector liveness, computed per channel from the bytes a statement carries.

The problem
-----------
A check that never fires may be guarding a well-designed boundary or may be
dead, and from outside the two are indistinguishable: both runs come back
clean. Nothing in a clean report separates them, and no amount of reading it
harder will, because the two states have the same wire form. The only way to
tell is to plant something the check MUST catch and then establish, from the
bytes, that it did.

The construction
----------------
This version of the predicate already carries every member the construction
needs, and this script adds none. Five carried values line up:

  ``corpus.manifest.classes``        which channel an attack belongs to
  ``corpus.manifest.expectedPayloads`` the planted stimulus: the commitment
                                     value a corpus author computed in advance
                                     for what that attack looks like on the wire
  ``aeePayloadCommitment``           what the substrate actually committed to,
                                     on the interception record it signed
  ``attribution: pinned``            the row asserting the two are comparable
  ``aeeObservedAttacks``             the run-end seal's own signed list of what
                                     the substrate attributed

A channel is DEMONSTRATED when at least one attack in it satisfies all five:
the corpus planted a probe there, the row for that probe is caught, declares
the stronger attribution, resolves an interception whose committed value the
corpus predicted, and the run-end seal names it.

The claim is strictly per channel and does not generalise across channels. A
probe caught on the egress channel establishes nothing whatever about the
channel beside it, so a run that plants one probe and reports a live detector
has measured a sample and called it a census. One fixture per claimed channel
is the minimum, not a sample of them, which is why the verdict below is
computed per entry of ``coverage.assessedClasses`` and never rolled into one
boolean for the run.

What this is NOT
----------------
It is not a validity gate, and running it is not verification. Liveness is not
a requirement of the predicate at this version: a producer whose detector
genuinely did not fire on one channel emits a statement that is valid, honest
and NOT demonstrated, and refusing it would refuse the honest report along with
the dishonest one. The predicate's own Consumer policy obligations park this
decision with the consumer, and this script computes the input to that decision
rather than making it.

It is also structural until signatures verify. Every value above except the
manifest travels inside a record payload, and record content means nothing
until its signature verifies against a key the consumer trusts -- the
verify-then-read discipline the specification states under Parsing Rules.
Without ``--key`` the report says ``structural`` in its own header and every
verdict is a statement about form. With ``--key`` each covering record is
checked as DSSE PAE over (payloadType, payload), and a channel whose
interception or seal does not verify is reported UNVERIFIED rather than
demonstrated.

Usage
-----
    scripts/liveness-probe.py <statement.json> [...]
    scripts/liveness-probe.py --corpus            # every accept vector
    scripts/liveness-probe.py --corpus --json     # machine-readable
    scripts/liveness-probe.py --corpus --key <64-hex-ed25519-public-key>

``--key`` wants the 32-byte ed25519 PUBLIC key as 64 hex characters. The
suite's own test key derives from a published constant -- the seed is
``SHA-256("in-toto-aee-test-key/substrate-observation-test/v1")`` -- so anyone
can re-derive it and produce the corpus report with signatures checked. Its
public half is published in ``vectors/reject/INDEX.md`` under the determinism
recipe, and is
``496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62``. It is a
test key by construction: the derivation being open is what makes it one.

Exit 0 when every statement parsed and was reported. Exit 1 when a file could
not be read or parsed, or when ``--require-demonstrated`` is passed and some
claimed channel is not demonstrated. A parse failure is never reported as a
channel that is not live: a check that did not run is not a result.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
ACCEPT_DIR = REPO_ROOT / "vectors" / "accept"

# Per-channel verdicts. Ordered worst to best for the summary line.
UNPROBED = "unprobed"          # the corpus planted no stimulus on this channel
NOT_DEMONSTRATED = "not-demonstrated"  # planted, and nothing carried shows a catch
UNVERIFIED = "unverified"      # would be demonstrated, but a covering signature failed
UNSEALED = "unsealed"          # the probe matched and no run-end seal names it
DEMONSTRATED = "demonstrated"  # every part of the construction lines up
# Ordered worst to best; probe_state keeps the best state any row reaches.
VERDICTS = (UNPROBED, NOT_DEMONSTRATED, UNVERIFIED, UNSEALED, DEMONSTRATED)


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE PAEv1 over (payloadType, payload)."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


class Verifier:
    """Signature checking, or an explicit refusal to pretend to do it."""

    def __init__(self, key_hex: str | None) -> None:
        self.key_hex = key_hex
        self.key: Any = None
        if key_hex is None:
            return
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as exc:  # pragma: no cover -- environment, not logic
            raise SystemExit(
                "liveness-probe: --key was given and the cryptography package "
                "is not importable, so no signature could be checked. Refusing "
                "to continue: reporting a structural verdict under a flag that "
                "asked for a verified one would report a check that did not run "
                "as a result. Install it, or run without --key and read the "
                "report as structural."
            ) from exc
        try:
            raw = binascii.unhexlify(key_hex)
        except binascii.Error as exc:
            raise SystemExit(
                f"liveness-probe: --key is not hex: {exc}") from exc
        if len(raw) != 32:
            raise SystemExit(
                f"liveness-probe: --key is {len(raw)} bytes; an ed25519 public "
                "key is 32"
            )
        self.key = Ed25519PublicKey.from_public_bytes(raw)

    @property
    def active(self) -> bool:
        return self.key is not None

    def record_verifies(self, rec: dict[str, Any]) -> bool:
        if self.key is None:
            return True
        from cryptography.exceptions import InvalidSignature

        try:
            payload = base64.b64decode(rec["payload"], validate=True)
            ptype = rec["payloadType"]
        except (KeyError, TypeError, binascii.Error):
            return False
        for sig in rec.get("signatures") or []:
            try:
                raw = base64.b64decode(sig["sig"], validate=True)
            except (KeyError, TypeError, binascii.Error):
                continue
            try:
                self.key.verify(raw, pae(ptype, payload))
                return True
            except InvalidSignature:
                continue
        return False


def record_payload(rec: Any) -> dict[str, Any] | None:
    """The parsed payload of one observation record, or None if it is not one.

    Every failure here returns None and the caller treats the record as
    covering nothing. A record this function cannot read is never counted as
    evidence that a channel is live.
    """
    if not isinstance(rec, dict):
        return None
    try:
        raw = base64.b64decode(rec["payload"], validate=True)
        obj = json.loads(raw.decode("utf-8"))
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None
    return obj if isinstance(obj, dict) else None


def better(a: str, b: str) -> str:
    return max(a, b, key=VERDICTS.index)


def sealed_attacks(records: list[Any], ver: Verifier) -> set[str]:
    """What the run-end seals attributed, from seals whose signature holds."""
    out: set[str] = set()
    for rec in records:
        payload = record_payload(rec)
        if not payload or payload.get("aeeKind") != "sealed":
            continue
        if not ver.record_verifies(rec):
            continue
        out |= {a for a in (payload.get("aeeObservedAttacks") or [])
                if isinstance(a, str)}
    return out


def claims_a_catch(row: Any, attack: str, caught_labels: set[str]) -> bool:
    """Whether this row is one that could demonstrate a probe was caught."""
    return (isinstance(row, dict)
            and row.get("attackId") == attack
            and row.get("containmentObserved") in caught_labels
            and row.get("basis") == "substrate"
            and row.get("attribution") == "pinned")


def row_state(row: dict[str, Any], records: list[Any], want: set[str],
              attack: str, sealed: set[str], ver: Verifier) -> str:
    """The best state one row reaches over the records it resolves."""
    best = NOT_DEMONSTRATED
    for idx in row.get("observationRefs") or []:
        if isinstance(idx, bool) or not isinstance(idx, int):
            continue
        if not 0 <= idx < len(records):
            continue
        payload = record_payload(records[idx])
        if not payload or payload.get("aeeKind") != "interception":
            continue
        if not set(payload.get("aeePayloadCommitment") or []) & want:
            continue
        if not ver.record_verifies(records[idx]):
            best = better(best, UNVERIFIED)
        elif attack not in sealed:
            # The comparison the corpus made possible succeeded and the run-end
            # commitment does not carry it, so a party holding the enclosing
            # envelope could have deleted that record and recomputed a
            # self-consistent root over what remained. The seal is what makes
            # the deletion visible, and a substrate holding no attack-to-record
            # correspondence carries the empty array honestly -- so this is a
            # real limit on what the run can show, not a fault in the statement.
            best = better(best, UNSEALED)
        else:
            return DEMONSTRATED
    return best


def probe_state(attack: str, rows: list[Any], records: list[Any],
                want: set[str], caught_labels: set[str], sealed: set[str],
                ver: Verifier) -> str:
    """The best state any row for this attack reaches."""
    best = NOT_DEMONSTRATED
    for row in rows:
        if not claims_a_catch(row, attack, caught_labels):
            continue
        best = better(best, row_state(row, records, want, attack, sealed, ver))
        if best == DEMONSTRATED:
            return best
    return best


def evaluate(stmt: dict[str, Any], ver: Verifier) -> dict[str, Any]:
    """Per-channel liveness over one statement. Never raises on shape."""
    pred = stmt.get("predicate")
    if not isinstance(pred, dict):
        return {"error": "no predicate object", "channels": {}}
    env = pred.get("observationEnvironment") or {}
    manifest = ((env.get("corpus") or {}).get("manifest")) or {}
    classes = manifest.get("classes") or {}
    expected = manifest.get("expectedPayloads") or {}
    if not isinstance(classes, dict) or not isinstance(expected, dict):
        return {"error": "manifest classes or expectedPayloads not objects",
                "channels": {}}
    caught_labels = {c for c in
                     ((env.get("observationVocabulary") or {}).get("caught") or [])
                     if isinstance(c, str)}
    records = pred.get("observationRecords") or []
    rows = pred.get("attackResults") or []
    assessed = (pred.get("coverage") or {}).get("assessedClasses") or []
    sealed = sealed_attacks(records, ver)

    channels: dict[str, Any] = {}
    for cls in assessed:
        if not isinstance(cls, str):
            continue
        planted = sorted(a for a in (classes.get(cls) or []) if a in expected)
        if not planted:
            channels[cls] = {"verdict": UNPROBED, "planted": [],
                             "demonstrated": []}
            continue
        states = {a: probe_state(a, rows, records,
                                 set(expected.get(a) or []), caught_labels,
                                 sealed, ver)
                  for a in planted}
        channels[cls] = {
            "verdict": max(states.values(), key=VERDICTS.index),
            "planted": planted,
            "demonstrated": sorted(a for a, s in states.items()
                                   if s == DEMONSTRATED),
        }
    return {"channels": channels}


def report(paths: list[Path], ver: Verifier, as_json: bool) -> tuple[int, int, int]:
    """Print one row per statement.

    Returns (claimed channels, demonstrated, read errors). The third value is
    reported separately and never folded into the first two: a file that could
    not be read contributes no channels, and counting it as channels that are
    not live would turn a check that did not run into a finding.
    """
    out: list[dict[str, Any]] = []
    claimed = demonstrated = 0
    read_errors = 0
    for path in paths:
        try:
            stmt = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            out.append({"vector": path.name, "readError": str(exc)})
            read_errors += 1
            continue
        res = evaluate(stmt, ver)
        chans = res.get("channels", {})
        claimed += len(chans)
        demonstrated += sum(1 for c in chans.values()
                            if c["verdict"] == DEMONSTRATED)
        out.append({"vector": path.name, **res})

    if as_json:
        print(json.dumps({
            "mode": "verified" if ver.active else "structural",
            "claimedChannels": claimed,
            "demonstratedChannels": demonstrated,
            "readErrors": read_errors,
            "statements": out,
        }, indent=2, sort_keys=True))
        return claimed, demonstrated, read_errors

    mode = "verified against the supplied key" if ver.active else \
        "STRUCTURAL: no key supplied, so no record content is trusted"
    print(f"detector liveness, per channel -- {mode}")
    print()
    for entry in out:
        if "readError" in entry:
            print(f"  {entry['vector']}: COULD NOT READ -- {entry['readError']}")
            continue
        if "error" in entry:
            print(f"  {entry['vector']}: not evaluable -- {entry['error']}")
            continue
        chans = entry["channels"]
        if not chans:
            continue
        cells = ", ".join(f"{c}={v['verdict']}" for c, v in sorted(chans.items()))
        print(f"  {entry['vector']}: {cells}")
    print()
    print(f"claimed channels: {claimed}; demonstrated: {demonstrated}; "
          f"read errors: {read_errors}")
    return claimed, demonstrated, read_errors


def main() -> int:
    ap = argparse.ArgumentParser(
        description="per-channel detector liveness over AEE statements")
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--corpus", action="store_true",
                    help="evaluate every accept vector in vectors/accept/")
    ap.add_argument("--key", default=None,
                    help="ed25519 public key (64 hex) to verify record "
                         "signatures against; without it the report is "
                         "structural and says so")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--require-demonstrated", action="store_true",
                    help="exit 1 unless every claimed channel is demonstrated")
    args = ap.parse_args()

    paths = list(args.files)
    if args.corpus:
        paths += sorted(ACCEPT_DIR.glob("ok-*.json"))
    if not paths:
        ap.error("no statements given; pass files or --corpus")

    ver = Verifier(args.key)
    claimed, demonstrated, read_errors = report(paths, ver, args.json)
    missing = [p for p in paths if not p.is_file()]
    if missing:
        for p in missing:
            print(f"missing: {p}", file=sys.stderr)
        return 1
    if read_errors:
        print(f"FAIL: {read_errors} statement(s) could not be read or parsed. "
              "That is not a report about their detectors: a check that did "
              "not run is not a result.", file=sys.stderr)
        return 1
    if args.require_demonstrated and demonstrated != claimed:
        print(f"FAIL: {claimed - demonstrated} claimed channel(s) not "
              "demonstrated", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
