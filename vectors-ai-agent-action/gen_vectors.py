#!/usr/bin/env python3
"""Generate the AI Agent Action v0.1 conformance vector suite.

Regenerate byte-identically: python3 gen_vectors.py

Ground truth: in-toto/attestation#588, spec/predicates/ai-agent-action.md at
639ec56cdbb2d7b3c9fc672adeef7fe46d995f7b.

Every member is a complete in-toto Statement. Members whose claim is about
the hash chain carry a sidecar under records/, the JSONL lines the chain hash
is computed over, because the chain hash's preimage is the underlying gateway
record and not the Statement.

A reject member here is rejectable under the canonicalization text this suite
proposes (docs/ai-agent-action-canonicalization.md), not under #588 as it
currently stands. That is the point: the divergences are constructible today
precisely because no rule forbids them, and a vector is how the rule stops
being advice.
"""

from __future__ import annotations

import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PREDICATE_TYPE = "https://in-toto.io/attestation/ai-agent-action/v0.1"
UPSTREAM_PR = "in-toto/attestation#588"
UPSTREAM_COMMIT = "639ec56cdbb2d7b3c9fc672adeef7fe46d995f7b"

for sub in ("accept", "reject", "records"):
    os.makedirs(os.path.join(HERE, sub), exist_ok=True)

MANIFEST: list[dict] = []


def jcs(obj) -> bytes:
    """RFC 8785 for the value space this suite uses.

    Every member is built from BMP strings, safe integers, booleans, null,
    objects and arrays, so lexicographic member sorting on the Python string
    and the shortest round-tripping number form coincide with JCS. Floats
    appear only inside content payloads, where they round-trip exactly.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def chain_hash(record: dict) -> str:
    return h(jcs(record))


def write(rel: str, data: bytes) -> None:
    with open(os.path.join(HERE, rel), "wb") as fh:
        fh.write(data)


def statement(subject_digest: str, predicate: dict,
              subject_name: str = "session:agent-workspace-4f2a") -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name,
                     "digest": {"sha256": subject_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def tool_call(previous_hash: str, tool: str = "create_pull_request",
              extensions: dict | None = None,
              content: dict | None = None,
              duration: int = 412, success: bool = True) -> dict:
    pred = {
        "action": {
            "type": "tool_call",
            "protocol": "mcp",
            "method": "tools/call",
            "toolName": tool,
            "timestamp": "2026-08-18T14:33:41.882Z",
            "durationMs": duration,
            "success": success,
        },
        "agent": {"principal": "svc:agent-workspace",
                  "sessionId": "sess-4f2a"},
        "parties": [{"party": "gateway", "role": "witness",
                     "scope": ["toolName", "timestamp", "durationMs"]}],
        "chain": {"previousHash": previous_hash},
        "metadata": {"attestorVersion": "example-gateway/0.4.0"},
    }
    if extensions is not None:
        pred["extensions"] = extensions
    if content is not None:
        pred["contentDigest"] = content
    return pred


def underlying(previous_hash: str, tool: str = "create_pull_request",
               extensions: dict | None = None, rid: str = "r1",
               success: bool = True) -> dict:
    rec = {
        "id": rid,
        "type": "tool_call",
        "timestamp": "2026-08-18T14:33:41.882Z",
        "toolName": tool,
        "durationMs": 412,
        "success": success,
        "previousHash": previous_hash,
    }
    if extensions is not None:
        rec["extensions"] = extensions
    return rec


def add(vid: str, kind: str, predicate: dict, subject: str,
        conditions: list[str], expected: dict, records: list[bytes] | None,
        cites: str) -> None:
    rel = f"{kind}/{vid}.json"
    write(rel, json.dumps(statement(subject, predicate), indent=2,
                          sort_keys=True, ensure_ascii=False).encode() + b"\n")
    entry = {"id": vid, "kind": kind, "file": rel,
             "conditions": conditions, "expected": expected, "cites": cites}
    if records is not None:
        rec_rel = f"records/{vid}.jsonl"
        write(rec_rel, b"\n".join(records) + b"\n")
        entry["records"] = rec_rel
    MANIFEST.append(entry)


# ---------------------------------------------------------------------------
# The canonical parent. Every member below is this record with one mutation.
# ---------------------------------------------------------------------------
EXT = {"10": "ten", "2": "two", "aa": "first", "zz": "last"}
PARENT_REC = underlying("genesis", extensions=EXT)
PARENT_HASH = chain_hash(PARENT_REC)

REQ = {"owner": "example", "repo": "widgets", "title": "Bump dependency"}
RESP_OK = {"content": [{"type": "text", "text": "opened #41"}]}
ERR = {"code": -32000, "message": "permission denied"}


# ---------------------------------------------------------------------------
# ACCEPT: the conformant twin of every reject member below.
# ---------------------------------------------------------------------------
def build_accept() -> None:
    add("ok-001-canonical-chain-hash-integer-like-keys", "accept",
        tool_call("genesis", extensions=EXT), PARENT_HASH,
        ["aia-c-1", "aia-c-2"],
        {"verdict": "valid", "chainHash": PARENT_HASH},
        [jcs(PARENT_REC)],
        "canonicalization: member ordering is JCS, never the host language's "
        "property order")

    rec = underlying("genesis", tool="creer_fichier_été")
    add("ok-002-canonical-chain-hash-non-ascii", "accept",
        tool_call("genesis", tool="creer_fichier_été"),
        chain_hash(rec), ["aia-c-3"],
        {"verdict": "valid", "chainHash": chain_hash(rec)}, [jcs(rec)],
        "canonicalization: JCS emits the character, never a \\u escape")

    add("ok-003-log-line-equals-canonical-bytes", "accept",
        tool_call("genesis", extensions=EXT), PARENT_HASH,
        ["aia-c-4"],
        {"verdict": "valid", "chainHash": PARENT_HASH}, [jcs(PARENT_REC)],
        "canonicalization: the log line IS the canonical bytes, so the two "
        "readings of the preimage coincide")

    add("ok-004-unique-members", "accept",
        tool_call("genesis", tool="read_file"),
        chain_hash(underlying("genesis", tool="read_file")),
        ["aia-c-5"],
        {"verdict": "valid",
         "chainHash": chain_hash(underlying("genesis", tool="read_file"))},
        [jcs(underlying("genesis", tool="read_file"))],
        "canonicalization: I-JSON, no duplicate member at any depth")

    # A linear three-record chain: the predecessor relation is injective.
    r1 = underlying("genesis", tool="list_files", rid="r1")
    h1 = chain_hash(r1)
    r2 = underlying(h1, tool="read_config", rid="r2")
    h2 = chain_hash(r2)
    r3 = underlying(h2, tool="create_pull_request", rid="r3")
    add("ok-005-linear-chain-single-head", "accept",
        tool_call(h2), h1, ["aia-c-6", "aia-c-7"],
        {"verdict": "valid", "chainHash": chain_hash(r3), "records": 3},
        [jcs(r1), jcs(r2), jcs(r3)],
        "chain shape: exactly one record carries any given previousHash")

    ck = {"id": "ckpt_1", "type": "checkpoint",
          "timestamp": "2026-08-18T14:33:42.101Z",
          "previousHash": PARENT_HASH,
          "sequence": 1, "recordCount": 1}
    ck_pred = {
        "action": {"type": "checkpoint",
                   "timestamp": "2026-08-18T14:33:42.101Z"},
        "chain": {"previousHash": PARENT_HASH},
        "checkpoint": {"sequence": 1, "recordCount": 1,
                       "previousHash": PARENT_HASH},
        "parties": [{"party": "gateway", "role": "witness",
                     "scope": ["sequence", "recordCount", "previousHash"]}],
        "metadata": {"attestorVersion": "example-gateway/0.4.0"},
    }
    add("ok-006-checkpoint-carries-chain-link", "accept", ck_pred,
        PARENT_HASH, ["aia-c-8"],
        {"verdict": "valid", "chainHash": chain_hash(ck)},
        [jcs(PARENT_REC), jcs(ck)],
        "chain shape: every record type links through predicate.chain")

    content = {"request": {"sha256": h(jcs(dict(REQ, temperature=0.7)))},
               "response": {"sha256": h(jcs(RESP_OK))}}
    add("ok-007-float-in-content-payload-only", "accept",
        tool_call("genesis", content=content), PARENT_HASH,
        ["aia-c-9"],
        {"verdict": "valid"}, None,
        "canonicalization: the safe-integer profile binds signed record "
        "fields; content payloads are JCS and admit floats")

    err_content = {"request": {"sha256": h(jcs(REQ))},
                   "response": {"sha256": h(jcs(ERR))}}
    err_rec = underlying("genesis", tool="delete_branch", success=False)
    add("ok-008-error-response-digest-over-error-member", "accept",
        tool_call("genesis", tool="delete_branch", content=err_content,
                  success=False),
        chain_hash(err_rec), ["aia-c-10"],
        {"verdict": "valid", "responseDigest": err_content["response"]["sha256"]},
        [jcs(err_rec)],
        "content digest: a failed call digests the error member, named "
        "explicitly rather than left to the reader")

    add("ok-009-previoushash-lowercase-64-hex", "accept",
        tool_call(PARENT_HASH), PARENT_HASH, ["aia-c-11"],
        {"verdict": "valid"}, None,
        "chain shape: previousHash is lowercase 64-hex or the literal genesis")

    add("ok-010-extensions-depth-128", "accept",
        tool_call("genesis", extensions=nested(128)), PARENT_HASH,
        ["aia-c-12"], {"verdict": "valid"}, None,
        "bounds: 128 is admissible; the counting rule is #570's")

    # The twin of bad-113. A surrogate PAIR is one supplementary-plane
    # character and is well formed; only a lone half is not.
    pair_rec = underlying("genesis", tool="deploy_\U0001F680")
    add("ok-011-paired-surrogate-in-toolname", "accept",
        tool_call("genesis", tool="deploy_\U0001F680"),
        chain_hash(pair_rec), ["aia-c-13"],
        {"verdict": "valid", "chainHash": chain_hash(pair_rec)},
        [jcs(pair_rec)],
        "strings: the rule excludes an unpaired half, never a valid "
        "supplementary-plane character, so a verifier that rejects both is "
        "over-rejecting")

    # The twin of bad-115: the largest value the profile admits.
    add("ok-012-largest-safe-integer-durationms", "accept",
        tool_call("genesis", duration=2 ** 53 - 1), PARENT_HASH,
        ["aia-c-14"], {"verdict": "valid"}, None,
        "bounds: 2^53 - 1 is admissible, so the boundary is exercised from "
        "both sides rather than assumed")


def nested(levels: int):
    """An object whose own outermost brace is depth 1 and whose innermost
    open container is depth `levels`, matching #588's counting rule."""
    node: object = "leaf"
    for _ in range(levels):
        node = {"n": node}
    return node


# ---------------------------------------------------------------------------
# REJECT: one declared fault each.
# ---------------------------------------------------------------------------
def build_reject() -> None:
    # A1: ECMAScript hoists canonical numeric member names to the front.
    js_order = {"2": "two", "10": "ten", "zz": "last", "aa": "first"}
    js_rec = dict(PARENT_REC)
    js_rec["extensions"] = js_order
    js_bytes = json.dumps(js_rec, separators=(",", ":"),
                          ensure_ascii=False).encode()
    add("bad-101-chain-hash-ecmascript-member-order", "reject",
        tool_call("genesis", extensions=EXT), h(js_bytes),
        ["aia-c-1"], {"verdict": "invalid", "codes": ["chain-hash-mismatch"]},
        [js_bytes],
        "A1: JSON.stringify orders 2 before 10 and leaves zz before aa; JCS "
        "orders 10, 2, aa, zz. Three languages, three chain hashes.")

    # A2: escaping policy.
    esc_rec = underlying("genesis", tool="creer_fichier_été")
    esc_bytes = json.dumps(esc_rec, separators=(",", ":"),
                           ensure_ascii=True).encode()
    add("bad-102-chain-hash-ascii-escaped-string", "reject",
        tool_call("genesis", tool="creer_fichier_été"),
        h(esc_bytes), ["aia-c-3"],
        {"verdict": "invalid", "codes": ["chain-hash-mismatch"]}, [esc_bytes],
        "A2: a producer whose serializer defaults to ASCII escaping emits "
        "different bytes for the same string")

    html_rec = underlying("genesis", tool="run<script>")
    html_bytes = (json.dumps(html_rec, separators=(",", ":"),
                             ensure_ascii=False)
                  .replace("<", "\\u003c").replace(">", "\\u003e")
                  .encode())
    add("bad-103-chain-hash-html-escaped-string", "reject",
        tool_call("genesis", tool="run<script>"), h(html_bytes),
        ["aia-c-3"], {"verdict": "invalid", "codes": ["chain-hash-mismatch"]},
        [html_bytes],
        "A2b: Go's encoding/json escapes <, > and & by default, so a Go "
        "gateway and a Node gateway disagree on identical input")

    # A3: the log line carries insignificant whitespace.
    ws_bytes = json.dumps(PARENT_REC, separators=(", ", ": "),
                          ensure_ascii=False).encode()
    add("bad-104-log-line-not-canonical-bytes", "reject",
        tool_call("genesis", extensions=EXT), h(ws_bytes),
        ["aia-c-4"], {"verdict": "invalid", "codes": ["noncanonical-bytes"]},
        [ws_bytes],
        "A3: the record parses identically and hashes differently; any log "
        "shipper that reserializes produces this")

    # A4: duplicate member.
    dup = (b'{"durationMs":412,"id":"r1","previousHash":"genesis",'
           b'"success":true,"timestamp":"2026-08-18T14:33:41.882Z",'
           b'"toolName":"read_file","toolName":"delete_repository",'
           b'"type":"tool_call"}')
    add("bad-105-duplicate-member-toolname", "reject",
        tool_call("genesis", tool="read_file"), h(dup),
        ["aia-c-5"], {"verdict": "invalid", "codes": ["duplicate-member"]},
        [dup],
        "A4: a first-wins reader displays read_file while the hash commits "
        "to delete_repository")

    # A5: the chain forks.
    f1 = underlying("genesis", tool="list_files", rid="r1")
    fh1 = chain_hash(f1)
    f2a = underlying(fh1, tool="read_secrets", rid="r2a")
    f2b = underlying(fh1, tool="create_pull_request", rid="r2b")
    add("bad-106-chain-fork-shared-previoushash", "reject",
        tool_call(fh1), fh1, ["aia-c-6"],
        {"verdict": "invalid", "codes": ["chain-fork"]},
        [jcs(f1), jcs(f2a), jcs(f2b)],
        "A5: two records carry one previousHash. Every hash verifies, the "
        "genesis hash and therefore the subject digest are unchanged, and "
        "the presenter chooses which branch the auditor sees.")

    ck_nolink = {"id": "ckpt_1", "type": "checkpoint",
                 "timestamp": "2026-08-18T14:33:42.101Z",
                 "sequence": 1, "recordCount": 1,
                 "previousHash": PARENT_HASH}
    ck_pred = {
        "action": {"type": "checkpoint",
                   "timestamp": "2026-08-18T14:33:42.101Z"},
        "checkpoint": {"sequence": 1, "recordCount": 1,
                       "previousHash": PARENT_HASH},
        "metadata": {"attestorVersion": "example-gateway/0.4.0"},
    }
    succ = underlying(PARENT_HASH, tool="create_pull_request", rid="r2")
    add("bad-107-checkpoint-omitted-from-chain", "reject", ck_pred,
        PARENT_HASH, ["aia-c-8"],
        {"verdict": "invalid", "codes": ["checkpoint-not-linked"]},
        [jcs(PARENT_REC), jcs(ck_nolink), jcs(succ)],
        "A6: the successor chains past the checkpoint to the record before "
        "it, so the checkpoint is deletable and the anti-truncation "
        "mechanism carries no weight")

    float_rec = dict(PARENT_REC)
    float_rec["durationMs"] = 412.5
    add("bad-108-float-in-signed-record-field", "reject",
        tool_call("genesis", extensions=EXT, duration=412),
        chain_hash(float_rec), ["aia-c-9"],
        {"verdict": "invalid", "codes": ["non-integer-in-signed-field"]},
        [jcs(float_rec)],
        "A7: the safe-integer profile binds signed record fields; the "
        "content-digest form is where a float belongs")

    err_null = {"request": {"sha256": h(jcs(REQ))},
                "response": {"sha256": h(b"null")}}
    err_rec = underlying("genesis", tool="delete_branch", success=False)
    add("bad-109-error-response-digest-over-null", "reject",
        tool_call("genesis", tool="delete_branch", content=err_null,
                  success=False),
        chain_hash(err_rec), ["aia-c-10"],
        {"verdict": "invalid", "codes": ["content-digest-mismatch"]},
        [jcs(err_rec)],
        "A8: one of four readings a verifier could take of an absent result "
        "member, and the only one this suite forbids by naming the other")

    add("bad-110-previoushash-uppercase-hex", "reject",
        tool_call(PARENT_HASH.upper()), PARENT_HASH, ["aia-c-11"],
        {"verdict": "invalid", "codes": ["previoushash-not-canonical"]}, None,
        "A9: a case-normalizing verifier links it and a byte-comparing one "
        "does not, so the same logical link has two spellings")

    add("bad-111-previoushash-wrong-length", "reject",
        tool_call("da39a3ee5e6b4b0d3255bfef95601890afd80709"), PARENT_HASH,
        ["aia-c-11"],
        {"verdict": "invalid", "codes": ["previoushash-not-canonical"]}, None,
        "A9b: 40 hex digits. Nothing in the current text excludes a digest "
        "from another algorithm")

    g1 = underlying("genesis", tool="list_files", rid="r1")
    brk = {"id": "brk_1", "type": "chain_break",
           "timestamp": "2026-08-18T15:01:00.000Z",
           "reason": "crash_recovery", "priorHead": chain_hash(g1)}
    g2 = underlying("genesis", tool="create_pull_request", rid="r2")
    add("bad-112-second-genesis-after-break", "reject",
        tool_call("genesis"), chain_hash(g1), ["aia-c-7"],
        {"verdict": "invalid", "codes": ["duplicate-genesis"]},
        [jcs(g1), jcs(brk), jcs(g2)],
        "F3: the successor of a break restarts at genesis instead of "
        "chaining from the break, discarding the scar. #588 makes detection "
        "SHOULD; this member makes it MUST")

    sur = ('{"id":"r1","previousHash":"genesis","toolName":"bad\\ud800",'
           '"type":"tool_call"}').encode()
    add("bad-113-unpaired-surrogate-in-toolname", "reject",
        tool_call("genesis", tool="bad"), h(sur), ["aia-c-13"],
        {"verdict": "invalid", "codes": ["ill-formed-string"]}, [sur],
        "F2: already forbidden by #588's own text. The vector is what stops "
        "the rule from being advice")

    add("bad-114-extensions-depth-129", "reject",
        tool_call("genesis", extensions=nested(129)), PARENT_HASH,
        ["aia-c-12"], {"verdict": "invalid", "codes": ["depth-exceeded"]},
        None,
        "bounds: one level past the stated cap, so the counting rule is "
        "exercised rather than assumed")

    add("bad-115-unsafe-integer-durationms", "reject",
        tool_call("genesis", duration=9007199254740993), PARENT_HASH,
        ["aia-c-14"], {"verdict": "invalid", "codes": ["unsafe-integer"]},
        None,
        "bounds: 2^53 + 1, the first value the I-JSON profile excludes")


def main() -> None:
    build_accept()
    build_reject()
    counts = {"accept": sum(1 for m in MANIFEST if m["kind"] == "accept"),
              "reject": sum(1 for m in MANIFEST if m["kind"] == "reject")}
    corpus = h(b"".join(
        open(os.path.join(HERE, m["file"]), "rb").read()
        for m in sorted(MANIFEST, key=lambda m: m["id"])))
    manifest = {
        "suite": "ai-agent-action-conformance",
        "predicateType": PREDICATE_TYPE,
        "tracksUpstream": UPSTREAM_PR,
        "specUpstreamCommit": UPSTREAM_COMMIT,
        "proposedText": "docs/ai-agent-action-canonicalization.md",
        "counts": counts,
        "corpusDigest": corpus,
        "note": "A reject member is rejectable under the proposed "
                "canonicalization text, not under #588 as it stands. Each "
                "accept member is the conformant twin of the reject member "
                "sharing its condition, so a verifier that rejects "
                "everything scores zero rather than full marks.",
        "vectors": sorted(MANIFEST, key=lambda m: m["id"]),
    }
    write("MANIFEST.json",
          json.dumps(manifest, indent=2, ensure_ascii=False).encode() + b"\n")
    print(json.dumps(counts), "corpusDigest", corpus)


if __name__ == "__main__":
    main()
