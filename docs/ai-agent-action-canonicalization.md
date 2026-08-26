# Canonicalization text offered into in-toto/attestation#588

This is specification prose, written to be dropped into
`spec/predicates/ai-agent-action.md` in place of its current `### Canonicalization`
and `### Genesis and chain continuity` sections. It is adapted from the
canonicalization and bounds text in in-toto/attestation#570, which fought the same
question out over several rounds and settled it.

The conformance members that exercise every rule below live in
`vectors-ai-agent-action/`, and `check_vectors.py` refuses to pass a corpus in which
any rejecting member lacks an accepting twin.

What changed in adapting #570's text to #588:

- #570 canonicalizes a Statement; #588 canonicalizes an underlying gateway record
  that lives outside the Statement, so the identical-bytes requirement had to be
  restated as a relationship between the log line and the recomputed form rather
  than as a property of one document.
- #570 has no hash chain, so the injective-predecessor rule, the single-head rule
  and the checkpoint linkage rule are new here and have no counterpart there.
- #570's depth bound, safe-integer profile, duplicate-member rule and
  well-formed-string rule carry over almost verbatim, because #588 already cites
  #570 for the depth counting rule and the safe-integer bound and the wording
  should not fork.
- #588's two-form split is kept. The change is that the signing form's field list
  becomes part of the specification rather than part of an implementation, and the
  chain hash stops being a third, unnamed form.

---

## Canonicalization

This predicate uses two canonical forms, and the boundary between them is drawn by
what a party signs rather than by what a party stores. Every byte string any rule
below hashes is named exactly once, so that two implementations reading only this
document derive identical bytes from identical observations.

### The record canonical form

The record canonical form is the RFC 8785 (JCS) canonicalization of the audit
record object, encoded as UTF-8. Object members are sorted by UTF-16 code unit,
numbers take the shortest form that round-trips under IEEE 754, and no
insignificant whitespace appears. A producer MUST write each JSONL line as exactly
these bytes, and a verifier MUST recompute the form from the parsed record and MUST
reject, fail-closed, any line whose bytes differ from the recomputation.

That last obligation is the one that cannot be dropped. Without it the preimage has
two readings, the bytes on disk and the re-serialization of the parsed object, and
they coincide only by accident. Any log shipper that reparses and re-emits JSON
moves a verifier from one reading to the other while every field value stays
identical, so a chain that verified before the shipper ran fails after it.

`JSON.stringify` MUST NOT be used to derive any hashed byte string. It is not a
canonical form and it is not portable. ECMAScript orders canonical numeric property
names ahead of every other name and in ascending numeric order regardless of
insertion order, so an `extensions` object whose members are `10`, `2`, `aa`, `zz`
serializes as `2, 10, zz, aa` in a JavaScript gateway, as `10, 2, zz, aa` in a
Python gateway that preserves insertion order, and as `10, 2, aa, zz` in a Go
gateway, whose `encoding/json` sorts map keys. That is three chain hashes for one
observation, and none of the three implementations has done anything wrong. JCS
fixes the order to `10, 2, aa, zz` for all of them.

String escaping is fixed by the same rule. JCS emits a character rather than an
escape wherever the character is permitted, so a serializer whose default is
ASCII-escaping output, and a serializer that escapes `<`, `>` and `&`, both produce
non-canonical bytes and both are rejected. Neither behaviour is exotic: the first
is Python's default and the second is Go's.

### The content digest form

Content digests bind MCP payloads without inlining them. They use RFC 8785 over the
payload, and the digest is the lowercase 64-hex SHA-256 of those bytes.

`contentDigest.request` is the digest of the JSON-RPC `params` member. For
`contentDigest.response` the preimage depends on which JSON-RPC response arrived. A
success response carries a `result` member and the digest is over that member. An
error response carries no `result` member at all, and the digest is over the `error`
member. A record with `action.success` false is by construction an error response,
so this is not an edge case: it is every failed tool call, which is the half of an
audit trail an investigator reaches for first. A producer MUST NOT digest `null`,
an empty object, or the whole response envelope in place of the named member.

Floats are permitted here and only here. MCP tool payloads are arbitrary JSON and
routinely carry them.

### The signing canonical form

The signing canonical form is the tuple-array this predicate already defines: an
ordered array of `[field-name, value]` pairs in which objects become
`["M", [[key, value], ...]]` with keys sorted by UTF-16 code unit, arrays become
`["L", [value, ...]]`, and scalars pass through untagged.

The field list and its order are part of this specification. An implementation
MUST build the tuple from exactly the following fields, in exactly this order,
omitting an absent optional field rather than encoding it as null:

    id, type, timestamp, toolName, namespace, durationMs, success,
    errorCode, errorClass, previousHash, contentDigestRequest,
    contentDigestResponse, extensionsDigest, attestorVersion, configHash

A form whose input list lives in an implementation's type definition is not a
specification of anything. A second implementer can reproduce the tagging rules,
the sort order and the tags exactly and still reproduce no signature at all, and no
conformance vector can be written for it, because a vector needs a preimage the
text determines.

Numbers in the signing form MUST be safe integers: magnitude below 2^53, per RFC
7493 section 2.2. This constraint binds the signing form and the record canonical
form. It does not bind content payloads, which is why the content digest form
exists.

### Strict I-JSON, statement-wide

The whole record and the whole Statement are parsed as strict I-JSON.

A duplicate member anywhere, at any depth, makes the record malformed, and a
verifier MUST reject it fail-closed. A lenient parser that keeps the last of a
repeated member lets a record carry `"toolName": "read_file"` and
`"toolName": "delete_repository"` at once: a first-wins reader shows the auditor
the harmless call while the hash commits to the destructive one, and both readers
believe the chain intact.

Every string literal MUST be a well-formed sequence of Unicode scalar values, in
member-name and value position alike. The record MUST be valid UTF-8 with no
overlong form and no surrogate encoded directly in UTF-8; a `\u` escape naming a
high surrogate MUST be immediately followed by one naming a low surrogate, and an
unpaired escape of either half is malformed; a `\u` escape MUST be exactly four
hexadecimal digits with no sign, whitespace or radix prefix; a string MUST NOT
carry a raw unescaped character below U+0020; and the Unicode noncharacters, U+FDD0
through U+FDEF and U+nFFFE and U+nFFFF in every plane, are excluded. A verifier
MUST apply this to the raw bytes before any decoded string is read, because a
lenient decoder does not fail on ill-formed input, it substitutes U+FFFD, and every
check after that point reads a string the producer never wrote.

A valid surrogate pair is one supplementary-plane character and is well formed. A
verifier that rejects it is over-rejecting.

A verifier MUST reject, fail-closed, a record whose JSON nesting depth exceeds 128.
Depth is the number of arrays and objects open at a point, counting the outermost
brace as depth 1; scalars do not increase it. The bound is normative rather than a
resource limit, because with no bound stated two conforming verifiers disagree
about whether identical bytes are evidence at all across the whole range between
their private choices.

## Chain shape

### The chain hash

The chain hash of a record is the lowercase 64-hex SHA-256 of that record's canonical
form as defined above, including its attestation signature member. The next record
carries it as `previousHash`.

`previousHash` is either lowercase 64-hex or the literal lowercase string `genesis`,
and nothing else. Uppercase hex is not canonical. A digest of any other length is
not admissible, and there is no algorithm agility in this field at v0.1; a future
version that needs another algorithm adds an algorithm member rather than widening
what this one accepts. Without this, a verifier that folds hex case treats two
distinct byte strings as one link while the two successors carrying them hash
differently, so the same logical chain has two identities.

### One head, and one predecessor

Exactly one record in a chain MUST carry any given `previousHash` value. A verifier
MUST reject, fail-closed, a log in which two records share one, and MUST reconstruct
the chain as a strict walk from the genesis record rather than by checking that each
record's `previousHash` appears somewhere in the presented set.

This is the rule that makes the chain a chain. Nothing in a hash link forbids a
fork: two records may each chain from record one, and every hash in both branches
verifies. Since the subject digest is the genesis hash, both branches carry the same
subject digest and a policy targeting the chain cannot distinguish them. A presenter
holding a four-record chain can therefore present a two-record branch that omits
whichever calls it prefers an auditor not see, with no hash broken, no second
genesis, and no gap in sequence for a checkpoint to catch. Set-membership
verification accepts it; a strict walk plus the injectivity rule does not.

### Every record type is on the chain

`checkpoint` and `chain_break` records carry `predicate.chain.previousHash` exactly
as `tool_call` records do, and the record following any record of any type carries
that record's chain hash. `predicate.checkpoint.previousHash` restates the chain
head for the consumer that externalizes it and is not the linkage; the linkage is
always `predicate.chain.previousHash`.

Stating this for `chain_break` alone leaves the checkpoint off the chain the fields
table defines. A verifier walking the documented linkage field steps past every
checkpoint, so a checkpoint can be removed without breaking any documented link, and
the checkpoint is the entire mechanism standing between this predicate and silent
tail truncation.

`predicate.chain` is REQUIRED on every record that is part of a chain. A record
emitted with no chain object stands alone, and a verifier MUST NOT treat it as
evidence about any chain, including one whose genesis hash its subject names.

### Genesis and breaks

The literal `genesis` appears as `previousHash` exactly once in a chain's lifetime,
on the first record. After a `chain_break`, the successor carries the break record's
chain hash, never `genesis`, which binds the discontinuity into the successor chain
so that discarding the break record breaks linkage.

A verifier MUST reject, fail-closed, a log in which `genesis` appears more than
once. This is a MUST and not a SHOULD. A detection obligation a conformant verifier
may decline is not a defence against an adversary who is choosing which verifier to
present to.
