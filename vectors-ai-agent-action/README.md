# AI Agent Action v0.1 conformance suite

## Identifiers name the bytes, not the answer

Every member of this suite is named after a digest of its own bytes and lives in
`statements/`, alongside a record sidecar in `records/` where it has one. There
is no `accept/` directory, no `reject/` directory, and no `ok-`/`bad-` prefix.
The verdict is in `MANIFEST.json`, which is where a scoring harness reads it.

This was a defect in this corpus, found by a gate in this repository, and it is
worth stating plainly rather than presenting the layout as though it had always
been this way. Measured over each vector's whole manifest-relative path, a cheap
classifier predicted accept-or-reject from the identifier alone with a
separability of 1.0000 -- a perfect score, because the prefix and the directory
each named the answer and either one alone was enough. A rail could have
certified against this suite without reading a single statement.

After the change the identifier surface measures 0.5245 against a null of
0.5245, which is to say it carries nothing: shuffling the labels produces the
same figure. The whole surface fell from 0.9238 to 0.7810.

It did not fall to chance, and the remaining gap is a second and separate defect
that this change does not fix. Most accept members carry a `contentDigest`
member and almost no reject member does, because the RFC 8785 Appendix B
number-serialization family sits entirely on the accept side with no reject
counterpart, so the presence of one member path still very nearly names the
verdict. That is content rather than naming, it measures 0.7810 against a null
of 0.6458, and closing it means writing Appendix B reject members from the same
template. It is tracked in `TODO.md`.

Identifiers are not reused. The names this corpus published before are retired
with the vectors that carried them, and no mapping from the old names to the new
ones is published: such a file would list a retired `ok-`/`bad-` name beside a
live identifier for every member, which is the surface this change removed.
Re-run the suite to get current results.


Conformance vectors for the AI Agent Action predicate proposed in
in-toto/attestation#588, tracked at `8783c6b`.

**These vectors test proposed strengthening text, not #588 as it stands.**
The accept members are conformant under the pull request's own text. The
reject members are rejectable under the proposed canonicalization text this
project offers into that pull request
(`../docs/ai-agent-action-canonicalization.md`); the text as it stands leaves
those divergences open, which is the reason the strengthening is proposed.
Any table, badge or count quoted out of this directory carries that sentence
with it: the vector count describes a suite measuring a proposal, and reading
it as a suite measuring the pull request today overstates what the pull
request currently requires.

That commit no longer resolves anywhere. It lived on
`add-ai-agent-action-predicate` in the fork `elang2/attestation`, which the pull
request is opened from and which has since been rewritten past it, so a plain
clone of that fork, of `in-toto/attestation`, or of this project's own fork all
exit 128 on it. The corpus does not depend on it: `spec-vendored/` carries the
text, `MANIFEST.json` pins its sha256, and `check_vectors.py` recomputes that
digest on every run. A commit id names bytes nobody can fetch; the digest names
bytes in this directory.

The predicate records AI agent tool invocations as observed by a protocol
intermediary, and the records form a hash chain whose genesis hash serves as the
subject digest, so a policy can target a whole audit chain. It shipped without
conformance vectors. This suite is offered into that pull request rather than
alongside it: the vectors certify its predicate, use its type URI, and are built
from its own worked example. What they certify against is the pull request's
text plus the proposed canonicalization strengthening, never the pull request's
text alone, for the reason given at the top of this file.

## Layout

| path | what it is |
|---|---|
| `accept/` | 13 members a conformant verifier accepts, with `INDEX.md` |
| `reject/` | 16 members a conformant verifier rejects for one declared reason, with `INDEX.md` |
| `records/` | JSONL sidecars, the log lines a chain hash is computed over |
| `attacks/` | the harness that produced the corpus, and its artifacts |
| `spec-vendored/` | the specification text the corpus certifies against, and the only surviving copy of it |
| `MANIFEST.json` | machine-readable expectations, counts and corpus digest |
| `gen_vectors.py` | regenerates the corpus byte-identically |
| `check_vectors.py` | self-check; exit non-zero when a member does not do what it claims |

The canonicalization text the reject members are rejectable under is
`docs/ai-agent-action-canonicalization.md`, adapted from in-toto/attestation#570.

## Why the corpus is built from attacks rather than from the schema

A vector derived from a schema tests that a parser reads the fields the schema
names. It cannot find the case the text does not cover, because it is generated
from the same reading of the text that the implementation has.

So each member here starts from an attempt to break a guarantee the predicate
claims, using only what its text actually pins. Ten of thirteen attempts
succeeded. The three that did not are recorded too, in
`attacks/artifacts/f*.json`, because an attack that fails against the text tells
you the text already closed something, and that is a result worth keeping rather
than a dead end worth deleting.

The sharpest member is the chain-fork member (`v861f20f3fa63ce2b`, condition aia-c-6). The chain forks: two records carry the same
`previousHash`, so both branches verify completely, the genesis hash and
therefore the subject digest are identical on both, and a presenter chooses which
branch an auditor is shown. No hash is broken, no second genesis appears, and no
checkpoint gap opens. Nothing in the text requires the predecessor relation to be
injective, and one sentence fixes it.

## Running it

```
python3 gen_vectors.py     # regenerate, byte-identically
python3 check_vectors.py   # self-check
python3 attacks/run_attacks.py
```

`check_vectors.py` refuses to pass a corpus in which a reject condition has no
accepting twin. A suite of rejections alone awards full marks to a verifier that
rejects every input, which is the one verifier that certifies nothing.
