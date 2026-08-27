# AI Agent Action v0.1 conformance suite

Conformance vectors for the AI Agent Action predicate proposed in
in-toto/attestation#588, tracked at `639ec56`.

The predicate records AI agent tool invocations as observed by a protocol
intermediary, and the records form a hash chain whose genesis hash serves as the
subject digest, so a policy can target a whole audit chain. It shipped without
conformance vectors. This suite is offered into that pull request rather than
alongside it: the vectors certify its predicate, use its type URI, and are built
from its own worked example.

## Layout

| path | what it is |
|---|---|
| `accept/` | 13 members a conformant verifier accepts, with `INDEX.md` |
| `reject/` | 16 members a conformant verifier rejects for one declared reason, with `INDEX.md` |
| `records/` | JSONL sidecars, the log lines a chain hash is computed over |
| `attacks/` | the harness that produced the corpus, and its artifacts |
| `spec-vendored/` | the specification text at the commit the corpus certifies against |
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

The sharpest member is `bad-106`. The chain forks: two records carry the same
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
