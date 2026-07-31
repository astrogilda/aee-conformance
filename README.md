<p align="center">
  <img src=".github/assets/banner.svg" alt="aee-conformance" width="820">
</p>

<p align="center">
  <a href="https://github.com/astrogilda/aee-conformance/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/astrogilda/aee-conformance/ci.yml?branch=main&label=build" alt="build status"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0">
  <img src="https://img.shields.io/badge/conformance%20vectors-220-e8951c" alt="220 conformance vectors">
  <img src="https://img.shields.io/badge/rails-Go%20%C2%B7%20Python-546274" alt="Go and Python rails">
  <img src="https://img.shields.io/badge/predicate-in--toto%20AEE%20v0.7-6f57c2" alt="in-toto AEE v0.7 predicate">
</p>

A recomputable execution attestation toolkit for the in-toto Adversarial
Execution Evidence predicate, version 0.7.

The predicate's model is execute-and-attest, not match-and-assert: the
consumer recomputes the outcome from carried bytes instead of trusting a
producer-asserted verdict. This repository is a second, independently usable
implementation of that contract: any future producer of the predicateType
can self-certify; any consumer can reject a lying emitter.

Spec line references throughout the code are to the vendored predicate
specification (`spec/predicates/adversarial-execution-evidence.md`), in the
coordinate frame of the commit it was vendored at and no other. That commit is
recorded in [`spec/VENDOR-PIN.json`](spec/VENDOR-PIN.json), written from git at
vendor time rather than by hand, and re-vendoring remaps every reference onto
the new line numbers in the same pass that copies the bytes.

Two gates keep the references honest, because line numbers into a file that is
periodically re-vendored rot by construction and a reference that points at the
wrong prose reads as evidence. `scripts/spec-citation-gate.py` covers the
`spec:NNN` citations in the sources and `scripts/spec-anchor-gate.py` covers the
`Lnnn` anchors in the vector tables. Both ask the same two questions, and the
second is the one that matters: not only whether a reference still resolves to a
line carrying text, which a stale number does perfectly well, but whether it
still addresses the prose it was written for.
[`spec/CITATION-PINS.json`](spec/CITATION-PINS.json) and
[`spec/ANCHOR-PINS.json`](spec/ANCHOR-PINS.json) record the text each reference
was drawn around, keyed by the thing doing the citing rather than by the line
range, so a reference that comes to address different prose fails rather than
resolving quietly. The shared machinery is `scripts/specpins.py`.

Both ledgers are refreshed by the same command that re-vendors, which is the one
operation that moves references, so they also have to be trustworthy across
their own refresh. A refresh refuses to record a reference that came off prose
the document still contains: upstream may rewrite a passage freely and the
excerpt follows it, but a remap that simply lost track of a passage stops the
vendoring and names what it lost. A move onto genuinely different prose is still
allowed, one citation at a time and by name, because no gate can read a claim
and judge which paragraph settles it.

## Layout

```
go.mod                      core module (stdlib-only, enforced by test)
aee/                        the verification core
  statement.go              GATE 0: statement well-formedness
  validity.go               GATE 1: coverage validity (consumption precondition)
  recompute.go              pure result recompute
  tier.go                   GATE 2: evidence tier {declared|unattested|attested}
  runbinding.go             run-binding v1: exactly ONE construction, fail-closed on others
  merkle.go                 RFC 6962: domain-separated, recursive split, duplicate-reject
  pae.go                    DSSE PAEv1 + digest helpers
  jcs.go                    RFC 8785 canonicalization + RFC 7493 I-JSON checks (stdlib)
  types.go / codes.go       parsed statement model + the closed failure-code set
  *_test.go                 unit tests, known answers, the conformance-vector runner
aeetest/                    deterministic synthetic statement builder (derived TEST keys)
cmd/aee-verify/             consumer CLI: gate0 → gate1 → recompute → tier table
cmd/mutgen/                 forcing measurement: enumerate + apply one weakening at a time
cmd/mutrun/                 forcing measurement: replay the whole corpus in process
witnessattestor/            SEPARATE module: the go-witness attestor + library-mode demo
go.work.example             wiring for building the attestor module (see BUILD-NOTES.md)
```

## The verification pipeline

<p align="center">
  <img src=".github/assets/pipeline.svg" alt="A signed statement passes four byte-pure gates (well-formedness, coverage validity, result recompute, evidence tier) to a verdict; any gate fails closed with no result and no tiers." width="380">
</p>

Four byte-pure gates plus a consumer-relative evidence tier. Any gate fails
closed: no result, no tiers. The full contract, step by step:

1. GATE 0: statement well-formedness. Statement `_type` and
   `predicateType` (fail-closed: exactly one accepted construction, no
   cross-version fallback), result vocabulary, environment members,
   vocabulary shape/subset/digest, corpus manifest digest and duplicate
   attack ids, coverage integrity at attack granularity, per-row
   `actualLayer` altitude, subject cardinality and digest canonicality for
   substrate-carrying statements, `runEntropy` presence, `issuedAt`.
2. GATE 1: coverage validity. Statement-level record checks run first
   (batchRoot presence/recompute over RFC 6962 with domain separation and
   no pad-last-node, duplicate-record rejection, orphaned-root), then per
   `basis: substrate` row: refs resolve and are in range, referenced
   payloads are canonical RFC 8785 + I-JSON `+json` objects carrying the
   reserved members with a run binding equal to the derived one,
   class-match per `aeeKind` with each kind's constraints (arming armedAt
   and posture, sealed still-armed/drop-bound/joint posture equalities,
   examination method), and the row `method` capped by the weakest signed
   `aeeMethod` across covering records. On any failure the attestation is
   invalid and its `result` is never consumed; the report carries no
   result and no tiers.
3. Recompute equality. The carried `result` must equal the pure recompute
   over carried bytes; the recompute reads no records, no signature
   outcomes, no consumer policy.
4. GATE 2: evidence tier. Per row: `declared` (artifact basis), `attested`
   (every covering record verifies against a consumer-pinned substrate
   observation key), else `unattested`. No pinned key means every
   substrate row is `unattested`; the substrate root is never inferred
   from the predicate. A record's `keyid` is a lookup hint, never the
   check, and the tier never alters `result`.

## The failure-code contract

Every rejection carries a stable machine-readable code (`aee/codes.go`).
The deterministic primary code (first in pinned detection order) is the
conformance contract; message text and code order beyond the primary one
are not. A few precedence pins matter to anyone reimplementing the gates.
A missing binding input reports its own member code
(`run-entropy-missing`, `subject-sha256-missing`), not
`run-binding-mismatch`; that code is reserved for values that can be
derived but come out unequal. `records-absent` fires when
`observationRecords` is missing entirely, and `ref-out-of-range` fires
only once records exist. The method cap reads covering records only, so
records that cover nothing do not participate, and the two sealed posture
equalities (pinned digest, arming record's claim) are enforced jointly,
not independently. Signature *verification* failure is never a failure
code; it is a tier outcome. The one signature-shaped question the
byte-pure layer does answer is how many entries the array carries: a
record with zero of them (`record-signatures-empty`) is malformed, since
counting entries needs no key material. An absent member, an empty array
and a member that is not an array at all are that one fault counted three
ways, and the count is asked once over the record set before any payload
is decoded, so a record carrying no signature is settled ahead of a record
whose payload does not decode. That last sentence is this rail's READING and
not a rule the specification states, and it is the one place where saying so
required a third kind of vector; see Indeterminate vectors below.

### What the suite compares

`packaging/run_vectors.py` runs an external verifier as `<cmd> <vector-file>`,
reads the verdict from the exit status, and reads the codes, the recomputed
result and the tiers from the last line of stdout when that line is a JSON
object of the shape `{"verdict": ..., "codes": [...], "result": ...,
"tiers": [...]}`. `--verifier` takes a command line rather than a path, so a
rail whose machine-readable output sits behind a flag needs no wrapper. One
further member is read and is OPTIONAL: `primaryCode`, the single condition the
rail reports when several hold. Nothing in the accept or reject contract reads
it, because that contract compares code sets and says so below; the
indeterminate families read it and a rail that omits it is recorded as having
committed to no reading rather than as failing.

That object has to be **one line**. The harness reads the last line and parses
that line alone, so an indented encoding delivers a line reading `}` and the run
degrades to the exit status, which as the next paragraph says fails every vector
in the suite. This is not a hypothetical: `cmd/aee-verify -json` wrote
`json.MarshalIndent` for as long as the flag existed, and the first time the CLI
this repository ships was pointed at the corpus this repository ships it scored
0 of 186. `scripts/external-rail-gate.py` now runs that exact pairing in CI, and
a clean sweep by the shipped CLI is the gate.

Each vector is run **twice**, through identical argv. The consumer key policy
travels in the environment variable `AEE_SUBSTRATE_KEYS`, holding a path to
`{"substrateObservationKeys": [{"keyid": ..., "publicKeyHex": ...}]}`; argv is
fixed by the contract, so naming a flag would dictate a spelling to every rail
while naming a variable dictates only where to look. The pinned pass answers
`expected.tierWithPinnedKey` and the unset pass answers
`expected.tierWithoutKey`. Two rules only the second pass can ask about are what
the second pass is for: GATE 2's no-TOFU rule, that a consumer with no pinned
key derives `unattested` for every substrate row and never infers the substrate
root from the predicate, and the rule that deriving a tier never moves
`result`. Before the variable existed there was no key channel at all, the
harness recorded `tiers_without_key: None` for every external run, and the
evaluator skips a column it was handed nothing for -- so `ok-024`'s
`tierWithoutKey` read in the MANIFEST as a requirement on every implementation
while binding two first-party rails and nothing else.

What it compares against `vectors/MANIFEST.json` is not the verdict alone. A reject
vector's manifest entry declares an expected code set, and the codes the
implementation emits must intersect it, so a verifier that rejects a statement
for no stated reason fails the vector. An accept vector's entry declares a
`result`, and the recomputed result must equal it. An implementation that answers
with an exit status and nothing else therefore fails every vector in the suite.
That is worth stating plainly, because the runner's own description of its
external rail said the opposite for several revisions, and nothing was checking
the description against the evaluator it described.

The codes are compared as a set. Order carries nothing and message text carries
nothing, so a verifier that reports the first fault it finds and one that reports
every fault it finds both pass the same entry. That is what lets a strict
single-code implementation and a superset-emitting one certify against one
manifest. It is also why the optional `primaryCode` exists rather than the
harness reading the first entry of the set: a harness that inferred precedence
from an order this paragraph tells rails to ignore would be enforcing a rule the
corpus disclaims.

An implementation that would rather keep its own reject reasons is not shut out
of the corpus. It can emit a report in its own vocabulary and compare that report
against a recorded run of itself, which is how the independent checker described
below verifies parity without ever reading these codes. What that route does not
give is the per-condition comparison: two verifiers can agree on every verdict
and still disagree about which condition each statement violated, and that
disagreement stays invisible until the codes are compared. Two of the divergences
this suite has fixed were exactly that shape.

### The registry

The codes are this suite's registry rather than the specification's. The
specification states the conditions and says nothing about what a verifier should
call them, so the spellings, the precedence pins above, and the promise that
neither of those moves are all contracts this repository carries and not that
document. `aee/codes.go` is the enumerated set.

Adding a code takes four things, and `scripts/code-contract-gate.py` checks the
last three mechanically:

- a condition the specification states that no existing code already names;
- a constant in `aee/codes.go`, in the block for the gate that detects it;
- the same spelling in the Python rail, so the two first-party rails share one
  vocabulary rather than two that happen to agree;
- at least one vector that emits it, which bumps `suiteRevision`.

What the registry guarantees:

- a published code's spelling never changes, and neither does the condition it
  names. A changed condition is a new code, not a redefined one;
- a code is never removed while any published `suiteRevision` names it;
- codes are additive across revisions, so a verifier that recognises the set at
  one revision still recognises it at the next;
- precedence is contractual only where this README pins it. Where two conditions
  can hold at once and nothing here decides which is reported, either is
  conformant — and that no longer means no vector. It means an INDETERMINATE
  vector, which declares every reading a conformant rail may take and holds the
  rail to one of them rather than to ours. The reasoning behind each open
  question still lives in `docs/interpretation-decisions-open.md`;
- message text is never part of the contract, at any revision.

### Indeterminate vectors

Two buckets can make two claims. `accept/` says every conformant verifier admits
these bytes and recomputes this result; `reject/` says every conformant verifier
refuses them and names a condition from a declared set. Neither can say that the
verdict is settled and the condition is not, and about some statements that is
the only true thing to say. The specification carries no failure-code vocabulary
at all, and of its own two-stage verification description it says that "the
sequencing itself is informative" (L366-368). Two rails can therefore reject the
same bytes, name different conditions, and both be right.

Saying it by widening a reject vector's expected set does not work: the harness
compares code SETS, so a set naming both conditions is satisfied by either
answer and by a rail that emits both, and the vector stops measuring the
question instead of starting to. `vectors/indeterminate/` is the third bucket.
A member declares a DETERMINED verdict — indeterminacy is scoped to the
condition, because a vector whose verdict were open would certify nothing — and
a set of READINGS, each naming the condition that reading predicts for that
member. A family is the members sharing one reading vocabulary, and the
generator refuses a family whose declared readings no member's answer can
separate.

A rail satisfies three requirements: the verdict; CLOSURE, its answer on each
member is one some declared reading predicts; and COHERENCE, one reading
explains its answers across the whole family. Either answer is admissible. No
answer is not, and neither is a pair of answers straddling two readings, because
the reported condition is then a function of incidental structure rather than of
a policy the rail applies — the shape a primary-code selector that overwrites
rather than sets-if-unset produces, and a shape no single-fault vector can see.

Which reading a rail took is READ and REPORTED rather than required. A rail may
publish an optional `primaryCode` beside its code set, naming the one condition
it reports when several hold; the families read it, and nothing else does. A rail
that publishes only the set has declined to answer — reporting every condition a
statement carries is a legitimate response — and is recorded as committing to no
reading. That report is the point. Both findings this corpus has taken from an
outside reader were divergences five agreeing rails could not show each other,
and a bucket that records which reading each rail took is where the next one
becomes visible without anybody having to arbitrate.

`vectors/indeterminate/INDEX.md` carries the families, the readings, and the
enumeration of what is deliberately NOT in the bucket: the specification's limits
(the passive-sensor producer assertions, the shared-reference evidencing
obligation), the consumer MAY clauses that sit outside the verdict this suite
reads, and the producer options whose verifier handling is forced.

Two codes carry a standing exemption the gate knows about.
`corpus-anchor-mismatch` and `substrate-anchor-mismatch` are consumer-policy
facts rather than validity conditions: they are recorded on the report's consumer
surface and never change the byte-pure verdict, so no single-statement vector can
exercise them, and the gate requires that none claims to.

## Conformance vectors

`aee/vectors_test.go` replays the conformance vector suite in this repository
(default `../../vectors`, override `AEE_VECTORS_DIR`): every accept vector
must verify valid with matching result and tier columns under both key
policies; every reject vector must be invalid with the primary code inside
the vector's expected code set, emitting no result and no tiers. The runner
skips with an explicit message when the suite is not yet present. The
pinned-policy key is derived from the published test-key recipe
(`seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`). Nothing
private is committed anywhere in this repository.

### What the corpus forces, as a measured number

A vector count is an upper bound on forcing and never a measurement of it. The
evaluator satisfies a vector when ANY expected code in a stage is observed, and
the per-stage column the runner prints is a display rather than a verdict: delete
the `result-vocabulary` emission from the rail and two vectors' gate-0 column goes
FAIL while the suite still reports 220 of 220, exit 0. A rail with no
result-vocabulary check at all clears this corpus.

So forcing is measured instead. `scripts/forcing-gate.py` switches off exactly one
rule in the reference rail, replays every vector, and asks whether the corpus
notices — 590 single-site weakenings of `aee/`, one rebuild and one full replay
each. A rule the corpus never notices losing is a rule no third-party implementer
is obliged to build, whatever the vector count says.

[`docs/FORCING-BASELINE.json`](docs/FORCING-BASELINE.json) is the result, held as a
tighten-only ratchet: **331 rules forced, 17 seen-but-tolerated, 237 unforced, 5
unmeasurable.** The four outcomes stay apart on purpose — "we could not measure it"
and "the corpus does not force it" are different claims and only one is a gap — and
four sites carry an annotation saying that "unforced" is the wrong word for them,
three because the weakened rail computes exactly what the original computes and one
because an earlier check reaches it first on every input that could get there. Those
annotations are claims the gate falsifies: an annotated site that is ever killed
fails the build.

CI runs the ratchet on every push over the rules the baseline records as forced —
the complete set where a regression is possible — and sweeps all 590 sites nightly,
which is what can see forcing improve.

### Condition ids

A vector cites the specification rules it forces as `aee-c-NN` condition ids,
and those ids are the normative link between a vector and the rule it exists to
pin. **The registry that resolves them to spec lines is the condition table in
[`vectors/reject/INDEX.md`](vectors/reject/INDEX.md), and it is the only one.**
Both index files used to say the table lived in this README. It never did, in
any revision, and the effect was not cosmetic: the table that does exist listed
only the ids the reject set happened to use, so 17 ids cited by accept vectors
resolved to nothing at all. The table now covers every id the suite cites, in
either direction, and `scripts/condition-registry-gate.py` fails the build when
a cited id has no row or a row names an id no vector cites.

## The go-witness attestor (`witnessattestor/`)

A go-witness-compatible attestor package; upstream go-witness PR staged.
It follows the upstream sarif pattern: an attestor that runs after the
step's products exist, locates a substrate-emitted evidence statement
among them (`aee-evidence.json` by default), re-hashes it for integrity
against the recorded product digest, and then runs the emit seam (GATE 0
+ GATE 1 + recompute equality), returning an error rather than signing on
any failure. The signed predicate bytes are exactly the validated bytes.

The security scope, stated in the package documentation and binding on every
description of the attestor: the witness envelope key backs the
**producer-asserted plane only** (assembly, gate-validity,
recompute-consistency at pipeline step time), while the
**substrate-covered plane** travels exclusively in the signed
`observationRecords`, verified per record at the consumer's tier
derivation against consumer-pinned substrate observation keys. The
attestor never claims that go-witness observed the execution, and
go-witness's own `commandrun` tracing is never `basis: substrate`. GATE 2
never runs at emit, since the tier is relative to the consumer and
derived by definition; the optional `expect-substrate-key` producer-QA
flag checks record signatures locally and derives no tier.

`cmd/aee-witness-demo` drives the attestor through the real witness run
lifecycle as a library and prints the signed standalone AEE statement.
Consume-side, `cmd/aee-verify` (core module, stdlib-only) is the MVP; a
witness `VerifyRunType` attestor that re-emits gate outcomes as a signed
verification summary is named future work (the witness verify CLI is
currently coupled to its policy attestor).

## On independence

I wrote the Go core here, the sibling Python implementation, and the three
consumer rails in two first-party stacks. Five implementations,
one author, one reading of RFC 8785 and RFC 7493. They catch each other's
transcription errors and the differential fuzzer catches drift between them, but
they cannot catch a misreading of the specification, because they all inherit
the same one. Counting them as independent would be counting the same opinion
five times.

**The number of implementations independent of this specification's author is
one.** [`Rul1an/aee-checker`][aee-checker] is a from-spec Rust implementation
with its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root,
run-binding derivation, and Ed25519 tier, built with no sight of the reference
code. It cleared 125/125 at suiteRevision 1, then re-ran against the round-7
corpus and reached 138/138 at suiteRevision 2 after a spec-diff-led update
(132/138 on the unchanged build), cleared suiteRevision 3 at 140/140, cleared
suiteRevision 5 at 149/149 after it adopted the normative nesting bound of 128
and moved its depth counter from per parsed value into the container branch
(aee-checker#3), and cleared suiteRevision 6 at 153/153, 36/36 accepts and
117/117 rejects, after implementing the Unicode noncharacter exclusion RFC 7493
section 2.1 requires (aee-checker#4, 2026-07-28; the unchanged revision-5 build
scored 151/153 against it).

Each of those figures moves this column only because a record and the source
digest that produced it were posted with it. The revision-6 record names checker
source `sha256:1c3e2e78` and suite commit `7098f4e`, and it is the revision his
CI now verifies continuously. That suite commit no longer resolves in a fresh
clone of this repository, because the history it sat on was rewritten here after
he pinned it; the commit that carries the identical tree, and so the identical
153 vectors of suiteRevision 6, is `8959bd3`, which is where a reproduction of
the record should point until he repins.

Only two of those figures are evidence that an outside reader reached a rule on
his own. The 125/125 was the first full corpus run with no vector-driven fixes.
The 140/140 was a first run by an unchanged build whose rule for the two new
vectors was derived from the spec text and predated them, so the vectors met a
rule that was already there rather than driving it. The other figures each
followed a spec diff he had read, and the newest one followed more than that.
In his words,
kept here because paraphrasing it would soften it: "This one is directed, and
more so than revision 2 was: the rule was written and the vectors named before
this checker ran, so what it demonstrates is that the corrected rule is
implementable from the text, not that an independent reader found it." A
directed 153/153 says the corrected rule is implementable by someone who has only
the text. It is not the same evidence as 125/125 and this suite does not present
it as such.

It has not been run against suiteRevision 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 or 17, so
this suite publishes no score for it at any of them. They are on that list for
two different reasons. From suiteRevision 7 onward the corpus itself moved past
his last run: the single suiteRevision-7 vector (`bad-745`) and the two
suiteRevision-8 vectors (`bad-746`, `bad-747`) test requirements the
specification gained after it, the two suiteRevision-9 vectors (`bad-748`,
`bad-749`) pin the precedence and the wrong-type spelling of the requirement
`bad-745` carries, the seven suiteRevision-10 vectors (`bad-750`, `bad-751`,
`bad-820`, `bad-821`, `bad-822`, `ok-038`, `ok-039`) carry a timestamp profile
the specification gained in the same revision, suiteRevision 11 moved the
vendored text with every vector byte-identical, suiteRevision 12 re-minted every
decodable record identity for version 2 of the run binding and added ten
vectors, suiteRevision 13 added four vectors and moved five results for the
fourth `result` value, and suiteRevision 14 vendored the words the corpus had
already implemented without moving a byte of it. suiteRevision 4 is on the list
for the opposite reason: its corpus is the revision-3 corpus, 140 vectors with
the same verdicts and the same codes, so the revision-3 run did put those bytes
through this checker. What that revision changed was the text, which made
encoding well-formedness and the 128-deep nesting bound normative over a corpus
that, as its own changelog entry says, exercised neither. A pass at 140/140 was
therefore compatible with getting both new rules wrong, and one of them he did
get wrong: when suiteRevision 5 published, this checker still read the bound as
256, and aee-checker#3 is where it adopted 128. Recording revision 4 as run
would assert a conformance no record of his carries. It keeps its own
authorship, history, and CI. The link is pinned to the build that recorded the
153/153 run.

That one reading has already earned its keep, twice. The specification did not
pin a maximum JSON nesting depth, so all five of my rails chose 128 and agreed at
every depth; the independent checker read the same text and chose 256. For the
127 depths in between, identical bytes were valid evidence to one conformant
verifier and malformed to another. Five agreeing rails could not surface that;
one outside reader surfaced it on contact, and the bound is now normative at 128.
Reading it back a second time surfaced a split the five rails had hidden from
each other: the reference Go rail counted nesting depth per parsed child, so an
empty-container leaf slipped one level past the bound where the Python rail
rejected it -- two first-party rails disagreeing on identical bytes at one exact
depth. That one is fixed and pinned by a boundary vector pair; both findings came
from the same outside reader, and neither could have come from the rails alone.

More outside implementations are wanted, and the count above is the reason.
Wiring one in means answering the external-verifier contract above: a verdict in
the exit status, a single-line JSON object carrying the codes and the recomputed
result, and a key policy read from `AEE_SUBSTRATE_KEYS` so the two tier columns
can be compared. A conformant checker passes even when it evaluates in a
different order, since the suite compares verdicts and code sets and ignores both
message text and evaluation order. The shortest way to see the whole contract
working is the CLI in this repository, which CI drives through it on every push:

```
go build -o aee-verify ./cmd/aee-verify
python3 packaging/run_vectors.py --verifier "$PWD/aee-verify -json"
```

[aee-checker]: https://github.com/Rul1an/aee-checker/tree/f8bd3a787ef0b4610e96054ee1f167368f2ccdc2
