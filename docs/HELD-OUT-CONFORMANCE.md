# Held-out conformance: a design

Status: proposal. Nothing described below is built. It is offered into the
conformance workstream of a standard whose own issue tracker states the
problem it solves, and its purpose is to be argued with before anyone starts
writing vectors.

## The contradiction

A maintainer of that standard wrote it down exactly:

> "Only a held-out corpus tells a real implementation from a lookup table, and
> holding vectors back conflicts with publishing them."

Both halves are true, and the measurement behind the first half is worse than
it reads. An adapter whose first statement discarded its input scored 19 of 19
against a published suite and exited 0, because each vector's identifier
encoded its verdict class. Emptying the question to an empty object, handing
the adapter nothing at all, still passed every vector through a seven-line
walk of the interpreter's own call stack. A published corpus cannot prove
enforcement, and a corpus nobody can read cannot be reviewed, cannot be
contributed to, and cannot be checked by the party the conformance claim is
made to.

Three resolutions are already ruled out by measurement.

**Redacting the identifier relocates the leak.** This was tried on a corpus of
272 vectors at suiteRevision 28, for an attestation predicate. Measured over
each vector's whole manifest-relative path, a cheap classifier predicted the
verdict from the identifier alone with a separability of 1.0000 against a
permutation null of 0.5879. Stripping the verdict prefix left the authoring
slugs at 0.9936; stripping the family token as well left 0.7260; the
description words alone scored 0.7307, against a null near 0.585. The leak was not the prefix. It was
the vocabulary: one side of a corpus says missing, mismatch, duplicate and
wrong, and the other says clean, canonical and pass. There is no spelling of a
published mapping from old names to new that carries no label. What closed it
was naming every vector after a digest of its own bytes and keeping the verdict
only in the manifest, after which the identifier surface measured 0.5075
against a null of 0.5075 and the whole surface fell from 0.9906 to 0.5567
against a null of 0.5817.

**Publishing nothing** removes review. A suite nobody reads is a suite whose
positive controls nobody has checked, and a positive control is a mandatory
allow: one contributed vector demanding a bypass turns the runner into an
instrument that flags the honest implementation as the broken one.

**Publishing everything and calling the suite a self-certification aid**
is honest and gives up the thing the label is for. It is the right description
of a suite that stops here, and this design exists to get further.

## The claim the design supports

The resolution starts by narrowing what must be unavailable. **The thing an
implementer must not be able to look up is the verdict, not the vector.** A
published corpus whose identifiers, paths, filenames and lexicon each sit
inside their own measured noise floor gives a lookup table nothing to key on
except the bytes of the statement, and reading the bytes of the statement is
the behaviour under test.

That is not a proof of enforcement and this document does not claim it is one.
It moves the honest description from "self-certification aid" to something
narrower and checkable: a corpus that cannot be passed by an adapter that never
opened a file, published alongside the measurement of how much its own surfaces
leak, so a reader checks the claim instead of taking it. The genuinely held-out
part then shrinks to a small sealed slice, which is a governance question with
a mechanism rather than the thing the whole suite rests on.

## Four parts

### 1. The public corpus

Every vector published, with three properties enforced by a gate rather than
asserted in prose.

- **Content-addressed identifiers.** A vector is named after a digest of its
  own declaration. No directory per verdict, no prefix per verdict, no
  published mapping from any earlier naming.
- **A published leakage measurement.** The suite ships the separability of a
  cheap classifier trained on nothing but each vector's identifier, scored
  against the same estimator with the labels shuffled. A run whose identifier
  surface scores above its own null fails the gate. The recipe is the
  contribution: anyone can run it against their own corpus, and the number is
  meaningful only beside its null.
- **A verdict asserted as a code.** Never a message. Substring matching
  against operator prose fails a correct implementation that words a refusal
  differently and passes a wrong one that words the right cause.

### 2. The sealed corpus

A small slice, generated from the same families as the public corpus and never
published. Its purpose is one measurement and not a score: the difference
between a run's public result and its sealed result on the same families.

- **It is generated, not curated.** The generator is public and its seed is
  not, so an implementer can read exactly how a sealed vector is shaped and
  cannot enumerate which ones exist. A curated sealed corpus is a secret that
  degrades as it is used; a generator plus a withheld seed is a secret that
  regenerates.
- **It is small.** Enough members per family to make agreement unlikely by
  chance, and no more. A large sealed corpus is a large secret and a large
  thing to leak.
- **A sealed member is published once it has been used.** Its verdict, its
  bytes and every run against it are released with the report. The seal buys
  one measurement per release, then becomes public review. A permanent secret
  is a permanent unfalsifiable claim, which is the defect this whole document
  is answering.
- **The steward holds the seed.** Who that is, and how the role is appointed,
  is governance and is not proposed here.

### 3. The attested-adapter run

A run is worth reading only when a reader can tell what was run.

- **The adapter runs out of process, one child per suite run.** In process, an
  adapter owns the runner: a call to exit inside one gave exit 0 with no output
  at all, because catching a broad exception class misses the interpreter's own
  exit exception. One child per vector is also wrong, because it breaks every
  implementation with real state, which includes anything that actually detects
  replay.
- **The run record pins the adapter, not its name.** A digest of the adapter
  bytes, a digest of the corpus, the suite revision, the sealed generator
  revision, the command line, the wall-clock start and end, and the transcript.
  An implementation name and a version string are a claim; a digest is a thing
  a second party can recompute.
- **The runner ships its own negative controls.** Mutating a reference adapter
  measures the vectors and leaves the runner untested. Nineteen mutants of one
  runner found five guards with nothing behind them, two of them exploitable,
  and one silently restored a defect a reviewer had already caught. A run whose
  runner has no mutation baseline of its own is a run whose scoring code is
  unmeasured.
- **A run that scored nothing does not exit 0.** An empty capability profile
  printing zero of zero vectors conformant and exiting 0 is the cheapest
  possible pass, and it is a pass a scoring gate must refuse by construction.

### 4. Scoring

A claim is scored per requirement, on four rungs, and the rung is part of the
claim.

| rung | what it asserts | what establishes it |
|---|---|---|
| supported | the implementation declares the control | a declaration, and nothing else |
| configured | the control is enabled in this deployment | configuration read from the deployment |
| effective | the execution path is actually intercepted | a public-corpus run under an attested adapter |
| observed | traffic has been seen traversing that path | a run record with a transcript |

The ladder is what stops a declaration being read as an enforcement result. A
runtime can emit correct traces for a tool action while the execution path
bypasses the enforcement hook entirely, and one resolved package instance can
be instrumented while a second is not. Both are `supported` and neither is
`effective`, and a scoring surface with one column cannot say so.

A requirement is scored `effective` only when a weakening of that requirement
is killed by a vector the row names. A row proving a requirement is *named*
proves nothing about whether its test would fail if the requirement were
violated, and those two properties look identical in a table.

Three further columns travel with each row, because the verdict cannot carry
them:

- **basis**, `substrate` or `artifact`: whether the expectation rests on an
  observation of the run or on a record the run emitted about itself. A party
  holding the enclosing signing key and not the observation key can move every
  row to `artifact`, drop the observation records those rows no longer need,
  and emit something byte-identical to what an honest producer with no
  observation vantage emits from the same configuration. No function of the
  carried bytes separates them, so only a required declaration does.
- **witness scope**, `SELF`, `PEER` or `EXTERNAL`: who can check the row
  without the enforcement point's cooperation. A row is `SELF` unless a
  concrete artifact path exists that lets the named witness check it without
  relying on the enforcement point's own account.
- **stop reason**: which branch produced the verdict. A guard that fires before
  the property is evaluated emits a verdict word indistinguishable from the one
  a real check produces, and when it stops on the correct side nothing catches
  it. Asserting the stop reason rather than the verdict column is what catches
  that, and it is cheap.

## What the label then means

Four claim forms, and the unqualified word is not one of them.

- **emission-conformant.** The implementation emits the shapes the
  specification defines. No enforcement is asserted. Establishable from the
  public corpus alone at the `supported` rung.
- **operationally conformant, self-attested.** Every requirement is
  `effective` under an attested-adapter run of the public corpus, with the
  leakage measurement published. The runner's own mutation baseline is
  published. Every row is `SELF`.
- **operationally conformant, sealed-checked.** The above, plus a sealed-slice
  run by the steward whose result agrees with the public result on the same
  families, plus the release of those sealed members. This is the rung at which
  "not a lookup table" stops being an argument and becomes a measurement, and
  it is a measurement with a stated confidence rather than a proof.
- **operationally conformant, externally verifiable.** The above, plus at least
  one requirement whose row is `EXTERNAL`: an artifact a party outside the
  trust domain can check without the enforcement point's cooperation. On the
  wire format as it stands, no row reaches this. That is a finding about the
  format and it is recorded as one.

**Unqualified "conformant" overclaims and is not used.** A suite that publishes
only what it covers has the same problem one level up as a label with nothing
behind it, so the suite also publishes what it fails to force: how many
normative conditions it cites, how many are forced by a vector no other
condition's vectors duplicate, how many are covered only redundantly, how many
are not forced at all, and which failure codes a conforming implementation may
decline to emit entirely.

## What this does not buy

It does not prove enforcement. A sealed-slice agreement is evidence that the
implementation read the bytes of the statement rather than a table of answers,
at a confidence set by how many sealed members were run, and nothing stronger.

It does not survive a steward who leaks the seed, and it is not meant to: the
mechanism assumes the seed holder is the party whose incentive is to keep the
label meaningful, and it fails loudly rather than quietly if that stops being
true, because a sealed result that stops disagreeing with the public result on
any implementation is itself the signal.

It says nothing about requirements the specification cannot express. Those are
scored `unmeasurable` with the reason recorded, and folding them into either
column would be the same error in two directions: a rejection credits an
implementation for behaviour nothing requires, and a pass deletes the gap from
the record.

## What it costs

The public corpus, its leakage gate and its verdict-code discipline are the
bulk of the work and are worth doing whether or not the sealed half is ever
built. The sealed generator is small. The attested-adapter contract is a
document plus a runner change. The scoring surface is a schema.

The part that is not engineering is the steward, and this document deliberately
proposes no answer to it.
