# Detector liveness, per channel, from the bytes

A check that never fires may be guarding a well-designed boundary or may be
dead. From outside, the two are the same run: nothing was caught, and nothing
in the report distinguishes a boundary nobody tested from an instrument that
stopped working. Reading the report harder does not help, because the two
states have the same wire form.

The only thing that separates them is a stimulus the check must catch. This
document says how that is expressed in the predicate this suite certifies
against, which vectors force it, and — as carefully as the rest — what it does
not establish.

## The construction

No member is added for it. Five that this version already carries line up:

| Carried value | What it contributes |
|---|---|
| `observationEnvironment.corpus.manifest.classes` | which channel an attack belongs to |
| `observationEnvironment.corpus.manifest.expectedPayloads` | the planted stimulus: the commitment value a corpus author computed in advance for what that attack looks like on the wire |
| `aeePayloadCommitment` on an `interception` record | what the substrate actually committed to |
| `attribution: pinned` on the row | the row asserting the two are comparable |
| `aeeObservedAttacks` on the run-end `sealed` record | the substrate's own signed list of what it attributed |

A channel is **demonstrated** when at least one attack in it satisfies all
five: the corpus planted a probe there, the row for that probe is caught and
declares the stronger attribution, it resolves an interception whose committed
value the corpus predicted, and the run-end seal names it.

The seal is not decoration on that list. Without it the interception could have
been deleted by a party holding the enclosing envelope, who then recomputes a
self-consistent `batchRoot` over what remains; the seal is signed by a party
that does not control the carried set, so it still commits to the record that
is gone. A run whose probe matched but whose seal does not name the attack is
reported `unsealed` rather than demonstrated, and that is a real limit on what
the run can show rather than a fault in the statement — a substrate that holds
no attack-to-record correspondence carries the empty array honestly.

## The claim is per channel, so the fixtures are per channel

A probe caught on the egress channel establishes nothing whatever about the
channel beside it. A corpus that plants one probe and reports a live detector
has measured a sample and called it a census, so the verdict is computed per
entry of `coverage.assessedClasses` and is never rolled into one boolean for
the run. One fixture per claimed channel is the minimum.

`ok-052-liveness-probe-per-channel` carries three channels, three planted
probes and three demonstrations at once. Three rather than two, because a rail
that decides on the first row and the last passes a two-channel statement while
skipping everything between. The three refusals beside it each place their
fault on a channel that is not the first:

| Vector | Fault, and on which channel |
|---|---|
| `bad-983-liveness-middle-channel-commitment-unmatched` | the middle channel's interception commits to a value the corpus declared for no attack, with the channels either side left satisfied |
| `bad-984-liveness-last-channel-unpinnable` | the corpus drops the last channel's `expectedPayloads` entry while its row keeps declaring `pinned` |
| `bad-985-liveness-middle-channel-probe-uncaught` | the middle channel's interception is deleted and its row re-pointed at the seal, so a caught `pinned` row resolves no interception at all |

Each is one mutation away from `ok-052` and reports an existing condition
(`aee-c-102`, `aee-c-101`, `aee-c-100` respectively). What is new is where the
fault sits: the single-channel forms of all three already shipped as
`bad-960`, `bad-959` and `bad-958`, and on a one-row statement the first pinned
row and the only pinned row are the same row, so a rail that decides the rule
on the first row it meets — or stops at the first row it can satisfy — passes
every one of them.

## What it is not

**Liveness is not a validity requirement at this version, and one accept vector
exists to stop it becoming one by accident.**
`ok-053-liveness-probe-uncaught-on-one-channel` carries the same three planted
probes with the middle channel's row clean, its attribution at the honest
floor, and its attack absent from the seal. That is a producer whose detector
did not fire saying so, and it MUST be accepted: refusing it would refuse the
honest report along with the dishonest one, and `bad-985` is the dishonest
report of the same run. What the format does instead is make the difference
legible — three probes declared, two named on the seal — and leave the decision
with the consumer, which is where the predicate's Consumer policy obligations
already put it.

**It is structural until signatures verify.** Every value above except the
manifest travels inside a record payload, and record content means nothing
until its signature verifies against a key the consumer trusts. Run without a
key, the report says `structural` in its own header and every verdict is a
statement about form.

**It does not reach a producer that declines to plant a probe.** A channel with
no `expectedPayloads` entry is reported `unprobed`, which is neither a pass nor
a failure: it is the absence of the only evidence that could settle the
question. Most of this corpus is `unprobed` by that measure, because most of it
was written to force other rules.

## Reproducing every verdict here

```sh
# every verdict this document publishes, recomputed and compared to what it
# says, plus each arm of the construction switched off in turn
uv run --extra dev python scripts/liveness-probe-test.py

# per-channel verdicts over the whole accept set, signatures checked
uv run --extra dev python scripts/liveness-probe.py --corpus \
  --key 496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62

# the same, machine-readable
uv run --extra dev python scripts/liveness-probe.py --corpus --json \
  --key <as above>

# the two vectors built for the construction, and the three refusals
uv run --extra dev python scripts/liveness-probe.py --key <as above> \
  vectors/accept/ok-05[23]*.json vectors/reject/bad-98[345]*.json

# the same with no key at all: stdlib only, and the report says structural
python3 scripts/liveness-probe.py vectors/accept/ok-05[23]*.json
```

`--key` is the only part that needs a dependency, because checking an ed25519
signature does; the keyless run is stdlib-only like the reference rail beside
it. Asked for a verified report in an environment that cannot produce one, the
probe refuses and says so rather than printing a structural answer under a flag
that asked for more.

The key is the suite's own test key. Its seed derives from a published constant
(`SHA-256("in-toto-aee-test-key/substrate-observation-test/v1")`), which is
what makes it a test key by construction, and its public half is published in
`vectors/reject/INDEX.md` under the determinism recipe.

No verdict in this document — the three in the refusal table above, the two in
the arm table below, and the three `ok-052` reports — was read off a run and
typed in. `scripts/liveness-probe-test.py` carries every one of them as an
expected value and recomputes it from the shipped vectors, so a corpus that
moves without this document moving fails in CI. It then plants, against a copy
of `ok-052`, each fault the construction is
supposed to notice — no expectation declared, an expectation nothing matches, a
row that is not caught, a row resolving no record, the weaker attribution, an
interception that does not verify, a seal that does not verify — and requires
the affected channel to degrade to the named state. That second half is the
part worth having: a probe hard-wired to answer `demonstrated` would clear
every vector in this corpus and report a live detector for a dead one, which is
this document's own subject one level up.

## What forced each arm of the construction

Every arm is separated by a shipped vector rather than argued, so a rail that
implements the construction loosely fails somewhere concrete:

| Arm | Separated by |
|---|---|
| the commitment comparison | `ok-052` demonstrated against `bad-983` not-demonstrated on the same channel |
| the corpus expectation | `ok-052` against `bad-984`, whose last channel becomes `unprobed` |
| the interception must exist | `ok-052` against `bad-985` |
| the stronger attribution | `ok-047` (`unsealed`) against `ok-048`, which declares `paired` and reports `not-demonstrated` |
| the run-end seal | `ok-047`, whose probe matches and whose seal names nothing, reports `unsealed` where `ok-052` reports `demonstrated` |
