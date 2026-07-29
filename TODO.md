# aee-conformance — roadmap

Open work for the conformance-vector suite and reference verifier of the in-toto
Adversarial Execution Evidence (AEE) predicate. Contributions welcome.

> **Session code-health audit 2026-07-24:** `go build ./...` + `go vet ./...` + `mypy` all
> **CLEAN** — no findings for this repo. Combined cross-repo report:
> an internal audit report.

## Status: v0.6 review (in-toto/attestation#570)

The reviewer's independent from-spec checker went 138/138 on the earlier corner-case
features and conceded every open corner; the latest reply invites him to move the v0.6
proposal out of draft.

- [ ] **Await reviewer's read on moving v0.6 out of draft** — no code change pending on
  our side; the next step is the reviewer's call.
- [ ] **v0.7 forward-design — HELD** until v0.6 merges. Do not start new predicate design
  while v0.6 is at the merge line.

## Standards-ecosystem interoperability

- [ ] **SARIF v2.1.0 output** — an `aee-in-sarif` convention doc + emitter so a verifier
  run lands as findings in the GitHub Security tab and any SARIF-consuming tool. Speaks a
  format security teams already ingest.
- [ ] **Framework crosswalk (`.md` + machine-readable `.json`)** — map the AEE evidence
  model and each conformance-vector class to OWASP MCP Top 10, the OWASP Agentic Security
  Initiative Top 10, OWASP AIVSS, and MITRE ATLAS, so findings land in the frameworks
  defenders already report against. Regenerate the table from the vectors; do not hand-edit.
- [ ] **`GOVERNANCE.md`** — document the decision process for new conformance vectors and
  schema changes, deprecation policy (IDs never reused), and the crosswalk-update process.
  Publish the record `$schema` at a stable URL.

## Suite hygiene & citability

- [ ] **Paired positive/negative fixtures per vector** — for each conformance vector, a
  short `<id>_positive` / `<id>_negative` fixture pair so any implementation's detection
  logic can be tested against the standard, with the logic living in the implementer's repo.
- [ ] **Claim -> verdict-token -> reproduce-command manifest** — a table mapping each thing
  the suite asserts to (a) the exact verdict token a verifier emits and (b) a one-line
  command an evaluator runs to reproduce it, so nothing has to be taken on trust.
- [ ] **Shippable tamper-evidence demo** — a dependency-free script that corrupts a copy of
  a signed record two ways (flip one byte, drop one entry) and shows the verifier catches
  each, recomputing from the record's own stored bytes (no re-serialization false alarms).
- [ ] **Citable dataset DOI** — mint a Zenodo (or equivalent) DOI for a tagged release of
  the conformance-vector corpus so it can be cited in papers and reports.

## Supply-chain posture

- [ ] **OpenSSF Scorecard workflow** — add `ossf/scorecard-action` and publish the badge.

## Predicate ergonomics

- [ ] **`honest_limits[]` + `contract_version` fields** — machine-readable declaration of
  exactly what a given evidence record does and does NOT cover, and the predicate contract
  version it was produced under, so a consumer can reason about scope explicitly.
- [ ] **Fail-closed client hygiene** — for any network path a verifier may use, enforce
  immutable config, single-flight, error-on-redirect, and coerce-unknown-toward-reject.

## Known gaps in the gates

- [ ] **A vendored copy that is refreshed, recorded, then reverted stays green.** The
  consumer-lag gate compares `vectors/CONSUMERS.json` against the corpus published here,
  and that ledger records what each copy carried when it was last synced. A copy reverted
  after its sync would keep a stale ledger entry that still matches, and the copy's own
  stamp check cannot see it either, since a revert plus a re-stamp is internally
  consistent. Closing it needs this repository to read the consumer, which is the
  cross-repository read the gate is built to avoid. File: `scripts/consumer-lag-gate.py`.
- [ ] **The sync's re-aim check cannot see a truncated citation.** `--sync` refuses to move
  a citation off text that is still in the document, which catches one whose range
  collapsed onto unrelated prose. A citation cut short of the requirement it exists for,
  where the prose it lost was also edited, reads as an ordinary rewrite and is only
  reported for review. This holds for both spellings, since both now share the rule.
  Fix: compare the citation's own subject rather than its former text.
  File: `scripts/specpins.py`.
- [ ] **The posture registry is asserted by three rails and stated by no line of the
  specification.** `NetworkPosture` and `EgressPostures` in `aee/types.go` accept a
  closed four-value registry with an append-only minor-version rule and reject anything
  else as malformed, and `bad-823`, `bad-824` and `bad-825` lock that reading. The
  vendored text introduces the values as examples ("the substrate-authoritative egress
  posture, e.g. `no_network`, `allowlist`, `sinkhole`", L459-461) and names no
  consequence for a value outside the list, at any line. The reading, its argument and
  the upstream ask are recorded under `docs/interpretation-decisions-open.md`
  suiteRevision 12; the two comments now attribute it to this repository rather than to
  the document, and cite L459-461 for the part the document does state. Closing it needs
  the upstream edit, then a re-vendor. Files: `aee/types.go`,
  `docs/interpretation-decisions-open.md`.

- [ ] **The number profile is integers-only and the specification asks only for safe
  integers.** `checkSafeInteger` rejects any JSON number carrying a fractional part,
  anywhere in a canonicalized payload, including inside members the specification leaves
  to the producer ("everything else in the payload stays producer territory", L977-979).
  What the document states is the safe-integer bound (L83-85, and L856-858 for record
  payloads); it declares every numeric member it defines an integer and states no rule
  against a fractional number elsewhere. The rails reject one anyway, so cross-language
  float formatting can never split them, which is a real reason and a different one from
  conformance. No vector distinguishes the two readings, so a from-spec verifier that
  accepts `1.5` in producer territory is conformant and passes this corpus today. Decide
  whether to ask upstream for the stricter profile or to narrow the rails. File:
  `aee/jcs.go`.

- [ ] **Nothing compares an interpretation entry's anchors with the anchors its own
  prose quotes, outside the registry.** The registry gate now requires an entry's
  `specAnchors` to cover every line reference its title or reading makes, which is what
  found four entries whose recorded anchor sat two lines above the words the entry puts
  in quotation marks. The same disagreement is possible in `vectors/CHANGES.md`,
  `vectors/coverage-unforced.json` and `docs/interpretation-decisions-open.md`, which
  carry anchors and prose side by side with no equivalent check.
  File: `scripts/interpretation-registry-gate.py`.

## Recently landed

- [x] **Re-aim every `spec:NNN` citation onto the passage its own claim names** (2026-07-29) --
  eighty-seven of ninety-eight citation spans across thirteen files were corrected by
  hand, each accepted through `--accept-reaim` by name so the ledger records a decision
  rather than a sweep. The backward measurement that found the drift returns zero over
  every citation not named that way, and reverting any single correction turns it red
  again. The classes separate as follows. Thirty-eight spans were mechanically drifted,
  and correcting thirty of them put the citation back on the text it was written for.
  Twenty-six are aimed somewhere their old text never went, because they were pointed at
  the wrong passage when they were written; eighteen of those the mechanical test could
  never see at all, since a citation still sitting on the prose it was first pointed at
  looks correct from history no matter what the claim beside it says. The remaining
  thirty-one address passages upstream has since rewritten, which the measurement cannot
  classify either way, and they were corrected on reading like the rest.

- [x] **Force reason-map membership on all three coverage sets** (2026-07-26, `cf0d540`) —
  the spec already made the three coverage sets a disjoint partition of the manifest's
  classes, but only `bad-819` forced the `assessedClasses` side. Added
  `bad-731-outofscope-unknown-class` and `bad-732-routedelsewhere-unknown-class`: each puts
  an unknown class key in one reason map, leaves the result alone, and is rejected as
  coverage-incomplete. Both reference rails (Go `aee/statement.go`, Python
  `_coverage_partition_ok` in `packaging/run_vectors.py`) already enforced it, so the two
  vectors lock the written rule and mutation-prove the rails (reverting the reason-map
  accounting flips both). Corpus now suiteRevision 3, 140 vectors (35 accept + 105 reject);
  full local gate green and remote CI green.
- [x] **Extend registry decision 14** (2026-07-26, `cf0d540`) — recorded the two new
  vectors in `vectors/interpretation-decisions.json`, and added a `CHANGES.md`
  suiteRevision-3 section.
- [x] **Document the registry as a post-run reconciliation surface** (2026-07-26, `cf0d540`) —
  added a note to `docs/interpretation-decisions-open.md` clarifying that the interpretation
  registry is read for post-run reconciliation, not as a pre-implementation answer key.
- [x] **Correct the CI vector-replay label 138 -> 140** (2026-07-26, `cf0d540`).
- [x] **Update the multi-implementation report** (2026-07-26, `cf0d540`) —
  `docs/IMPLEMENTATION-REPORT.md` now records the reviewer's re-run as a third
  fully-independent column on the earlier corner-case features (138/138 spec-diff-led,
  132/138 unchanged).

---
_Detailed rationale and cross-repo tracking live in the private product backlog; this file
is the public roadmap for the open conformance artifact._
