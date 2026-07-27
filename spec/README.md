# Vendored predicate specification

[`predicates/adversarial-execution-evidence.md`](predicates/adversarial-execution-evidence.md)
is a version-locked copy of the Adversarial Execution Evidence predicate
specification, vendored so this repository is self-contained: a relying party
can implement or check the predicate from this repo alone, and the `spec:NNN`
line references throughout the Go and Python source resolve against a file that
is actually present here (they cite line numbers in this copy).

- **Tracks:** the upstream repository, pull request and commit these bytes were
  taken from are recorded in [`VENDOR-PIN.json`](VENDOR-PIN.json), together with
  their SHA-256. That file is written by
  [`scripts/vendor-spec.py`](../scripts/vendor-spec.py) from git at vendor time
  and is not maintained by hand.
- **Version:** v0.6.0 (`https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`).
- **Authority:** the canonical namespace is the in-toto attestation catalog.
  This repository is the reference implementation and conformance authority for
  that predicate, not a competing source of truth. On any normative change
  upstream, this copy is re-vendored at the new pinned commit and the corpus is
  regenerated with a `suiteRevision` bump.

The copy is byte-verbatim (no added header) precisely so the line numbers the
source cites stay accurate.

The pin used to be a commit hash written into this paragraph by hand, and it
went stale the first time the upstream branch moved: it named a commit three
normative revisions behind the bytes beside it. That is worth more than a
typo's attention, because an implementer working from this repository diffs the
vendored copy against the pinned commit to certify there is no version skew,
and a pin naming the wrong commit either reports a drift that does not exist or
conceals one that does. `spec-drift-gate.py` now fails closed unless the
vendored bytes, the pin, and the digest the corpus was generated against all
agree.
