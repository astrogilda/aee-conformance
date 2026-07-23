# Vendored predicate specification

[`predicates/adversarial-execution-evidence.md`](predicates/adversarial-execution-evidence.md)
is a version-locked copy of the Adversarial Execution Evidence predicate
specification, vendored so this repository is self-contained: a relying party
can implement or check the predicate from this repo alone, and the `spec:NNN`
line references throughout the Go and Python source resolve against a file that
is actually present here (they cite line numbers in this copy).

- **Tracks:** in-toto/attestation#570 at commit `e5ea1eb`.
- **Version:** v0.6.0 (`https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`).
- **Authority:** the canonical namespace is the in-toto attestation catalog.
  This repository is the reference implementation and conformance authority for
  that predicate, not a competing source of truth. On any normative change
  upstream, this copy is re-vendored at the new pinned commit and the corpus is
  regenerated with a `suiteRevision` bump.

The copy is byte-verbatim (no added header) precisely so the line numbers the
source cites stay accurate.
