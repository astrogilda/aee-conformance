# Test keys

The suite is signed with **TEST KEYS ONLY**: deterministic Ed25519 keys any
verifier re-derives from a published recipe, so no private key material is
distributed and the vectors are reproducible by anyone.

## Derivation

For each role, the 32-byte Ed25519 seed is:

    seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")

The public key is the Ed25519 public key for that seed. Both the vector
generators and the reference verifier (`packaging/run_vectors.py`,
`derive_test_keys()`) derive the same keys from this recipe, so the signatures
in every vector verify without shipping any key file.

## Roles

`<role>` is one of the following published names (no role has to be guessed):

| role | used for |
|------|----------|
| `substrate-observation-test` | the substrate observation key a consumer pins out of band; the key that verifies `basis: substrate` covering records into the `attested` tier. This is the key a consumer policy pins in the accept vectors. |
| `wrong-signer-test` | a validly-derived-but-unpinned key (e.g. the second covering record in `ok-024`); verifies as a signature but not under the pinned substrate key, so its row stays `unattested`. |
| `statement-test` | the DSSE statement-level signer, distinct from the record signers. |
| `no-pae-verify` | a construction whose signature is not over the DSSE PAE, so it never verifies (`ok-020`); exercises the tier's fail-closed path. |

## keyid convention

A record's `keyid` is the **lowercase hex SHA-256 of the raw 32-byte Ed25519
public key**: `keyid = SHA-256(pubkey_raw_32_bytes)`. It is an unauthenticated
lookup hint only; a conforming verifier checks signatures, never the `keyid`
(a wrong `keyid` on an otherwise-valid signature still verifies, e.g. `ok-019`).

These keys carry no security value and MUST NOT be used outside the conformance
suite.
