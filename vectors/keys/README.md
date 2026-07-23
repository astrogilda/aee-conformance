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

These keys carry no security value and MUST NOT be used outside the conformance
suite.
