// Package aeetest builds deterministic, fully synthetic AEE v0.6 statements
// for tests and demos. Every value is either a string the public predicate
// specification itself publishes (posture names, observation labels) or an
// obviously synthetic example value; every digest is DERIVED from a
// committed one-line synthetic pre-image, never typed in.
//
// TEST KEYS — derived, never stored. seed(role) = SHA-256 of the published
// constant "in-toto-aee-test-key/<role>/v1". Anyone can re-derive the
// private side; these keys authenticate NOTHING and must never be trusted
// outside test fixtures.
package aeetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/astrogilda/aee-conformance/aee"
)

// Published test-key roles.
const (
	RoleSubstrateObservation = "substrate-observation-test"
	RoleWrongSigner          = "wrong-signer-test"
	RoleStatement            = "statement-test"
)

// TestKey derives the deterministic test key for a role.
func TestKey(role string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("in-toto-aee-test-key/" + role + "/v1"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// KeyID returns the lookup-hint keyid for a key: the SHA-256 of the raw
// public key bytes. A keyid is never the check itself.
func KeyID(pub ed25519.PublicKey) string {
	return aee.SHA256Hex(pub)
}

// Fixed timestamps used by every built statement.
const (
	IssuedAt = "2026-01-01T00:00:00Z"
	ArmedAt  = "2025-12-31T23:59:00Z"
)

// PayloadType is the neutral example media type for observation records.
const PayloadType = "application/vnd.example.aee-observation.v1+json"

// Options selects the built statement's shape and optional single faults.
// The zero value builds a VALID caught-row statement (substrate basis,
// method intercepted, one interception record).
type Options struct {
	// Clean builds a clean-row statement (label no_egress, arming + sealed
	// records) instead of a caught-row one.
	Clean bool

	// RowMethod overrides the row's method member ("" = intercepted;
	// "ABSENT" drops the member entirely).
	RowMethod string

	// RecordMethod overrides the aeeMethod signed inside the interception
	// record ("" = intercepted). Setting it to reconstructed while the row
	// stays intercepted is the method-inflation fault.
	RecordMethod string

	// Result overrides the carried result ("" = the honest recompute).
	Result string

	// SignerRole selects the record-signing key role ("" =
	// RoleSubstrateObservation).
	SignerRole string

	// ArmedAt overrides the arming record's armedAt ("" = ArmedAt).
	ArmedAtOverride string

	// SealedStillArmedFalse signs the sealed record with aeeStillArmed false.
	SealedStillArmedFalse bool

	// TamperBatchRoot flips the last hex digit of the committed batchRoot.
	TamperBatchRoot bool

	// TamperVocabularyDigest carries a stale observationVocabulary digest.
	TamperVocabularyDigest bool

	// DropRunEntropy removes observationEnvironment.runEntropy.
	DropRunEntropy bool

	// ExtraManifestAttack adds a second attack id to the manifest with no
	// matching row (coverage-incomplete at attack granularity).
	ExtraManifestAttack bool

	// PredicateType overrides the statement predicateType ("" = v0.6 URI).
	PredicateType string
}

// canonMust canonicalizes or panics; builder inputs are all synthetic
// literals, so a failure is a programming error in the builder itself.
func canonMust(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		panic(err)
	}
	return canon
}

func digestOf(v any) string { return aee.SHA256Hex(canonMust(v)) }

// Pinned synthetic pre-images (each a committed one-liner).
var (
	catchPolicyDigest = digestOf(map[string]any{"examplePolicy": "enforcing"})
	postureDigest     = digestOf(map[string]any{"examplePosture": "sinkhole"})
	substrateDigest   = digestOf(map[string]any{"exampleSubstrate": "image"})
	subjectDigest     = digestOf(map[string]any{"exampleSubject": "bundle"})
	runEntropyDigest  = aee.SHA256Hex([]byte("example-run-start-checkpoint/1"))
)

// Build returns the canonical bytes of one complete in-toto statement.
func Build(o Options) []byte {
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	vocabDigest := aee.SHA256Hex(canonMust(map[string]any{"caught": caught, "labels": labels}))
	if o.TamperVocabularyDigest {
		vocabDigest = aee.SHA256Hex([]byte("stale"))
	}

	attackIDs := []string{"XA-EXAMPLE-1"}
	if o.ExtraManifestAttack {
		attackIDs = append(attackIDs, "XA-EXAMPLE-2")
	}
	manifest := map[string]any{"classes": map[string]any{"XA": attackIDs}}
	corpusDigest := aee.SHA256Hex(canonMust(manifest))

	binding := aee.DeriveRunBinding(catchPolicyDigest, corpusDigest, postureDigest, runEntropyDigest, subjectDigest, substrateDigest)

	signerRole := o.SignerRole
	if signerRole == "" {
		signerRole = RoleSubstrateObservation
	}
	signer := TestKey(signerRole)

	var records []map[string]any
	var refs []int
	if o.Clean {
		armedAt := o.ArmedAtOverride
		if armedAt == "" {
			armedAt = ArmedAt
		}
		arming := map[string]any{
			"aeeKind":          "arming",
			"aeeMethod":        "intercepted",
			"aeePostureDigest": postureDigest,
			"aeeRunBinding":    binding,
			"armedAt":          armedAt,
			"producerNote":     "example arming record",
		}
		sealed := map[string]any{
			"aeeDropCount":     0,
			"aeeKind":          "sealed",
			"aeeMethod":        "intercepted",
			"aeePostureDigest": postureDigest,
			"aeeRunBinding":    binding,
			"aeeStillArmed":    !o.SealedStillArmedFalse,
		}
		records = append(records, signRecord(arming, signer), signRecord(sealed, signer))
		refs = []int{0, 1}
	} else {
		recordMethod := o.RecordMethod
		if recordMethod == "" {
			recordMethod = "intercepted"
		}
		interception := map[string]any{
			"aeeKind":       "interception",
			"aeeMethod":     recordMethod,
			"aeeRunBinding": binding,
			"producerNote":  "example interception commitment",
		}
		records = append(records, signRecord(interception, signer))
		refs = []int{0}
	}

	batchRoot := computeBatchRoot(records)
	if o.TamperBatchRoot {
		batchRoot = flipLastHex(batchRoot)
	}

	rowMethod := o.RowMethod
	if rowMethod == "" {
		rowMethod = "intercepted"
	}
	row := map[string]any{
		"attackId":        "XA-EXAMPLE-1",
		"basis":           "substrate",
		"observationRefs": refs,
	}
	if rowMethod != "ABSENT" {
		row["method"] = rowMethod
	}
	if o.Clean {
		row["containmentObserved"] = "no_egress"
		row["actualLayer"] = "none"
	} else {
		row["containmentObserved"] = "egress_captured"
		row["actualLayer"] = "policy.egress_sinkhole"
	}

	result := o.Result
	if result == "" {
		if o.Clean && (rowMethod == "intercepted" || rowMethod == "reconstructed") {
			result = "pass"
		} else {
			result = "fail"
		}
	}

	env := map[string]any{
		"catchPolicy":    map[string]any{"digest": map[string]any{"sha256": catchPolicyDigest}},
		"corpus":         map[string]any{"digest": map[string]any{"sha256": corpusDigest}, "manifest": manifest, "name": "example-corpus", "uri": "pkg:example/corpus@1"},
		"networkPosture": map[string]any{"digest": map[string]any{"sha256": postureDigest}, "posture": "sinkhole"},
		"observationVocabulary": map[string]any{
			"caught": caught,
			"digest": map[string]any{"sha256": vocabDigest},
			"labels": labels,
		},
		"substrate": map[string]any{"digest": map[string]any{"sha256": substrateDigest}, "name": "example-substrate"},
	}
	if !o.DropRunEntropy {
		env["runEntropy"] = map[string]any{"digest": map[string]any{"sha256": runEntropyDigest}}
	}

	predicateType := o.PredicateType
	if predicateType == "" {
		predicateType = aee.PredicateType
	}

	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": predicateType,
		"subject": []any{
			map[string]any{"digest": map[string]any{"sha256": subjectDigest}, "name": "example-agent-bundle"},
		},
		"predicate": map[string]any{
			"attackResults":          []any{row},
			"batchRoot":              batchRoot,
			"coverage":               map[string]any{"assessedClasses": []any{"XA"}, "outOfScope": map[string]any{}, "routedElsewhere": map[string]any{}},
			"issuedAt":               IssuedAt,
			"observationEnvironment": env,
			"observationRecords":     records,
			"result":                 result,
		},
	}
	return canonMust(statement)
}

// BuildArtifactOnly returns a minimal VALID artifact-only statement: one
// artifact-basis caught row, no records, no batchRoot, no runEntropy.
func BuildArtifactOnly() []byte {
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	vocabDigest := aee.SHA256Hex(canonMust(map[string]any{"caught": caught, "labels": labels}))
	manifest := map[string]any{"classes": map[string]any{"XA": []any{"XA-EXAMPLE-1"}}}
	corpusDigest := aee.SHA256Hex(canonMust(manifest))
	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": aee.PredicateType,
		"subject": []any{
			map[string]any{"digest": map[string]any{"sha256": subjectDigest}, "name": "example-agent-bundle"},
		},
		"predicate": map[string]any{
			"attackResults": []any{map[string]any{
				"actualLayer":         "none",
				"attackId":            "XA-EXAMPLE-1",
				"basis":               "artifact",
				"containmentObserved": "egress_captured",
				"method":              "reconstructed",
			}},
			"coverage": map[string]any{"assessedClasses": []any{"XA"}, "outOfScope": map[string]any{}, "routedElsewhere": map[string]any{}},
			"issuedAt": IssuedAt,
			"observationEnvironment": map[string]any{
				"catchPolicy":    map[string]any{"digest": map[string]any{"sha256": catchPolicyDigest}},
				"corpus":         map[string]any{"digest": map[string]any{"sha256": corpusDigest}, "manifest": manifest, "name": "example-corpus", "uri": "pkg:example/corpus@1"},
				"networkPosture": map[string]any{"digest": map[string]any{"sha256": postureDigest}, "posture": "sinkhole"},
				"observationVocabulary": map[string]any{
					"caught": caught,
					"digest": map[string]any{"sha256": vocabDigest},
					"labels": labels,
				},
				"substrate": map[string]any{"digest": map[string]any{"sha256": substrateDigest}, "name": "example-substrate"},
			},
			"result": "fail",
		},
	}
	return canonMust(statement)
}

func signRecord(payload map[string]any, signer ed25519.PrivateKey) map[string]any {
	canon := canonMust(payload)
	pae := aee.PAE(PayloadType, canon)
	sig := ed25519.Sign(signer, pae)
	return map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(canon),
		"payloadType": PayloadType,
		"signatures": []any{map[string]any{
			"keyid": KeyID(signer.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
}

func computeBatchRoot(records []map[string]any) string {
	leaves := make([][32]byte, len(records))
	for i, rec := range records {
		payload, err := base64.StdEncoding.DecodeString(rec["payload"].(string))
		if err != nil {
			panic(err)
		}
		leaves[i] = aee.LeafHash(aee.PAE(rec["payloadType"].(string), payload))
	}
	root := aee.MerkleRoot(leaves)
	return fmt.Sprintf("%x", root[:])
}

func flipLastHex(s string) string {
	last := s[len(s)-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	return s[:len(s)-1] + string(replacement)
}
