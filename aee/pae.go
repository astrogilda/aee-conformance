package aee

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// PAE computes the DSSE v1 pre-authentication encoding over
// (payloadType, payload). Record signatures — and the batchRoot leaves —
// are defined over these bytes (spec:623-625, 629-631).
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// SHA256Hex returns the lowercase 64-hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IsLowerHex64 reports whether s is exactly 64 lowercase hex characters —
// the only accepted digest value form (spec:115-118).
func IsLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
