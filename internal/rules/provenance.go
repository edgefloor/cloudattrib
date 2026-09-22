package rules

import (
	"crypto/sha256"
	"encoding/hex"
)

// DefaultDigest identifies the exact embedded rule artifact bytes.
func DefaultDigest() string {
	sum := sha256.Sum256(builtin)
	return "sha256:" + hex.EncodeToString(sum[:])
}
