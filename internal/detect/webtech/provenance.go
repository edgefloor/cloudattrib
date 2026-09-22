package webtech

import (
	"crypto/sha256"
	"encoding/hex"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// EngineID identifies the passive fingerprint engine dependency.
const EngineID = "wappalyzergo@v0.3.2"

// FingerprintDigest identifies the exact embedded fingerprint artifact bytes.
func FingerprintDigest() string {
	sum := sha256.Sum256([]byte(wappalyzer.GetFingerprints()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
