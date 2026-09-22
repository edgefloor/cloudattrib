package webtech

import "testing"

func TestFingerprintDigestIdentifiesEmbeddedArtifact(t *testing.T) {
	t.Parallel()

	const want = "sha256:c662ae9244c255b35ccc6d5e92c05aa0f9ca95af5f6cd552217524e6f7e464e5"
	if got := FingerprintDigest(); got != want {
		t.Fatalf("FingerprintDigest() = %q, want %q", got, want)
	}
}
