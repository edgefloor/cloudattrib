package rules

import "testing"

func TestDefaultDigestIdentifiesEmbeddedRuleArtifact(t *testing.T) {
	t.Parallel()

	const want = "sha256:9a3a12a74740b1851abf5ea0145563335aa72637e6651b04747566bc3ab9c5f9"
	if got := DefaultDigest(); got != want {
		t.Fatalf("DefaultDigest() = %q, want %q", got, want)
	}
}
