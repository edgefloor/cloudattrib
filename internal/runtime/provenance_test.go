package runtime

import (
	"testing"

	"cloudattrib/internal/config"
	"cloudattrib/internal/detect/webtech"
	"cloudattrib/internal/policy"
	"cloudattrib/internal/rules"
)

func TestDetectorBuildIDMatchesClassifierInputs(t *testing.T) {
	t.Parallel()

	got := classifierBuildID(webtech.EngineID, rules.DefaultDigest(), webtech.FingerprintDigest(), policy.PublicDestinationPolicyRevision)
	if got != detectorBuildID {
		t.Fatalf("classifier inputs produce %q, want detector build ID %q", got, detectorBuildID)
	}
}

func TestObservationContextIDSeparatesResolverAndPolicy(t *testing.T) {
	t.Parallel()
	base := observationContextID(config.Resolver{Network: "udp", Address: "127.0.0.1:53"}, "public-v1")
	if base == observationContextID(config.Resolver{Network: "udp", Address: "127.0.0.2:53"}, "public-v1") ||
		base == observationContextID(config.Resolver{Network: "tcp", Address: "127.0.0.1:53"}, "public-v1") ||
		base == observationContextID(config.Resolver{Network: "udp", Address: "127.0.0.1:53"}, "public-v2") {
		t.Fatal("observation context merged different resolver or policy settings")
	}
}

func TestClassifierBuildIDChangesWithEachInput(t *testing.T) {
	t.Parallel()

	base := classifierBuildID("engine-a", "sha256:rules-a", "sha256:fingerprints-a", "policy-a")
	for _, test := range []struct {
		name string
		got  string
	}{
		{name: "engine", got: classifierBuildID("engine-b", "sha256:rules-a", "sha256:fingerprints-a", "policy-a")},
		{name: "rules", got: classifierBuildID("engine-a", "sha256:rules-b", "sha256:fingerprints-a", "policy-a")},
		{name: "fingerprints", got: classifierBuildID("engine-a", "sha256:rules-a", "sha256:fingerprints-b", "policy-a")},
		{name: "policy", got: classifierBuildID("engine-a", "sha256:rules-a", "sha256:fingerprints-a", "policy-b")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.got == base {
				t.Fatalf("classifierBuildID() did not cover %s", test.name)
			}
		})
	}
}
