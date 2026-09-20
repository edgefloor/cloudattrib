package ingest_test

import (
	"context"
	"os"
	"testing"

	"cloudattrib/internal/enrich/prefix"
	"cloudattrib/internal/ingest/aws"
	"cloudattrib/internal/ingest/azure"
	"cloudattrib/internal/ingest/gcp"
	"cloudattrib/internal/model"
)

func TestOfficialFixturesBuildOneOfflinePrefixIndex(t *testing.T) {
	t.Parallel()

	revision := "fixture-revision"
	digest := "sha256:fixture"
	awsResult, err := aws.Parse(readFixture(t, "../../testdata/upstream/aws-ip-ranges.json"), revision, digest)
	if err != nil {
		t.Fatalf("parse AWS fixture: %v", err)
	}
	gcpResult, err := gcp.Parse(readFixture(t, "../../testdata/upstream/gcp-cloud.json"), revision, digest)
	if err != nil {
		t.Fatalf("parse GCP fixture: %v", err)
	}
	azureResult, err := azure.Parse(readFixture(t, "../../testdata/upstream/azure-service-tags.json"), revision, digest)
	if err != nil {
		t.Fatalf("parse Azure fixture: %v", err)
	}
	associations := append(awsResult.Associations, gcpResult.Associations...)
	associations = append(associations, azureResult.Associations...)
	index := prefix.New(associations)
	for _, association := range associations {
		results, coverage, lookupErr := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: association.Prefix.Addr(), Match: "all"}, model.AttributionView{})
		if lookupErr != nil {
			t.Fatalf("lookup %s: %v", association.Prefix, lookupErr)
		}
		if len(results) == 0 || coverage.Status != model.CoverageComplete {
			t.Fatalf("lookup %s = %#v, %#v", association.Prefix, results, coverage)
		}
		if association.SourceRevision != revision || association.SourceDigest != digest || len(association.RecordRefs) == 0 {
			t.Fatalf("association provenance is incomplete: %#v", association)
		}
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}
