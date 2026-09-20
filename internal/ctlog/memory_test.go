package ctlog

import (
	"context"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestMemoryStoreDiscoverIsBoundedDeterministicAndDoesNotExpandWildcards(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	wildcard := fixtureRecord("wild.example.com", "wild", base.Add(3*time.Minute))
	wildcard.Wildcard = true
	records := []Record{
		fixtureRecord("old.example.com", "old", base),
		fixtureRecord("new.example.com", "new", base.Add(2*time.Minute)),
		fixtureRecord("mid.example.com", "mid", base.Add(time.Minute)),
		wildcard,
	}
	if err := store.Import(context.Background(), records); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	first, err := store.Discover(context.Background(), "example.com", 2)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	second, err := store.Discover(context.Background(), "example.com", 2)
	if err != nil {
		t.Fatalf("Discover() second error = %v", err)
	}
	if first.IndexIdentity != second.IndexIdentity {
		t.Fatalf("index identities differ: %q != %q", first.IndexIdentity, second.IndexIdentity)
	}
	if first.Available != 3 || first.Omitted != 1 || len(first.Candidates) != 2 {
		t.Fatalf("Discover() result = %#v", first)
	}
	if first.Candidates[0].Hostname != "new.example.com" || first.Candidates[1].Hostname != "mid.example.com" {
		t.Fatalf("Discover() order = %#v", first.Candidates)
	}
}

func fixtureRecord(name, hash string, loggedAt time.Time) Record {
	passed := model.CTVerificationCheck{Status: model.CTCheckPassed, Procedure: "rfc6962", ProcedureVersion: "1"}
	return Record{
		Name: name, CertificateHash: hash, LoggedAt: loggedAt, SourceID: "fixture", Provenance: ProvenanceVerifiedLog,
		Verification: model.CTVerification{CheckpointSignature: passed, Continuity: passed, EntryInclusion: passed},
	}
}
