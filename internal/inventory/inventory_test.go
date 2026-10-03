package inventory

import (
	"context"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

type recordingStore struct {
	roots      []string
	sightings  []Sighting
	receipt    ImportReceipt
	searchPage Page
}

func (s *recordingStore) ImportInventoryChunk(_ context.Context, receipt ImportReceipt, _ string, roots []string, sightings []Sighting, _ time.Time) (ImportReceipt, error) {
	s.roots, s.sightings, s.receipt = roots, sightings, receipt
	return receipt, nil
}
func (s *recordingStore) SearchInventory(context.Context, SearchRequest, string) (Page, error) {
	return s.searchPage, nil
}
func (*recordingStore) ReadInventory(context.Context, string) (Asset, error) { return Asset{}, nil }

func (*recordingStore) SearchInventoryEvidence(context.Context, EvidenceQuery) (EvidencePage, error) {
	return EvidencePage{}, nil
}
func (*recordingStore) ReadInventoryEvidence(context.Context, string, string) (EvidenceResult, error) {
	return EvidenceResult{}, nil
}
func (*recordingStore) InventoryProjectionStatus(context.Context) (ProjectionStatus, error) {
	return ProjectionStatus{}, nil
}
func (*recordingStore) ArchiveInventory(context.Context, string, bool) (Asset, error) {
	return Asset{}, nil
}
func (*recordingStore) DeleteInventory(context.Context, string, bool) (int64, error) { return 0, nil }

func TestImportNormalizesAndClassifiesNames(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	old := time.Unix(10, 0).UTC()
	newer := time.Unix(20, 0).UTC()
	receipt, err := NewService(store).Import(t.Context(), ImportRequest{
		OperationID: "op", ChunkID: "chunk", SourceID: "export", ScopeRoots: []string{"Example.COM.", "dev.example.com"},
		Entries: []Entry{{Hostname: "API.Dev.Example.Com.", ObservedAt: &newer}, {Hostname: "api.dev.example.com", ObservedAt: &old},
			{Hostname: "example.com.evil"}, {Hostname: "*.example.com"}, {Hostname: "bad name"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Counts.Duplicate != 1 || receipt.Counts.OutOfScope != 1 || receipt.Counts.Wildcard != 1 || receipt.Counts.Invalid != 1 || len(store.sightings) != 1 {
		t.Fatalf("receipt=%#v sightings=%#v", receipt, store.sightings)
	}
	sighting := store.sightings[0]
	if sighting.Hostname != "api.dev.example.com" || sighting.AssetID != AssetID(sighting.Hostname) || len(sighting.ScopeRoots) != 2 || !sighting.FirstObservedAt.Equal(old) || !sighting.LastObservedAt.Equal(newer) {
		t.Fatalf("sighting = %#v", sighting)
	}
}

func TestSearchCursorBindsFilters(t *testing.T) {
	t.Parallel()
	request, _, err := PrepareSearch(SearchRequest{Mode: SearchDescendant, Query: "Example.COM.", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	request.Cursor = NextCursor(request, "api.example.com")
	_, after, err := PrepareSearch(request)
	if err != nil || after != "api.example.com" {
		t.Fatalf("cursor after = %q, %v", after, err)
	}
	request.Query = "other.example.com"
	if _, _, err := PrepareSearch(request); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("mismatched cursor = %v", err)
	}
	if _, _, err := PrepareSearch(SearchRequest{Mode: SearchPartial, Query: "ap"}); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("short unscoped search = %v", err)
	}
}

func TestNormalizeIDNAndLabelBoundary(t *testing.T) {
	t.Parallel()
	unicodeName, _, err := Normalize("Bücher.Example.")
	if err != nil {
		t.Fatal(err)
	}
	asciiName, _, err := Normalize("xn--bcher-kva.example")
	if err != nil {
		t.Fatal(err)
	}
	if unicodeName != asciiName || !WithinScope(unicodeName, "example") || WithinScope("example.evil", "example") {
		t.Fatalf("IDN normalization or scope boundary: %q, %q", unicodeName, asciiName)
	}
}
