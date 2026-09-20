package ctlog

import (
	"context"
	"strings"
	"testing"
)

func TestImportJSONLFiltersScopeAndDeduplicates(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	input := strings.Join([]string{
		`{"name":"API.Example.COM","certificate_hash":"one","logged_at":"2026-09-20T10:00:00Z","source_id":"fixture","provenance":"imported_unverified","verification":{"checkpoint_signature":{"status":"not_performed","procedure":"import","procedure_version":"1"},"continuity":{"status":"not_performed","procedure":"import","procedure_version":"1"},"entry_inclusion":{"status":"not_performed","procedure":"import","procedure_version":"1"}}}`,
		`{"name":"api.example.com","certificate_hash":"one","logged_at":"2026-09-20T10:00:00Z","source_id":"fixture","provenance":"imported_unverified","verification":{"checkpoint_signature":{"status":"not_performed","procedure":"import","procedure_version":"1"},"continuity":{"status":"not_performed","procedure":"import","procedure_version":"1"},"entry_inclusion":{"status":"not_performed","procedure":"import","procedure_version":"1"}}}`,
		`{"name":"other.test","certificate_hash":"two","logged_at":"2026-09-20T10:00:00Z","source_id":"fixture","provenance":"imported_unverified","verification":{"checkpoint_signature":{"status":"not_performed","procedure":"import","procedure_version":"1"},"continuity":{"status":"not_performed","procedure":"import","procedure_version":"1"},"entry_inclusion":{"status":"not_performed","procedure":"import","procedure_version":"1"}}}`,
	}, "\n")

	count, err := ImportJSONL(context.Background(), strings.NewReader(input), []string{"example.com"}, store)
	if err != nil {
		t.Fatalf("ImportJSONL() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("ImportJSONL() count = %d, want 1", count)
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Hostname != "api.example.com" {
		t.Fatalf("Discover() candidates = %#v", result.Candidates)
	}
}

func TestImportJSONLRejectsTrailingJSONWithoutPublishing(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	input := `{"name":"api.example.com","certificate_hash":"one","logged_at":"2026-09-20T10:00:00Z","source_id":"fixture","provenance":"imported_unverified","verification":{"checkpoint_signature":{"status":"not_performed","procedure":"import","procedure_version":"1"},"continuity":{"status":"not_performed","procedure":"import","procedure_version":"1"},"entry_inclusion":{"status":"not_performed","procedure":"import","procedure_version":"1"}}} {}`
	if _, err := ImportJSONL(context.Background(), strings.NewReader(input), []string{"example.com"}, store); err == nil {
		t.Fatal("ImportJSONL() error = nil, want syntax error")
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Candidates) != 0 {
		t.Fatalf("Discover() published candidates = %#v", result.Candidates)
	}
}

func TestImportJSONLDowngradesUnprovenVerifiedRecord(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	input := `{"name":"bad.example.com","certificate_hash":"two","logged_at":"2026-09-20T10:00:00Z","source_id":"fixture","provenance":"verified_log","verification":{"checkpoint_signature":{"status":"passed","procedure":"rfc6962","procedure_version":"1"},"continuity":{"status":"passed","procedure":"rfc6962","procedure_version":"1"},"entry_inclusion":{"status":"passed","procedure":"rfc6962","procedure_version":"1"}}}`
	if _, err := ImportJSONL(context.Background(), strings.NewReader(input), []string{"example.com"}, store); err != nil {
		t.Fatalf("ImportJSONL() error = %v", err)
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.Candidates[0].Provenance != ProvenanceImportedUnverified {
		t.Fatalf("import provenance = %q", result.Candidates[0].Provenance)
	}
}
