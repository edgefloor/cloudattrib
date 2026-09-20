package cloudranges

import "testing"

func TestParsePreservesRetirementAndMasksHostBits(t *testing.T) {
	result, err := Parse([]byte(`{"provider":"Example","provider_id":"example","method":"published_list","ipv4":["192.0.2.1/24",{"address":"198.51.100.0/24","retired_at":"2026-09-20T00:00:00Z"}],"ipv6":[]}`), Input{Path: "json/example.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Associations) != 2 {
		t.Fatalf("associations = %d", len(result.Associations))
	}
	if result.Associations[0].Prefix.String() != "192.0.2.0/24" || result.Associations[1].Lifecycle != "retired" {
		t.Fatalf("unexpected result: %#v", result.Associations)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
}

func TestParseRejectsAmbiguousJSON(t *testing.T) {
	_, err := Parse([]byte(`{"provider":"Example","provider":"other","provider_id":"example","ipv4":[],"ipv6":[]}`), Input{Path: "json/example.json"})
	if err == nil {
		t.Fatal("Parse accepted duplicate key")
	}
}
