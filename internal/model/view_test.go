package model

import (
	"testing"
	"time"
)

func TestAttributionViewCopiesMutableInputAndOutput(t *testing.T) {
	t.Parallel()

	detectors := []string{"detector-a"}
	capabilities := []CapabilityState{{Name: "dns", Status: CoverageComplete}}
	view := NewAttributionView("bundle-a", "policy-a", detectors, capabilities)
	detectors[0] = "changed"
	capabilities[0].Name = "changed"

	gotDetectors := view.DetectorIDs()
	gotCapabilities := view.Capabilities()
	gotDetectors[0] = "changed-again"
	gotCapabilities[0].Name = "changed-again"

	if view.DetectorIDs()[0] != "detector-a" || view.Capabilities()[0].Name != "dns" {
		t.Fatal("caller mutation changed immutable view")
	}
}

func TestAttributionViewCalculatesSourceAgeAtUseTime(t *testing.T) {
	published := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	view := NewAttributionView("bundle", "policy", nil, []CapabilityState{
		{Name: "dated", Status: CoverageComplete, PublishedAt: &published},
		{Name: "unknown", Status: CoverageComplete},
	})
	published = published.Add(72 * time.Hour)
	first := view.CapabilitiesAt(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))
	second := view.CapabilitiesAt(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC))
	if first[0].SourceAge == nil || *first[0].SourceAge != 24*time.Hour || second[0].SourceAge == nil || *second[0].SourceAge != 72*time.Hour {
		t.Fatalf("source ages = %#v then %#v", first, second)
	}
	if first[1].SourceAge != nil || second[1].SourceAge != nil {
		t.Fatal("unknown publication time acquired a source age")
	}
	*first[0].PublishedAt = time.Time{}
	*first[0].SourceAge = 0
	if *view.CapabilitiesAt(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))[0].SourceAge != 24*time.Hour {
		t.Fatal("caller changed immutable source provenance")
	}
	future := view.CapabilitiesAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if future[0].SourceAge == nil || *future[0].SourceAge != 0 {
		t.Fatalf("future publication age = %#v", future[0].SourceAge)
	}
}
