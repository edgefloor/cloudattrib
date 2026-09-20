package model

import "testing"

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
