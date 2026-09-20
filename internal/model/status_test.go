package model

import (
	"encoding/json"
	"os"
	"testing"
)

func TestResultStatusContractFixtures(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/contracts/result-status.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixtures []struct {
		Name    string `json:"name"`
		Summary struct {
			UsablePath          bool `json:"usable_path"`
			UsefulEvidence      bool `json:"useful_evidence"`
			CompletedSearch     bool `json:"completed_search"`
			RequestedIncomplete bool `json:"requested_incomplete"`
			CollectionFailed    bool `json:"collection_failed"`
			Cancelled           bool `json:"cancelled"`
		} `json:"summary"`
		Want ExecutionDecision `json:"want"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			got := DecideExecution(ExecutionSummary{
				UsablePath:          fixture.Summary.UsablePath,
				UsefulEvidence:      fixture.Summary.UsefulEvidence,
				CompletedSearch:     fixture.Summary.CompletedSearch,
				RequestedIncomplete: fixture.Summary.RequestedIncomplete,
				CollectionFailed:    fixture.Summary.CollectionFailed,
				Cancelled:           fixture.Summary.Cancelled,
			})
			if got != fixture.Want {
				t.Fatalf("DecideExecution() = %#v, want %#v", got, fixture.Want)
			}
		})
	}
}
