package model

import "testing"

func TestObservationIDUsesEveryOccurrenceDimension(t *testing.T) {
	t.Parallel()

	base := ObservationOccurrence{
		CollectionRunID: "run-1",
		Seed:            "example.com",
		SeedIndex:       1,
		RequestIndex:    2,
		Hop:             3,
		Attempt:         4,
		ItemIndex:       5,
	}
	baseID := ObservationID("http-response", base, "GET", "https", "example.com", "/path")
	tests := []struct {
		name       string
		occurrence ObservationOccurrence
	}{
		{name: "collection run", occurrence: func() ObservationOccurrence { value := base; value.CollectionRunID = "run-2"; return value }()},
		{name: "seed", occurrence: func() ObservationOccurrence { value := base; value.Seed = "www.example.com"; return value }()},
		{name: "seed index", occurrence: func() ObservationOccurrence { value := base; value.SeedIndex++; return value }()},
		{name: "request index", occurrence: func() ObservationOccurrence { value := base; value.RequestIndex++; return value }()},
		{name: "hop", occurrence: func() ObservationOccurrence { value := base; value.Hop++; return value }()},
		{name: "attempt", occurrence: func() ObservationOccurrence { value := base; value.Attempt++; return value }()},
		{name: "item index", occurrence: func() ObservationOccurrence { value := base; value.ItemIndex++; return value }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ObservationID("http-response", test.occurrence, "GET", "https", "example.com", "/path"); got == baseID {
				t.Fatalf("ObservationID() = %q after changing %s", got, test.name)
			}
		})
	}
}
