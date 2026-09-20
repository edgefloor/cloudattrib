package aggregate

import (
	"math/rand/v2"
	"reflect"
	"testing"

	"cloudattrib/internal/model"
)

func TestBuildDeduplicatesEvidenceAndIsOrderIndependent(t *testing.T) {
	t.Parallel()

	input := []model.Evidence{
		{ID: "b", ObservationIDs: []string{"obs-1"}, DetectorID: "rules-v1", RuleID: "rule-1", Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Category: "cdn", Relation: model.RelationWebDelivery, Scope: model.ScopeRoot, Strength: model.StrengthModerate, Activity: model.ActivityConfigured},
		{ID: "a", ObservationIDs: []string{"obs-1"}, DetectorID: "rules-v1", RuleID: "rule-1", Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Category: "cdn", Relation: model.RelationWebDelivery, Scope: model.ScopeRoot, Strength: model.StrengthStrong, Activity: model.ActivityConfigured},
		{ID: "a", ObservationIDs: []string{"obs-1"}, DetectorID: "rules-v1", RuleID: "rule-1", Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Category: "cdn", Relation: model.RelationWebDelivery, Scope: model.ScopeRoot, Strength: model.StrengthStrong, Activity: model.ActivityConfigured},
	}
	want := Build(input)
	if got := want[0].EvidenceIDs; !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("EvidenceIDs = %#v, want correlated source once", got)
	}
	if want[0].Strength != model.StrengthStrong {
		t.Fatalf("Strength = %q, want strong", want[0].Strength)
	}

	shuffled := append([]model.Evidence(nil), input...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	if got := Build(shuffled); !reflect.DeepEqual(got, want) {
		t.Fatalf("Build(shuffled) = %#v, want %#v", got, want)
	}
}
