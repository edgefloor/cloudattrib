package dns

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestJobReusesQuestionsWithoutChangingObservationTime(t *testing.T) {
	var mu sync.Mutex
	calls := make(map[model.DNSQuestion]int)
	clock := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		mu.Lock()
		calls[question]++
		mu.Unlock()
		return model.DNSResult{Question: question, ResponseCode: 0, NegativeTTL: 7200}, nil
	}, policy.PublicDestinationPolicy())
	collector.now = func() time.Time { return clock }
	job := collector.NewJob()
	first := job.CollectOccurrence(t.Context(), "example.com", 443, model.ObservationOccurrence{CollectionRunID: "run", Seed: "example.com", SeedIndex: 0, Attempt: 1}, nil)
	clock = clock.Add(time.Hour)
	second := job.CollectOccurrence(t.Context(), "example.com", 443, model.ObservationOccurrence{CollectionRunID: "run", Seed: "example.com", SeedIndex: 1, Attempt: 1}, nil)
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != len(questionTypes)+1 {
		t.Fatalf("queries = %#v", calls)
	}
	for _, count := range calls {
		if count != 1 {
			t.Fatalf("query reused %d times", count)
		}
	}
	if len(first.Observations) != len(questionTypes)+1 || len(second.Observations) != len(questionTypes)+1 {
		t.Fatalf("observations = %d and %d", len(first.Observations), len(second.Observations))
	}
	byType := make(map[string]model.Observation)
	for _, observation := range first.Observations {
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		byType[payload.RRType] = observation
	}
	for _, observation := range second.Observations {
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		original := byType[payload.RRType]
		if !observation.ObservedAt.Equal(original.ObservedAt) || observation.ID == original.ID {
			t.Fatalf("cached observation = %#v, original = %#v", observation, original)
		}
	}
}

func TestJobBoundsDistinctQuestions(t *testing.T) {
	limits := policy.DefaultLimits()
	limits.DNSQuestions = len(questionTypes)
	var calls atomic.Int64
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		calls.Add(1)
		return model.DNSResult{Question: question, ResponseCode: 0}, nil
	}, policy.PublicDestinationPolicy()).WithLimits(limits)
	job := collector.NewJob()
	job.CollectOccurrence(t.Context(), "first.example", 443, model.ObservationOccurrence{CollectionRunID: "run", Seed: "first.example", Attempt: 1}, nil)
	second := job.CollectOccurrence(t.Context(), "second.example", 443, model.ObservationOccurrence{CollectionRunID: "run", Seed: "second.example", Attempt: 1}, nil)
	if calls.Load() != int64(len(questionTypes)) || second.Coverage.Status != model.CoveragePartial || second.Coverage.Omitted < len(questionTypes) {
		t.Fatalf("calls = %d, second coverage = %#v", calls.Load(), second.Coverage)
	}
}

func TestJobExpiresPositiveAndNegativeAnswers(t *testing.T) {
	clock := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	var calls atomic.Int64
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		calls.Add(1)
		result := model.DNSResult{Question: question, ResponseCode: 0, NegativeTTL: 30}
		if question.Type == typeCNAME {
			payload, _ := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: "target.example.net", TTL: 30})
			result.Records = []model.Observation{{Type: "dns_record", Status: "answered", Payload: payload}}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	collector.now = func() time.Time { return clock }
	job := collector.NewJob()
	for _, questionType := range []uint16{typeCNAME, typeMX} {
		question := model.DNSQuestion{Name: "EXAMPLE.COM.", Type: questionType}
		first, _, firstAt, cached := job.query(t.Context(), question)
		if cached || first.Question.Name != "example.com" {
			t.Fatalf("first query = %#v, cached=%t", first, cached)
		}
		clock = clock.Add(29 * time.Second)
		_, _, cachedAt, cached := job.query(t.Context(), question)
		if !cached || !cachedAt.Equal(firstAt) {
			t.Fatalf("answer was not reused within TTL: cached=%t at=%v first=%v", cached, cachedAt, firstAt)
		}
		clock = clock.Add(2 * time.Second)
		_, _, refreshedAt, cached := job.query(t.Context(), question)
		if cached || !refreshedAt.After(firstAt) {
			t.Fatalf("expired answer was reused: cached=%t at=%v first=%v", cached, refreshedAt, firstAt)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("network queries = %d, want four", calls.Load())
	}
}

func TestDifferentJobsObserveChangedDNSAnswers(t *testing.T) {
	var calls atomic.Int64
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		version := calls.Add(1)
		address := netip.MustParseAddr("93.184.216.34")
		if version > 1 {
			address = netip.MustParseAddr("1.1.1.1")
		}
		payload, _ := json.Marshal(model.DNSPayload{RRType: "A", Owner: question.Name, Address: address, TTL: 300})
		return model.DNSResult{Question: question, Outcome: model.DNSOutcomeAnswered, Addresses: []netip.Addr{address}, Records: []model.Observation{{Type: "dns_record", Payload: payload, Status: "answered", Subject: question.Name}}}, nil
	}, policy.PublicDestinationPolicy())
	question := model.DNSQuestion{Name: "redirect.example", Type: typeA}
	first, err := collector.NewJob().Query(t.Context(), question)
	if err != nil {
		t.Fatal(err)
	}
	second, err := collector.NewJob().Query(t.Context(), question)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || first.Addresses[0] == second.Addresses[0] {
		t.Fatalf("queries = %d, first = %#v, second = %#v", calls.Load(), first, second)
	}
}
