package app

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	collectdns "cloudattrib/internal/collect/dns"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestAnalyzeRejectsQueryValuesBeforeCollection(t *testing.T) {
	t.Parallel()

	var queries atomic.Int64
	collector := collectdns.New(func(context.Context, model.DNSQuestion) (model.DNSResult, error) {
		queries.Add(1)
		return model.DNSResult{}, nil
	}, policy.PublicDestinationPolicy())
	service := NewService(Dependencies{DNS: collector, View: model.NewAttributionView("bundle", "policy", nil, nil)})
	_, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "https://example.com/path?token=QUERY_CANARY", Kind: model.TargetURL})
	if model.ErrorCodeOf(err) != model.CodeInvalidTarget {
		t.Fatalf("Analyze() error = %v, want invalid_target", err)
	}
	if strings.Contains(err.Error(), "QUERY_CANARY") {
		t.Fatalf("Analyze() error exposed query value: %v", err)
	}
	if queries.Load() != 0 {
		t.Fatalf("DNS queries = %d, want 0", queries.Load())
	}
}
