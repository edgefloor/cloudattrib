package app

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	collectdns "cloudattrib/internal/collect/dns"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestAnalyzeReportsConfiguredSeedLimit(t *testing.T) {
	limits := policy.DefaultLimits()
	limits.SeedHostnames = 1
	var mu sync.Mutex
	queried := make(map[string]int)
	collector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		mu.Lock()
		queried[question.Name]++
		mu.Unlock()
		return model.DNSResult{Question: question}, nil
	}, policy.PublicDestinationPolicy())
	service := NewService(Dependencies{DNS: collector, Limits: limits, View: model.NewAttributionView("bundle", "policy", nil, nil)})

	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{
		Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS,
		IncludeWWW: &includeWWW, AdditionalHostnames: []string{"a.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(queried) != 1 || queried["example.com"] != 6 {
		t.Fatalf("queried hostnames = %#v", queried)
	}
	if report.Status != model.StatusPartial || !hasCoverageError(report.Coverage, "seed_hostnames", model.CodeBudgetExceeded) {
		t.Fatalf("report status = %q, coverage = %#v", report.Status, report.Coverage)
	}
}

func TestLookupIPRejectsAssociationOverflow(t *testing.T) {
	limits := policy.DefaultLimits()
	limits.PrefixAssociations = 1
	service := NewService(Dependencies{
		Prefixes: overflowingPrefixReader{},
		Limits:   limits,
		View: model.NewAttributionView("bundle", "policy", nil, []model.CapabilityState{
			{Name: "prefix", Status: model.CoverageComplete},
			{Name: "asn", Status: model.CoverageUnavailable},
		}),
	})

	_, err := service.LookupIP(t.Context(), model.IPLookupRequest{Address: netip.MustParseAddr("198.51.100.7")})
	if model.ErrorCodeOf(err) != model.CodeBudgetExceeded {
		t.Fatalf("LookupIP() error = %v", err)
	}
}

func TestServicesShareTargetAdmissionAcrossBundleAnalyzers(t *testing.T) {
	limits := policy.DefaultLimits()
	controller, err := policy.NewController(limits, 1, 8, 4)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	releaseQueries := make(chan struct{})
	var startedOnce sync.Once
	firstCollector := collectdns.New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-ctx.Done():
			return model.DNSResult{Question: question}, ctx.Err()
		case <-releaseQueries:
			return model.DNSResult{Question: question}, nil
		}
	}, policy.PublicDestinationPolicy())
	var secondQueries atomic.Int64
	secondCollector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		secondQueries.Add(1)
		return model.DNSResult{Question: question}, nil
	}, policy.PublicDestinationPolicy())
	view := model.NewAttributionView("bundle", "policy", nil, nil)
	firstService := NewService(Dependencies{DNS: firstCollector, Controller: controller, Limits: limits, View: view})
	secondService := NewService(Dependencies{DNS: secondCollector, Controller: controller, Limits: limits, View: view})
	request := model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS}

	firstDone := make(chan error, 1)
	go func() {
		_, analyzeErr := firstService.Analyze(t.Context(), request)
		firstDone <- analyzeErr
	}()
	<-started
	waitCtx, cancelWait := context.WithCancel(t.Context())
	secondDone := make(chan error, 1)
	go func() {
		_, analyzeErr := secondService.Analyze(waitCtx, request)
		secondDone <- analyzeErr
	}()
	cancelWait()
	if err := <-secondDone; model.ErrorCodeOf(err) != model.CodeCancelled {
		t.Fatalf("cancelled Analyze() error = %v", err)
	}
	if got := secondQueries.Load(); got != 0 {
		t.Fatalf("second analyzer queries before admission = %d", got)
	}
	close(releaseQueries)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Analyze() error = %v", err)
	}
	if _, err := secondService.Analyze(t.Context(), request); err != nil {
		t.Fatalf("third Analyze() error = %v", err)
	}
	if got := secondQueries.Load(); got != 12 {
		t.Fatalf("second analyzer queries after admission = %d, want 12", got)
	}
}

type overflowingPrefixReader struct{}

func (overflowingPrefixReader) LookupPrefixes(context.Context, model.IPLookupRequest, model.AttributionView) ([]model.Association, model.Coverage, error) {
	return []model.Association{{ID: "one"}, {ID: "two"}}, model.Coverage{Capability: "prefix", Status: model.CoverageComplete, Attempted: 1, Completed: 1}, nil
}

func hasCoverageError(coverage []model.Coverage, capability string, code model.ErrorCode) bool {
	for _, item := range coverage {
		if item.Capability != capability {
			continue
		}
		for _, itemCode := range item.ErrorCodes {
			if itemCode == code {
				return true
			}
		}
	}
	return false
}
