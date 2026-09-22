package dns

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestCollectBoundsResolvedAddressesAcrossQuestions(t *testing.T) {
	limits := policy.DefaultLimits()
	limits.ResolvedAddresses = 1
	controller, err := policy.NewController(limits, 1, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question}
		if question.Type == typeA {
			result.Addresses = []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("8.8.8.8"),
			}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(ctx, "example.com", 443, nil)
	if len(result.Addresses) != 1 || result.Coverage.Status != model.CoveragePartial || result.Coverage.Omitted != 1 {
		t.Fatalf("Collect() result = %#v", result)
	}
	if !slices.Contains(result.Coverage.ErrorCodes, model.CodeBudgetExceeded) {
		t.Fatalf("coverage error codes = %v", result.Coverage.ErrorCodes)
	}
}
