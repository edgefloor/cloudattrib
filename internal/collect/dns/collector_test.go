package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "fixture timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

func TestCollectDistinguishesNegativeAnswersFromProtocolFailures(t *testing.T) {
	t.Parallel()

	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		responseCode := 0
		switch question.Type {
		case typeAAAA:
			responseCode = 3
		case typeCNAME:
			responseCode = 2
		case typeMX:
			responseCode = 5
		}
		return model.DNSResult{Question: question, ResponseCode: responseCode}, nil
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(t.Context(), "example.com", 443, nil)
	statuses := make(map[string]string)
	for _, observation := range result.Observations {
		if observation.Type != "dns_query" {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		statuses[payload.RRType] = observation.Status
	}
	if statuses["A"] != "nodata" || statuses["AAAA"] != "nxdomain" || statuses["CNAME"] != "servfail" || statuses["MX"] != "refused" {
		t.Fatalf("query statuses = %#v", statuses)
	}
	if result.Coverage.Status != model.CoveragePartial || result.Coverage.Completed != 4 {
		t.Fatalf("coverage = %#v", result.Coverage)
	}
}

func TestCollectDoesNotPublishAddressesFromFailedDNSResponse(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("93.184.216.34")
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		return model.DNSResult{Question: question, ResponseCode: 2, Addresses: []netip.Addr{address}}, nil
	}, policy.PublicDestinationPolicy())
	published := 0
	result := collector.Collect(t.Context(), "example.com", 443, func(Candidate) { published++ })
	if published != 0 || len(result.Addresses) != 0 {
		t.Fatalf("published = %d, addresses = %v", published, result.Addresses)
	}
}

func TestCollectPublishesEachApprovedAddressOnce(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("93.184.216.34")
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		if question.Type != typeA {
			return model.DNSResult{Question: question, ResponseCode: 0}, nil
		}
		return model.DNSResult{Question: question, ResponseCode: 0, Addresses: []netip.Addr{address, address}}, nil
	}, policy.PublicDestinationPolicy())
	published := 0
	collector.Collect(t.Context(), "example.com", 443, func(Candidate) { published++ })
	if published != 1 {
		t.Fatalf("published candidates = %d, want 1", published)
	}
}

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

func TestCollectCountsReportedNetworkAttempts(t *testing.T) {
	t.Parallel()

	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		attempts := 1
		if question.Type == typeA {
			attempts = 2
		}
		return model.DNSResult{Question: question, Attempt: attempts}, nil
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(t.Context(), "example.com", 443, nil)
	if result.Coverage.Attempted != 7 {
		t.Fatalf("coverage attempted = %d, want 7", result.Coverage.Attempted)
	}
}

func TestCollectCountsBudgetDeniedQuestionsAsOmitted(t *testing.T) {
	t.Parallel()

	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		if question.Type == typeA {
			return model.DNSResult{Question: question, Attempt: 1}, nil
		}
		return model.DNSResult{Question: question, Outcome: model.DNSOutcomeBudgetExhausted}, model.NewError(model.CodeBudgetExceeded, "DNS question budget exhausted", nil)
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(t.Context(), "example.com", 443, nil)
	if result.Coverage.Attempted != 1 || result.Coverage.Omitted != len(questionTypes)-1 {
		t.Fatalf("coverage = %#v, want one attempt and %d omitted", result.Coverage, len(questionTypes)-1)
	}
	if !slices.Contains(result.Coverage.ErrorCodes, model.CodeBudgetExceeded) {
		t.Fatalf("coverage error codes = %v, want budget_exceeded", result.Coverage.ErrorCodes)
	}
}

func TestCollectReportsTerminalDeadlineAsTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	collector := New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		return model.DNSResult{Question: question}, ctx.Err()
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(ctx, "example.com", 443, nil)
	if !slices.Contains(result.Coverage.ErrorCodes, model.CodeTimeout) {
		t.Fatalf("coverage error codes = %v, want timeout", result.Coverage.ErrorCodes)
	}
	if slices.Contains(result.Coverage.ErrorCodes, model.CodeCancelled) {
		t.Fatalf("coverage error codes = %v, do not want cancelled", result.Coverage.ErrorCodes)
	}
}

func TestErrorCodeDistinguishesTimeoutFromCollectionFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want model.ErrorCode
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: model.CodeTimeout},
		{name: "network timeout", err: timeoutError{}, want: model.CodeTimeout},
		{name: "cancellation", err: context.Canceled, want: model.CodeCancelled},
		{name: "transport failure", err: errors.New("malformed DNS response"), want: model.CodeCollectionFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := errorCode(test.err); got != test.want {
				t.Fatalf("errorCode() = %q, want %q", got, test.want)
			}
		})
	}
}
