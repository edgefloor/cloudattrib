package runtime

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"cloudattrib/internal/collect/http"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestRedirectResolverRetainsAddressesWhenOtherFamilyFails(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		outcome model.DNSOutcome
		code    model.ErrorCode
	}{
		{outcome: model.DNSOutcomeSERVFAIL, code: model.CodeCollectionFailed},
		{outcome: model.DNSOutcomeRefused, code: model.CodeCollectionFailed},
		{outcome: model.DNSOutcomeFailed, code: model.CodeCollectionFailed},
		{outcome: model.DNSOutcomeTimeout, code: model.CodeTimeout},
		{outcome: model.DNSOutcomeCancelled, code: model.CodeCancelled},
		{outcome: model.DNSOutcomeBudgetExhausted, code: model.CodeBudgetExceeded},
	} {
		t.Run(string(test.outcome), func(t *testing.T) {
			t.Parallel()
			want := netip.MustParseAddr("93.184.216.34")
			resolve := newRedirectResolver(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
				switch question.Type {
				case 1:
					return model.DNSResult{Question: question, Outcome: model.DNSOutcomeAnswered, Addresses: []netip.Addr{want}}, nil
				case 28:
					return model.DNSResult{Question: question, Outcome: test.outcome}, nil
				default:
					t.Fatalf("unexpected question type %d", question.Type)
					return model.DNSResult{}, nil
				}
			})

			addresses, err := resolve(t.Context(), "redirect.example")
			var partial *http.PartialResolutionError
			if !errors.As(err, &partial) {
				t.Fatalf("resolve() error = %v, want PartialResolutionError", err)
			}
			if !slices.Equal(addresses, []netip.Addr{want}) || partial.Omitted != 1 || model.ErrorCodeOf(partial.Err) != test.code {
				t.Fatalf("resolve() = %v, %#v", addresses, partial)
			}
		})
	}
}

func TestRedirectResolverRetainsAcceptedAddressesAtAddressLimit(t *testing.T) {
	t.Parallel()

	first := netip.MustParseAddr("93.184.216.34")
	second := netip.MustParseAddr("1.1.1.1")
	limits := policy.DefaultLimits()
	limits.ResolvedAddresses = 1
	controller, err := policy.NewController(limits, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	resolve := newRedirectResolver(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		if question.Type == 1 {
			return model.DNSResult{Question: question, Outcome: model.DNSOutcomeAnswered, Addresses: []netip.Addr{first, second}}, nil
		}
		return model.DNSResult{Question: question, Outcome: model.DNSOutcomeNoData}, nil
	})

	addresses, err := resolve(ctx, "redirect.example")
	var partial *http.PartialResolutionError
	if !errors.As(err, &partial) {
		t.Fatalf("resolve() error = %v, want PartialResolutionError", err)
	}
	if !slices.Equal(addresses, []netip.Addr{first}) || partial.Omitted != 1 || model.ErrorCodeOf(partial.Err) != model.CodeBudgetExceeded {
		t.Fatalf("resolve() = %v, %#v", addresses, partial)
	}
}
