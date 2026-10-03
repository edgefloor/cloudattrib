package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

// redirectResolver shares the analysis DNS job with seed and dependency queries.
// Both address families run concurrently so a usable answer can start HTTP.
func redirectResolver(job *collectdns.Job, occurrence model.ObservationOccurrence, roots []string, retain func([]model.Observation)) collecthttp.StreamResolveFunc {
	return func(ctx context.Context, hostname string, hop int, publish func(netip.Addr)) error {
		type answer struct {
			result     model.DNSResult
			err        error
			observedAt time.Time
		}
		answers := make(chan answer, 2)
		for _, questionType := range []uint16{1, 28} {
			go func() {
				result, observedAt, err := job.QueryWithObservedAt(ctx, model.DNSQuestion{Name: hostname, Type: questionType})
				answers <- answer{result: result, err: err, observedAt: observedAt}
			}()
		}
		var failures []error
		omitted := 0
		accepted := 0
		for range 2 {
			item := <-answers
			retain(redirectDNSObservations(item.result, item.err, item.observedAt, hostname, hop, occurrence, roots))
			if item.err == nil {
				item.err = redirectOutcomeError(item.result)
			}
			if item.err != nil {
				failures = append(failures, item.err)
				omitted += max(item.result.Omitted, 1)
				continue
			}
			if item.result.Omitted > 0 {
				failures = append(failures, model.NewError(model.CodeBudgetExceeded, "redirect DNS response was truncated", nil))
				omitted += item.result.Omitted
			}
			for _, address := range item.result.Addresses {
				if !policy.ReserveAddress(ctx) {
					failures = append(failures, model.NewError(model.CodeBudgetExceeded, "resolved address budget exhausted", nil))
					omitted++
					continue
				}
				accepted++
				publish(address.Unmap())
			}
		}
		if len(failures) == 0 {
			return nil
		}
		failure := errors.Join(failures...)
		if accepted == 0 {
			return failure
		}
		return &collecthttp.PartialResolutionError{Omitted: omitted, Err: failure}
	}
}

func redirectDNSObservations(result model.DNSResult, queryErr error, observedAt time.Time, hostname string, hop int, base model.ObservationOccurrence, roots []string) []model.Observation {
	questionType := result.Question.Type
	requestIndex := 0
	rrtype := "A"
	if questionType == 28 {
		requestIndex = 1
		rrtype = "AAAA"
	}
	itemOccurrence := base
	itemOccurrence.Hop = hop
	itemOccurrence.RequestIndex = requestIndex
	outcome := redirectOutcome(result)
	if queryErr != nil {
		switch {
		case errors.Is(queryErr, context.DeadlineExceeded), model.ErrorCodeOf(queryErr) == model.CodeTimeout:
			outcome = model.DNSOutcomeTimeout
		case errors.Is(queryErr, context.Canceled), model.ErrorCodeOf(queryErr) == model.CodeCancelled:
			outcome = model.DNSOutcomeCancelled
		case model.ErrorCodeOf(queryErr) == model.CodeBudgetExceeded:
			outcome = model.DNSOutcomeBudgetExhausted
		default:
			outcome = model.DNSOutcomeFailed
		}
	}
	reason := ""
	if queryErr != nil {
		reason = queryErr.Error()
	}
	queryPayload, _ := json.Marshal(model.DNSPayload{
		RRType: rrtype, Owner: hostname, Outcome: outcome, ResponseCode: result.ResponseCode,
		Resolver: result.Resolver, Transport: result.Transport, PolicyReason: reason,
	})
	observations := []model.Observation{{
		ID: model.ObservationID("redirect-dns-query", itemOccurrence, hostname, rrtype), Type: "dns_query",
		Subject: hostname, Scope: redirectDNSScope(hostname, roots), ObservedAt: observedAt,
		Status: string(outcome), Payload: queryPayload,
	}}
	if outcome != model.DNSOutcomeAnswered {
		return observations
	}
	for index, record := range result.Records {
		recordOccurrence := itemOccurrence
		recordOccurrence.ItemIndex = index
		record.ID = model.ObservationID("redirect-dns-record", recordOccurrence, hostname, rrtype)
		if record.ObservedAt.IsZero() {
			record.ObservedAt = observedAt
		}
		record.Scope = redirectDNSScope(record.Subject, roots)
		observations = append(observations, record)
	}
	return observations
}

func redirectDNSScope(hostname string, roots []string) model.Scope {
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	if slices.Contains(roots, hostname) {
		return model.ScopeRoot
	}
	for _, root := range roots {
		if strings.HasSuffix(hostname, "."+root) {
			return model.ScopeSubdomain
		}
	}
	return model.ScopeExternalRedirect
}

func redirectOutcome(result model.DNSResult) model.DNSOutcome {
	if result.Outcome != "" {
		return result.Outcome
	}
	switch result.ResponseCode {
	case 0:
		if len(result.Addresses) > 0 || len(result.Records) > 0 {
			return model.DNSOutcomeAnswered
		}
		return model.DNSOutcomeNoData
	case 3:
		return model.DNSOutcomeNXDomain
	case 2:
		return model.DNSOutcomeSERVFAIL
	case 5:
		return model.DNSOutcomeRefused
	default:
		return model.DNSOutcomeFailed
	}
}

func redirectOutcomeError(result model.DNSResult) error {
	switch redirectOutcome(result) {
	case model.DNSOutcomeAnswered, model.DNSOutcomeNoData, model.DNSOutcomeNXDomain:
		return nil
	case model.DNSOutcomeTimeout:
		return model.NewError(model.CodeTimeout, "redirect DNS query timed out", nil)
	case model.DNSOutcomeCancelled:
		return model.NewError(model.CodeCancelled, "redirect DNS query was cancelled", nil)
	case model.DNSOutcomeBudgetExhausted:
		return model.NewError(model.CodeBudgetExceeded, "redirect DNS query budget exhausted", nil)
	default:
		return model.NewError(model.CodeCollectionFailed, "redirect DNS query failed", nil)
	}
}
