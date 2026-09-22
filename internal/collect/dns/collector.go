// Package dns collects raw DNS outcomes and publishes approved addresses early.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

const (
	typeA     = 1
	typeNS    = 2
	typeCNAME = 5
	typeMX    = 15
	typeTXT   = 16
	typeAAAA  = 28
)

var questionTypes = []uint16{typeA, typeAAAA, typeCNAME, typeMX, typeNS, typeTXT}

// QueryFunc performs one raw DNS question.
type QueryFunc func(context.Context, model.DNSQuestion) (model.DNSResult, error)

// Candidate is one independently approved address for HTTP collection.
type Candidate struct {
	Hostname string
	Address  netip.Addr
	Port     uint16
}

// Result contains all completed DNS work after candidate publication.
type Result struct {
	Observations []model.Observation
	Coverage     model.Coverage
	Addresses    []netip.Addr
}

// Collector runs bounded raw DNS questions through an injected client.
type Collector struct {
	query  QueryFunc
	policy policy.DestinationPolicy
	now    func() time.Time
}

// New constructs a collector without starting background work.
func New(query QueryFunc, destinationPolicy policy.DestinationPolicy) *Collector {
	return &Collector{query: query, policy: destinationPolicy, now: time.Now}
}

// Collect waits for every configured question. It calls onCandidate as soon as
// an independently approved A or AAAA answer arrives.
func (c *Collector) Collect(ctx context.Context, hostname string, port uint16, onCandidate func(Candidate)) Result {
	runID, err := model.NewCollectionRunID()
	if err != nil {
		return Result{Coverage: model.Coverage{
			Capability: "dns", Status: model.CoverageUnavailable, ErrorCodes: []model.ErrorCode{model.CodeCollectionFailed}, Reason: "create collection run ID",
		}}
	}
	return c.CollectOccurrence(ctx, hostname, port, model.ObservationOccurrence{CollectionRunID: runID, Seed: hostname, Attempt: 1}, onCandidate)
}

// CollectOccurrence waits for every configured question using caller-owned
// collection occurrence context.
func (c *Collector) CollectOccurrence(ctx context.Context, hostname string, port uint16, occurrence model.ObservationOccurrence, onCandidate func(Candidate)) Result {
	type queryResult struct {
		result     model.DNSResult
		occurrence model.ObservationOccurrence
		err        error
	}
	results := make(chan queryResult)
	var wg sync.WaitGroup
	for requestIndex, questionType := range questionTypes {
		question := model.DNSQuestion{Name: hostname, Type: questionType}
		queryOccurrence := occurrence
		queryOccurrence.RequestIndex = requestIndex
		wg.Go(func() {
			result, err := c.query(ctx, question)
			if result.Attempt > 0 {
				queryOccurrence.Attempt = result.Attempt
			}
			select {
			case results <- queryResult{result: result, occurrence: queryOccurrence, err: err}:
			case <-ctx.Done():
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	collected := Result{Coverage: model.Coverage{Capability: "dns", Status: model.CoverageComplete, Attempted: len(questionTypes)}}
	publishedAddresses := make(map[netip.Addr]struct{})
	for item := range results {
		outcome := normalizeOutcome(item.result, item.err)
		if item.err != nil {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(item.err))
			collected.Observations = append(collected.Observations, c.queryObservation(hostname, item.result.Question, outcome, item.result, item.err.Error(), item.occurrence))
			continue
		}
		if dnsOutcomeCompleted(outcome) {
			collected.Coverage.Completed++
		} else {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeCollectionFailed)
		}
		collected.Observations = append(collected.Observations, c.queryObservation(hostname, item.result.Question, outcome, item.result, "", item.occurrence))
		if outcome != model.DNSOutcomeAnswered {
			continue
		}
		if item.result.Omitted > 0 {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted += item.result.Omitted
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeBudgetExceeded)
		}
		for recordIndex, observation := range item.result.Records {
			if observation.ObservedAt.IsZero() {
				observation.ObservedAt = c.now()
			}
			recordOccurrence := item.occurrence
			recordOccurrence.ItemIndex = recordIndex
			observation.ID = model.ObservationID("dns-record", recordOccurrence)
			collected.Observations = append(collected.Observations, observation)
		}
		for addressIndex, address := range item.result.Addresses {
			address = address.Unmap()
			if !policy.ReserveAddress(ctx) {
				collected.Coverage.Status = model.CoveragePartial
				collected.Coverage.Omitted++
				collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeBudgetExceeded)
				continue
			}
			collected.Addresses = append(collected.Addresses, address)
			decision := c.policy.Check(address, port)
			status := "answered"
			if !decision.Allowed {
				status = "policy_blocked"
				collected.Coverage.Status = model.CoveragePartial
				collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodePolicyBlocked)
			}
			payload := model.DNSPayload{RRType: typeName(item.result.Question.Type), Owner: hostname, Address: address, PolicyReason: string(decision.Reason)}
			addressOccurrence := item.occurrence
			addressOccurrence.ItemIndex = addressIndex
			collected.Observations = append(collected.Observations, model.Observation{
				ID:         model.ObservationID("dns-address", addressOccurrence),
				Type:       "dns_address",
				Subject:    hostname,
				Scope:      model.ScopeRoot,
				ObservedAt: c.now(),
				Status:     status,
				Payload:    marshalPayload(payload),
			})
			if decision.Allowed && onCandidate != nil {
				if _, published := publishedAddresses[address]; !published {
					publishedAddresses[address] = struct{}{}
					onCandidate(Candidate{Hostname: hostname, Address: address, Port: port})
				}
			}
		}
	}
	if ctx.Err() != nil {
		collected.Coverage.Status = model.CoveragePartial
		collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeCancelled)
	}
	return collected
}

func (c *Collector) queryObservation(hostname string, question model.DNSQuestion, outcome model.DNSOutcome, result model.DNSResult, reason string, occurrence model.ObservationOccurrence) model.Observation {
	payload := model.DNSPayload{
		RRType:       typeName(question.Type),
		Owner:        hostname,
		Outcome:      outcome,
		ResponseCode: result.ResponseCode,
		Resolver:     result.Resolver,
		Transport:    result.Transport,
		PolicyReason: reason,
	}
	return model.Observation{
		ID:         model.ObservationID("dns-query", occurrence, hostname, fmt.Sprint(question.Type)),
		Type:       "dns_query",
		Subject:    hostname,
		Scope:      model.ScopeRoot,
		ObservedAt: c.now(),
		Status:     string(outcome),
		Payload:    marshalPayload(payload),
	}
}

func normalizeOutcome(result model.DNSResult, err error) model.DNSOutcome {
	if result.Outcome != "" {
		return result.Outcome
	}
	if err != nil {
		return outcomeForError(err)
	}
	switch result.ResponseCode {
	case 0:
		if len(result.Records) == 0 && len(result.Addresses) == 0 {
			return model.DNSOutcomeNoData
		}
		return model.DNSOutcomeAnswered
	case 2:
		return model.DNSOutcomeSERVFAIL
	case 3:
		return model.DNSOutcomeNXDomain
	case 5:
		return model.DNSOutcomeRefused
	default:
		return model.DNSOutcomeFailed
	}
}

func dnsOutcomeCompleted(outcome model.DNSOutcome) bool {
	return outcome == model.DNSOutcomeAnswered || outcome == model.DNSOutcomeNoData || outcome == model.DNSOutcomeNXDomain
}

func marshalPayload(value any) model.JSONValue {
	data, err := json.Marshal(value)
	if err != nil {
		return model.JSONValue("null")
	}
	return data
}

func errorCode(err error) model.ErrorCode {
	if code := model.ErrorCodeOf(err); code != "" {
		return code
	}
	if errors.Is(err, context.Canceled) {
		return model.CodeCancelled
	}
	return model.CodeTimeout
}

func typeName(value uint16) string {
	switch value {
	case typeA:
		return "A"
	case typeAAAA:
		return "AAAA"
	case typeCNAME:
		return "CNAME"
	case typeMX:
		return "MX"
	case typeNS:
		return "NS"
	case typeTXT:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE%d", value)
	}
}
