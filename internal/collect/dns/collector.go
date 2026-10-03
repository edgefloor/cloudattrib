// Package dns collects raw DNS outcomes and publishes approved addresses early.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	typeSOA   = 6
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
	limits policy.Limits
}

// New constructs a collector without starting background work.
func New(query QueryFunc, destinationPolicy policy.DestinationPolicy) *Collector {
	return &Collector{query: query, policy: destinationPolicy, now: time.Now, limits: policy.DefaultLimits()}
}

// WithLimits configures graph depth and question budgets before collection starts.
func (c *Collector) WithLimits(limits policy.Limits) *Collector {
	c.limits = limits
	return c
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
	return c.NewJob().CollectOccurrence(ctx, hostname, port, occurrence, onCandidate)
}

func (c *Collector) collectOccurrence(ctx context.Context, job *Job, hostname string, port uint16, occurrence model.ObservationOccurrence, onCandidate func(Candidate)) Result {
	type queryResult struct {
		result     model.DNSResult
		occurrence model.ObservationOccurrence
		err        error
		observedAt time.Time
		fromCache  bool
	}
	results := make(chan queryResult)
	var wg sync.WaitGroup
	for requestIndex, questionType := range questionTypes {
		question := model.DNSQuestion{Name: hostname, Type: questionType}
		queryOccurrence := occurrence
		queryOccurrence.RequestIndex = requestIndex
		wg.Go(func() {
			result, observedAt, fromCache, err := job.query(ctx, question)
			if result.Attempt > 0 {
				queryOccurrence.Attempt = result.Attempt
			}
			results <- queryResult{result: result, occurrence: queryOccurrence, err: err, observedAt: observedAt, fromCache: fromCache}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	collected := Result{Coverage: model.Coverage{Capability: "dns", Status: model.CoverageComplete}}
	publishedAddresses := make(map[netip.Addr]struct{})
	var publishMu sync.Mutex
	allPublished := make(map[netip.Addr]struct{})
	publish := onCandidate
	if onCandidate != nil {
		publish = func(candidate Candidate) {
			publishMu.Lock()
			defer publishMu.Unlock()
			if _, exists := allPublished[candidate.Address]; exists {
				return
			}
			allPublished[candidate.Address] = struct{}{}
			onCandidate(candidate)
		}
	}
	type graphResult struct {
		result Result
		next   int
	}
	graphTargets := make(chan cnameTarget, len(questionTypes))
	graphDone := make(chan graphResult, 1)
	go func() {
		graph := Result{Coverage: model.Coverage{Capability: "dns", Status: model.CoverageComplete}}
		next := c.followCNAMEGraph(ctx, job, hostname, port, occurrence, publish, &graph, make(map[netip.Addr]struct{}), graphTargets)
		graphDone <- graphResult{result: graph, next: next}
	}()
	root := normalizedGraphName(hostname)
	for item := range results {
		if !item.fromCache && item.result.Attempt > 0 {
			collected.Coverage.Attempted += item.result.Attempt
		}
		outcome := normalizeOutcome(item.result, item.err)
		if item.result.Omitted > 0 {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted += item.result.Omitted
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeBudgetExceeded)
		}
		if item.err != nil {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(item.err))
			if outcome == model.DNSOutcomeBudgetExhausted {
				collected.Coverage.Omitted++
			}
			collected.Observations = append(collected.Observations, c.queryObservation(hostname, item.result.Question, outcome, item.result, item.err.Error(), item.occurrence, item.observedAt))
			continue
		}
		if dnsOutcomeCompleted(outcome) {
			collected.Coverage.Completed++
		} else {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeCollectionFailed)
		}
		collected.Observations = append(collected.Observations, c.queryObservation(hostname, item.result.Question, outcome, item.result, "", item.occurrence, item.observedAt))
		if outcome != model.DNSOutcomeAnswered {
			continue
		}
		for recordIndex, observation := range item.result.Records {
			if observation.ObservedAt.IsZero() {
				observation.ObservedAt = item.observedAt
			}
			recordOccurrence := item.occurrence
			recordOccurrence.ItemIndex = recordIndex
			observation.ID = model.ObservationID("dns-record", recordOccurrence)
			collected.Observations = append(collected.Observations, observation)
			if target := cnameDestination(observation); target != "" {
				select {
				case graphTargets <- cnameTarget{name: target, depth: 1, path: []string{root}}:
				case <-ctx.Done():
					collected.Coverage.Status = model.CoveragePartial
					collected.Coverage.Omitted++
				}
			}
		}
		for addressIndex, address := range item.result.Addresses {
			address = address.Unmap()
			details := addressRecord(item.result, addressIndex, hostname, item.observedAt)
			owner := details.owner
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
			payload := model.DNSPayload{RRType: details.rrtype, Owner: owner, Address: address, TTL: details.ttl, Section: details.section, PolicyReason: string(decision.Reason)}
			addressOccurrence := item.occurrence
			addressOccurrence.ItemIndex = addressIndex
			addressScope := model.ScopeRoot
			if owner != hostname {
				addressScope = model.ScopeCNAME
			}
			collected.Observations = append(collected.Observations, model.Observation{
				ID:         model.ObservationID("dns-address", addressOccurrence),
				Type:       "dns_address",
				Subject:    owner,
				Scope:      addressScope,
				ObservedAt: details.observedAt,
				Status:     status,
				Payload:    marshalPayload(payload),
			})
			if decision.Allowed && onCandidate != nil {
				if _, published := publishedAddresses[address]; !published {
					publishedAddresses[address] = struct{}{}
					publish(Candidate{Hostname: hostname, Address: address, Port: port})
				}
			}
		}
	}
	close(graphTargets)
	completedGraph := <-graphDone
	collected.Observations = append(collected.Observations, completedGraph.result.Observations...)
	collected.Addresses = append(collected.Addresses, completedGraph.result.Addresses...)
	collected.Coverage.Attempted += completedGraph.result.Coverage.Attempted
	collected.Coverage.Completed += completedGraph.result.Coverage.Completed
	collected.Coverage.Omitted += completedGraph.result.Coverage.Omitted
	collected.Coverage.Truncated += completedGraph.result.Coverage.Truncated
	collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, completedGraph.result.Coverage.ErrorCodes...)
	if completedGraph.result.Coverage.Status != model.CoverageComplete {
		collected.Coverage.Status = model.CoveragePartial
	}
	if completedGraph.result.Coverage.Reason != "" {
		collected.Coverage.Reason = completedGraph.result.Coverage.Reason
	}
	nextRequestIndex := completedGraph.next
	nextRequestIndex = c.followInheritedZone(ctx, job, hostname, port, occurrence, nextRequestIndex, &collected)
	c.followDependencies(ctx, job, hostname, port, occurrence, nextRequestIndex, &collected)
	if ctx.Err() != nil {
		collected.Coverage.Status = model.CoveragePartial
		collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(ctx.Err()))
	}
	return collected
}

func (c *Collector) queryObservation(hostname string, question model.DNSQuestion, outcome model.DNSOutcome, result model.DNSResult, reason string, occurrence model.ObservationOccurrence, observedAt time.Time) model.Observation {
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
		ObservedAt: observedAt,
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

type addressDetails struct {
	owner      string
	rrtype     string
	ttl        uint32
	section    string
	observedAt time.Time
}

func addressRecord(result model.DNSResult, addressIndex int, fallback string, observedAt time.Time) addressDetails {
	details := addressDetails{owner: fallback, rrtype: typeName(result.Question.Type), observedAt: observedAt}
	index := 0
	for _, record := range result.Records {
		var payload model.DNSPayload
		if json.Unmarshal(record.Payload, &payload) != nil || !payload.Address.IsValid() {
			continue
		}
		if index == addressIndex {
			if owner := normalizedGraphName(payload.Owner); owner != "" {
				details.owner = owner
			}
			if payload.RRType == "A" || payload.RRType == "AAAA" {
				details.rrtype = payload.RRType
			}
			details.ttl = payload.TTL
			details.section = payload.Section
			if !record.ObservedAt.IsZero() {
				details.observedAt = record.ObservedAt
			}
			return details
		}
		index++
	}
	return details
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
	if errors.Is(err, context.DeadlineExceeded) {
		return model.CodeTimeout
	}
	if errors.Is(err, context.Canceled) {
		return model.CodeCancelled
	}
	if code := model.ErrorCodeOf(err); code != "" {
		return code
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return model.CodeTimeout
	}
	return model.CodeCollectionFailed
}

func typeName(value uint16) string {
	switch value {
	case typeA:
		return "A"
	case typeAAAA:
		return "AAAA"
	case typeCNAME:
		return "CNAME"
	case typeSOA:
		return "SOA"
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
