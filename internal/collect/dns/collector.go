// Package dns collects raw DNS outcomes and publishes approved addresses early.
package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	type queryResult struct {
		result model.DNSResult
		err    error
	}
	results := make(chan queryResult)
	var wg sync.WaitGroup
	for _, questionType := range questionTypes {
		question := model.DNSQuestion{Name: hostname, Type: questionType}
		wg.Go(func() {
			result, err := c.query(ctx, question)
			select {
			case results <- queryResult{result: result, err: err}:
			case <-ctx.Done():
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	collected := Result{Coverage: model.Coverage{Capability: "dns", Status: model.CoverageComplete, Attempted: len(questionTypes)}}
	for item := range results {
		collected.Coverage.Completed++
		if item.err != nil {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(item.err))
			collected.Observations = append(collected.Observations, c.queryObservation(hostname, item.result.Question, "failed", item.result, item.err.Error()))
			continue
		}
		collected.Observations = append(collected.Observations, c.queryObservation(hostname, item.result.Question, "answered", item.result, ""))
		for _, observation := range item.result.Records {
			if observation.ObservedAt.IsZero() {
				observation.ObservedAt = c.now()
			}
			collected.Observations = append(collected.Observations, observation)
		}
		for _, address := range item.result.Addresses {
			address = address.Unmap()
			collected.Addresses = append(collected.Addresses, address)
			decision := c.policy.Check(address, port)
			status := "answered"
			if !decision.Allowed {
				status = "policy_blocked"
				collected.Coverage.Status = model.CoveragePartial
				collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodePolicyBlocked)
			}
			payload := model.DNSPayload{RRType: typeName(item.result.Question.Type), Owner: hostname, Address: address, PolicyReason: string(decision.Reason)}
			collected.Observations = append(collected.Observations, model.Observation{
				ID:         observationID("dns-address", hostname, address.String()),
				Type:       "dns_address",
				Subject:    hostname,
				Scope:      model.ScopeRoot,
				ObservedAt: c.now(),
				Status:     status,
				Payload:    marshalPayload(payload),
			})
			if decision.Allowed && onCandidate != nil {
				onCandidate(Candidate{Hostname: hostname, Address: address, Port: port})
			}
		}
	}
	if ctx.Err() != nil {
		collected.Coverage.Status = model.CoveragePartial
		collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeCancelled)
	}
	return collected
}

func (c *Collector) queryObservation(hostname string, question model.DNSQuestion, status string, result model.DNSResult, reason string) model.Observation {
	payload := model.DNSPayload{
		RRType:       typeName(question.Type),
		Owner:        hostname,
		ResponseCode: result.ResponseCode,
		Resolver:     result.Resolver,
		Transport:    result.Transport,
		PolicyReason: reason,
	}
	return model.Observation{
		ID:         observationID("dns-query", hostname, fmt.Sprint(question.Type)),
		Type:       "dns_query",
		Subject:    hostname,
		Scope:      model.ScopeRoot,
		ObservedAt: c.now(),
		Status:     status,
		Payload:    marshalPayload(payload),
	}
}

func observationID(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return parts[0] + "-" + hex.EncodeToString(hash.Sum(nil)[:12])
}

func marshalPayload(value any) model.JSONValue {
	data, err := json.Marshal(value)
	if err != nil {
		return model.JSONValue("null")
	}
	return data
}

func errorCode(err error) model.ErrorCode {
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
