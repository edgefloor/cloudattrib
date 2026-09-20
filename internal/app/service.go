package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"cloudattrib/internal/aggregate"
	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/model"
	"cloudattrib/internal/target"
)

// Dependencies contains the settled E1 application seams.
type Dependencies struct {
	DNS        *collectdns.Collector
	HTTP       *collecthttp.Collector
	Detectors  []Detector
	Prefixes   PrefixReader
	View       model.AttributionView
	HTTPScheme string
	Now        func() time.Time
}

// Service coordinates one immutable view through collection and classification.
type Service struct {
	dns        *collectdns.Collector
	http       *collecthttp.Collector
	detectors  []Detector
	prefixes   PrefixReader
	view       model.AttributionView
	httpScheme string
	now        func() time.Time
}

// NewService constructs the analyzer without starting background work.
func NewService(dependencies Dependencies) *Service {
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	scheme := dependencies.HTTPScheme
	if scheme == "" {
		scheme = "https"
	}
	return &Service{
		dns:        dependencies.DNS,
		http:       dependencies.HTTP,
		detectors:  slices.Clone(dependencies.Detectors),
		prefixes:   dependencies.Prefixes,
		view:       dependencies.View,
		httpScheme: scheme,
		now:        now,
	}
}

// Analyze runs the early domain-to-report pipeline against one captured view.
func (s *Service) Analyze(ctx context.Context, request model.AnalyzeRequest) (model.Report, error) {
	startedAt := s.now()
	normalized, err := target.Normalize(request)
	if err != nil {
		return model.Report{}, fmt.Errorf("normalize target: %w", err)
	}
	if normalized.Target.Kind == model.TargetIP {
		return model.Report{}, model.NewError(model.CodeInvalidOptions, "use LookupIP for an IP target", nil)
	}
	if s.dns == nil {
		return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "DNS collector is unavailable", nil)
	}

	hostname := normalized.SeedHostnames[0]
	port := uint16(443)
	if s.httpScheme == "http" {
		port = 80
	}
	type dnsOutcome struct {
		result collectdns.Result
	}
	type httpOutcome struct {
		result collecthttp.Result
		err    error
	}
	dnsDone := make(chan dnsOutcome, 1)
	candidates := make(chan collectdns.Candidate, 1)
	go func() {
		result := s.dns.Collect(ctx, hostname, port, func(candidate collectdns.Candidate) {
			select {
			case candidates <- candidate:
			default:
			}
		})
		dnsDone <- dnsOutcome{result: result}
	}()

	var dnsResult collectdns.Result
	var httpResult collecthttp.Result
	var httpErr error
	httpStarted := false
	httpDone := make(chan httpOutcome, 1)
	for dnsDone != nil || (httpStarted && httpDone != nil) {
		select {
		case candidate := <-candidates:
			if httpStarted || s.http == nil {
				continue
			}
			httpStarted = true
			go func() {
				result, collectErr := s.http.Collect(ctx, s.httpScheme, candidate.Hostname, candidate.Address)
				httpDone <- httpOutcome{result: result, err: collectErr}
			}()
		case outcome := <-dnsDone:
			dnsResult = outcome.result
			dnsDone = nil
			if !httpStarted && s.http != nil {
				select {
				case candidate := <-candidates:
					httpStarted = true
					go func() {
						result, collectErr := s.http.Collect(ctx, s.httpScheme, candidate.Hostname, candidate.Address)
						httpDone <- httpOutcome{result: result, err: collectErr}
					}()
				default:
				}
			}
			if !httpStarted {
				httpDone = nil
			}
		case outcome := <-httpDone:
			httpResult = outcome.result
			httpErr = outcome.err
			httpDone = nil
		}
	}

	observations := append([]model.Observation(nil), dnsResult.Observations...)
	coverage := []model.Coverage{dnsResult.Coverage}
	if httpStarted {
		coverage = append(coverage, httpResult.Coverage)
		if httpErr == nil {
			observations = append(observations, httpResult.Observation)
		}
	} else {
		coverage = append(coverage, model.Coverage{Capability: "http", Status: model.CoverageUnavailable, Reason: "no approved address"})
	}

	classifiedAt := s.now()
	var evidence []model.Evidence
	for _, detector := range s.detectors {
		detected, detectorCoverage := detector.Detect(ctx, observations, s.view)
		for i := range detected {
			if detected[i].ClassifiedAt.IsZero() {
				detected[i].ClassifiedAt = classifiedAt
			}
		}
		evidence = append(evidence, detected...)
		coverage = append(coverage, detectorCoverage...)
	}

	if s.prefixes != nil {
		seen := make(map[netip.Addr]struct{})
		for _, address := range dnsResult.Addresses {
			address = address.Unmap()
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			associations, prefixCoverage, lookupErr := s.prefixes.LookupPrefixes(ctx, model.IPLookupRequest{Address: address, Match: "all"}, s.view)
			if lookupErr != nil {
				prefixCoverage.Status = model.CoverageUnavailable
				prefixCoverage.ErrorCodes = append(prefixCoverage.ErrorCodes, model.ErrorCodeOf(lookupErr))
			}
			coverage = append(coverage, prefixCoverage)
			for _, association := range associations {
				item, evidenceErr := prefixEvidence(hostname, address, association, classifiedAt, observations)
				if evidenceErr != nil {
					return model.Report{}, evidenceErr
				}
				evidence = append(evidence, item)
			}
		}
	}

	status := model.StatusComplete
	for _, item := range coverage {
		if item.Status == model.CoveragePartial || item.Status == model.CoverageUnavailable {
			status = model.StatusPartial
			break
		}
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Target:        normalized.Target,
		Mode:          normalized.Mode,
		StartedAt:     startedAt,
		EndedAt:       s.now(),
		ClassifiedAt:  classifiedAt,
		BundleID:      s.view.BundleID(),
		BuildID:       "cloudattrib-e1",
		Status:        status,
		Observations:  observations,
		Evidence:      evidence,
		Findings:      aggregate.Build(evidence),
		Coverage:      coverage,
		Warnings:      make([]string, 0),
	}
	id, err := report.ContentID()
	if err != nil {
		return model.Report{}, fmt.Errorf("create report ID: %w", err)
	}
	report.ID = id
	if err := report.ValidateReferences(); err != nil {
		return model.Report{}, fmt.Errorf("validate report references: %w", err)
	}
	return report, nil
}

// LookupIP performs local prefix lookup without DNS, HTTP, or storage.
func (s *Service) LookupIP(ctx context.Context, request model.IPLookupRequest) (model.IPLookupResult, error) {
	if s.prefixes == nil {
		return model.IPLookupResult{}, model.NewError(model.CodeCapabilityUnavailable, "prefix lookup is unavailable", nil)
	}
	associations, coverage, err := s.prefixes.LookupPrefixes(ctx, request, s.view)
	if err != nil {
		return model.IPLookupResult{}, fmt.Errorf("lookup prefixes: %w", err)
	}
	status := model.StatusComplete
	if coverage.Status != model.CoverageComplete {
		status = model.StatusPartial
	}
	return model.IPLookupResult{Address: request.Address.Unmap(), Status: status, Associations: associations, Coverage: []model.Coverage{coverage}}, nil
}

// Reclassify is added after retained replay inputs ship.
func (*Service) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "reclassification is not available in the E1 slice", nil)
}

func prefixEvidence(subject string, address netip.Addr, association model.Association, classifiedAt time.Time, observations []model.Observation) (model.Evidence, error) {
	fields, err := json.Marshal(association)
	if err != nil {
		return model.Evidence{}, fmt.Errorf("encode prefix association: %w", err)
	}
	observationID := addressObservationID(address, observations)
	if observationID == "" {
		return model.Evidence{}, fmt.Errorf("find address observation for %s", address)
	}
	key := association.ID + "\x00" + observationID
	sum := sha256.Sum256([]byte(key))
	return model.Evidence{
		ID:             "evidence-prefix-" + hex.EncodeToString(sum[:12]),
		ObservationIDs: []string{observationID},
		DatasetRecords: []model.DatasetRecord{{
			SourceID:  association.SourceID,
			Revision:  "fixture-v1",
			Digest:    "fixture-sha256",
			RecordRef: association.RecordRef,
			Fields:    fields,
		}},
		ClassifiedAt: classifiedAt,
		DetectorID:   "prefix-v1",
		Subject:      subject,
		ProviderID:   association.ProviderID,
		ProductID:    association.ProductID,
		Category:     "cloud_infrastructure",
		Relation:     model.RelationServiceRange,
		Strength:     model.StrengthModerate,
		Activity:     model.ActivityUnknown,
		Scope:        model.ScopeRoot,
		Explanation:  "address is contained by a normalized local prefix record",
	}, nil
}

func addressObservationID(address netip.Addr, observations []model.Observation) string {
	for _, observation := range observations {
		if observation.Type != "dns_address" {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err == nil && payload.Address == address {
			return observation.ID
		}
	}
	return ""
}
