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
	DNS         *collectdns.Collector
	HTTP        *collecthttp.Collector
	Detectors   []Detector
	WebDetector WebDetector
	Prefixes    PrefixReader
	ASN         ASNReader
	Store       ResultStore
	View        model.AttributionView
	HTTPScheme  string
	Now         func() time.Time
}

// Service coordinates one immutable view through collection and classification.
type Service struct {
	dns         *collectdns.Collector
	http        *collecthttp.Collector
	detectors   []Detector
	webDetector WebDetector
	prefixes    PrefixReader
	asn         ASNReader
	store       ResultStore
	view        model.AttributionView
	httpScheme  string
	now         func() time.Time
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
		dns:         dependencies.DNS,
		http:        dependencies.HTTP,
		detectors:   slices.Clone(dependencies.Detectors),
		webDetector: dependencies.WebDetector,
		prefixes:    dependencies.Prefixes,
		asn:         dependencies.ASN,
		store:       dependencies.Store,
		view:        dependencies.View,
		httpScheme:  scheme,
		now:         now,
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
	collectHTTP := normalized.Mode == model.ModeFull && s.http != nil
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
			if httpStarted || !collectHTTP {
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
			if !httpStarted && collectHTTP {
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

	type dnsRun struct {
		hostname string
		result   collectdns.Result
	}
	type httpRun struct {
		hostname string
		result   collecthttp.Result
		err      error
	}
	dnsRuns := []dnsRun{{hostname: hostname, result: dnsResult}}
	httpRuns := make([]httpRun, 0, len(normalized.SeedHostnames))
	if httpStarted {
		httpRuns = append(httpRuns, httpRun{hostname: hostname, result: httpResult, err: httpErr})
	}
	for _, seed := range normalized.SeedHostnames[1:] {
		var selected collectdns.Candidate
		result := s.dns.Collect(ctx, seed, port, func(candidate collectdns.Candidate) {
			if !selected.Address.IsValid() {
				selected = candidate
			}
		})
		dnsRuns = append(dnsRuns, dnsRun{hostname: seed, result: result})
		if collectHTTP && selected.Address.IsValid() {
			result, collectErr := s.http.Collect(ctx, s.httpScheme, selected.Hostname, selected.Address)
			httpRuns = append(httpRuns, httpRun{hostname: seed, result: result, err: collectErr})
		}
	}

	observations := make([]model.Observation, 0)
	coverage := make([]model.Coverage, 0, len(dnsRuns)+len(httpRuns))
	for _, run := range dnsRuns {
		scope := scopeForSeed(run.hostname, normalized.ScopeRoots)
		for _, observation := range run.result.Observations {
			observation.Scope = scope
			observations = append(observations, observation)
		}
		coverage = append(coverage, run.result.Coverage)
	}
	if normalized.Mode == model.ModeDNS {
		coverage = append(coverage, model.Coverage{Capability: "http", Status: model.CoverageSkipped, Reason: "DNS-only mode"})
	} else if len(httpRuns) == 0 {
		coverage = append(coverage, model.Coverage{Capability: "http", Status: model.CoverageUnavailable, Reason: "no approved address"})
	}
	for _, run := range httpRuns {
		coverage = append(coverage, run.result.Coverage)
		if run.err == nil {
			for _, observation := range run.result.Observations {
				if observation.Scope != model.ScopeExternalRedirect {
					observation.Scope = scopeForSeed(run.hostname, normalized.ScopeRoots)
				}
				observations = append(observations, observation)
			}
		}
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
	if s.webDetector != nil {
		for _, run := range httpRuns {
			if run.err != nil {
				continue
			}
			scope := run.result.Observation.Scope
			if scope != model.ScopeExternalRedirect {
				scope = scopeForSeed(run.hostname, normalized.ScopeRoots)
			}
			detected, detectorCoverage := s.webDetector.Detect(ctx, run.result.Observation.ID, run.result.Observation.Subject, scope, run.result.Headers, run.result.Body, s.view)
			for i := range detected {
				if detected[i].ClassifiedAt.IsZero() {
					detected[i].ClassifiedAt = classifiedAt
				}
			}
			evidence = append(evidence, detected...)
			coverage = append(coverage, detectorCoverage)
		}
	}

	if s.prefixes != nil {
		seen := make(map[string]struct{})
		for _, run := range dnsRuns {
			for _, address := range run.result.Addresses {
				address = address.Unmap()
				lookupKey := run.hostname + "\x00" + address.String()
				if _, exists := seen[lookupKey]; exists {
					continue
				}
				seen[lookupKey] = struct{}{}
				associations, prefixCoverage, lookupErr := s.prefixes.LookupPrefixes(ctx, model.IPLookupRequest{Address: address, Match: "all"}, s.view)
				if lookupErr != nil {
					prefixCoverage.Status = model.CoverageUnavailable
					prefixCoverage.ErrorCodes = append(prefixCoverage.ErrorCodes, model.ErrorCodeOf(lookupErr))
				}
				coverage = append(coverage, prefixCoverage)
				for _, association := range associations {
					item, evidenceErr := prefixEvidence(run.hostname, scopeForSeed(run.hostname, normalized.ScopeRoots), address, association, classifiedAt, observations)
					if evidenceErr != nil {
						return model.Report{}, evidenceErr
					}
					evidence = append(evidence, item)
				}
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
	if !request.Address.IsValid() {
		return model.IPLookupResult{}, model.NewError(model.CodeInvalidTarget, "IP address is invalid", nil)
	}
	if s.prefixes == nil && s.asn == nil {
		return model.IPLookupResult{}, model.NewError(model.CodeCapabilityUnavailable, "local IP lookup is unavailable", nil)
	}
	result := model.IPLookupResult{Address: request.Address.Unmap(), Status: model.StatusComplete}
	usable := 0
	if s.prefixes == nil {
		result.Coverage = append(result.Coverage, model.Coverage{Capability: "prefix", Status: model.CoverageUnavailable, Reason: "prefix source is unavailable"})
	} else {
		associations, coverage, err := s.prefixes.LookupPrefixes(ctx, request, s.view)
		result.Coverage = append(result.Coverage, coverage)
		if err == nil {
			usable++
			result.Associations = associations
		} else if model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable && model.ErrorCodeOf(err) != model.CodeSourceUnavailable {
			return model.IPLookupResult{}, fmt.Errorf("lookup prefixes: %w", err)
		}
	}
	if s.asn == nil {
		result.Coverage = append(result.Coverage, model.Coverage{Capability: "asn", Status: model.CoverageUnavailable, Reason: "ASN source is unavailable"})
	} else {
		records, coverage, err := s.asn.LookupASN(ctx, request.Address, s.view)
		result.Coverage = append(result.Coverage, coverage)
		if err == nil {
			usable++
			result.ASN = records
		} else if model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable && model.ErrorCodeOf(err) != model.CodeSourceUnavailable {
			return model.IPLookupResult{}, fmt.Errorf("lookup ASN: %w", err)
		}
	}
	if usable == 0 {
		return model.IPLookupResult{}, model.NewError(model.CodeCapabilityUnavailable, "all local IP lookup sources are unavailable", nil)
	}
	for _, coverage := range result.Coverage {
		if coverage.Status != model.CoverageComplete {
			result.Status = model.StatusPartial
			break
		}
	}
	return result, nil
}

// Reclassify reinterprets immutable normalized observations without collecting.
func (s *Service) Reclassify(ctx context.Context, request model.ReclassifyRequest) (model.Report, error) {
	if request.ReportID == "" {
		return model.Report{}, model.NewError(model.CodeInvalidOptions, "report ID is required", nil)
	}
	if s.store == nil {
		return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "reclassification input storage is unavailable", nil)
	}
	if request.BundleID != "" && request.BundleID != s.view.BundleID() {
		return model.Report{}, model.NewError(model.CodeBundleUnavailable, "requested bundle is not loaded", nil)
	}
	if len(s.detectors) == 0 && s.prefixes == nil {
		return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "no replay classifier is usable", nil)
	}
	original, err := s.store.LoadReport(ctx, request.ReportID)
	if err != nil {
		if model.ErrorCodeOf(err) != "" {
			return model.Report{}, fmt.Errorf("load replay input: %w", err)
		}
		return model.Report{}, model.NewError(model.CodePersistenceFailed, "load replay input", err)
	}
	classifiedAt := s.now()
	observations := slices.Clone(original.Observations)
	evidence := make([]model.Evidence, 0)
	coverage := make([]model.Coverage, 0, len(original.Coverage)+len(s.detectors)+1)
	coverage = append(coverage, original.Coverage...)
	for _, detector := range s.detectors {
		detected, detectorCoverage := detector.Detect(ctx, observations, s.view)
		for index := range detected {
			detected[index].ClassifiedAt = classifiedAt
		}
		evidence = append(evidence, detected...)
		coverage = append(coverage, detectorCoverage...)
	}
	if s.prefixes != nil {
		for _, observation := range observations {
			if observation.Type != "dns_address" {
				continue
			}
			var payload model.DNSPayload
			if json.Unmarshal(observation.Payload, &payload) != nil || !payload.Address.IsValid() {
				continue
			}
			associations, prefixCoverage, lookupErr := s.prefixes.LookupPrefixes(ctx, model.IPLookupRequest{Address: payload.Address, Match: "all"}, s.view)
			if lookupErr != nil {
				prefixCoverage.Status = model.CoverageUnavailable
				prefixCoverage.ErrorCodes = append(prefixCoverage.ErrorCodes, model.ErrorCodeOf(lookupErr))
			}
			coverage = append(coverage, prefixCoverage)
			for _, association := range associations {
				item, evidenceErr := prefixEvidence(observation.Subject, observation.Scope, payload.Address, association, classifiedAt, observations)
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
		SchemaVersion: model.SchemaVersion, OriginalReportID: original.ID, Target: original.Target, Mode: model.ModeReclassify,
		StartedAt: classifiedAt, EndedAt: s.now(), ClassifiedAt: classifiedAt, BundleID: s.view.BundleID(), BuildID: "cloudattrib-reclassify-v1",
		Status: status, Observations: observations, Evidence: evidence, Findings: aggregate.Build(evidence), Coverage: coverage, Warnings: make([]string, 0),
	}
	report.ID, err = report.ContentID()
	if err != nil {
		return model.Report{}, fmt.Errorf("create reclassified report ID: %w", err)
	}
	if err := report.ValidateReferences(); err != nil {
		return model.Report{}, fmt.Errorf("validate reclassified report references: %w", err)
	}
	return report, nil
}

func prefixEvidence(subject string, scope model.Scope, address netip.Addr, association model.Association, classifiedAt time.Time, observations []model.Observation) (model.Evidence, error) {
	fields, err := json.Marshal(association)
	if err != nil {
		return model.Evidence{}, fmt.Errorf("encode prefix association: %w", err)
	}
	observationID := addressObservationID(subject, address, observations)
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
			Revision:  association.SourceRevision,
			Digest:    association.SourceDigest,
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
		Scope:        scope,
		Explanation:  "address is contained by a normalized local prefix record",
	}, nil
}

func scopeForSeed(hostname string, roots []string) model.Scope {
	if slices.Contains(roots, hostname) {
		return model.ScopeRoot
	}
	return model.ScopeSubdomain
}

func addressObservationID(subject string, address netip.Addr, observations []model.Observation) string {
	for _, observation := range observations {
		if observation.Type != "dns_address" || observation.Subject != subject {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err == nil && payload.Address == address {
			return observation.ID
		}
	}
	return ""
}
