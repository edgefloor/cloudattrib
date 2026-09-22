package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"cloudattrib/internal/aggregate"
	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
	"cloudattrib/internal/target"
)

// Dependencies contains the settled E1 application seams.
type Dependencies struct {
	DNS               *collectdns.Collector
	HTTP              *collecthttp.Collector
	Detectors         []Detector
	WebDetector       WebDetector
	Prefixes          PrefixReader
	ASN               ASNReader
	Store             ResultStore
	CT                ctlog.Reader
	CTEnabled         bool
	CTMaximumSeed     int
	View              model.AttributionView
	BuildProvenance   model.BuildProvenance
	RulesDigest       model.ProvenanceValue
	FingerprintDigest model.ProvenanceValue
	HTTPScheme        string
	Now               func() time.Time
	TargetTimeout     time.Duration
	Controller        *policy.Controller
	Limits            policy.Limits
}

// Service coordinates one immutable view through collection and classification.
type Service struct {
	dns               *collectdns.Collector
	http              *collecthttp.Collector
	detectors         []Detector
	webDetector       WebDetector
	prefixes          PrefixReader
	asn               ASNReader
	store             ResultStore
	ct                ctlog.Reader
	ctEnabled         bool
	ctMaximumSeed     int
	view              model.AttributionView
	buildProvenance   model.BuildProvenance
	rulesDigest       model.ProvenanceValue
	fingerprintDigest model.ProvenanceValue
	httpScheme        string
	now               func() time.Time
	targetTimeout     time.Duration
	controller        *policy.Controller
	limits            policy.Limits
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
		dns:               dependencies.DNS,
		http:              dependencies.HTTP,
		detectors:         slices.Clone(dependencies.Detectors),
		webDetector:       dependencies.WebDetector,
		prefixes:          dependencies.Prefixes,
		asn:               dependencies.ASN,
		store:             dependencies.Store,
		ct:                dependencies.CT,
		ctEnabled:         dependencies.CTEnabled,
		ctMaximumSeed:     dependencies.CTMaximumSeed,
		view:              dependencies.View,
		buildProvenance:   dependencies.BuildProvenance.Explicit(),
		rulesDigest:       dependencies.RulesDigest.Explicit(),
		fingerprintDigest: dependencies.FingerprintDigest.Explicit(),
		httpScheme:        scheme,
		now:               now,
		targetTimeout:     dependencies.TargetTimeout,
		controller:        dependencies.Controller,
		limits:            dependencies.Limits,
	}
}

// Analyze runs the early domain-to-report pipeline against one captured view.
func (s *Service) Analyze(ctx context.Context, request model.AnalyzeRequest) (model.Report, error) {
	normalized, err := target.NormalizeWithSeedLimit(request, max(policy.DefaultLimits().SeedHostnames, s.seedLimit()))
	if err != nil {
		return model.Report{}, fmt.Errorf("normalize target: %w", err)
	}
	if normalized.Target.Kind == model.TargetIP {
		return model.Report{}, model.NewError(model.CodeInvalidOptions, "use LookupIP for an IP target", nil)
	}
	if s.dns == nil {
		return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "DNS collector is unavailable", nil)
	}
	if s.controller != nil {
		var release func()
		ctx, release, err = s.controller.Begin(ctx)
		if err != nil {
			return model.Report{}, err
		}
		defer release()
	} else if s.targetTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.targetTimeout)
		defer cancel()
	}
	startedAt := s.now()
	var seedCoverage *model.Coverage
	if limit := s.seedLimit(); len(normalized.SeedHostnames) > limit {
		omitted := len(normalized.SeedHostnames) - limit
		normalized.SeedHostnames = boundedSeeds(normalized, limit)
		seedCoverage = &model.Coverage{
			Capability: "seed_hostnames", Status: model.CoveragePartial,
			Attempted: len(normalized.SeedHostnames) + omitted, Completed: len(normalized.SeedHostnames), Omitted: omitted,
			Reason: "configured seed hostname limit reached", ErrorCodes: []model.ErrorCode{model.CodeBudgetExceeded},
		}
	}
	collectionRunID, err := model.NewCollectionRunID()
	if err != nil {
		return model.Report{}, fmt.Errorf("create collection run ID: %w", err)
	}
	ctObservations, ctCoverage := s.planCTDiscovery(ctx, &normalized)

	collectHTTP := normalized.Mode == model.ModeFull && s.http != nil
	type dnsRun struct {
		hostname string
		result   collectdns.Result
	}
	type httpRun struct {
		hostname string
		result   collecthttp.Result
		err      error
	}
	dnsRuns := make([]dnsRun, 0, len(normalized.SeedHostnames))
	httpRuns := make([]httpRun, 0, len(normalized.SeedHostnames))
	for seedIndex, seed := range normalized.SeedHostnames {
		portForSeed := seedPort(normalized, seed, s.httpScheme)
		occurrence := model.ObservationOccurrence{CollectionRunID: collectionRunID, Seed: seed, SeedIndex: seedIndex, Attempt: 1}
		if !collectHTTP {
			result := s.dns.CollectOccurrence(ctx, seed, portForSeed, occurrence, nil)
			dnsRuns = append(dnsRuns, dnsRun{hostname: seed, result: result})
			continue
		}

		// The buffer equals the configured retained-address limit. DNS can finish
		// without blocking after HTTP succeeds and stops reading candidates.
		candidates := make(chan netip.Addr, s.addressLimit())
		dnsDone := make(chan collectdns.Result, 1)
		go func() {
			dropped := 0
			result := s.dns.CollectOccurrence(ctx, seed, portForSeed, occurrence, func(candidate collectdns.Candidate) {
				select {
				case candidates <- candidate.Address:
				default:
					dropped++
				}
			})
			if dropped > 0 {
				result.Coverage.Status = model.CoveragePartial
				result.Coverage.Omitted += dropped
				result.Coverage.ErrorCodes = append(result.Coverage.ErrorCodes, model.CodeBudgetExceeded)
			}
			close(candidates)
			dnsDone <- result
		}()
		httpResult, httpErr := s.http.CollectTargetCandidatesOccurrence(ctx, seedURL(normalized, seed, s.httpScheme), candidates, occurrence)
		dnsResult := <-dnsDone
		dnsRuns = append(dnsRuns, dnsRun{hostname: seed, result: dnsResult})
		if model.ErrorCodeOf(httpErr) == model.CodeCapabilityUnavailable {
			httpResult.Coverage.Status = model.CoverageUnavailable
			httpResult.Coverage.Reason = "no approved address"
			httpErr = nil
		}
		httpRuns = append(httpRuns, httpRun{hostname: seed, result: httpResult, err: httpErr})
	}

	observations := slices.Clone(ctObservations)
	coverage := make([]model.Coverage, 0, len(dnsRuns)+len(httpRuns)+2)
	if seedCoverage != nil {
		coverage = append(coverage, *seedCoverage)
	}
	if ctCoverage != nil {
		coverage = append(coverage, *ctCoverage)
	}
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
		for _, observation := range run.result.Observations {
			if observation.Scope != model.ScopeExternalRedirect {
				observation.Scope = scopeForSeed(run.hostname, normalized.ScopeRoots)
			}
			observations = append(observations, observation)
		}
	}
	coverage = append(coverage, tlsCertificateCoverage(normalized, observations, s.httpScheme))

	if s.webDetector != nil {
		for _, run := range httpRuns {
			if run.err != nil || run.result.Observation.ID == "" {
				continue
			}
			source := run.result.Observation
			if source.Scope != model.ScopeExternalRedirect {
				source.Scope = scopeForSeed(run.hostname, normalized.ScopeRoots)
			}
			detected, detectorCoverage := s.webDetector.Detect(ctx, run.result.Headers, run.result.Body)
			for _, detection := range detected {
				if technology, ok := technologyObservation(detection, source); ok {
					observations = append(observations, technology)
				}
			}
			coverage = append(coverage, detectorCoverage)
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
	technologyEvidence, technologyCoverage := classifyUnmappedTechnology(observations, evidence, classifiedAt)
	evidence = append(evidence, technologyEvidence...)
	if technologyCoverage != nil {
		coverage = append(coverage, *technologyCoverage)
	}

	enrichedEvidence, enrichedCoverage, err := s.enrichAddresses(ctx, observations, classifiedAt)
	if err != nil {
		return model.Report{}, err
	}
	evidence = append(evidence, enrichedEvidence...)
	coverage = append(coverage, enrichedCoverage...)

	status := reportStatus(ctx, observations, coverage)
	report := model.Report{
		SchemaVersion:    model.SchemaVersion,
		ContentIDVersion: model.ReportContentIDVersion,
		Target:           normalized.Target,
		Mode:             normalized.Mode,
		StartedAt:        startedAt,
		EndedAt:          s.now(),
		ClassifiedAt:     classifiedAt,
		BundleID:         s.view.BundleID(),
		BuildID:          s.buildProvenance.CompatibilityID(),
		Provenance:       s.liveProvenance(),
		Status:           status,
		Observations:     observations,
		Evidence:         evidence,
		Findings:         aggregate.Build(evidence),
		Coverage:         coverage,
		Warnings:         make([]string, 0),
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

func (s *Service) planCTDiscovery(ctx context.Context, request *model.NormalizedRequest) ([]model.Observation, *model.Coverage) {
	if !request.CTDiscovery {
		return nil, nil
	}
	coverage := &model.Coverage{Capability: "ct_discovery"}
	if !s.ctEnabled {
		coverage.Status = model.CoverageSkipped
		coverage.Reason = "disabled"
		return nil, coverage
	}
	if s.ct == nil {
		coverage.Status = model.CoverageUnavailable
		coverage.Reason = "local CT index is unavailable"
		return nil, coverage
	}
	limit := s.ctMaximumSeed
	if limit <= 0 {
		limit = 20
	}
	if remaining := s.seedLimit() - len(request.SeedHostnames); limit > remaining {
		limit = remaining
	}
	if limit <= 0 {
		coverage.Status = model.CoveragePartial
		coverage.Reason = "seed hostname limit reached"
		return nil, coverage
	}
	seen := make(map[string]struct{}, len(request.SeedHostnames))
	for _, hostname := range request.SeedHostnames {
		seen[hostname] = struct{}{}
	}
	observations := make([]model.Observation, 0, limit)
	identities := make([]string, 0, len(request.ScopeRoots))
	partial := false
	for _, root := range request.ScopeRoots {
		if limit <= 0 {
			break
		}
		result, err := s.ct.Discover(ctx, root, limit)
		if err != nil {
			coverage.Status = model.CoverageUnavailable
			coverage.Reason = "query local CT index: " + err.Error()
			return observations, coverage
		}
		coverage.Attempted += result.Available
		coverage.Omitted += result.Omitted
		partial = partial || result.Partial
		identities = append(identities, result.IndexIdentity)
		for _, candidate := range result.Candidates {
			if _, duplicate := seen[candidate.Hostname]; duplicate {
				continue
			}
			seen[candidate.Hostname] = struct{}{}
			request.SeedHostnames = append(request.SeedHostnames, candidate.Hostname)
			payload, err := json.Marshal(candidate)
			if err != nil {
				continue
			}
			digest := sha256.Sum256(append([]byte("ct-name-v1\x00"), payload...))
			observations = append(observations, model.Observation{
				ID: "ct-name-" + hex.EncodeToString(digest[:12]), Type: "ct_name", Subject: candidate.Hostname, Scope: model.ScopeSubdomain,
				ObservedAt: candidate.LoggedAt, CollectorVersion: "ct-index-v1", Status: "historical_discovery", Payload: payload,
				ContentHash: "sha256:" + hex.EncodeToString(digest[:]),
			})
			limit--
		}
	}
	coverage.Completed = len(observations)
	coverage.Reason = strings.Join(identities, ",")
	switch {
	case coverage.Attempted == 0:
		coverage.Status = model.CoverageComplete
		coverage.Reason = "empty_index"
	case partial:
		coverage.Status = model.CoveragePartial
	case coverage.Omitted > 0:
		coverage.Status = model.CoveragePartial
	default:
		coverage.Status = model.CoverageComplete
	}
	return observations, coverage
}

func (s *Service) seedLimit() int {
	if s.limits.SeedHostnames > 0 {
		return s.limits.SeedHostnames
	}
	return policy.DefaultLimits().SeedHostnames
}

func (s *Service) addressLimit() int {
	if s.limits.ResolvedAddresses > 0 {
		return s.limits.ResolvedAddresses
	}
	return policy.DefaultLimits().ResolvedAddresses
}

func boundedSeeds(request model.NormalizedRequest, limit int) []string {
	primary := request.Target.Canonical
	if request.Target.Kind == model.TargetURL {
		if parsed, err := url.Parse(request.Target.Canonical); err == nil {
			primary = parsed.Hostname()
		}
	}
	result := make([]string, 0, limit)
	if slices.Contains(request.SeedHostnames, primary) {
		result = append(result, primary)
	}
	for _, seed := range request.SeedHostnames {
		if len(result) >= limit {
			break
		}
		if seed != primary {
			result = append(result, seed)
		}
	}
	return result
}

// LookupIP performs local prefix lookup without DNS, HTTP, or storage.
func (s *Service) LookupIP(ctx context.Context, request model.IPLookupRequest) (model.IPLookupResult, error) {
	if !request.Address.IsValid() {
		return model.IPLookupResult{}, model.NewError(model.CodeInvalidTarget, "IP address is invalid", nil)
	}
	if s.prefixes == nil && s.asn == nil {
		return model.IPLookupResult{}, model.NewError(model.CodeCapabilityUnavailable, "local IP lookup is unavailable", nil)
	}
	if s.controller != nil {
		var release func()
		var err error
		ctx, release, err = s.controller.Begin(ctx)
		if err != nil {
			return model.IPLookupResult{}, err
		}
		defer release()
	}
	result := model.IPLookupResult{Address: request.Address.Unmap(), Status: model.StatusComplete}
	result.Coverage = append(result.Coverage, s.sourceCoverage([]netip.Addr{result.Address})...)
	usable := 0
	prefixUsable := s.prefixes != nil && s.sourceGroupUsable("prefix_source/")
	if !prefixUsable {
		result.Coverage = append(result.Coverage, model.Coverage{Capability: "prefix", Status: model.CoverageUnavailable, Reason: "prefix source is unavailable"})
	} else {
		associations, coverage, err := s.prefixes.LookupPrefixes(ctx, request, s.view)
		result.Coverage = append(result.Coverage, coverage)
		if err == nil {
			if len(associations) > s.prefixAssociationLimit() {
				return model.IPLookupResult{}, model.NewError(model.CodeBudgetExceeded, "prefix association limit exceeded", nil)
			}
			usable++
			result.Associations = associations
		} else if model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable && model.ErrorCodeOf(err) != model.CodeSourceUnavailable {
			return model.IPLookupResult{}, fmt.Errorf("lookup prefixes: %w", err)
		}
	}
	asnSource := "asn_source/ipv6"
	if result.Address.Is4() {
		asnSource = "asn_source/ipv4"
	}
	asnUsable := s.asn != nil && s.sourceCapabilityUsable(asnSource)
	if !asnUsable {
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

func (s *Service) prefixAssociationLimit() int {
	if s.limits.PrefixAssociations > 0 {
		return s.limits.PrefixAssociations
	}
	return policy.DefaultLimits().PrefixAssociations
}

// Reclassify reinterprets immutable normalized observations without collecting.
func (s *Service) Reclassify(ctx context.Context, request model.ReclassifyRequest) (model.Report, error) {
	if err := s.ValidateReclassify(ctx, request); err != nil {
		return model.Report{}, err
	}
	if s.controller != nil {
		var release func()
		var err error
		ctx, release, err = s.controller.Begin(ctx)
		if err != nil {
			return model.Report{}, err
		}
		defer release()
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
	coverage := make([]model.Coverage, 0, len(original.Coverage)+len(s.detectors)+2)
	for _, originalCoverage := range original.Coverage {
		originalCoverage.Capability = "original_collection/" + originalCoverage.Capability
		coverage = append(coverage, originalCoverage)
	}
	for _, detector := range s.detectors {
		detected, detectorCoverage := detector.Detect(ctx, observations, s.view)
		for index := range detected {
			detected[index].ClassifiedAt = classifiedAt
		}
		evidence = append(evidence, detected...)
		coverage = append(coverage, detectorCoverage...)
	}
	technologyEvidence, technologyCoverage := classifyUnmappedTechnology(observations, evidence, classifiedAt)
	evidence = append(evidence, technologyEvidence...)
	if technologyCoverage != nil {
		coverage = append(coverage, *technologyCoverage)
	}
	hasHTTP, hasTechnology := false, false
	for _, observation := range observations {
		hasHTTP = hasHTTP || observation.Type == "http_response"
		hasTechnology = hasTechnology || observation.Type == "technology"
	}
	if s.webDetector != nil && hasHTTP && !hasTechnology {
		coverage = append(coverage, model.Coverage{Capability: "replay_webtech", Status: model.CoverageUnavailable, Reason: "raw response bytes and raw technology labels were not retained"})
	}
	enrichedEvidence, enrichedCoverage, err := s.enrichAddresses(ctx, observations, classifiedAt)
	if err != nil {
		return model.Report{}, err
	}
	evidence = append(evidence, enrichedEvidence...)
	coverage = append(coverage, enrichedCoverage...)
	status := model.StatusComplete
	for _, item := range coverage {
		if strings.HasPrefix(item.Capability, "original_collection/") {
			continue
		}
		if item.Status == model.CoveragePartial || item.Status == model.CoverageUnavailable {
			status = model.StatusPartial
			break
		}
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion, ContentIDVersion: model.ReportContentIDVersion, OriginalReportID: original.ID, Target: original.Target, Mode: model.ModeReclassify,
		StartedAt: classifiedAt, EndedAt: s.now(), ClassifiedAt: classifiedAt, BundleID: s.view.BundleID(), BuildID: s.buildProvenance.CompatibilityID(),
		Provenance: s.reclassificationProvenance(original),
		Status:     status, Observations: observations, Evidence: evidence, Findings: aggregate.Build(evidence), Coverage: coverage, Warnings: make([]string, 0),
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

func (s *Service) liveProvenance() *model.ReportProvenance {
	provenance := model.ExplicitReportProvenance(
		s.buildProvenance,
		model.KnownProvenance(s.view.PolicyVersion()),
		s.fingerprintDigest,
		s.rulesDigest,
	)
	return &provenance
}

func (s *Service) reclassificationProvenance(original model.Report) *model.ReportProvenance {
	collection := model.UnknownCollectionProvenance()
	if original.Provenance != nil {
		collection = original.Provenance.Collection
	}
	return &model.ReportProvenance{
		Collection: collection,
		Classification: model.ClassificationProvenance{
			Build:       s.buildProvenance.Explicit(),
			RulesDigest: s.rulesDigest.Explicit(),
		},
	}
}

// ValidateReclassify checks bundle compatibility, retained inputs, and replay classifiers.
func (s *Service) ValidateReclassify(ctx context.Context, request model.ReclassifyRequest) error {
	if request.ReportID == "" {
		return model.NewError(model.CodeInvalidOptions, "report ID is required", nil)
	}
	if s.store == nil {
		return model.NewError(model.CodeCapabilityUnavailable, "reclassification input storage is unavailable", nil)
	}
	if request.BundleID != "" && request.BundleID != s.view.BundleID() {
		return model.NewError(model.CodeBundleUnavailable, "requested bundle is not loaded", nil)
	}
	original, err := s.store.LoadReport(ctx, request.ReportID)
	if err != nil {
		if model.ErrorCodeOf(err) != "" {
			return fmt.Errorf("load replay input: %w", err)
		}
		return model.NewError(model.CodePersistenceFailed, "load replay input", err)
	}
	if len(original.Observations) == 0 && len(original.Evidence) == 0 {
		return model.NewError(model.CodeCapabilityUnavailable, "report has no retained replay inputs", nil)
	}
	inputs := addressInputs(original.Observations)
	hasTechnology := false
	for _, observation := range original.Observations {
		hasTechnology = hasTechnology || observation.Type == "technology"
	}
	hasAddressPath := len(inputs) > 0 && s.prefixes != nil && s.sourceGroupUsable("prefix_source/")
	if !hasAddressPath && s.asn != nil {
		for _, input := range inputs {
			name := "asn_source/ipv6"
			if input.address.Is4() {
				name = "asn_source/ipv4"
			}
			hasAddressPath = hasAddressPath || s.sourceCapabilityUsable(name)
		}
	}
	hasDetectorPath := len(s.detectors) > 0 && len(original.Observations) > 0
	if !hasDetectorPath && !hasTechnology && !hasAddressPath {
		return model.NewError(model.CodeCapabilityUnavailable, "no replay classifier is usable for retained inputs", nil)
	}
	return nil
}

func technologyObservation(detection model.TechnologyDetection, source model.Observation) (model.Observation, bool) {
	if detection.Name == "" || detection.DetectorID == "" {
		return model.Observation{}, false
	}
	granularity := detection.ExplanationGranularity
	if granularity == "" {
		granularity = model.ExplanationGranularityDetectorResult
	}
	payload, err := json.Marshal(model.TechnologyPayload{
		Name: detection.Name, DetectorID: detection.DetectorID, ExplanationGranularity: granularity,
	})
	if err != nil {
		return model.Observation{}, false
	}
	sum := sha256.Sum256([]byte(detection.DetectorID + "\x00" + source.ID + "\x00" + detection.Name))
	return model.Observation{
		ID: "technology-" + hex.EncodeToString(sum[:12]), Type: "technology", Subject: source.Subject, Relation: model.RelationWebIntegration,
		Scope: source.Scope, ObservedAt: source.ObservedAt, CollectorVersion: detection.DetectorID, Status: "detected", Payload: payload,
	}, true
}

func classifyUnmappedTechnology(observations []model.Observation, existing []model.Evidence, classifiedAt time.Time) ([]model.Evidence, *model.Coverage) {
	evidence := make([]model.Evidence, 0)
	for _, observation := range observations {
		if observation.Type != "technology" || evidenceReferences(observation.ID, existing) {
			continue
		}
		var payload model.TechnologyPayload
		if json.Unmarshal(observation.Payload, &payload) != nil || payload.Name == "" {
			continue
		}
		detectorID := payload.DetectorID
		if detectorID == "" {
			detectorID = observation.CollectorVersion
		}
		sum := sha256.Sum256([]byte("technology-taxonomy-v1\x00" + observation.ID + "\x00" + payload.Name))
		evidence = append(evidence, model.Evidence{
			ID: "evidence-technology-" + hex.EncodeToString(sum[:12]), ObservationIDs: []string{observation.ID}, ClassifiedAt: classifiedAt,
			DetectorID: detectorID, Subject: observation.Subject, ProductID: "webtech." + normalizeTechnologyID(payload.Name), Category: "web_technology",
			Relation: model.RelationWebIntegration, Strength: model.StrengthModerate, Activity: model.ActivityResponding, Scope: observation.Scope,
			Explanation: "passive detector result: " + payload.Name,
		})
	}
	if len(evidence) == 0 {
		return nil, nil
	}
	coverage := model.Coverage{Capability: "technology_taxonomy", Status: model.CoverageComplete, Attempted: len(evidence), Completed: len(evidence)}
	return evidence, &coverage
}

func evidenceReferences(observationID string, evidence []model.Evidence) bool {
	for _, item := range evidence {
		if slices.Contains(item.ObservationIDs, observationID) {
			return true
		}
	}
	return false
}

func normalizeTechnologyID(value string) string {
	value = strings.ToLower(value)
	value = strings.Map(func(char rune) rune {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			return char
		}
		return '-'
	}, value)
	return strings.Trim(value, "-")
}

type addressInput struct {
	subject        string
	scope          model.Scope
	address        netip.Addr
	observationIDs []string
}

func addressInputs(observations []model.Observation) []addressInput {
	byKey := make(map[string]*addressInput)
	for _, observation := range observations {
		var address netip.Addr
		switch observation.Type {
		case "dns_address":
			var payload model.DNSPayload
			if json.Unmarshal(observation.Payload, &payload) == nil {
				address = payload.Address
			}
		case "http_response":
			var payload model.HTTPPayload
			if json.Unmarshal(observation.Payload, &payload) == nil {
				address = payload.PeerAddress
			}
		}
		if !address.IsValid() {
			continue
		}
		address = address.Unmap()
		key := observation.Subject + "\x00" + string(observation.Scope) + "\x00" + address.String()
		input := byKey[key]
		if input == nil {
			input = &addressInput{subject: observation.Subject, scope: observation.Scope, address: address}
			byKey[key] = input
		}
		if !slices.Contains(input.observationIDs, observation.ID) {
			input.observationIDs = append(input.observationIDs, observation.ID)
		}
	}
	inputs := make([]addressInput, 0, len(byKey))
	for _, input := range byKey {
		slices.Sort(input.observationIDs)
		inputs = append(inputs, *input)
	}
	slices.SortFunc(inputs, func(left, right addressInput) int {
		leftKey := left.subject + "\x00" + string(left.scope) + "\x00" + left.address.String()
		rightKey := right.subject + "\x00" + string(right.scope) + "\x00" + right.address.String()
		return strings.Compare(leftKey, rightKey)
	})
	return inputs
}

func (s *Service) enrichAddresses(ctx context.Context, observations []model.Observation, classifiedAt time.Time) ([]model.Evidence, []model.Coverage, error) {
	inputs := addressInputs(observations)
	if len(inputs) == 0 {
		return nil, nil, nil
	}
	addresses := make([]netip.Addr, 0, len(inputs))
	for _, input := range inputs {
		addresses = append(addresses, input.address)
	}
	coverage := s.sourceCoverage(addresses)
	var evidence []model.Evidence
	prefixUsable := s.prefixes != nil && s.sourceGroupUsable("prefix_source/")
	if !prefixUsable {
		coverage = append(coverage, model.Coverage{Capability: "prefix", Status: model.CoverageUnavailable, Reason: "prefix source is unavailable"})
	} else {
		for _, input := range inputs {
			associations, itemCoverage, lookupErr := s.prefixes.LookupPrefixes(ctx, model.IPLookupRequest{Address: input.address, Match: "all"}, s.view)
			if lookupErr != nil {
				itemCoverage.Status = model.CoverageUnavailable
				itemCoverage.ErrorCodes = append(itemCoverage.ErrorCodes, model.ErrorCodeOf(lookupErr))
			}
			if len(associations) > s.prefixAssociationLimit() {
				omitted := len(associations) - s.prefixAssociationLimit()
				associations = associations[:s.prefixAssociationLimit()]
				itemCoverage.Status = model.CoveragePartial
				itemCoverage.Omitted += omitted
				itemCoverage.ErrorCodes = append(itemCoverage.ErrorCodes, model.CodeBudgetExceeded)
				itemCoverage.Reason = "configured prefix association limit reached"
			}
			coverage = append(coverage, itemCoverage)
			for _, association := range associations {
				item, err := prefixEvidence(input, association, classifiedAt)
				if err != nil {
					return nil, nil, err
				}
				evidence = append(evidence, item)
			}
		}
	}
	if s.asn == nil {
		coverage = append(coverage, model.Coverage{Capability: "asn", Status: model.CoverageUnavailable, Reason: "ASN source is unavailable"})
	} else {
		for _, input := range inputs {
			asnSource := "asn_source/ipv6"
			if input.address.Is4() {
				asnSource = "asn_source/ipv4"
			}
			if !s.sourceCapabilityUsable(asnSource) {
				continue
			}
			records, itemCoverage, lookupErr := s.asn.LookupASN(ctx, input.address, s.view)
			if lookupErr != nil {
				itemCoverage.Status = model.CoverageUnavailable
				itemCoverage.ErrorCodes = append(itemCoverage.ErrorCodes, model.ErrorCodeOf(lookupErr))
			}
			coverage = append(coverage, itemCoverage)
			for _, record := range records {
				item, err := asnEvidence(input, record, classifiedAt)
				if err != nil {
					return nil, nil, err
				}
				evidence = append(evidence, item)
			}
		}
	}
	return evidence, coverage, nil
}

func (s *Service) sourceCoverage(addresses []netip.Addr) []model.Coverage {
	wantV4, wantV6 := false, false
	for _, address := range addresses {
		wantV4 = wantV4 || address.Unmap().Is4()
		wantV6 = wantV6 || address.Is6() && !address.Is4In6()
	}
	var coverage []model.Coverage
	for _, capability := range s.view.Capabilities() {
		include := strings.HasPrefix(capability.Name, "prefix_source/")
		if capability.Name == "asn_source/ipv4" {
			include = wantV4
		}
		if capability.Name == "asn_source/ipv6" {
			include = wantV6
		}
		if !include {
			continue
		}
		item := model.Coverage{Capability: capability.Name, Status: capability.Status, Reason: capability.Reason}
		if capability.SourceAge != nil {
			seconds := int64(*capability.SourceAge / time.Second)
			item.DataAgeSeconds = &seconds
		}
		coverage = append(coverage, item)
	}
	return coverage
}

func (s *Service) sourceCapabilityUsable(name string) bool {
	found := false
	for _, capability := range s.view.Capabilities() {
		if capability.Name != name {
			continue
		}
		found = true
		if capability.Status == model.CoverageComplete || capability.Status == model.CoveragePartial {
			return true
		}
	}
	return !found
}

func (s *Service) sourceGroupUsable(prefix string) bool {
	found := false
	for _, capability := range s.view.Capabilities() {
		if !strings.HasPrefix(capability.Name, prefix) {
			continue
		}
		found = true
		if capability.Status == model.CoverageComplete || capability.Status == model.CoveragePartial {
			return true
		}
	}
	return !found
}

func prefixEvidence(input addressInput, association model.Association, classifiedAt time.Time) (model.Evidence, error) {
	fields, err := json.Marshal(association)
	if err != nil {
		return model.Evidence{}, fmt.Errorf("encode prefix association: %w", err)
	}
	key := association.ID + "\x00" + strings.Join(input.observationIDs, ",")
	sum := sha256.Sum256([]byte(key))
	return model.Evidence{
		ID:             "evidence-prefix-" + hex.EncodeToString(sum[:12]),
		ObservationIDs: slices.Clone(input.observationIDs),
		DatasetRecords: []model.DatasetRecord{{
			SourceID:  association.SourceID,
			Revision:  association.SourceRevision,
			Digest:    association.SourceDigest,
			RecordRef: association.RecordRef,
			Fields:    fields,
		}},
		ClassifiedAt: classifiedAt,
		DetectorID:   "prefix-v1",
		Subject:      input.subject,
		ProviderID:   association.ProviderID,
		ProductID:    association.ProductID,
		Category:     "cloud_infrastructure",
		Relation:     model.RelationServiceRange,
		Strength:     model.StrengthModerate,
		Activity:     model.ActivityUnknown,
		Scope:        input.scope,
		Explanation:  "address is contained by a normalized local prefix record",
	}, nil
}

func asnEvidence(input addressInput, record model.ASNRecord, classifiedAt time.Time) (model.Evidence, error) {
	fields, err := json.Marshal(record)
	if err != nil {
		return model.Evidence{}, fmt.Errorf("encode ASN record: %w", err)
	}
	key := fmt.Sprintf("%d\x00%s\x00%s", record.ASN, record.RecordRef, strings.Join(input.observationIDs, ","))
	sum := sha256.Sum256([]byte(key))
	return model.Evidence{
		ID: "evidence-asn-" + hex.EncodeToString(sum[:12]), ObservationIDs: slices.Clone(input.observationIDs),
		DatasetRecords: []model.DatasetRecord{{SourceID: record.SourceID, Revision: record.SourceRevision, Digest: record.SourceDigest, RecordRef: record.RecordRef, Fields: fields}},
		ClassifiedAt:   classifiedAt, DetectorID: "asn-v1", Subject: input.subject, ProviderID: fmt.Sprintf("asn:%d", record.ASN), Category: "network",
		Relation: model.RelationNetworkProvider, Strength: model.StrengthWeak, Activity: model.ActivityUnknown, Scope: input.scope,
		Explanation: "address is contained by a local ASN interval; organization attribution is not a product claim",
	}, nil
}

func scopeForSeed(hostname string, roots []string) model.Scope {
	if slices.Contains(roots, hostname) {
		return model.ScopeRoot
	}
	return model.ScopeSubdomain
}

func reportStatus(ctx context.Context, observations []model.Observation, coverage []model.Coverage) model.ReportStatus {
	if errors.Is(ctx.Err(), context.Canceled) {
		return model.StatusCancelled
	}
	useful := false
	for _, observation := range observations {
		if observation.Status == string(model.DNSOutcomeAnswered) || observation.Status == string(model.DNSOutcomeNoData) || observation.Status == string(model.DNSOutcomeNXDomain) || observation.Status == "responded" || observation.Status == "policy_blocked" {
			useful = true
			break
		}
	}
	partial := false
	for _, item := range coverage {
		if item.Status == model.CoveragePartial || item.Status == model.CoverageUnavailable {
			partial = true
		}
	}
	if !useful && partial {
		return model.StatusFailed
	}
	if partial {
		return model.StatusPartial
	}
	return model.StatusComplete
}

func seedURL(request model.NormalizedRequest, hostname, fallbackScheme string) string {
	if request.Target.Kind == model.TargetURL {
		parsed, err := url.Parse(request.Target.Canonical)
		if err == nil && parsed.Hostname() == hostname {
			return parsed.String()
		}
	}
	return fallbackScheme + "://" + hostname + "/"
}

func tlsCertificateCoverage(request model.NormalizedRequest, observations []model.Observation, fallbackScheme string) model.Coverage {
	coverage := model.Coverage{Capability: "tls_certificate"}
	if request.Mode == model.ModeDNS {
		coverage.Status = model.CoverageSkipped
		coverage.Reason = "DNS-only mode"
		return coverage
	}
	applicable := false
	for _, hostname := range request.SeedHostnames {
		parsed, err := url.Parse(seedURL(request, hostname, fallbackScheme))
		applicable = applicable || err == nil && strings.EqualFold(parsed.Scheme, "https")
	}
	for _, observation := range observations {
		if observation.Type != "http_response" {
			continue
		}
		var payload model.HTTPPayload
		if json.Unmarshal(observation.Payload, &payload) != nil {
			continue
		}
		parsed, err := url.Parse(payload.URL)
		applicable = applicable || err == nil && strings.EqualFold(parsed.Scheme, "https")
	}
	if !applicable {
		coverage.Status = model.CoverageSkipped
		coverage.Reason = "plain HTTP has no TLS session"
		return coverage
	}
	coverage.Status = model.CoverageUnavailable
	coverage.Reason = "TLS certificate evidence collection is unsupported"
	return coverage
}

func seedPort(request model.NormalizedRequest, hostname, fallbackScheme string) uint16 {
	parsed, err := url.Parse(seedURL(request, hostname, fallbackScheme))
	if err == nil {
		if parsed.Port() == "80" {
			return 80
		}
		if parsed.Port() == "443" {
			return 443
		}
		if parsed.Scheme == "http" {
			return 80
		}
	}
	return 443
}
