// Package runtime wires the local CLI application from operator configuration.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"cloudattrib/internal/app"
	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/config"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/detect/dnsrules"
	"cloudattrib/internal/detect/webtech"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
	"cloudattrib/internal/store/postgres"
)

// NewLocal constructs the collection-only local analyzer without downloading data.
func NewLocal(configuration config.Config) (app.Analyzer, error) {
	return newAnalyzer(context.Background(), configuration, standaloneReportStore{})
}

// OpenLocal constructs a CLI analyzer and opens durable CT storage only when CT is enabled.
func OpenLocal(ctx context.Context, configuration config.Config) (app.Analyzer, func(), error) {
	if !configuration.CT.Enabled {
		analyzer, err := newAnalyzer(ctx, configuration, standaloneReportStore{})
		return analyzer, func() {}, err
	}
	dsn, err := readDSN(configuration.Storage.PostgresDSNFile)
	if err != nil {
		return nil, nil, err
	}
	store, err := postgres.Open(ctx, dsn, configuration.Limits.MaximumBacklogTargets)
	if err != nil {
		return nil, nil, err
	}
	analyzer, err := newAnalyzer(ctx, configuration, store)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	return analyzer, store.Close, nil
}

func newAnalyzer(ctx context.Context, configuration config.Config, store app.ResultStore) (app.Analyzer, error) {
	analyzer, _, _, _, err := newAnalyzerDetails(ctx, configuration, store)
	return analyzer, err
}

type lookupAvailability struct {
	prefix bool
	asn    bool
	data   []model.CapabilityState
}

func (a lookupAvailability) usable() bool { return a.prefix || a.asn }
func (a lookupAvailability) complete() bool {
	if !a.prefix || !a.asn {
		return false
	}
	for _, capability := range a.data {
		if (capability.Name == "prefix" || capability.Name == "asn") && capability.Status != model.CoverageComplete {
			return false
		}
	}
	return true
}

func newAnalyzerDetails(ctx context.Context, configuration config.Config, store app.ResultStore) (app.Analyzer, string, []byte, lookupAvailability, error) {
	if err := configuration.Validate(); err != nil {
		return nil, "", nil, lookupAvailability{}, fmt.Errorf("validate configuration: %w", err)
	}
	dnsClient, err := collectdns.NewClient(collectdns.ClientConfig{
		Resolver: configuration.Resolver.Address,
		Network:  configuration.Resolver.Network,
		Timeout:  configuration.Limits.Target.DNSQueryTimeout,
		Attempts: configuration.Limits.Target.DNSAttempts,
	})
	if err != nil {
		return nil, "", nil, lookupAvailability{}, fmt.Errorf("create DNS client: %w", err)
	}
	destinationPolicy := policy.PublicDestinationPolicy()
	resolver := func(ctx context.Context, hostname string) ([]netip.Addr, error) {
		var addresses []netip.Addr
		for _, questionType := range []uint16{1, 28} {
			result, queryErr := dnsClient.Query(ctx, model.DNSQuestion{Name: hostname, Type: questionType})
			if queryErr != nil {
				continue
			}
			addresses = append(addresses, result.Addresses...)
		}
		if len(addresses) == 0 {
			return nil, model.NewError(model.CodeCollectionFailed, "redirect hostname did not resolve", nil)
		}
		return addresses, nil
	}
	dial := func(ctx context.Context, network string, address netip.Addr, port uint16) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), fmt.Sprint(port)))
	}
	webDetector, err := webtech.New(map[string]webtech.Mapping{
		"React": {ProductID: "webtech.react", Category: "web_technology", Relation: model.RelationWebIntegration},
	})
	if err != nil {
		return nil, "", nil, lookupAvailability{}, fmt.Errorf("create passive web detector: %w", err)
	}
	bundleID := builtinBundleID
	manifest := []byte(`{"schema_version":1,"bundle_id":"builtin-rules-v1"}`)
	capabilities := []model.CapabilityState{
		{Name: "dns", Status: model.CoverageComplete},
		{Name: "http", Status: model.CoverageComplete},
		{Name: "rules", Status: model.CoverageComplete},
		{Name: "webtech", Status: model.CoverageComplete},
		{Name: "prefix", Status: model.CoverageUnavailable, Reason: "no active local bundle"},
		{Name: "asn", Status: model.CoverageUnavailable, Reason: "no active local bundle"},
	}
	var prefixReader app.PrefixReader
	var asnReader app.ASNReader
	sourceDirectory := configuration.Data.SourceDirectory
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return nil, "", nil, lookupAvailability{}, err
	}
	activeSourceDirectory, activation, err := repository.SourceDirectory()
	if err != nil {
		return nil, "", nil, lookupAvailability{}, fmt.Errorf("resolve active bundle: %w", err)
	}
	if activation != nil {
		sourceDirectory = activeSourceDirectory
	}
	loaded, loadErr := datasets.LoadSources(ctx, sourceDirectory, detectorBuildID)
	if loadErr == nil {
		if activation != nil && loaded.Candidate.Manifest.BundleID != activation.BundleID {
			_ = repository.RecordLoad(activation.BundleID, "failed", "loaded content identity differs from active pointer")
			return nil, "", nil, lookupAvailability{}, fmt.Errorf("active bundle content identity differs from its pointer")
		}
		bundleID = loaded.Candidate.Manifest.BundleID
		if loaded.Prefixes != nil {
			prefixReader = loaded.Prefixes
		}
		if loaded.ASN != nil {
			asnReader = loaded.ASN
		}
		manifest, err = json.Marshal(loaded.Candidate.Manifest)
		if err != nil {
			return nil, "", nil, lookupAvailability{}, fmt.Errorf("encode local bundle manifest: %w", err)
		}
		capabilities = append(capabilities[:4], loaded.Candidate.View.Capabilities()...)
		if activation != nil {
			if err := repository.RecordLoad(bundleID, "loaded", ""); err != nil {
				return nil, "", nil, lookupAvailability{}, fmt.Errorf("record active bundle load: %w", err)
			}
		}
	} else if !errors.Is(loadErr, datasets.ErrNoSources) {
		if activation != nil {
			_ = repository.RecordLoad(activation.BundleID, "failed", loadErr.Error())
		}
		return nil, "", nil, lookupAvailability{}, fmt.Errorf("load local attribution sources: %w", loadErr)
	}
	view := model.NewAttributionView(
		bundleID,
		"public-destination-v1",
		[]string{detectorBuildID, "rules-v1", "wappalyzergo-v0.3.2"}, capabilities,
	)
	var ctReader ctlog.Reader
	if configuration.CT.Enabled {
		ctReader, _ = store.(ctlog.Reader)
	}
	return app.NewService(app.Dependencies{
		DNS:           collectdns.New(dnsClient.Query, destinationPolicy),
		HTTP:          collecthttp.New(dial, destinationPolicy, configuration.Limits.Target.HTTPDocumentBytes, collecthttp.WithRedirectResolver(resolver), collecthttp.WithRequestTimeout(configuration.Limits.Target.HTTPRequestTimeout)),
		Detectors:     []app.Detector{dnsrules.NewDefault()},
		WebDetector:   webDetector,
		Prefixes:      prefixReader,
		ASN:           asnReader,
		View:          view,
		Store:         store,
		CT:            ctReader,
		CTEnabled:     configuration.CT.Enabled,
		CTMaximumSeed: configuration.CT.MaximumSeedNames,
		TargetTimeout: configuration.Limits.Target.TargetDeadline,
	}), bundleID, manifest, lookupAvailability{prefix: prefixReader != nil, asn: asnReader != nil, data: slices.Clone(capabilities[4:])}, nil
}
