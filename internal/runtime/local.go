// Package runtime wires the local CLI application from operator configuration.
package runtime

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"cloudattrib/internal/app"
	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/config"
	"cloudattrib/internal/detect/dnsrules"
	"cloudattrib/internal/detect/webtech"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

// NewLocal constructs the collection-only local analyzer without downloading data.
func NewLocal(configuration config.Config) (app.Analyzer, error) {
	return newAnalyzer(configuration, standaloneReportStore{})
}

func newAnalyzer(configuration config.Config, store app.ResultStore) (app.Analyzer, error) {
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	dnsClient, err := collectdns.NewClient(collectdns.ClientConfig{
		Resolver: configuration.Resolver.Address,
		Timeout:  configuration.Limits.Target.DNSQueryTimeout,
		Attempts: configuration.Limits.Target.DNSAttempts,
	})
	if err != nil {
		return nil, fmt.Errorf("create DNS client: %w", err)
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
		return nil, fmt.Errorf("create passive web detector: %w", err)
	}
	view := model.NewAttributionView(
		"builtin-rules-v1",
		"public-destination-v1",
		[]string{"rules-v1", "wappalyzergo-v0.3.2"},
		[]model.CapabilityState{
			{Name: "dns", Status: model.CoverageComplete},
			{Name: "http", Status: model.CoverageComplete},
			{Name: "rules", Status: model.CoverageComplete},
			{Name: "webtech", Status: model.CoverageComplete},
			{Name: "prefix", Status: model.CoverageUnavailable, Reason: "no active local bundle"},
			{Name: "asn", Status: model.CoverageUnavailable, Reason: "no active local bundle"},
		},
	)
	return app.NewService(app.Dependencies{
		DNS:           collectdns.New(dnsClient.Query, destinationPolicy),
		HTTP:          collecthttp.New(dial, destinationPolicy, configuration.Limits.Target.HTTPDocumentBytes, collecthttp.WithRedirectResolver(resolver), collecthttp.WithRequestTimeout(configuration.Limits.Target.HTTPRequestTimeout)),
		Detectors:     []app.Detector{dnsrules.NewDefault()},
		WebDetector:   webDetector,
		View:          view,
		Store:         store,
		TargetTimeout: configuration.Limits.Target.TargetDeadline,
	}), nil
}
