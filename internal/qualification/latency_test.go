package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"cloudattrib/internal/datasets"
	"cloudattrib/internal/enrich/asn"
	"cloudattrib/internal/enrich/prefix"
	"cloudattrib/internal/ingest/iptoasn"
	"cloudattrib/internal/model"
	"cloudattrib/internal/rules"
)

func TestLocalLatencyDistribution(t *testing.T) {
	prefixAssociations := make([]model.Association, 0, 4096)
	intervals := make([]iptoasn.Interval, 0, 4096)
	for index := 0; index < 4096; index++ {
		base := fmt.Sprintf("10.%d.%d", index/256, index%256)
		prefixAssociations = append(prefixAssociations, model.Association{
			ID: fmt.Sprintf("record-%d", index), Prefix: netip.MustParsePrefix(base + ".0/24"), ProviderID: "fixture", Lifecycle: "active",
		})
		intervals = append(intervals, iptoasn.Interval{
			Start: netip.MustParseAddr(base + ".0"), End: netip.MustParseAddr(base + ".255"), ASN: uint32(64512 + index), SourceID: "fixture",
		})
	}
	prefixIndex := prefix.New(prefixAssociations)
	asnIndex, err := asn.New(intervals)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("10.15.255.7")
	t.Run("prefix", func(t *testing.T) {
		recordLatency(t, 20000, func() error {
			_, _, err := prefixIndex.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: address, Match: "all"}, model.AttributionView{})
			return err
		})
	})
	t.Run("asn", func(t *testing.T) {
		recordLatency(t, 20000, func() error {
			_, _, err := asnIndex.LookupASN(context.Background(), address, model.AttributionView{})
			return err
		})
	})

	engine, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: "example.com", Value: "d111111abcdef8.cloudfront.net"})
	if err != nil {
		t.Fatal(err)
	}
	observations := []model.Observation{{ID: "dns", Type: "dns_record", Subject: "example.com", Scope: model.ScopeRoot, Status: "answered", Payload: payload}}
	t.Run("rules", func(t *testing.T) {
		recordLatency(t, 5000, func() error {
			engine.Detect(context.Background(), observations, model.AttributionView{})
			return nil
		})
	})

	sources := fixtureSources(t)
	t.Run("bundle_load", func(t *testing.T) {
		recordLatency(t, 1000, func() error {
			_, err := datasets.LoadSources(context.Background(), sources, "qualification-build")
			return err
		})
	})
}

func recordLatency(t *testing.T, samples int, operation func() error) {
	t.Helper()
	durations := make([]time.Duration, samples)
	for index := range samples {
		started := time.Now()
		if err := operation(); err != nil {
			t.Fatal(err)
		}
		durations[index] = time.Since(started)
	}
	slices.Sort(durations)
	t.Logf("samples=%d p50=%s p95=%s p99=%s", samples, percentile(durations, 50), percentile(durations, 95), percentile(durations, 99))
}

func percentile(values []time.Duration, percent int) time.Duration {
	index := (len(values)*percent + 99) / 100
	if index > 0 {
		index--
	}
	return values[index]
}

func fixtureSources(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	for _, name := range []string{
		"aws-ip-ranges.json", "gcp-cloud.json", "azure-service-tags.json", "cdncheck-sources-data.json", "iptoasn-v4.tsv", "iptoasn-v6.tsv",
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "upstream", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}
