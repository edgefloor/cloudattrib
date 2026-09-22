package policy

import (
	"encoding/csv"
	"net/netip"
	"os"
	"strconv"
	"testing"
)

func TestPublicDestinationPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		port    uint16
		allowed bool
		reason  Reason
	}{
		{name: "public IPv4", addr: "8.8.8.8", port: 443, allowed: true},
		{name: "public IPv6", addr: "2606:4700:4700::1111", port: 80, allowed: true},
		{name: "private", addr: "10.0.0.1", port: 443, reason: ReasonPrivate},
		{name: "loopback", addr: "127.0.0.1", port: 443, reason: ReasonLoopback},
		{name: "link local metadata", addr: "169.254.169.254", port: 443, reason: ReasonLinkLocal},
		{name: "documentation", addr: "198.51.100.7", port: 443, reason: ReasonDocumentation},
		{name: "IPv6 documentation", addr: "2001:db8::1", port: 443, reason: ReasonDocumentation},
		{name: "IPv6 documentation 2024 allocation", addr: "3fff::1", port: 443, reason: ReasonDocumentation},
		{name: "IPv6 documentation lower boundary", addr: "3fff::", port: 443, reason: ReasonDocumentation},
		{name: "IPv6 documentation upper boundary", addr: "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", port: 443, reason: ReasonDocumentation},
		{name: "before IPv6 documentation allocation", addr: "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", port: 443, allowed: true},
		{name: "after IPv6 documentation allocation", addr: "3fff:1000::", port: 443, allowed: true},
		{name: "benchmark", addr: "198.18.0.1", port: 443, reason: ReasonBenchmark},
		{name: "local-use translation", addr: "64:ff9b:1::a00:1", port: 443, reason: ReasonSpecialUse},
		{name: "dummy IPv6 prefix", addr: "100:0:0:1::1", port: 443, reason: ReasonSpecialUse},
		{name: "SRv6 SID", addr: "5f00::1", port: 443, reason: ReasonSpecialUse},
		{name: "globally reachable registry exception", addr: "2001:1::1", port: 443, allowed: true},
		{name: "well-known translation of public IPv4", addr: "64:ff9b::808:808", port: 443, allowed: true},
		{name: "well-known translation of private IPv4", addr: "64:ff9b::a00:1", port: 443, reason: ReasonPrivate},
		{name: "mapped private", addr: "::ffff:10.0.0.1", port: 443, reason: ReasonPrivate},
		{name: "forbidden port", addr: "8.8.8.8", port: 22, reason: ReasonPort},
	}

	policy := PublicDestinationPolicy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision := policy.Check(netip.MustParseAddr(tt.addr), tt.port)
			if decision.Allowed != tt.allowed || decision.Reason != tt.reason {
				t.Fatalf("Check() = %#v, want allowed %t reason %q", decision, tt.allowed, tt.reason)
			}
		})
	}
}

func TestPolicyChecksMixedAddressesIndependently(t *testing.T) {
	t.Parallel()

	policy := PublicDestinationPolicy()
	private := policy.Check(netip.MustParseAddr("10.0.0.1"), 443)
	public := policy.Check(netip.MustParseAddr("8.8.8.8"), 443)
	if private.Allowed || !public.Allowed {
		t.Fatalf("independent checks = private %#v public %#v", private, public)
	}
}

func TestPublicDestinationPolicyMatchesPinnedIANARegistry(t *testing.T) {
	t.Parallel()

	fixture, err := os.Open("testdata/iana-special-purpose-2025-10-09.csv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	reader := csv.NewReader(fixture)
	reader.Comment = '#'
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatal("IANA registry fixture has no records")
	}
	policy := PublicDestinationPolicy()
	for _, row := range rows[1:] {
		if len(row) != 4 {
			t.Fatalf("registry row has %d fields: %v", len(row), row)
		}
		wantAllowed, err := strconv.ParseBool(row[3])
		if err != nil {
			t.Fatalf("parse globally reachable for %s: %v", row[1], err)
		}
		address := netip.MustParseAddr(row[2])
		if !netip.MustParsePrefix(row[1]).Contains(address) {
			t.Fatalf("sample %s is outside %s", address, row[1])
		}
		t.Run(row[0]+"/"+row[1], func(t *testing.T) {
			t.Parallel()
			decision := policy.Check(address, 443)
			if decision.Allowed != wantAllowed {
				t.Fatalf("Check(%s) = %#v, want allowed %t", address, decision, wantAllowed)
			}
		})
	}
}

func TestMappedPublicAddressUsesIPv4Decision(t *testing.T) {
	t.Parallel()

	decision := PublicDestinationPolicy().Check(netip.MustParseAddr("::ffff:8.8.8.8"), 443)
	if !decision.Allowed || decision.Address != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("Check() = %#v, want allowed unmapped IPv4", decision)
	}
}
