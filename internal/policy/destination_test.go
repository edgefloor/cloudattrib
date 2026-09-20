package policy

import (
	"net/netip"
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
		{name: "benchmark", addr: "198.18.0.1", port: 443, reason: ReasonBenchmark},
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
