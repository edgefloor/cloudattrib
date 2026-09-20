// Package policy enforces collection limits and network destination rules.
package policy

import "net/netip"

// Reason explains why a concrete destination was rejected.
type Reason string

// Reason values describe production destination-policy rejections.
const (
	ReasonInvalid       Reason = "invalid"
	ReasonPort          Reason = "forbidden_port"
	ReasonLoopback      Reason = "loopback"
	ReasonPrivate       Reason = "private"
	ReasonLinkLocal     Reason = "link_local"
	ReasonUnspecified   Reason = "unspecified"
	ReasonMulticast     Reason = "multicast"
	ReasonDocumentation Reason = "documentation"
	ReasonBenchmark     Reason = "benchmark"
	ReasonSpecialUse    Reason = "special_use"
)

// Decision is the result of validating one address and port.
type Decision struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
	Allowed bool       `json:"allowed"`
	Reason  Reason     `json:"reason,omitempty"`
}

// DestinationPolicy validates concrete addresses immediately before dialing.
type DestinationPolicy struct{}

// PublicDestinationPolicy returns the production public-address policy.
func PublicDestinationPolicy() DestinationPolicy {
	return DestinationPolicy{}
}

// Check validates one concrete address independently from other DNS answers.
func (DestinationPolicy) Check(address netip.Addr, port uint16) Decision {
	address = address.Unmap()
	decision := Decision{Address: address, Port: port}
	if !address.IsValid() {
		decision.Reason = ReasonInvalid
		return decision
	}
	if port != 80 && port != 443 {
		decision.Reason = ReasonPort
		return decision
	}
	switch {
	case address.IsLoopback():
		decision.Reason = ReasonLoopback
	case address.IsPrivate():
		decision.Reason = ReasonPrivate
	case address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast():
		decision.Reason = ReasonLinkLocal
	case address.IsUnspecified():
		decision.Reason = ReasonUnspecified
	case address.IsMulticast():
		decision.Reason = ReasonMulticast
	case inPrefixes(address, documentationPrefixes):
		decision.Reason = ReasonDocumentation
	case inPrefixes(address, benchmarkPrefixes):
		decision.Reason = ReasonBenchmark
	case !address.IsGlobalUnicast() || inPrefixes(address, specialUsePrefixes):
		decision.Reason = ReasonSpecialUse
	default:
		decision.Allowed = true
	}
	return decision
}

var documentationPrefixes = mustPrefixes(
	"192.0.2.0/24",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"2001:db8::/32",
)

var benchmarkPrefixes = mustPrefixes(
	"198.18.0.0/15",
	"2001:2::/48",
)

var specialUsePrefixes = mustPrefixes(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"240.0.0.0/4",
	"100::/64",
	"2001:10::/28",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func inPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
