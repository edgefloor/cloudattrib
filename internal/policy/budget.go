package policy

import (
	"fmt"
	"time"
)

// Limits contains the shared per-target collection limits.
type Limits struct {
	TargetDeadline      time.Duration `json:"target_deadline" yaml:"target_deadline"`
	DNSQueryTimeout     time.Duration `json:"dns_query_timeout" yaml:"dns_query_timeout"`
	DNSAttempts         int           `json:"dns_attempts" yaml:"dns_attempts"`
	DNSQuestions        int           `json:"dns_questions" yaml:"dns_questions"`
	CNAMEChainDepth     int           `json:"cname_chain_depth" yaml:"cname_chain_depth"`
	HTTPRequestTimeout  time.Duration `json:"http_request_timeout" yaml:"http_request_timeout"`
	HTTPRequests        int           `json:"http_requests" yaml:"http_requests"`
	HTTPResponseHeaders int64         `json:"http_response_headers" yaml:"http_response_headers"`
	HTTPDocumentBytes   int64         `json:"http_document_bytes" yaml:"http_document_bytes"`
	HTTPTotalBodyBytes  int64         `json:"http_total_body_bytes" yaml:"http_total_body_bytes"`
	Redirects           int           `json:"redirects" yaml:"redirects"`
	SeedHostnames       int           `json:"seed_hostnames" yaml:"seed_hostnames"`
	ResolvedAddresses   int           `json:"resolved_addresses" yaml:"resolved_addresses"`
	PrefixAssociations  int           `json:"prefix_associations" yaml:"prefix_associations"`
}

// DefaultLimits returns SPEC section 14.1's initial bounds.
func DefaultLimits() Limits {
	return Limits{
		TargetDeadline:      60 * time.Second,
		DNSQueryTimeout:     3 * time.Second,
		DNSAttempts:         2,
		DNSQuestions:        512,
		CNAMEChainDepth:     16,
		HTTPRequestTimeout:  10 * time.Second,
		HTTPRequests:        64,
		HTTPResponseHeaders: 64 << 10,
		HTTPDocumentBytes:   2 << 20,
		HTTPTotalBodyBytes:  16 << 20,
		Redirects:           5,
		SeedHostnames:       32,
		ResolvedAddresses:   128,
		PrefixAssociations:  1024,
	}
}

// Validate rejects disabled or unbounded collection limits.
func (l Limits) Validate() error {
	if l.TargetDeadline <= 0 || l.DNSQueryTimeout <= 0 || l.HTTPRequestTimeout <= 0 {
		return fmt.Errorf("timeouts must be positive")
	}
	if l.DNSAttempts <= 0 || l.DNSQuestions <= 0 || l.CNAMEChainDepth <= 0 || l.HTTPRequests <= 0 ||
		l.HTTPResponseHeaders <= 0 || l.HTTPDocumentBytes <= 0 || l.HTTPTotalBodyBytes <= 0 ||
		l.Redirects < 0 || l.SeedHostnames <= 0 || l.ResolvedAddresses <= 0 || l.PrefixAssociations <= 0 {
		return fmt.Errorf("resource limits must be positive")
	}
	return nil
}
