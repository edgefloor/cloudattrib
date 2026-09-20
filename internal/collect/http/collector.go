// Package http collects one bounded document through an approved address.
package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

// DialFunc dials one already approved concrete address.
type DialFunc func(context.Context, string, netip.Addr, uint16) (net.Conn, error)

// Result contains one response observation and its coverage.
type Result struct {
	Observation model.Observation
	Coverage    model.Coverage
	PeerAddress netip.Addr
}

// Collector owns the application HTTP transport settings.
type Collector struct {
	dial    DialFunc
	policy  policy.DestinationPolicy
	maxBody int64
	now     func() time.Time
}

// New constructs a bounded collector without environment proxy behavior.
func New(dial DialFunc, destinationPolicy policy.DestinationPolicy, maxBody int64) *Collector {
	return &Collector{dial: dial, policy: destinationPolicy, maxBody: maxBody, now: time.Now}
}

// Collect fetches one root document through the selected address. The URL host
// remains the HTTP Host value and the TLS server name.
func (c *Collector) Collect(ctx context.Context, scheme, hostname string, address netip.Addr) (Result, error) {
	port := uint16(443)
	if scheme == "http" {
		port = 80
	}
	decision := c.policy.Check(address, port)
	if !decision.Allowed {
		return Result{Coverage: model.Coverage{Capability: "http", Status: model.CoverageUnavailable, ErrorCodes: []model.ErrorCode{model.CodePolicyBlocked}}},
			model.NewError(model.CodePolicyBlocked, "HTTP destination is prohibited", nil)
	}

	transport := &stdhttp.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return c.dial(dialCtx, network, address, port)
		},
	}
	defer transport.CloseIdleConnections()
	client := &stdhttp.Client{
		Transport: transport,
		CheckRedirect: func(_ *stdhttp.Request, _ []*stdhttp.Request) error {
			return stdhttp.ErrUseLastResponse
		},
	}
	request, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, scheme+"://"+hostname+"/", nil)
	if err != nil {
		return Result{}, fmt.Errorf("create HTTP request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return Result{Coverage: model.Coverage{Capability: "http", Status: model.CoveragePartial, Attempted: 1, ErrorCodes: []model.ErrorCode{model.CodeCollectionFailed}}},
			fmt.Errorf("collect HTTP response: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return Result{}, fmt.Errorf("read HTTP response: %w", readErr)
	}
	if closeErr != nil {
		return Result{}, fmt.Errorf("close HTTP response: %w", closeErr)
	}
	truncated := int64(len(body)) > c.maxBody
	if truncated {
		body = body[:c.maxBody]
	}
	bodyDigest := sha256.Sum256(body)
	payload := model.HTTPPayload{
		URL:           scheme + "://" + hostname + "/",
		StatusCode:    response.StatusCode,
		PeerAddress:   address,
		Headers:       selectedHeaders(response.Header),
		BodyHash:      "sha256:" + hex.EncodeToString(bodyDigest[:]),
		BodyLength:    int64(len(body)),
		BodyTruncated: truncated,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Result{}, fmt.Errorf("encode HTTP observation: %w", err)
	}
	coverage := model.Coverage{Capability: "http", Status: model.CoverageComplete, Attempted: 1, Completed: 1}
	if truncated {
		coverage.Status = model.CoveragePartial
		coverage.Truncated = 1
	}
	return Result{
		Observation: model.Observation{
			ID:          observationID(hostname, address),
			Type:        "http_response",
			Subject:     hostname,
			Relation:    model.RelationWebDelivery,
			Scope:       model.ScopeRoot,
			ObservedAt:  c.now(),
			Status:      "responded",
			Payload:     encoded,
			ContentHash: payload.BodyHash,
		},
		Coverage:    coverage,
		PeerAddress: address,
	}, nil
}

func selectedHeaders(headers stdhttp.Header) []model.HTTPHeader {
	allowed := map[string]struct{}{
		"content-type": {},
		"server":       {},
		"via":          {},
		"x-powered-by": {},
	}
	result := make([]model.HTTPHeader, 0, len(allowed))
	for name, values := range headers {
		canonical := strings.ToLower(name)
		if _, ok := allowed[canonical]; !ok {
			continue
		}
		result = append(result, model.HTTPHeader{Name: canonical, Values: slices.Clone(values)})
	}
	slices.SortFunc(result, func(a, b model.HTTPHeader) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func observationID(hostname string, address netip.Addr) string {
	sum := sha256.Sum256([]byte(hostname + "\x00" + address.String()))
	return "http-response-" + hex.EncodeToString(sum[:12])
}
