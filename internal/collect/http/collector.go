// Package http collects bounded documents through approved concrete addresses.
package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/html"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

// DialFunc dials one already approved concrete address.
type DialFunc func(context.Context, string, netip.Addr, uint16) (net.Conn, error)

// ResolveFunc resolves a redirect hostname through the configured resolver.
type ResolveFunc func(context.Context, string) ([]netip.Addr, error)

// Option configures a Collector.
type Option func(*Collector)

// WithRedirectResolver enables bounded redirects with fresh address validation.
func WithRedirectResolver(resolve ResolveFunc) Option {
	return func(collector *Collector) { collector.resolve = resolve }
}

// WithRequestTimeout bounds each request within the caller's target deadline.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(collector *Collector) { collector.requestTimeout = timeout }
}

// Result contains response observations and the final passive detector input.
type Result struct {
	Observation  model.Observation
	Observations []model.Observation
	Coverage     model.Coverage
	PeerAddress  netip.Addr
	Headers      stdhttp.Header
	Body         []byte
}

// Collector owns the application HTTP transport settings.
type Collector struct {
	dial           DialFunc
	resolve        ResolveFunc
	policy         policy.DestinationPolicy
	maxBody        int64
	maxRedirects   int
	requestTimeout time.Duration
	now            func() time.Time
}

// New constructs a bounded collector without environment proxy behavior.
func New(dial DialFunc, destinationPolicy policy.DestinationPolicy, maxBody int64, options ...Option) *Collector {
	collector := &Collector{dial: dial, policy: destinationPolicy, maxBody: maxBody, maxRedirects: 5, requestTimeout: 10 * time.Second, now: time.Now}
	for _, option := range options {
		option(collector)
	}
	return collector
}

// Collect fetches one root document and its bounded redirect chain. Each hop
// resolves and validates its concrete destination before dialing.
func (c *Collector) Collect(ctx context.Context, scheme, hostname string, address netip.Addr) (Result, error) {
	return c.CollectTarget(ctx, scheme+"://"+hostname+"/", address)
}

// CollectTarget fetches one normalized HTTP URL through an approved address.
func (c *Collector) CollectTarget(ctx context.Context, rawURL string, address netip.Addr) (Result, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Result{}, fmt.Errorf("parse HTTP target: %w", err)
	}
	runID, err := model.NewCollectionRunID()
	if err != nil {
		return Result{}, fmt.Errorf("create HTTP collection run ID: %w", err)
	}
	return c.CollectTargetOccurrence(ctx, rawURL, address, model.ObservationOccurrence{
		CollectionRunID: runID,
		Seed:            parsed.Hostname(),
		Attempt:         1,
	})
}

// CollectTargetOccurrence fetches one normalized HTTP URL with caller-owned
// collection occurrence context.
func (c *Collector) CollectTargetOccurrence(ctx context.Context, rawURL string, address netip.Addr, occurrence model.ObservationOccurrence) (Result, error) {
	currentURL, err := url.Parse(rawURL)
	if err != nil {
		return Result{}, fmt.Errorf("parse HTTP target: %w", err)
	}
	if currentURL.User != nil || currentURL.Hostname() == "" || (currentURL.Scheme != "http" && currentURL.Scheme != "https") {
		return Result{}, model.NewError(model.CodeInvalidTarget, "HTTP target is invalid", nil)
	}
	if currentURL.Port() != "" && currentURL.Port() != "80" && currentURL.Port() != "443" {
		return Result{}, model.NewError(model.CodePolicyBlocked, "HTTP target port is prohibited", nil)
	}
	currentAddress := address.Unmap()
	originalHostname := currentURL.Hostname()
	coverage := model.Coverage{Capability: "http", Status: model.CoverageComplete}
	var observations []model.Observation
	var final Result
	for hop := 0; ; hop++ {
		if hop > c.maxRedirects {
			coverage.Status = model.CoveragePartial
			coverage.Omitted++
			coverage.ErrorCodes = append(coverage.ErrorCodes, model.CodeLimitExceeded)
			return Result{Observations: observations, Coverage: coverage}, model.NewError(model.CodeLimitExceeded, "HTTP redirect limit exceeded", nil)
		}
		coverage.Attempted++
		requestCtx := ctx
		cancel := func() {}
		if c.requestTimeout > 0 {
			requestCtx, cancel = context.WithTimeout(ctx, c.requestTimeout)
		}
		hopOccurrence := occurrence
		hopOccurrence.Hop = hop
		hopResult, location, collectErr := c.collectHop(requestCtx, currentURL, currentAddress, originalHostname, hopOccurrence)
		cancel()
		if collectErr != nil {
			coverage.Status = model.CoveragePartial
			coverage.ErrorCodes = append(coverage.ErrorCodes, model.CodeCollectionFailed)
			return Result{Observations: observations, Coverage: coverage}, collectErr
		}
		coverage.Completed++
		observations = append(observations, hopResult.Observation)
		if hopResult.Coverage.Status == model.CoveragePartial {
			coverage.Status = model.CoveragePartial
			coverage.Truncated += hopResult.Coverage.Truncated
		}
		final = hopResult
		if location == "" {
			break
		}
		if c.resolve == nil {
			coverage.Status = model.CoveragePartial
			coverage.Omitted++
			coverage.ErrorCodes = append(coverage.ErrorCodes, model.CodeCapabilityUnavailable)
			return finish(final, observations, coverage), nil
		}
		nextURL, resolveErr := currentURL.Parse(location)
		if resolveErr != nil || nextURL.Hostname() == "" || nextURL.User != nil || (nextURL.Scheme != "http" && nextURL.Scheme != "https") {
			return Result{Observations: observations, Coverage: coverage}, model.NewError(model.CodeInvalidTarget, "HTTP redirect URL is invalid", resolveErr)
		}
		if nextURL.Port() != "" && nextURL.Port() != "80" && nextURL.Port() != "443" {
			return Result{Observations: observations, Coverage: coverage}, model.NewError(model.CodePolicyBlocked, "HTTP redirect port is prohibited", nil)
		}
		addresses, resolveErr := c.resolve(ctx, nextURL.Hostname())
		if resolveErr != nil {
			coverage.Status = model.CoveragePartial
			coverage.ErrorCodes = append(coverage.ErrorCodes, model.CodeTimeout)
			return finish(final, observations, coverage), nil
		}
		approved, blocked := c.firstApproved(addresses, portForURL(nextURL))
		if blocked {
			coverage.Status = model.CoveragePartial
			coverage.ErrorCodes = append(coverage.ErrorCodes, model.CodePolicyBlocked)
		}
		if !approved.IsValid() {
			coverage.Status = model.CoveragePartial
			coverage.Omitted++
			return finish(final, observations, coverage), nil
		}
		currentURL = nextURL
		currentAddress = approved
	}
	return finish(final, observations, coverage), nil
}

func (c *Collector) collectHop(ctx context.Context, targetURL *url.URL, address netip.Addr, originalHostname string, occurrence model.ObservationOccurrence) (Result, string, error) {
	port := portForURL(targetURL)
	if decision := c.policy.Check(address, port); !decision.Allowed {
		return Result{}, "", model.NewError(model.CodePolicyBlocked, "HTTP destination is prohibited", nil)
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
	client := &stdhttp.Client{Transport: transport, CheckRedirect: func(_ *stdhttp.Request, _ []*stdhttp.Request) error { return stdhttp.ErrUseLastResponse }}
	request, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, targetURL.String(), nil)
	if err != nil {
		return Result{}, "", fmt.Errorf("create HTTP request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return Result{}, "", fmt.Errorf("collect HTTP response: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return Result{}, "", fmt.Errorf("read HTTP response: %w", readErr)
	}
	if closeErr != nil {
		return Result{}, "", fmt.Errorf("close HTTP response: %w", closeErr)
	}
	truncated := int64(len(body)) > c.maxBody
	if truncated {
		body = body[:c.maxBody]
	}
	bodyDigest := sha256.Sum256(body)
	payload := model.HTTPPayload{URL: redactQuery(targetURL), StatusCode: response.StatusCode, PeerAddress: address, Headers: selectedHeaders(response.Header), BodyHash: "sha256:" + hex.EncodeToString(bodyDigest[:]), BodyLength: int64(len(body)), BodyTruncated: truncated, ScriptURLs: scriptURLs(body, targetURL, 128)}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Result{}, "", fmt.Errorf("encode HTTP observation: %w", err)
	}
	coverage := model.Coverage{Capability: "http", Status: model.CoverageComplete, Attempted: 1, Completed: 1}
	if truncated {
		coverage.Status = model.CoveragePartial
		coverage.Truncated = 1
	}
	scope := model.ScopeRoot
	if !strings.EqualFold(targetURL.Hostname(), originalHostname) {
		scope = model.ScopeExternalRedirect
	}
	path := targetURL.EscapedPath()
	if path == "" {
		path = "/"
	}
	observation := model.Observation{
		ID:   model.ObservationID("http-response", occurrence, stdhttp.MethodGet, targetURL.Scheme, targetURL.Host, path, address.String()),
		Type: "http_response", Subject: targetURL.Hostname(), Relation: model.RelationWebDelivery, Scope: scope,
		ObservedAt: c.now(), Status: "responded", Payload: encoded, ContentHash: payload.BodyHash,
	}
	return Result{Observation: observation, Coverage: coverage, PeerAddress: address, Headers: response.Header.Clone(), Body: slices.Clone(body)}, response.Header.Get("Location"), nil
}

func scriptURLs(body []byte, base *url.URL, limit int) []string {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for len(result) < limit {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if !strings.EqualFold(token.Data, "script") {
			continue
		}
		for _, attribute := range token.Attr {
			if !strings.EqualFold(attribute.Key, "src") {
				continue
			}
			parsed, err := base.Parse(attribute.Val)
			if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				break
			}
			parsed.RawQuery = ""
			parsed.Fragment = ""
			value := parsed.String()
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				result = append(result, value)
			}
			break
		}
	}
	slices.Sort(result)
	return result
}

func (c *Collector) firstApproved(addresses []netip.Addr, port uint16) (netip.Addr, bool) {
	var approved netip.Addr
	blocked := false
	for _, address := range addresses {
		decision := c.policy.Check(address.Unmap(), port)
		if decision.Allowed && !approved.IsValid() {
			approved = address.Unmap()
		}
		blocked = blocked || !decision.Allowed
	}
	return approved, blocked
}

func finish(final Result, observations []model.Observation, coverage model.Coverage) Result {
	final.Observations = observations
	final.Coverage = coverage
	return final
}

func selectedHeaders(headers stdhttp.Header) []model.HTTPHeader {
	allowed := map[string]struct{}{"content-type": {}, "server": {}, "via": {}, "x-powered-by": {}}
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

func portForScheme(scheme string) uint16 {
	if scheme == "http" {
		return 80
	}
	return 443
}

func portForURL(value *url.URL) uint16 {
	if value.Port() == "80" {
		return 80
	}
	if value.Port() == "443" {
		return 443
	}
	return portForScheme(value.Scheme)
}

func redactQuery(value *url.URL) string {
	copyURL := *value
	if copyURL.RawQuery != "" {
		copyURL.RawQuery = "redacted"
	}
	copyURL.Fragment = ""
	return copyURL.String()
}
