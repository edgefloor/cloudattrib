package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cloudattrib/internal/model"
)

const (
	// Per-target concurrency stays separate from the process-wide configuration.
	// These are the SPEC section 14.1 defaults.
	concurrentDNSPerTarget  = 8
	concurrentHTTPPerTarget = 4
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

// Controller owns process-wide target and network permits. One controller must
// be shared by every analyzer bundle loaded in a process.
type Controller struct {
	limits  Limits
	targets chan struct{}
	dns     chan struct{}
	http    chan struct{}
}

// NewController constructs a process-level execution controller. The channel
// capacities are the configured permit counts, not work queues.
func NewController(limits Limits, concurrentTargets, concurrentDNS, concurrentHTTP int) (*Controller, error) {
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("validate target limits: %w", err)
	}
	if concurrentTargets <= 0 || concurrentDNS <= 0 || concurrentHTTP <= 0 {
		return nil, fmt.Errorf("concurrent permit counts must be positive")
	}
	return &Controller{
		limits:  limits,
		targets: make(chan struct{}, concurrentTargets),
		dns:     make(chan struct{}, concurrentDNS),
		http:    make(chan struct{}, concurrentHTTP),
	}, nil
}

type executionKey struct{}

type execution struct {
	controller *Controller
	mu         sync.Mutex
	dnsLeft    int
	httpLeft   int
	addresses  int
	bodyLeft   int64
	dns        chan struct{}
	http       chan struct{}
}

// Begin waits for target admission using the caller's context. The configured
// target deadline starts only after admission succeeds. The returned release
// function is idempotent.
func (c *Controller) Begin(ctx context.Context) (context.Context, func(), error) {
	if c == nil {
		return ctx, func() {}, nil
	}
	if err := acquirePermit(ctx, c.targets); err != nil {
		return nil, nil, model.NewError(model.CodeCancelled, "wait for target admission", err)
	}
	executionCtx, cancel := context.WithTimeout(ctx, c.limits.TargetDeadline)
	state := &execution{
		controller: c,
		dnsLeft:    c.limits.DNSQuestions,
		httpLeft:   c.limits.HTTPRequests,
		addresses:  c.limits.ResolvedAddresses,
		bodyLeft:   c.limits.HTTPTotalBodyBytes,
		dns:        make(chan struct{}, min(concurrentDNSPerTarget, cap(c.dns))),
		http:       make(chan struct{}, min(concurrentHTTPPerTarget, cap(c.http))),
	}
	executionCtx = context.WithValue(executionCtx, executionKey{}, state)
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			releasePermit(c.targets)
		})
	}
	return executionCtx, release, nil
}

// AcquireDNS accounts for one actual DNS network attempt and waits for both
// per-target and process-level DNS permits.
func AcquireDNS(ctx context.Context) (func(), error) {
	state, ok := executionFromContext(ctx)
	if !ok {
		return func() {}, nil
	}
	if !state.reserveCount(&state.dnsLeft) {
		return nil, budgetError("DNS question budget exhausted")
	}
	return state.acquireNetwork(ctx, state.dns, state.controller.dns)
}

// AcquireHTTP accounts for one HTTP request and waits for both per-target and
// process-level HTTP permits.
func AcquireHTTP(ctx context.Context) (func(), error) {
	state, ok := executionFromContext(ctx)
	if !ok {
		return func() {}, nil
	}
	if !state.reserveCount(&state.httpLeft) {
		return nil, budgetError("HTTP request budget exhausted")
	}
	return state.acquireNetwork(ctx, state.http, state.controller.http)
}

// ReserveAddress accounts for one resolved address retained for later work.
func ReserveAddress(ctx context.Context) bool {
	state, ok := executionFromContext(ctx)
	if !ok {
		return true
	}
	return state.reserveCount(&state.addresses)
}

// ReserveHTTPBody reserves cumulative decoded-body capacity for one document.
// The caller may read one extra byte to detect truncation. It must report the
// retained byte count to commit so unused capacity is returned.
func ReserveHTTPBody(ctx context.Context, documentLimit int64) (int64, func(int64)) {
	state, ok := executionFromContext(ctx)
	if !ok {
		return documentLimit, func(int64) {}
	}
	state.mu.Lock()
	reserved := min(documentLimit, state.bodyLeft)
	state.bodyLeft -= reserved
	state.mu.Unlock()
	var once sync.Once
	return reserved, func(retained int64) {
		once.Do(func() {
			if retained < 0 {
				retained = 0
			}
			if retained > reserved {
				retained = reserved
			}
			state.mu.Lock()
			state.bodyLeft += reserved - retained
			state.mu.Unlock()
		})
	}
}

func executionFromContext(ctx context.Context) (*execution, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(executionKey{}).(*execution)
	return state, ok && state != nil
}

func (e *execution) reserveCount(counter *int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if *counter <= 0 {
		return false
	}
	*counter--
	return true
}

func (e *execution) acquireNetwork(ctx context.Context, target, process chan struct{}) (func(), error) {
	if err := acquirePermit(ctx, target); err != nil {
		return nil, model.NewError(model.CodeCancelled, "wait for per-target network admission", err)
	}
	if err := acquirePermit(ctx, process); err != nil {
		releasePermit(target)
		return nil, model.NewError(model.CodeCancelled, "wait for process network admission", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			releasePermit(process)
			releasePermit(target)
		})
	}, nil
}

func acquirePermit(ctx context.Context, permits chan struct{}) error {
	select {
	case permits <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releasePermit(permits chan struct{}) {
	<-permits
}

func budgetError(message string) error {
	return model.NewError(model.CodeBudgetExceeded, message, nil)
}
