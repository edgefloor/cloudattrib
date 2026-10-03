package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

type timeoutError struct{}

func fixtureNSResult(question model.DNSQuestion, target string) model.DNSResult {
	payload, _ := json.Marshal(model.DNSPayload{RRType: "NS", Owner: question.Name, Value: target})
	return model.DNSResult{Question: question, ResponseCode: 0, Records: []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}}
}

func (timeoutError) Error() string   { return "fixture timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

func TestCollectDistinguishesNegativeAnswersFromProtocolFailures(t *testing.T) {
	t.Parallel()

	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		responseCode := 0
		switch question.Type {
		case typeAAAA:
			responseCode = 3
		case typeCNAME:
			responseCode = 2
		case typeMX:
			responseCode = 5
		}
		return model.DNSResult{Question: question, ResponseCode: responseCode}, nil
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(t.Context(), "example.com", 443, nil)
	statuses := make(map[string]string)
	for _, observation := range result.Observations {
		if observation.Type != "dns_query" {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		statuses[payload.RRType] = observation.Status
	}
	if statuses["A"] != "nodata" || statuses["AAAA"] != "nxdomain" || statuses["CNAME"] != "servfail" || statuses["MX"] != "refused" {
		t.Fatalf("query statuses = %#v", statuses)
	}
	if result.Coverage.Status != model.CoveragePartial || result.Coverage.Completed != 5 {
		t.Fatalf("coverage = %#v", result.Coverage)
	}
}

func TestCollectFollowsCNAMEChainAndPublishesTerminalAddress(t *testing.T) {
	var mu sync.Mutex
	calls := make(map[model.DNSQuestion]int)
	query := func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		mu.Lock()
		calls[question]++
		mu.Unlock()
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Name == "example.com" && question.Type == typeNS {
			return fixtureNSResult(question, "ns.provider.test"), nil
		}
		if question.Type == typeCNAME {
			target := ""
			switch question.Name {
			case "example.com":
				target = "first.example.net"
			case "first.example.net":
				target = "terminal.example.net"
			}
			if target != "" {
				payload, _ := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: target, TTL: 300})
				result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
			}
		}
		if question.Name == "terminal.example.net" && question.Type == typeA {
			result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
		return result, nil
	}
	collector := New(query, policy.PublicDestinationPolicy())
	var published []netip.Addr
	result := collector.Collect(t.Context(), "example.com", 443, func(candidate Candidate) {
		published = append(published, candidate.Address)
	})
	if result.Coverage.Status != model.CoverageComplete || !slices.Equal(published, []netip.Addr{netip.MustParseAddr("93.184.216.34")}) {
		t.Fatalf("result = %#v, published = %v", result.Coverage, published)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, question := range []model.DNSQuestion{
		{Name: "first.example.net", Type: typeCNAME},
		{Name: "terminal.example.net", Type: typeCNAME},
		{Name: "terminal.example.net", Type: typeA},
		{Name: "terminal.example.net", Type: typeAAAA},
	} {
		if calls[question] != 1 {
			t.Fatalf("query %v ran %d times", question, calls[question])
		}
	}
	var links, terminalAddresses int
	for _, observation := range result.Observations {
		if observation.Type == "dns_record" {
			var payload model.DNSPayload
			if json.Unmarshal(observation.Payload, &payload) == nil && payload.RRType == "CNAME" {
				links++
			}
		}
		if observation.Type == "dns_address" && observation.Subject == "terminal.example.net" {
			terminalAddresses++
			if observation.Scope != model.ScopeCNAME {
				t.Fatalf("terminal scope = %q", observation.Scope)
			}
		}
	}
	if links != 2 || terminalAddresses != 1 {
		t.Fatalf("links = %d, terminal addresses = %d", links, terminalAddresses)
	}
	if err := (model.Report{Observations: result.Observations}).ValidateReferences(); err != nil {
		t.Fatalf("invalid observation identities: %v", err)
	}
}

func TestCollectPublishesCNAMEAddressWhileUnrelatedSeedQuestionWaits(t *testing.T) {
	textStarted := make(chan struct{})
	releaseText := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseText) }) }
	defer release()
	collector := New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		switch {
		case question.Name == "example.com" && question.Type == typeTXT:
			close(textStarted)
			select {
			case <-releaseText:
			case <-ctx.Done():
				return result, ctx.Err()
			}
		case question.Name == "example.com" && question.Type == typeCNAME:
			payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: "terminal.example.net", TTL: 60})
			if err != nil {
				return result, err
			}
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		case question.Name == "terminal.example.net" && question.Type == typeA:
			result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	candidates := make(chan Candidate, 1)
	done := make(chan Result, 1)
	go func() {
		done <- collector.Collect(t.Context(), "example.com", 443, func(candidate Candidate) { candidates <- candidate })
	}()
	<-textStarted
	var early bool
	select {
	case candidate := <-candidates:
		early = candidate.Address == netip.MustParseAddr("93.184.216.34")
	case <-time.After(2 * time.Second):
	}
	release()
	result := <-done
	if !early {
		t.Fatalf("terminal CNAME address was not published before unrelated TXT completed; coverage=%#v", result.Coverage)
	}
}

func TestCollectAttributesAddressInCNAMEAnswerToRecordOwner(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")
	observedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Name == "example.com" && question.Type == typeNS {
			return fixtureNSResult(question, "ns.provider.test"), nil
		}
		if question.Name == "example.com" && question.Type == typeA {
			for _, payload := range []model.DNSPayload{
				{RRType: "CNAME", Owner: "example.com", Value: "terminal.example.net"},
				{RRType: "A", Owner: "terminal.example.net", Address: address, TTL: 90, Section: "answer"},
			} {
				data, _ := json.Marshal(payload)
				result.Records = append(result.Records, model.Observation{Type: "dns_record", Subject: payload.Owner, Status: "answered", ObservedAt: observedAt, Payload: data})
			}
			result.Addresses = []netip.Addr{address}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	var candidates []Candidate
	result := collector.Collect(t.Context(), "example.com", 443, func(candidate Candidate) { candidates = append(candidates, candidate) })
	if len(candidates) != 1 || candidates[0].Hostname != "example.com" || candidates[0].Address != address {
		t.Fatalf("candidates = %#v", candidates)
	}
	for _, observation := range result.Observations {
		if observation.Type != "dns_address" || observation.Subject != "terminal.example.net" {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if observation.Scope != model.ScopeCNAME || !observation.ObservedAt.Equal(observedAt) || payload.RRType != "A" || payload.TTL != 90 || payload.Section != "answer" {
			t.Fatalf("address observation = %#v, payload = %#v", observation, payload)
		}
		return
	}
	t.Fatal("missing terminal address observation")
}

func TestCollectCNAMEGraphDistinguishesDuplicateLinksAndLoop(t *testing.T) {
	for _, test := range []struct {
		name, next  string
		wantPartial bool
	}{
		{name: "duplicate seed link", next: "", wantPartial: false},
		{name: "loop", next: "example.com", wantPartial: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
				result := model.DNSResult{Question: question, ResponseCode: 0}
				if question.Name == "example.com" && question.Type == typeNS {
					return fixtureNSResult(question, "ns.provider.test"), nil
				}
				target := ""
				if question.Name == "example.com" && (question.Type == typeA || question.Type == typeCNAME) {
					target = "first.example.net"
				}
				if question.Name == "first.example.net" && question.Type == typeCNAME {
					target = test.next
				}
				if target != "" {
					payload, _ := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: target})
					result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
				}
				return result, nil
			}, policy.PublicDestinationPolicy())
			result := collector.Collect(t.Context(), "example.com", 443, nil)
			if (result.Coverage.Status == model.CoveragePartial) != test.wantPartial {
				t.Fatalf("coverage = %#v", result.Coverage)
			}
		})
	}
}

func TestCollectStopsCNAMEAtConfiguredDepth(t *testing.T) {
	limits := policy.DefaultLimits()
	limits.CNAMEChainDepth = 1
	var terminalQueries atomic.Int64
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Name == "terminal.example.net" {
			terminalQueries.Add(1)
		}
		if question.Name == "example.com" && question.Type == typeNS {
			return fixtureNSResult(question, "ns.provider.test"), nil
		}
		target := ""
		if question.Type == typeCNAME {
			switch question.Name {
			case "example.com":
				target = "first.example.net"
			case "first.example.net":
				target = "terminal.example.net"
			}
		}
		if target != "" {
			payload, _ := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: target})
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		}
		return result, nil
	}, policy.PublicDestinationPolicy()).WithLimits(limits)
	result := collector.Collect(t.Context(), "example.com", 443, nil)
	if result.Coverage.Status != model.CoveragePartial || result.Coverage.Omitted == 0 || terminalQueries.Load() != 0 {
		t.Fatalf("coverage = %#v, terminal queries = %d", result.Coverage, terminalQueries.Load())
	}
}

func TestCollectResolvesMXAndNSDependenciesWithoutWebsiteCandidates(t *testing.T) {
	var mu sync.Mutex
	calls := make(map[model.DNSQuestion]int)
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		mu.Lock()
		calls[question]++
		mu.Unlock()
		result := model.DNSResult{Question: question, ResponseCode: 0}
		value, rrtype := "", ""
		switch question.Type {
		case typeMX:
			if question.Name == "example.com" {
				value, rrtype = "10 mail.provider.test", "MX"
			}
		case typeNS:
			if question.Name == "example.com" {
				value, rrtype = "ns.provider.test", "NS"
			}
		case typeA:
			if question.Name == "mail.provider.test" || question.Name == "ns.provider.test" {
				result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
			}
		}
		if rrtype != "" {
			payload, _ := json.Marshal(model.DNSPayload{RRType: rrtype, Owner: question.Name, Value: value})
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	var published []netip.Addr
	result := collector.Collect(t.Context(), "example.com", 443, func(candidate Candidate) { published = append(published, candidate.Address) })
	if len(published) != 0 || result.Coverage.Status != model.CoverageComplete {
		t.Fatalf("published = %v, coverage = %#v", published, result.Coverage)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"mail.provider.test", "ns.provider.test"} {
		for _, questionType := range []uint16{typeA, typeAAAA} {
			if calls[model.DNSQuestion{Name: name, Type: questionType}] != 1 {
				t.Fatalf("missing dependency question %s type %d", name, questionType)
			}
		}
	}
	var mail, dns int
	for _, observation := range result.Observations {
		if observation.Type != "dns_address" {
			continue
		}
		switch observation.Scope {
		case model.ScopeMailDependency:
			mail++
		case model.ScopeDNSDependency:
			dns++
		}
	}
	if mail != 1 || dns != 1 {
		t.Fatalf("dependency address scopes: mail=%d dns=%d", mail, dns)
	}
}

func TestCollectDiscoversInheritedNSWithoutInheritingParentMailOrTXT(t *testing.T) {
	var mu sync.Mutex
	calls := make(map[model.DNSQuestion]int)
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		mu.Lock()
		calls[question]++
		mu.Unlock()
		result := model.DNSResult{Question: question, ResponseCode: 0}
		value, rrtype := "", ""
		switch {
		case question.Name == "example.com" && question.Type == typeSOA:
			value, rrtype = "ns1.example.com", "SOA"
		case question.Name == "example.com" && question.Type == typeNS:
			value, rrtype = "ns1.example.com", "NS"
		case question.Name == "ns1.example.com" && question.Type == typeA:
			result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
		if rrtype != "" {
			payload, _ := json.Marshal(model.DNSPayload{RRType: rrtype, Owner: question.Name, Value: value, TTL: 300})
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	result := collector.Collect(t.Context(), "www.example.com", 443, nil)
	if result.Coverage.Status != model.CoverageComplete {
		t.Fatalf("DNS coverage = %#v", result.Coverage)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, question := range []model.DNSQuestion{
		{Name: "www.example.com", Type: typeSOA},
		{Name: "example.com", Type: typeSOA},
		{Name: "example.com", Type: typeNS},
		{Name: "ns1.example.com", Type: typeA},
		{Name: "ns1.example.com", Type: typeAAAA},
	} {
		if calls[question] != 1 {
			t.Fatalf("question %v ran %d times", question, calls[question])
		}
	}
	for question := range calls {
		if question.Name == "example.com" && (question.Type == typeMX || question.Type == typeTXT) {
			t.Fatalf("inherited parent mail or TXT query: %v", question)
		}
	}
	var inherited, dependency bool
	for _, observation := range result.Observations {
		if observation.Type == "dns_record" && observation.Subject == "example.com" && observation.Scope == model.ScopeInheritedZone {
			inherited = true
		}
		if observation.Type == "dns_address" && observation.Subject == "ns1.example.com" && observation.Scope == model.ScopeDNSDependency {
			dependency = true
		}
	}
	if !inherited || !dependency {
		t.Fatalf("inherited NS and dependency address not retained: %#v", result.Observations)
	}
}

func TestCollectDoesNotPublishAddressesFromFailedDNSResponse(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("93.184.216.34")
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		return model.DNSResult{Question: question, ResponseCode: 2, Addresses: []netip.Addr{address}}, nil
	}, policy.PublicDestinationPolicy())
	published := 0
	result := collector.Collect(t.Context(), "example.com", 443, func(Candidate) { published++ })
	if published != 0 || len(result.Addresses) != 0 {
		t.Fatalf("published = %d, addresses = %v", published, result.Addresses)
	}
}

func TestCollectPublishesEachApprovedAddressOnce(t *testing.T) {
	t.Parallel()

	address := netip.MustParseAddr("93.184.216.34")
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		if question.Type != typeA {
			return model.DNSResult{Question: question, ResponseCode: 0}, nil
		}
		return model.DNSResult{Question: question, ResponseCode: 0, Addresses: []netip.Addr{address, address}}, nil
	}, policy.PublicDestinationPolicy())
	published := 0
	collector.Collect(t.Context(), "example.com", 443, func(Candidate) { published++ })
	if published != 1 {
		t.Fatalf("published candidates = %d, want 1", published)
	}
}

func TestCollectBoundsResolvedAddressesAcrossQuestions(t *testing.T) {
	limits := policy.DefaultLimits()
	limits.ResolvedAddresses = 1
	controller, err := policy.NewController(limits, 1, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question}
		if question.Type == typeNS {
			return fixtureNSResult(question, "ns.provider.test"), nil
		}
		if question.Name == "example.com" && question.Type == typeA {
			result.Addresses = []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("8.8.8.8"),
			}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(ctx, "example.com", 443, nil)
	if len(result.Addresses) != 1 || result.Coverage.Status != model.CoveragePartial || result.Coverage.Omitted != 1 {
		t.Fatalf("Collect() result = %#v", result)
	}
	if !slices.Contains(result.Coverage.ErrorCodes, model.CodeBudgetExceeded) {
		t.Fatalf("coverage error codes = %v", result.Coverage.ErrorCodes)
	}
}

func TestCollectCountsReportedNetworkAttempts(t *testing.T) {
	t.Parallel()

	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		attempts := 1
		if question.Type == typeA {
			attempts = 2
		}
		return model.DNSResult{Question: question, Attempt: attempts}, nil
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(t.Context(), "example.com", 443, nil)
	if result.Coverage.Attempted != 8 {
		t.Fatalf("coverage attempted = %d, want 8 including SOA discovery", result.Coverage.Attempted)
	}
}

func TestCollectCountsBudgetDeniedQuestionsAsOmitted(t *testing.T) {
	t.Parallel()

	collector := New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		if question.Type == typeA {
			return model.DNSResult{Question: question, Attempt: 1}, nil
		}
		return model.DNSResult{Question: question, Outcome: model.DNSOutcomeBudgetExhausted}, model.NewError(model.CodeBudgetExceeded, "DNS question budget exhausted", nil)
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(t.Context(), "example.com", 443, nil)
	if result.Coverage.Attempted != 1 || result.Coverage.Omitted != len(questionTypes)-1 {
		t.Fatalf("coverage = %#v, want one attempt and %d omitted", result.Coverage, len(questionTypes)-1)
	}
	if !slices.Contains(result.Coverage.ErrorCodes, model.CodeBudgetExceeded) {
		t.Fatalf("coverage error codes = %v, want budget_exceeded", result.Coverage.ErrorCodes)
	}
}

func TestCollectReportsTerminalDeadlineAsTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	var queries atomic.Int64
	collector := New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		queries.Add(1)
		return model.DNSResult{Question: question, Attempt: 1}, ctx.Err()
	}, policy.PublicDestinationPolicy())

	result := collector.Collect(ctx, "example.com", 443, nil)
	if len(result.Observations) != len(questionTypes) || result.Coverage.Attempted != 0 || queries.Load() != 0 {
		t.Fatalf("terminal DNS results = %d observations, %d attempts, %d queries; want one outcome per question and no network attempt", len(result.Observations), result.Coverage.Attempted, queries.Load())
	}
	if !slices.Contains(result.Coverage.ErrorCodes, model.CodeTimeout) {
		t.Fatalf("coverage error codes = %v, want timeout", result.Coverage.ErrorCodes)
	}
	if slices.Contains(result.Coverage.ErrorCodes, model.CodeCancelled) {
		t.Fatalf("coverage error codes = %v, do not want cancelled", result.Coverage.ErrorCodes)
	}
}

func TestErrorCodeDistinguishesTimeoutFromCollectionFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want model.ErrorCode
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: model.CodeTimeout},
		{name: "network timeout", err: timeoutError{}, want: model.CodeTimeout},
		{name: "cancellation", err: context.Canceled, want: model.CodeCancelled},
		{name: "transport failure", err: errors.New("malformed DNS response"), want: model.CodeCollectionFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := errorCode(test.err); got != test.want {
				t.Fatalf("errorCode() = %q, want %q", got, test.want)
			}
		})
	}
}
