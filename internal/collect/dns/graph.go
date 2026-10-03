package dns

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

type cnameTarget struct {
	name  string
	depth int
	path  []string
}

// followCNAMEGraph retains each discovered link and resolves terminal addresses
// while the seed queries continue. The caller owns and closes targets.
func (c *Collector) followCNAMEGraph(ctx context.Context, job *Job, seed string, port uint16, occurrence model.ObservationOccurrence, onCandidate func(Candidate), collected *Result, published map[netip.Addr]struct{}, targets <-chan cnameTarget) int {
	queue := make([]cnameTarget, 0)
	seen := make(map[string]struct{})
	requestIndex := len(questionTypes)
	inputOpen := true
	depthLimit := c.limits.CNAMEChainDepth
	if depthLimit <= 0 {
		depthLimit = policy.DefaultLimits().CNAMEChainDepth
	}
	for len(queue) > 0 || inputOpen {
		if err := ctx.Err(); err != nil {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted += len(queue)
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(err))
			return requestIndex
		}
		if len(queue) == 0 {
			select {
			case target, ok := <-targets:
				if !ok {
					inputOpen = false
					continue
				}
				queue = append(queue, target)
			case <-ctx.Done():
				collected.Coverage.Status = model.CoveragePartial
				collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(ctx.Err()))
				return requestIndex
			}
		}
		if inputOpen {
			select {
			case target, ok := <-targets:
				if ok {
					queue = append(queue, target)
				} else {
					inputOpen = false
				}
			default:
			}
		}
		slices.SortFunc(queue, func(a, b cnameTarget) int { return strings.Compare(a.name, b.name) })
		item := queue[0]
		queue = queue[1:]
		if slices.Contains(item.path, item.name) || item.depth > depthLimit {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted++
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeBudgetExceeded)
			collected.Coverage.Reason = "CNAME loop or chain depth limit reached"
			continue
		}
		if _, repeated := seen[item.name]; repeated {
			continue
		}
		seen[item.name] = struct{}{}
		query := model.DNSQuestion{Name: item.name, Type: typeCNAME}
		result, err, observedAt, fromCache := job.query(ctx, query)
		linkOccurrence := occurrence
		linkOccurrence.RequestIndex = requestIndex
		linkOccurrence.Hop = item.depth
		requestIndex++
		c.appendGraphQuery(ctx, collected, seed, port, model.ScopeCNAME, linkOccurrence, result, err, observedAt, fromCache, onCandidate, published)
		if err != nil {
			continue
		}
		outcome := normalizeOutcome(result, err)
		if outcome != model.DNSOutcomeAnswered && outcome != model.DNSOutcomeNoData {
			continue
		}
		var next []string
		for _, record := range result.Records {
			if target := cnameDestination(record); target != "" {
				next = append(next, target)
			}
		}
		if len(next) > 0 {
			slices.Sort(next)
			for _, target := range next {
				queue = append(queue, cnameTarget{name: target, depth: item.depth + 1, path: append(slices.Clone(item.path), item.name)})
			}
			continue
		}
		for _, questionType := range []uint16{typeA, typeAAAA} {
			query := model.DNSQuestion{Name: item.name, Type: questionType}
			result, err, observedAt, fromCache := job.query(ctx, query)
			addressOccurrence := occurrence
			addressOccurrence.RequestIndex = requestIndex
			addressOccurrence.Hop = item.depth
			requestIndex++
			c.appendGraphQuery(ctx, collected, seed, port, model.ScopeCNAME, addressOccurrence, result, err, observedAt, fromCache, onCandidate, published)
		}
	}
	return requestIndex
}

func cnameDestination(observation model.Observation) string {
	if observation.Type != "dns_record" || observation.Status != "answered" {
		return ""
	}
	var payload model.DNSPayload
	if json.Unmarshal(observation.Payload, &payload) != nil || !strings.EqualFold(payload.RRType, "CNAME") {
		return ""
	}
	return normalizedGraphName(payload.Value)
}

func normalizedGraphName(value string) string {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return name
}

// followInheritedZone finds the nearest SOA owner before using its NS records.
// A parent's MX and TXT records are never queried through this path.
func (c *Collector) followInheritedZone(ctx context.Context, job *Job, seed string, port uint16, occurrence model.ObservationOccurrence, requestIndex int, collected *Result) int {
	seed = normalizedGraphName(seed)
	if seed == "" {
		return requestIndex
	}
	nsNoData := false
	for _, observation := range collected.Observations {
		var payload model.DNSPayload
		if json.Unmarshal(observation.Payload, &payload) != nil || !strings.EqualFold(payload.RRType, "NS") || normalizedGraphName(payload.Owner) != seed {
			continue
		}
		if observation.Type == "dns_query" && observation.Status == string(model.DNSOutcomeNoData) {
			nsNoData = true
		}
		if observation.Type == "dns_record" && observation.Status == "answered" {
			return requestIndex
		}
	}
	if !nsNoData {
		return requestIndex
	}
	depthLimit := c.limits.CNAMEChainDepth
	if depthLimit <= 0 {
		depthLimit = policy.DefaultLimits().CNAMEChainDepth
	}
	candidate := seed
	for depth := 0; depth < depthLimit && strings.Contains(candidate, "."); depth++ {
		if ctx.Err() != nil {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted++
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(ctx.Err()))
			return requestIndex
		}
		question := model.DNSQuestion{Name: candidate, Type: typeSOA}
		result, err, observedAt, fromCache := job.query(ctx, question)
		itemOccurrence := occurrence
		itemOccurrence.RequestIndex = requestIndex
		requestIndex++
		c.appendGraphQuery(ctx, collected, seed, port, model.ScopeInheritedZone, itemOccurrence, result, err, observedAt, fromCache, nil, nil)
		if err == nil && hasSOARecord(result, candidate) {
			question := model.DNSQuestion{Name: candidate, Type: typeNS}
			result, err, observedAt, fromCache := job.query(ctx, question)
			itemOccurrence := occurrence
			itemOccurrence.RequestIndex = requestIndex
			requestIndex++
			c.appendGraphQuery(ctx, collected, seed, port, model.ScopeInheritedZone, itemOccurrence, result, err, observedAt, fromCache, nil, nil)
			if err == nil && hasNSRecord(result, candidate) {
				return requestIndex
			}
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted++
			collected.Coverage.Reason = "applicable zone NS records unavailable"
			return requestIndex
		}
		_, parent, found := strings.Cut(candidate, ".")
		if !found {
			break
		}
		candidate = parent
	}
	collected.Coverage.Status = model.CoveragePartial
	collected.Coverage.Omitted++
	collected.Coverage.Reason = "applicable DNS zone could not be established"
	return requestIndex
}

func hasSOARecord(result model.DNSResult, owner string) bool {
	return hasRecord(result, owner, "SOA")
}

func hasNSRecord(result model.DNSResult, owner string) bool {
	return hasRecord(result, owner, "NS")
}

func hasRecord(result model.DNSResult, owner, rrtype string) bool {
	if normalizeOutcome(result, nil) != model.DNSOutcomeAnswered {
		return false
	}
	for _, observation := range result.Records {
		var payload model.DNSPayload
		if json.Unmarshal(observation.Payload, &payload) == nil && strings.EqualFold(payload.RRType, rrtype) && normalizedGraphName(payload.Owner) == owner {
			return true
		}
	}
	return false
}

func (c *Collector) followDependencies(ctx context.Context, job *Job, seed string, port uint16, occurrence model.ObservationOccurrence, requestIndex int, collected *Result) {
	type dependency struct {
		name  string
		scope model.Scope
	}
	var dependencies []dependency
	seen := make(map[dependency]struct{})
	for _, observation := range collected.Observations {
		if observation.Type != "dns_record" || observation.Status != "answered" {
			continue
		}
		var payload model.DNSPayload
		if json.Unmarshal(observation.Payload, &payload) != nil {
			continue
		}
		var target dependency
		switch strings.ToUpper(payload.RRType) {
		case "MX":
			_, host, found := strings.Cut(payload.Value, " ")
			if !found || host == "." {
				continue
			}
			target = dependency{name: normalizedGraphName(host), scope: model.ScopeMailDependency}
		case "NS":
			target = dependency{name: normalizedGraphName(payload.Value), scope: model.ScopeDNSDependency}
		default:
			continue
		}
		if target.name == "" {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted++
			collected.Coverage.Reason = "invalid DNS dependency target"
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		dependencies = append(dependencies, target)
	}
	slices.SortFunc(dependencies, func(a, b dependency) int {
		if cmp := strings.Compare(a.name, b.name); cmp != 0 {
			return cmp
		}
		return strings.Compare(string(a.scope), string(b.scope))
	})
	for _, dependency := range dependencies {
		for _, questionType := range []uint16{typeA, typeAAAA} {
			if err := ctx.Err(); err != nil {
				collected.Coverage.Status = model.CoveragePartial
				collected.Coverage.Omitted++
				collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(err))
				return
			}
			query := model.DNSQuestion{Name: dependency.name, Type: questionType}
			result, err, observedAt, fromCache := job.query(ctx, query)
			itemOccurrence := occurrence
			itemOccurrence.RequestIndex = requestIndex
			requestIndex++
			c.appendGraphQuery(ctx, collected, seed, port, dependency.scope, itemOccurrence, result, err, observedAt, fromCache, nil, nil)
		}
	}
}

func (c *Collector) appendGraphQuery(ctx context.Context, collected *Result, seed string, port uint16, scope model.Scope, occurrence model.ObservationOccurrence, result model.DNSResult, err error, observedAt time.Time, fromCache bool, onCandidate func(Candidate), published map[netip.Addr]struct{}) {
	if !fromCache {
		collected.Coverage.Attempted += result.Attempt
	}
	outcome := normalizeOutcome(result, err)
	if result.Omitted > 0 {
		collected.Coverage.Status = model.CoveragePartial
		collected.Coverage.Omitted += result.Omitted
		collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeBudgetExceeded)
	}
	reason := ""
	if err != nil {
		reason = err.Error()
		collected.Coverage.Status = model.CoveragePartial
		collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, errorCode(err))
		if outcome == model.DNSOutcomeBudgetExhausted {
			collected.Coverage.Omitted++
		}
	} else if dnsOutcomeCompleted(outcome) {
		collected.Coverage.Completed++
	} else {
		collected.Coverage.Status = model.CoveragePartial
		collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeCollectionFailed)
	}
	queryObservation := c.queryObservation(result.Question.Name, result.Question, outcome, result, reason, occurrence, observedAt)
	queryObservation.Scope = scope
	collected.Observations = append(collected.Observations, queryObservation)
	if outcome != model.DNSOutcomeAnswered {
		return
	}
	for index, observation := range result.Records {
		if observation.ObservedAt.IsZero() {
			observation.ObservedAt = observedAt
		}
		recordOccurrence := occurrence
		recordOccurrence.ItemIndex = index
		observation.ID = model.ObservationID("dns-record", recordOccurrence)
		observation.Scope = scope
		collected.Observations = append(collected.Observations, observation)
	}
	for index, address := range result.Addresses {
		address = address.Unmap()
		details := addressRecord(result, index, result.Question.Name, observedAt)
		owner := details.owner
		if !policy.ReserveAddress(ctx) {
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.Omitted++
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodeBudgetExceeded)
			continue
		}
		collected.Addresses = append(collected.Addresses, address)
		decision := c.policy.Check(address, port)
		status := "answered"
		if !decision.Allowed {
			status = "policy_blocked"
			collected.Coverage.Status = model.CoveragePartial
			collected.Coverage.ErrorCodes = append(collected.Coverage.ErrorCodes, model.CodePolicyBlocked)
		}
		addressOccurrence := occurrence
		addressOccurrence.ItemIndex = index
		collected.Observations = append(collected.Observations, model.Observation{
			ID: model.ObservationID("dns-address", addressOccurrence), Type: "dns_address", Subject: owner,
			Scope: scope, ObservedAt: details.observedAt, Status: status,
			Payload: marshalPayload(model.DNSPayload{RRType: details.rrtype, Owner: owner, Address: address, TTL: details.ttl, Section: details.section, PolicyReason: string(decision.Reason)}),
		})
		if decision.Allowed && onCandidate != nil {
			if _, exists := published[address]; !exists {
				published[address] = struct{}{}
				onCandidate(Candidate{Hostname: seed, Address: address, Port: port})
			}
		}
	}
}
