// Package rules loads and evaluates inert, versioned attribution rules.
package rules

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"cloudattrib/internal/model"
)

//go:embed builtin.json
var builtin []byte

// Bundle is the application-owned, executable-free rule format.
type Bundle struct {
	SchemaVersion int        `json:"schema_version"`
	Providers     []Provider `json:"providers"`
	Products      []Product  `json:"products"`
	Rules         []Rule     `json:"rules"`
}

// Provider identifies one canonical provider.
type Provider struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// Product identifies one canonical product and its supported relations.
type Product struct {
	ID         string           `json:"id"`
	ProviderID string           `json:"provider_id,omitempty"`
	Name       string           `json:"name,omitempty"`
	Aliases    []string         `json:"aliases,omitempty"`
	Category   string           `json:"category,omitempty"`
	Relations  []model.Relation `json:"relations"`
}

// Rule maps one bounded local signal to one canonical relationship.
type Rule struct {
	ID         string   `json:"id"`
	Signal     string   `json:"signal"`
	RRType     string   `json:"rrtype,omitempty"`
	Field      string   `json:"field"`
	Match      Match    `json:"match"`
	Emit       Emit     `json:"emit"`
	SourceRefs []string `json:"source_refs"`
	ReviewedAt string   `json:"reviewed_at"`
	compiled   *regexp.Regexp
}

// Match contains exactly one supported, inert matching operation.
type Match struct {
	Exact            string `json:"exact,omitempty"`
	FQDNSuffix       string `json:"fqdn_suffix,omitempty"`
	IncludeApex      bool   `json:"include_apex,omitempty"`
	Regex            string `json:"regex,omitempty"`
	TXTPrefix        string `json:"txt_prefix,omitempty"`
	SPFInclude       string `json:"spf_include,omitempty"`
	HeaderName       string `json:"header_name,omitempty"`
	HeaderContains   string `json:"header_contains,omitempty"`
	ScriptHostSuffix string `json:"script_host_suffix,omitempty"`
	ScriptPathPrefix string `json:"script_path_prefix,omitempty"`
	TechnologyAlias  string `json:"technology_alias,omitempty"`
}

// Emit is the reviewed conclusion produced by one rule match.
type Emit struct {
	ProviderID string         `json:"provider_id,omitempty"`
	ProductID  string         `json:"product_id,omitempty"`
	Category   string         `json:"category"`
	Relation   model.Relation `json:"relation"`
	Strength   model.Strength `json:"strength"`
	Activity   model.Activity `json:"activity"`
	Limitation string         `json:"limitation,omitempty"`
}

// Engine evaluates a validated immutable rule bundle.
type Engine struct {
	rules     []Rule
	providers []Provider
	products  []Product
}

// Default loads the reviewed rules embedded in this detector build.
func Default() (*Engine, error) {
	return Load(builtin)
}

// DefaultCatalog returns caller-owned canonical provider and product entries.
func DefaultCatalog() ([]Provider, []Product, error) {
	engine, err := Default()
	if err != nil {
		return nil, nil, err
	}
	return cloneProviders(engine.providers), cloneProducts(engine.products), nil
}

// Load validates and compiles a rule bundle before it can be activated.
func Load(data []byte) (*Engine, error) {
	var bundle Bundle
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decode rule bundle: %w", err)
	}
	if bundle.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported rule schema version %d", bundle.SchemaVersion)
	}
	providers := make(map[string]struct{}, len(bundle.Providers))
	for _, provider := range bundle.Providers {
		if !validID(provider.ID) {
			return nil, fmt.Errorf("invalid provider ID %q", provider.ID)
		}
		providers[provider.ID] = struct{}{}
	}
	products := make(map[string]Product, len(bundle.Products))
	for _, product := range bundle.Products {
		if !validID(product.ID) {
			return nil, fmt.Errorf("invalid product ID %q", product.ID)
		}
		if product.ProviderID != "" {
			if _, ok := providers[product.ProviderID]; !ok {
				return nil, fmt.Errorf("product %q references unknown provider %q", product.ID, product.ProviderID)
			}
		}
		products[product.ID] = product
	}
	ids := make(map[string]struct{}, len(bundle.Rules))
	for index := range bundle.Rules {
		rule := &bundle.Rules[index]
		if !validID(rule.ID) {
			return nil, fmt.Errorf("invalid rule ID %q", rule.ID)
		}
		if _, duplicate := ids[rule.ID]; duplicate {
			return nil, fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if err := validateRule(rule, providers, products); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
	}
	return &Engine{rules: slices.Clone(bundle.Rules), providers: cloneProviders(bundle.Providers), products: cloneProducts(bundle.Products)}, nil
}

func cloneProviders(input []Provider) []Provider {
	output := slices.Clone(input)
	for index := range output {
		output[index].Aliases = slices.Clone(output[index].Aliases)
	}
	return output
}

func cloneProducts(input []Product) []Product {
	output := slices.Clone(input)
	for index := range output {
		output[index].Aliases = slices.Clone(output[index].Aliases)
		output[index].Relations = slices.Clone(output[index].Relations)
	}
	return output
}

// Detect evaluates existing observations without making requests.
func (e *Engine) Detect(ctx context.Context, observations []model.Observation, _ model.AttributionView) ([]model.Evidence, []model.Coverage) {
	evidence := make([]model.Evidence, 0)
	for _, observation := range observations {
		if err := ctx.Err(); err != nil {
			return evidence, []model.Coverage{{Capability: "rules", Status: model.CoveragePartial, Attempted: len(observations), ErrorCodes: []model.ErrorCode{model.CodeCancelled}}}
		}
		for _, rule := range e.rules {
			matchedField, ok := rule.matches(observation)
			if !ok || !scopeAllows(rule.Emit.Relation, observation.Scope) {
				continue
			}
			evidence = append(evidence, rule.evidence(observation, matchedField))
		}
	}
	slices.SortFunc(evidence, func(a, b model.Evidence) int { return strings.Compare(a.ID, b.ID) })
	return evidence, []model.Coverage{{Capability: "rules", Status: model.CoverageComplete, Attempted: len(observations), Completed: len(observations)}}
}

func validateRule(rule *Rule, providers map[string]struct{}, products map[string]Product) error {
	if rule.Signal != "dns" && rule.Signal != "http" && rule.Signal != "technology" {
		return fmt.Errorf("unsupported signal %q", rule.Signal)
	}
	if rule.Field == "" || len(rule.SourceRefs) == 0 {
		return fmt.Errorf("field and source references are required")
	}
	if _, err := time.Parse("2006-01-02", rule.ReviewedAt); err != nil {
		return fmt.Errorf("invalid review date: %w", err)
	}
	if rule.Emit.ProviderID != "" {
		if _, ok := providers[rule.Emit.ProviderID]; !ok {
			return fmt.Errorf("unknown provider %q", rule.Emit.ProviderID)
		}
	}
	product, ok := products[rule.Emit.ProductID]
	if !ok {
		return fmt.Errorf("unknown product %q", rule.Emit.ProductID)
	}
	if product.ProviderID != rule.Emit.ProviderID {
		return fmt.Errorf("product/provider mismatch")
	}
	if !slices.Contains(product.Relations, rule.Emit.Relation) {
		return fmt.Errorf("product does not support relation %q", rule.Emit.Relation)
	}
	if rule.Emit.Strength != model.StrengthStrong && rule.Emit.Strength != model.StrengthModerate && rule.Emit.Strength != model.StrengthWeak {
		return fmt.Errorf("invalid strength %q", rule.Emit.Strength)
	}
	if rule.Emit.Activity != model.ActivityConfigured && rule.Emit.Activity != model.ActivityResponding && rule.Emit.Activity != model.ActivityVerificationOnly && rule.Emit.Activity != model.ActivityHistorical && rule.Emit.Activity != model.ActivityUnknown {
		return fmt.Errorf("invalid activity %q", rule.Emit.Activity)
	}
	if !validID(rule.Emit.Category) {
		return fmt.Errorf("invalid category %q", rule.Emit.Category)
	}
	operations := 0
	for _, value := range []string{rule.Match.Exact, rule.Match.FQDNSuffix, rule.Match.Regex, rule.Match.TXTPrefix, rule.Match.SPFInclude, rule.Match.HeaderContains, rule.Match.ScriptHostSuffix, rule.Match.TechnologyAlias} {
		if value != "" {
			operations++
		}
	}
	if operations != 1 {
		return fmt.Errorf("exactly one match operation is required")
	}
	if rule.Match.Regex != "" {
		if !strings.HasPrefix(rule.Match.Regex, "^") || !strings.HasSuffix(rule.Match.Regex, "$") {
			return fmt.Errorf("regular expression must be anchored")
		}
		compiled, err := regexp.Compile(rule.Match.Regex)
		if err != nil {
			return fmt.Errorf("compile regular expression: %w", err)
		}
		rule.compiled = compiled
	}
	if rule.Match.HeaderContains != "" && rule.Match.HeaderName == "" {
		return fmt.Errorf("header name is required")
	}
	switch rule.Signal {
	case "dns":
		if rule.RRType == "" || rule.Match.HeaderContains != "" || rule.Match.ScriptHostSuffix != "" || rule.Match.TechnologyAlias != "" {
			return fmt.Errorf("DNS rule has an incompatible operation")
		}
		if (rule.Match.TXTPrefix != "" || rule.Match.SPFInclude != "") && !strings.EqualFold(rule.RRType, "TXT") {
			return fmt.Errorf("TXT operation requires TXT rrtype")
		}
	case "http":
		if rule.RRType != "" || rule.Match.HeaderContains == "" && rule.Match.ScriptHostSuffix == "" {
			return fmt.Errorf("HTTP rule has an incompatible operation")
		}
	case "technology":
		if rule.RRType != "" || rule.Match.TechnologyAlias == "" {
			return fmt.Errorf("technology rule has an incompatible operation")
		}
	}
	return nil
}

func (r Rule) matches(observation model.Observation) (string, bool) {
	switch r.Signal {
	case "dns":
		if observation.Type != "dns_record" {
			return "", false
		}
		var payload model.DNSPayload
		if json.Unmarshal(observation.Payload, &payload) != nil || !strings.EqualFold(payload.RRType, r.RRType) {
			return "", false
		}
		value := payload.Value
		if strings.EqualFold(payload.RRType, "MX") {
			_, value, _ = strings.Cut(value, " ")
		}
		return r.Field, r.matchValue(value)
	case "http":
		if observation.Type != "http_response" {
			return "", false
		}
		var payload model.HTTPPayload
		if json.Unmarshal(observation.Payload, &payload) != nil {
			return "", false
		}
		if r.Match.HeaderContains != "" {
			for _, header := range payload.Headers {
				if strings.EqualFold(header.Name, r.Match.HeaderName) {
					for _, value := range header.Values {
						if strings.Contains(strings.ToLower(value), strings.ToLower(r.Match.HeaderContains)) {
							return "header." + strings.ToLower(r.Match.HeaderName), true
						}
					}
				}
			}
		}
		for _, rawURL := range payload.ScriptURLs {
			parsed, err := url.Parse(rawURL)
			if err == nil && fqdnSuffix(parsed.Hostname(), r.Match.ScriptHostSuffix, true) && (r.Match.ScriptPathPrefix == "" || strings.HasPrefix(parsed.EscapedPath(), r.Match.ScriptPathPrefix)) {
				return "script_url", true
			}
		}
	case "technology":
		if observation.Type != "technology" {
			return "", false
		}
		var payload model.TechnologyPayload
		if json.Unmarshal(observation.Payload, &payload) == nil && strings.EqualFold(payload.Name, r.Match.TechnologyAlias) {
			return "technology.name", true
		}
	}
	return "", false
}

func (r Rule) matchValue(value string) bool {
	value = strings.TrimSpace(value)
	switch {
	case r.Match.Exact != "":
		return strings.EqualFold(strings.TrimSuffix(value, "."), strings.TrimSuffix(r.Match.Exact, "."))
	case r.Match.FQDNSuffix != "":
		return fqdnSuffix(value, r.Match.FQDNSuffix, r.Match.IncludeApex)
	case r.compiled != nil:
		return r.compiled.MatchString(strings.ToLower(strings.TrimSuffix(value, ".")))
	case r.Match.TXTPrefix != "":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(r.Match.TXTPrefix))
	case r.Match.SPFInclude != "":
		return spfIncludes(value, r.Match.SPFInclude)
	}
	return false
}

func (r Rule) evidence(observation model.Observation, matchedField string) model.Evidence {
	sum := sha256.Sum256([]byte(r.ID + "\x00" + observation.ID))
	explanation := "reviewed rule matched " + matchedField
	if r.Match.SPFInclude != "" {
		explanation = "SPF record contains a reachable positive include for " + r.Match.SPFInclude + "; sender-specific authorization was not evaluated"
	}
	return model.Evidence{
		ID:             "evidence-rule-" + hex.EncodeToString(sum[:12]),
		ObservationIDs: []string{observation.ID},
		DetectorID:     "rules-v1",
		RuleID:         r.ID,
		Subject:        observation.Subject,
		ProviderID:     r.Emit.ProviderID,
		ProductID:      r.Emit.ProductID,
		Category:       r.Emit.Category,
		Relation:       r.Emit.Relation,
		Strength:       r.Emit.Strength,
		Activity:       r.Emit.Activity,
		Scope:          observation.Scope,
		Explanation:    explanation,
	}
}

func validID(value string) bool {
	matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9._-]*$`, value)
	return matched
}

func fqdnSuffix(value, suffix string, includeApex bool) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	suffix = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	return (includeApex && value == suffix) || strings.HasSuffix(value, "."+suffix)
}

func spfIncludes(value, expected string) bool {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(value)))
	if len(fields) == 0 || fields[0] != "v=spf1" {
		return false
	}
	expected = strings.ToLower(strings.TrimSuffix(expected, "."))
	matched := false
	for _, term := range fields[1:] {
		if term == "" {
			continue
		}
		qualifier := byte('+')
		hasQualifier := false
		if isSPFQualifier(term[0]) {
			hasQualifier = true
			qualifier = term[0]
			term = term[1:]
			if term == "" || isSPFQualifier(term[0]) {
				return false
			}
		}
		if strings.Contains(term, "=") {
			name, argument, _ := strings.Cut(term, "=")
			if hasQualifier || !validSPFName(name) || argument == "" {
				return false
			}
			if (name == "redirect" || name == "exp") && !validSPFDomainSpec(argument) {
				return false
			}
			continue
		}
		separator := strings.IndexAny(term, ":/")
		mechanism, suffix, hasSuffix := term, "", separator >= 0
		if hasSuffix {
			mechanism, suffix = term[:separator], term[separator:]
		}
		switch mechanism {
		case "all":
			if hasSuffix {
				return false
			}
			return matched
		case "include":
			if !hasSuffix || !strings.HasPrefix(suffix, ":") || !validSPFDomainSpec(suffix[1:]) {
				return false
			}
			domain := strings.TrimSuffix(suffix[1:], ".")
			if qualifier == '+' && domain == expected {
				matched = true
			}
		case "a", "mx":
			if !validSPFDomainCIDR(suffix, hasSuffix) {
				return false
			}
		case "ptr":
			if !validSPFPtr(suffix, hasSuffix) {
				return false
			}
		case "ip4":
			if !hasSuffix || !strings.HasPrefix(suffix, ":") || !validSPFIP(suffix[1:], true) {
				return false
			}
		case "ip6":
			if !hasSuffix || !strings.HasPrefix(suffix, ":") || !validSPFIP(suffix[1:], false) {
				return false
			}
		case "exists":
			if !hasSuffix || !strings.HasPrefix(suffix, ":") || !validSPFDomainSpec(suffix[1:]) {
				return false
			}
		default:
			return false
		}
	}
	return matched
}

func validSPFDomainCIDR(suffix string, hasSuffix bool) bool {
	if !hasSuffix {
		return true
	}
	if strings.HasPrefix(suffix, ":") {
		suffix = suffix[1:]
		if suffix == "" {
			return false
		}
		beforeCIDR, cidr, hasCIDR := strings.Cut(suffix, "/")
		if !validSPFDomainSpec(beforeCIDR) {
			return false
		}
		if !hasCIDR {
			return true
		}
		return validSPFDualCIDR(cidr)
	}
	if !strings.HasPrefix(suffix, "/") {
		return false
	}
	return validSPFDualCIDR(suffix[1:])
}

func validSPFPtr(suffix string, hasSuffix bool) bool {
	return !hasSuffix || (strings.HasPrefix(suffix, ":") && validSPFDomainSpec(suffix[1:]))
}

func validSPFDualCIDR(value string) bool {
	if strings.HasPrefix(value, "/") {
		return validSPFCIDRLength(value[1:], 128)
	}
	ipv4, ipv6, hasIPv6 := strings.Cut(value, "//")
	if !validSPFCIDRLength(ipv4, 32) {
		return false
	}
	return !hasIPv6 || validSPFCIDRLength(ipv6, 128)
}

func validSPFIP(value string, ipv4 bool) bool {
	address, cidr, hasCIDR := strings.Cut(value, "/")
	if address == "" || strings.Contains(cidr, "/") {
		return false
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil || parsed.Is4() != ipv4 {
		return false
	}
	if !hasCIDR {
		return true
	}
	maximum := 128
	if ipv4 {
		maximum = 32
	}
	return validSPFCIDRLength(cidr, maximum)
}

func validSPFCIDRLength(value string, maximum int) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	length, err := strconv.Atoi(value)
	return err == nil && length <= maximum
}

func validSPFDomainSpec(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for index := 0; index < len(value); {
		character := value[index]
		switch {
		case isSPFDomainLiteral(character):
			index++
		case character == '%':
			next, ok := validSPFMacro(value, index)
			if !ok {
				return false
			}
			index = next
		default:
			return false
		}
	}
	return validSPFDomainLabels(value)
}

func isSPFDomainLiteral(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || strings.ContainsRune("-._", rune(value))
}

func validSPFMacro(value string, start int) (int, bool) {
	if start+1 >= len(value) {
		return 0, false
	}
	switch value[start+1] {
	case '%', '_', '-':
		return start + 2, true
	case '{':
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return 0, false
		}
		end += start + 2
		body := value[start+2 : end]
		if body == "" || !strings.ContainsRune("slodiphcrt", rune(body[0])) {
			return 0, false
		}
		index := 1
		for index < len(body) && body[index] >= '0' && body[index] <= '9' {
			index++
		}
		if index < len(body) && body[index] == 'r' {
			index++
		}
		for index < len(body) && strings.ContainsRune(".-+,/_=", rune(body[index])) {
			index++
		}
		return end + 1, index == len(body)
	default:
		return 0, false
	}
}

func validSPFDomainLabels(value string) bool {
	labels := strings.Split(value, ".")
	if labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func isSPFQualifier(value byte) bool {
	return value == '+' || value == '-' || value == '~' || value == '?'
}

func validSPFName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.", character) {
			continue
		}
		return false
	}
	return true
}

func scopeAllows(relation model.Relation, scope model.Scope) bool {
	if scope == model.ScopeExternalRedirect && relation == model.RelationWebIntegration {
		return false
	}
	if scope == model.ScopeMailDependency && relation == model.RelationWebDelivery {
		return false
	}
	return true
}
