package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"cloudattrib/internal/model"
)

func BenchmarkDefaultRulesDetect(b *testing.B) {
	engine, err := Default()
	if err != nil {
		b.Fatal(err)
	}
	observations := []model.Observation{
		dnsObservation("CNAME", "d111111abcdef8.cloudfront.net", model.ScopeRoot),
		dnsObservation("NS", "ada.ns.cloudflare.com", model.ScopeRoot),
		dnsObservation("MX", "1 aspmx.l.google.com", model.ScopeRoot),
		dnsObservation("TXT", "v=spf1 include:_spf.google.com ~all", model.ScopeRoot),
		httpObservation(nil, []string{"https://cdn.segment.com/analytics.js/v1/key/analytics.min.js"}, model.ScopeRoot),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		engine.Detect(context.Background(), observations, model.AttributionView{})
	}
}

func TestDefaultRulesCoverProductRelationshipMatrix(t *testing.T) {
	t.Parallel()

	engine, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	tests := []struct {
		name        string
		observation model.Observation
		provider    string
		product     string
		relation    model.Relation
	}{
		{name: "cloudfront", observation: dnsObservation("CNAME", "d111111abcdef8.cloudfront.net", model.ScopeRoot), provider: "aws", product: "aws.cloudfront", relation: model.RelationWebDelivery},
		{name: "elastic load balancing", observation: dnsObservation("CNAME", "app-123456.us-east-1.elb.amazonaws.com", model.ScopeRoot), provider: "aws", product: "aws.elb", relation: model.RelationWebDelivery},
		{name: "s3 website", observation: dnsObservation("CNAME", "bucket.s3-website.eu-west-1.amazonaws.com", model.ScopeRoot), provider: "aws", product: "aws.s3", relation: model.RelationWebDelivery},
		{name: "route 53", observation: dnsObservation("NS", "ns-123.awsdns-45.net", model.ScopeRoot), provider: "aws", product: "aws.route53", relation: model.RelationAuthoritativeDNS},
		{name: "azure app service", observation: dnsObservation("CNAME", "app.azurewebsites.net", model.ScopeRoot), provider: "microsoft", product: "azure.app-service", relation: model.RelationWebDelivery},
		{name: "azure blob", observation: dnsObservation("CNAME", "account.blob.core.windows.net", model.ScopeRoot), provider: "microsoft", product: "azure.blob-storage", relation: model.RelationWebDelivery},
		{name: "azure dns", observation: dnsObservation("NS", "ns1-01.azure-dns.com", model.ScopeRoot), provider: "microsoft", product: "azure.dns", relation: model.RelationAuthoritativeDNS},
		{name: "cloudflare dns", observation: dnsObservation("NS", "ada.ns.cloudflare.com", model.ScopeRoot), provider: "cloudflare", product: "cloudflare.dns", relation: model.RelationAuthoritativeDNS},
		{name: "cloudflare delivery", observation: httpObservation(map[string][]string{"server": {"cloudflare"}}, nil, model.ScopeRoot), provider: "cloudflare", product: "cloudflare.cdn", relation: model.RelationWebDelivery},
		{name: "fastly", observation: dnsObservation("CNAME", "customer.global.fastly.net", model.ScopeRoot), provider: "fastly", product: "fastly.cdn", relation: model.RelationWebDelivery},
		{name: "vercel", observation: dnsObservation("CNAME", "cname.vercel-dns.com", model.ScopeRoot), provider: "vercel", product: "vercel.platform", relation: model.RelationWebDelivery},
		{name: "netlify", observation: dnsObservation("CNAME", "site.netlify.app", model.ScopeRoot), provider: "netlify", product: "netlify.platform", relation: model.RelationWebDelivery},
		{name: "google mail", observation: dnsObservation("MX", "1 aspmx.l.google.com", model.ScopeRoot), provider: "google", product: "google.workspace-mail", relation: model.RelationMailRouting},
		{name: "microsoft mail", observation: dnsObservation("MX", "0 tenant.mail.protection.outlook.com", model.ScopeRoot), provider: "microsoft", product: "microsoft.exchange-online", relation: model.RelationMailRouting},
		{name: "proofpoint", observation: dnsObservation("MX", "10 mx1-us1.ppe-hosted.com", model.ScopeRoot), provider: "proofpoint", product: "proofpoint.email-protection", relation: model.RelationMailRouting},
		{name: "mimecast", observation: dnsObservation("MX", "10 us-smtp-inbound-1.mimecast.com", model.ScopeRoot), provider: "mimecast", product: "mimecast.email-security", relation: model.RelationMailRouting},
		{name: "google spf", observation: dnsObservation("TXT", "v=spf1 include:_spf.google.com ~all", model.ScopeRoot), provider: "google", product: "google.workspace-mail", relation: model.RelationSendingAuthorization},
		{name: "hubspot", observation: httpObservation(nil, []string{"https://js.hs-scripts.com/123.js"}, model.ScopeRoot), provider: "hubspot", product: "hubspot.tracking", relation: model.RelationWebIntegration},
		{name: "segment", observation: httpObservation(nil, []string{"https://cdn.segment.com/analytics.js/v1/key/analytics.min.js"}, model.ScopeRoot), provider: "segment", product: "segment.analytics", relation: model.RelationWebIntegration},
		{name: "atlassian verification", observation: dnsObservation("TXT", "atlassian-domain-verification=fixture", model.ScopeRoot), provider: "atlassian", product: "atlassian.domain-verification", relation: model.RelationDomainVerification},
		{name: "react", observation: technologyObservation("React"), product: "webtech.react", relation: model.RelationWebIntegration},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence, coverage := engine.Detect(context.Background(), []model.Observation{tt.observation}, model.AttributionView{})
			if coverage[0].Status != model.CoverageComplete {
				t.Fatalf("coverage = %#v", coverage)
			}
			if !hasEvidence(evidence, tt.provider, tt.product, tt.relation) {
				t.Fatalf("evidence = %#v, want %s/%s %s", evidence, tt.provider, tt.product, tt.relation)
			}
		})
	}
}

func TestDefaultRulesRejectUnsupportedConclusions(t *testing.T) {
	t.Parallel()

	engine, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	tests := []struct {
		name        string
		observation model.Observation
		forbidden   string
	}{
		{name: "cloudfront lookalike", observation: dnsObservation("CNAME", "cloudfront.net.evil.example", model.ScopeRoot), forbidden: "aws.cloudfront"},
		{name: "cloudfront missing boundary", observation: dnsObservation("CNAME", "notcloudfront.net", model.ScopeRoot), forbidden: "aws.cloudfront"},
		{name: "cloudfront mail dependency", observation: dnsObservation("CNAME", "d111111abcdef8.cloudfront.net", model.ScopeMailDependency), forbidden: "aws.cloudfront"},
		{name: "cloudflare nameserver is not proxy", observation: dnsObservation("NS", "ada.ns.cloudflare.com", model.ScopeRoot), forbidden: "cloudflare.cdn"},
		{name: "google verification is not workspace", observation: dnsObservation("TXT", "google-site-verification=fixture", model.ScopeRoot), forbidden: "google.workspace-mail"},
		{name: "spf substring is not parsed include", observation: dnsObservation("TXT", "note=include:_spf.google.com", model.ScopeRoot), forbidden: "google.workspace-mail"},
		{name: "external redirect integration", observation: httpObservation(nil, []string{"https://cdn.segment.com/analytics.js"}, model.ScopeExternalRedirect), forbidden: "segment.analytics"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence, _ := engine.Detect(context.Background(), []model.Observation{tt.observation}, model.AttributionView{})
			for _, item := range evidence {
				if item.ProductID == tt.forbidden {
					t.Fatalf("unexpected evidence = %#v", item)
				}
			}
		})
	}
}

func TestSPFIncludeRequiresReachablePositiveMechanism(t *testing.T) {
	t.Parallel()

	engine, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	tests := []struct {
		name  string
		value string
		match bool
	}{
		{name: "implicit positive", value: "v=spf1 include:_spf.google.com -all", match: true},
		{name: "explicit positive", value: "v=spf1 +include:_spf.google.com -all", match: true},
		{name: "case and terminal dot", value: "V=SPF1 +INCLUDE:_SPF.GOOGLE.COM. -ALL", match: true},
		{name: "negative", value: "v=spf1 -include:_spf.google.com -all"},
		{name: "neutral", value: "v=spf1 ?include:_spf.google.com -all"},
		{name: "softfail", value: "v=spf1 ~include:_spf.google.com -all"},
		{name: "repeated qualifier", value: "v=spf1 --include:_spf.google.com -all"},
		{name: "other repeated qualifier", value: "v=spf1 +~include:_spf.google.com -all"},
		{name: "missing domain", value: "v=spf1 include: -all"},
		{name: "unknown mechanism invalidates record", value: "v=spf1 madeup:x include:_spf.google.com -all"},
		{name: "empty modifier invalidates record", value: "v=spf1 include:_spf.google.com redirect="},
		{name: "empty unknown modifier is valid", value: "v=spf1 x= include:_spf.google.com -all", match: true},
		{name: "invalid macro in unknown modifier invalidates record", value: "v=spf1 x=%{c} include:_spf.google.com -all"},
		{name: "zero transformer in unknown modifier invalidates record", value: "v=spf1 x=%{l0} include:_spf.google.com -all"},
		{name: "qualified modifier is invalid", value: "v=spf1 include:_spf.google.com +redirect=example.com"},
		{name: "duplicate redirect invalidates record", value: "v=spf1 include:_spf.google.com redirect=one.example.com redirect=two.example.com -all"},
		{name: "duplicate exp invalidates record", value: "v=spf1 include:_spf.google.com exp=one.example.com exp=two.example.com -all"},
		{name: "duplicate redirect after all invalidates record", value: "v=spf1 include:_spf.google.com -all redirect=one.example.com redirect=two.example.com"},
		{name: "duplicate exp after all invalidates record", value: "v=spf1 include:_spf.google.com -all exp=one.example.com exp=two.example.com"},
		{name: "invalid IPv4 mechanism invalidates record", value: "v=spf1 ip4:not-an-address include:_spf.google.com -all"},
		{name: "invalid IPv4 CIDR length invalidates record", value: "v=spf1 ip4:192.0.2.1/33 include:_spf.google.com -all"},
		{name: "invalid IPv6 mechanism invalidates record", value: "v=spf1 ip6:not-an-address include:_spf.google.com -all"},
		{name: "invalid IPv6 CIDR length invalidates record", value: "v=spf1 ip6:2001:db8::1/129 include:_spf.google.com -all"},
		{name: "invalid single-slash dual CIDR invalidates record", value: "v=spf1 a/24/64 include:_spf.google.com -all"},
		{name: "invalid a domain spec invalidates record", value: "v=spf1 a:??? include:_spf.google.com -all"},
		{name: "invalid mx domain spec invalidates record", value: "v=spf1 mx:??? include:_spf.google.com -all"},
		{name: "invalid ptr domain spec invalidates record", value: "v=spf1 ptr:??? include:_spf.google.com -all"},
		{name: "invalid exists domain spec invalidates record", value: "v=spf1 exists:??? include:_spf.google.com -all"},
		{name: "invalid include domain spec invalidates record", value: "v=spf1 include:??? include:_spf.google.com -all"},
		{name: "valid IPv4 mechanism", value: "v=spf1 ip4:192.0.2.1/24 include:_spf.google.com -all", match: true},
		{name: "valid IPv6 mechanism", value: "v=spf1 ip6:2001:db8::1/64 include:_spf.google.com -all", match: true},
		{name: "valid IPv6-only dual CIDR", value: "v=spf1 a//64 mx:mail.example.com//64 include:_spf.google.com -all", match: true},
		{name: "valid IPv4 and IPv6 dual CIDR", value: "v=spf1 a:mail.example.com/24//64 mx:mail.example.com/24//64 ptr:mail.example.com exists:%{l}.example.com include:_spf.google.com -all", match: true},
		{name: "valid macro include", value: "v=spf1 include:%{d}.example.com include:_spf.google.com -all", match: true},
		{name: "valid macro delimiter", value: "v=spf1 exists:%{l=}.example.com include:_spf.google.com -all", match: true},
		{name: "valid slash macro delimiter in a", value: "v=spf1 a:%{l/}.example.com include:_spf.google.com -all", match: true},
		{name: "valid slash macro delimiter in mx", value: "v=spf1 mx:%{l/}.example.com include:_spf.google.com -all", match: true},
		{name: "valid slash macro delimiter before dual CIDR", value: "v=spf1 a:%{l/}.example.com/24//64 include:_spf.google.com -all", match: true},
		{name: "valid repeated dot macro delimiter", value: "v=spf1 exists:%{l..}.example.com include:_spf.google.com -all", match: true},
		{name: "valid address-family macro", value: "v=spf1 exists:%{ir}.%{v}.example.com include:_spf.google.com -all", match: true},
		{name: "valid macro literal punctuation", value: "v=spf1 exists:mail+tag.example.com include:_spf.google.com -all", match: true},
		{name: "valid truncatable domain", value: "v=spf1 exists:" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + ".example include:_spf.google.com -all", match: true},
		{name: "exp-only c macro invalidates domain argument", value: "v=spf1 exists:%{c}.example.com include:_spf.google.com -all"},
		{name: "exp-only r macro invalidates domain argument", value: "v=spf1 exists:%{r}.example.com include:_spf.google.com -all"},
		{name: "exp-only t macro invalidates domain argument", value: "v=spf1 exists:%{t}.example.com include:_spf.google.com -all"},
		{name: "zero transformer invalidates domain argument", value: "v=spf1 exists:%{l0}.example.com include:_spf.google.com -all"},
		{name: "numeric top label invalidates domain argument", value: "v=spf1 exists:mail.example.123 include:_spf.google.com -all"},
		{name: "underscore top label invalidates domain argument", value: "v=spf1 exists:mail.example._bad include:_spf.google.com -all"},
		{name: "lookalike domain", value: "v=spf1 include:_spf.google.com.evil.example -all"},
		{name: "after negative all", value: "v=spf1 -all include:_spf.google.com"},
		{name: "after positive all", value: "v=spf1 +all include:_spf.google.com"},
		{name: "malformed after all is unreachable", value: "v=spf1 -all --include:_spf.google.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			evidence, _ := engine.Detect(context.Background(), []model.Observation{
				dnsObservation("TXT", tt.value, model.ScopeRoot),
			}, model.AttributionView{})
			got := hasEvidence(evidence, "google", "google.workspace-mail", model.RelationSendingAuthorization)
			if got != tt.match {
				t.Fatalf("sending authorization match = %t, want %t; evidence = %#v", got, tt.match, evidence)
			}
			if tt.match {
				for _, item := range evidence {
					if item.ProductID != "google.workspace-mail" || item.Relation != model.RelationSendingAuthorization {
						continue
					}
					if item.Activity != model.ActivityConfigured || len(item.ObservationIDs) != 1 || item.ObservationIDs[0] != "TXT-observation" {
						t.Fatalf("SPF evidence contract = %#v", item)
					}
					if !strings.Contains(item.Explanation, "sender-specific authorization was not evaluated") {
						t.Fatalf("SPF explanation = %q", item.Explanation)
					}
				}
			}
		})
	}
}

func TestGoogleWorkspaceMXCurrentAndLegacyValues(t *testing.T) {
	t.Parallel()

	engine, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	tests := []struct {
		name  string
		value string
		match bool
	}{
		{name: "current", value: "1 smtp.google.com", match: true},
		{name: "current case and terminal dot", value: "1 SMTP.GOOGLE.COM.", match: true},
		{name: "legacy apex", value: "1 aspmx.l.google.com", match: true},
		{name: "legacy alternate", value: "5 alt4.aspmx.l.google.com.", match: true},
		{name: "current lookalike", value: "1 smtp.google.com.evil.example"},
		{name: "missing boundary", value: "1 notsmtp.google.com"},
		{name: "unrelated Google host", value: "1 mail.google.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			evidence, _ := engine.Detect(context.Background(), []model.Observation{
				dnsObservation("MX", tt.value, model.ScopeRoot),
			}, model.AttributionView{})
			got := hasEvidence(evidence, "google", "google.workspace-mail", model.RelationMailRouting)
			if got != tt.match {
				t.Fatalf("mail routing match = %t, want %t; evidence = %#v", got, tt.match, evidence)
			}
		})
	}
}

func TestDefaultRulesKeepMultiVendorRelationshipsSeparate(t *testing.T) {
	t.Parallel()

	engine, err := Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	observations := []model.Observation{
		dnsObservation("NS", "ada.ns.cloudflare.com", model.ScopeRoot),
		dnsObservation("CNAME", "d111111abcdef8.cloudfront.net", model.ScopeRoot),
		dnsObservation("MX", "1 aspmx.l.google.com", model.ScopeRoot),
		httpObservation(nil, []string{"https://cdn.segment.com/analytics.js/v1/key/analytics.min.js"}, model.ScopeRoot),
	}
	evidence, coverage := engine.Detect(context.Background(), observations, model.AttributionView{})
	if coverage[0].Status != model.CoverageComplete {
		t.Fatalf("coverage = %#v", coverage)
	}
	for _, expected := range []struct {
		provider string
		product  string
		relation model.Relation
	}{
		{"cloudflare", "cloudflare.dns", model.RelationAuthoritativeDNS},
		{"aws", "aws.cloudfront", model.RelationWebDelivery},
		{"google", "google.workspace-mail", model.RelationMailRouting},
		{"segment", "segment.analytics", model.RelationWebIntegration},
	} {
		if !hasEvidence(evidence, expected.provider, expected.product, expected.relation) {
			t.Fatalf("evidence = %#v, missing %#v", evidence, expected)
		}
	}
}

func TestLoadRejectsUnknownProductAndUnanchoredRegex(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		`{"schema_version":1,"providers":[],"products":[],"rules":[{"id":"bad.product","signal":"dns","rrtype":"CNAME","field":"rdata.target","match":{"exact":"x.example"},"emit":{"product_id":"missing","relation":"web_delivery","strength":"strong","activity":"configured"},"source_refs":["fixture"],"reviewed_at":"2026-09-20"}]}`,
		`{"schema_version":1,"providers":[{"id":"p"}],"products":[{"id":"p.x","provider_id":"p","relations":["web_delivery"]}],"rules":[{"id":"bad.regex","signal":"dns","rrtype":"CNAME","field":"rdata.target","match":{"regex":"x.*"},"emit":{"provider_id":"p","product_id":"p.x","relation":"web_delivery","strength":"strong","activity":"configured"},"source_refs":["fixture"],"reviewed_at":"2026-09-20"}]}`,
		`{"schema_version":1,"providers":[{"id":"p"}],"products":[{"id":"p.x","provider_id":"p","relations":["web_delivery"]}],"rules":[{"id":"bad.http-op","signal":"http","field":"url","match":{"exact":"https://example.com"},"emit":{"provider_id":"p","product_id":"p.x","category":"hosting","relation":"web_delivery","strength":"strong","activity":"configured"},"source_refs":["fixture"],"reviewed_at":"2026-09-20"}]}`,
	} {
		if _, err := Load([]byte(input)); err == nil {
			t.Fatalf("Load(%s) succeeded, want error", input)
		}
	}
}

func dnsObservation(rrtype, value string, scope model.Scope) model.Observation {
	payload, _ := json.Marshal(model.DNSPayload{RRType: rrtype, Owner: "example.com", Value: value})
	return model.Observation{ID: rrtype + "-observation", Type: "dns_record", Subject: "example.com", Scope: scope, Status: "answered", Payload: payload}
}

func httpObservation(headers map[string][]string, scripts []string, scope model.Scope) model.Observation {
	retained := make([]model.HTTPHeader, 0, len(headers))
	for name, values := range headers {
		retained = append(retained, model.HTTPHeader{Name: name, Values: values})
	}
	payload, _ := json.Marshal(model.HTTPPayload{URL: "https://example.com/", Headers: retained, ScriptURLs: scripts})
	return model.Observation{ID: "http-observation", Type: "http_response", Subject: "example.com", Scope: scope, Status: "responded", Payload: payload}
}

func technologyObservation(name string) model.Observation {
	payload, _ := json.Marshal(model.TechnologyPayload{Name: name, DetectorID: "fixture"})
	return model.Observation{ID: "technology-observation", Type: "technology", Subject: "example.com", Scope: model.ScopeRoot, Status: "detected", Payload: payload}
}

func hasEvidence(evidence []model.Evidence, provider, product string, relation model.Relation) bool {
	for _, item := range evidence {
		if item.ProviderID == provider && item.ProductID == product && item.Relation == relation {
			return true
		}
	}
	return false
}
