package rules

import (
	"context"
	"encoding/json"
	"testing"

	"cloudattrib/internal/model"
)

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

func TestLoadRejectsUnknownProductAndUnanchoredRegex(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		`{"schema_version":1,"providers":[],"products":[],"rules":[{"id":"bad.product","signal":"dns","rrtype":"CNAME","field":"rdata.target","match":{"exact":"x.example"},"emit":{"product_id":"missing","relation":"web_delivery","strength":"strong","activity":"configured"},"source_refs":["fixture"],"reviewed_at":"2026-09-20"}]}`,
		`{"schema_version":1,"providers":[{"id":"p"}],"products":[{"id":"p.x","provider_id":"p","relations":["web_delivery"]}],"rules":[{"id":"bad.regex","signal":"dns","rrtype":"CNAME","field":"rdata.target","match":{"regex":"x.*"},"emit":{"provider_id":"p","product_id":"p.x","relation":"web_delivery","strength":"strong","activity":"configured"},"source_refs":["fixture"],"reviewed_at":"2026-09-20"}]}`,
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
