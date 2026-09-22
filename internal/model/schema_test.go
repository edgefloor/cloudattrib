package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

func TestSchemaFilesAreValidJSON(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("../../schema")
	if err != nil {
		t.Fatalf("read schema directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()
			data, readErr := os.ReadFile(filepath.Join("../../schema", entry.Name()))
			if readErr != nil {
				t.Fatalf("read schema: %v", readErr)
			}
			var schema map[string]any
			if decodeErr := json.Unmarshal(data, &schema); decodeErr != nil {
				t.Fatalf("decode schema: %v", decodeErr)
			}
			if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
				t.Fatalf("$schema = %v", schema["$schema"])
			}
		})
	}
}

func TestFindingSchemaProviderIDContract(t *testing.T) {
	t.Parallel()

	schema := compileJSONSchema(t, "finding.schema.json")
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{
			name:  "provider finding",
			input: `{"id":"finding-1","subject":"example.com","provider_id":"aws","relation":"web_delivery","strength":"strong","evidence_ids":["evidence-1"]}`,
			valid: true,
		},
		{
			name:  "technology-only finding omits provider",
			input: `{"id":"finding-1","subject":"example.com","product_id":"webtech.react","category":"web_technology","relation":"web_integration","strength":"moderate","evidence_ids":["evidence-1"]}`,
			valid: true,
		},
		{
			name:  "empty provider",
			input: `{"id":"finding-1","subject":"example.com","provider_id":"","product_id":"webtech.react","category":"web_technology","relation":"web_integration","strength":"moderate","evidence_ids":["evidence-1"]}`,
		},
		{
			name:  "null provider",
			input: `{"id":"finding-1","subject":"example.com","provider_id":null,"product_id":"webtech.react","category":"web_technology","relation":"web_integration","strength":"moderate","evidence_ids":["evidence-1"]}`,
		},
		{
			name:  "missing provider and product",
			input: `{"id":"finding-1","subject":"example.com","category":"web_technology","relation":"web_integration","strength":"moderate","evidence_ids":["evidence-1"]}`,
		},
		{
			name:  "missing provider with another category",
			input: `{"id":"finding-1","subject":"example.com","product_id":"webtech.react","category":"framework","relation":"web_integration","strength":"moderate","evidence_ids":["evidence-1"]}`,
		},
		{
			name:  "missing provider with another relation",
			input: `{"id":"finding-1","subject":"example.com","product_id":"webtech.react","category":"web_technology","relation":"web_delivery","strength":"moderate","evidence_ids":["evidence-1"]}`,
		},
		{
			name:  "empty evidence IDs",
			input: `{"id":"finding-1","subject":"example.com","provider_id":"aws","relation":"web_delivery","strength":"strong","evidence_ids":[]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var input any
			if err := json.Unmarshal([]byte(test.input), &input); err != nil {
				t.Fatalf("decode input: %v", err)
			}
			err := schema.Validate(input)
			if test.valid && err != nil {
				t.Fatalf("expected valid finding: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected invalid finding")
			}
		})
	}
}

func TestCanonicalTechnologyReportMatchesSchema(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)
	report := Report{
		SchemaVersion:    SchemaVersion,
		ContentIDVersion: ReportContentIDVersion,
		ID:               "report-1",
		Target:           Target{Original: "example.com", Canonical: "example.com", Kind: TargetDomain},
		Mode:             ModeFull,
		StartedAt:        now,
		EndedAt:          now,
		ClassifiedAt:     now,
		BundleID:         "bundle-1",
		BuildID:          "build-1",
		Provenance: &ReportProvenance{
			Collection: CollectionProvenance{
				Build:             BuildProvenance{Revision: KnownProvenance("revision-1"), Dirty: BuildClean},
				PolicyRevision:    KnownProvenance("policy-1"),
				FingerprintDigest: KnownProvenance("sha256:fingerprints"),
			},
			Classification: ClassificationProvenance{
				Build:       BuildProvenance{Revision: KnownProvenance("revision-1"), Dirty: BuildClean},
				RulesDigest: KnownProvenance("sha256:rules"),
			},
		},
		Status: StatusPartial,
		Evidence: []Evidence{{
			ID: "evidence-1", ClassifiedAt: now, DetectorID: "wappalyzergo-v0.3.2", Subject: "example.com",
			ProductID: "webtech.react", Category: "web_technology", Relation: RelationWebIntegration, Strength: StrengthModerate,
		}},
		Findings: []Finding{{
			ID: "finding-1", Subject: "example.com", ProductID: "webtech.react", Category: "web_technology",
			Relation: RelationWebIntegration, Strength: StrengthModerate, EvidenceIDs: []string{"evidence-1"},
		}},
	}
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	var document any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if err := compileJSONSchema(t, "report.schema.json").Validate(document); err != nil {
		t.Fatalf("canonical report does not match schema: %v\n%s", err, encoded)
	}
	withoutProvenance := document.(map[string]any)
	delete(withoutProvenance, "provenance")
	if err := compileJSONSchema(t, "report.schema.json").Validate(withoutProvenance); err == nil {
		t.Fatal("content ID version 2 report without provenance matched schema")
	}
}

func compileJSONSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()

	compiler := jsonschema.NewCompiler()
	entries, err := os.ReadDir("../../schema")
	if err != nil {
		t.Fatalf("read schema directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../schema", entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("decode %s: %v", entry.Name(), err)
		}
		identifier := "https://cloudattrib.local/schema/" + entry.Name()
		if err := compiler.AddResource(identifier, document); err != nil {
			t.Fatalf("add %s: %v", entry.Name(), err)
		}
	}
	schema, err := compiler.Compile("https://cloudattrib.local/schema/" + name)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return schema
}

func TestOpenAPIParsesAndLocalReferencesExist(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../schema/openapi.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI document: %v", err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse OpenAPI document: %v", err)
	}
	if document["openapi"] != "3.1.0" {
		t.Fatalf("OpenAPI version = %v", document["openapi"])
	}
	paths, ok := document["paths"].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI paths = %#v", document["paths"])
	}
	for _, required := range []string{"/v1/analyze", "/v1/lookup/ip", "/v1/jobs", "/readyz", "/metrics"} {
		if _, exists := paths[required]; !exists {
			t.Errorf("OpenAPI document is missing %s", required)
		}
	}
	checkLocalOpenAPIRefs(t, document)
}

func checkLocalOpenAPIRefs(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok {
					t.Errorf("OpenAPI reference = %#v", child)
					continue
				}
				if strings.HasPrefix(reference, "#") {
					continue
				}
				path := strings.SplitN(reference, "#", 2)[0]
				if _, err := os.Stat(filepath.Join("../../schema", path)); err != nil {
					t.Errorf("OpenAPI reference %q: %v", reference, err)
				}
			}
			checkLocalOpenAPIRefs(t, child)
		}
	case []any:
		for _, child := range typed {
			checkLocalOpenAPIRefs(t, child)
		}
	}
}
