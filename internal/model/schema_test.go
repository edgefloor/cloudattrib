package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
