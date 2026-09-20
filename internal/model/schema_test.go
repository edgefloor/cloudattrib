package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
