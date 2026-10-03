package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"cloudattrib/internal/inventory"
)

func TestInventoryCLIImportAndNDJSONSearch(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	var imported inventory.ImportRequest
	exit := Run(t.Context(), []string{"inventory", "import", "--input", "-", "--scope", "example.com", "--source", "export", "--operation", "op", "--chunk", "1"}, Dependencies{
		Stdin: strings.NewReader("API.Example.Com.\n*.example.com\n"), Stdout: &out, Stderr: &errOut,
		InventoryImport: func(_ context.Context, request inventory.ImportRequest) (inventory.ImportReceipt, error) {
			imported = request
			return inventory.ImportReceipt{OperationID: request.OperationID, ChunkID: request.ChunkID}, nil
		},
	})
	if exit != 0 || imported.OperationID != "op" || len(imported.Entries) != 2 || !strings.Contains(out.String(), `"operation_id":"op"`) {
		t.Fatalf("import exit=%d request=%#v stdout=%q stderr=%q", exit, imported, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	exit = Run(t.Context(), []string{"inventory", "search", "--mode", "partial", "--query", "api", "--format", "ndjson"}, Dependencies{
		Stdout: &out, Stderr: &errOut,
		InventorySearch: func(_ context.Context, request inventory.SearchRequest) (inventory.Page, error) {
			if request.Mode != inventory.SearchPartial || request.Query != "api" {
				t.Fatalf("search request = %#v", request)
			}
			return inventory.Page{Items: []inventory.Asset{{ID: "asset-1", Hostname: "api.example.com"}}, NextCursor: "next"}, nil
		},
	})
	if exit != 0 || !strings.Contains(out.String(), `"api.example.com"`) || !strings.Contains(errOut.String(), "next_cursor=next") {
		t.Fatalf("search exit=%d stdout=%q stderr=%q", exit, out.String(), errOut.String())
	}
}
