package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

type inventoryFixture struct {
	imported  inventory.ImportRequest
	searched  inventory.SearchRequest
	validated inventory.ValidationRequest
}

func (fixture *inventoryFixture) Import(_ context.Context, request inventory.ImportRequest) (inventory.ImportReceipt, error) {
	fixture.imported = request
	return inventory.ImportReceipt{OperationID: request.OperationID, ChunkID: request.ChunkID}, nil
}
func (fixture *inventoryFixture) Search(_ context.Context, request inventory.SearchRequest) (inventory.Page, error) {
	fixture.searched = request
	return inventory.Page{Items: []inventory.Asset{{ID: "asset-1", Hostname: "api.example.com"}}, NextCursor: "next"}, nil
}
func (*inventoryFixture) Read(_ context.Context, name string) (inventory.Asset, error) {
	return inventory.Asset{Hostname: name}, nil
}
func (*inventoryFixture) Archive(_ context.Context, name string, _ bool) (inventory.Asset, error) {
	return inventory.Asset{Hostname: name}, nil
}
func (*inventoryFixture) Delete(context.Context, string, bool) (int64, error) { return 2, nil }
func (fixture *inventoryFixture) Validate(_ context.Context, operatorID string, request inventory.ValidationRequest) (jobs.Job, error) {
	fixture.validated = request
	if operatorID == "" {
		return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "operator is required", nil)
	}
	return jobs.Job{ID: "validation-job"}, nil
}

func TestInventoryHTTPRoutes(t *testing.T) {
	t.Parallel()
	fixture := &inventoryFixture{}
	handler, err := NewHandler(Config{Inventory: fixture})
	if err != nil {
		t.Fatal(err)
	}
	importBody := []byte(`{"operation_id":"op","chunk_id":"1","source_id":"export","scope_roots":["example.com"],"entries":[{"hostname":"api.example.com"}]}`)
	importRequest := httptest.NewRequest(http.MethodPost, "/v1/inventory/import", bytes.NewReader(importBody))
	importRequest.RemoteAddr = "127.0.0.1:1000"
	importResponse := httptest.NewRecorder()
	handler.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusOK || fixture.imported.OperationID != "op" {
		t.Fatalf("import = %d %s %#v", importResponse.Code, importResponse.Body.String(), fixture.imported)
	}
	searchResponse := httptest.NewRecorder()
	searchRequest := httptest.NewRequest(http.MethodGet, "/v1/inventory?mode=partial&query=api&limit=1&format=ndjson", nil)
	searchRequest.RemoteAddr = "127.0.0.1:1000"
	handler.ServeHTTP(searchResponse, searchRequest)
	if searchResponse.Code != http.StatusOK || searchResponse.Header().Get("X-Next-Cursor") != "next" || !strings.Contains(searchResponse.Body.String(), `"api.example.com"`) || fixture.searched.Mode != inventory.SearchPartial {
		t.Fatalf("search = %d %s %#v", searchResponse.Code, searchResponse.Body.String(), fixture.searched)
	}
	badResponse := httptest.NewRecorder()
	badRequest := httptest.NewRequest(http.MethodGet, "/v1/inventory?limit=0&limit=1", nil)
	badRequest.RemoteAddr = "127.0.0.1:1000"
	handler.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate query status = %d", badResponse.Code)
	}
	deleteResponse := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/inventory/api.example.com?suppress=true", nil)
	deleteRequest.RemoteAddr = "127.0.0.1:1000"
	handler.ServeHTTP(deleteResponse, deleteRequest)
	var deletion struct {
		Generation int64 `json:"deletion_generation"`
	}
	if deleteResponse.Code != http.StatusOK || json.Unmarshal(deleteResponse.Body.Bytes(), &deletion) != nil || deletion.Generation != 2 {
		t.Fatalf("delete = %d %s", deleteResponse.Code, deleteResponse.Body.String())
	}
}

func TestInventoryHTTPValidationSchedulesExplicitJob(t *testing.T) {
	t.Parallel()
	fixture := &inventoryFixture{}
	handler, err := NewHandler(Config{Inventory: fixture, InventoryValidator: fixture})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/inventory/validate", strings.NewReader(`{"idempotency_key":"check-1","mode":"dns","asset_ids":["asset-1"]}`))
	request.RemoteAddr = "127.0.0.1:1000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || fixture.validated.IdempotencyKey != "check-1" || len(fixture.validated.AssetIDs) != 1 {
		t.Fatalf("validation = %d %s %#v", response.Code, response.Body.String(), fixture.validated)
	}
}
