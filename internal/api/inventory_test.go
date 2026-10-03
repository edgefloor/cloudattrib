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
	imported       inventory.ImportRequest
	searched       inventory.SearchRequest
	evidenceQuery  inventory.EvidenceQuery
	retrievalQuery inventory.RetrievalRequest
	validated      inventory.ValidationRequest
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
func (fixture *inventoryFixture) SearchEvidence(_ context.Context, query inventory.EvidenceQuery) (inventory.EvidencePage, error) {
	fixture.evidenceQuery = query
	return inventory.EvidencePage{Items: []inventory.EvidenceResult{{Hostname: "api.example.com"}}}, nil
}
func (fixture *inventoryFixture) Retrieve(_ context.Context, query inventory.RetrievalRequest) (inventory.RetrievalPage, error) {
	fixture.retrievalQuery = query
	return inventory.RetrievalPage{Items: []inventory.RetrievalResult{{EvidenceResult: inventory.EvidenceResult{Hostname: "api.example.com"}}}}, nil
}
func (*inventoryFixture) ReadEvidence(context.Context, string, string) (inventory.EvidenceResult, error) {
	return inventory.EvidenceResult{Hostname: "api.example.com", ProjectionStatus: "ready"}, nil
}
func (*inventoryFixture) ProjectionStatus(context.Context) (inventory.ProjectionStatus, error) {
	return inventory.ProjectionStatus{}, nil
}
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

func TestInventoryEvidenceAndValidationHTTPRoutes(t *testing.T) {
	t.Parallel()
	fixture := &inventoryFixture{}
	handler, err := NewHandler(Config{Inventory: fixture, InventoryValidator: fixture})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		input := httptest.NewRequest(method, path, strings.NewReader(body))
		input.RemoteAddr = "127.0.0.1:1000"
		output := httptest.NewRecorder()
		handler.ServeHTTP(output, input)
		return output
	}
	search := request(http.MethodGet, "/v1/inventory/evidence?text=portal&scope=example.com&context=unknown&limit=10", "")
	if search.Code != http.StatusOK || fixture.evidenceQuery.Text != "portal" || fixture.evidenceQuery.ContextID != "unknown" || fixture.evidenceQuery.Limit != 10 {
		t.Fatalf("evidence search = %d %s %#v", search.Code, search.Body.String(), fixture.evidenceQuery)
	}
	retrieval := request(http.MethodPost, "/v1/inventory/retrieve", `{"text":"customer sign in","mode":"hybrid","scope_root":"example.com","context_id":"unknown","limit":10}`)
	if retrieval.Code != http.StatusOK || fixture.retrievalQuery.Text != "customer sign in" || fixture.retrievalQuery.Mode != inventory.RetrievalHybrid || fixture.retrievalQuery.ContextID != "unknown" || !strings.Contains(retrieval.Body.String(), "api.example.com") {
		t.Fatalf("retrieval = %d %s %#v", retrieval.Code, retrieval.Body.String(), fixture.retrievalQuery)
	}
	read := request(http.MethodGet, "/v1/inventory/api.example.com/evidence?context=unknown", "")
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"projection_status":"ready"`) {
		t.Fatalf("evidence read = %d %s", read.Code, read.Body.String())
	}
	status := request(http.MethodGet, "/v1/inventory/projection-status", "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"pending":0`) {
		t.Fatalf("projection status = %d %s", status.Code, status.Body.String())
	}
	validation := request(http.MethodPost, "/v1/inventory/validate", `{"idempotency_key":"validation-1","mode":"dns","asset_ids":["asset-1"]}`)
	if validation.Code != http.StatusAccepted || fixture.validated.IdempotencyKey != "validation-1" || len(fixture.validated.AssetIDs) != 1 {
		t.Fatalf("validation = %d %s %#v", validation.Code, validation.Body.String(), fixture.validated)
	}
}
