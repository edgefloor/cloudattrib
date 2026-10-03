package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

// InventoryService is the shared application boundary for hostname inventory.
type InventoryService interface {
	Import(context.Context, inventory.ImportRequest) (inventory.ImportReceipt, error)
	Search(context.Context, inventory.SearchRequest) (inventory.Page, error)
	Read(context.Context, string) (inventory.Asset, error)
	Archive(context.Context, string, bool) (inventory.Asset, error)
	Delete(context.Context, string, bool) (int64, error)
}

// InventoryValidator submits frozen asset selections through existing target jobs.
type InventoryValidator interface {
	Validate(context.Context, string, inventory.ValidationRequest) (jobs.Job, error)
}

func (s *server) inventoryRoute(writer http.ResponseWriter, request *http.Request) {
	if s.inventory == nil {
		writeApplicationError(writer, model.NewError(model.CodeCapabilityUnavailable, "inventory is unavailable", nil))
		return
	}
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/inventory/validate":
		if s.inventoryValidator == nil {
			writeApplicationError(writer, model.NewError(model.CodeCapabilityUnavailable, "inventory validation is unavailable", nil))
			return
		}
		var input inventory.ValidationRequest
		if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
			writeRequestError(writer, err)
			return
		}
		job, err := s.inventoryValidator.Validate(request.Context(), OperatorID(request.Context()), input)
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		writeJSON(writer, http.StatusAccepted, job)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/inventory/import":
		var input inventory.ImportRequest
		if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
			writeRequestError(writer, err)
			return
		}
		receipt, err := s.inventory.Import(request.Context(), input)
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, receipt)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/inventory":
		values := request.URL.Query()
		if err := rejectUnknownInventoryQuery(values, "mode", "query", "scope", "limit", "cursor", "include_archived", "format"); err != nil {
			writeApplicationError(writer, err)
			return
		}
		limit := 0
		if raw := values.Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil {
				writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "invalid inventory limit", err))
				return
			}
		}
		archived := false
		if raw := values.Get("include_archived"); raw != "" {
			var err error
			archived, err = strconv.ParseBool(raw)
			if err != nil {
				writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "invalid include_archived value", err))
				return
			}
		}
		page, err := s.inventory.Search(request.Context(), inventory.SearchRequest{
			Mode: inventory.SearchMode(values.Get("mode")), Query: values.Get("query"), ScopeRoot: values.Get("scope"),
			Limit: limit, Cursor: values.Get("cursor"), IncludeArchived: archived,
		})
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		switch values.Get("format") {
		case "", "json":
			writeJSON(writer, http.StatusOK, page)
		case "ndjson":
			writer.Header().Set("Content-Type", "application/x-ndjson")
			if page.NextCursor != "" {
				writer.Header().Set("X-Next-Cursor", page.NextCursor)
			}
			for _, item := range page.Items {
				if err := json.NewEncoder(writer).Encode(item); err != nil {
					return
				}
			}
		default:
			writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "unsupported inventory format", nil))
		}
	case strings.HasPrefix(request.URL.Path, "/v1/inventory/"):
		s.inventoryAssetRoute(writer, request)
	default:
		writeError(writer, http.StatusNotFound, errorEnvelope{Code: model.CodeNotFound, Message: "route not found"})
	}
}

func (s *server) inventoryAssetRoute(writer http.ResponseWriter, request *http.Request) {
	name := strings.TrimPrefix(request.URL.Path, "/v1/inventory/")
	archive := strings.HasSuffix(name, "/archive")
	if archive {
		name = strings.TrimSuffix(name, "/archive")
	}
	if name == "" || strings.Contains(name, "/") {
		writeError(writer, http.StatusNotFound, errorEnvelope{Code: model.CodeNotFound, Message: "route not found"})
		return
	}
	switch {
	case request.Method == http.MethodGet && !archive:
		asset, err := s.inventory.Read(request.Context(), name)
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, asset)
	case request.Method == http.MethodPost && archive:
		var input struct {
			Archived *bool `json:"archived"`
		}
		if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
			writeRequestError(writer, err)
			return
		}
		if input.Archived == nil {
			writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "archived is required", nil))
			return
		}
		asset, err := s.inventory.Archive(request.Context(), name, *input.Archived)
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, asset)
	case request.Method == http.MethodDelete && !archive:
		if err := rejectUnknownInventoryQuery(request.URL.Query(), "suppress"); err != nil {
			writeApplicationError(writer, err)
			return
		}
		suppress := false
		if raw := request.URL.Query().Get("suppress"); raw != "" {
			var err error
			suppress, err = strconv.ParseBool(raw)
			if err != nil {
				writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "invalid suppress value", err))
				return
			}
		}
		generation, err := s.inventory.Delete(request.Context(), name, suppress)
		if err != nil {
			writeApplicationError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			DeletionGeneration int64 `json:"deletion_generation"`
		}{generation})
	default:
		writeError(writer, http.StatusNotFound, errorEnvelope{Code: model.CodeNotFound, Message: "route not found"})
	}
}

func rejectUnknownInventoryQuery(values map[string][]string, allowed ...string) error {
	accepted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		accepted[key] = true
	}
	for key, entries := range values {
		if !accepted[key] || len(entries) != 1 {
			return model.NewError(model.CodeInvalidOptions, "unknown or duplicate inventory query parameter", nil)
		}
	}
	return nil
}
