package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"cloudattrib/internal/model"
)

// SearchMode selects one indexed hostname lookup.
type SearchMode string

const (
	SearchBrowse     SearchMode = "browse"
	SearchExact      SearchMode = "exact"
	SearchDescendant SearchMode = "descendant"
	SearchPrefix     SearchMode = "prefix"
	SearchPartial    SearchMode = "partial"
)

// SearchRequest describes a bounded search over known names, not live DNS.
type SearchRequest struct {
	Mode            SearchMode `json:"mode"`
	Query           string     `json:"query,omitempty"`
	ScopeRoot       string     `json:"scope_root,omitempty"`
	Limit           int        `json:"limit,omitempty"`
	Cursor          string     `json:"cursor,omitempty"`
	IncludeArchived bool       `json:"include_archived,omitempty"`
}

// Source records compact discovery provenance and distinguishes observation from receipt.
type Source struct {
	Kind            string     `json:"kind"`
	ID              string     `json:"id"`
	Provenance      string     `json:"provenance"`
	Verification    string     `json:"verification"`
	FirstObservedAt *time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt  *time.Time `json:"last_observed_at,omitempty"`
	FirstReceivedAt time.Time  `json:"first_received_at"`
	LastReceivedAt  time.Time  `json:"last_received_at"`
	Reference       string     `json:"reference,omitempty"`
	LogID           string     `json:"log_id,omitempty"`
	EntryIndex      string     `json:"entry_index,omitempty"`
	CheckpointID    string     `json:"checkpoint_id,omitempty"`
}

// Asset is one canonical concrete hostname and its discovery facts.
type Asset struct {
	ID                   string     `json:"id"`
	Hostname             string     `json:"hostname"`
	NormalizationVersion string     `json:"normalization_version"`
	ArchivedAt           *time.Time `json:"archived_at,omitempty"`
	DeletionGeneration   int64      `json:"deletion_generation"`
	Scopes               []string   `json:"scopes"`
	Sources              []Source   `json:"sources"`
}

// Page is a stable keyset page over known names. Concurrent writes can change later pages.
type Page struct {
	Items      []Asset `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

// SearchStore reads bounded pages and individual assets.
type SearchStore interface {
	SearchInventory(context.Context, SearchRequest, string) (Page, error)
	ReadInventory(context.Context, string) (Asset, error)
}

type pageCursor struct {
	Filter string `json:"filter"`
	After  string `json:"after"`
}

// PrepareSearch normalizes filters and rejects invalid cursors before querying storage.
func PrepareSearch(request SearchRequest) (SearchRequest, string, error) {
	if request.Mode == "" {
		request.Mode = SearchBrowse
	}
	switch request.Mode {
	case SearchBrowse, SearchExact, SearchDescendant, SearchPrefix, SearchPartial:
	default:
		return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "unsupported inventory search mode", nil)
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	if request.Limit < 1 || request.Limit > 100 {
		return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "inventory page limit must be between 1 and 100", nil)
	}
	if request.ScopeRoot != "" {
		root, _, err := Normalize(request.ScopeRoot)
		if err != nil {
			return SearchRequest{}, "", err
		}
		request.ScopeRoot = root
	}
	switch request.Mode {
	case SearchExact, SearchDescendant:
		query, _, err := Normalize(request.Query)
		if err != nil {
			return SearchRequest{}, "", err
		}
		request.Query = query
	case SearchPrefix, SearchPartial:
		request.Query = strings.ToLower(strings.TrimSpace(request.Query))
		if len(request.Query) == 0 || len(request.Query) > 253 || strings.ContainsAny(request.Query, "\x00\r\n") {
			return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "invalid inventory search text", nil)
		}
		if request.Mode == SearchPartial && len([]rune(request.Query)) < 3 && request.ScopeRoot == "" {
			return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "unscoped partial search needs at least three characters", nil)
		}
	case SearchBrowse:
		if request.Query != "" {
			return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "browse does not accept search text", nil)
		}
	}
	fingerprint := searchFingerprint(request)
	if request.Cursor == "" {
		return request, "", nil
	}
	if len(request.Cursor) > 1024 {
		return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "invalid inventory cursor", nil)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(request.Cursor)
	if err != nil {
		return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "invalid inventory cursor", err)
	}
	var cursor pageCursor
	if json.Unmarshal(encoded, &cursor) != nil || cursor.Filter != fingerprint || cursor.After == "" || len(cursor.After) > 253 {
		return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "inventory cursor does not match filters", nil)
	}
	hostname, _, err := Normalize(cursor.After)
	if err != nil || hostname != cursor.After {
		return SearchRequest{}, "", model.NewError(model.CodeInvalidOptions, "invalid inventory cursor hostname", err)
	}
	return request, cursor.After, nil
}

// NextCursor binds the last hostname to normalized filters and sort order.
func NextCursor(request SearchRequest, after string) string {
	encoded, _ := json.Marshal(pageCursor{Filter: searchFingerprint(request), After: after})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func searchFingerprint(request SearchRequest) string {
	encoded, _ := json.Marshal(struct {
		Mode     SearchMode
		Query    string
		Scope    string
		Archived bool
	}{request.Mode, request.Query, request.ScopeRoot, request.IncludeArchived})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
