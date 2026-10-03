package inventory

import (
	"context"
	"slices"
	"time"

	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

// ValidationRequest chooses explicit known assets or one bounded search selection.
// Validation is the only inventory operation here that schedules target collection.
type ValidationRequest struct {
	IdempotencyKey string         `json:"idempotency_key"`
	BundleID       string         `json:"bundle_id,omitempty"`
	Mode           model.Mode     `json:"mode"`
	AssetIDs       []string       `json:"asset_ids,omitempty"`
	Selection      *SearchRequest `json:"selection,omitempty"`
	ScopeRoot      string         `json:"scope_root,omitempty"`
}

// ValidationStore resolves stable asset IDs to current canonical names.
type ValidationStore interface {
	ReadInventoryByID(context.Context, string) (Asset, error)
}

// JobSubmitter is the existing durable target-job admission contract.
type JobSubmitter interface {
	Submit(context.Context, jobs.SubmitRequest) (jobs.Job, error)
}

// Validator freezes inventory names into existing bounded target jobs.
type Validator struct {
	inventory *Service
	assets    ValidationStore
	jobs      JobSubmitter
}

func NewValidator(inventory *Service, assets ValidationStore, jobs JobSubmitter) *Validator {
	return &Validator{inventory: inventory, assets: assets, jobs: jobs}
}

// Validate admits explicit DNS-only or full-analysis work for selected assets.
func (v *Validator) Validate(ctx context.Context, operatorID string, request ValidationRequest) (jobs.Job, error) {
	if v == nil || v.inventory == nil || v.assets == nil || v.jobs == nil {
		return jobs.Job{}, model.NewError(model.CodeCapabilityUnavailable, "inventory validation is unavailable", nil)
	}
	if operatorID == "" || request.IdempotencyKey == "" || (request.Mode != model.ModeDNS && request.Mode != model.ModeFull) ||
		(len(request.AssetIDs) == 0) == (request.Selection == nil) || len(request.AssetIDs) > 1000 {
		return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "validation requires one bounded selection and DNS or full mode", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if request.ScopeRoot != "" {
		root, _, err := Normalize(request.ScopeRoot)
		if err != nil {
			return jobs.Job{}, err
		}
		request.ScopeRoot = root
	}
	assets := make([]Asset, 0, len(request.AssetIDs))
	if request.Selection != nil {
		selection := *request.Selection
		selection.Cursor = ""
		selection.IncludeArchived = false
		selection.Limit = 100
		if request.ScopeRoot != "" {
			selection.ScopeRoot = request.ScopeRoot
		}
		for {
			page, err := v.inventory.Search(ctx, selection)
			if err != nil {
				return jobs.Job{}, err
			}
			assets = append(assets, page.Items...)
			if len(assets) > 1000 || len(assets) == 1000 && page.NextCursor != "" {
				return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "validation selection exceeds 1000 assets", nil)
			}
			if page.NextCursor == "" {
				break
			}
			selection.Cursor = page.NextCursor
		}
	} else {
		for _, id := range request.AssetIDs {
			asset, err := v.assets.ReadInventoryByID(ctx, id)
			if err != nil {
				return jobs.Job{}, err
			}
			if asset.ArchivedAt != nil {
				return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "archived assets need explicit restoration before validation", nil)
			}
			if request.ScopeRoot != "" && !slices.Contains(asset.Scopes, request.ScopeRoot) {
				return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "asset is outside the selected scope", nil)
			}
			assets = append(assets, asset)
		}
	}
	if len(assets) == 0 {
		return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "validation selected no assets", nil)
	}
	slices.SortFunc(assets, func(a, b Asset) int {
		if a.Hostname < b.Hostname {
			return -1
		}
		if a.Hostname > b.Hostname {
			return 1
		}
		return 0
	})
	assets = slices.CompactFunc(assets, func(a, b Asset) bool { return a.ID == b.ID })
	includeWWW := false
	targets := make([]model.AnalyzeRequest, len(assets))
	selections := make([]jobs.InventorySelection, len(assets))
	for index, asset := range assets {
		targets[index] = model.AnalyzeRequest{Target: asset.Hostname, Kind: model.TargetDomain, Mode: request.Mode, IncludeWWW: &includeWWW, CTDiscovery: false}
		selections[index] = jobs.InventorySelection{AssetID: asset.ID, DeletionGeneration: asset.DeletionGeneration}
		if request.ScopeRoot != "" {
			targets[index].ScopeRoots = []string{request.ScopeRoot}
		}
	}
	return v.jobs.Submit(ctx, jobs.SubmitRequest{OperatorID: operatorID, IdempotencyKey: request.IdempotencyKey, BundleID: request.BundleID, Targets: targets, InventorySelections: selections})
}
