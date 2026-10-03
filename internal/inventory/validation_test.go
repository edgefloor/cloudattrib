package inventory

import (
	"context"
	"testing"

	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

type selectedAssets map[string]Asset

func (assets selectedAssets) ReadInventoryByID(_ context.Context, id string) (Asset, error) {
	asset, ok := assets[id]
	if !ok {
		return Asset{}, model.NewError(model.CodeNotFound, "asset not found", nil)
	}
	return asset, nil
}

type recordingJobs struct{ submitted jobs.SubmitRequest }

func (store *recordingJobs) Submit(_ context.Context, request jobs.SubmitRequest) (jobs.Job, error) {
	store.submitted = request
	return jobs.Job{ID: "job-1"}, nil
}

func TestValidationFreezesExplicitAssetsWithoutCTExpansion(t *testing.T) {
	t.Parallel()
	assets := selectedAssets{
		"asset-b": {ID: "asset-b", Hostname: "b.example.com", Scopes: []string{"example.com"}},
		"asset-a": {ID: "asset-a", Hostname: "a.example.com", Scopes: []string{"example.com"}},
	}
	jobsStore := &recordingJobs{}
	validator := NewValidator(NewService(&recordingStore{}), assets, jobsStore)
	job, err := validator.Validate(t.Context(), "operator", ValidationRequest{IdempotencyKey: "key", Mode: model.ModeDNS,
		AssetIDs: []string{"asset-b", "asset-a", "asset-b"}, ScopeRoot: "example.com"})
	if err != nil || job.ID != "job-1" {
		t.Fatalf("validation = %#v, %v", job, err)
	}
	if len(jobsStore.submitted.Targets) != 2 || jobsStore.submitted.Targets[0].Target != "a.example.com" || jobsStore.submitted.Targets[1].Target != "b.example.com" {
		t.Fatalf("frozen targets = %#v", jobsStore.submitted.Targets)
	}
	for _, target := range jobsStore.submitted.Targets {
		if target.CTDiscovery || target.IncludeWWW == nil || *target.IncludeWWW || target.Mode != model.ModeDNS || len(target.ScopeRoots) != 1 || target.ScopeRoots[0] != "example.com" {
			t.Fatalf("validation expanded collection: %#v", target)
		}
	}
}

func TestValidationRejectsUnboundedOrEmptySelection(t *testing.T) {
	t.Parallel()
	store := &recordingStore{searchPage: Page{Items: []Asset{}}}
	jobsStore := &recordingJobs{}
	validator := NewValidator(NewService(store), selectedAssets{}, jobsStore)
	_, err := validator.Validate(t.Context(), "operator", ValidationRequest{IdempotencyKey: "key", Mode: model.ModeFull, Selection: &SearchRequest{Mode: SearchBrowse}})
	if model.ErrorCodeOf(err) != model.CodeInvalidOptions || len(jobsStore.submitted.Targets) != 0 {
		t.Fatalf("empty selection = %v", err)
	}
}
