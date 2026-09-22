package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"cloudattrib/internal/buildinfo"
	"cloudattrib/internal/detect/webtech"
	"cloudattrib/internal/model"
	"cloudattrib/internal/rules"
)

const detectorBuildID = "classifier-sha256-28d453f22d3a0008b9a35d571bd2d3fe39929ef85383e3912ce56217275a7198"

type runtimeProvenance struct {
	build             model.BuildProvenance
	rulesDigest       model.ProvenanceValue
	fingerprintDigest model.ProvenanceValue
}

func currentRuntimeProvenance() runtimeProvenance {
	information := buildinfo.Current()
	revision := model.UnknownProvenance()
	if information.RevisionKnown {
		revision = model.KnownProvenance(information.Revision)
	}
	dirty := model.BuildDirtyUnknown
	switch information.Dirty {
	case buildinfo.Clean:
		dirty = model.BuildClean
	case buildinfo.Dirty:
		dirty = model.BuildDirty
	}
	return runtimeProvenance{
		build:             model.BuildProvenance{Revision: revision, Dirty: dirty},
		rulesDigest:       model.KnownProvenance(rules.DefaultDigest()),
		fingerprintDigest: model.KnownProvenance(webtech.FingerprintDigest()),
	}
}

func classifierBuildID(engineID, rulesDigest, fingerprintDigest, policyRevision string) string {
	encoded, _ := json.Marshal(struct {
		EngineID          string `json:"engine_id"`
		RulesDigest       string `json:"rules_digest"`
		FingerprintDigest string `json:"fingerprint_digest"`
		PolicyRevision    string `json:"policy_revision"`
	}{
		EngineID:          engineID,
		RulesDigest:       rulesDigest,
		FingerprintDigest: fingerprintDigest,
		PolicyRevision:    policyRevision,
	})
	sum := sha256.Sum256(encoded)
	return "classifier-sha256-" + hex.EncodeToString(sum[:])
}
