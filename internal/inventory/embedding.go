package inventory

import (
	"context"
	"encoding/hex"
	"math"
	"strings"
	"time"

	"cloudattrib/internal/model"
)

// Embedder computes vectors locally for bounded retained descriptions.
// Implementations must honor context cancellation and perform no query logging.
type Embedder interface {
	Embed(context.Context, string) ([]float32, error)
}

// EmbeddingGeneration fixes the complete local model and text-input contract.
// Its ID is never reused with changed fields or vectors.
type EmbeddingGeneration struct {
	ID                    string `json:"generation_id"`
	ModelID               string `json:"model_id"`
	ModelRevision         string `json:"model_revision"`
	ArtifactSHA256        string `json:"artifact_sha256"`
	License               string `json:"license"`
	Dimensions            int    `json:"dimensions"`
	DocumentFormatVersion string `json:"document_format_version"`
	Preprocessing         string `json:"preprocessing"`
	QueryPrefix           string `json:"query_prefix"`
	DocumentPrefix        string `json:"document_prefix"`
	Metric                string `json:"metric"`
}

// EmbeddingCoverage measures current vectors against eligible descriptions.
type EmbeddingCoverage struct {
	GenerationID  string     `json:"generation_id"`
	Status        string     `json:"status,omitempty"`
	RollbackUntil *time.Time `json:"rollback_until,omitempty"`
	Eligible      int64      `json:"eligible"`
	Current       int64      `json:"current"`
	Failed        int64      `json:"failed"`
	Pending       int64      `json:"pending"`
}

// ValidateEmbeddingGeneration rejects incomplete and ambiguous model contracts.
func ValidateEmbeddingGeneration(g EmbeddingGeneration) error {
	if !SafeGenerationID(g.ID) {
		return model.NewError(model.CodeInvalidOptions, "embedding generation ID must be a safe local identifier", nil)
	}
	for _, value := range []string{g.ID, g.ModelID, g.ModelRevision, g.License, g.Preprocessing} {
		if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
			return model.NewError(model.CodeInvalidOptions, "embedding generation identity and model fields are required and bounded", nil)
		}
	}
	if len(g.ArtifactSHA256) != 64 {
		return model.NewError(model.CodeInvalidOptions, "embedding model artifact requires a SHA-256 digest", nil)
	}
	if _, err := hex.DecodeString(g.ArtifactSHA256); err != nil || strings.ToLower(g.ArtifactSHA256) != g.ArtifactSHA256 {
		return model.NewError(model.CodeInvalidOptions, "embedding model artifact digest must be lowercase hexadecimal", err)
	}
	if g.Dimensions < 1 || g.Dimensions > 2000 || g.DocumentFormatVersion != DescriptionFormatVersion || g.Metric != "cosine" {
		return model.NewError(model.CodeInvalidOptions, "embedding dimensions, description format, or distance metric are unsupported", nil)
	}
	for _, value := range []string{g.QueryPrefix, g.DocumentPrefix} {
		if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return model.NewError(model.CodeInvalidOptions, "embedding input prefix is invalid", nil)
		}
	}
	return nil
}

// SafeGenerationID can be used as one socket basename without path traversal.
func SafeGenerationID(id string) bool {
	if id == "" || len(id) > 128 || id == "." || id == ".." {
		return false
	}
	for _, character := range id {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// ValidateEmbedding rejects invalid cosine vectors before database publication.
func ValidateEmbedding(vector []float32, dimensions int) error {
	if dimensions < 1 || dimensions > 2000 || len(vector) != dimensions {
		return model.NewError(model.CodeInvalidOptions, "embedding has wrong dimensions", nil)
	}
	var squaredNorm float64
	for _, coordinate := range vector {
		if math.IsNaN(float64(coordinate)) || math.IsInf(float64(coordinate), 0) {
			return model.NewError(model.CodeInvalidOptions, "embedding contains a non-finite coordinate", nil)
		}
		squaredNorm += float64(coordinate) * float64(coordinate)
	}
	if squaredNorm == 0 || math.IsInf(squaredNorm, 0) {
		return model.NewError(model.CodeInvalidOptions, "embedding has zero or invalid norm", nil)
	}
	return nil
}
