package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const observationIDVersion = "observation-occurrence-v1"

// ObservationOccurrence identifies one collection event without putting target
// query values or credentials in the resulting observation ID.
type ObservationOccurrence struct {
	CollectionRunID string `json:"collection_run_id"`
	Seed            string `json:"seed"`
	SeedIndex       int    `json:"seed_index"`
	RequestIndex    int    `json:"request_index"`
	Hop             int    `json:"hop"`
	Attempt         int    `json:"attempt"`
	ItemIndex       int    `json:"item_index"`
}

// NewCollectionRunID returns an opaque identifier for one live collection run.
func NewCollectionRunID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "collection-run-" + hex.EncodeToString(value), nil
}

// ObservationID returns a versioned occurrence ID. Callers may add sanitized
// request attributes such as a URL path. They must not add query values or
// credentials.
func ObservationID(kind string, occurrence ObservationOccurrence, attributes ...string) string {
	payload, _ := json.Marshal(struct {
		Version    string                `json:"version"`
		Kind       string                `json:"kind"`
		Occurrence ObservationOccurrence `json:"occurrence"`
		Attributes []string              `json:"attributes"`
	}{
		Version:    observationIDVersion,
		Kind:       kind,
		Occurrence: occurrence,
		Attributes: attributes,
	})
	sum := sha256.Sum256(payload)
	return kind + "-" + hex.EncodeToString(sum[:12])
}
