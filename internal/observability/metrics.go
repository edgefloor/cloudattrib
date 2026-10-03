// Package observability defines bounded operational telemetry contracts.
package observability

import (
	"context"
	"time"
)

// Generation identifies a committed activation without exposing its manifest hash.
type Generation struct {
	BundleID    string    `json:"bundle_id"`
	Number      int64     `json:"generation"`
	Action      string    `json:"action,omitempty"`
	ActivatedAt time.Time `json:"activated_at,omitempty"`
}

// ReloadStatus describes this process's latest attempt to load desired state.
type ReloadStatus struct {
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	Failed        bool       `json:"failed"`
}

// GenerationStatus separates durable desired state from process-loaded state.
type GenerationStatus struct {
	Desired *Generation  `json:"desired,omitempty"`
	Loaded  *Generation  `json:"loaded,omitempty"`
	Reload  ReloadStatus `json:"reload"`
}

// Snapshot contains low-cardinality service gauges read from durable state.
type Snapshot struct {
	ReservedTargets              int64
	MaximumTargets               int64
	QueuedTargets                int64
	RunningTargets               int64
	BundlePins                   int64
	ResidentGenerations          int64
	EstimatedRetainedBytes       int64
	CTCheckpoints                int64
	CTIngestionLagSeconds        float64
	UnavailableSources           int64
	OldestSourceAgeSeconds       float64
	ActiveBundleID               string
	Generations                  GenerationStatus
	LoadedUnavailableSources     int64
	LoadedOldestSourceAgeSeconds float64
}

// Provider reads one internally consistent operational snapshot.
type Provider interface {
	OperationalMetrics(context.Context) (Snapshot, error)
}
