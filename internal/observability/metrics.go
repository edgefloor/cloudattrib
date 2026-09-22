// Package observability defines bounded operational telemetry contracts.
package observability

import "context"

// Snapshot contains low-cardinality service gauges read from durable state.
type Snapshot struct {
	ReservedTargets        int64
	MaximumTargets         int64
	QueuedTargets          int64
	RunningTargets         int64
	BundlePins             int64
	ResidentGenerations    int64
	EstimatedRetainedBytes int64
	CTCheckpoints          int64
	CTIngestionLagSeconds  float64
	UnavailableSources     int64
	OldestSourceAgeSeconds float64
	ActiveBundleID         string
}

// Provider reads one internally consistent operational snapshot.
type Provider interface {
	OperationalMetrics(context.Context) (Snapshot, error)
}
