package runtime

import (
	"context"
	"time"

	"cloudattrib/internal/config"
	"cloudattrib/internal/retention"
)

// RunReportRetention previews or deletes one bounded page of expired reports.
// It runs only when an operator invokes the maintenance command.
func RunReportRetention(ctx context.Context, configuration config.Config, request retention.Request) (retention.Page, error) {
	if request.Cutoff.IsZero() {
		request.Cutoff = time.Now().UTC().Add(-configuration.Storage.ReportRetention)
	}
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return retention.Page{}, err
	}
	defer store.Close()
	return retention.NewService(store).Run(ctx, request)
}
