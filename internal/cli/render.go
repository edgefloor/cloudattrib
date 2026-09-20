// Package cli renders stable command output and exit codes.
package cli

import (
	"fmt"

	"cloudattrib/internal/model"
)

// RenderReport returns canonical JSON and the report's CLI exit code.
func RenderReport(report model.Report) ([]byte, int, error) {
	encoded, err := report.CanonicalJSON()
	if err != nil {
		return nil, 4, fmt.Errorf("encode report: %w", err)
	}
	switch report.Status {
	case model.StatusComplete:
		return encoded, 0, nil
	case model.StatusPartial, model.StatusFailed, model.StatusCancelled:
		return encoded, 3, nil
	default:
		return nil, 4, model.NewError(model.CodeCapabilityUnavailable, "report has no terminal status", nil)
	}
}
