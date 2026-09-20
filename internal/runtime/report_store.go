package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	"cloudattrib/internal/model"
)

const maximumStandaloneReportBytes = 64 << 20

type standaloneReportStore struct{}

func (standaloneReportStore) SaveReport(context.Context, model.Report) error {
	return model.NewError(model.CodeCapabilityUnavailable, "standalone report storage is read-only", nil)
}

func (standaloneReportStore) LoadReport(ctx context.Context, path string) (model.Report, error) {
	if err := ctx.Err(); err != nil {
		return model.Report{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return model.Report{}, model.NewError(model.CodePersistenceFailed, "open standalone report", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, maximumStandaloneReportBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return model.Report{}, model.NewError(model.CodePersistenceFailed, "read standalone report", err)
	}
	if len(data) > maximumStandaloneReportBytes {
		return model.Report{}, model.NewError(model.CodeInputTooLarge, "standalone report exceeds 64 MiB", nil)
	}
	var report model.Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&report); err != nil {
		return model.Report{}, model.NewError(model.CodeInvalidSyntax, "decode standalone report", err)
	}
	if report.ID == "" {
		return model.Report{}, model.NewError(model.CodeInvalidSyntax, "standalone report has no report ID", nil)
	}
	if err := report.ValidateReferences(); err != nil {
		return model.Report{}, model.NewError(model.CodeInvalidSyntax, "standalone report references are invalid", err)
	}
	return report, nil
}
