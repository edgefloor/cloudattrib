package jobs

import (
	"cloudattrib/internal/model"
	"cloudattrib/internal/target"
)

// ValidateAnalyzeRequest checks target syntax and operation compatibility before admission.
func ValidateAnalyzeRequest(request model.AnalyzeRequest) error {
	normalized, err := target.Normalize(request)
	if err != nil {
		return err
	}
	if normalized.Target.Kind == model.TargetIP {
		return model.NewError(model.CodeInvalidOptions, "use local IP lookup for an IP target", nil)
	}
	return nil
}

// ValidationReason is the stable terminal reason stored for an invalid batch row.
func ValidationReason(err error) string {
	if err == nil {
		return ""
	}
	return "validation failed: " + err.Error()
}
