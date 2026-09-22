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

// ValidatePersistentAnalyzeRequests rejects a batch before hashing or storage
// when an execution input is not safe for ordinary durable records.
func ValidatePersistentAnalyzeRequests(requests []model.AnalyzeRequest) error {
	for _, request := range requests {
		if err := target.ValidatePersistentInput(request); err != nil {
			return err
		}
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
