package model

// ExecutionSummary contains the facts needed to apply SPEC section 14.2.
type ExecutionSummary struct {
	UsablePath          bool
	UsefulEvidence      bool
	CompletedSearch     bool
	RequestedIncomplete bool
	CollectionFailed    bool
	Cancelled           bool
}

// ExecutionDecision maps execution facts to report and interface outcomes.
type ExecutionDecision struct {
	Status     ReportStatus `json:"status,omitempty"`
	ErrorCode  ErrorCode    `json:"error_code,omitempty"`
	HTTPStatus int          `json:"http_status"`
	CLIExit    int          `json:"cli_exit"`
}

// DecideExecution applies the cross-interface result status contract.
func DecideExecution(summary ExecutionSummary) ExecutionDecision {
	switch {
	case summary.Cancelled:
		return ExecutionDecision{Status: StatusCancelled, ErrorCode: CodeCancelled, HTTPStatus: 200, CLIExit: 3}
	case !summary.UsablePath:
		return ExecutionDecision{ErrorCode: CodeCapabilityUnavailable, HTTPStatus: 503, CLIExit: 4}
	case summary.CollectionFailed && !summary.UsefulEvidence && !summary.CompletedSearch:
		return ExecutionDecision{Status: StatusFailed, ErrorCode: CodeCollectionFailed, HTTPStatus: 200, CLIExit: 3}
	case summary.RequestedIncomplete:
		return ExecutionDecision{Status: StatusPartial, HTTPStatus: 200, CLIExit: 3}
	default:
		return ExecutionDecision{Status: StatusComplete, HTTPStatus: 200, CLIExit: 0}
	}
}
