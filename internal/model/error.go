package model

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable external error identifier.
type ErrorCode string

// ErrorCode values are stable across CLI and HTTP adapters.
const (
	CodeInvalidSyntax          ErrorCode = "invalid_syntax"
	CodeInvalidTarget          ErrorCode = "invalid_target"
	CodeInvalidOptions         ErrorCode = "invalid_options"
	CodeInputTooLarge          ErrorCode = "input_too_large"
	CodePolicyBlocked          ErrorCode = "policy_blocked"
	CodeTimeout                ErrorCode = "timeout"
	CodeBudgetExceeded         ErrorCode = "budget_exceeded"
	CodeSourceUnavailable      ErrorCode = "source_unavailable"
	CodeCapabilityUnavailable  ErrorCode = "capability_unavailable"
	CodeBundleUnavailable      ErrorCode = "bundle_unavailable"
	CodeBundleIncompatible     ErrorCode = "bundle_incompatible"
	CodeQueueCapacityExceeded  ErrorCode = "queue_capacity_exceeded"
	CodeIdempotencyConflict    ErrorCode = "idempotency_conflict"
	CodePersistenceUnavailable ErrorCode = "persistence_unavailable"
	CodePersistenceFailed      ErrorCode = "persistence_failed"
	CodeCollectionFailed       ErrorCode = "collection_failed"
	CodeCancelled              ErrorCode = "cancelled"
	CodeLimitExceeded          ErrorCode = "limit_exceeded"
)

// AppError carries a stable code without exposing its cause to external users.
type AppError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

// NewError constructs a typed application error.
func NewError(code ErrorCode, message string, cause error) *AppError {
	return &AppError{Code: code, Message: message, Cause: cause}
}

// Error implements error.
func (e *AppError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

// Unwrap returns the internal cause for errors.Is and errors.As.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ErrorCodeOf extracts a stable code, or an empty code for an untyped error.
func ErrorCodeOf(err error) ErrorCode {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return ""
}

// HTTPStatus maps an application error to its synchronous HTTP contract.
func HTTPStatus(err error) int {
	switch ErrorCodeOf(err) {
	case CodeInvalidSyntax:
		return 400
	case CodeInvalidTarget, CodeInvalidOptions:
		return 422
	case CodeInputTooLarge:
		return 413
	case CodeIdempotencyConflict:
		return 409
	case CodeQueueCapacityExceeded:
		return 429
	case CodeCapabilityUnavailable, CodeBundleUnavailable, CodeBundleIncompatible,
		CodePersistenceUnavailable, CodePersistenceFailed:
		return 503
	case CodeBudgetExceeded, CodeCollectionFailed, CodeCancelled:
		return 200
	default:
		return 500
	}
}

// CLIExit maps an application error to the command exit contract.
func CLIExit(err error) int {
	switch ErrorCodeOf(err) {
	case CodeInvalidSyntax, CodeInvalidTarget, CodeInvalidOptions, CodeInputTooLarge,
		CodeIdempotencyConflict, CodeQueueCapacityExceeded:
		return 2
	case CodeBudgetExceeded, CodeCollectionFailed, CodeCancelled:
		return 3
	case CodeCapabilityUnavailable, CodeBundleUnavailable, CodeBundleIncompatible,
		CodePersistenceUnavailable, CodePersistenceFailed:
		return 4
	default:
		return 4
	}
}

// WrapError adds operation context while preserving a typed cause.
func WrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
