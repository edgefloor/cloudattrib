package model

import (
	"errors"
	"testing"
)

func TestErrorCodeMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code       ErrorCode
		httpStatus int
		cliExit    int
	}{
		{CodeInvalidSyntax, 400, 2},
		{CodeInvalidTarget, 422, 2},
		{CodeInputTooLarge, 413, 2},
		{CodeQueueCapacityExceeded, 429, 2},
		{CodeIdempotencyConflict, 409, 2},
		{CodeCapabilityUnavailable, 503, 4},
		{CodeBundleUnavailable, 503, 4},
		{CodeBundleIncompatible, 503, 4},
		{CodePersistenceUnavailable, 503, 4},
		{CodePersistenceFailed, 503, 4},
		{CodeBudgetExceeded, 200, 3},
		{CodeCollectionFailed, 200, 3},
		{CodeCancelled, 200, 3},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			t.Parallel()
			err := NewError(tt.code, "operation failed", errors.New("cause"))
			if got := HTTPStatus(err); got != tt.httpStatus {
				t.Fatalf("HTTPStatus() = %d, want %d", got, tt.httpStatus)
			}
			if got := CLIExit(err); got != tt.cliExit {
				t.Fatalf("CLIExit() = %d, want %d", got, tt.cliExit)
			}
			if !errors.Is(err, err.Cause) {
				t.Fatal("NewError() does not unwrap cause")
			}
		})
	}
}
