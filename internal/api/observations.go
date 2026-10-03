package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"cloudattrib/internal/model"
)

const observationCursorVersion = 1
const maximumObservationCursorBytes = 1024

type observationCursor struct {
	Version       int        `json:"v"`
	ReportID      string     `json:"report_id"`
	ObservedAt    *time.Time `json:"observed_at"`
	ObservationID string     `json:"observation_id"`
}

func parseObservationCursor(raw, reportID string) (observationCursor, error) {
	if raw == "" {
		return observationCursor{}, nil
	}
	if len(raw) > maximumObservationCursorBytes {
		return observationCursor{}, model.NewError(model.CodeInvalidOptions, "observation cursor is too long", nil)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return observationCursor{}, model.NewError(model.CodeInvalidOptions, "observation cursor is invalid", err)
	}
	if _, err := strconv.Atoi(string(decoded)); err == nil {
		return observationCursor{}, model.NewError(model.CodeInvalidOptions, "legacy observation offset cursor is unsupported; restart pagination", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	var cursor observationCursor
	if err := decoder.Decode(&cursor); err != nil {
		return observationCursor{}, model.NewError(model.CodeInvalidOptions, "observation cursor is invalid", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return observationCursor{}, model.NewError(model.CodeInvalidOptions, "observation cursor has trailing data", err)
	}
	if cursor.Version != observationCursorVersion || cursor.ReportID != reportID || cursor.ObservedAt == nil || cursor.ObservedAt.IsZero() || cursor.ObservationID == "" {
		return observationCursor{}, model.NewError(model.CodeInvalidOptions, "observation cursor does not match this result or version", nil)
	}
	return cursor, nil
}

func encodeObservationCursor(reportID string, observedAt time.Time, observationID string) string {
	encoded, _ := json.Marshal(observationCursor{Version: observationCursorVersion, ReportID: reportID, ObservedAt: &observedAt, ObservationID: observationID})
	return base64.RawURLEncoding.EncodeToString(encoded)
}
