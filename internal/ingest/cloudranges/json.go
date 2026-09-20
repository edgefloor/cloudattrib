// Package cloudranges imports disposable/cloud-ip-ranges provider documents.
package cloudranges

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// maxJSONBytes accommodates the largest audited provider document while keeping
// every importer below the repository's 64 MiB artifact boundary.
const maxJSONBytes = 16 << 20

// DecodeStrict rejects ambiguous JSON before decoding it into destination.
func DecodeStrict(data []byte, destination any) error {
	if len(data) == 0 {
		return fmt.Errorf("empty JSON input")
	}
	if len(data) > maxJSONBytes {
		return fmt.Errorf("JSON input exceeds %d byte limit", maxJSONBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON input is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON input contains trailing document")
		}
		return fmt.Errorf("JSON input has trailing content: %w", err)
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read JSON token: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("read object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			keys[key] = struct{}{}
			if err := checkJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("close JSON object: %w", err)
		}
	case '[':
		for decoder.More() {
			if err := checkJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("close JSON array: %w", err)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
