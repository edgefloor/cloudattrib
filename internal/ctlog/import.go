package ctlog

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"cloudattrib/internal/model"
	"cloudattrib/internal/target"
)

// ImportJSONL validates, scope-filters, deduplicates, and atomically stores records.
func ImportJSONL(ctx context.Context, reader io.Reader, roots []string, store Store) (int, error) {
	if store == nil || len(roots) == 0 {
		return 0, model.NewError(model.CodeInvalidOptions, "CT import roots and store are required", nil)
	}
	normalizedRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		normalized, err := normalizeName(root)
		if err != nil {
			return 0, fmt.Errorf("normalize CT root: %w", err)
		}
		normalizedRoots = append(normalizedRoots, normalized)
	}
	slices.Sort(normalizedRoots)
	normalizedRoots = slices.Compact(normalizedRoots)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	records := make([]Record, 0)
	seen := make(map[string]struct{})
	for line := 1; scanner.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var record Record
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return 0, model.NewError(model.CodeInvalidSyntax, fmt.Sprintf("decode CT record at line %d", line), err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				err = fmt.Errorf("multiple JSON values")
			}
			return 0, model.NewError(model.CodeInvalidSyntax, fmt.Sprintf("decode CT record at line %d", line), err)
		}
		switch record.Provenance {
		case ProvenanceVerifiedLog, ProvenanceLogUnverified, ProvenanceImportedUnverified:
			record.Provenance = ProvenanceImportedUnverified
		default:
			return 0, model.NewError(model.CodeInvalidOptions, fmt.Sprintf("CT provenance at line %d is invalid", line), nil)
		}
		if err := normalizeRecord(&record); err != nil {
			return 0, fmt.Errorf("validate CT record at line %d: %w", line, err)
		}
		if !withinRoots(record.Name, normalizedRoots) {
			continue
		}
		key := record.Name + "\x00" + record.CertificateHash
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return 0, model.NewError(model.CodeInputTooLarge, "read CT JSONL", err)
	}
	if err := store.Import(ctx, records); err != nil {
		return 0, err
	}
	return len(records), nil
}

func normalizeRecord(record *Record) error {
	name := strings.TrimSpace(strings.ToLower(record.Name))
	wildcard := strings.HasPrefix(name, "*.")
	if wildcard {
		name = strings.TrimPrefix(name, "*.")
	}
	normalized, err := normalizeName(name)
	if err != nil {
		return err
	}
	record.Name, record.Wildcard = normalized, wildcard || record.Wildcard
	if record.CertificateHash == "" || record.SourceID == "" || record.LoggedAt.IsZero() {
		return model.NewError(model.CodeInvalidOptions, "CT certificate hash, source, and logged time are required", nil)
	}
	if record.NotBefore != nil && record.NotAfter != nil && record.NotBefore.After(*record.NotAfter) {
		return model.NewError(model.CodeInvalidOptions, "CT certificate validity interval is reversed", nil)
	}
	for _, check := range []model.CTVerificationCheck{
		record.Verification.CheckpointSignature, record.Verification.Continuity, record.Verification.EntryInclusion,
	} {
		if check.Procedure == "" || check.ProcedureVersion == "" ||
			(check.Status != model.CTCheckPassed && check.Status != model.CTCheckFailed && check.Status != model.CTCheckNotPerformed) {
			return model.NewError(model.CodeInvalidOptions, "CT verification checks require a valid status, procedure, and version", nil)
		}
	}
	switch record.Provenance {
	case ProvenanceVerifiedLog:
		if record.Verification.CheckpointSignature.Status != model.CTCheckPassed || record.Verification.EntryInclusion.Status != model.CTCheckPassed ||
			(record.Verification.Continuity.Status != model.CTCheckPassed && record.Verification.Continuity.Status != model.CTCheckNotPerformed) {
			return model.NewError(model.CodeInvalidOptions, "verified CT provenance requires authenticated checkpoint and entry inclusion", nil)
		}
	case ProvenanceLogUnverified, ProvenanceImportedUnverified:
	default:
		return model.NewError(model.CodeInvalidOptions, "CT provenance is invalid", nil)
	}
	return nil
}

func normalizeName(name string) (string, error) {
	normalized, err := target.Normalize(model.AnalyzeRequest{Target: name, Kind: model.TargetDomain, Mode: model.ModeDNS})
	if err != nil {
		return "", err
	}
	return normalized.Target.Canonical, nil
}

func withinRoots(name string, roots []string) bool {
	for _, root := range roots {
		if name == root || strings.HasSuffix(name, "."+root) {
			return true
		}
	}
	return false
}
