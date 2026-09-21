package datasets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cloudattrib/internal/enrich/asn"
	"cloudattrib/internal/enrich/prefix"
	"cloudattrib/internal/ingest/aws"
	"cloudattrib/internal/ingest/azure"
	"cloudattrib/internal/ingest/cdndata"
	"cloudattrib/internal/ingest/cloudranges"
	"cloudattrib/internal/ingest/gcp"
	"cloudattrib/internal/ingest/iptoasn"
	"cloudattrib/internal/model"
)

const maximumSourceBytes = 64 << 20

// ErrNoSources means a directory contains no supported local source artifacts.
var ErrNoSources = errors.New("no supported local source artifacts")

// Counts records the normalized rows built from local sources.
type Counts struct {
	PrefixAssociations  int `json:"prefix_associations"`
	ActiveAssociations  int `json:"active_associations"`
	RetiredAssociations int `json:"retired_associations"`
	ServiceAssociations int `json:"service_associations"`
	RegionAssociations  int `json:"region_associations"`
	RoleAssociations    int `json:"role_associations"`
	ASNIntervals        int `json:"asn_intervals"`
	CDNSuffixes         int `json:"cdn_suffixes"`
}

// LoadedBundle is one fully validated immutable local execution bundle.
type LoadedBundle struct {
	Candidate Candidate
	Prefixes  *prefix.Index
	ASN       *asn.Index
	Counts    Counts
	Warnings  []string
}

// LoadSources validates supported files and builds immutable local indexes.
func LoadSources(ctx context.Context, directory, buildID string) (LoadedBundle, error) {
	if directory == "" || buildID == "" {
		return LoadedBundle{}, fmt.Errorf("source directory and build ID are required")
	}
	info, err := os.Stat(directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LoadedBundle{}, ErrNoSources
		}
		return LoadedBundle{}, fmt.Errorf("inspect source directory: %w", err)
	}
	if !info.IsDir() {
		return LoadedBundle{}, fmt.Errorf("source path is not a directory")
	}

	loaded := LoadedBundle{}
	var associations []model.Association
	var intervals []iptoasn.Interval
	var sources []Source
	var artifacts []Artifact
	loadedAny := false

	load := func(filename, sourceID string, parse func([]byte, string, string) (int, *time.Time, error)) error {
		data, artifact, digest, readErr := readSource(directory, filename)
		if errors.Is(readErr, os.ErrNotExist) {
			sources = append(sources, Source{ID: sourceID, Status: model.CoverageUnavailable, Reason: "source file is absent"})
			return nil
		}
		if readErr != nil {
			return readErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		records, publishedAt, parseErr := parse(data, digest, digest)
		if parseErr != nil {
			return fmt.Errorf("validate %s: %w", filename, parseErr)
		}
		loadedAny = true
		artifacts = append(artifacts, artifact)
		sources = append(sources, Source{ID: sourceID, Revision: digest, Digest: digest, Status: model.CoverageComplete, Records: records, PublishedAt: publishedAt})
		return nil
	}

	if err := load("aws-ip-ranges.json", "aws-ip-ranges", func(data []byte, revision, digest string) (int, *time.Time, error) {
		result, parseErr := aws.Parse(data, revision, digest)
		if parseErr != nil {
			return 0, nil, parseErr
		}
		associations = append(associations, result.Associations...)
		loaded.Warnings = append(loaded.Warnings, result.Warnings...)
		return len(result.Associations), parseRFC3339(result.CreateDate), nil
	}); err != nil {
		return LoadedBundle{}, err
	}
	if err := load("gcp-cloud.json", "gcp-cloud-ranges", func(data []byte, revision, digest string) (int, *time.Time, error) {
		result, parseErr := gcp.Parse(data, revision, digest)
		if parseErr != nil {
			return 0, nil, parseErr
		}
		associations = append(associations, result.Associations...)
		loaded.Warnings = append(loaded.Warnings, result.Warnings...)
		return len(result.Associations), parseRFC3339(result.CreationTime), nil
	}); err != nil {
		return LoadedBundle{}, err
	}
	if err := load("azure-service-tags.json", "azure-service-tags", func(data []byte, revision, digest string) (int, *time.Time, error) {
		result, parseErr := azure.Parse(data, revision, digest)
		if parseErr != nil {
			return 0, nil, parseErr
		}
		associations = append(associations, result.Associations...)
		loaded.Warnings = append(loaded.Warnings, result.Warnings...)
		return len(result.Associations), nil, nil
	}); err != nil {
		return LoadedBundle{}, err
	}
	if err := load("cdncheck-sources-data.json", "cdncheck-data", func(data []byte, revision, digest string) (int, *time.Time, error) {
		result, parseErr := cdndata.Parse(data, cdndata.Metadata{Revision: revision, Digest: digest})
		if parseErr != nil {
			return 0, nil, parseErr
		}
		for index, record := range result.CIDRs {
			providerID := normalizedID(record.Provider)
			associations = append(associations, model.Association{
				ID: fmt.Sprintf("cdn:%s:%s:%d", providerID, record.Prefix, index), Prefix: record.Prefix, ProviderID: providerID,
				Service: record.Category, Lifecycle: "active", SourceID: record.SourceID, SourceRevision: record.Revision,
				SourceDigest: record.Digest, RecordRef: record.RecordRef, RecordRefs: []string{record.RecordRef}, ProvenanceGroup: record.ProvenanceGroup,
			})
		}
		loaded.Counts.CDNSuffixes = len(result.Suffixes)
		return len(result.CIDRs) + len(result.Suffixes), nil, nil
	}); err != nil {
		return LoadedBundle{}, err
	}
	for _, input := range []struct {
		filename string
		sourceID string
		v4       bool
	}{{"iptoasn-v4.tsv", "iptoasn-v4", true}, {"iptoasn-v6.tsv", "iptoasn-v6", false}} {
		current := input
		if err := load(current.filename, current.sourceID, func(data []byte, revision, digest string) (int, *time.Time, error) {
			metadata := iptoasn.Metadata{Revision: revision, Digest: digest}
			var parsed []iptoasn.Interval
			var parseErr error
			if current.v4 {
				parsed, parseErr = iptoasn.ParseV4(data, metadata)
			} else {
				parsed, parseErr = iptoasn.ParseV6(data, metadata)
			}
			intervals = append(intervals, parsed...)
			return len(parsed), nil, parseErr
		}); err != nil {
			return LoadedBundle{}, err
		}
	}

	cloudSources, cloudArtifacts, cloudAssociations, warnings, err := loadCloudRanges(ctx, directory)
	if err != nil {
		return LoadedBundle{}, err
	}
	if len(cloudArtifacts) > 0 {
		loadedAny = true
	}
	sources = append(sources, cloudSources...)
	artifacts = append(artifacts, cloudArtifacts...)
	associations = append(associations, cloudAssociations...)
	loaded.Warnings = append(loaded.Warnings, warnings...)
	if !loadedAny {
		return LoadedBundle{}, ErrNoSources
	}

	slices.SortFunc(sources, func(left, right Source) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(artifacts, func(left, right Artifact) int { return strings.Compare(left.Path, right.Path) })
	bundleID, err := contentBundleID(sources, artifacts)
	if err != nil {
		return LoadedBundle{}, err
	}
	capabilities := sourceCapabilities(sources)
	if len(associations) > 0 {
		loaded.Prefixes = prefix.New(associations)
		capabilities = append(capabilities, aggregateCapability("prefix", capabilities, "prefix_source/", "no usable prefix source"))
	} else {
		capabilities = append(capabilities, model.CapabilityState{Name: "prefix", Status: model.CoverageUnavailable, Reason: "no usable prefix source"})
	}
	if len(intervals) > 0 {
		loaded.ASN, err = asn.New(intervals)
		if err != nil {
			return LoadedBundle{}, fmt.Errorf("build ASN index: %w", err)
		}
		capabilities = append(capabilities, aggregateCapability("asn", capabilities, "asn_source/", "no usable ASN source"))
	} else {
		capabilities = append(capabilities, model.CapabilityState{Name: "asn", Status: model.CoverageUnavailable, Reason: "no usable ASN source"})
	}
	loaded.Counts.PrefixAssociations = len(associations)
	for _, association := range associations {
		if association.Lifecycle == "retired" {
			loaded.Counts.RetiredAssociations++
		} else {
			loaded.Counts.ActiveAssociations++
		}
		if association.Service != "" {
			loaded.Counts.ServiceAssociations++
		}
		if association.Region != "" {
			loaded.Counts.RegionAssociations++
		}
		if association.Role != "" {
			loaded.Counts.RoleAssociations++
		}
	}
	loaded.Counts.ASNIntervals = len(intervals)
	loaded.Candidate = Candidate{
		Manifest: Manifest{SchemaVersion: 1, BundleID: bundleID, Sources: sources, Artifacts: artifacts, CompatibleDetectorBuilds: []string{buildID}},
		View:     model.NewAttributionView(bundleID, "public-destination-v1", []string{buildID, "rules-v1", "wappalyzergo-v0.3.2"}, capabilities),
	}
	return loaded, nil
}

func sourceCapabilities(sources []Source) []model.CapabilityState {
	byName := make(map[string]model.CapabilityState)
	for _, source := range sources {
		name := ""
		switch source.ID {
		case "aws-ip-ranges", "gcp-cloud-ranges", "azure-service-tags", "cdncheck-data":
			name = "prefix_source/" + source.ID
		case "iptoasn-v4":
			name = "asn_source/ipv4"
		case "iptoasn-v6":
			name = "asn_source/ipv6"
		case "disposable/cloud-ip-ranges":
			name = "prefix_source/disposable-cloud-ip-ranges"
		default:
			if strings.HasPrefix(source.ID, "disposable/cloud-ip-ranges/") {
				name = "prefix_source/disposable-cloud-ip-ranges"
			}
		}
		if name == "" {
			continue
		}
		state := model.CapabilityState{Name: name, Status: source.Status, Reason: source.Reason}
		if source.PublishedAt != nil {
			age := time.Since(*source.PublishedAt)
			if age < 0 {
				age = 0
			}
			state.SourceAge = &age
		}
		if current, exists := byName[name]; !exists || current.Status != model.CoverageComplete {
			byName[name] = state
		}
	}
	capabilities := make([]model.CapabilityState, 0, len(byName))
	for _, state := range byName {
		capabilities = append(capabilities, state)
	}
	slices.SortFunc(capabilities, func(left, right model.CapabilityState) int { return strings.Compare(left.Name, right.Name) })
	return capabilities
}

func aggregateCapability(name string, capabilities []model.CapabilityState, prefix, unavailableReason string) model.CapabilityState {
	complete, unavailable := 0, 0
	for _, capability := range capabilities {
		if !strings.HasPrefix(capability.Name, prefix) {
			continue
		}
		if capability.Status == model.CoverageComplete {
			complete++
		} else {
			unavailable++
		}
	}
	switch {
	case complete > 0 && unavailable == 0:
		return model.CapabilityState{Name: name, Status: model.CoverageComplete}
	case complete > 0:
		return model.CapabilityState{Name: name, Status: model.CoveragePartial, Reason: "one or more configured sources are unavailable"}
	default:
		return model.CapabilityState{Name: name, Status: model.CoverageUnavailable, Reason: unavailableReason}
	}
}

func readSource(root, relative string) ([]byte, Artifact, string, error) {
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, Artifact{}, "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, Artifact{}, "", fmt.Errorf("source %s is not a regular file", relative)
	}
	if info.Size() <= 0 || info.Size() > maximumSourceBytes {
		return nil, Artifact{}, "", fmt.Errorf("source %s has invalid size", relative)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Artifact{}, "", fmt.Errorf("read source %s: %w", relative, err)
	}
	digestBytes := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	return data, Artifact{Path: filepath.ToSlash(relative), SHA256: digest, Size: int64(len(data))}, digest, nil
}

func loadCloudRanges(ctx context.Context, root string) ([]Source, []Artifact, []model.Association, []string, error) {
	base := filepath.Join(root, "cloudranges")
	if _, err := os.Stat(base); errors.Is(err, os.ErrNotExist) {
		return []Source{{ID: "disposable/cloud-ip-ranges", Status: model.CoverageUnavailable, Reason: "source directory is absent"}}, nil, nil, nil, nil
	} else if err != nil {
		return nil, nil, nil, nil, err
	}
	var sources []Source
	var artifacts []Artifact
	var associations []model.Association
	var warnings []string
	var primaryFiles []string
	companionFiles := make(map[string]struct{})
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(base, path)
		if err != nil || entry.IsDir() {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("cloud range source %s is a symlink", relative)
		}
		if cloudranges.PrimaryFile(relative) {
			primaryFiles = append(primaryFiles, relative)
		} else if strings.HasPrefix(relative, "json/") && strings.HasSuffix(relative, "-details.json") {
			companionFiles[relative] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
	}
	slices.Sort(primaryFiles)
	usedCompanions := make(map[string]struct{})
	for _, relative := range primaryFiles {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
		}
		fullRelative := filepath.ToSlash(filepath.Join("cloudranges", relative))
		data, artifact, digest, err := readSource(root, fullRelative)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
		}
		input := cloudranges.Input{Revision: digest, Digest: digest, Path: relative}
		companionRelative := strings.TrimSuffix(relative, ".json") + "-details.json"
		if _, ok := companionFiles[companionRelative]; ok {
			fullCompanionRelative := filepath.ToSlash(filepath.Join("cloudranges", companionRelative))
			companionData, companionArtifact, companionDigest, err := readSource(root, fullCompanionRelative)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
			}
			input.Companion = &cloudranges.CompanionInput{
				Data: companionData, Revision: companionDigest, Digest: companionDigest, Path: companionRelative,
			}
			artifacts = append(artifacts, companionArtifact)
			usedCompanions[companionRelative] = struct{}{}
		}
		result, err := cloudranges.Parse(data, input)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
		}
		artifacts = append(artifacts, artifact)
		associations = append(associations, result.Associations...)
		warnings = append(warnings, result.Warnings...)
		sources = append(sources, Source{ID: "disposable/cloud-ip-ranges/" + result.ProviderID, Revision: digest, Digest: digest, Status: model.CoverageComplete, Records: len(result.Associations)})
	}
	for relative := range companionFiles {
		if _, ok := usedCompanions[relative]; !ok {
			return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: companion source %s has no primary provider file", relative)
		}
	}
	if len(sources) == 0 {
		sources = append(sources, Source{ID: "disposable/cloud-ip-ranges", Status: model.CoverageUnavailable, Reason: "no primary provider files"})
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load cloud ranges: %w", err)
	}
	return sources, artifacts, associations, warnings, nil
}

func parseRFC3339(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &parsed
}

func normalizedID(value string) string {
	value = strings.ToLower(value)
	value = strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			return character
		}
		return '-'
	}, value)
	return strings.Trim(value, "-")
}

func contentBundleID(sources []Source, artifacts []Artifact) (string, error) {
	encoded, err := json.Marshal(struct {
		Sources   []Source   `json:"sources"`
		Artifacts []Artifact `json:"artifacts"`
	}{Sources: sources, Artifacts: artifacts})
	if err != nil {
		return "", fmt.Errorf("encode bundle identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "bundle-sha256-" + hex.EncodeToString(digest[:]), nil
}
