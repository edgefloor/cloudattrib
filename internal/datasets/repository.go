package datasets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	manifestFilename   = "manifest.json"
	validationFilename = "validation.json"
	activeFilename     = "active.json"
)

// FetchReceipt records one operator-controlled local source import.
type FetchReceipt struct {
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	ImportedAt time.Time `json:"imported_at"`
}

// CoverageDiff describes a source state change relative to the active bundle.
type CoverageDiff struct {
	SourceID string `json:"source_id"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

// ValidationReport is the immutable review record bound to a candidate hash.
type ValidationReport struct {
	CandidateID    string         `json:"candidate_id"`
	CandidateHash  string         `json:"candidate_hash"`
	Valid          bool           `json:"valid"`
	ReviewRequired bool           `json:"review_required"`
	Reasons        []string       `json:"reasons"`
	CoverageDiffs  []CoverageDiff `json:"coverage_diffs"`
	Counts         Counts         `json:"counts"`
	Warnings       []string       `json:"warnings"`
	Receipts       []FetchReceipt `json:"fetch_receipts"`
	ValidatedAt    time.Time      `json:"validated_at"`
}

// Activation records a desired-bundle publication or rollback.
type Activation struct {
	BundleID      string    `json:"bundle_id"`
	CandidateHash string    `json:"candidate_hash"`
	Action        string    `json:"action"`
	At            time.Time `json:"at"`
}

// RepositoryStatus is the operator-visible bundle state.
type RepositoryStatus struct {
	Active     *Activation   `json:"active,omitempty"`
	Candidates []string      `json:"candidates"`
	Loads      []ProcessLoad `json:"process_loads"`
}

// ProcessLoad makes desired publication and successful process loading distinct.
type ProcessLoad struct {
	BundleID  string    `json:"bundle_id"`
	ProcessID int       `json:"process_id"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	At        time.Time `json:"at"`
}

// Repository owns same-filesystem candidate publication and activation pointers.
type Repository struct {
	root    string
	buildID string
	now     func() time.Time
}

// NewRepository returns a filesystem bundle repository.
func NewRepository(root, buildID string) (*Repository, error) {
	if root == "" || buildID == "" {
		return nil, fmt.Errorf("bundle directory and build ID are required")
	}
	return &Repository{root: root, buildID: buildID, now: time.Now}, nil
}

// Import validates local sources and atomically publishes an immutable candidate.
func (r *Repository) Import(ctx context.Context, sourceDirectory string) (ValidationReport, error) {
	var report ValidationReport
	err := r.withWriterLock(func() error {
		loaded, err := LoadSources(ctx, sourceDirectory, r.buildID)
		if err != nil {
			return err
		}
		manifestBytes, err := json.MarshalIndent(loaded.Candidate.Manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("encode candidate manifest: %w", err)
		}
		report = r.validationReport(loaded, manifestBytes)
		candidateDirectory := r.candidateDirectory(report.CandidateID)
		if _, err := os.Stat(candidateDirectory); err == nil {
			existing, validateErr := r.Validate(ctx, report.CandidateID)
			if validateErr != nil {
				return validateErr
			}
			if existing.CandidateHash != report.CandidateHash {
				return fmt.Errorf("candidate ID exists with different content")
			}
			report = existing
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Join(r.root, "candidates"), 0o750); err != nil {
			return fmt.Errorf("create candidate directory: %w", err)
		}
		stage, err := os.MkdirTemp(r.root, ".staging-")
		if err != nil {
			return fmt.Errorf("create bundle staging directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(stage) }()
		for _, artifact := range loaded.Candidate.Manifest.Artifacts {
			source := filepath.Join(sourceDirectory, filepath.FromSlash(artifact.Path))
			destination := filepath.Join(stage, "sources", filepath.FromSlash(artifact.Path))
			if err := copyDurableFile(source, destination, artifact); err != nil {
				return err
			}
			report.Receipts = append(report.Receipts, FetchReceipt{Path: artifact.Path, SHA256: artifact.SHA256, Size: artifact.Size, ImportedAt: r.now().UTC()})
		}
		reportBytes, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode validation report: %w", err)
		}
		if err := writeDurableFile(filepath.Join(stage, manifestFilename), append(manifestBytes, '\n'), 0o640); err != nil {
			return err
		}
		if err := writeDurableFile(filepath.Join(stage, validationFilename), append(reportBytes, '\n'), 0o640); err != nil {
			return err
		}
		if err := syncDirectory(stage); err != nil {
			return err
		}
		if err := os.Rename(stage, candidateDirectory); err != nil {
			return fmt.Errorf("publish candidate: %w", err)
		}
		return syncDirectory(filepath.Join(r.root, "candidates"))
	})
	return report, err
}

// Validate re-hashes a published candidate and rebuilds its indexes.
func (r *Repository) Validate(ctx context.Context, candidateID string) (ValidationReport, error) {
	if err := validCandidateID(candidateID); err != nil {
		return ValidationReport{}, err
	}
	directory := r.candidateDirectory(candidateID)
	manifest, manifestBytes, err := readManifest(filepath.Join(directory, manifestFilename))
	if err != nil {
		return ValidationReport{}, err
	}
	for _, artifact := range manifest.Artifacts {
		data, actual, digest, err := readSource(filepath.Join(directory, "sources"), artifact.Path)
		_ = data
		if err != nil {
			return ValidationReport{}, fmt.Errorf("validate candidate artifact %s: %w", artifact.Path, err)
		}
		if actual.Size != artifact.Size || digest != artifact.SHA256 {
			return ValidationReport{}, fmt.Errorf("candidate artifact %s does not match its manifest", artifact.Path)
		}
	}
	loaded, err := LoadSources(ctx, filepath.Join(directory, "sources"), r.buildID)
	if err != nil {
		return ValidationReport{}, err
	}
	if loaded.Candidate.Manifest.BundleID != manifest.BundleID || manifest.BundleID != candidateID || !slices.Contains(manifest.CompatibleDetectorBuilds, r.buildID) {
		return ValidationReport{}, fmt.Errorf("candidate manifest identity or compatibility is invalid")
	}
	report := r.validationReport(loaded, manifestBytes)
	stored, err := readValidation(filepath.Join(directory, validationFilename))
	if err == nil {
		report.Receipts = stored.Receipts
	}
	return report, nil
}

// Activate atomically publishes a reviewed candidate as the desired bundle.
func (r *Repository) Activate(ctx context.Context, candidateID, approvalHash, action string) (Activation, error) {
	return r.ActivateCoordinated(ctx, candidateID, approvalHash, action, func(_ Manifest, _ []byte, publish func() error) error {
		return publish()
	})
}

// ActivateCoordinated holds the repository writer lock while durable admission
// and filesystem publication are coordinated in one lock order.
func (r *Repository) ActivateCoordinated(
	ctx context.Context,
	candidateID, approvalHash, action string,
	coordinate func(Manifest, []byte, func() error) error,
) (Activation, error) {
	if coordinate == nil {
		return Activation{}, fmt.Errorf("activation coordinator is required")
	}
	var activation Activation
	err := r.withWriterLock(func() error {
		report, err := r.Validate(ctx, candidateID)
		if err != nil {
			return err
		}
		if approvalHash == "" || approvalHash != report.CandidateHash {
			return fmt.Errorf("approval hash does not match the validated candidate")
		}
		if action == "" {
			action = "activate"
		}
		manifest, manifestBytes, err := r.Manifest(candidateID)
		if err != nil {
			return err
		}
		activation = Activation{BundleID: candidateID, CandidateHash: report.CandidateHash, Action: action, At: r.now().UTC()}
		encoded, err := json.Marshal(activation)
		if err != nil {
			return err
		}
		activePath := filepath.Join(r.root, activeFilename)
		previous, previousErr := os.ReadFile(activePath)
		if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
			return previousErr
		}
		published := false
		publish := func() error {
			if published {
				return fmt.Errorf("activation was published more than once")
			}
			if err := atomicWrite(activePath, append(encoded, '\n'), 0o640); err != nil {
				return err
			}
			published = true
			if err := appendAudit(filepath.Join(r.root, "activation-audit.jsonl"), encoded); err != nil {
				return err
			}
			return nil
		}
		if err := coordinate(manifest, manifestBytes, publish); err != nil {
			if published {
				var restoreErr error
				if previousErr == nil {
					restoreErr = atomicWrite(activePath, previous, 0o640)
				} else {
					if removeErr := os.Remove(activePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
						restoreErr = removeErr
					} else {
						restoreErr = syncDirectory(r.root)
					}
				}
				if restoreErr != nil {
					return fmt.Errorf("%w; restore active pointer: %v", err, restoreErr)
				}
			}
			return err
		}
		if !published {
			return fmt.Errorf("activation coordinator did not publish the candidate")
		}
		return nil
	})
	return activation, err
}

// Active returns the desired bundle publication, if one exists.
func (r *Repository) Active() (*Activation, error) {
	data, err := os.ReadFile(filepath.Join(r.root, activeFilename))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var activation Activation
	if err := json.Unmarshal(data, &activation); err != nil || validCandidateID(activation.BundleID) != nil {
		return nil, fmt.Errorf("active bundle pointer is corrupt")
	}
	return &activation, nil
}

// SourceDirectory returns the active candidate's immutable source directory.
func (r *Repository) SourceDirectory() (string, *Activation, error) {
	activation, err := r.Active()
	if err != nil || activation == nil {
		return "", activation, err
	}
	return filepath.Join(r.candidateDirectory(activation.BundleID), "sources"), activation, nil
}

// Manifest returns canonical bytes for one validated candidate manifest.
func (r *Repository) Manifest(candidateID string) (Manifest, []byte, error) {
	if err := validCandidateID(candidateID); err != nil {
		return Manifest{}, nil, err
	}
	return readManifest(filepath.Join(r.candidateDirectory(candidateID), manifestFilename))
}

// Status lists the desired bundle and immutable candidates.
func (r *Repository) Status() (RepositoryStatus, error) {
	active, err := r.Active()
	if err != nil {
		return RepositoryStatus{}, err
	}
	status := RepositoryStatus{Active: active, Candidates: []string{}}
	entries, err := os.ReadDir(filepath.Join(r.root, "candidates"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return RepositoryStatus{}, err
	}
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && validCandidateID(entry.Name()) == nil {
				status.Candidates = append(status.Candidates, entry.Name())
			}
		}
	}
	slices.Sort(status.Candidates)
	loadEntries, err := os.ReadDir(filepath.Join(r.root, "loads"))
	if err == nil {
		for _, entry := range loadEntries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(r.root, "loads", entry.Name()))
			if readErr != nil {
				return RepositoryStatus{}, readErr
			}
			var load ProcessLoad
			if decodeErr := decodeStrictJSON(data, &load); decodeErr != nil {
				return RepositoryStatus{}, fmt.Errorf("decode process load %s: %w", entry.Name(), decodeErr)
			}
			status.Loads = append(status.Loads, load)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return RepositoryStatus{}, err
	}
	slices.SortFunc(status.Loads, func(left, right ProcessLoad) int {
		if left.At.Equal(right.At) {
			return left.ProcessID - right.ProcessID
		}
		if left.At.Before(right.At) {
			return -1
		}
		return 1
	})
	return status, nil
}

// RecordLoad publishes one process's load success or failure after activation.
func (r *Repository) RecordLoad(bundleID, status, reason string) error {
	if err := validCandidateID(bundleID); err != nil || (status != "loaded" && status != "failed") {
		return fmt.Errorf("bundle ID and load status are invalid")
	}
	record := ProcessLoad{BundleID: bundleID, ProcessID: os.Getpid(), Status: status, Reason: reason, At: r.now().UTC()}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(r.root, "loads", fmt.Sprintf("process-%d.json", record.ProcessID)), append(encoded, '\n'), 0o640)
}

// Prune removes one unprotected immutable candidate.
func (r *Repository) Prune(candidateID string, protected func(string) (bool, error)) (bool, error) {
	if err := validCandidateID(candidateID); err != nil || protected == nil {
		return false, fmt.Errorf("candidate ID and protection check are required")
	}
	removed := false
	err := r.withWriterLock(func() error {
		active, err := r.Active()
		if err != nil {
			return err
		}
		if active != nil && active.BundleID == candidateID {
			return nil
		}
		keep, err := protected(candidateID)
		if err != nil {
			return err
		}
		if keep {
			return nil
		}
		if err := os.RemoveAll(r.candidateDirectory(candidateID)); err != nil {
			return err
		}
		removed = true
		return syncDirectory(filepath.Join(r.root, "candidates"))
	})
	return removed, err
}

func (r *Repository) validationReport(loaded LoadedBundle, manifestBytes []byte) ValidationReport {
	digest := sha256.Sum256(manifestBytes)
	report := ValidationReport{
		CandidateID: loaded.Candidate.Manifest.BundleID, CandidateHash: "sha256:" + hex.EncodeToString(digest[:]), Valid: true,
		Reasons: []string{}, CoverageDiffs: []CoverageDiff{}, Counts: loaded.Counts, Warnings: slices.Clone(loaded.Warnings), ValidatedAt: r.now().UTC(),
	}
	for _, source := range loaded.Candidate.Manifest.Sources {
		if source.PublishedAt != nil && r.now().Sub(*source.PublishedAt) > 45*24*time.Hour {
			report.ReviewRequired = true
			report.Reasons = append(report.Reasons, "stale source "+source.ID)
		}
	}
	active, _ := r.Active()
	if active == nil {
		return report
	}
	currentManifest, _, err := readManifest(filepath.Join(r.candidateDirectory(active.BundleID), manifestFilename))
	if err != nil {
		report.ReviewRequired = true
		report.Reasons = append(report.Reasons, "active manifest cannot be compared")
		return report
	}
	before := make(map[string]Source)
	for _, source := range currentManifest.Sources {
		before[source.ID] = source
	}
	for _, source := range loaded.Candidate.Manifest.Sources {
		previous := before[source.ID]
		if previous.Status != source.Status {
			report.CoverageDiffs = append(report.CoverageDiffs, CoverageDiff{SourceID: source.ID, Before: string(previous.Status), After: string(source.Status)})
			report.ReviewRequired = true
		}
		if previous.Records > 0 && (source.Records < previous.Records/2 || source.Records > previous.Records*2) {
			report.ReviewRequired = true
			report.Reasons = append(report.Reasons, "extreme record-count delta for "+source.ID)
		}
		delete(before, source.ID)
	}
	for sourceID, previous := range before {
		report.CoverageDiffs = append(report.CoverageDiffs, CoverageDiff{SourceID: sourceID, Before: string(previous.Status)})
		report.ReviewRequired = true
	}
	return report
}

func (r *Repository) candidateDirectory(candidateID string) string {
	return filepath.Join(r.root, "candidates", candidateID)
}

func (r *Repository) withWriterLock(action func() error) error {
	if err := os.MkdirAll(r.root, 0o750); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(r.root, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("another dataset writer holds the repository lock: %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
	return action()
}

func validCandidateID(candidateID string) error {
	if !strings.HasPrefix(candidateID, "bundle-sha256-") || len(candidateID) != len("bundle-sha256-")+64 {
		return fmt.Errorf("candidate ID is invalid")
	}
	_, err := hex.DecodeString(strings.TrimPrefix(candidateID, "bundle-sha256-"))
	return err
}

func readManifest(path string) (Manifest, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	if err := decodeStrictJSON(data, &manifest); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode bundle manifest: %w", err)
	}
	canonical, err := json.MarshalIndent(manifest, "", "  ")
	return manifest, canonical, err
}

func readValidation(path string) (ValidationReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ValidationReport{}, err
	}
	var report ValidationReport
	return report, decodeStrictJSON(data, &report)
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func copyDurableFile(source, destination string, expected Artifact) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source artifact is not a regular file")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != expected.Size || "sha256:"+hex.EncodeToString(digest[:]) != expected.SHA256 {
		return fmt.Errorf("source artifact changed while candidate was staged")
	}
	return writeDurableFile(destination, data, 0o640)
}

func writeDurableFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".pointer-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func appendAudit(path string, record []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(record, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
