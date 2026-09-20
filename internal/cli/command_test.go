package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/model"
)

type analyzerStub struct{}

func (analyzerStub) Analyze(_ context.Context, request model.AnalyzeRequest) (model.Report, error) {
	return model.Report{SchemaVersion: model.SchemaVersion, ID: "report", Target: model.Target{Original: request.Target, Canonical: request.Target, Kind: request.Kind}, Mode: model.ModeFull, StartedAt: time.Unix(0, 0).UTC(), EndedAt: time.Unix(0, 0).UTC(), ClassifiedAt: time.Unix(0, 0).UTC(), Status: model.StatusComplete, Observations: []model.Observation{}, Evidence: []model.Evidence{}, Findings: []model.Finding{}, Coverage: []model.Coverage{}, Warnings: []string{}}, nil
}
func (analyzerStub) LookupIP(_ context.Context, request model.IPLookupRequest) (model.IPLookupResult, error) {
	return model.IPLookupResult{Address: request.Address, Status: model.StatusComplete, Associations: []model.Association{}, ASN: []model.ASNRecord{}, Coverage: []model.Coverage{}}, nil
}
func (analyzerStub) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "unavailable", nil)
}

func TestRunAnalyzeRendersOnlyJSONOnStdout(t *testing.T) {
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{"analyze", "example.test", "--kind", "domain"}, Dependencies{Analyzer: analyzerStub{}, Stdout: &out, Stderr: &errOut})
	if exit != 0 {
		t.Fatalf("exit = %d, stderr = %s", exit, errOut.String())
	}
	if got := out.String(); got == "" || got[0] != '{' {
		t.Fatalf("stdout = %q", got)
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q", errOut.String())
	}
}
func TestRunLookupIPRejectsInvalidAddress(t *testing.T) {
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{"lookup-ip", "not-an-ip"}, Dependencies{Analyzer: analyzerStub{}, Stdout: &out, Stderr: &errOut})
	if exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if out.Len() != 0 || errOut.Len() == 0 {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestRunServeUsesLifecycleDependency(t *testing.T) {
	var out, errOut bytes.Buffer
	called := false
	exit := Run(t.Context(), []string{"serve", "--config", "config.yaml"}, Dependencies{Serve: func(_ context.Context, path string) error {
		called = path == "config.yaml"
		return nil
	}, Stdout: &out, Stderr: &errOut})
	if exit != 0 || !called || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("exit=%d called=%v stdout=%q stderr=%q", exit, called, out.String(), errOut.String())
	}
}

func TestRunServePreservesTypedError(t *testing.T) {
	var errOut bytes.Buffer
	exit := Run(t.Context(), []string{"serve", "--config", "missing.yaml"}, Dependencies{
		Serve: func(context.Context, string) error {
			return model.NewError(model.CodeInvalidSyntax, "load configuration", nil)
		},
		Stdout: io.Discard,
		Stderr: &errOut,
	})
	if exit != 2 {
		t.Fatalf("exit = %d, want 2; stderr = %q", exit, errOut.String())
	}
}

func TestRunServeClassifiesUntypedStartupFailure(t *testing.T) {
	var errOut bytes.Buffer
	exit := Run(t.Context(), []string{"serve"}, Dependencies{
		Serve: func(context.Context, string) error {
			return errors.New("listen failed")
		},
		Stdout: io.Discard,
		Stderr: &errOut,
	})
	if exit != 4 {
		t.Fatalf("exit = %d, want 4; stderr = %q", exit, errOut.String())
	}
}
func TestRunAnalyzeJSONLAddsInputIndex(t *testing.T) {
	var out, errOut bytes.Buffer
	input := bytes.NewBufferString("{\"target\":\"one.test\",\"kind\":\"domain\"}\n{\"target\":\"two.test\",\"kind\":\"domain\"}\n")
	exit := Run(context.Background(), []string{"analyze", "--input", "-", "--format", "jsonl"}, Dependencies{Analyzer: analyzerStub{}, Stdin: input, Stdout: &out, Stderr: &errOut})
	if exit != 0 {
		t.Fatalf("exit = %d: %s", exit, errOut.String())
	}
	if got := out.String(); !bytes.Contains([]byte(got), []byte("\"input_index\":0")) || !bytes.Contains([]byte(got), []byte("\"input_index\":1")) {
		t.Fatalf("stdout = %s", got)
	}
}

func TestRunCTImportAndCollect(t *testing.T) {
	var out, errOut bytes.Buffer
	input := bytes.NewBufferString("fixture\n")
	dependencies := Dependencies{
		Stdin: input, Stdout: &out, Stderr: &errOut,
		CTImport: func(_ context.Context, reader io.Reader, roots []string) (int, error) {
			content, _ := io.ReadAll(reader)
			if string(content) != "fixture\n" || len(roots) != 1 || roots[0] != "example.com" {
				t.Fatalf("CTImport input=%q roots=%v", content, roots)
			}
			return 1, nil
		},
		CTCollect: func(_ context.Context, path string) (ctlog.Metrics, error) {
			if path != "ct.json" {
				t.Fatalf("CTCollect path=%q", path)
			}
			return ctlog.Metrics{EntriesFetched: 2}, nil
		},
	}
	if exit := Run(context.Background(), []string{"ct", "import", "--input", "-", "--scope", "example.com"}, dependencies); exit != 0 {
		t.Fatalf("ct import exit=%d stderr=%q", exit, errOut.String())
	}
	var imported map[string]int
	if err := json.Unmarshal(out.Bytes(), &imported); err != nil || imported["imported"] != 1 {
		t.Fatalf("ct import output=%q error=%v", out.String(), err)
	}
	out.Reset()
	if exit := Run(context.Background(), []string{"ct", "collect", "--config", "ct.json"}, dependencies); exit != 0 {
		t.Fatalf("ct collect exit=%d stderr=%q", exit, errOut.String())
	}
	var metrics ctlog.Metrics
	if err := json.Unmarshal(out.Bytes(), &metrics); err != nil || metrics.EntriesFetched != 2 {
		t.Fatalf("ct collect output=%q error=%v", out.String(), err)
	}
}

func TestRunDatasetsCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	dependencies := Dependencies{
		Stdout: &out, Stderr: &errOut,
		DatasetImport: func(_ context.Context, configPath, sourceDirectory string) (datasets.ValidationReport, error) {
			if configPath != "config.yaml" || sourceDirectory != "sources" {
				t.Fatalf("DatasetImport config=%q source=%q", configPath, sourceDirectory)
			}
			return datasets.ValidationReport{CandidateID: "bundle-sha256-fixture", Valid: true}, nil
		},
		DatasetActivate: func(_ context.Context, configPath, candidateID, approvalHash, action string) (datasets.Activation, error) {
			if configPath != "config.yaml" || candidateID != "bundle-sha256-fixture" || approvalHash != "sha256:approval" || action != "rollback" {
				t.Fatalf("DatasetActivate config=%q candidate=%q approval=%q action=%q", configPath, candidateID, approvalHash, action)
			}
			return datasets.Activation{BundleID: candidateID, Action: action}, nil
		},
	}
	if exit := Run(context.Background(), []string{"datasets", "import", "--source-dir", "sources", "--config", "config.yaml"}, dependencies); exit != 0 {
		t.Fatalf("datasets import exit=%d stderr=%q", exit, errOut.String())
	}
	out.Reset()
	if exit := Run(context.Background(), []string{"datasets", "rollback", "--bundle", "bundle-sha256-fixture", "--approval-hash", "sha256:approval", "--config", "config.yaml"}, dependencies); exit != 0 {
		t.Fatalf("datasets rollback exit=%d stderr=%q", exit, errOut.String())
	}
}

func TestRunBatchReadsPlainTargetsAndAddsInputIndex(t *testing.T) {
	var out, errOut bytes.Buffer
	input := bytes.NewBufferString("one.test\ntwo.test\n")
	exit := Run(context.Background(), []string{"batch", "--input", "-", "--format", "jsonl", "--unordered"}, Dependencies{Analyzer: analyzerStub{}, Stdin: input, Stdout: &out, Stderr: &errOut})
	if exit != 0 {
		t.Fatalf("exit = %d: %s", exit, errOut.String())
	}
	if got := out.String(); !bytes.Contains([]byte(got), []byte("\"input_index\":0")) || !bytes.Contains([]byte(got), []byte("\"input_index\":1")) {
		t.Fatalf("stdout = %s", got)
	}
}
