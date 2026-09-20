package cli

import (
	"bytes"
	"context"
	"testing"
	"time"

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
	exit := Run(t.Context(), []string{"serve"}, Dependencies{Serve: func(context.Context) error { called = true; return nil }, Stdout: &out, Stderr: &errOut})
	if exit != 0 || !called || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("exit=%d called=%v stdout=%q stderr=%q", exit, called, out.String(), errOut.String())
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
