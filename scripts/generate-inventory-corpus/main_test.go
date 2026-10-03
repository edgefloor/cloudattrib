package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckedInCorpusMatchesRenderer(t *testing.T) {
	output := filepath.Join(t.TempDir(), "corpus.json")
	if err := generate("../../docs/benchmarks/inventory-retrieval-facts-v2.json", output); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../docs/benchmarks/inventory-retrieval-corpus-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("checked-in corpus differs from production description renderer; regenerate it")
	}
}
