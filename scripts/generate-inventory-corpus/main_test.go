package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckedInCorpusMatchesRenderer(t *testing.T) {
	for _, version := range []string{"v2", "v3"} {
		t.Run(version, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "corpus.json")
			if err := generate("../../docs/benchmarks/inventory-retrieval-facts-"+version+".json", output); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("../../docs/benchmarks/inventory-retrieval-corpus-" + version + ".json")
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
		})
	}
}
