package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCredentialsRequiresPrivateUniqueMapping(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte("fixture-token: operator-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadCredentials(path)
	if err != nil || credentials["fixture-token"] != "operator-a" {
		t.Fatalf("LoadCredentials() = %#v, %v", credentials, err)
	}
	if err := os.WriteFile(path, []byte("duplicate: one\nduplicate: two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("LoadCredentials() accepted a duplicate token")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("LoadCredentials() accepted a group/world-readable file")
	}
}
