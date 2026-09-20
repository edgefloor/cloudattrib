package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOverlaysStrictYAMLOnDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("api:\n  listen_address: 127.0.0.1:9090\nresolver:\n  address: 127.0.0.1:5353\n  network: tcp\nstorage:\n  lease_duration: 45s\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	configuration, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.API.ListenAddress != "127.0.0.1:9090" || configuration.Resolver.Network != "tcp" || configuration.Storage.LeaseDuration != 45*time.Second {
		t.Fatalf("Load() = %#v", configuration)
	}
	if configuration.Limits.MaximumBacklogTargets != Default().Limits.MaximumBacklogTargets {
		t.Fatalf("Load() did not retain defaults: %#v", configuration.Limits)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want unknown-field error")
	}
}

func TestLoadRejectsOversizedConfiguration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := make([]byte, maximumConfigBytes+1)
	for index := range content {
		content[index] = '#'
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want size error")
	}
}

func TestCheckedInExampleLoads(t *testing.T) {
	t.Parallel()

	configuration, err := Load(filepath.Join("..", "..", "config", "example.yaml"))
	if err != nil {
		t.Fatalf("Load(example.yaml) error = %v", err)
	}
	if configuration.API.ListenAddress != "127.0.0.1:8080" || configuration.Storage.PostgresDSNFile == "" {
		t.Fatalf("Load(example.yaml) = %#v", configuration)
	}
}
