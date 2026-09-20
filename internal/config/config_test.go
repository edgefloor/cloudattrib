package config

import "testing"

func TestDefaultIsValidAndCTIsDisabled(t *testing.T) {
	t.Parallel()

	config := Default()
	if err := config.Validate(); err != nil {
		t.Fatalf("Default().Validate() error = %v", err)
	}
	if config.CT.Enabled {
		t.Fatal("Default().CT.Enabled = true, want false")
	}
	if config.API.ListenAddress != "127.0.0.1:8080" {
		t.Fatalf("Default().API.ListenAddress = %q", config.API.ListenAddress)
	}
}

func TestMissingResolverIsInvalid(t *testing.T) {
	t.Parallel()

	config := Default()
	config.Resolver.Address = ""
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want resolver error")
	}
}
