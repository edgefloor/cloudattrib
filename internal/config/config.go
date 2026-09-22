// Package config defines the local operator configuration contract.
package config

import (
	"fmt"
	"net"
	"time"

	"cloudattrib/internal/policy"
)

// Config is the complete local application configuration.
type Config struct {
	API      API      `json:"api" yaml:"api"`
	Resolver Resolver `json:"resolver" yaml:"resolver"`
	Data     Data     `json:"data" yaml:"data"`
	Limits   Limits   `json:"limits" yaml:"limits"`
	CT       CT       `json:"ct" yaml:"ct"`
	Storage  Storage  `json:"storage" yaml:"storage"`
}

// API configures the local HTTP listener and trusted-operator identity mode.
type API struct {
	ListenAddress              string            `json:"listen_address" yaml:"listen_address"`
	AuthenticationEnabled      bool              `json:"authentication_enabled" yaml:"authentication_enabled"`
	AuthenticationMode         string            `json:"authentication_mode,omitempty" yaml:"authentication_mode,omitempty"`
	Credentials                map[string]string `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	CredentialsFile            string            `json:"credentials_file,omitempty" yaml:"credentials_file,omitempty"`
	TrustedProxyCIDRs          []string          `json:"trusted_proxy_cidrs,omitempty" yaml:"trusted_proxy_cidrs,omitempty"`
	TrustedProxyIdentityHeader string            `json:"trusted_proxy_identity_header,omitempty" yaml:"trusted_proxy_identity_header,omitempty"`
	LocalOperatorID            string            `json:"local_operator_id,omitempty" yaml:"local_operator_id,omitempty"`
}

// Resolver identifies the only DNS resolver used by collectors.
type Resolver struct {
	Address string `json:"address" yaml:"address"`
	Network string `json:"network" yaml:"network"`
}

// Data configures immutable bundle and local source storage.
type Data struct {
	BundleDirectory string `json:"bundle_directory" yaml:"bundle_directory"`
	SourceDirectory string `json:"source_directory" yaml:"source_directory"`
}

// Limits adds service-wide bounds to the per-target policy.
type Limits struct {
	Target                     policy.Limits `json:"target" yaml:"target"`
	ConcurrentTargets          int           `json:"concurrent_targets" yaml:"concurrent_targets"`
	ConcurrentHTTP             int           `json:"concurrent_http" yaml:"concurrent_http"`
	ConcurrentDNS              int           `json:"concurrent_dns" yaml:"concurrent_dns"`
	MaximumRequestBytes        int64         `json:"maximum_request_bytes" yaml:"maximum_request_bytes"`
	MaximumBatchTargets        int           `json:"maximum_batch_targets" yaml:"maximum_batch_targets"`
	MaximumBacklogTargets      int           `json:"maximum_backlog_targets" yaml:"maximum_backlog_targets"`
	MaximumResidentGenerations int           `json:"maximum_resident_generations" yaml:"maximum_resident_generations"`
}

// CT configures the optional local CT index and background collector.
type CT struct {
	Enabled          bool   `json:"enabled" yaml:"enabled"`
	ConfigPath       string `json:"config_path,omitempty" yaml:"config_path,omitempty"`
	MaximumSeedNames int    `json:"maximum_seed_names" yaml:"maximum_seed_names"`
}

// Storage configures PostgreSQL-dependent service operations.
type Storage struct {
	PostgresDSNFile string        `json:"postgres_dsn_file,omitempty" yaml:"postgres_dsn_file,omitempty"`
	LeaseDuration   time.Duration `json:"lease_duration" yaml:"lease_duration"`
	MaximumAttempts int           `json:"maximum_attempts" yaml:"maximum_attempts"`
}

// Default returns the bounded loopback configuration without credentials.
func Default() Config {
	return Config{
		API:      API{ListenAddress: "127.0.0.1:8080"},
		Resolver: Resolver{Address: "127.0.0.1:53", Network: "udp"},
		Data:     Data{BundleDirectory: "./data/bundles", SourceDirectory: "./data/sources"},
		Limits: Limits{
			Target:                     policy.DefaultLimits(),
			ConcurrentTargets:          32,
			ConcurrentHTTP:             32,
			ConcurrentDNS:              128,
			MaximumRequestBytes:        1 << 20,
			MaximumBatchTargets:        1000,
			MaximumBacklogTargets:      10000,
			MaximumResidentGenerations: 4,
		},
		CT:      CT{Enabled: false, MaximumSeedNames: 20},
		Storage: Storage{LeaseDuration: 30 * time.Second, MaximumAttempts: 3},
	}
}

// Validate rejects missing resolver and unbounded resource settings.
func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.API.ListenAddress); err != nil {
		return fmt.Errorf("parse API listen address: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.Resolver.Address); err != nil {
		return fmt.Errorf("parse resolver address: %w", err)
	}
	if c.Resolver.Network != "udp" && c.Resolver.Network != "tcp" {
		return fmt.Errorf("resolver network must be udp or tcp")
	}
	if c.Data.BundleDirectory == "" || c.Data.SourceDirectory == "" {
		return fmt.Errorf("data directories are required")
	}
	if err := c.Limits.Target.Validate(); err != nil {
		return fmt.Errorf("validate target limits: %w", err)
	}
	if c.Limits.ConcurrentTargets <= 0 || c.Limits.ConcurrentHTTP <= 0 || c.Limits.ConcurrentDNS <= 0 ||
		c.Limits.MaximumRequestBytes <= 0 || c.Limits.MaximumBatchTargets <= 0 || c.Limits.MaximumBacklogTargets <= 0 {
		return fmt.Errorf("service limits must be positive")
	}
	if c.Limits.MaximumResidentGenerations < 2 {
		return fmt.Errorf("maximum resident generations must be at least 2")
	}
	if c.CT.MaximumSeedNames < 0 || c.CT.MaximumSeedNames > c.Limits.Target.SeedHostnames {
		return fmt.Errorf("CT seed limit exceeds the target seed limit")
	}
	if c.Storage.LeaseDuration <= 0 || c.Storage.MaximumAttempts <= 0 {
		return fmt.Errorf("storage lease settings must be positive")
	}
	return nil
}
