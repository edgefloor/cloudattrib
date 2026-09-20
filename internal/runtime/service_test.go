package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"cloudattrib/internal/api"
	"cloudattrib/internal/config"
)

func TestReadDSNRequiresPrivateSingleLineFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "postgres.dsn")
	if err := os.WriteFile(path, []byte("postgres://service@database/cloudattrib?sslmode=require\n"), 0o600); err != nil {
		t.Fatalf("write DSN: %v", err)
	}
	value, err := readDSN(path)
	if err != nil || value != "postgres://service@database/cloudattrib?sslmode=require" {
		t.Fatalf("readDSN() = %q, %v", value, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod DSN: %v", err)
	}
	if _, err := readDSN(path); err == nil {
		t.Fatal("readDSN() accepted a group/world-readable secret")
	}
}

func TestServiceAuthenticationParsesTrustedProxyRanges(t *testing.T) {
	t.Parallel()

	authentication, err := serviceAuthentication(config.API{
		AuthenticationEnabled: true, AuthenticationMode: string(api.AuthTrustedProxy),
		TrustedProxyCIDRs: []string{"192.0.2.7/24"}, TrustedProxyIdentityHeader: "X-Operator",
	})
	if err != nil {
		t.Fatalf("serviceAuthentication() error = %v", err)
	}
	if authentication.Mode != api.AuthTrustedProxy || len(authentication.TrustedProxyCIDRs) != 1 || authentication.TrustedProxyCIDRs[0].String() != "192.0.2.0/24" {
		t.Fatalf("authentication = %#v", authentication)
	}
}
