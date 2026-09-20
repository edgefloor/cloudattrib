package target

import (
	"testing"

	"cloudattrib/internal/model"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		req       model.AnalyzeRequest
		wantKind  model.TargetKind
		wantValue string
		wantSeeds []string
		wantErr   bool
	}{
		{
			name:      "IDNA domain and terminal dot",
			req:       model.AnalyzeRequest{Target: "BÜCHER.Example.", Kind: model.TargetDomain, IncludeWWW: boolPointer(false)},
			wantKind:  model.TargetDomain,
			wantValue: "xn--bcher-kva.example",
			wantSeeds: []string{"xn--bcher-kva.example"},
		},
		{
			name:      "root domain adds www",
			req:       model.AnalyzeRequest{Target: "Example.COM", Kind: model.TargetDomain},
			wantKind:  model.TargetDomain,
			wantValue: "example.com",
			wantSeeds: []string{"example.com", "www.example.com"},
		},
		{
			name:      "hostname does not expand",
			req:       model.AnalyzeRequest{Target: "App.Example.COM", Kind: model.TargetDomain},
			wantKind:  model.TargetDomain,
			wantValue: "app.example.com",
			wantSeeds: []string{"app.example.com"},
		},
		{
			name:      "mapped IP is unmapped",
			req:       model.AnalyzeRequest{Target: "::ffff:192.0.2.1", Kind: model.TargetIP, Mode: model.ModeIP},
			wantKind:  model.TargetIP,
			wantValue: "192.0.2.1",
		},
		{
			name:      "bracketed URL IPv6",
			req:       model.AnalyzeRequest{Target: "https://[2001:db8::1]/a?q=1", Kind: model.TargetURL},
			wantKind:  model.TargetURL,
			wantValue: "https://[2001:db8::1]/a?q=1",
			wantSeeds: []string{"2001:db8::1"},
		},
		{name: "userinfo", req: model.AnalyzeRequest{Target: "https://user@example.com", Kind: model.TargetURL}, wantErr: true},
		{name: "fragment", req: model.AnalyzeRequest{Target: "https://example.com/#secret", Kind: model.TargetURL}, wantErr: true},
		{name: "unsupported scheme", req: model.AnalyzeRequest{Target: "ftp://example.com/", Kind: model.TargetURL}, wantErr: true},
		{name: "forbidden port", req: model.AnalyzeRequest{Target: "https://example.com:8443/", Kind: model.TargetURL}, wantErr: true},
		{name: "zoned IP", req: model.AnalyzeRequest{Target: "fe80::1%eth0", Kind: model.TargetIP}, wantErr: true},
		{name: "public suffix", req: model.AnalyzeRequest{Target: "com", Kind: model.TargetDomain}, wantErr: true},
		{name: "IP live mode", req: model.AnalyzeRequest{Target: "192.0.2.1", Kind: model.TargetIP, Mode: model.ModeFull}, wantErr: true},
		{
			name: "hostname outside scope",
			req: model.AnalyzeRequest{
				Target:              "example.com",
				Kind:                model.TargetDomain,
				AdditionalHostnames: []string{"other.example.net"},
				ScopeRoots:          []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name: "lookalike suffix outside scope",
			req: model.AnalyzeRequest{
				Target:              "example.com",
				Kind:                model.TargetDomain,
				AdditionalHostnames: []string{"notexample.com"},
				ScopeRoots:          []string{"example.com"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Normalize(tt.req)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Normalize() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if got.Target.Kind != tt.wantKind || got.Target.Canonical != tt.wantValue {
				t.Fatalf("Normalize() target = %#v, want kind %q value %q", got.Target, tt.wantKind, tt.wantValue)
			}
			if !equalStrings(got.SeedHostnames, tt.wantSeeds) {
				t.Fatalf("Normalize() seeds = %v, want %v", got.SeedHostnames, tt.wantSeeds)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boolPointer(value bool) *bool {
	return &value
}
