package gcp

import "testing"

func TestParsePreservesRawServiceAndScope(t *testing.T) {
	result, err := Parse([]byte(`{"syncToken":"1","creationTime":"2026-09-20T00:00:00Z","prefixes":[{"ipv6Prefix":"2001:db8::/32","service":"Google Cloud","scope":"global"}]}`), "1", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Associations[0]; got.Service != "Google Cloud" || got.Region != "global" {
		t.Fatalf("association = %#v", got)
	}
}
