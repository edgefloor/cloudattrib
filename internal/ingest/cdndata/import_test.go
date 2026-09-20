package cdndata

import "testing"

func TestParsePreservesRawCategoriesAndKinds(t *testing.T) {
	result, err := Parse([]byte(`{"cdn":{"edge":["192.0.2.0/24","edge.example"]},"waf":{"shield":["198.51.100.0/24"]},"cloud":{"host":["2001:db8::/32"]},"common":{"shared":["common.example"]}}`), Metadata{Revision: "fixture", Digest: "digest"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CIDRs) != 3 || len(result.Suffixes) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if result.CIDRs[0].Category == "" || result.CIDRs[0].ProvenanceGroup == "" {
		t.Fatalf("record = %#v", result.CIDRs[0])
	}
}

func TestParseRejectsMalformedPrefix(t *testing.T) {
	_, err := Parse([]byte(`{"cdn":{"edge":["not-a-prefix"]}}`), Metadata{})
	if err == nil {
		t.Fatal("Parse accepted malformed prefix")
	}
}
