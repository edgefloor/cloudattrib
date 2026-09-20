package aws

import "testing"

func TestParsePreservesOverlappingServices(t *testing.T) {
	data := []byte(`{"syncToken":"1","createDate":"2026-09-20T00:00:00Z","prefixes":[{"ip_prefix":"192.0.2.0/24","region":"us-test-1","service":"EC2","network_border_group":"us-test-1"},{"ip_prefix":"192.0.2.0/24","region":"us-test-1","service":"S3","network_border_group":"us-test-1"}],"ipv6_prefixes":[]}`)
	result, err := Parse(data, "1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Associations) != 2 {
		t.Fatalf("associations = %d", len(result.Associations))
	}
}
