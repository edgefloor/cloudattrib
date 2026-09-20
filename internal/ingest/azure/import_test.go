package azure

import "testing"

func TestParsePreservesServiceTagMetadata(t *testing.T) {
	data := []byte(`{"changeNumber":"1","cloud":"Public","values":[{"name":"Storage.Test","id":"Storage.Test","properties":{"changeNumber":"1","region":"testregion","systemService":"Storage","platform":"Azure","addressPrefixes":["203.0.113.0/24"]}}]}`)
	result, err := Parse(data, "1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Associations) != 1 {
		t.Fatalf("associations = %d", len(result.Associations))
	}
	if got := result.Associations[0]; got.Service != "Storage" || got.Region != "testregion" {
		t.Fatalf("association = %#v", got)
	}
}
