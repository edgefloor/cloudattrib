package azure

import "testing"

func TestParsePreservesServiceTagMetadata(t *testing.T) {
	data := []byte(`{"changeNumber":1,"cloud":"Public","values":[{"name":"Storage.Test","id":"Storage.Test","properties":{"changeNumber":1,"region":"testregion","regionId":7,"systemService":"Storage","platform":"Azure","networkFeatures":["API"],"addressPrefixes":["203.0.113.0/24"]}}]}`)
	result, err := Parse(data, "1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Associations) != 1 {
		t.Fatalf("associations = %d", len(result.Associations))
	}
	if result.ChangeNumber != "1" {
		t.Fatalf("change number = %q", result.ChangeNumber)
	}
	if got := result.Associations[0]; got.Service != "Storage" || got.Region != "testregion" {
		t.Fatalf("association = %#v", got)
	}
}

func TestParsePreservesTagNameWhenSystemServiceIsEmpty(t *testing.T) {
	data := []byte(`{"changeNumber":1,"cloud":"Public","values":[{"name":"AzureFrontDoor.Frontend","id":"AzureFrontDoor.Frontend","properties":{"changeNumber":1,"region":"","regionId":0,"systemService":"","platform":"Azure","networkFeatures":[],"addressPrefixes":["203.0.113.0/24"]}}]}`)
	result, err := Parse(data, "1", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Associations[0].Service != "AzureFrontDoor.Frontend" || len(result.Warnings) != 1 {
		t.Fatalf("result = %#v", result)
	}
}
