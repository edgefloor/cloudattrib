package cdndata

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

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

func TestParseCIDRIdentityAndOrdering(t *testing.T) {
	data := []byte(`{"waf":{"edge":["192.0.2.1/24"]},"cdn":{"edge":["192.0.2.0/24","192.0.2.128/24","192.0.2.0/25"],"other":["192.0.2.0/24"]}}`)
	var previous Result
	for i := 0; i < 100; i++ {
		got, err := Parse(data, Metadata{Revision: "rev", Digest: "digest"})
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && !reflect.DeepEqual(got, previous) {
			t.Fatalf("parse %d differs from first: %#v vs %#v", i, got, previous)
		}
		previous = got
	}
	if len(previous.CIDRs) != 4 {
		t.Fatalf("CIDR records = %#v", previous.CIDRs)
	}
	seen := make(map[string]bool)
	for _, record := range previous.CIDRs {
		if seen[record.ID] {
			t.Fatalf("duplicate identity %q", record.ID)
		}
		seen[record.ID] = true
		if record.Category == "cdn" && record.Provider == "edge" && record.Prefix.String() == "192.0.2.0/24" && len(record.RecordRefs) != 2 {
			t.Fatalf("duplicate source references lost: %#v", record)
		}
	}
	changed, err := Parse([]byte(`{"cdn":{"edge":["192.0.2.0/24"]}}`), Metadata{Revision: "new", Digest: "new"})
	if err != nil {
		t.Fatal(err)
	}
	var sameID bool
	for _, record := range previous.CIDRs {
		if record.Category == "cdn" && record.Provider == "edge" && record.Prefix.String() == "192.0.2.0/24" {
			sameID = record.ID == changed.CIDRs[0].ID
		}
	}
	if !sameID {
		t.Fatal("provenance-only changes changed semantic identity")
	}
}

func TestParseCIDRIdentityInFreshProcess(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_CDN_ID_HELPER") == "1" {
		result, err := Parse([]byte(`{"cdn":{"edge":["192.0.2.1/24"],"other":["192.0.2.0/25"]},"waf":{"edge":["192.0.2.0/24"]}}`), Metadata{Revision: "fixture", Digest: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(result.CIDRs); err != nil {
			t.Fatal(err)
		}
		return
	}
	var previous []byte
	for i := 0; i < 3; i++ {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestParseCIDRIdentityInFreshProcess$")
		command.Env = append(os.Environ(), "CLOUDATTRIB_CDN_ID_HELPER=1")
		got, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && !reflect.DeepEqual(got, previous) {
			t.Fatalf("fresh process %d changed normalized records: %s vs %s", i, got, previous)
		}
		previous = got
	}
}

func TestParseCIDRIdentityChangesOnlyForChangedRelationship(t *testing.T) {
	baseline := []byte(`{"cdn":{"edge":["192.0.2.1/24"],"steady":["198.51.100.0/24"]}}`)
	first, err := Parse(baseline, Metadata{Revision: "first", Digest: "first"})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(t *testing.T, records []CIDRRecord, provider string) string {
		t.Helper()
		for _, record := range records {
			if record.Provider == provider {
				return record.ID
			}
		}
		t.Fatalf("missing provider %q in %#v", provider, records)
		return ""
	}
	baseChanged := identity(t, first.CIDRs, "edge")
	baseSteady := identity(t, first.CIDRs, "steady")
	cases := []struct {
		name    string
		data    string
		changed string
	}{
		{name: "provider", data: `{"cdn":{"new-edge":["192.0.2.1/24"],"steady":["198.51.100.0/24"]}}`, changed: "new-edge"},
		{name: "category", data: `{"waf":{"edge":["192.0.2.1/24"]},"cdn":{"steady":["198.51.100.0/24"]}}`, changed: "edge"},
		{name: "prefix", data: `{"cdn":{"edge":["192.0.3.1/24"],"steady":["198.51.100.0/24"]}}`, changed: "edge"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse([]byte(test.data), Metadata{Revision: "later", Digest: "later"})
			if err != nil {
				t.Fatal(err)
			}
			if identity(t, got.CIDRs, test.changed) == baseChanged {
				t.Fatal("changed relationship kept its previous identity")
			}
			if identity(t, got.CIDRs, "steady") != baseSteady {
				t.Fatal("unaffected association changed identity")
			}
		})
	}
}
