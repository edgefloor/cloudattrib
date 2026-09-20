package iptoasn

import "testing"

func TestParseV4AcceptsInclusiveEndpoints(t *testing.T) {
	records, err := ParseV4([]byte("3221225984\t3221225985\t64512\tZZ\tExample\n"), Metadata{Revision: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Start.String(); got != "192.0.2.0" {
		t.Fatalf("start = %s", got)
	}
	if got := records[0].End.String(); got != "192.0.2.1" {
		t.Fatalf("end = %s", got)
	}
}

func TestParseV4AcceptsCurrentTextualEndpoints(t *testing.T) {
	records, err := ParseV4([]byte("192.0.2.0\t192.0.2.255\t64512\tZZ\tExample\n"), Metadata{Revision: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Start.String() != "192.0.2.0" || records[0].End.String() != "192.0.2.255" {
		t.Fatalf("interval = %#v", records[0])
	}
}

func TestParseRejectsOverlap(t *testing.T) {
	_, err := ParseV6([]byte("2001:db8::\t2001:db8::f\t1\tZZ\tOne\n2001:db8::f\t2001:db8::ff\t2\tZZ\tTwo\n"), Metadata{})
	if err == nil {
		t.Fatal("ParseV6 accepted overlapping intervals")
	}
}
