package main

import "testing"

func TestRequiresLocalAnalyzer(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		args []string
		want bool
	}{
		{[]string{"analyze", "example.com"}, true},
		{[]string{"lookup-ip", "192.0.2.1"}, true},
		{[]string{"serve"}, false},
		{[]string{"datasets", "sync"}, false},
		{[]string{"ct", "collect"}, false},
		{nil, false},
	} {
		if got := requiresLocalAnalyzer(test.args); got != test.want {
			t.Fatalf("requiresLocalAnalyzer(%v) = %v, want %v", test.args, got, test.want)
		}
	}
}
