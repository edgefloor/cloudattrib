package dnsrules

import (
	"context"
	"encoding/json"
	"testing"

	"cloudattrib/internal/model"
)

func TestCloudFrontSuffixUsesLabelBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  int
	}{
		{value: "d111111abcdef8.cloudfront.net", want: 1},
		{value: "cloudfront.net.evil.example", want: 0},
		{value: "notcloudfront.net", want: 0},
	}
	detector := NewDefault()
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Value: tt.value})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			evidence, _ := detector.Detect(context.Background(), []model.Observation{{ID: "obs", Type: "dns_record", Subject: "example.com", Payload: payload}}, model.AttributionView{})
			if len(evidence) != tt.want {
				t.Fatalf("Detect() evidence = %d, want %d", len(evidence), tt.want)
			}
		})
	}
}
