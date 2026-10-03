package config

import (
	"testing"
	"time"
)

func TestReportRetentionDefaultAndValidation(t *testing.T) {
	configuration := Default()
	if configuration.Storage.ReportRetention != 30*24*time.Hour {
		t.Fatalf("default report retention = %s", configuration.Storage.ReportRetention)
	}
	configuration.Storage.ReportRetention = 0
	if err := configuration.Validate(); err == nil {
		t.Fatal("zero report retention accepted")
	}
}
