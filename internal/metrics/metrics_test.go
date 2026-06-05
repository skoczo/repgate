package metrics

import (
	"testing"
)

func TestGetMetrics(t *testing.T) {
	m := GetMetrics()
	if m == nil {
		t.Fatal("expected GetMetrics to return non-nil instance")
	}

	// Verify we can call GetMetrics multiple times and it returns the same instance
	m2 := GetMetrics()
	if m2 != m {
		t.Fatal("expected GetMetrics to return the same singleton instance")
	}

	// Verify fields are initialized
	if m.RequestCount == nil {
		t.Error("expected RequestCount to be initialized")
	}
	if m.RequestDuration == nil {
		t.Error("expected RequestDuration to be initialized")
	}
	if m.ThreatCount == nil {
		t.Error("expected ThreatCount to be initialized")
	}
	if m.AbuseIpDbCacheSize == nil {
		t.Error("expected AbuseIpDbCacheSize to be initialized")
	}
	if m.AbuseIpDbDatabaseEntitiesCount == nil {
		t.Error("expected AbuseIpDbDatabaseEntitiesCount to be initialized")
	}
	if m.AbuseIpDbDatabaseThreatsCount == nil {
		t.Error("expected AbuseIpDbDatabaseThreatsCount to be initialized")
	}
	if m.AbuseIpDbCacheEntitiesCount == nil {
		t.Error("expected AbuseIpDbCacheEntitiesCount to be initialized")
	}
	if m.AbuseIpDbCacheThreatsCount == nil {
		t.Error("expected AbuseIpDbCacheThreatsCount to be initialized")
	}
}
