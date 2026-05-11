package model

import (
	"testing"
	"time"
)

func TestIPRecord(t *testing.T) {
	now := time.Now()
	record := IPRecord{
		IP:        "127.0.0.1",
		Status:    "safe",
		Score:     0,
		Source:    "test",
		CheckedAt: now,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	if record.IP != "127.0.0.1" {
		t.Errorf("Expected IP 127.0.0.1, got %s", record.IP)
	}
	if record.Status != "safe" {
		t.Errorf("Expected Status safe, got %s", record.Status)
	}
	if record.Score != 0 {
		t.Errorf("Expected Score 0, got %d", record.Score)
	}
}
