package config

import (
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig("../../config.yaml")
	if err != nil {
		t.Errorf("failed to load config: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log level is not info but %s", cfg.LogLevel)
	}
	if cfg.FailOpen != true {
		t.Errorf("fail open is not true but %t", cfg.FailOpen)
	}
	if cfg.LiveStreamRetentionDays != 7 {
		t.Errorf("live stream retention days is not 7 but %d", cfg.LiveStreamRetentionDays)
	}
	if cfg.AbuseIPDB.Enabled != true {
		t.Errorf("abuse ip db is not enabled but %t", cfg.AbuseIPDB.Enabled)
	}
	if cfg.AbuseIPDB.APIKey != "YOUR_API_KEY_HERE" {
		t.Errorf("abuse ip db api key is not YOUR_API_KEY_HERE but %s", cfg.AbuseIPDB.APIKey)
	}
	if cfg.AbuseIPDB.ExpirationTime != 24*time.Hour {
		t.Errorf("abuse ip db expiration time is not 24 hours but %s", cfg.AbuseIPDB.ExpirationTime)
	}
	if cfg.AbuseIPDB.ConfidenceScoreThreshold != 50 {
		t.Errorf("abuse ip db confidence score threshold is not 50 but %d", cfg.AbuseIPDB.ConfidenceScoreThreshold)
	}
	if cfg.AbuseIPDB.CacheMaxSize != 1000 {
		t.Errorf("abuse ip db cache max size is not 1000 but %d", cfg.AbuseIPDB.CacheMaxSize)
	}
	if cfg.ActiveDefence.Enabled != true {
		t.Errorf("active defence is not enabled but %t", cfg.ActiveDefence.Enabled)
	}
	if cfg.ActiveDefence.ExpirationTime != "48h" {
		t.Errorf("active defence expiration time is not 48h but %s", cfg.ActiveDefence.ExpirationTime)
	}
	if cfg.ActiveDefence.AutoReport != false {
		t.Errorf("active defence auto report is not false but %t", cfg.ActiveDefence.AutoReport)
	}
	if len(cfg.ActiveDefence.ReportCategories) != 1 || cfg.ActiveDefence.ReportCategories[0] != 21 {
		t.Errorf("active defence report categories is not [21] but %v", cfg.ActiveDefence.ReportCategories)
	}
	if cfg.ActiveDefence.ReportComment != "Honeytoken tripped" {
		t.Errorf("active defence report comment is not 'Honeytoken tripped' but %q", cfg.ActiveDefence.ReportComment)
	}
}

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := LoadConfig("invalid.yaml")
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	_, err := LoadConfig("../../resources/tests/config/invalid.yaml")
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}
