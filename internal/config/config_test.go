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
