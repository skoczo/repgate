package config

import (
	"net/netip"
	"os"
	"path/filepath"
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
	if len(cfg.LocalNetworks) != 5 {
		t.Errorf("expected 5 local networks, got %d", len(cfg.LocalNetworks))
	}
	if len(cfg.ParsedLocalNetworks) != 5 {
		t.Errorf("expected 5 parsed local networks, got %d", len(cfg.ParsedLocalNetworks))
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

func TestLoadConfigInvalidLocalNetworks(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "invalid_local.yaml")
	content := []byte("local_networks:\n  - 'invalid-cidr/999'\n")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadConfig(filePath)
	if err == nil {
		t.Errorf("expected error for invalid local_networks, got nil")
	}
}

func TestParseLocalNetworks(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		expectError bool
		checkIPs    map[string]bool // ip -> should match
	}{
		{
			name: "valid mixed networks and IPs",
			input: []string{
				"192.168.0.0/16",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"127.0.0.1",
				"192.168.1.22",
				"::1",
				"fd00::/8",
				"   ", // empty/whitespace
			},
			expectError: false,
			checkIPs: map[string]bool{
				"192.168.1.22":       true,
				"192.168.200.5":      true,
				"10.10.1.45":         true,
				"172.30.0.7":         true,
				"127.0.0.1":          true,
				"::1":                true,
				"fd12:3456:789a::1":  true,
				"8.8.8.8":            false,
				"1.1.1.1":            false,
				"172.32.0.1":         false,
				"2001:4860:4860::88": false,
			},
		},
		{
			name:        "invalid CIDR",
			input:       []string{"192.168.1.0/99"},
			expectError: true,
		},
		{
			name:        "invalid IP address",
			input:       []string{"999.999.999.999"},
			expectError: true,
		},
		{
			name:        "invalid string format",
			input:       []string{"not-an-ip"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, err := ParseLocalNetworks(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for input %v, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for ipStr, expected := range tt.checkIPs {
				addr, parseErr := netip.ParseAddr(ipStr)
				if parseErr != nil {
					t.Fatalf("test error parsing IP %s: %v", ipStr, parseErr)
				}
				matched := false
				for _, p := range prefixes {
					if p.Contains(addr) {
						matched = true
						break
					}
				}
				if matched != expected {
					t.Errorf("IP %s: expected match=%v, got match=%v", ipStr, expected, matched)
				}
			}
		})
	}
}

