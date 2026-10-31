package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel                string         `yaml:"log_level"`
	FailOpen                bool           `yaml:"fail_open"`
	LogSafeIPs              bool           `yaml:"log_safe_ips"`
	LiveStreamRetentionDays int            `yaml:"live_stream_retention_days"`
	LocalNetworks           []string       `yaml:"local_networks"`
	ParsedLocalNetworks     []netip.Prefix `yaml:"-"`
	Server                  struct {
		Port              string        `yaml:"port"`
		ReadTimeout       time.Duration `yaml:"read_timeout"`
		WriteTimeout      time.Duration `yaml:"write_timeout"`
		ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	} `yaml:"server"`
	AbuseIPDB struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
		APIURL                   string        `yaml:"api_url"`
		ExpirationTime           time.Duration `yaml:"expiration_time"`
		ConfidenceScoreThreshold int           `yaml:"confidence_score_threshold"`
		CacheMaxSize             int           `yaml:"cache_max_size"`
		CircuitBreaker           struct {
			MaxRetries     int           `yaml:"max_retries"`
			CoolDownPeriod time.Duration `yaml:"cool_down_period"`
			OpenOnError    bool          `yaml:"open_on_error"`
		} `yaml:"circuit_breaker"`
	} `yaml:"AbuseIPDB"`
	ActiveDefence struct {
		Enabled          bool     `yaml:"enabled"`
		ExpirationTime   string   `yaml:"expiration_time"`
		HoneytokenPaths  []string `yaml:"honeytoken_paths"`
		AutoReport       bool     `yaml:"auto_report"`
		ReportCategories []int    `yaml:"report_categories"`
		ReportComment    string   `yaml:"report_comment"`
	} `yaml:"active_defence"`
}

// ParseLocalNetworks parses a slice of CIDR prefixes or single IP addresses into []netip.Prefix.
// Single IP addresses (without a slash) are converted into /32 (IPv4) or /128 (IPv6) prefixes.
func ParseLocalNetworks(networks []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, entry := range networks {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR prefix %q in local_networks: %w", entry, err)
			}
			prefixes = append(prefixes, prefix.Masked())
		} else {
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid IP address %q in local_networks: %w", entry, err)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes, nil
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	cfg.LiveStreamRetentionDays = 0 // disabled by default
	// Default ActiveDefence config
	cfg.ActiveDefence.AutoReport = false
	cfg.ActiveDefence.ReportCategories = []int{21} // Web App Attack
	cfg.ActiveDefence.ReportComment = "Honeytoken tripped"

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	parsedLocal, err := ParseLocalNetworks(cfg.LocalNetworks)
	if err != nil {
		return nil, err
	}
	cfg.ParsedLocalNetworks = parsedLocal

	return &cfg, nil
}

