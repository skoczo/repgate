package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel   string `yaml:"log_level"`
	FailOpen   bool   `yaml:"fail_open"`
	LogSafeIPs bool   `yaml:"log_safe_ips"`
	Server     struct {
		Port              string        `yaml:"port"`
		ReadTimeout       time.Duration `yaml:"read_timeout"`
		WriteTimeout      time.Duration `yaml:"write_timeout"`
		ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	} `yaml:"server"`
	AbuseIPDB struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
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
		Enabled         bool     `yaml:"enabled"`
		ExpirationTime  string   `yaml:"expiration_time"`
		HoneytokenPaths []string `yaml:"honeytoken_paths"`
	} `yaml:"active_defence"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
